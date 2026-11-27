"""Authenticated Ghidra-Cloud gateway. Durable storage lives on private GitHub."""

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import PurePosixPath
from urllib.parse import quote, urlsplit

import requests
from flask import Flask, Response, abort, jsonify, render_template, request, session, stream_with_context
from werkzeug.exceptions import HTTPException

MIB = 1024 * 1024
MAX_INPUT = 100 * MIB
FILE_ID = re.compile(r"[a-f0-9]{32}")
TITLE = re.compile(r"upload:([a-f0-9]{32})(?::([a-f0-9]{32}))? (analyze|toolbox|compare|resume)")
WORKFLOWS = ("ghidra-cloud.yml", "toolbox.yml")
TEXT_EXTENSIONS = {".txt", ".tsv", ".log", ".json", ".sha256", ".java", ".xml", ".smali"}
ASSET_NAME = "input.bin"


class InputError(ValueError):
    pass


class GitHubError(RuntimeError):
    def __init__(self, status, message="Ошибка обращения к GitHub"):
        super().__init__(message)
        self.status = status


def inspect_upload(stream, name):
    if not name or len(name) > 240 or any(ch in "/\\" or ord(ch) < 32 or ord(ch) == 127 or ord(ch) in range(0x202a, 0x202f) for ch in name):
        raise InputError("Недопустимое имя файла")
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    if not 0 < size <= MAX_INPUT:
        raise InputError("Размер файла должен быть от 1 байта до 100 МиБ")
    stream.seek(0)
    head = stream.read(512)
    extension = PurePosixPath(name).suffix.lower()
    fmt = "raw"
    if head[:4] == b"\x7fELF":
        fmt = "elf"
    elif head[:2] == b"MZ":
        fmt = "pe"
    elif head[:4].hex() in {"feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca"}:
        fmt = "macho"
    elif head.startswith(b"dex\n"):
        fmt = "dex"
    elif head[:4].hex() in {"d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a"}:
        fmt = "pcap"
    elif head.startswith(b"PK") or extension in {".zip", ".apk", ".jar"}:
        try:
            with zipfile.ZipFile(stream) as archive:
                names = set()
                total = 0
                for member in archive.infolist():
                    path = PurePosixPath(member.filename)
                    key = str(path).casefold()
                    total += member.file_size
                    if (len(names) >= 20000 or total > 128 * MIB or key in names or path.is_absolute()
                            or ".." in path.parts or "\\" in member.filename or ":" in member.filename
                            or "\0" in member.orig_filename or member.flag_bits & 1
                            or (member.external_attr >> 16) & 0o170000 == 0o120000):
                        raise InputError("Архив превышает лимиты или содержит небезопасные записи")
                    names.add(key)
                originals = archive.namelist()
                fmt = "apk" if "AndroidManifest.xml" in originals else "jar" if any(n.endswith(".class") for n in originals) else "zip"
                if extension in {".apk", ".jar"} and fmt != extension[1:]:
                    raise InputError("Содержимое архива не соответствует расширению")
        except zipfile.BadZipFile as err:
            raise InputError("Повреждённый ZIP-архив") from err
    elif head.startswith(b"\x1f\x8b\x08"):
        fmt = "gz"
    elif head[257:262] == b"ustar":
        fmt = "tar"
    elif re.match(rb":[0-9a-fA-F]{10,}", head):
        fmt = "hex"
    elif re.match(rb"S[0-9][0-9a-fA-F]{6,}", head):
        fmt = "srec"
    elif head[0] == 0xE9 and len(head) >= 24 and 1 <= head[1] <= 16:
        fmt = "esp-candidate"
    stream.seek(0)
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
    stream.seek(0)
    return {"name": name, "size": size, "format": fmt, "sha256": digest}


def valid_id(value):
    if not isinstance(value, str) or not FILE_ID.fullmatch(value):
        raise InputError("Некорректный идентификатор файла")
    return value


class GitHub:
    def __init__(self, repo, token):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo or "") or not token:
            raise GitHubError(503, "Серверу требуется доступ к закрытому репозиторию GitHub")
        self.base = f"https://api.github.com/repos/{repo}"
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def call(self, method, path, *, retry=False, allow_missing=False, url=None, **kwargs):
        headers = self.headers | kwargs.pop("headers", {})
        for attempt in range(3 if retry else 1):
            try:
                response = requests.request(method, url or self.base + path, headers=headers,
                                            timeout=(10, 90), **kwargs)
                if response.ok or (allow_missing and response.status_code == 404):
                    return response
                status = response.status_code
                response.close()
                if status not in (429, 500, 502, 503, 504) or not retry:
                    raise GitHubError(status)
            except (requests.ConnectionError, requests.Timeout):
                status = 503
            if retry and attempt < 2:
                time.sleep(2 ** attempt)
        raise GitHubError(status)

    def get(self, path, **kwargs):
        return self.call("GET", path, retry=True, **kwargs)

    def ensure_private(self, *, write=False):
        repo = self.get("").json()
        if not repo.get("private") or repo.get("visibility") != "private":
            raise GitHubError(503, "Приватность репозитория GitHub не подтверждена")
        if write and repo.get("archived"):
            raise GitHubError(503, "Репозиторий GitHub архивирован")

    def release(self, upload_id):
        response = self.get(f"/releases/tags/upload-{valid_id(upload_id)}", allow_missing=True)
        if response.status_code == 404:
            return None
        return response.json()

    def upload(self, upload_id, stream, record):
        self.ensure_private(write=True)
        release = self.release(upload_id)
        if release is None:
            try:
                release = self.call("POST", "/releases", json={
                    "tag_name": f"upload-{upload_id}", "name": f"upload-{upload_id}",
                    "body": json.dumps(record, ensure_ascii=False), "prerelease": True,
                }).json()
            except GitHubError as err:
                if err.status not in (422, 500, 502, 503, 504):
                    raise
                release = self.release(upload_id)
                if release is None:
                    raise
        if json.loads(release["body"]) != record:
            raise GitHubError(409, "Идентификатор уже связан с другим файлом")
        asset_path = release["upload_url"].split("{", 1)[0]
        if urlsplit(asset_path).netloc != "uploads.github.com" or urlsplit(asset_path).scheme != "https":
            raise GitHubError(502)
        for attempt in range(3):
            assets = self.get(f"/releases/{release['id']}/assets").json()
            asset = next((item for item in assets if item["name"] == ASSET_NAME), None)
            if asset and asset["state"] != "uploaded":
                self.call("DELETE", f"/releases/assets/{asset['id']}", retry=True, allow_missing=True)
                asset = None
            if asset is None:
                stream.seek(0)
                try:
                    asset = self.call("POST", "", url=asset_path, params={"name": ASSET_NAME},
                                      data=stream, headers={"Content-Type": "application/octet-stream"}).json()
                except GitHubError as err:
                    if err.status not in (422, 429, 500, 502, 503, 504) or attempt == 2:
                        raise
                    time.sleep(2 ** attempt)
                    continue
            if asset["state"] != "uploaded" or asset["size"] != record["size"]:
                raise GitHubError(502, "GitHub сохранил файл с неправильным размером")
            digest = asset.get("digest")
            if not digest:
                with self.get(f"/releases/assets/{asset['id']}", stream=True,
                              headers={"Accept": "application/octet-stream"}) as downloaded:
                    check = hashlib.sha256()
                    for chunk in downloaded.iter_content(256 * 1024):
                        check.update(chunk)
                    digest = "sha256:" + check.hexdigest()
            if digest != "sha256:" + record["sha256"]:
                self.call("DELETE", f"/releases/assets/{asset['id']}", retry=True, allow_missing=True)
                raise GitHubError(502, "SHA-256 на GitHub отличается от исходного")
            return

    def runs(self):
        return self.get("/actions/runs?event=workflow_dispatch&per_page=100").json()["workflow_runs"]

    def dispatch(self, first, second, mode, options, source=None):
        self.ensure_private(write=True)
        workflow = WORKFLOWS[1] if mode == "toolbox" else WORKFLOWS[0]
        run_mode = "analyze" if mode == "toolbox" else mode
        inputs = {"mode": run_mode, "upload_id": first, **options}
        if second:
            inputs["compare_upload_id"] = second
        if source:
            inputs["resume_run"] = str(source)
        response = self.call("POST", f"/actions/workflows/{workflow}/dispatches",
                             json={"ref": "main", "return_run_details": True, "inputs": inputs})
        if response.content:
            return response.json().get("workflow_run_id")
        return None

    def run(self, run_id):
        if not re.fullmatch(r"[1-9][0-9]{0,19}", str(run_id)):
            abort(404)
        run = self.get(f"/actions/runs/{run_id}").json()
        if not TITLE.fullmatch(run["display_title"]) or run["path"].split("@")[0].rsplit("/", 1)[-1] not in WORKFLOWS:
            abort(404)
        return run

    def binary(self, path):
        return self.get(path, headers={"Accept": "application/octet-stream"}, stream=True)


def options_from(data):
    language = data.get("raw_language", "").strip()
    if not language:
        return {}
    if not re.fullmatch(r"[a-zA-Z0-9:_-]{1,80}", language):
        raise InputError("Некорректный Ghidra language ID")
    options = {"raw_language": language}
    for key in ("raw_base", "raw_entry"):
        value = data.get(key, "").strip()
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", value):
            raise InputError("Базовый адрес и точка входа должны быть в шестнадцатеричном виде")
        options[key] = value
    compiler = data.get("raw_compiler", "").strip()
    if compiler:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", compiler):
            raise InputError("Некорректный compiler spec ID")
        options["raw_compiler"] = compiler
    return options


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_INPUT + 128 * 1024, MAX_FORM_PARTS=8,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    app.config.update({key: os.environ.get(key) for key in ("APP_PASSWORD", "SESSION_SECRET", "GITHUB_TOKEN", "GITHUB_REPO")})
    app.config.update(overrides or {})
    app.secret_key = app.config["SESSION_SECRET"]
    login_lock = threading.Lock()
    failures = []
    upload_slots = threading.BoundedSemaphore(3)
    job_lock = threading.Lock()

    def github():
        return GitHub(app.config["GITHUB_REPO"], app.config["GITHUB_TOKEN"])

    @app.before_request
    def access():
        if request.endpoint in {"health", "index", "login", "static"}:
            return
        if not session.get("csrf"):
            abort(401)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
                abort(403)

    @app.after_request
    def security(response):
        response.headers.update({
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        })
        return response

    @app.errorhandler(InputError)
    def invalid(err):
        return jsonify(error=str(err)), 400

    @app.errorhandler(GitHubError)
    def upstream(err):
        status = err.status if err.status in {404, 409, 429, 503} else 502
        return jsonify(error=f"{err} (GitHub HTTP {err.status})"), status

    @app.errorhandler(HTTPException)
    def http_error(err):
        return jsonify(error={401: "Войдите в систему", 403: "Запрос отклонён",
                              404: "Запись не найдена", 413: "Файл превышает 100 МиБ",
                              429: "Слишком много одновременных запросов"}.get(err.code, err.name)), err.code

    @app.get("/healthz")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/login")
    def login():
        password = app.config["APP_PASSWORD"]
        if not password or not app.secret_key:
            return jsonify(error="Вход пока не настроен"), 503
        supplied = (request.get_json(silent=True) or {}).get("password", "")
        if not isinstance(supplied, str) or len(supplied) > 512:
            abort(403)
        with login_lock:
            now = time.monotonic()
            failures[:] = [stamp for stamp in failures if now - stamp < 60]
            if len(failures) >= 12:
                abort(429)
            if not hmac.compare_digest(supplied.encode(), password.encode()):
                failures.append(now)
                abort(401)
        session.clear()
        session["csrf"] = secrets.token_urlsafe(24)
        return jsonify(csrf=session["csrf"])

    @app.get("/api/session")
    def auth_session():
        return jsonify(csrf=session["csrf"])

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.post("/api/uploads")
    def put_upload():
        if not upload_slots.acquire(blocking=False):
            abort(429)
        try:
            file = request.files.get("file")
            if not file:
                raise InputError("Выберите файл")
            upload_id = valid_id(request.form.get("id") or uuid.uuid4().hex)
            record = inspect_upload(file.stream, file.filename)
            expected = request.form.get("sha256")
            if expected and expected != record["sha256"]:
                raise InputError("SHA-256 полученного файла отличается от исходного")
            record["keep"] = request.form.get("keep") == "1"
            gh = github()
            gh.upload(upload_id, file.stream, record)
            return jsonify(id=upload_id, **record), 201
        finally:
            upload_slots.release()

    @app.get("/api/uploads")
    def state():
        gh = github()
        gh.ensure_private()
        uploads = []
        records = {}
        for page in range(1, 6):
            releases = gh.get(f"/releases?per_page=100&page={page}").json()
            for release in releases:
                tag = release["tag_name"]
                if tag.startswith("upload-") and FILE_ID.fullmatch(tag[7:]) and release.get("body"):
                    upload_id = tag[7:]
                    record = json.loads(release["body"])
                    records[upload_id] = record
                    present = any(asset["name"] == ASSET_NAME and asset["state"] == "uploaded" for asset in release["assets"])
                    if present:
                        uploads.append({"id": upload_id, "created": release["created_at"], **record})
            if len(releases) < 100:
                break
        runs = []
        for run in gh.runs():
            match = TITLE.fullmatch(run["display_title"])
            if not match:
                continue
            first, second, mode = match.groups()
            ids = [file_id for file_id in [first, second] if file_id]
            fields = ("id", "status", "conclusion", "created_at", "run_started_at", "html_url", "run_attempt")
            item = {key: run.get(key) for key in fields}
            item.update(mode=mode, files=[{"id": file_id, **records.get(file_id, {})} for file_id in ids])
            runs.append(item)
        return jsonify(uploads=uploads, runs=runs)

    @app.delete("/api/uploads/<upload_id>")
    def remove(upload_id):
        gh = github()
        gh.ensure_private(write=True)
        with job_lock:
            release = gh.release(upload_id)
            if not release:
                abort(404)
            if any(upload_id in run["display_title"] and run["status"] != "completed" for run in gh.runs()):
                return jsonify(error="Файл используется активным заданием"), 409
            for asset in release["assets"]:
                if asset["name"] == ASSET_NAME:
                    gh.call("DELETE", f"/releases/assets/{asset['id']}", retry=True, allow_missing=True)
        return jsonify(ok=True)

    @app.post("/api/runs")
    def start():
        data = request.get_json()
        mode = data.get("mode")
        if mode not in {"analyze", "compare", "resume", "toolbox"}:
            raise InputError("Неизвестный режим")
        first = valid_id(data.get("first"))
        second = valid_id(data.get("second")) if mode == "compare" else None
        if second == first:
            raise InputError("Для сравнения выберите два разных файла")
        gh = github()
        with job_lock:
            source = None
            if mode == "resume":
                original = gh.run(data.get("source"))
                if (original["conclusion"] != "success" or TITLE.fullmatch(original["display_title"])[1] != first
                        or not original["path"].startswith(".github/workflows/ghidra-cloud.yml")):
                    raise InputError("Для продолжения нужен успешный запуск Ghidra")
                source = original["id"]
            else:
                for file_id in filter(None, (first, second)):
                    release = gh.release(file_id)
                    if not release or not any(asset["name"] == ASSET_NAME and asset["state"] == "uploaded" for asset in release["assets"]):
                        abort(404)
            ids = [file_id for file_id in (first, second) if file_id]
            existing = [run for run in gh.runs() if run["status"] != "completed"
                        and any(file_id in run["display_title"] for file_id in ids)]
            if existing:
                return jsonify(error="Для этого файла уже запущено исследование"), 409
            run_id = gh.dispatch(first, second, mode, options_from(data), source)
        return jsonify(id=run_id), 202

    @app.get("/api/runs/<int:run_id>")
    def detail(run_id):
        gh = github()
        run = gh.run(run_id)
        jobs = gh.get(f"/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs").json()["jobs"]
        artifacts = gh.get(f"/actions/runs/{run_id}/artifacts").json()["artifacts"]
        return jsonify(status=run["status"], conclusion=run["conclusion"],
                       jobs=[{"id": job["id"], "name": job["name"], "steps": job["steps"]} for job in jobs],
                       artifacts=[{key: item[key] for key in ("id", "name", "expired", "size_in_bytes")} for item in artifacts])

    @app.post("/api/runs/<int:run_id>/<action>")
    def run_action(run_id, action):
        gh = github()
        run = gh.run(run_id)
        if action not in {"cancel", "rerun"}:
            abort(404)
        if action == "rerun" and TITLE.fullmatch(run["display_title"])[3] != "resume":
            match = TITLE.fullmatch(run["display_title"])
            for file_id in filter(None, match.groups()[:2]):
                release = gh.release(file_id)
                if not release or not any(asset["name"] == ASSET_NAME and asset["state"] == "uploaded" for asset in release["assets"]):
                    return jsonify(error="Исходный файл удалён. Для повторного запуска загрузите его снова."), 409
        gh.call("POST", f"/actions/runs/{run_id}/{action}")
        return jsonify(ok=True), 202

    def allowed_artifact(gh, run_id, artifact_id):
        gh.run(run_id)
        items = gh.get(f"/actions/runs/{run_id}/artifacts").json()["artifacts"]
        for item in items:
            if item["id"] == artifact_id and not item["expired"]:
                return item
        abort(404)

    def streamed(upstream, content_type, filename=None):
        def content():
            with upstream:
                yield from upstream.iter_content(256 * 1024)
        response = Response(stream_with_context(content()), mimetype=content_type)
        response.call_on_close(upstream.close)
        if filename:
            response.headers["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(filename, safe="")
        return response

    @app.get("/api/runs/<int:run_id>/jobs/<int:job_id>/log")
    def log(run_id, job_id):
        gh = github()
        run = gh.run(run_id)
        jobs = gh.get(f"/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs").json()["jobs"]
        if not any(job["id"] == job_id for job in jobs):
            abort(404)
        return streamed(gh.binary(f"/actions/jobs/{job_id}/logs"), "text/plain")

    @app.get("/api/runs/<int:run_id>/artifacts/<int:artifact_id>/download")
    def download(run_id, artifact_id):
        gh = github()
        item = allowed_artifact(gh, run_id, artifact_id)
        return streamed(gh.binary(f"/actions/artifacts/{artifact_id}/zip"), "application/zip", item["name"] + ".zip")

    @app.get("/api/runs/<int:run_id>/artifacts/<int:artifact_id>/text")
    def browse(run_id, artifact_id):
        gh = github()
        item = allowed_artifact(gh, run_id, artifact_id)
        if item["size_in_bytes"] > 100 * MIB:
            raise InputError("Архив слишком велик для просмотра. Скачайте ZIP.")
        with gh.binary(f"/actions/artifacts/{artifact_id}/zip") as source, tempfile.TemporaryFile() as spool:
            for chunk in source.iter_content(256 * 1024):
                spool.write(chunk)
                if spool.tell() > 100 * MIB:
                    raise InputError("Архив слишком велик для просмотра. Скачайте ZIP.")
            with zipfile.ZipFile(spool) as archive:
                members = {member.filename: member for member in archive.infolist()[:20000]
                           if not member.is_dir() and PurePosixPath(member.filename).suffix.lower() in TEXT_EXTENSIONS}
                member = request.args.get("file")
                if not member:
                    return jsonify(files=sorted(members))
                if member not in members:
                    abort(404)
                with archive.open(members[member]) as text_file:
                    data = text_file.read(2 * MIB + 1)
                return Response(data[:2 * MIB].decode("utf-8", "replace") + ("\n[Предпросмотр ограничен 2 МиБ]" if len(data) > 2 * MIB else ""), mimetype="text/plain")

    return app
