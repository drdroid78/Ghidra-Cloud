"""Stage and verify release inputs in the private analysis repository."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

REPO = os.environ["GITHUB_REPOSITORY"]
ROOT = Path(os.environ["GITHUB_WORKSPACE"])
LIMIT = 100 * 1024 * 1024
SUFFIX = {"elf": "elf", "pe": "exe", "macho": "macho", "hex": "hex", "srec": "srec",
          "apk": "apk", "zip": "zip", "jar": "jar", "dex": "dex", "pcap": "pcap", "gz": "gz", "tar": "tar"}


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True, encoding="utf-8", timeout=180)


def private():
    repository = json.loads(gh("api", "repos/" + REPO))
    if repository["visibility"] != "private" or not repository["private"]:
        raise SystemExit("Upload jobs require a private GitHub repository")


def release(upload_id):
    if not re.fullmatch(r"[a-f0-9]{32}", upload_id):
        raise ValueError("Invalid upload ID")
    return json.loads(gh("api", f"repos/{REPO}/releases/tags/upload-{upload_id}"))


def stage(upload_id, slot, workflow):
    info = release(upload_id)
    record = json.loads(info["body"])
    if (not isinstance(record["size"], int) or not 0 < record["size"] <= LIMIT
            or not re.fullmatch(r"[a-f0-9]{64}", record["sha256"])):
        raise ValueError("Invalid size or digest metadata")
    candidate = next((x for x in info["assets"] if x["name"] == "input.bin"), None)
    if not candidate or candidate["size"] != record["size"] or candidate["state"] != "uploaded":
        raise ValueError("Input asset missing or invalid")
    directory = ROOT / ".cloud-uploads" / slot
    directory.mkdir(parents=True, exist_ok=True)
    gh("release", "download", info["tag_name"], "--repo", REPO, "--pattern", "input.bin",
       "--dir", str(directory), "--clobber")
    downloaded = directory / "input.bin"
    with downloaded.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if downloaded.stat().st_size != record["size"] or digest != record["sha256"]:
        raise ValueError("Downloaded bytes do not match the recorded SHA-256")
    path = directory / ("target." + SUFFIX.get(record["format"], "bin"))
    downloaded.replace(path)
    report = Path(os.environ["RUNNER_TEMP"]) / workflow / "report" / "inputs" / slot
    report.mkdir(parents=True, exist_ok=True)
    (report / "input.sha256").write_text(digest + "\n")
    (report / "manifest.json").write_text(json.dumps({"id": upload_id, **record}, indent=2, ensure_ascii=False), encoding="utf-8")
    print("INPUT_SHA256_VERIFIED", slot, digest, flush=True)
    return path.relative_to(ROOT).as_posix()


def cleanup(ids):
    for upload_id in ids:
        info = release(upload_id)
        if json.loads(info["body"]).get("keep", True):
            continue
        for asset in info["assets"]:
            if asset["name"] == "input.bin":
                gh("api", "--method", "DELETE", f"repos/{REPO}/releases/assets/{asset['id']}")
                print("INPUT_REMOVED", upload_id, flush=True)


def main():
    private()
    first = os.environ["UPLOAD_ID"]
    second = os.getenv("COMPARE_UPLOAD_ID")
    if os.getenv("PURGE_INPUTS") == "1":
        cleanup([first, second] if second else [first])
        return
    workflow = os.environ["UPLOAD_WORKFLOW"]
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as env:
        print("INPUT_PATH=" + stage(first, "a", workflow), file=env)
        if second:
            print("COMPARE_PATH=" + stage(second, "b", workflow), file=env)


if __name__ == "__main__":
    main()
