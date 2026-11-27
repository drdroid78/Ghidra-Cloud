"""Exchange a repo-only SSH credential for on-demand, scoped Actions API access."""

import os
import re
import secrets
import shlex
import subprocess
import tempfile
import threading
import time
from pathlib import Path


class CredentialLease:
    def __init__(self, repo, private_key, known_host):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("Invalid GitHub repository")
        self.repo = repo
        self.private_key = private_key
        self.known_host = known_host
        self.condition = threading.Condition()
        self.pending = None
        self.active = None
        self.token = None
        self.expires = 0
        self.last_used = 0

    def _request_runner(self, nonce):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            known_hosts = Path(directory) / "known_hosts"
            key.touch(mode=0o600)
            key.write_text(self.private_key.strip() + "\n", encoding="ascii")
            known_hosts.write_text(self.known_host.strip() + "\n", encoding="ascii")
            command = ["ssh", "-F", "/dev/null", "-i", str(key), "-o", "BatchMode=yes",
                       "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                       "-o", f"UserKnownHostsFile={known_hosts}", "-o", "ConnectTimeout=12"]
            environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": shlex.join(command)}
            remote = f"ssh://git@ssh.github.com:443/{self.repo}.git"

            def git(*args):
                subprocess.run(["git", *args], cwd=directory, env=environment, check=True,
                               timeout=18, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            git("init", "--quiet")
            git("fetch", "--depth=1", remote, "refs/heads/web-auth")
            git("checkout", "--quiet", "--detach", "FETCH_HEAD")
            git("-c", "user.name=Ghidra Cloud", "-c", "user.email=ghidra-cloud@users.noreply.github.com",
                "commit", "--quiet", "--allow-empty", "-m", f"ghidra-token {nonce}")
            git("push", "--quiet", remote, "HEAD:refs/heads/web-auth")

    def get(self):
        with self.condition:
            now = time.monotonic()
            if self.token and now < self.expires:
                self.last_used = now
                return self.token
            launch = self.pending is None
            if launch:
                self.pending = secrets.token_hex(24)
            nonce = self.pending
        if launch:
            try:
                self._request_runner(nonce)
            except (OSError, subprocess.SubprocessError):
                with self.condition:
                    if self.pending == nonce:
                        self.pending = None
                    self.condition.notify_all()
                raise RuntimeError("Связь с GitHub Actions по SSH недоступна") from None
        with self.condition:
            self.condition.wait_for(lambda: self.active == nonce or self.pending != nonce, timeout=65)
            if self.active == nonce and self.token and time.monotonic() < self.expires:
                self.last_used = time.monotonic()
                return self.token
            if self.pending == nonce:
                self.pending = None
                self.condition.notify_all()
            raise RuntimeError("GitHub Actions ещё не выдал доступ. Повторите запрос.")

    def submit(self, nonce, token):
        if not isinstance(token, str) or not re.fullmatch(r"ghs_[!-~]{20,8000}", token):
            return False
        with self.condition:
            if self.pending != nonce or not nonce:
                return False
            now = time.monotonic()
            self.active = nonce
            self.pending = None
            self.token = token
            self.expires = now + 323
            self.last_used = now
            self.condition.notify_all()
            return True

    def running(self, nonce):
        with self.condition:
            now = time.monotonic()
            if self.active != nonce or not nonce:
                return False
            if now < self.expires and now - self.last_used < 75:
                return True
            self.active = None
            self.token = None
            return False
