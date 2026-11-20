"""Start the app under test on a random localhost port with a throwaway database, and kill the whole
process tree when done (plan 3.2 step 2).

The app runs with a CLEAN environment: PATH/system variables plus PORT and DB_PATH. API keys, tokens and anything
that looks like a secret in our own environment are never passed to the code under test.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from ..redact import redact
from ..runner import _kill_tree
from .guard import ensure_temp_db

ENTRY_CANDIDATES = ("app.py", "main.py", "server.py", "run.py", "wsgi.py")
_SECRETISH = re.compile(r"KEY|TOKEN|SECRET|PASSW|GEMINI|SUPABASE|CREDENTIAL|AUTH", re.IGNORECASE)
_KEEP = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "APPDATA",
         "LOCALAPPDATA", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "PYTHONIOENCODING", "VIRTUAL_ENV", "PYTHONHOME"}


class LaunchError(Exception):
    pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def clean_env(port: int, db_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in _KEEP and not _SECRETISH.search(k)}
    env.update({"PORT": str(port), "DB_PATH": str(db_path), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    return env


def find_entry(project: Path) -> Path | None:
    for name in ENTRY_CANDIDATES:
        p = project / name
        if p.is_file():
            return p
    return None


class AppProcess:
    """One running copy of the app. Use `async with AppProcess.start(project) as app:`."""

    def __init__(self, project: Path, entry: Path, workdir: Path, python: str | None = None):
        self.project, self.entry, self.workdir = project, entry, workdir
        self.port = free_port()
        self.db_path = ensure_temp_db(workdir / "probe.db")
        self.url = f"http://127.0.0.1:{self.port}"
        self.python = python or sys.executable
        self._proc: asyncio.subprocess.Process | None = None
        self._log = workdir / "app.log"

    @classmethod
    def start(cls, project: str | Path, python: str | None = None) -> "AppProcess":
        project = Path(project).resolve()
        entry = find_entry(project)
        if entry is None:
            raise LaunchError(f"no entry file ({', '.join(ENTRY_CANDIDATES)}) in {project}")
        workdir = Path(tempfile.mkdtemp(prefix="proofgate-probe-"))
        return cls(project, entry, workdir, python)

    async def __aenter__(self) -> "AppProcess":
        kwargs: dict = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        log = open(self._log, "wb")
        try:
            self._proc = await asyncio.create_subprocess_exec(
                self.python, str(self.entry), cwd=str(self.project), env=clean_env(self.port, self.db_path),
                stdin=asyncio.subprocess.DEVNULL, stdout=log, stderr=log, **kwargs)
        finally:
            log.close()
        try:
            await self._wait_ready()
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self

    async def _wait_ready(self, timeout: float = 25.0) -> None:
        assert self._proc is not None
        deadline = time.monotonic() + timeout
        async with httpx.AsyncClient(timeout=2.0) as c:
            while time.monotonic() < deadline:
                if self._proc.returncode is not None:
                    raise LaunchError(f"the app exited during start-up (code {self._proc.returncode}): {self.log_tail()}")
                try:
                    await c.get(self.url + "/")
                    return
                except httpx.TransportError:
                    await asyncio.sleep(0.1)
        raise LaunchError(f"the app did not answer on {self.url} within {timeout:g}s: {self.log_tail()}")

    def log_tail(self, n: int = 400) -> str:
        try:
            return redact(self._log.read_text(encoding="utf-8", errors="replace")[-n:].strip())
        except OSError:
            return ""

    async def __aexit__(self, *exc) -> None:
        if self._proc is not None:
            _kill_tree(self._proc)
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=10)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
        for _ in range(25):  # Windows keeps a file handle open for a moment after the process is killed: retry
            shutil.rmtree(self.workdir, ignore_errors=True)  # delete the throwaway database
            if not self.workdir.exists():
                break
            await asyncio.sleep(0.2)
