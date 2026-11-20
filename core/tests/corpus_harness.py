"""Test-only helper: run a corpus app on a free port with a temp DB, and talk to it with httpx."""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "demo-apps" / "flask-corpus"
FIXES = ROOT / "demo-apps" / "flask-fixes"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RunningApp:
    def __init__(self, app_dir: Path, tmp: Path):
        self.dir = app_dir
        self.port = free_port()
        self.db_path = tmp / f"{app_dir.name}.db"
        self.url = f"http://127.0.0.1:{self.port}"
        env = {**__import__("os").environ, "PORT": str(self.port), "DB_PATH": str(self.db_path)}
        self.proc = subprocess.Popen(
            [sys.executable, "app.py"], cwd=app_dir, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )

    def wait_ready(self, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.dir.name} exited early: {self.proc.stderr.read().decode(errors='replace')[-500:]}")
            try:
                httpx.post(f"{self.url}/signup", json={}, timeout=2)
                return
            except httpx.TransportError:
                time.sleep(0.1)
        raise TimeoutError(f"{self.dir.name} did not start")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)
        if self.proc.stderr:
            self.proc.stderr.close()

    # --- convenience client -------------------------------------------------
    def signup(self, email: str, display_name: str = "") -> dict:
        r = httpx.post(f"{self.url}/signup", json={"email": email, "password": "pw-" + email, "display_name": display_name})
        r.raise_for_status()
        return r.json()

    def call(self, method: str, path: str, token: str | None = None, **kw) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx.request(method, f"{self.url}{path}", headers=headers, timeout=10, **kw)


@contextmanager
def running(app_dir: Path, tmp: Path):
    app = RunningApp(app_dir, tmp)
    try:
        app.wait_ready()
        yield app
    finally:
        app.stop()


def start_many(dirs: list[Path], tmp: Path) -> list[RunningApp]:
    """Start everything first, then wait, so 28 apps boot in parallel."""
    apps = [RunningApp(d, tmp) for d in dirs]
    try:
        for a in apps:
            a.wait_ready()
    except Exception:
        for a in apps:
            a.stop()
        raise
    return apps
