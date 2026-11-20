"""Async external-tool runner. It never raises: every failure becomes a ToolResult.

Missing tool -> status "skipped". Unpinned/mismatched -> refused, not run. Timeout -> the
whole process tree is killed. Callers decide what a non-zero exit code means
(scanners often use 1 for "found something").
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Sequence

from .models import ToolRecord
from .toollock import ToolLock, verify_tool

Status = Literal["ok", "skipped", "mismatch", "unpinned", "timeout", "error"]
MAX_OUTPUT_BYTES = 20 * 1024 * 1024


@dataclass(frozen=True)
class ToolResult:
    name: str
    status: Status
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    reason: str = ""
    path: str | None = None
    sha256: str | None = None

    @property
    def ran(self) -> bool:
        return self.status == "ok"

    def to_record(self, version: str | None = None) -> ToolRecord:
        status = "ok" if self.status == "ok" else self.status
        return ToolRecord(name=self.name, version=version, sha256=self.sha256, status=status)  # type: ignore[arg-type]


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True, check=False, timeout=10,
            )
        else:
            import signal

            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:  # noqa: BLE001 - best effort
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


async def exec_binary(
    path: Path | str,
    args: Sequence[str],
    *,
    name: str,
    cwd: str | os.PathLike | None = None,
    timeout: float = 60.0,
    env: Mapping[str, str] | None = None,
    stdin: str | None = None,
    sha256: str | None = None,
) -> ToolResult:
    """Run an already-resolved binary. Use `run_tool` unless you verified the binary yourself."""
    started = time.monotonic()
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        proc = await asyncio.create_subprocess_exec(
            str(path), *args,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )
    except Exception as e:  # noqa: BLE001
        return ToolResult(name, "error", reason=f"could not start: {e}", path=str(path), sha256=sha256,
                          duration_s=time.monotonic() - started)
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout=timeout
        )
    except asyncio.TimeoutError:
        _kill_tree(proc)
        try:
            await asyncio.wait_for(proc.communicate(), timeout=5)
        except Exception:  # noqa: BLE001
            pass
        return ToolResult(name, "timeout", reason=f"killed after {timeout:g}s", path=str(path), sha256=sha256,
                          duration_s=time.monotonic() - started)
    except Exception as e:  # noqa: BLE001
        _kill_tree(proc)
        return ToolResult(name, "error", reason=f"run failed: {e}", path=str(path), sha256=sha256,
                          duration_s=time.monotonic() - started)
    return ToolResult(
        name, "ok", proc.returncode,
        out[:MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
        err[:MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
        time.monotonic() - started, path=str(path), sha256=sha256,
    )


async def run_tool(
    name: str,
    args: Sequence[str] = (),
    *,
    lock: ToolLock | None = None,
    cwd: str | os.PathLike | None = None,
    timeout: float = 60.0,
    env: Mapping[str, str] | None = None,
    stdin: str | None = None,
    tools_dir: str | os.PathLike | None = None,
) -> ToolResult:
    try:
        lock = lock or ToolLock.load()
        v = verify_tool(name, lock, tools_dir)
    except Exception as e:  # noqa: BLE001 - a broken lock file must not crash a scan
        return ToolResult(name, "error", reason=f"tools.lock.json unreadable: {e}")
    if v.status == "missing":
        return ToolResult(name, "skipped", reason=v.reason)
    if v.status in ("unpinned", "mismatch"):
        return ToolResult(name, v.status, reason=v.reason, path=str(v.path) if v.path else None, sha256=v.sha256)
    return await exec_binary(v.path, args, name=name, cwd=cwd, timeout=timeout, env=env, stdin=stdin,
                             sha256=v.sha256)


def run_tool_sync(name: str, args: Sequence[str] = (), **kw) -> ToolResult:
    return asyncio.run(run_tool(name, args, **kw))
