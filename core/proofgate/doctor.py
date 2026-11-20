"""`proofgate doctor`: verify tools against tools.lock.json; `--pin` records a trusted binary."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from .runner import exec_binary
from .toollock import ToolLock, find_binary, platform_key, sha256_file, verify_tool


@dataclass(frozen=True)
class ToolCheck:
    name: str
    status: str  # ok | missing | unpinned | mismatch
    version: str | None
    detail: str


async def _version(path: Path, args: list[str]) -> str | None:
    res = await exec_binary(path, args, name="version", timeout=15)
    text = (res.stdout or res.stderr).strip().splitlines()
    return text[0].strip() if res.status == "ok" and text else None


async def check_all(lock: ToolLock, tools_dir=None) -> list[ToolCheck]:
    out: list[ToolCheck] = []
    for name, entry in sorted(lock.tools.items()):
        v = verify_tool(name, lock, tools_dir)
        version = None
        status, detail = v.status, v.reason
        if v.status == "ok" and v.path:
            version = await _version(v.path, entry.version_args)
            if entry.verify == "sha256" and entry.version and version and entry.version != version:
                status, detail = "mismatch", f"version {version!r} differs from pinned {entry.version!r}"
        out.append(ToolCheck(name, status, version, detail))
    return out


def pin_tool(name: str, lock: ToolLock, tools_dir=None) -> ToolCheck:
    """Record the SHA-256 and version of the binary currently found. A deliberate human action."""
    entry = lock.tools.get(name)
    if entry is None:
        raise KeyError(f"unknown tool {name!r}; known: {', '.join(sorted(lock.tools))}")
    path = find_binary(entry.binary, tools_dir)
    if path is None:
        raise FileNotFoundError(f"{entry.binary} not found on PATH or in PROOFGATE_TOOLS_DIR")
    version = asyncio.run(_version(path, entry.version_args))
    entry.version = version
    if entry.verify == "sha256":
        entry.sha256[platform_key()] = sha256_file(path)
    return ToolCheck(name, "ok", version, f"pinned {path}")
