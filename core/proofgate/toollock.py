"""tools.lock.json: pin every external binary by version + SHA-256 (plan 2, 8).

Policy: a binary runs only if it is pinned AND its SHA-256 matches. Unpinned or
mismatched binaries are refused and recorded; they are never run silently.
The shipped lock has no hashes: run `proofgate doctor --pin <tool>` after installing a
tool you trust. Hashes are per platform (`sys.platform-machine`), so a team on mixed
machines can share one lock.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

LOCK_SCHEMA = "proofgate.tools.lock/v1"
DEFAULT_LOCK_PATH = Path(__file__).with_name("tools.lock.json")


def platform_key() -> str:
    return f"{sys.platform}-{platform.machine()}"


class ToolEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    binary: str
    version: str | None = None
    sha256: dict[str, str] = Field(default_factory=dict)  # platform_key -> hex digest
    verify: Literal["sha256", "presence"] = "sha256"  # "presence": system tools we cannot pin (docker, node)
    version_args: list[str] = Field(default_factory=lambda: ["--version"])


class ToolLock(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: Literal["proofgate.tools.lock/v1"] = Field(LOCK_SCHEMA, alias="schema")
    tools: dict[str, ToolEntry] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "ToolLock":
        p = path or Path(os.environ.get("PROOFGATE_TOOLS_LOCK") or DEFAULT_LOCK_PATH)
        return cls.model_validate(json.loads(p.read_text(encoding="utf-8")))

    def save(self, path: Path | None = None) -> Path:
        p = path or Path(os.environ.get("PROOFGATE_TOOLS_LOCK") or DEFAULT_LOCK_PATH)
        text = json.dumps(self.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n"
        p.write_text(text, encoding="utf-8", newline="\n")
        return p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_binary(binary: str, tools_dir: str | os.PathLike | None = None) -> Path | None:
    """Look in PROOFGATE_TOOLS_DIR first, then PATH. An absolute path is used as-is."""
    p = Path(binary)
    if p.is_absolute():
        return p if p.is_file() else None
    tdir = tools_dir if tools_dir is not None else os.environ.get("PROOFGATE_TOOLS_DIR")
    if tdir:
        hit = shutil.which(binary, path=str(tdir))
        if hit:
            return Path(hit)
    hit = shutil.which(binary)
    return Path(hit) if hit else None


@dataclass(frozen=True)
class Verification:
    status: Literal["ok", "missing", "unpinned", "mismatch"]
    path: Path | None = None
    sha256: str | None = None
    expected: str | None = None
    reason: str = ""


def verify_tool(name: str, lock: ToolLock, tools_dir: str | os.PathLike | None = None) -> Verification:
    entry = lock.tools.get(name)
    if entry is None:
        return Verification("unpinned", reason=f"{name} is not listed in tools.lock.json")
    path = find_binary(entry.binary, tools_dir)
    if path is None:
        return Verification("missing", reason=f"{entry.binary} not found on PATH or in PROOFGATE_TOOLS_DIR")
    if entry.verify == "presence":
        return Verification("ok", path=path, reason="presence-only (system tool)")
    actual = sha256_file(path)
    expected = entry.sha256.get(platform_key())
    if expected is None:
        return Verification(
            "unpinned", path=path, sha256=actual,
            reason=f"no SHA-256 pinned for {platform_key()}; run `proofgate doctor --pin {name}`",
        )
    if actual.lower() != expected.lower():
        return Verification(
            "mismatch", path=path, sha256=actual, expected=expected,
            reason=f"SHA-256 differs from tools.lock.json for {path}",
        )
    return Verification("ok", path=path, sha256=actual, expected=expected)
