"""Shared pieces for every layer adapter."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Iterator

from ..models import Finding, ToolRecord
from ..runner import ToolResult, run_tool

# Async callable with run_tool's signature; tests inject a fake that returns recorded tool output.
Runner = Callable[..., Awaitable[ToolResult]]

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".proofgate", ".pytest_cache", ".mypy_cache",
    ".tox", ".idea", ".vscode", "site-packages",
}
MAX_FILE_BYTES = 1_000_000


@dataclass
class LayerResult:
    layer: int
    findings: list[Finding] = field(default_factory=list)
    tools: list[ToolRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # e.g. "betterleaks skipped: not installed"
    # filled by the probe layer (L8) only
    tested_tables: list[str] = field(default_factory=list)
    tested_routes: list[str] = field(default_factory=list)
    untested: list[str] = field(default_factory=list)
    receipt_counts: tuple[int, int] | None = None  # (contract rules attacked, rules held)
    target_overrides: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)


def finding_id(fingerprint: str) -> str:
    return "f_" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:8]


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def iter_files(root: Path, *, skip_names: Callable[[str], bool] | None = None) -> Iterator[Path]:
    """Text-ish files under `root`, skipping vendored/build dirs and oversized files. Symlinks are not followed."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if skip_names and skip_names(name):
                continue
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def read_text(path: Path) -> str | None:
    """UTF-8 text, or None for binary/unreadable files."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


__all__ = ["LayerResult", "Runner", "run_tool", "finding_id", "short_hash", "iter_files", "read_text", "SKIP_DIRS"]
