"""Disk cache of package-registry answers, so L4 works offline and the inline hook never touches the network.

Records: {"exists": bool, "first_release": ISO date | None, "weekly_downloads": int | None, "checked_at": ISO}.
Writers: the registry client (feat/10) and tests. Readers: the inline hook and L4.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any

Record = dict[str, Any]
DEFAULT_TTL = dt.timedelta(days=7)


def normalize(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def default_path() -> Path:
    base = os.environ.get("PROOFGATE_CACHE_DIR")
    return Path(base) / "packages.json" if base else Path.home() / ".cache" / "proofgate" / "packages.json"


class PackageCache:
    def __init__(self, path: Path | None = None, ttl: dt.timedelta = DEFAULT_TTL):
        self.path = Path(path) if path else default_path()
        self.ttl = ttl
        self._data: dict[str, Record] | None = None

    def _load(self) -> dict[str, Record]:
        if self._data is None:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self._data = raw if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                self._data = {}
        return self._data

    @staticmethod
    def _key(ecosystem: str, name: str) -> str:
        return f"{ecosystem}:{normalize(ecosystem, name)}"

    def get(self, ecosystem: str, name: str, *, allow_stale: bool = False) -> Record | None:
        rec = self._load().get(self._key(ecosystem, name))
        if rec is None:
            return None
        if not allow_stale:
            try:
                age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(rec["checked_at"])
                if age > self.ttl:
                    return None
            except (KeyError, ValueError):
                return None
        return rec

    def put(self, ecosystem: str, name: str, *, exists: bool, first_release: str | None = None,
            weekly_downloads: int | None = None) -> Record:
        rec: Record = {
            "exists": exists, "first_release": first_release, "weekly_downloads": weekly_downloads,
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        }
        self._load()[self._key(ecosystem, name)] = rec
        return rec

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._load(), indent=1, sort_keys=True), encoding="utf-8", newline="\n")
        tmp.replace(self.path)
