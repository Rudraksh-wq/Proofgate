"""Target guard (plan 3.2, 8): the probe attacks ONLY localhost, 127.0.0.0/8, ::1 and a throwaway temp database.

Anything else is refused unless the caller passes both a target URL and `--i-own-this`; that override is returned
so the report can log it. ProofGate never scans third-party apps.
"""
from __future__ import annotations

import ipaddress
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class TargetRefused(Exception):
    """The requested target is not local and no ownership override was given."""


@dataclass(frozen=True)
class TargetDecision:
    url: str
    host: str
    local: bool
    override: bool  # True when a non-local target was allowed only because of --i-own-this


def _is_local_host(host: str) -> bool:
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def check_target(url: str, *, i_own_this: bool = False) -> TargetDecision:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or not host:
        raise TargetRefused(f"not a valid http(s) target: {url!r}")
    local = _is_local_host(host)
    if local:
        return TargetDecision(url, host, True, False)
    if i_own_this:
        return TargetDecision(url, host, False, True)
    raise TargetRefused(
        f"refusing to attack {host!r}: ProofGate only probes localhost. "
        "If you own this target, pass --target <url> --i-own-this (the override is logged in the report)."
    )


def ensure_temp_db(path: str | Path) -> Path:
    """A database path is acceptable only inside the system temp directory (a throwaway database)."""
    p = Path(path).resolve()
    tmp = Path(tempfile.gettempdir()).resolve()
    try:
        p.relative_to(tmp)
    except ValueError:
        raise TargetRefused(f"refusing to use {p} as the probe database: it must live under {tmp}") from None
    return p
