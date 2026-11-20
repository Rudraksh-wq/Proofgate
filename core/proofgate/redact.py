"""Redactor (plan 5.1, 8): no log line, hook message, MCP reply, report field or LLM payload may
contain a raw secret or a full canary.

* secrets  -> «SECRET:<type>:<8 hex of sha256>»   (same secret -> same hash, so it stays correlatable)
* canaries -> PGCANARY_A_«masked»

`redact` is idempotent and never raises on odd input.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
from typing import Any, Callable, Iterable

from pydantic import BaseModel

SECRET_MARK = "\u00abSECRET:"  # «SECRET:
CANARY_RE = re.compile(r"PGCANARY_([A-Za-z0-9]+)_([A-Za-z0-9]{4,})")
_MASKED_CANARY = re.compile(r"PGCANARY_[A-Za-z0-9]+_\u00abmasked\u00bb")


def new_canary(actor: str) -> str:
    """A fresh unguessable canary for one identity, e.g. PGCANARY_A_7f3c9a1b."""
    return f"PGCANARY_{actor}_{secrets.token_hex(4)}"


def _tag(kind: str, value: str) -> str:
    return f"\u00abSECRET:{kind}:{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:8]}\u00bb"


# (type, pattern). Whole match is replaced unless the pattern has a group named `v`.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("supabase-secret-key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")),  # sb_publishable_ is public by design and is not masked
    ("stripe-key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("db-url-password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<v>[^\s@/]{3,})@")),
    ("bearer", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/=-]{16,})")),
    (
        "env-secret",
        re.compile(
            r"""(?P<k>["']?[A-Za-z0-9_.-]{0,40}(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|service[_-]?role)"""
            r"""[A-Za-z0-9_.-]{0,40}["']?\s*[:=]\s*["']?)(?P<v>[^\s"'#,}\)]{8,})""",
            re.IGNORECASE,
        ),
    ),
]
_PROTECTED = re.compile("«SECRET:[a-z0-9-]+:[0-9a-f]{8}»|PGCANARY_[A-Za-z0-9]+_«masked»")
_REFERENCE_PREFIXES = ("\ue000", "os.", "process.", "env.", "getenv", "${", "$(", "<", "\u00ab", "import.meta", "config.", "settings.")


def _looks_like_reference(value: str) -> bool:
    low = value.lower()
    return low.startswith(_REFERENCE_PREFIXES) or "environ" in low


def _sub(kind: str, pat: re.Pattern[str]) -> Callable[[re.Match[str]], str]:
    def repl(m: re.Match[str]) -> str:
        if "v" in pat.groupindex:
            value = m.group("v")
            if value.startswith("\u00abSECRET:") or (kind == "env-secret" and _looks_like_reference(value)):
                return m.group(0)
            s, e = m.span("v")
            return m.group(0)[: s - m.start()] + _tag(kind, value) + m.group(0)[e - m.start():]
        return _tag(kind, m.group(0))

    return repl


def _protect(text: str, saved: list[str] | None = None) -> tuple[str, list[str]]:
    """Swap masked tokens for placeholders so later patterns cannot re-match inside them."""
    saved = [] if saved is None else saved

    def keep(m: re.Match[str]) -> str:
        saved.append(m.group(0))
        return f"\ue000{len(saved) - 1}\ue000"

    return _PROTECTED.sub(keep, text), saved


def _restore(text: str, saved: list[str]) -> str:
    return re.sub("\ue000(\\d+)\ue000", lambda m: saved[int(m.group(1))], text)


def redact(text: str) -> str:
    """Mask secrets and canaries in `text`. Non-str input is returned untouched."""
    if not isinstance(text, str) or not text:
        return text
    out = CANARY_RE.sub(lambda m: f"PGCANARY_{m.group(1)}_«masked»", text)
    out, saved = _protect(out)
    for kind, pat in _PATTERNS:
        out = pat.sub(_sub(kind, pat), out)
        out, saved = _protect(out, saved)  # fresh tags must not be re-matched by later patterns
    return _restore(out, saved)


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings inside dicts, lists, tuples and pydantic models (returns a copy)."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, BaseModel):
        return obj.__class__.model_validate(redact_obj(obj.model_dump(mode="json", by_alias=True)))
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_obj(v) for v in obj)
    return obj


def excerpt(text: str, limit: int = 200) -> str:
    """Redact first, then truncate, so a cut can never expose half of a secret."""
    r = redact(text)
    return r if len(r) <= limit else r[: limit - 1] + "\u2026"


def find_leaks(text: str, *, secrets_: Iterable[str] = (), canaries: Iterable[str] = ()) -> list[str]:
    """Return what leaked into `text`: any listed raw secret/canary, plus any unmasked canary or
    secret pattern. Empty list = clean. Used by tests (and the T10 no-leak check)."""
    leaks = [s for s in list(secrets_) + list(canaries) if s and s in text]
    for m in CANARY_RE.finditer(text):
        if not _MASKED_CANARY.fullmatch(m.group(0)) and m.group(2) != "\u00abmasked\u00bb":
            leaks.append(m.group(0))
    leaks += [m for m in _unmasked_secret_hits(text)]
    return sorted(set(leaks))


def _unmasked_secret_hits(text: str) -> list[str]:
    hits = []
    text, _ = _protect(text)
    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            value = m.group("v") if "v" in pat.groupindex else m.group(0)
            if value.startswith("\u00abSECRET:") or (kind == "env-secret" and _looks_like_reference(value)):
                continue
            hits.append(value)
    return hits


class RedactingFilter(logging.Filter):
    """Attach to a logger or handler so every record is redacted before it is formatted."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:  # noqa: BLE001 - logging must not fail
            pass
        return True


def install_logging_filter(logger: logging.Logger | None = None) -> None:
    target = logger or logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for f in target.filters):
        target.addFilter(RedactingFilter())
    for h in target.handlers:
        if not any(isinstance(f, RedactingFilter) for f in h.filters):
            h.addFilter(RedactingFilter())
