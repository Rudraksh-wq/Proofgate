"""Accepted risks (plan 5.3): `.proofgate/accepted.yml`, the one file under `.proofgate/` that is committed.

A person (never an agent: there is no MCP tool for this) accepts a finding by its fingerprint with a reason, an owner and an expiry.

  * An accepted finding gets status `accepted-risk`, does not count toward `--fail-on`, and stays listed in report.json and report.html.
  * An expired entry is ignored: the finding comes back as `open`, and the report says why.
  * A finding that is PROVEN and critical is only accepted when the entry was written with `--force`; without it the finding stays open.
    Accepted proven criticals are always shown in the scan summary and the agent/hook output.
  * `// proofgate-ignore` comments and instructions found in code do nothing: only this file changes a finding's status.

The file is a small, strict subset of YAML so that no YAML library is needed at run time.
"""
from __future__ import annotations

import datetime as dt
import getpass
import json
import re
from pathlib import Path

from pydantic import ValidationError

from .models import ACCEPTED_SCHEMA, AcceptedRisk, AcceptedSummary, Finding

FILE_REL = ".proofgate/accepted.yml"
_HEADER = (
    "# ProofGate accepted risks. Commit this file: it records who accepted what, why, and until when.\n"
    "# Add entries with `proofgate accept <fingerprint> --reason \"...\" --expires 90d`. An agent must never run that command.\n"
)


class AcceptedError(Exception):
    """The file is not valid or an accept request is refused."""


def path_for(project: Path) -> Path:
    return Path(project) / FILE_REL


# ---------------------------------------------------------------------------------------------- file format
def _scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dt.date):
        return value.isoformat()
    return json.dumps(str(value), ensure_ascii=False)  # a JSON string is a valid YAML double-quoted scalar


def render(risks: list[AcceptedRisk]) -> str:
    out = [_HEADER, f"schema: {ACCEPTED_SCHEMA}\n", "accepted:" + (" []" if not risks else "") + "\n"]
    for r in risks:
        out.append(f"  - fingerprint: {_scalar(r.fingerprint)}\n")
        for key in ("reason", "owner", "expires", "forced", "created"):
            v = getattr(r, key)
            if v is not None:
                out.append(f"    {key}: {_scalar(v)}\n")
    return "".join(out)


def _unscalar(text: str, lineno: int):
    t = text.strip()
    if t.startswith('"'):
        try:
            return json.loads(t)
        except ValueError:
            raise AcceptedError(f"{FILE_REL} line {lineno}: bad quoted string")
    if t.startswith("'") and t.endswith("'") and len(t) >= 2:
        return t[1:-1].replace("''", "'")
    if t in ("true", "false"):
        return t == "true"
    return t  # bare word: a date or plain text; the model validates it


def parse(text: str) -> list[AcceptedRisk]:
    entries: list[dict] = []
    cur: dict | None = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("schema:"):
            if _unscalar(line.split(":", 1)[1], n) != ACCEPTED_SCHEMA:
                raise AcceptedError(f"{FILE_REL}: unknown schema (expected {ACCEPTED_SCHEMA})")
            continue
        if re.fullmatch(r"accepted:\s*(\[\])?", line):
            continue
        m = re.fullmatch(r"\s+-\s+(\w+):\s*(.*)", line)
        if m:
            cur = {m.group(1): _unscalar(m.group(2), n)}
            entries.append(cur)
            continue
        m = re.fullmatch(r"\s{4}(\w+):\s*(.*)", line)
        if m and cur is not None:
            cur[m.group(1)] = _unscalar(m.group(2), n)
            continue
        raise AcceptedError(f"{FILE_REL} line {n}: cannot read this line (keep the format `proofgate accept` writes)")
    out = []
    for e in entries:
        try:
            out.append(AcceptedRisk.model_validate(e))
        except ValidationError as err:
            raise AcceptedError(f"{FILE_REL}: invalid entry for {e.get('fingerprint', '?')}: {err.errors()[0]['msg']}")
    return out


def load(project: Path) -> list[AcceptedRisk]:
    p = path_for(project)
    if not p.is_file():
        return []
    try:
        return parse(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise AcceptedError(f"cannot read {FILE_REL}: {e}")


def save(project: Path, risks: list[AcceptedRisk]) -> Path:
    p = path_for(project)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render(risks), encoding="utf-8", newline="\n")
    return p


# ---------------------------------------------------------------------------------------------- adding
def needs_force(f: Finding) -> bool:
    return bool(f.proven and f.severity == "critical")


def add(project: Path, fingerprint: str, *, reason: str, expires: dt.date, owner: str | None = None, force: bool = False,
        finding: Finding | None = None, today: dt.date | None = None) -> AcceptedRisk:
    """Record an accepted risk. `finding` (when known from the last report) lets us require --force for a proven critical."""
    today = today or dt.date.today()
    if not reason.strip():
        raise AcceptedError("--reason is required: say why this risk is acceptable")
    if expires <= today:
        raise AcceptedError("--expires must be in the future")
    if finding is not None and needs_force(finding) and not force:
        raise AcceptedError(f"{finding.title.split(' (')[0]} is a PROVEN critical problem: data was actually exposed. "
                            "Accepting it needs --force, and it will be shown in every summary.")
    risk = AcceptedRisk(fingerprint=fingerprint, reason=reason.strip(), owner=owner or _default_owner(), expires=expires,
                        forced=force, created=today)
    existing = [r for r in load(project) if r.fingerprint != fingerprint]  # one entry per fingerprint: the new one replaces the old
    save(project, existing + [risk])
    return risk


def _default_owner() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------------------------------- applying
def apply(findings: list[Finding], risks: list[AcceptedRisk], *, today: dt.date | None = None
          ) -> tuple[list[Finding], list[AcceptedSummary], list[str]]:
    """Mark accepted findings. Returns (findings, accepted summaries, notes). Findings are never removed."""
    today = today or dt.date.today()
    by_fp = {r.fingerprint: r for r in risks}
    out: list[Finding] = []
    accepted: list[AcceptedSummary] = []
    notes: list[str] = []
    used: set[str] = set()
    for f in findings:
        risk = by_fp.get(f.fingerprint or "")
        if risk is None or f.status in ("fixed",):
            out.append(f)
            continue
        used.add(risk.fingerprint)
        title = f.title.split(" (")[0]
        if risk.is_expired(today):
            notes.append(f"accepted risk for '{title}' expired on {risk.expires.isoformat()}: it is open again")
            out.append(f)
        elif needs_force(f) and not risk.forced:
            notes.append(f"accepted risk for '{title}' ignored: the finding is proven and critical, and the entry was not made with --force")
            out.append(f)
        else:
            out.append(f.model_copy(update={"status": "accepted-risk"}))
            accepted.append(AcceptedSummary(
                fingerprint=risk.fingerprint, finding_id=f.id, title=title, severity=f.severity, proven=f.proven, reason=risk.reason,
                owner=risk.owner, expires=risk.expires, forced=risk.forced))
    for fp, risk in by_fp.items():
        if fp not in used and risk.is_expired(today):
            notes.append(f"accepted risk {fp[:24]} expired on {risk.expires.isoformat()}")
    return out, accepted, notes


def forced_lines(accepted: list[AcceptedSummary]) -> list[str]:
    """Always-shown warnings for accepted risks that are proven criticals."""
    return [f"ACCEPTED RISK (proven critical, forced by {a.owner} until {a.expires.isoformat()}): {a.title}. Reason given: {a.reason}"
            for a in accepted if a.forced and a.proven and a.severity == "critical"]
