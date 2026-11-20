"""Layer 1: secrets (plan 2).

Betterleaks (Gitleaks fallback) + a JWT role decoder + a placeholder filter + a small built-in
detector. The built-in part needs no external tool, so L1 still finds the obvious leaks when
Betterleaks is missing (the missing tool is recorded as skipped, never hidden).

Rules of the road:
* a Supabase `anon` key is public by design -> not a finding; `service_role` -> critical.
* placeholders (`changeme`, `your-key-here`, `xxxxxxxx`, `${ENV}`) are not findings.
* findings never carry the secret; the fingerprint holds only an 8-hex hash of it.

Tool flags follow the Gitleaks >= 8.19 CLI (Betterleaks is a drop-in): `dir <path> --report-format json
--report-path - --no-banner --redact --exit-code 0`. Verified only against recorded/synthetic output so
far: pending real-tool verification (see tests/fixtures/tool_outputs/README.md).
"""
from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, ToolRecord
from ..redact import redact
from .base import LayerResult, Runner, finding_id, iter_files, read_text, run_tool, short_hash

LAYER = 1

# ---------------------------------------------------------------------------- JWT role decoder
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def _b64json(part: str) -> dict | None:
    try:
        data = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def decode_jwt(token: str) -> dict | None:
    """Payload of a JWT-shaped token, or None. The signature is never checked (we only read the claims)."""
    parts = token.split(".")
    if len(parts) != 3 or _b64json(parts[0]) is None:
        return None
    return _b64json(parts[1])


def jwt_role(token: str) -> str | None:
    payload = decode_jwt(token)
    role = payload.get("role") if payload else None
    return role if isinstance(role, str) else None


# ---------------------------------------------------------------------------- placeholder filter
_PLACEHOLDER_WORDS = (
    "changeme", "change-me", "change_me", "your_", "your-", "yourkey", "example", "placeholder", "dummy",
    "replace_me", "replace-me", "replaceme", "redacted", "insert", "todo", "fixme", "sample", "<", ">",
    "${", "{{", "%(", "process.env", "os.environ", "getenv", "secret_here", "key_here", "token_here",
)
_FILLER = re.compile(r"^[xX*._\-0]{6,}$|(?:x{8,}|X{8,}|\*{6,}|0{10,})")
_LOW_VALUE = {"password", "secret", "test", "token", "apikey", "api_key", "none", "null", "undefined", "admin"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def is_placeholder(value: str, *, check_entropy: bool = True) -> bool:
    v = value.strip().strip("'\"`")
    low = v.lower()
    if not v or low in _LOW_VALUE:
        return True
    if any(w in low for w in _PLACEHOLDER_WORDS) or _FILLER.search(v):
        return True
    return check_entropy and len(v) >= 8 and _entropy(v) < 2.2


# ---------------------------------------------------------------------------- built-in rules
@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    severity: str
    confidence: str
    title: str
    plain: str
    entropy_check: bool = False


_ROTATE = " Move it to an environment variable and rotate it now: a key that was in code is already exposed."

BUILTIN_RULES: tuple[Rule, ...] = (
    Rule("stripe-live-secret-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}"), "critical", "high",
         "Live Stripe secret key in code",
         "A live Stripe secret key is written in your code; anyone who can read the code can move money." + _ROTATE),
    Rule("stripe-test-secret-key", re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}"), "medium", "high",
         "Stripe test secret key in code",
         "A Stripe test key is written in your code. It cannot move real money, but it should not live in code."),
    Rule("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high", "high",
         "AWS access key id in code", "An AWS access key id is written in your code." + _ROTATE),
    Rule("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"), "high", "high",
         "GitHub token in code", "A GitHub access token is written in your code." + _ROTATE),
    Rule("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "high", "high",
         "Slack token in code", "A Slack token is written in your code." + _ROTATE),
    Rule("google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"), "medium", "medium",
         "Google API key in code",
         "A Google API key is written in your code. Some are meant to be public; check what it can do."),
    Rule("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "critical", "high",
         "Private key in code", "A private key is written in your code." + _ROTATE),
)

SERVICE_ROLE = Rule(
    "supabase-service-role-key", JWT_RE, "critical", "high", "Supabase service_role key in code",
    "A Supabase service_role key bypasses all row-level security: whoever has it can read and change every row."
    + _ROTATE,
)
AUTHENTICATED_JWT = Rule(
    "jwt-user-session", JWT_RE, "medium", "medium", "A signed-in user's JWT is in code",
    "A JWT that belongs to a signed-in user is written in your code. Remove it and expire the session.",
)

_BOUNDARY = r"""["'`=:\s,(\[{]"""  # JWT must not be glued to an identifier


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _make_finding(rule: Rule, rel: str, line: int, secret: str, source: str, confirmed_by: int = 1) -> Finding:
    tag = short_hash(secret)
    fp = f"sha256:{rule.id}|{rel}|{tag}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category="secrets", rule=rule.id, cwe="CWE-798",
        severity=rule.severity, confidence=rule.confidence, title=f"{rule.title} ({rel}:{line})",
        plain_words=rule.plain, location={"file": rel, "line": line}, sources=[source], confirmed_by=confirmed_by,
        fix_tier="A", interrupt_human=rule.severity == "critical",
    )


def scan_text(text: str, rel_path: str) -> list[Finding]:
    """Built-in detection on one file's text. No subprocess, no network: also used by the inline hook."""
    out: list[Finding] = []
    for rule in BUILTIN_RULES:
        for m in rule.pattern.finditer(text):
            if is_placeholder(m.group(0), check_entropy=rule.entropy_check):
                continue
            out.append(_make_finding(rule, rel_path, _line_of(text, m.start()), m.group(0), "proofgate-builtin"))
    for m in JWT_RE.finditer(text):
        role = jwt_role(m.group(0))
        if role == "service_role":
            rule = SERVICE_ROLE
        elif role == "authenticated":
            rule = AUTHENTICATED_JWT
        else:  # anon = public by design; unknown/none = not a Supabase key we can judge
            continue
        out.append(_make_finding(rule, rel_path, _line_of(text, m.start()), m.group(0), "proofgate-jwt"))
    return out


# ---------------------------------------------------------------------------- Betterleaks / Gitleaks
@dataclass(frozen=True)
class RawLeak:
    rule_id: str
    file: str  # path relative to the project
    line: int
    start_col: int
    end_col: int
    secret: str  # value read from the source line (or the tool's field if it was not redacted)


_GENERIC_RULES = ("generic-api-key", "generic")
_RULE_SEVERITY = {
    "stripe-access-token": ("critical", "high"), "private-key": ("critical", "high"),
    "aws-access-token": ("high", "high"), "github-pat": ("high", "high"), "slack-bot-token": ("high", "high"),
    "gcp-api-key": ("medium", "medium"), "generic-api-key": ("medium", "low"),
}


def parse_leaks_json(stdout: str, project: Path) -> list[RawLeak]:
    """Gitleaks-format JSON report -> RawLeak. Values come from the source file, so --redact is safe."""
    stdout = stdout.strip()
    if not stdout:
        return []
    items = json.loads(stdout)
    if not isinstance(items, list):
        raise ValueError("report is not a JSON array")
    leaks: list[RawLeak] = []
    for it in items:
        rel = str(it.get("File", "")).replace("\\", "/")
        try:
            p = Path(rel) if Path(rel).is_absolute() else project / rel
            rel = p.resolve().relative_to(project.resolve()).as_posix()
        except (ValueError, OSError):
            continue  # outside the project: ignore
        line = int(it.get("StartLine") or 1)
        s_col, e_col = int(it.get("StartColumn") or 0), int(it.get("EndColumn") or 0)
        secret = str(it.get("Secret") or "")
        text = read_text(project / rel)
        if text is not None:
            lines = text.splitlines()
            if 0 < line <= len(lines):
                src = lines[line - 1]
                if secret in ("", "REDACTED") or "REDACTED" in secret:
                    secret = src[max(s_col - 1, 0):e_col] if s_col and e_col else src
                if not JWT_RE.search(secret) and JWT_RE.search(src):
                    secret = JWT_RE.search(src).group(0)  # column offsets can differ between tools
        leaks.append(RawLeak(str(it.get("RuleID", "unknown")), rel, line, s_col, e_col, secret))
    return leaks


def _leak_to_finding(leak: RawLeak, source: str) -> Finding | None:
    """Apply the JWT role decoder and placeholder filter to a tool finding (the precision bait: anon, changeme)."""
    jwt = JWT_RE.search(leak.secret)
    if jwt or leak.rule_id == "jwt":
        role = jwt_role(jwt.group(0)) if jwt else None
        if role == "service_role":
            return _make_finding(SERVICE_ROLE, leak.file, leak.line, jwt.group(0), source)
        if role == "authenticated":
            return _make_finding(AUTHENTICATED_JWT, leak.file, leak.line, jwt.group(0), source)
        return None  # anon / role-less JWTs are not secrets
    generic = leak.rule_id in _GENERIC_RULES
    if is_placeholder(_value_part(leak.secret), check_entropy=generic):
        return None
    sev, conf = _RULE_SEVERITY.get(leak.rule_id, ("medium", "medium"))
    rule = Rule(leak.rule_id, re.compile("$^"), sev, conf, f"Possible secret ({leak.rule_id})",
                "A value that looks like a secret is written in your code." + _ROTATE)
    return _make_finding(rule, leak.file, leak.line, leak.secret, source)


def _value_part(s: str) -> str:
    m = re.search(r"[:=]\s*(.+)$", s)
    return m.group(1) if m else s


def _text_files(project: Path):
    for p in iter_files(project, skip_names=lambda n: n == ".env" or (n.startswith(".env.") and n.endswith(".local"))):
        yield p


def merge(findings: list[Finding]) -> list[Finding]:
    """One finding per (file, line): keep the most severe, union the sources, count the tools that agree."""
    order = ["low", "medium", "high", "critical"]
    best: dict[tuple[str, int], Finding] = {}
    for f in findings:
        key = (f.location.file, f.location.line)
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        keep, other = (f, cur) if order.index(f.severity) > order.index(cur.severity) or (
            f.severity == cur.severity and f.sources[0].startswith("proofgate") and not cur.sources[0].startswith("proofgate")
        ) else (cur, f)
        sources = sorted(set(keep.sources) | set(other.sources))
        best[key] = keep.model_copy(update={"sources": sources, "confirmed_by": len(sources)})
    return sorted(best.values(), key=lambda f: (f.location.file, f.location.line, f.rule))


async def run(project_dir: str | Path, *, lock=None, runner: Runner = run_tool, timeout: float = 120.0) -> LayerResult:
    project = Path(project_dir).resolve()
    result = LayerResult(layer=LAYER)
    findings: list[Finding] = []

    for path in _text_files(project):
        text = read_text(path)
        if text:
            findings.extend(scan_text(text, path.relative_to(project).as_posix()))
    result.tools.append(ToolRecord(name="proofgate-builtin", status="ok"))

    tool_res = None
    for name in ("betterleaks", "gitleaks"):  # Betterleaks first; Gitleaks is the drop-in fallback
        res = await runner(
            name, ["dir", str(project), "--report-format", "json", "--report-path", "-", "--no-banner", "--redact",
                   "--exit-code", "0"],
            lock=lock, timeout=timeout,
        )
        result.tools.append(res.to_record())
        if res.status == "ok":
            tool_res = (name, res)
            break
        result.notes.append(f"{name}: {res.status}: {redact(res.reason)}")

    if tool_res:
        name, res = tool_res
        if res.returncode not in (0, 1):
            result.notes.append(f"{name} exited {res.returncode}; its findings were ignored: {redact(res.stderr[-300:])}")
        else:
            try:
                for leak in parse_leaks_json(res.stdout, project):
                    f = _leak_to_finding(leak, name)
                    if f:
                        findings.append(f)
            except (ValueError, json.JSONDecodeError) as e:
                result.notes.append(f"{name}: could not parse report: {redact(str(e))}")
    result.findings = merge(findings)
    return result
