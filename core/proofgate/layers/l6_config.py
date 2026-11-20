"""Layer 6: configuration and infrastructure-as-code (plan 2).

Own checks (no tool needed):
  env-file-committed             a `.env` / `.env.*` file that git would commit (not `.env.example`, `.sample`, `.template`)
  next-public-secret-name        a `NEXT_PUBLIC_*` name containing SERVICE, SECRET or PRIVATE: Next.js copies it into the browser bundle
  cors-wildcard-with-credentials `Access-Control-Allow-Origin: *` together with credentials: true
  next-production-source-maps    `productionBrowserSourceMaps: true` in next.config.*

Checkov (Terraform, Dockerfile, Kubernetes, GitHub Actions...) runs when installed and is skipped and recorded when it is not.
Its adapter is tested against recorded sample output: pending real-tool verification.
"""
from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import tempfile
from pathlib import Path

from ..models import Finding, ToolRecord
from ..redact import redact
from .base import LayerResult, Runner, finding_id, iter_files, read_text, run_tool

LAYER = 6
SOURCE = "proofgate-config"
_ENV_FILE = re.compile(r"^\.env(\..+)?$")
_ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.IGNORECASE)
_PUBLIC_NAME = re.compile(r"\bNEXT_PUBLIC_[A-Z0-9_]*(SERVICE|SECRET|PRIVATE)[A-Z0-9_]*")
_CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".json", ".yml", ".yaml", ".toml"}
_CORS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}  # not yaml/json: Semgrep rule files quote these patterns as text
_ORIGIN_STAR = re.compile(r"""(?:origins?|Access-Control-Allow-Origin)["']?\s*[:=,(]\s*\[?\s*["']\*["']""", re.IGNORECASE)
_CRED_TRUE = re.compile(
    r"""(?:supports_credentials|credentials|Access-Control-Allow-Credentials)["']?\s*[:=,(]?\s*(?:value\s*:\s*)?["']?(?:true|True)\b""", re.IGNORECASE)
_SOURCE_MAPS = re.compile(r"productionBrowserSourceMaps\s*:\s*true")


def _finding(rule: str, rel: str, line: int, key: str, *, severity, title: str, plain: str, cwe: str | None, fix_tier=None) -> Finding:
    fp = f"sha256:{rule}|{rel}|{key}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category="config", rule=rule, cwe=cwe, severity=severity, confidence="high",
        title=f"{title} ({rel}:{line})", plain_words=plain, location={"file": rel, "line": line}, sources=[SOURCE], fix_tier=fix_tier,
        interrupt_human=severity == "critical",
    )


# ---------------------------------------------------------------------------- is this file committed?
def _gitignore_patterns(project: Path) -> list[str]:
    text = read_text(project / ".gitignore") or ""
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", "!"))]


def is_committed(project: Path, rel: str) -> bool:
    """True when git would commit the file. Uses git when the folder is a repository, otherwise the project's .gitignore."""
    try:
        r = subprocess.run(["git", "-C", str(project), "check-ignore", "-q", "--", rel], capture_output=True, timeout=10)
        inside = subprocess.run(["git", "-C", str(project), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True, timeout=10)
        if inside.returncode == 0 and inside.stdout.strip() == "true":
            if r.returncode == 0:
                return False
            tracked = subprocess.run(["git", "-C", str(project), "ls-files", "--error-unmatch", "--", rel], capture_output=True, timeout=10)
            return tracked.returncode == 0 or r.returncode == 1
    except (OSError, subprocess.SubprocessError):
        pass
    name = rel.rsplit("/", 1)[-1]
    for pat in _gitignore_patterns(project):
        pat = pat.rstrip("/")
        if fnmatch.fnmatch(name, pat.lstrip("/")) or fnmatch.fnmatch(rel, pat.lstrip("/")):
            return False
    return True


def _has_values(text: str) -> bool:
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#") and "=" in ln and ln.split("=", 1)[1].strip().strip("\"'"):
            return True
    return False


# ---------------------------------------------------------------------------- own checks
def check_env_files(project: Path) -> list[Finding]:
    out = []
    for p in sorted(project.rglob(".env*")):
        if not p.is_file() or not _ENV_FILE.match(p.name) or _ENV_TEMPLATE.search(p.name):
            continue
        if any(part in {"node_modules", ".git", ".venv", ".next"} for part in p.relative_to(project).parts):
            continue
        rel = p.relative_to(project).as_posix()
        if not is_committed(project, rel):
            continue
        filled = _has_values(read_text(p) or "")
        out.append(_finding(
            "env-file-committed", rel, 1, "file", severity="high" if filled else "low", cwe="CWE-538", fix_tier="A",
            title="Environment file is not git-ignored",
            plain=(f"{rel} {'holds values and ' if filled else ''}is not ignored by git, so it can be committed and pushed. Add it to .gitignore, "
                   "keep only a .env.example with empty values, and rotate anything that was already committed.")))
    return out


def check_public_names(project: Path) -> list[Finding]:
    out, seen = [], set()
    for p in iter_files(project):
        is_env = bool(_ENV_FILE.match(p.name))
        if not is_env and p.suffix not in _CODE_EXT:
            continue
        rel = p.relative_to(project).as_posix()
        for i, line in enumerate((read_text(p) or "").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue  # a comment that mentions the name is not a use of it
            for m in _PUBLIC_NAME.finditer(line):
                if (rel, m.group(0)) in seen:
                    continue
                seen.add((rel, m.group(0)))
                critical = "SERVICE" in m.group(0)
                out.append(_finding(
                    "next-public-secret-name", rel, i, m.group(0), severity="critical" if critical else "high", cwe="CWE-200", fix_tier="A",
                    title=f"{m.group(0)} is exposed to the browser",
                    plain=("Next.js copies every NEXT_PUBLIC_ variable into the JavaScript sent to all visitors, so a secret under this name is public. "
                           "Rename it without the NEXT_PUBLIC_ prefix, use it only in server code, and rotate the key.")))
    return out


def check_cors(project: Path) -> list[Finding]:
    out = []
    for p in iter_files(project):
        if p.suffix not in _CORS_EXT:
            continue
        text = read_text(p) or ""
        if "redentials" not in text or "rigin" not in text:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not _ORIGIN_STAR.search(line):
                continue
            window = "\n".join(lines[max(0, i - 12): i + 13])
            if _CRED_TRUE.search(window):
                rel = p.relative_to(project).as_posix()
                out.append(_finding(
                    "cors-wildcard-with-credentials", rel, i + 1, "cors", severity="high", cwe="CWE-942", fix_tier="C",
                    title="Any website may call this API with the visitor's login",
                    plain=("The API allows every origin (*) and also allows credentials, so a malicious page can make requests as a signed-in "
                           "visitor. List the exact origins you trust instead of *.")))
                break
    return out


def check_source_maps(project: Path) -> list[Finding]:
    out = []
    for p in iter_files(project):
        if not p.name.startswith("next.config."):
            continue
        for i, line in enumerate((read_text(p) or "").splitlines(), 1):
            if _SOURCE_MAPS.search(line) and not line.lstrip().startswith(("//", "*")):
                rel = p.relative_to(project).as_posix()
                out.append(_finding(
                    "next-production-source-maps", rel, i, "maps", severity="medium", cwe="CWE-540", fix_tier="A",
                    title="Production source maps are switched on",
                    plain="productionBrowserSourceMaps: true publishes your original source code next to the browser bundle. Remove it or set it to false."))
    return out


# ---------------------------------------------------------------------------- Checkov (SARIF)
_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


def parse_checkov_sarif(text: str, project: Path) -> list[Finding]:
    data = json.loads(text)
    runs = data if isinstance(data, list) else data.get("runs", [])  # a bare list = several Checkov outputs; accept both
    out: list[Finding] = []
    for run in runs:
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = (loc.get("artifactLocation") or {}).get("uri", "")
            rel = uri.replace("file:///", "").replace("\\", "/").lstrip("/")
            try:
                rel = Path(rel).resolve().relative_to(project).as_posix() if Path(rel).is_absolute() else rel
            except ValueError:
                pass
            line = int((loc.get("region") or {}).get("startLine", 1) or 1)
            rid = str(r.get("ruleId", "checkov"))
            msg = (r.get("message") or {}).get("text", rid)
            fp = f"sha256:checkov:{rid}|{rel}|{line}"
            out.append(Finding(
                id=finding_id(fp), fingerprint=fp, layer=LAYER, category="config", rule=f"checkov:{rid}",
                severity=_LEVEL.get(str(r.get("level", "warning")).lower(), "medium"), confidence="medium",
                title=redact(f"{msg[:110]} ({rel}:{line})"), plain_words=redact(msg), location={"file": rel, "line": line}, sources=["checkov"]))
    return out


async def _checkov(project: Path, runner: Runner, lock, timeout: float, result: LayerResult) -> list[Finding]:
    with tempfile.TemporaryDirectory(prefix="proofgate-checkov-") as td:
        res = await runner("checkov", ["-d", str(project), "-o", "sarif", "--output-file-path", td, "--quiet", "--compact",
                                       "--skip-path", "node_modules", "--skip-path", ".next", "--skip-path", ".venv"],
                           lock=lock, timeout=timeout, cwd=project)
        result.tools.append(res.to_record())
        if res.status != "ok":
            result.notes.append(f"checkov: {res.status}: {redact(res.reason)}")
            return []
        if res.returncode not in (0, 1):  # 1 = checks failed
            result.notes.append(f"checkov exited {res.returncode}: {redact(res.stderr[-300:])}")
            return []
        sarif = Path(td) / "results.sarif"
        text = sarif.read_text(encoding="utf-8") if sarif.exists() else res.stdout
        if not text.strip():
            return []
        try:
            return parse_checkov_sarif(text, project)
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            result.notes.append(f"checkov: could not parse output: {redact(str(e))}")
            return []


async def run(project_dir: str | Path, *, lock=None, runner: Runner = run_tool, timeout: float = 120.0, **_ignored) -> LayerResult:
    project = Path(project_dir).resolve()
    result = LayerResult(layer=LAYER)
    result.tools.append(ToolRecord(name="proofgate-config", status="ok"))
    for check in (check_env_files, check_public_names, check_cors, check_source_maps):
        result.findings += check(project)
    result.findings += await _checkov(project, runner, lock, timeout, result)
    result.findings.sort(key=lambda f: (f.location.file, f.location.line, f.rule))
    return result
