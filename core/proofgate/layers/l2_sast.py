"""Layer 2: SAST (plan 2).

* Semgrep CE with `--metrics=off` and ProofGate's own rules (core/proofgate/rules/*.yaml). Extra rules
  you already have locally are read from `$PROOFGATE_TOOLS_DIR/semgrep-rules` if that folder exists.
  We never bundle third-party rule packs (Semgrep Rules License).
* Bandit for Python.

Missing tools are recorded as skipped. Findings never include the matched source text beyond what
the redactor allows, and the severity ceiling here is `high`: only a proof (L8) makes something critical.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..models import Finding, ToolRecord
from ..redact import redact
from .base import LayerResult, Runner, finding_id, read_text, run_tool, short_hash

LAYER = 2
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
BANDIT_SKIP = {"B101"}  # assert_used: a code-quality note, not a security finding
EXCLUDE_GLOBS = ["*/.venv/*", "*/venv/*", "*/node_modules/*", "*/.git/*", "*/.proofgate/*", "*/__pycache__/*"]

_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_LEVEL = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_CWE_NUM = re.compile(r"CWE-(\d+)")

_CATEGORY_BY_CWE = {
    78: "injection", 89: "injection", 94: "injection", 95: "injection", 22: "injection", 502: "injection",
    918: "injection", 1336: "injection", 79: "web", 295: "web", 327: "web", 326: "web", 330: "web", 942: "config",
    798: "secrets", 259: "secrets", 489: "config", 16: "config", 200: "config", 1188: "config", 306: "access",
    862: "access", 863: "access", 639: "access", 347: "access", 285: "access",
}
_BANDIT_PLAIN = {
    "B602": "The app starts a program through a shell. If any part of that command comes from a visitor, they can run commands on your server.",
    "B605": "The app starts a shell command from a string. If it contains user text, a visitor can run commands.",
    "B608": "A database query is assembled from text. If any piece comes from a visitor, they can change what the query does.",
    "B201": "Flask debug mode is on, which exposes an interactive debugger.",
    "B501": "The app talks to another server without checking its certificate.",
    "B105": "A password or key is written in the code.",
    "B106": "A password or key is passed as a literal value in the code.",
    "B107": "A password or key is the default value of a parameter in the code.",
}


def semgrep_rule_dirs(tools_dir: str | os.PathLike | None = None) -> list[Path]:
    dirs = [RULES_DIR]
    base = tools_dir if tools_dir is not None else os.environ.get("PROOFGATE_TOOLS_DIR")
    if base and (Path(base) / "semgrep-rules").is_dir():
        dirs.append(Path(base) / "semgrep-rules")
    return dirs


def semgrep_args(project: Path, rule_dirs: list[Path]) -> list[str]:
    args = ["--metrics=off", "--json", "--quiet", "--disable-version-check", "--no-git-ignore"]
    for d in rule_dirs:
        args += ["--config", str(d)]
    return args + [str(project)]


def bandit_args(project: Path) -> list[str]:
    return ["-r", str(project), "-f", "json", "-q", "--exit-zero", "-x", ",".join(EXCLUDE_GLOBS)]


def _rel(path: str, project: Path) -> str | None:
    try:
        p = Path(path)
        p = p if p.is_absolute() else project / p
        return p.resolve().relative_to(project.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _line_text(project: Path, rel: str, line: int) -> str:
    text = read_text(project / rel)
    lines = text.splitlines() if text else []
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def _cwes(raw) -> list[str]:
    items = raw if isinstance(raw, list) else [raw] if raw else []
    return [f"CWE-{m.group(1)}" for it in items if (m := _CWE_NUM.search(str(it)))]


def _category(meta_category, cwe: str | None) -> str:
    valid = {"secrets", "injection", "access", "deps", "supply-chain", "database", "config", "web", "bundle"}
    if meta_category in valid:
        return meta_category
    if cwe and (m := _CWE_NUM.fullmatch(cwe)):
        return _CATEGORY_BY_CWE.get(int(m.group(1)), "config")
    return "config"


def _build(rule: str, rel: str, line: int, text_for_fp: str, *, category: str, cwe: str | None, severity: str,
           confidence: str, title: str, plain: str, source: str, fix_tier: str | None) -> Finding:
    fp = f"sha256:{rule}|{rel}|{short_hash(text_for_fp or str(line))}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category=category, rule=rule, cwe=cwe, severity=severity,
        confidence=confidence, title=redact(f"{title} ({rel}:{line})"), plain_words=redact(plain),
        location={"file": rel, "line": line}, sources=[source], fix_tier=fix_tier,
    )


def parse_semgrep(stdout: str, project: Path) -> list[Finding]:
    data = json.loads(stdout)
    out: list[Finding] = []
    for r in data.get("results", []):
        rel = _rel(r.get("path", ""), project)
        if rel is None:
            continue
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        line = int(r.get("start", {}).get("line", 1))
        check_id = str(r.get("check_id", "semgrep"))
        own = re.search(r"(proofgate\.[A-Za-z0-9_-]+)$", check_id)  # semgrep prefixes ids with the rules path
        rule = own.group(1) if own else check_id.rsplit(".", 1)[-1]
        source = f"proofgate-rule:{rule.split('.', 1)[1]}" if own else "semgrep"
        cwes = _cwes(meta.get("cwe"))
        cwe = cwes[0] if cwes else None
        msg = str(extra.get("message", rule))
        out.append(_build(
            rule, rel, line, _line_text(project, rel, line),
            category=_category(meta.get("category"), cwe), cwe=cwe,
            severity=_SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "medium"),
            confidence=_LEVEL.get(str(meta.get("confidence", "")).upper(), "medium"),
            title=msg.split(".")[0][:120], plain=str(meta.get("plain_words") or msg), source=source,
            fix_tier=meta.get("fix_tier") if meta.get("fix_tier") in ("A", "B", "C") else None,
        ))
    return out


def parse_bandit(stdout: str, project: Path) -> list[Finding]:
    data = json.loads(stdout)
    out: list[Finding] = []
    for r in data.get("results", []):
        test_id = str(r.get("test_id", ""))
        if test_id in BANDIT_SKIP:
            continue
        rel = _rel(r.get("filename", ""), project)
        if rel is None:
            continue
        line = int(r.get("line_number", 1))
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        cwe = f"CWE-{cwe_id}" if cwe_id else None
        text = str(r.get("issue_text", test_id))
        out.append(_build(
            f"bandit-{test_id}", rel, line, _line_text(project, rel, line), category=_category(None, cwe), cwe=cwe,
            severity=_LEVEL.get(str(r.get("issue_severity", "")).upper(), "medium"),
            confidence=_LEVEL.get(str(r.get("issue_confidence", "")).upper(), "medium"),
            title=text.split(".")[0][:120], plain=_BANDIT_PLAIN.get(test_id, f"The Bandit scanner flagged this line: {text}"),
            source="bandit", fix_tier=None,
        ))
    return out


async def _run_one(name, args, parser, project, result: LayerResult, runner: Runner, lock, timeout, tools_dir):
    res = await runner(name, args, lock=lock, timeout=timeout, tools_dir=tools_dir, cwd=project)
    result.tools.append(res.to_record())
    if res.status != "ok":
        result.notes.append(f"{name}: {res.status}: {redact(res.reason)}")
        return []
    if res.returncode not in (0, 1):
        result.notes.append(f"{name} exited {res.returncode}: {redact(res.stderr[-300:])}")
        return []
    try:
        return parser(res.stdout, project)
    except (ValueError, json.JSONDecodeError, TypeError, AttributeError) as e:
        result.notes.append(f"{name}: could not parse output: {redact(str(e))}")
        return []


def builtin_findings(project: Path) -> list[Finding]:
    """The same Python-AST and JS checks the inline hook runs (rules mirror rules/*.yaml), over the whole project."""
    from ..inline import js_findings, python_findings
    from .base import iter_files

    out: list[Finding] = []
    for p in iter_files(project):
        rel = p.relative_to(project)
        if "tests" in rel.parts[:-1] or "test" in rel.parts[:-1]:
            continue
        text = read_text(p) if p.suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs") else None
        if not text:
            continue
        out += python_findings(text, rel.as_posix()) if p.suffix == ".py" else js_findings(text, rel.as_posix())
    return out


async def run(project_dir: str | Path, *, lock=None, runner: Runner = run_tool, timeout: float = 300.0,
              tools_dir=None) -> LayerResult:
    project = Path(project_dir).resolve()
    result = LayerResult(layer=LAYER)
    findings: list[Finding] = []
    findings += await _run_one("semgrep", semgrep_args(project, semgrep_rule_dirs(tools_dir)), parse_semgrep,
                               project, result, runner, lock, timeout, tools_dir)
    findings += await _run_one("bandit", bandit_args(project), parse_bandit, project, result, runner, lock,
                               timeout, tools_dir)
    findings += builtin_findings(project)  # ProofGate's own AST/JS checks: no external tool needed
    result.tools.append(ToolRecord(name="proofgate-inline", status="ok"))
    seen: set[tuple[str, int, str]] = set()
    for f in sorted(findings, key=lambda f: (f.location.file, f.location.line, f.rule)):
        key = (f.location.file, f.location.line, f.rule)
        if key not in seen:
            seen.add(key)
            result.findings.append(f)
    return result
