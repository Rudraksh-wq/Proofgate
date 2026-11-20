"""Layer 3: dependencies with known vulnerabilities (plan 2).

OSV-Scanner (offline DB capable) + pip-audit + npm audit. One finding per (manifest, package, version),
aggregated over every advisory, with `fixed_in` = the lowest version that fixes all of them (Tier A input).

Offline mode (`PROOFGATE_OFFLINE=1`): pip-audit and npm audit need the network, so they are skipped and
recorded; OSV-Scanner runs with `--offline` against its downloaded database.

Severity: npm and OSV give one; pip-audit does not, so a pip-audit-only finding is `medium` until OSV refines it.
Never dishonest: an unknown severity is never rounded up to high.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding, ToolRecord
from ..redact import redact
from .base import SKIP_DIRS, LayerResult, Runner, finding_id, iter_files, read_text, run_tool, short_hash

LAYER = 3
_SEV_ORDER = ["low", "medium", "high", "critical"]
_NPM_SEV = {"info": "low", "low": "low", "moderate": "medium", "medium": "medium", "high": "high", "critical": "critical"}
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)\s*(?:;.*)?(?:#.*)?$")
_REQ_FILE = re.compile(r"requirements.*\.txt$")


# ------------------------------------------------------------------------------------ versions
def _vkey(v: str):
    try:
        from packaging.version import Version

        return (0, Version(v))
    except Exception:  # noqa: BLE001 - not PEP 440 / odd semver: fall back to numeric parts
        return (1, tuple(int(x) for x in re.findall(r"\d+", v)) or (0,))


def _gt(a: str, b: str) -> bool:
    ka, kb = _vkey(a), _vkey(b)
    return ka > kb if ka[0] == kb[0] else a > b


def _ge(a: str, b: str) -> bool:
    return a == b or _gt(a, b)


def lowest_fix(fix_versions: list[str], installed: str) -> str | None:
    """The smallest advertised fix that is at or above the installed version."""
    ok = [f for f in fix_versions if _ge(f, installed)]
    if not ok:
        return None
    best = ok[0]
    for f in ok[1:]:
        if _gt(best, f):
            best = f
    return best


def highest(versions: list[str | None]) -> str | None:
    vs = [v for v in versions if v]
    if not vs:
        return None
    best = vs[0]
    for v in vs[1:]:
        if _gt(v, best):
            best = v
    return best


# ------------------------------------------------------------------------------------ raw model
@dataclass
class PkgVuln:
    ecosystem: str  # pypi | npm | ...
    name: str
    version: str
    file: str  # manifest, relative to the project
    ids: list[str] = field(default_factory=list)
    severity: str | None = None
    fixed_in: str | None = None
    source: str = ""


def _max_sev(*sevs: str | None) -> str | None:
    known = [s for s in sevs if s in _SEV_ORDER]
    return max(known, key=_SEV_ORDER.index) if known else None


def _cvss_level(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _rel(path: str, project: Path) -> str | None:
    try:
        p = Path(path)
        p = p if p.is_absolute() else project / p
        return p.resolve().relative_to(project.resolve()).as_posix()
    except (ValueError, OSError):
        return None


# ------------------------------------------------------------------------------------ pip-audit
def pinned_requirements(text: str) -> tuple[list[tuple[str, str, int]], list[str]]:
    """([(name, version, line)], [unpinned names]) for one requirements file."""
    pinned, unpinned = [], []
    for n, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith(("#", "-")) or "://" in s:
            continue
        m = _PIN.match(line)
        if m:
            pinned.append((m.group(1), m.group(2), n))
        else:
            name = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", s)
            if name:
                unpinned.append(name.group(0))
    return pinned, unpinned


def parse_pip_audit(stdout: str, rel_file: str) -> list[PkgVuln]:
    out: list[PkgVuln] = []
    for dep in json.loads(stdout).get("dependencies", []):
        vulns = dep.get("vulns") or []
        if not vulns:
            continue
        version = str(dep.get("version", ""))
        ids = []
        for v in vulns:
            ids += [x for x in [v.get("id"), *v.get("aliases", [])] if x and str(x).startswith(("CVE-", "GHSA-", "PYSEC-"))][:2]
        out.append(PkgVuln(
            "pypi", str(dep["name"]), version, rel_file, sorted(set(ids)), None,
            highest([lowest_fix(v.get("fix_versions") or [], version) for v in vulns]), "pip-audit"))
    return out


# ------------------------------------------------------------------------------------ npm audit
def parse_npm_audit(stdout: str, rel_lock: str, installed: dict[str, str]) -> list[PkgVuln]:
    out: list[PkgVuln] = []
    for name, v in (json.loads(stdout).get("vulnerabilities") or {}).items():
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        ids = sorted({Path(a.get("url", "")).name for a in advisories if a.get("url")})
        fix = v.get("fixAvailable")
        out.append(PkgVuln(
            "npm", str(name), installed.get(name, "?"), rel_lock, ids,
            _max_sev(_NPM_SEV.get(str(v.get("severity", "")).lower()), *(_NPM_SEV.get(str(a.get("severity", "")).lower()) for a in advisories)),
            fix.get("version") if isinstance(fix, dict) else None, "npm-audit"))
    return out


def lock_versions(lock_text: str) -> dict[str, str]:
    try:
        pk = json.loads(lock_text).get("packages", {})
    except ValueError:
        return {}
    return {k.rsplit("node_modules/", 1)[-1]: v.get("version", "?") for k, v in pk.items() if k.startswith("node_modules/")}


# ------------------------------------------------------------------------------------ osv-scanner
_ECO = {"pypi": "pypi", "npm": "npm"}


def parse_osv(stdout: str, project: Path) -> list[PkgVuln]:
    out: list[PkgVuln] = []
    for res in json.loads(stdout).get("results", []):
        rel = _rel(str(res.get("source", {}).get("path", "")), project)
        if rel is None:
            continue
        for pk in res.get("packages", []):
            vulns = pk.get("vulnerabilities") or []
            if not vulns:
                continue
            info = pk.get("package", {})
            name, version = str(info.get("name", "")), str(info.get("version", ""))
            eco = _ECO.get(str(info.get("ecosystem", "")).lower(), str(info.get("ecosystem", "")).lower())
            scores = [float(g["max_severity"]) for g in pk.get("groups", []) if _is_num(g.get("max_severity"))]
            text_sev = [_NPM_SEV.get(str((v.get("database_specific") or {}).get("severity", "")).lower()) for v in vulns]
            sev = _max_sev(*(_cvss_level(s) for s in scores), *text_sev)
            fixes = []
            for v in vulns:
                cand = [e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
                fixes.append(lowest_fix(cand, version) if version else None)
            ids = sorted({x for v in vulns for x in [v.get("id"), *[a for a in v.get("aliases", []) if str(a).startswith("CVE-")]] if x})
            out.append(PkgVuln(eco, name, version, rel, ids, sev, highest(fixes), "osv-scanner"))
    return out


def _is_num(x) -> bool:
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


# ------------------------------------------------------------------------------------ aggregate -> Findings
def _dep_line(project: Path, rel: str, name: str) -> int:
    text = read_text(project / rel)
    if not text:
        return 1
    pat = re.compile(rf"""^\s*"?{re.escape(name)}"?\s*(?:==|>=|<=|~=|:|\[|$|"\s*:)""", re.IGNORECASE) \
        if _REQ_FILE.search(rel) else re.compile(rf'"node_modules/{re.escape(name)}"|"{re.escape(name)}"\s*:')
    for n, line in enumerate(text.splitlines(), start=1):
        if pat.search(line):
            return n
    return 1


def to_findings(items: list[PkgVuln], project: Path) -> list[Finding]:
    merged: dict[tuple[str, str, str, str], PkgVuln] = {}
    srcs: dict[tuple[str, str, str, str], set[str]] = {}
    for it in items:
        key = (it.file, it.ecosystem, it.name.lower(), it.version)
        cur = merged.get(key)
        if cur is None:
            merged[key] = PkgVuln(it.ecosystem, it.name, it.version, it.file, list(it.ids), it.severity, it.fixed_in, it.source)
            srcs[key] = {it.source}
        else:
            cur.ids = sorted(set(cur.ids) | set(it.ids))
            cur.severity = _max_sev(cur.severity, it.severity)
            cur.fixed_in = highest([cur.fixed_in, it.fixed_in])
            srcs[key].add(it.source)
    findings: list[Finding] = []
    for key, p in sorted(merged.items()):
        n = len(p.ids) or 1
        shown = ", ".join(p.ids[:3]) + (f" and {len(p.ids) - 3} more" if len(p.ids) > 3 else "")
        line = _dep_line(project, p.file, p.name)
        fp = f"sha256:known-vulnerable-dependency|{p.file}|{short_hash(p.ecosystem + ':' + p.name.lower())}"
        fix_txt = f" Upgrade to {p.fixed_in} or newer." if p.fixed_in else " No fixed version is published yet."
        findings.append(Finding(
            id=finding_id(fp), fingerprint=fp, layer=LAYER, category="deps", rule="known-vulnerable-dependency",
            cwe="CWE-1395", severity=p.severity or "medium", confidence="high",
            title=redact(f"{p.name} {p.version} has known vulnerabilities ({p.file}:{line})"),
            plain_words=redact(f"{p.name} {p.version} has publicly known security holes ({shown})." + fix_txt),
            location={"file": p.file, "line": line}, sources=sorted(srcs[key]), confirmed_by=len(srcs[key]),
            fix_tier="A" if p.fixed_in else None, fixed_in=p.fixed_in,
        ))
    return findings


# ------------------------------------------------------------------------------------ run
def _offline() -> bool:
    return os.environ.get("PROOFGATE_OFFLINE") == "1"


def osv_args(project: Path, offline: bool) -> list[str]:
    return ["scan", "source", "-r", str(project), "--format", "json"] + (["--offline"] if offline else [])


async def run(project_dir: str | Path, *, lock=None, runner: Runner = run_tool, timeout: float = 180.0,
              tools_dir=None, offline: bool | None = None) -> LayerResult:
    project = Path(project_dir).resolve()
    offline = _offline() if offline is None else offline
    result = LayerResult(layer=LAYER)
    items: list[PkgVuln] = []
    kw = dict(lock=lock, timeout=timeout, tools_dir=tools_dir)

    req_files = [p for p in iter_files(project) if _REQ_FILE.search(p.name)]
    lock_files = [p for p in iter_files(project) if p.name == "package-lock.json"]

    # --- OSV-Scanner (works offline against its local database)
    res = await runner("osv-scanner", osv_args(project, offline), cwd=project, **kw)
    result.tools.append(res.to_record())
    if res.status != "ok":
        result.notes.append(f"osv-scanner: {res.status}: {redact(res.reason)}")
    elif res.returncode in (0, 1) and res.stdout.strip():  # 1 = vulnerabilities found
        _parse(result, "osv-scanner", lambda: parse_osv(res.stdout, project), items)
    elif res.returncode not in (0, 1):
        result.notes.append(f"osv-scanner exited {res.returncode}: {redact(res.stderr[-300:])}")

    # --- pip-audit (network)
    if req_files and offline:
        result.tools.append(ToolRecord(name="pip-audit", status="skipped"))
        result.notes.append("pip-audit: skipped: PROOFGATE_OFFLINE=1 (needs the network)")
    elif req_files:
        for req in req_files:
            rel = req.relative_to(project).as_posix()
            pinned, unpinned = pinned_requirements(read_text(req) or "")
            if unpinned:
                result.notes.append(f"pip-audit: {rel}: not audited (not pinned with ==): {', '.join(unpinned)}")
            if not pinned:
                continue
            with tempfile.TemporaryDirectory(prefix="proofgate-pipaudit-") as td:
                tmp = Path(td) / "requirements.txt"
                tmp.write_text("\n".join(f"{n}=={v}" for n, v, _ in pinned) + "\n", encoding="utf-8")
                res = await runner("pip-audit", ["-r", str(tmp), "--no-deps", "--disable-pip", "-f", "json",
                                                 "--progress-spinner", "off"], cwd=project, **kw)
            result.tools.append(res.to_record())
            _handle(result, res, "pip-audit", lambda r=res, f=rel: parse_pip_audit(r.stdout, f), items)

    # --- npm audit (network; needs a lockfile)
    if (project / "package.json").exists() and not lock_files:
        result.notes.append("npm audit: not run: no package-lock.json (run `npm install --package-lock-only`)")
    if lock_files and offline:
        result.tools.append(ToolRecord(name="npm", status="skipped"))
        result.notes.append("npm audit: skipped: PROOFGATE_OFFLINE=1 (needs the network)")
    else:
        for lf in lock_files:
            rel = lf.relative_to(project).as_posix()
            res = await runner("npm", ["audit", "--json", "--package-lock-only"], cwd=lf.parent, **kw)
            result.tools.append(res.to_record())
            versions = lock_versions(read_text(lf) or "")
            _handle(result, res, "npm audit", lambda r=res, f=rel, v=versions: parse_npm_audit(r.stdout, f, v), items)

    result.findings = to_findings(items, project)
    return result


def _handle(result: LayerResult, res, label: str, parse, items: list[PkgVuln]) -> None:
    if res.status != "ok":
        result.notes.append(f"{label}: {res.status}: {redact(res.reason)}")
    elif res.returncode not in (0, 1):
        result.notes.append(f"{label} exited {res.returncode}: {redact(res.stderr[-300:])}")
    elif res.stdout.strip():
        _parse(result, label, parse, items)


def _parse(result: LayerResult, label: str, parse, items: list[PkgVuln]) -> None:
    try:
        items.extend(parse())
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        result.notes.append(f"{label}: could not parse output: {redact(str(e))}")
