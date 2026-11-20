"""Layer 4: fake or malicious packages (plan 2).

For every dependency in requirements*.txt / package.json: does it exist on the registry? When was it first
published? How many weekly downloads? Is its name one edit away from a hugely popular package?
Answers are cached on disk, so the inline hook and offline demos work without the network.

Policy (matches the inline hook): a package that does not exist is `critical` (AI tools invent names and attackers
register them); a package younger than 30 days is `high`; very low downloads or a typosquat-shaped name are
warnings. A registry that cannot be reached produces a note, never a finding.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import re
from functools import lru_cache
from pathlib import Path

from ..models import Finding, ToolRecord
from ..pkgcache import PackageCache, normalize
from ..redact import redact
from ..registry import RegistryClient
from .base import LayerResult, Runner, finding_id, iter_files, read_text, run_tool, short_hash

LAYER = 4
NEW_PACKAGE_DAYS = 30
LOW_DOWNLOADS = 100
ESTABLISHED_DAYS = 365
ESTABLISHED_DOWNLOADS = 10_000
_TOP_PATH = Path(__file__).resolve().parent.parent / "data" / "top_packages.json"

# ------------------------------------------------------------------------------------ manifests
_REQ_FILE = re.compile(r"requirements.*\.txt$")
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==|>=|<=|~=|!=|===|<|>|@|;|\s|$)")
_PKG_JSON_DEP = re.compile(r"""^\s*"((?:@[\w.-]+/)?[\w.-]+)"\s*:\s*"([^"]*)"\s*,?\s*$""")
_NON_REGISTRY = ("file:", "link:", "workspace:", "git", "http:", "https:", "npm:", "github:")


def dependency_lines(src: str, basename: str) -> list[tuple[str, str, int]]:
    """[(ecosystem, name, line)] for the registry packages named in a manifest."""
    out: list[tuple[str, str, int]] = []
    if _REQ_FILE.fullmatch(basename):
        for n, line in enumerate(src.splitlines(), start=1):
            s = line.strip()
            if not s or s.startswith(("#", "-", "git+")) or "://" in s.split(";")[0].split("@")[0]:
                continue
            m = _REQ_LINE.match(line)
            if m:
                out.append(("pypi", m.group(1), n))
    elif basename == "package.json":
        try:
            data = json.loads(src)
            names = {k for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                     for k, v in (data.get(sec) or {}).items() if isinstance(v, str) and not v.startswith(_NON_REGISTRY)}
            for n, line in enumerate(src.splitlines(), start=1):
                m = _PKG_JSON_DEP.match(line)
                if m and m.group(1) in names:
                    out.append(("npm", m.group(1), n))
        except (ValueError, AttributeError):
            for n, line in enumerate(src.splitlines(), start=1):  # a fragment of a manifest
                m = _PKG_JSON_DEP.match(line)
                if m and not m.group(2).startswith(_NON_REGISTRY) and m.group(1) not in ("name", "version", "main", "type"):
                    out.append(("npm", m.group(1), n))
    return out


# ------------------------------------------------------------------------------------ typosquat distance
@lru_cache(maxsize=1)
def top_packages() -> dict[str, set[str]]:
    data = json.loads(_TOP_PATH.read_text(encoding="utf-8"))
    return {eco: {normalize(eco, n) for n in data.get(eco, [])} for eco in ("pypi", "npm")}


def is_one_edit(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance exactly 1 (substitute, insert, delete, or swap two adjacent characters)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    s, t = (a, b) if la < lb else (b, a)  # s shorter by one
    i = 0
    while i < len(s) and s[i] == t[i]:
        i += 1
    return s[i:] == t[i + 1:]


def typosquat_target(eco: str, name: str, tops: dict[str, set[str]] | None = None) -> str | None:
    n = normalize(eco, name)
    if n.startswith("@") or len(n) < 4:  # scoped names and very short names produce only noise
        return None
    pool = (tops or top_packages())[eco]
    if n in pool:
        return None
    return next((t for t in sorted(pool) if len(t) >= 4 and is_one_edit(n, t)), None)


# ------------------------------------------------------------------------------------ evaluation
def _finding(rel: str, line: int, eco: str, name: str, rule: str, severity: str, confidence: str, title: str,
             plain: str) -> Finding:
    fp = f"sha256:{rule}|{rel}|{short_hash(eco + ':' + normalize(eco, name))}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category="supply-chain", rule=rule, cwe="CWE-829",
        severity=severity, confidence=confidence, title=redact(f"{title} ({rel}:{line})"), plain_words=redact(plain),
        location={"file": rel, "line": line}, sources=["proofgate-registry"], fix_tier=None,
        interrupt_human=severity == "critical",
    )


def evaluate_record(eco: str, name: str, rec: dict, rel: str, line: int, now: dt.datetime,
                    tops: dict[str, set[str]] | None = None, source: str | None = None) -> list[Finding]:
    """Findings for one dependency given its registry record. Pure: no I/O."""
    out: list[Finding] = []
    if rec.get("exists") is False:
        out.append(_finding(rel, line, eco, name, "package-does-not-exist", "critical", "high",
            f"Package '{name}' does not exist on {eco}",
            f"'{name}' is not a real package. AI tools sometimes invent names, and an attacker can register that name "
            "and ship malware. Remove it or use the real package."))
    else:
        first, downloads = rec.get("first_release"), rec.get("weekly_downloads")
        age_days = None
        if first:
            try:
                age_days = (now - dt.datetime.fromisoformat(first).replace(tzinfo=dt.timezone.utc)).days
            except ValueError:
                pass
        if age_days is not None and age_days < NEW_PACKAGE_DAYS:
            out.append(_finding(rel, line, eco, name, "package-very-new", "high", "medium",
                f"Package '{name}' was first published less than {NEW_PACKAGE_DAYS} days ago",
                f"'{name}' is brand new. New packages are a common way to deliver malware; check it is the one you meant."))
        if downloads is not None and downloads < LOW_DOWNLOADS:
            out.append(_finding(rel, line, eco, name, "package-low-downloads", "medium", "low",
                f"Package '{name}' has very few downloads ({downloads} last week)",
                f"Almost nobody downloads '{name}'. Check you spelled it right and that you trust its author."))
        established = (age_days is not None and age_days > ESTABLISHED_DAYS) or (
            downloads is not None and downloads >= ESTABLISHED_DOWNLOADS)
        target = None if established else typosquat_target(eco, name, tops)
        if target:
            out.append(_finding(rel, line, eco, name, "package-typosquat", "high", "medium",
                f"Package name '{name}' is one character away from the popular '{target}'",
                f"'{name}' looks like a misspelling of '{target}'. Attackers publish look-alike names to catch typos. "
                f"Did you mean '{target}'?"))
    if source:
        out = [f.model_copy(update={"sources": [source]}) for f in out]
    return out


# ------------------------------------------------------------------------------------ run
def _offline() -> bool:
    return os.environ.get("PROOFGATE_OFFLINE") == "1"


async def run(project_dir: str | Path, *, lock=None, runner: Runner = run_tool, cache: PackageCache | None = None,
              client: RegistryClient | None = None, offline: bool | None = None, now: dt.datetime | None = None,
              concurrency: int = 8, timeout: float = 120.0, tools_dir=None) -> LayerResult:
    project = Path(project_dir).resolve()
    offline = _offline() if offline is None else offline
    now = now or dt.datetime.now(dt.timezone.utc)
    cache = cache or PackageCache()
    result = LayerResult(layer=LAYER)

    deps: list[tuple[str, str, str, int]] = []  # (eco, name, rel file, line)
    for p in iter_files(project):
        if _REQ_FILE.fullmatch(p.name) or p.name == "package.json":
            text = read_text(p) or ""
            rel = p.relative_to(project).as_posix()
            deps += [(eco, name, rel, line) for eco, name, line in dependency_lines(text, p.name)]

    unique = sorted({(eco, normalize(eco, name)): (eco, name) for eco, name, _, _ in deps}.values())
    records: dict[tuple[str, str], dict] = {}
    missing: list[tuple[str, str]] = []
    for eco, name in unique:
        rec = cache.get(eco, name)
        if rec is not None:
            records[(eco, normalize(eco, name))] = rec
        else:
            missing.append((eco, name))

    if missing and offline:
        result.tools += [ToolRecord(name=f"{e}-registry", status="skipped") for e in sorted({e for e, _ in missing})]
        result.notes.append(f"registry: skipped: PROOFGATE_OFFLINE=1; {len(missing)} package(s) not in the cache: "
                            + ", ".join(n for _, n in missing[:10]) + (" ..." if len(missing) > 10 else ""))
    elif missing:
        rc = client or RegistryClient()
        sem = asyncio.Semaphore(concurrency)
        try:
            async def one(eco: str, name: str):
                async with sem:
                    return eco, name, await rc.lookup(eco, name)

            unreachable: list[str] = []
            for eco, name, rec in await asyncio.gather(*(one(e, n) for e, n in missing)):
                if rec is None:
                    unreachable.append(name)
                    continue
                records[(eco, normalize(eco, name))] = cache.put(eco, name, **rec)
            cache.save()
        finally:
            if client is None:
                await rc.aclose()
        for eco in sorted({e for e, _ in missing}):
            bad = [n for e, n in missing if e == eco and n in unreachable]
            result.tools.append(ToolRecord(name=f"{eco}-registry", status="error" if bad else "ok"))
        if unreachable:
            result.notes.append("registry: could not check (network error, not a finding): " + ", ".join(sorted(unreachable)))
    else:
        result.tools += [ToolRecord(name=f"{e}-registry", status="ok") for e in sorted({e for e, _ in unique})]

    tops = top_packages()
    seen: set[str] = set()
    for eco, name, rel, line in sorted(deps, key=lambda d: (d[2], d[3])):
        rec = records.get((eco, normalize(eco, name)))
        if rec is None:
            continue
        for f in evaluate_record(eco, name, rec, rel, line, now, tops):
            if f.id not in seen:
                seen.add(f.id)
                result.findings.append(f)

    await _guarddog(result, project, deps, runner, lock, timeout, tools_dir)
    return result


async def _guarddog(result: LayerResult, project: Path, deps, runner: Runner, lock, timeout, tools_dir) -> None:
    """Optional: GuardDog heuristics for malicious-package behaviour. Skipped (and recorded) when not installed."""
    if lock is None:
        try:
            from ..toollock import ToolLock

            lock = ToolLock.load()
        except Exception:  # noqa: BLE001
            return
    if "guarddog" not in lock.tools:
        return
    manifests = sorted({(eco, rel) for eco, _, rel, _ in deps})
    if not manifests:
        return
    for eco, rel in manifests:
        res = await runner("guarddog", [eco, "verify", str(project / rel), "--output-format", "json"],
                           lock=lock, timeout=timeout, tools_dir=tools_dir, cwd=project)
        result.tools.append(res.to_record())
        if res.status != "ok":
            result.notes.append(f"guarddog: {res.status}: {redact(res.reason)}")
            return
        try:
            result.findings += parse_guarddog(res.stdout, project / rel, rel, eco)
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            result.notes.append(f"guarddog: could not parse output: {redact(str(e))}")


def parse_guarddog(stdout: str, manifest: Path, rel: str, eco: str) -> list[Finding]:
    """Tolerant parser for `guarddog <eco> verify --output-format json` (pending real-tool verification)."""
    data = json.loads(stdout)
    entries = data if isinstance(data, list) else [data]
    text = (read_text(manifest) or "").splitlines()
    out: list[Finding] = []
    for e in entries:
        res = e.get("result", e) if isinstance(e, dict) else {}
        name = str(e.get("dependency") or e.get("package") or "")
        hits = {k: v for k, v in (res.get("results") or {}).items() if v}
        if not name or not hits:
            continue
        line = next((i for i, t in enumerate(text, start=1) if name.lower() in t.lower()), 1)
        out.append(_finding(
            rel, line, eco, name, "guarddog-suspicious-behaviour", "high", "medium",
            f"Package '{name}' shows suspicious behaviour ({', '.join(sorted(hits)[:3])})",
            f"The GuardDog scanner found behaviour in '{name}' that malicious packages often have: "
            + ", ".join(sorted(hits)) + ". Review it before installing.",
        ).model_copy(update={"sources": ["guarddog"]}))
    return out
