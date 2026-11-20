"""Merge, de-duplicate and rank findings from every layer (plan 5, Master Guide P1 step 5).

Two findings are the same issue when
  1. their fingerprints are equal, or
  2. they are in the same file, within 2 lines, with the same CWE (or equivalent CWE family; or, if either
     lacks a CWE, the same category) AND come from different tools. Two findings from the same tool family are
     never merged this way: the tool already decided they are separate (e.g. two different keys on adjacent lines).

Merged findings keep the most severe representative, union their sources, set `confirmed_by`, and are ranked
proven > confirmed by several tools > single tool. Counts: raw (before merging) -> unique -> proven.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding

SEV = ["low", "medium", "high", "critical"]
CONF = ["low", "medium", "high", "proven"]
LINE_WINDOW = 2

# CWEs that describe the same weakness for the purpose of merging two tools' reports
_CWE_FAMILY = {
    **dict.fromkeys(["CWE-259", "CWE-321", "CWE-798"], "hardcoded-credential"),
    **dict.fromkeys(["CWE-77", "CWE-78", "CWE-88"], "command-injection"),
    **dict.fromkeys(["CWE-89", "CWE-564"], "sql-injection"),
    **dict.fromkeys(["CWE-94", "CWE-95", "CWE-96"], "code-injection"),
    **dict.fromkeys(["CWE-79", "CWE-80"], "xss"),
    **dict.fromkeys(["CWE-22", "CWE-23", "CWE-36"], "path-traversal"),
    **dict.fromkeys(["CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863"], "access-control"),
}

# which tool "family" produced a source; findings of one family are never merged by the fallback key
_FAMILY_EXACT = {
    "proofgate-builtin": "secrets-scanner", "proofgate-jwt": "secrets-scanner", "betterleaks": "secrets-scanner",
    "gitleaks": "secrets-scanner", "trufflehog": "secrets-scanner", "semgrep": "semgrep", "proofgate-inline": "semgrep",
    "bandit": "bandit", "pip-audit": "dep-audit", "osv-scanner": "dep-audit", "npm-audit": "dep-audit",
    "proofgate-registry": "registry", "guarddog": "guarddog", "proofgate-probe": "probe",
}


def tool_family(source: str) -> str:
    if source.startswith("proofgate-rule:"):
        return "semgrep"
    return _FAMILY_EXACT.get(source, source)


def _families(f: Finding) -> set[str]:
    return {tool_family(s) for s in f.sources}


def _same_weakness(a: Finding, b: Finding) -> bool:
    if a.cwe and b.cwe:
        return a.cwe == b.cwe or (_CWE_FAMILY.get(a.cwe) is not None and _CWE_FAMILY.get(a.cwe) == _CWE_FAMILY.get(b.cwe))
    return a.category == b.category


def _fallback_match(a: Finding, b: Finding) -> bool:
    return (
        a.location.file == b.location.file
        and abs(a.location.line - b.location.line) <= LINE_WINDOW
        and _same_weakness(a, b)
        and not (_families(a) & _families(b))
    )


def _merge_into(base: Finding, other: Finding) -> Finding:
    """Combine two findings of the same issue."""
    rep, rest = (base, other) if _rank_key_repr(base) <= _rank_key_repr(other) else (other, base)
    sources = sorted(set(base.sources) | set(other.sources))
    proven = base.proven or other.proven
    update: dict = {
        "sources": sources,
        "confirmed_by": len(sources),
        "severity": max(base.severity, other.severity, key=SEV.index),
        "proven": proven,
        "confidence": "proven" if proven else max(base.confidence or "high", other.confidence or "high", key=CONF.index),
        "evidence": rep.evidence or rest.evidence,
        "fixed_in": rep.fixed_in or rest.fixed_in,
        "fix_tier": rep.fix_tier or rest.fix_tier,
        "cwe": rep.cwe or rest.cwe,
        "contract_rule": rep.contract_rule or rest.contract_rule,
        "contract_confirmed": rep.contract_confirmed or rest.contract_confirmed,
    }
    return rep.model_copy(update=update)


def _rank_key_repr(f: Finding) -> tuple:
    """Which of two findings becomes the representative: proven first, then severity, then confidence, then layer."""
    return (not f.proven, -SEV.index(f.severity), -CONF.index(f.confidence or "high"), f.layer, f.rule)


def rank_key(f: Finding) -> tuple:
    return (not f.proven, f.confirmed_by < 2, -SEV.index(f.severity), f.location.file, f.location.line, f.rule)


def _finalise(f: Finding) -> Finding:
    # only proven or critical findings interrupt the human (Master Guide P1 step 5)
    return f.model_copy(update={"interrupt_human": f.proven or f.severity == "critical"})


@dataclass(frozen=True)
class Normalized:
    findings: list[Finding]
    raw_warning_count: int
    unique_count: int
    proven_count: int


def normalize(raw: list[Finding]) -> Normalized:
    # 1. exact fingerprint merge
    by_fp: dict[str, Finding] = {}
    nofp: list[Finding] = []
    for f in raw:
        if not f.fingerprint:
            nofp.append(f)
        elif f.fingerprint in by_fp:
            by_fp[f.fingerprint] = _merge_into(by_fp[f.fingerprint], f)
        else:
            by_fp[f.fingerprint] = f
    candidates = sorted([*by_fp.values(), *nofp], key=lambda f: (f.location.file, f.location.line, f.layer, f.rule))

    # 2. fallback key: (file, line +- 2, weakness), only across different tool families
    clusters: list[Finding] = []
    for f in candidates:
        for i, c in enumerate(clusters):
            if _fallback_match(c, f):
                clusters[i] = _merge_into(c, f)
                break
        else:
            clusters.append(f)

    final = sorted((_finalise(c) for c in clusters), key=rank_key)
    return Normalized(final, len(raw), len(final), sum(1 for f in final if f.proven))
