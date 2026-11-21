"""classify -> Tier A codemod | Tier B contract template -> tournament (plan 4).

Tier C (Gemini) arrives in feat/19. Nothing here applies a patch to the real project: the winning diff is returned and
the caller (a human or the user's own AI agent) applies it. `verify_patch` runs a patch somebody else wrote through the
very same gates.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from ..models import Contract, Finding, FixResult
from .patching import PatchError, diff_stats
from .tier_a import tier_a_patch
from .tier_b import tier_b_patch
from .tournament import Baseline, Candidate, compute_baseline, run_tournament

TIER_A_HINTS = ("sql-injection", "shell-true", "os-system", "command-injection", "flask-debug-true", "verify-false",
                "known-vulnerable-dependency", "B608", "B602", "B605", "B201", "B501")
TIER_B_HINTS = ("cross-user-", "admin-route", "mass-assignment", "rls-disabled", "policy-", "service-role", "uid-is-null")


def classify(finding: Finding) -> str:
    """A: deterministic codemod. B: contract template. C: needs the LLM (or a human)."""
    if finding.layer == 1 or finding.layer == 3 or any(h in finding.rule for h in TIER_A_HINTS):
        return "A"
    if any(h in finding.rule for h in TIER_B_HINTS):
        return "B"
    return "C"


def pre_fix_commit(project: Path) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(project), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        return (r.stdout.strip() or None) if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def deterministic_candidates(project: Path, finding: Finding, contract: Contract) -> tuple[list[Candidate], str | None]:
    """(candidates, learned rule). Empty list when no template fits: the finding is `needs-human` (or Tier C)."""
    tier = classify(finding)
    attempts = []
    if tier == "A":
        attempts.append(("A", lambda: tier_a_patch(project, finding)))
        if finding.layer == 8:
            attempts.append(("B", lambda: tier_b_patch(project, finding, contract)))
    elif tier == "B":
        attempts.append(("B", lambda: tier_b_patch(project, finding, contract)))
    if tier != "A" and finding.layer == 8 and finding.category == "injection":
        attempts.insert(0, ("A", lambda: tier_a_patch(project, finding)))
    out: list[Candidate] = []
    learned = None
    for t, make in attempts:
        try:
            res = make()
        except (SyntaxError, PatchError):
            res = None
        if res and res[0]:
            out.append(Candidate(res[0], t, f"tier-{t.lower()}-template"))
            learned = learned or res[1]
    return out, learned


async def fix_finding(project: str | Path, finding: Finding, contract: Contract, *, extra: list[Candidate] | None = None,
                      baseline: Baseline | None = None, tier_c: bool = True, gemini=None, break_fix: bool = False) -> FixResult:
    """Deterministic candidates first; Tier C (Gemini, paid key, redacted) only when no template fits."""
    project = Path(project).resolve()
    cands, learned = deterministic_candidates(project, finding, contract)
    cands += extra or []
    notes: list[str] = []
    if not cands and tier_c:
        from ..ai.tier_c import tier_c_candidates

        tc = await tier_c_candidates(project, finding, contract, client=gemini)
        cands += tc.candidates
        notes += [f"tier C discarded an answer: {d}" for d in tc.discarded]
        if tc.skipped:
            notes.append(tc.skipped)
    if not cands:
        return FixResult(
            finding_id=finding.id, tier=classify(finding), candidates=0, winner=None,
            gates={"exploit_blocked": False, "feature_works": False, "tests_pass": False, "no_new_findings": False,  # type: ignore[arg-type]
                   "diff_is_small": False},
            rejected=[{"reason": f"no deterministic fix exists for {finding.rule}: needs a human or Tier C"}],  # type: ignore[list-item]
            accepted=False, pre_fix_commit=pre_fix_commit(project), notes=notes)
    result = await run_tournament(project, finding, cands, contract, baseline=baseline, learned_rule=learned,
                                  pre_fix_commit=pre_fix_commit(project), break_fix=break_fix)
    return result.model_copy(update={"notes": sorted({*result.notes, *notes})}) if notes else result


async def verify_patch(project: str | Path, finding: Finding, patch: str, contract: Contract, *, tier: str | None = None,
                       break_fix: bool = False) -> FixResult:
    """Run somebody else's patch (the user's AI agent, a human) through the same gates."""
    project = Path(project).resolve()
    try:
        diff_stats(patch)
    except PatchError:
        pass  # the tournament reports it as a rejected candidate
    return await run_tournament(project, finding, [Candidate(patch, tier or finding.fix_tier or "C", "submitted-patch")], contract,
                                pre_fix_commit=pre_fix_commit(project), break_fix=break_fix)
