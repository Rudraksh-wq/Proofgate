"""Fix Tournament (plan 4): 5 gates + 2 guards decide whether a candidate patch is accepted.

  1. exploit_blocked   the same attack / detection now fails
  2. feature_works     every owner oracle that passed before still passes (catches "403 for everyone", `using(false)`)
  3. tests_pass        the project's existing tests pass
  4. no_new_findings   the fast checks find nothing new
  5. diff_is_small     <= 40 changed lines, limited to the finding's file (migrations: new files only)
  Guard A  the patch is applied in a TEMP COPY; the real project is never touched; only the winning diff is returned.
  Guard B  Supabase fixes: all migrations are replayed from scratch and an edit to an old migration is rejected.

ProofGate trusts no author: a patch written by an AI agent, by a human, or by our own templates goes through the same gates.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..inline import check_file
from ..layers import l5_database as l5
from ..layers.base import iter_files, read_text
from ..models import Contract, Finding, FixResult, Gates, Rejected, Winner
from ..redact import redact
from .patching import PatchError, Stats, apply_patch, copy_project, diff_stats

MAX_DIFF_LINES = 40
TEST_TIMEOUT_S = 120.0
CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"}
ORACLE_PHRASES = {
    "owner_can_read": "owner can no longer read own {r}", "owner_can_list": "owner can no longer list own {r}",
    "owner_can_update": "owner can no longer update own {r}", "owner_can_search": "owner can no longer search own {r}",
    "admin_can_use_admin_routes": "admin can no longer use the admin routes",
    "owner_can_edit_profile_field": "owner can no longer edit the allowed profile field",
}


@dataclass
class Candidate:
    patch: str
    tier: str  # A | B | C
    name: str = ""
    note: str = ""


@dataclass
class Baseline:
    oracles: dict[str, bool | None] = field(default_factory=dict)
    quick: dict[str, Finding] = field(default_factory=dict)
    probe_ran: bool = False
    schema_oracle: bool | None = None


@dataclass
class Evaluation:
    candidate: Candidate
    gates: Gates
    reasons: list[str] = field(default_factory=list)
    stats: Stats | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        g = self.gates
        return all([g.exploit_blocked, g.feature_works, g.tests_pass, g.no_new_findings, g.diff_is_small]) \
            and g.migrations_replayed is not False


# ------------------------------------------------------------------------------------ helpers
def _resource(contract: Contract) -> str:
    return contract.owned_resources[0].name if contract.owned_resources else "data"


def quick_scan(root: Path) -> dict[str, Finding]:
    """The fast, offline checks (inline L1/L2-AST, static L5) over a whole tree: {fingerprint: finding}."""
    found: dict[str, Finding] = {}
    for p in iter_files(root):
        if p.suffix in CODE_SUFFIXES or p.suffix == ".sql" or p.name == "package.json" or p.name.startswith("requirements"):
            if p.suffix == ".sql":
                continue
            for f in check_file(p, read_text(p) or "", project_root=root).findings:
                if f.fingerprint and f.layer != 4:
                    found[f.fingerprint] = f
    files = l5.sql_files(root)
    if files:
        try:
            from ..probe import load_contract

            for f in l5.check_schema(l5.build_schema(files), load_contract(root)):
                if f.fingerprint:
                    found[f.fingerprint] = f
        except Exception:  # noqa: BLE001 - a broken migration shows up in guard B, not here
            pass
    return found


def has_runnable_app(root: Path) -> bool:
    from ..probe.launcher import find_entry

    return find_entry(root) is not None


def rls_owner_oracle(root: Path, contract: Contract) -> bool | None:
    """Static stand-in for the owner oracles on a Supabase project: can the owner still do their actions?
    True when every contract action has a policy that gates on auth.uid() = owner column. None: no SQL here."""
    files = l5.sql_files(root)
    if not files or not contract.owned_resources:
        return None
    sch = l5.build_schema(files)
    ok = True
    for res in contract.owned_resources:
        t = sch.tables.get(res.name)
        if t is None:
            continue
        if not t.rls:
            continue  # RLS off: the owner can do everything (and so can everyone else: that is gate 1's business)
        kinds = {p.name: l5.policy_kind(p, res.owner_field) for p in t.policies.values() if p.permissive}
        wanted = {"read": "select", "list": "select", "create": "insert", "update": "update", "delete": "delete"}
        for action in res.actions:
            cmd = wanted.get(action, action)
            if not any(kinds[p.name] in ("strong", "true", "role_only") and cmd in l5._cmds(p)
                       for p in t.policies.values() if p.permissive):
                ok = False
    return ok


async def _probe(root: Path, contract: Contract):
    from ..probe import run_probe

    return await run_probe(root, contract)


async def compute_baseline(project: Path, contract: Contract) -> Baseline:
    b = Baseline(quick=quick_scan(project), schema_oracle=rls_owner_oracle(project, contract))
    if has_runnable_app(project) and (contract.owned_resources or contract.admin_only_routes):
        out = await _probe(project, contract)
        if out.error is None:
            b.probe_ran, b.oracles = True, out.result.oracles
    return b


def _run_tests(root: Path) -> tuple[bool, str]:
    has_tests = (root / "tests").is_dir() or any(root.glob("test_*.py")) or any(root.glob("*/test_*.py"))
    if not has_tests:
        return True, "no tests found"
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider"], cwd=root,
                           capture_output=True, text=True, timeout=TEST_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return False, f"tests timed out after {TEST_TIMEOUT_S:g}s"
    if r.returncode in (0, 5):
        return True, "tests passed" if r.returncode == 0 else "no tests collected"
    return False, redact((r.stdout or r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr).strip() else "tests failed")


# ------------------------------------------------------------------------------------ the gates
def _gate_diff(stats: Stats, finding: Finding) -> tuple[bool, str]:
    if stats.changed_lines > MAX_DIFF_LINES:
        return False, f"diff_is_small=false: {stats.changed_lines} changed lines (limit {MAX_DIFF_LINES})"
    if finding.layer == 5:
        if stats.modified_files:
            return False, ("diff_is_small=false: edits an existing migration; applied migrations are history, "
                           "add a new migration file instead (" + ", ".join(stats.modified_files) + ")")
        return True, ""
    allowed = {finding.location.file, ".env.example", ".gitignore"} if finding.layer == 1 else {finding.location.file}
    outside = [f for f in stats.files if f not in allowed]
    if outside:
        return False, "diff_is_small=false: touches files outside the finding: " + ", ".join(outside)
    return True, ""


def _migration_guard(copy: Path, stats: Stats) -> tuple[bool | None, str]:
    touched_sql = [f for f in stats.files if f.endswith(".sql")]
    if not touched_sql:
        return None, ""
    old = [f for f in stats.modified_files if f.endswith(".sql") and "migrations" in f.split("/")]
    if old:
        return False, "migrations_replayed=false: edits an existing migration: " + ", ".join(old)
    sch = l5.build_schema(l5.sql_files(copy))  # replay everything from scratch
    return (False, "migrations_replayed=false: " + sch.errors[0]) if sch.errors else (True, "")


def _version_ok(copy: Path, finding: Finding) -> bool | None:
    """Dependency findings: is the pinned version now at or above the fixed one?"""
    from ..layers.l3_deps import _ge

    if finding.layer != 3 or not finding.fixed_in:
        return None
    text = read_text(copy / finding.location.file) or ""
    name = finding.title.split(" ")[0]
    import re

    m = re.search(rf"^\s*{re.escape(name)}\s*==\s*([\w.]+)", text, re.IGNORECASE | re.MULTILINE) or re.search(
        rf'"{re.escape(name)}"\s*:\s*"[\^~]?([\w.]+)"', text)
    return bool(m and _ge(m.group(1), finding.fixed_in))


async def evaluate(project: Path, finding: Finding, cand: Candidate, contract: Contract, base: Baseline) -> Evaluation:
    gates = Gates(exploit_blocked=False, feature_works=False, tests_pass=False, no_new_findings=False, diff_is_small=False,
                  migrations_replayed=None)
    ev = Evaluation(cand, gates)
    try:
        ev.stats = stats = diff_stats(cand.patch)
    except PatchError as e:
        ev.reasons.append(f"patch is not a valid diff: {e}")
        return ev
    ok, why = _gate_diff(stats, finding)
    gates.diff_is_small = ok
    if not ok:
        ev.reasons.append(why)

    with tempfile.TemporaryDirectory(prefix="proofgate-fix-", ignore_cleanup_errors=True) as td:  # Guard A: never touch the real project
        copy = copy_project(project, Path(td) / "copy")
        try:
            apply_patch(copy, cand.patch)
        except PatchError as e:
            ev.reasons.append(f"the patch does not apply: {e}")
            return ev
        gates.migrations_replayed, why = _migration_guard(copy, stats)  # Guard B
        if why:
            ev.reasons.append(why)

        after_quick = quick_scan(copy)
        new = [f for fp, f in after_quick.items() if fp not in base.quick]
        gates.no_new_findings = not new
        if new:
            ev.reasons.append(f"no_new_findings=false: introduces {new[0].rule} in {new[0].location.file}")

        # gates 1 and 2: run the app again (Flask), or replay the schema statically (Supabase), or re-detect (other layers)
        r = _resource(contract)
        if finding.layer == 8 and base.probe_ran:
            out = await _probe(copy, contract)
            if out.error:
                ev.reasons.append("exploit_blocked=false: the patched app does not start: " + redact(out.error)[:160])
                gates.feature_works = False
            else:
                after = out.result.to_findings(out.contract)
                where = (finding.location.file, finding.location.function, finding.location.route)
                # any proven attack left on the same route counts: a fix for "anonymous can read" that still lets
                # User B read is a partial fix, not a fix
                left = [f for f in after if f.fingerprint == finding.fingerprint
                        or (f.location.file, f.location.function, f.location.route) == where]
                gates.exploit_blocked = not left
                if left:
                    who = "the same attack" if left[0].fingerprint == finding.fingerprint else f"a related attack ({left[0].rule})"
                    ev.reasons.append(f"exploit_blocked=false: {who} still works on {finding.location.route or finding.location.file}")
                broken = [k for k, v in base.oracles.items() if v is True and out.result.oracles.get(k) is not True]
                gates.feature_works = not broken
                if broken:
                    ev.reasons.append("feature_works=false: " + ORACLE_PHRASES.get(broken[0], broken[0]).format(r=r))
        elif finding.layer == 8:
            ev.reasons.append("exploit_blocked=false: the app cannot be started here, so the attack cannot be replayed")
        else:
            version_ok = _version_ok(copy, finding)
            gone = version_ok if version_ok is not None else finding.fingerprint not in after_quick
            gates.exploit_blocked = gone
            if not gone:
                ev.reasons.append(f"exploit_blocked=false: {finding.rule} is still detected")
            if finding.layer == 5:
                after_oracle = rls_owner_oracle(copy, contract)
                gates.feature_works = after_oracle is not False or base.schema_oracle is False
                if not gates.feature_works:
                    ev.reasons.append(f"feature_works=false: {ORACLE_PHRASES['owner_can_read'].format(r=r)} "
                                      "(no policy lets the owner use the table any more)")
                ev.notes.append("Supabase fix checked by static replay of all migrations; live replay pending (needs a configured Supabase backend: feat/15)")
            elif base.probe_ran and has_runnable_app(copy):
                out = await _probe(copy, contract)
                if out.error:
                    gates.feature_works = False
                    ev.reasons.append("feature_works=false: the patched app does not start: " + redact(out.error)[:160])
                else:
                    broken = [k for k, v in base.oracles.items() if v is True and out.result.oracles.get(k) is not True]
                    gates.feature_works = not broken
                    if broken:
                        ev.reasons.append("feature_works=false: " + ORACLE_PHRASES.get(broken[0], broken[0]).format(r=r))
            else:
                gates.feature_works = True
                ev.notes.append("feature_works not exercised: no runnable app to replay the owner oracles on")

        passed, msg = await asyncio.to_thread(_run_tests, copy)
        if not passed:  # was it already failing before the patch?
            before_ok, _ = await asyncio.to_thread(_run_tests, project)
            if not before_ok:
                passed, msg = True, "tests were already failing before the patch"
        gates.tests_pass = passed
        ev.notes.append(msg)
        if not passed:
            ev.reasons.append(f"tests_pass=false: {msg}")
    return ev


async def run_tournament(project: str | Path, finding: Finding, candidates: list[Candidate], contract: Contract, *,
                         baseline: Baseline | None = None, learned_rule: str | None = None,
                         pre_fix_commit: str | None = None) -> FixResult:
    """Evaluate every candidate; accept the smallest one that passes all gates, else `needs-human` with every reason."""
    project = Path(project).resolve()
    base = baseline or await compute_baseline(project, contract)
    evals = [await evaluate(project, finding, c, contract, base) for c in candidates]
    winners = sorted((e for e in evals if e.accepted), key=lambda e: e.stats.changed_lines if e.stats else 0)
    win = winners[0] if winners else None
    rejected = [Rejected(reason=redact(f"{e.candidate.name or 'candidate'}: {e.reasons[0] if e.reasons else 'not the smallest passing diff'}"))
                for e in evals if e is not win]
    gates = (win or (evals[0] if evals else None))
    notes = sorted({n for e in evals for n in e.notes}) if evals else []
    shown = redact(win.candidate.patch) if win else None
    if win and shown != win.candidate.patch:  # a secret sits in the diff context: never output it raw
        notes.append("the patch contains a secret, shown masked here; edit that line by hand as the patch describes, "
                     "then rotate the key (a key that was in code is already exposed)")
    return FixResult(
        finding_id=finding.id, tier=(candidates[0].tier if candidates else (finding.fix_tier or "C")),  # type: ignore[arg-type]
        candidates=len(candidates),
        winner=Winner(patch=shown, diff_lines=win.stats.changed_lines) if win and win.stats and shown is not None else None,
        gates=gates.gates if gates else Gates(exploit_blocked=False, feature_works=False, tests_pass=False,
                                              no_new_findings=False, diff_is_small=False),
        rejected=rejected, learned_rule=learned_rule, accepted=win is not None, pre_fix_commit=pre_fix_commit,
        notes=notes,
    )
