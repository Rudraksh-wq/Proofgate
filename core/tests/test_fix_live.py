"""The fix tournament against a live Supabase backend (Guard B on the real database), with the database and the probe faked."""
import shutil
from pathlib import Path

import pytest

from proofgate import supabase_db as db
from proofgate.fix import tournament as tn
from proofgate.fix.live import LiveCtx, current_live, live_applies
from proofgate.fix.pipeline import deterministic_candidates, fix_finding
from proofgate.models import Contract, Finding, OwnedResource
from proofgate.probe import ProbeOutcome
from proofgate.probe.result import Check, ProbeResult

from corpus_harness import ROOT

DEMO = ROOT / "demo-apps" / "nextjs-supabase"
CONTRACT = Contract(owned_resources=[OwnedResource(name="notes", owner_field="user_id", actions=["read", "write"])], profile_editable_fields=[],
                    admin_only_routes=[], public_routes=[], rules=["Users can only read and change their own notes."], confirmed_by_user=True, source="fallback")
ROUTE = "GET /rest/v1/notes?id=eq.<A's id>"
LIVE = LiveCtx("hosted", True, "A", None)


@pytest.fixture
def project(tmp_path):
    dst = tmp_path / "demo"
    shutil.copytree(DEMO, dst, ignore=shutil.ignore_patterns("node_modules", ".next", ".proofgate", "tsconfig.tsbuildinfo"))
    return dst


def check(verdict: str, file="supabase:public.notes", route=ROUTE, rule="cross-user-read", fn="notes") -> Check:
    return Check(attack="a", rule=rule, verdict=verdict, actor="B", resource="notes", route_label=route, file=file, line=1, function=fn,
                 request=f"{route} as B", status=200, response_text="PGCANARY_A_deadbeef")


def finding(project) -> Finding:
    return ProbeResult(checks=[check("PROVEN")]).to_findings(CONTRACT)[0]


class FakeLive:
    """Replaces live_replay and run_supabase_probe. The 'database' is secure iff the replayed project holds an RLS fix migration."""

    def __init__(self, *, replay_error: Exception | None = None, restore_error: Exception | None = None, skip_checks: bool = False, break_owner: bool = False):
        self.replays: list[Path] = []
        self.replay_error, self.restore_error, self.skip_checks, self.break_owner = replay_error, restore_error, skip_checks, break_owner
        self.state_secure: bool | None = None

    async def replay(self, root: Path, live) -> list[str]:
        patched = any("proofgate_rls" in p.name for p in (root / "supabase" / "migrations").glob("*.sql"))
        is_copy = ".proofgate" in root.parts
        if self.replay_error and is_copy:
            raise self.replay_error
        if self.restore_error and not is_copy:
            raise self.restore_error
        self.replays.append(root)
        self.state_secure = patched
        return ["x.sql"]

    async def probe(self, root: Path, contract, *, backend, i_own_this, config_dir=None) -> ProbeOutcome:
        res = ProbeResult(launched=False)
        verdict = "HELD" if self.state_secure else "PROVEN"
        res.oracles = {"A can read own notes": not self.break_owner or not self.state_secure, "A can update own notes": True}
        if not self.skip_checks:
            res.checks.append(check(verdict))
        return ProbeOutcome(res, contract)


@pytest.fixture
def fake(monkeypatch):
    f = FakeLive()
    monkeypatch.setattr(tn, "live_replay", f.replay)
    import proofgate.probe as probe_pkg

    monkeypatch.setattr(probe_pkg, "run_supabase_probe", f.probe)
    token = current_live.set(LIVE)
    yield f
    current_live.reset(token)


def use(monkeypatch, f: FakeLive):
    monkeypatch.setattr(tn, "live_replay", f.replay)
    import proofgate.probe as probe_pkg

    monkeypatch.setattr(probe_pkg, "run_supabase_probe", f.probe)


# ------------------------------------------------------------------------------------------- tier B for a live finding
def test_a_live_postgrest_finding_gets_the_rls_migration_and_a_route_finding_gets_the_ssr_switch(project):
    cands, learned = deterministic_candidates(project, finding(project), CONTRACT)
    assert [c.tier for c in cands] == ["B"] and "supabase/migrations/" in cands[0].patch and "proofgate_rls_notes.sql" in cands[0].patch
    assert "enable row level security" in cands[0].patch and "auth.uid() = user_id" in cands[0].patch and "RLS" in learned
    route = ProbeResult(checks=[check("PROVEN", file="app/api/notes/[id]/route.ts", route="GET /api/notes/[id]", fn="GET")]).to_findings(CONTRACT)[0]
    cands, _ = deterministic_candidates(project, route, CONTRACT)
    assert len(cands) == 1 and "createServer()" in cands[0].patch and 'eq("user_id", user.id)' in cands[0].patch and "SERVICE_ROLE" in cands[0].patch


# ------------------------------------------------------------------------------------------- migration order
def test_a_fix_migration_is_applied_after_the_variant_and_the_installed_copy_is_ignored(project):
    mig = project / "supabase" / "migrations"
    (mig / "20261120000000_proofgate_rls_notes.sql").write_text("select 1;", encoding="utf-8")
    (mig / db.INSTALLED_VARIANT_NAME).write_text("-- installed copy of B", encoding="utf-8")
    names = [n for n, _ in db.replay_files(project, "A")]
    assert names == ["20240101000000_notes.sql", "20240101000100_run_sql.sql", db.INSTALLED_VARIANT_NAME, "20261120000000_proofgate_rls_notes.sql"]
    assert dict(db.replay_files(project, "A"))[db.INSTALLED_VARIANT_NAME].name == "a_rls_off.sql"  # the chosen variant, not the stale copy
    assert dict(db.replay_files(project, None))[db.INSTALLED_VARIANT_NAME].read_text(encoding="utf-8") == "-- installed copy of B"


def test_live_applies_only_to_supabase_projects_without_a_flask_entry(project, tmp_path):
    assert live_applies(project, LIVE) and not live_applies(project, None)
    flask = tmp_path / "f"
    shutil.copytree(ROOT / "demo-apps" / "flask-corpus" / "c01_clean", flask, ignore=shutil.ignore_patterns(".proofgate"))
    (flask / "supabase").mkdir()
    assert not live_applies(flask, LIVE)


# ------------------------------------------------------------------------------------------- the tournament
async def test_the_rls_fix_is_accepted_when_the_replayed_database_holds_and_the_owner_still_works(project, fake):
    finding_ = finding(project)
    result = await fix_finding(project, finding_, CONTRACT)
    g = result.gates
    assert result.accepted and g.exploit_blocked and g.feature_works and g.no_new_findings and g.diff_is_small and g.migrations_replayed
    assert any("live database restored" in n for n in result.notes)
    assert fake.state_secure is False  # the original (unpatched) state was replayed LAST: a candidate never leaves the database changed
    assert not (project / ".proofgate" / "tmp").exists() or not list((project / ".proofgate" / "tmp").iterdir())  # the copy is gone
    assert not list((project / "supabase" / "migrations").glob("*proofgate_rls*"))  # nothing was applied to the real project


async def test_a_fix_that_does_not_stop_the_attack_is_rejected_on_the_live_database(project, fake):
    patch = "--- /dev/null\n+++ b/supabase/migrations/20990101000000_noop.sql\n@@ -0,0 +1 @@\n+select 1;\n"
    result = await tn.run_tournament(project, finding(project), [tn.Candidate(patch, "B", "noop")], CONTRACT)
    assert not result.accepted and "exploit_blocked=false" in result.rejected[0].reason


async def test_a_fix_that_breaks_the_owner_is_rejected(project, monkeypatch):
    f = FakeLive(break_owner=True)
    use(monkeypatch, f)
    token = current_live.set(LIVE)
    try:
        # baseline runs on the original (A can read own notes), the patched copy cannot: that is "locked everybody out"
        result = await fix_finding(project, finding(project), CONTRACT)
    finally:
        current_live.reset(token)
    assert not result.accepted and "feature_works=false" in result.rejected[0].reason and "A can read own notes" in result.rejected[0].reason


async def test_a_gate_cannot_pass_just_because_the_attack_was_not_replayed(project, monkeypatch):
    f = FakeLive()
    use(monkeypatch, f)
    token = current_live.set(LIVE)
    try:
        base = await tn.compute_baseline(project, CONTRACT)
        f.skip_checks = True  # the patched copy's probe returns no checks at all (routes unreachable): "no finding" must NOT mean "fixed"
        cands, _ = deterministic_candidates(project, finding(project), CONTRACT)
        result = await tn.run_tournament(project, finding(project), cands, CONTRACT, baseline=base)
    finally:
        current_live.reset(token)
    assert not result.accepted and "could not be replayed on the patched copy" in result.rejected[0].reason


async def test_a_migration_that_fails_on_the_live_database_is_a_rejected_candidate_not_a_crash(project, monkeypatch):
    f = FakeLive(replay_error=RuntimeError("syntax error at or near 'create'"))
    use(monkeypatch, f)
    token = current_live.set(LIVE)
    try:
        base = await tn.compute_baseline(project, CONTRACT)
        cands, _ = deterministic_candidates(project, finding(project), CONTRACT)
        result = await tn.run_tournament(project, finding(project), cands, CONTRACT, baseline=base)
    finally:
        current_live.reset(token)
    assert not result.accepted and "could not be replayed on the live database" in result.rejected[0].reason and "syntax error" in result.rejected[0].reason


async def test_a_failed_restore_is_a_loud_warning(project, monkeypatch):
    f = FakeLive(restore_error=RuntimeError("connection lost"))
    use(monkeypatch, f)
    token = current_live.set(LIVE)
    try:
        base = tn.Baseline(oracles={"A can read own notes": True}, probe_ran=True, quick=tn.quick_scan(project))
        cands, _ = deterministic_candidates(project, finding(project), CONTRACT)
        result = await tn.run_tournament(project, finding(project), cands, CONTRACT, baseline=base)
    finally:
        current_live.reset(token)
    assert any("could NOT be restored" in n and "make reset-demo" in n for n in result.notes)


async def test_without_a_live_context_nothing_touches_a_database(project, monkeypatch):
    f = FakeLive()
    use(monkeypatch, f)
    base = await tn.compute_baseline(project, CONTRACT)
    assert f.replays == [] and base.probe_ran is False  # static replay only, exactly as before


def test_cli_builds_the_live_context_from_its_flags(tmp_path):
    from argparse import Namespace

    from proofgate.cli import _live_ctx

    assert _live_ctx(Namespace(backend=None, i_own_this=False, variant=None, dir=str(tmp_path))) is None
    ctx = _live_ctx(Namespace(backend="hosted", i_own_this=True, variant="b", dir=str(tmp_path)))
    assert ctx.backend == "hosted" and ctx.i_own_this and ctx.variant == "B" and ctx.config_dir == tmp_path.resolve()
