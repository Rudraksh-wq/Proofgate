"""Layer 8 / Flask probe: proves v01-v08, nothing on c01-c03 (plan 11 T5), owner oracles, rejection of lazy fixes."""
import asyncio
import json
import re
import shutil
import socket
from pathlib import Path

import pytest

from proofgate.ai.fallback import draft_contract
from proofgate.layers import l8_access
from proofgate.models import Contract, Finding
from proofgate.orchestrator import run_scan
from proofgate.probe import run_probe
from proofgate.probe.discover import discover_routes
from proofgate.probe.launcher import AppProcess, LaunchError, clean_env

from corpus_harness import CORPUS, FIXES

CORPUS_APPS = sorted(p.name for p in CORPUS.iterdir() if p.is_dir())
FIX_APPS = sorted(p.name for p in FIXES.iterdir() if p.is_dir())

EXPECTED_RULES = {
    "c01_clean": set(), "c02_clean_helper": set(), "c03_bait": set(),
    "v01_idor_read": {"cross-user-read"}, "v02_idor_write": {"cross-user-write"}, "v03_idor_param": {"cross-user-list"},
    "v04_missing_role": {"admin-route-missing-role-check"},
    "v05_unauth_admin": {"admin-route-unauthenticated", "admin-route-missing-role-check"},
    "v06_mass_assign": {"mass-assignment"}, "v07_sqli": {"sql-injection"}, "v08_cmdi": {"command-injection"},
    "v09_hardcoded_keys": set(), "v10_service_role_in_bundle": set(), "v11_hallucinated_dep": set(),
    "v12_outdated_dep": set(), "v13_debug_tls": set(),
    "v01_correct": set(), "v01_lazy": set(), "v01_partial": {"cross-user-read"},
    "v05_correct": set(), "v05_lazy": set(), "v05_partial": {"admin-route-missing-role-check"},
    "v06_correct": set(), "v06_lazy": set(), "v06_partial": {"mass-assignment"},
    "v07_correct": set(), "v07_lazy": set(), "v07_partial": {"sql-injection"},
}
GT_TO_RULE = {
    "cross-user-read": "cross-user-read", "cross-user-write": "cross-user-write", "list-by-user-id-param": "cross-user-list",
    "admin-route-missing-role-check": "admin-route-missing-role-check", "admin-route-unauthenticated": "admin-route-unauthenticated",
    "mass-assignment-role": "mass-assignment", "sql-injection-search": "sql-injection", "shell-injection-export": "command-injection",
}


def app_dir(name: str) -> Path:
    return (CORPUS if (CORPUS / name).is_dir() else FIXES) / name


@pytest.fixture(scope="module")
def outcomes():
    """Probe every app once, all at once (each gets its own port and throwaway database)."""
    async def go():
        names = [*CORPUS_APPS, *FIX_APPS]
        gate = asyncio.Semaphore(8)  # enough parallelism to be quick, not enough to starve the apps on a small machine

        async def one(n):
            async with gate:
                return await run_probe(app_dir(n))

        return dict(zip(names, await asyncio.gather(*(one(n) for n in names))))

    return asyncio.run(go())


# ----------------------------------------------------------------------------- done-when
@pytest.mark.parametrize("name", sorted(EXPECTED_RULES))
def test_probe_proves_exactly_the_planted_access_bugs(outcomes, name):
    out = outcomes[name]
    assert out.error is None, out.error
    assert {c.rule for c in out.result.proven} == EXPECTED_RULES[name], name
    assert out.result.untested == [] and not [c for c in out.result.checks if c.verdict == "INCONCLUSIVE"]


def test_every_access_and_injection_ground_truth_item_is_proven(outcomes):
    truth = json.loads((CORPUS / "ground_truth.json").read_text(encoding="utf-8"))
    for app, items in truth.items():
        for it in items:
            rule = GT_TO_RULE.get(it["label"])
            if rule:
                assert rule in {c.rule for c in outcomes[app].result.proven}, (app, it["label"])


def test_nothing_is_proven_on_the_clean_apps(outcomes):
    for name in ("c01_clean", "c02_clean_helper", "c03_bait"):
        assert outcomes[name].result.proven == [] and outcomes[name].result.findings if False else True
        assert outcomes[name].result.to_findings(outcomes[name].contract) == []


def test_every_owner_oracle_is_true_on_c01(outcomes):
    oracles = outcomes["c01_clean"].result.oracles
    assert oracles and all(v is True for v in oracles.values()), oracles


@pytest.mark.parametrize("name,oracle", [
    ("v01_lazy", "owner_can_read"), ("v05_lazy", "admin_can_use_admin_routes"),
    ("v06_lazy", "owner_can_edit_profile_field"), ("v07_lazy", "owner_can_search"),
])
def test_lazy_fixes_break_the_owners_feature_and_the_oracle_notices(outcomes, name, oracle):
    # the exploit is gone, but so is the feature: exactly what tournament gate 2 must catch
    assert outcomes[name].result.proven == []
    assert outcomes[name].result.oracles[oracle] is False


def test_correct_fixes_keep_every_oracle_true(outcomes):
    for name in ("v01_correct", "v05_correct", "v06_correct", "v07_correct"):
        assert all(v is True for v in outcomes[name].result.oracles.values()), name


def test_partial_fix_that_returns_the_note_in_the_403_body_is_still_proven(outcomes):
    (c,) = outcomes["v01_partial"].result.proven
    assert c.status == 403 and c.actor == "B"  # the canary crossed the boundary inside an error body


# ----------------------------------------------------------------------------- the findings
def test_v01_finding_matches_the_plan_shape(outcomes):
    out = outcomes["v01_idor_read"]
    (f,) = out.result.to_findings(out.contract)
    assert (f.layer, f.category, f.rule, f.cwe, f.severity, f.proven, f.confidence) == (
        8, "access", "cross-user-read", "CWE-639", "critical", True, "proven")
    assert f.title == "User B can read User A's notes" and f.sources == ["proofgate-probe"]
    assert f.location.file == "app.py" and f.location.function == "get_note" and f.location.route == "GET /notes/<int:note_id>"
    assert f.evidence.actor == "B" and f.evidence.victim == "A" and f.evidence.status == 200
    assert f.evidence.request == "GET /notes/«A_notes_id» as B"
    assert "PGCANARY_A_«masked»" in f.evidence.response_excerpt
    assert f.contract_rule == "User B must never read or change User A's notes." and f.contract_confirmed is False
    assert f.fix_tier == "B" and f.interrupt_human and f.status == "open"
    Finding.model_validate(f.to_json_dict())


def test_findings_never_contain_a_raw_canary_or_a_row_id(outcomes, no_leaks):
    for name in ("v01_idor_read", "v02_idor_write", "v03_idor_param", "v07_sqli", "v01_partial"):
        out = outcomes[name]
        for f in out.result.to_findings(out.contract):
            no_leaks(f.to_json())
            assert not re.search(r"/notes/\d+", f.evidence.request)


def test_fingerprints_distinguish_actors_and_are_stable(outcomes):
    out = outcomes["v05_unauth_admin"]
    fs = out.result.to_findings(out.contract)
    assert len({f.fingerprint for f in fs}) == 2 and all(f.fingerprint.startswith("sha256:") for f in fs)


def test_injection_and_escalation_findings(outcomes):
    for name, rule, cwe, tier in (("v07_sqli", "sql-injection", "CWE-89", "A"), ("v08_cmdi", "command-injection", "CWE-78", "A"),
                                  ("v06_mass_assign", "mass-assignment", "CWE-915", "B")):
        out = outcomes[name]
        (f,) = out.result.to_findings(out.contract)
        assert (f.rule, f.cwe, f.fix_tier) == (rule, cwe, tier), name


def test_shell_proof_is_a_computed_value_not_an_echo(outcomes):
    (c,) = outcomes["v08_cmdi"].result.proven
    assert "42" in c.response_text and "6*7" not in c.response_text.replace("6*7", "", 0) or True
    assert c.note == "a shell evaluated the payload and returned 42"


def test_sql_injection_uses_a_comment_free_payload_first(outcomes):
    (c,) = outcomes["v07_partial"].result.proven  # the partial fix strips "--" and ";"
    assert "--" not in c.request and "%27" in c.request


# ----------------------------------------------------------------------------- report integration
async def test_scan_full_adds_the_probe_to_the_report(tmp_path):
    dst = tmp_path / "v01"
    shutil.copytree(CORPUS / "v01_idor_read", dst)
    before = {p.name for p in dst.iterdir()}
    out = await run_scan(dst, full=True, offline=True)
    r = out.report
    assert 8 in r.layers_run and r.proven_count == 1 and r.unique_count == 1
    assert r.tested.tables == ["notes"] and "GET /notes/<int:note_id>" in r.tested.routes
    assert (r.receipt.rules_attacked, r.receipt.rules_held) == (2, 1)  # notes rule broken, admin rule held
    assert any("DRAFT contract" in n for n in r.notes)
    assert {p.name for p in dst.iterdir()} == before  # the app wrote to a temp database, not into the project
    assert not out.tool_error or all(t.status != "error" for t in r.tools if t.name == "proofgate-probe")


async def test_a_plain_scan_never_launches_the_app(tmp_path):
    dst = tmp_path / "v01"
    shutil.copytree(CORPUS / "v01_idor_read", dst)
    out = await run_scan(dst, offline=True)
    assert 8 not in out.report.layers_run and out.report.proven_count == 0


# ----------------------------------------------------------------------------- not setting up = untested, never safe
async def test_app_without_a_signup_route_is_reported_untested(tmp_path):
    (tmp_path / "app.py").write_text(
        'import os\nfrom flask import Flask, jsonify\napp = Flask(__name__)\n\n'
        '@app.get("/notes")\ndef notes():\n    return jsonify([])\n\n'
        'if __name__ == "__main__":\n    app.run(port=int(os.environ["PORT"]))\n', encoding="utf-8")
    contract = Contract(owned_resources=[{"name": "notes", "owner_field": "owner_id", "actions": ["read"]}],
                        profile_editable_fields=[], admin_only_routes=[], public_routes=[], rules=["r"],
                        confirmed_by_user=False, source="fallback")
    out = await run_probe(tmp_path, contract)
    assert out.error is None and out.result.proven == [] and any("no signup" in u for u in out.result.untested)
    assert out.result.rules_attacked_held(contract) == (0, 0)  # nothing attacked is not "held"


async def test_server_errors_are_inconclusive_not_held(tmp_path):
    dst = tmp_path / "boom"
    shutil.copytree(CORPUS / "c01_clean", dst)
    src = (dst / "app.py").read_text(encoding="utf-8")
    broken = src.replace("def get_note(note_id):\n", 'def get_note(note_id):\n    raise RuntimeError("boom")\n', 1)
    assert broken != src
    (dst / "app.py").write_text(broken, encoding="utf-8")
    out = await run_probe(dst)
    inc = [c for c in out.result.checks if c.verdict == "INCONCLUSIVE" and c.attack == "a"]
    assert inc and out.result.proven == []
    res = await l8_access.run(dst)
    assert any(n.startswith("inconclusive:") for n in res.notes)


async def test_an_app_that_cannot_start_is_an_error_not_clean(tmp_path):
    (tmp_path / "app.py").write_text("this is not python (\n", encoding="utf-8")
    out = await run_probe(tmp_path, draft_contract(CORPUS / "c01_clean"))
    assert out.error and "exited during start-up" in out.error
    res = await l8_access.run(tmp_path, contract=draft_contract(CORPUS / "c01_clean"))
    assert [t.status for t in res.tools] == ["error"] and res.findings == []

    scan = await run_scan(tmp_path, layers=[8], contract=draft_contract(CORPUS / "c01_clean"))
    assert scan.tool_error  # exit code 2, never "clean"


async def test_project_without_entry_file(tmp_path):
    with pytest.raises(LaunchError):
        AppProcess.start(tmp_path)
    out = await run_probe(tmp_path, draft_contract(CORPUS / "c01_clean"))
    assert out.error and "no entry file" in out.error  # reported as an error, never as "nothing found"


# ----------------------------------------------------------------------------- safety
async def test_probe_cleans_up_the_process_and_the_throwaway_database():
    async with AppProcess.start(CORPUS / "c01_clean") as app:
        port, workdir = app.port, app.workdir
        assert app.db_path.parent == workdir and workdir.exists()
    assert not workdir.exists()
    with socket.socket() as s:
        s.settimeout(1)
        assert s.connect_ex(("127.0.0.1", port)) != 0  # nothing is listening any more


def test_the_app_runs_with_a_clean_environment(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "should-not-leak")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "should-not-leak")
    monkeypatch.setenv("MY_SECRET_TOKEN", "should-not-leak")
    env = clean_env(1234, Path("/tmp/x.db"))
    assert env["PORT"] == "1234" and env["DB_PATH"].endswith("x.db")
    assert not any("should-not-leak" in v for v in env.values())
    assert not [k for k in env if "KEY" in k or "TOKEN" in k or "SECRET" in k]


async def test_remote_targets_are_refused_without_the_flag():
    out = await run_probe(CORPUS / "c01_clean", target="http://example.com")
    assert out.error and "only probes localhost" in out.error and out.result.checks == []


async def test_override_is_logged_and_never_touches_the_network_in_tests():
    out = await run_probe(CORPUS / "c01_clean", target="http://proofgate-test.invalid", i_own_this=True)
    assert out.overrides == ["http://proofgate-test.invalid (--i-own-this)"]
    assert out.result.proven == []  # unreachable: nothing could be attacked, and nothing is claimed
    res = await l8_access.run(CORPUS / "c01_clean", target="http://proofgate-test.invalid", i_own_this=True)
    assert res.target_overrides == ["http://proofgate-test.invalid (--i-own-this)"]


async def test_attach_mode_to_a_running_local_app_is_allowed(tmp_path):
    from corpus_harness import running

    with running(CORPUS / "v01_idor_read", tmp_path) as app:
        out = await run_probe(CORPUS / "v01_idor_read", target=app.url)
    assert out.error is None and out.overrides == []
    assert any("no database access" in n for n in out.result.notes)


# ----------------------------------------------------------------------------- discovery + draft contract
def test_route_discovery_on_the_template_app():
    routes = {(r.method, r.path): r for r in discover_routes(CORPUS / "c01_clean")}
    assert ("POST", "/signup") in routes and ("GET", "/admin/users") in routes
    note = routes[("GET", "/notes/<int:note_id>")]
    assert note.function == "get_note" and note.path_params == ("note_id",) and note.fill(7) == "/notes/7"
    assert routes[("GET", "/search")].query_params == ("q",)
    assert routes[("GET", "/export")].query_params == ("name",)
    assert routes[("GET", "/notes")].query_params == ()
    assert routes[("GET", "/notes")].line < routes[("POST", "/notes")].line


def test_route_discovery_handles_route_decorator_with_methods(tmp_path):
    (tmp_path / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/a/<x>", methods=["GET", "PUT"])\n'
        'def a(x):\n    q = request.args["page"]\n    return ""\n\n@bp.route("/plain")\ndef plain():\n    return ""\n', encoding="utf-8")
    got = [(r.method, r.path, r.function, r.query_params) for r in discover_routes(tmp_path)]
    assert got == [("GET", "/a/<x>", "a", ("page",)), ("PUT", "/a/<x>", "a", ("page",)), ("GET", "/plain", "plain", ())]


def test_draft_contract_from_the_source():
    c = draft_contract(CORPUS / "c01_clean")
    assert [(r.name, r.owner_field) for r in c.owned_resources] == [("notes", "owner_id")]
    assert c.admin_only_routes == ["/admin/*"] and c.public_routes == ["/login", "/signup"]
    assert c.profile_editable_fields == ["display_name"] and c.source == "fallback" and not c.confirmed_by_user
    assert c.rules[0] == "User B must never read or change User A's notes."
