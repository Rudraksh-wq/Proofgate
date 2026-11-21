import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from proofgate.cli import main
from proofgate.fix.patching import apply_patch
from proofgate.fix.pipeline import fix_finding
from proofgate.fix.record import record_fix, rollback_commands
from proofgate.fix.vaccinate import (
    BEGIN, END, PY_TEST_FILE, build_vaccine, merge_rules_block, pgtap_for, rule_changes, vitest_for,
)
from proofgate.inline import check_file
from proofgate.models import FixResult, Report
from proofgate.pkgcache import PackageCache
from proofgate.probe import load_contract, run_probe

from corpus_harness import CORPUS

DEMO = Path(__file__).resolve().parents[2] / "demo-apps" / "nextjs-supabase"
RULE = "Every query on notes must filter by owner_id = current user."


def copy(src: Path, tmp_path: Path, name="proj") -> Path:
    dst = tmp_path / name
    shutil.copytree(src, dst)
    return dst


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.test", "-C", str(repo), *args],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


# ============================================================================= the rules block
def test_new_files_get_the_block_and_cursor_gets_front_matter():
    assert merge_rules_block(None, RULE, "f_1").startswith(BEGIN)
    cursor = merge_rules_block(None, RULE, "f_1", new_file_header="---\nalwaysApply: true\n---\n\n")
    assert cursor.startswith("---\nalwaysApply: true\n---") and cursor.count(BEGIN) == 1


def test_existing_file_keeps_everything_outside_the_markers():
    mine = "# My project\n\nUse tabs.\n"
    new = merge_rules_block(mine, RULE, "f_1")
    assert new.startswith(mine) and new.count(BEGIN) == 1 and RULE in new
    again = merge_rules_block(new + "\nMore of my notes.\n", "Check roles on admin routes.", "f_2")
    assert "More of my notes." in again and again.count(BEGIN) == 1 and again.count("<!-- pg:") == 2


def test_the_same_rule_is_never_added_twice_even_with_different_wording_or_ids():
    once = merge_rules_block(None, RULE, "f_1")
    assert merge_rules_block(once, RULE, "f_2") == once
    assert merge_rules_block(once, RULE.upper().replace("OWNER_ID", "owner_id") + " ", "f_3") == once
    assert merge_rules_block(once, "Every query on notes must filter by owner_id = current user", "f_4") == once


def test_rule_changes_only_lists_files_that_would_change(tmp_path):
    changes = rule_changes(tmp_path, RULE, "f_1")
    assert set(changes) == {"CLAUDE.md", "AGENTS.md", ".cursor/rules/proofgate.mdc"}
    for rel, text in changes.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    assert rule_changes(tmp_path, RULE, "f_9") == {}  # already taught: nothing to add


def test_the_block_is_replaced_in_place_not_duplicated():
    text = merge_rules_block("intro\n", RULE, "f_1")
    for i in range(5):
        text = merge_rules_block(text, f"Rule number {i} about owners.", f"f_{i}")
    assert text.count(BEGIN) == 1 and text.count(END) == 1 and text.count("<!-- pg:") == 6


# ============================================================================= the regression test
async def probed(app: str, tmp_path: Path):
    proj = copy(CORPUS / app, tmp_path, app)
    out = await run_probe(proj)
    return proj, out, out.result.to_findings(out.contract)


async def test_probe_regression_test_fails_before_and_passes_after(tmp_path):
    proj, out, findings = await probed("v01_idor_read", tmp_path)
    f = findings[0]
    res = await fix_finding(proj, f, out.contract)
    vac = await build_vaccine(proj, f, res, out.contract)
    assert vac.verified is True and vac.test_id == f"{PY_TEST_FILE}::test_{f.id}"
    assert set(vac.files) == {PY_TEST_FILE, "CLAUDE.md", "AGENTS.md", ".cursor/rules/proofgate.mdc"}

    # apply it for real in two copies and run the generated test with pytest
    before, after = copy(proj, tmp_path, "before"), copy(proj, tmp_path, "after")
    apply_patch(before, vac.patch)
    apply_patch(after, res.winner.patch)
    apply_patch(after, vac.patch)
    import sys

    def go(d):
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", vac.test_id], cwd=d,
                              capture_output=True, text=True)

    assert go(before).returncode != 0 and "the attack still works: cross-user-read" in go(before).stdout
    assert go(after).returncode == 0


async def test_a_second_finding_appends_to_the_same_test_file_without_duplicating(tmp_path):
    proj, out, findings = await probed("v05_unauth_admin", tmp_path)
    assert len(findings) == 2
    res0 = await fix_finding(proj, findings[0], out.contract)
    vac0 = await build_vaccine(proj, findings[0], res0, out.contract, verify=False)
    apply_patch(proj, vac0.patch)
    res1 = await fix_finding(proj, findings[1], out.contract)
    vac1 = await build_vaccine(proj, findings[1], res1, out.contract, verify=False)
    text = (proj / PY_TEST_FILE).read_text(encoding="utf-8")
    assert f"def test_{findings[0].id}" in text and text.count("def _assert_no_proven_attack") == 1
    apply_patch(proj, vac1.patch)
    assert f"def test_{findings[1].id}" in (proj / PY_TEST_FILE).read_text(encoding="utf-8")
    # the second patch MODIFIES the existing file (appends one test), it does not recreate it
    assert f"--- a/{PY_TEST_FILE}" in vac1.patch and f"def test_{findings[1].id}" in vac1.patch
    # and teaching the same rule again changes nothing in the agent files
    assert not any(f in vac1.files for f in ("CLAUDE.md", "AGENTS.md")) or res0.learned_rule != res1.learned_rule


async def test_vaccinating_the_same_finding_twice_adds_nothing(tmp_path):
    proj, out, findings = await probed("v01_idor_read", tmp_path)
    res = await fix_finding(proj, findings[0], out.contract)
    vac = await build_vaccine(proj, findings[0], res, out.contract, verify=False)
    apply_patch(proj, vac.patch)
    again = await build_vaccine(proj, findings[0], res, out.contract, verify=False)
    assert again.patch == "" and again.files == []


async def test_a_test_that_does_not_catch_the_fix_is_marked_unverified(tmp_path):
    proj, out, findings = await probed("v01_idor_read", tmp_path)
    f = findings[0]
    res = await fix_finding(proj, f, out.contract)
    noop = res.model_copy(update={"winner": res.winner.model_copy(update={
        "patch": "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-" + (proj / "app.py").read_text(encoding="utf-8").splitlines()[0] + "\n+# changed docstring only\n"})})
    vac = await build_vaccine(proj, f, noop, out.contract)
    assert vac.verified is False and any("still fails" in n for n in vac.notes)


async def test_static_python_findings_get_a_detection_test(tmp_path):
    proj = copy(CORPUS / "v13_debug_tls", tmp_path)
    f = next(x for x in check_file(proj / "app.py", project_root=proj, cache=PackageCache(tmp_path / "c.json")).findings
             if x.rule == "proofgate.py-flask-debug-true")
    res = await fix_finding(proj, f, load_contract(proj))
    vac = await build_vaccine(proj, f, res, load_contract(proj))
    assert vac.verified is True and "_assert_not_detected" in vac.patch


async def test_dependency_findings_get_a_version_test(tmp_path):
    from proofgate.models import Finding

    proj = copy(CORPUS / "v12_outdated_dep", tmp_path)
    f = Finding.model_validate({
        "id": "f_dep", "layer": 3, "category": "deps", "rule": "known-vulnerable-dependency", "severity": "medium",
        "title": "requests 2.19.0 has known vulnerabilities (requirements.txt:2)", "plain_words": "p", "fixed_in": "2.33.0",
        "fix_tier": "A", "location": {"file": "requirements.txt", "line": 2}, "sources": ["pip-audit"]})
    res = await fix_finding(proj, f, load_contract(proj))
    vac = await build_vaccine(proj, f, res, load_contract(proj))
    assert vac.verified is True and "_assert_min_version('requirements.txt', 'requests', '2.33.0')" in vac.patch


async def test_nextjs_route_gets_a_vitest_spec_checked_by_an_equivalent_static_check(tmp_path):
    proj = tmp_path / "next"
    for rel in ("app/api/notes/[id]/route.ts", "lib/supabase/server.ts"):
        (proj / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(DEMO / rel, proj / rel)
    f = next(x for x in check_file(proj / "app/api/notes/[id]/route.ts", project_root=proj, cache=PackageCache(tmp_path / "c.json")).findings
             if x.rule == "proofgate.next-route-service-role-client")
    res = await fix_finding(proj, f, load_contract(proj))
    vac = await build_vaccine(proj, f, res, load_contract(proj))
    assert vac.verified is True and vac.test_id.startswith("tests/proofgate/test_") and ".spec.ts::" in vac.test_id
    assert "from \"vitest\"" in vac.patch and "not.toMatch(/SERVICE_ROLE/)" in vac.patch
    assert any("npx vitest" in n for n in vac.notes)


def test_pgtap_test_for_rls_fixes_parses_and_names_all_four_policies():
    pglast = pytest.importorskip("pglast")
    from proofgate.models import Finding

    f = Finding.model_validate({"id": "f_rls", "layer": 5, "category": "database", "rule": "proofgate.sql-rls-disabled", "severity": "critical",
                                "title": "Row-level security is off on public.notes (x.sql:3)", "plain_words": "p",
                                "location": {"file": "x.sql", "line": 3}, "sources": ["s"]})
    path, sql = pgtap_for(f, "notes", "user_id")
    assert path == "supabase/tests/proofgate_f_rls.test.sql" and pglast.parse_sql(sql)
    assert sql.count("select ok(") == 5 and "relrowsecurity" in sql and "auth.uid()%user_id%" in sql
    for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        assert f"cmd = '{cmd}'" in sql


async def test_rls_fix_vaccine_is_a_pgtap_file_and_says_it_was_not_run(tmp_path):
    from proofgate.layers import l5_database as l5

    proj = tmp_path / "sb"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    shutil.copy(DEMO / "supabase/variants/a_rls_off.sql", proj / "supabase/migrations/20240201000000_rls_variant.sql")
    f = next(x for x in (await l5.run(proj)).findings if x.rule.endswith("rls-disabled"))
    res = await fix_finding(proj, f, load_contract(proj))
    vac = await build_vaccine(proj, f, res, load_contract(proj))
    assert vac.test_id.startswith("supabase/tests/proofgate_") and vac.verified is None
    assert any("supabase test db" in n and "pending" in n for n in vac.notes)


async def test_llm_written_fixes_never_write_rules_into_agent_files(tmp_path):
    proj, out, findings = await probed("v01_idor_read", tmp_path)
    res = await fix_finding(proj, findings[0], out.contract)
    human_review = res.model_copy(update={"learned_rule": None, "tier": "C"})
    vac = await build_vaccine(proj, findings[0], human_review, out.contract, verify=False)
    assert not {"CLAUDE.md", "AGENTS.md", ".cursor/rules/proofgate.mdc"} & set(vac.files)
    assert any("only ProofGate's own templates" in n for n in vac.notes) and PY_TEST_FILE in vac.files


async def test_a_rejected_fix_has_no_vaccine(tmp_path):
    proj, out, findings = await probed("v01_idor_read", tmp_path)
    rejected = FixResult.model_validate({"finding_id": findings[0].id, "tier": "B", "candidates": 1, "gates": {
        "exploit_blocked": False, "feature_works": True, "tests_pass": True, "no_new_findings": True, "diff_is_small": True},
        "rejected": [{"reason": "x"}], "accepted": False})
    vac = await build_vaccine(proj, findings[0], rejected, out.contract)
    assert vac.patch == "" and vac.notes == ["no vaccine: the fix was not accepted"]


# ============================================================================= recording + status
def report_for(tmp_path: Path) -> tuple[Path, str]:
    proj = copy(CORPUS / "v01_idor_read", tmp_path)
    assert main(["prove", str(proj)]) == 1
    report = Report.model_validate_json((proj / ".proofgate" / "report.json").read_text(encoding="utf-8"))
    return proj, report.findings[0].id


def accepted_result(fid: str, pre: str | None = None) -> FixResult:
    return FixResult.model_validate({
        "finding_id": fid, "tier": "B", "candidates": 1, "winner": {"patch": "--- a/app.py\n+++ b/app.py\n", "diff_lines": 1},
        "gates": {"exploit_blocked": True, "feature_works": True, "tests_pass": True, "no_new_findings": True, "diff_is_small": True},
        "rejected": [], "accepted": True, "pre_fix_commit": pre})


def test_record_fix_updates_status_and_replaces_older_results(tmp_path, capsys):
    proj, fid = report_for(tmp_path)
    rep = record_fix(proj, accepted_result(fid))
    assert rep.findings[0].status == "fixing" and len(rep.fixes) == 1
    bad = FixResult.model_validate({**accepted_result(fid).model_dump(mode="json"), "accepted": False, "winner": None, "rejected": [{"reason": "r"}]})
    rep = record_fix(proj, bad)
    assert rep.findings[0].status == "fix-rejected" and len(rep.fixes) == 1 and not rep.fixes[0].accepted
    none = bad.model_copy(update={"candidates": 0})
    assert record_fix(proj, none).findings[0].status == "needs-human"
    assert "needs-human" in (proj / ".proofgate" / "report.html").read_text(encoding="utf-8")


def test_record_fix_without_a_report_is_a_no_op(tmp_path):
    assert record_fix(tmp_path, accepted_result("f_x")) is None


def test_accepted_risk_status_is_not_overwritten(tmp_path):
    proj, fid = report_for(tmp_path)
    p = proj / ".proofgate" / "report.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    d["findings"][0]["status"] = "accepted-risk"
    p.write_text(json.dumps(d), encoding="utf-8")
    assert record_fix(proj, accepted_result(fid)).findings[0].status == "accepted-risk"


# ============================================================================= rollback
def committed_fix(tmp_path: Path):
    """A git repo whose last commit is the accepted fix; returns (repo, finding id, pre-fix commit, fix commit)."""
    proj, fid = report_for(tmp_path)
    git(proj, "init", "-q")
    (proj / ".gitignore").write_text(".proofgate/\n__pycache__/\n", encoding="utf-8")
    git(proj, "add", ".")
    git(proj, "commit", "-q", "-m", "before")
    pre = git(proj, "rev-parse", "--short", "HEAD")
    assert main(["fix", str(proj), "--finding", fid, "--no-vaccine"]) == 0
    res = Report.model_validate_json((proj / ".proofgate" / "report.json").read_text(encoding="utf-8")).fixes[0]
    assert res.pre_fix_commit == pre
    return proj, fid, pre, res


def test_rollback_prints_the_exact_revert_command_and_changes_nothing(tmp_path, capsys):
    proj, fid, pre, res = committed_fix(tmp_path)
    apply_patch(proj, res.winner.patch)
    git(proj, "commit", "-q", "-am", "apply the proofgate fix")
    fix_commit = git(proj, "rev-parse", "--short", "HEAD")
    head, status = git(proj, "rev-parse", "HEAD"), git(proj, "status", "--porcelain")
    capsys.readouterr()
    assert main(["rollback", fid, "--dir", str(proj)]) == 0
    out, err = capsys.readouterr()
    assert out.strip() == f"git revert {fix_commit}" and "never runs it" in err
    assert git(proj, "rev-parse", "HEAD") == head and git(proj, "status", "--porcelain") == status  # nothing was run


def test_rollback_lists_several_commits_newest_first(tmp_path):
    proj, fid, pre, res = committed_fix(tmp_path)
    apply_patch(proj, res.winner.patch)
    git(proj, "commit", "-q", "-am", "fix part 1")
    c1 = git(proj, "rev-parse", "--short", "HEAD")
    (proj / "app.py").write_text((proj / "app.py").read_text(encoding="utf-8") + "# tweak\n", encoding="utf-8")
    git(proj, "commit", "-q", "-am", "tweak the fixed file")
    c2 = git(proj, "rev-parse", "--short", "HEAD")
    assert rollback_commands(proj, fid) == [f"git revert {c2} {c1}"]


def test_rollback_before_the_fix_is_committed_says_so(tmp_path):
    proj, fid, pre, res = committed_fix(tmp_path)
    cmds = rollback_commands(proj, fid)
    assert "not been committed" in cmds[0] and "git checkout -- app.py" in cmds[1]


def test_rollback_without_git_or_without_a_fix(tmp_path, capsys):
    proj, fid = report_for(tmp_path)
    record_fix(proj, accepted_result(fid, pre=None))
    assert "no git history recorded" in rollback_commands(proj, fid)[0]
    with pytest.raises(LookupError):
        rollback_commands(proj, "f_nope")
    assert main(["rollback", "f_nope", "--dir", str(proj)]) == 2


# ============================================================================= CLI
def test_cli_fix_records_the_result_and_prints_the_vaccine(tmp_path, capsys):
    proj, fid = report_for(tmp_path)
    capsys.readouterr()
    assert main(["fix", str(proj), "--finding", fid]) == 0
    out = capsys.readouterr().out
    res = FixResult.model_validate_json(out)
    assert res.accepted and res.regression_test == f"{PY_TEST_FILE}::test_{fid}" and res.vaccine_patch
    assert RULE in res.vaccine_patch and not (proj / PY_TEST_FILE).exists()  # printed, never applied
    rep = Report.model_validate_json((proj / ".proofgate" / "report.json").read_text(encoding="utf-8"))
    assert rep.findings[0].status == "fixing" and rep.fixes[0].regression_test == res.regression_test
