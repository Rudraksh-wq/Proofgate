"""Fix pipeline: patching, Tier A/B fixers, the 5-gate tournament, guards A and B (plan 4, T7)."""
import asyncio
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from proofgate.fix import tier_a, tier_b
from proofgate.fix.patching import PatchError, apply_patch, diff_stats, make_diff, parse_patch
from proofgate.fix.pipeline import classify, deterministic_candidates, fix_finding, verify_patch
from proofgate.fix.tournament import MAX_DIFF_LINES, Candidate, compute_baseline, run_tournament
from proofgate.inline import check_file
from proofgate.layers import l5_database as l5
from proofgate.models import Finding
from proofgate.pkgcache import PackageCache
from proofgate.probe import load_contract, run_probe

from conftest import fake_secrets
from corpus_harness import CORPUS, FIXES

DEMO = Path(__file__).resolve().parents[2] / "demo-apps" / "nextjs-supabase"


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".proofgate" not in p.parts:
            h.update(str(p.relative_to(root)).encode() + p.read_bytes())
    return h.hexdigest()


def copy(src: Path, tmp_path: Path, name="proj") -> Path:
    dst = tmp_path / name
    shutil.copytree(src, dst)
    return dst


async def probe_findings(proj: Path):
    out = await run_probe(proj)
    return out, out.result.to_findings(out.contract)


# ============================================================================= patching
def test_make_parse_apply_roundtrip(tmp_path):
    (tmp_path / "a.txt").write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")
    patch = make_diff("a.txt", "one\ntwo\nthree\nfour\nfive\n", "one\n2\nthree\nfour\nfive\nsix\n")
    assert apply_patch(tmp_path, patch) == ["a.txt"]
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "one\n2\nthree\nfour\nfive\nsix\n"
    s = diff_stats(patch)
    assert (s.added, s.removed, s.files, s.new_files) == (2, 1, ("a.txt",), ())


def test_new_file_and_stats(tmp_path):
    patch = make_diff("sub/new.sql", None, "select 1;\nselect 2;\n")
    assert diff_stats(patch).new_files == ("sub/new.sql",) and diff_stats(patch).changed_lines == 2
    apply_patch(tmp_path, patch)
    assert (tmp_path / "sub" / "new.sql").read_text(encoding="utf-8") == "select 1;\nselect 2;\n"
    with pytest.raises(PatchError, match="already exists"):
        apply_patch(tmp_path, patch)


def test_hunk_that_does_not_match_is_an_error_and_changes_nothing(tmp_path):
    (tmp_path / "a.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    patch = make_diff("a.txt", "alpha\nOTHER\n", "alpha\nX\n")
    with pytest.raises(PatchError, match="does not match"):
        apply_patch(tmp_path, patch)
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "alpha\nbeta\n"


def test_hunk_is_found_when_line_numbers_have_drifted(tmp_path):
    body = "".join(f"line{i}\n" for i in range(30))
    (tmp_path / "a.txt").write_text("extra\nextra2\n" + body, encoding="utf-8")
    patch = make_diff("a.txt", body, body.replace("line15\n", "CHANGED\n"))
    apply_patch(tmp_path, patch)
    assert "CHANGED" in (tmp_path / "a.txt").read_text(encoding="utf-8")


def test_crlf_files_keep_their_line_endings(tmp_path):
    crlf = chr(13) + chr(10)
    before, after = crlf.join(["one", "two", "three", ""]), crlf.join(["one", "TWO", "three", ""])
    (tmp_path / "a.txt").write_bytes(before.encode())
    patch = make_diff("a.txt", before, after)
    assert chr(13) not in patch  # patches are LF
    apply_patch(tmp_path, patch)
    assert (tmp_path / "a.txt").read_bytes() == after.encode()
    assert diff_stats(patch).changed_lines == 2


@pytest.mark.parametrize("path", ["../evil.txt", "a/../../evil.txt", "/etc/evil", "C:/evil.txt"])
def test_paths_escaping_the_project_are_refused(tmp_path, path):
    patch = f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n"
    with pytest.raises(PatchError):
        apply_patch(tmp_path, patch)
    assert not (tmp_path.parent / "evil.txt").exists()


@pytest.mark.parametrize("bad", ["", "not a diff", "--- a/x\n", "--- a/x\n+++ b/x\n@@ garbage @@\n"])
def test_malformed_patches(bad):
    with pytest.raises(PatchError):
        parse_patch(bad)


# ============================================================================= Tier A codemods
SQL_CASES = [
    ('def f(c, q):\n    c.execute(f"SELECT * FROM t WHERE a = \'{q}\'")\n', '"SELECT * FROM t WHERE a = ?", (q,)'),
    ('def f(c, q):\n    c.execute(f"SELECT * FROM t WHERE a LIKE \'%{q}%\'")\n', '"SELECT * FROM t WHERE a LIKE ?", (f"%{q}%",)'),
    ('def f(c, n, u):\n    c.execute(f"SELECT * FROM t WHERE id = {n} AND u = \'{u}\'")\n', '"SELECT * FROM t WHERE id = ? AND u = ?", (n, u)'),
    ("def f(c, user):\n    c.execute(f\"SELECT * FROM t WHERE id = {user['id']}\")\n", '"SELECT * FROM t WHERE id = ?", (user[\'id\'],)'),
]


@pytest.mark.parametrize("code,expected", SQL_CASES)
def test_sql_becomes_placeholders(code, expected):
    new = tier_a.fix_sql_placeholders(code, 2, "f")
    assert new is not None and expected in new
    compile(new, "x", "exec")


def test_sql_with_percent_s_for_postgres_drivers():
    new = tier_a.fix_sql_placeholders("import psycopg2\ndef f(c, q):\n    c.execute(f\"SELECT {q}\")\n", 3, "f")
    assert "%s" in new and "?" not in new


@pytest.mark.parametrize("code", [
    'def f(c, q):\n    c.execute("SELECT 1 WHERE a = ?", (q,))\n',  # already parameterised
    'def f(c, q):\n    c.execute(f"SELECT {q:>5}")\n',  # format spec: do not guess
    'def f(c, q):\n    c.execute(f"SELECT \'{q}")\n',  # unbalanced quote
    "def f(c, q):\n    c.execute(q)\n",
])
def test_sql_fixer_refuses_what_it_cannot_do_safely(code):
    assert tier_a.fix_sql_placeholders(code, 2, "f") is None


def test_sql_fixer_touches_only_the_function_it_was_pointed_at():
    code = 'def a(c, q):\n    c.execute(f"SELECT {q}")\n\ndef b(c, q):\n    c.execute(f"SELECT {q}")\n'
    new = tier_a.fix_sql_placeholders(code, 2, "a")
    assert new.count('f"SELECT {q}"') == 1


def test_shell_true_becomes_an_argument_list():
    new = tier_a.fix_shell_true('import subprocess\ndef f(n):\n    subprocess.run(f"echo {n} -x", shell=True, capture_output=True)\n', 3, "f")
    assert 'subprocess.run(["echo", str(n), "-x"], capture_output=True)' in new
    new2 = tier_a.fix_shell_true("import subprocess\ndef f(n):\n    subprocess.run('ls', shell=True)\n", 3, "f")
    assert 'subprocess.run(["ls"])' in new2
    compile(new, "x", "exec")


@pytest.mark.parametrize("cmd", ['"ls | wc"', 'f"cat {n} > out"', 'f"echo $HOME {n}"', "build_cmd(n)"])
def test_shell_fixer_refuses_real_shell_syntax(cmd):
    assert tier_a.fix_shell_true(f"import subprocess\ndef f(n):\n    subprocess.run({cmd}, shell=True)\n", 3, "f") is None


def test_debug_true_reads_the_environment_and_adds_the_import():
    new = tier_a.fix_debug_true('from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n', 3, None)
    assert 'debug=os.environ.get("FLASK_DEBUG") == "1"' in new and "import os" in new
    assert tier_a.fix_debug_true("import os\napp.run(debug=True)\n", 2, None).count("import os") == 1


def test_verify_false_is_removed_wherever_it_sits():
    for call in ("requests.get(u, verify=False)", "requests.get(u, verify=False, timeout=3)", "requests.get(u, timeout=3, verify=False)"):
        new = tier_a.fix_verify_false(f"import requests\ndef f(u):\n    return {call}\n", 3, "f")
        assert "verify" not in new
        compile(new, "x", "exec")
    assert "create_default_context" in tier_a.fix_verify_false("import ssl\nctx = ssl._create_unverified_context()\n", 2, None)


def test_hardcoded_secret_moves_to_env_and_is_idempotent(tmp_path):
    key = fake_secrets()["stripe"]
    (tmp_path / "app.py").write_text(f'import flask\nSTRIPE_KEY = "{key}"\n', encoding="utf-8")
    ch = tier_a.fix_hardcoded_secret(tmp_path, "app.py", 2)
    assert 'STRIPE_KEY = os.environ.get("STRIPE_KEY")' in ch["app.py"] and "import os" in ch["app.py"] and key not in ch["app.py"]
    assert ch[".env.example"] == "STRIPE_KEY=\n" and ch[".gitignore"] == ".env\n"
    (tmp_path / ".env.example").write_text("STRIPE_KEY=\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    assert set(tier_a.fix_hardcoded_secret(tmp_path, "app.py", 2)) == {"app.py"}


def test_hardcoded_secret_in_javascript(tmp_path):
    (tmp_path / "c.ts").write_text('export const API_TOKEN = "abcdefghij1234567890";\n', encoding="utf-8")
    ch = tier_a.fix_hardcoded_secret(tmp_path, "c.ts", 1)
    assert "export const API_TOKEN = process.env.API_TOKEN;" in ch["c.ts"]


def test_secret_fixer_refuses_lines_that_are_not_simple_assignments(tmp_path):
    (tmp_path / "app.py").write_text('call(key="abcdef")\nx = {"k": "abcdef"}\n', encoding="utf-8")
    assert tier_a.fix_hardcoded_secret(tmp_path, "app.py", 1) is None and tier_a.fix_hardcoded_secret(tmp_path, "app.py", 2) is None
    assert tier_a.fix_hardcoded_secret(tmp_path, "app.py", 99) is None


def test_dependency_bump(tmp_path):
    f = Finding.model_validate({
        "id": "f_1", "layer": 3, "category": "deps", "rule": "known-vulnerable-dependency", "severity": "high",
        "title": "requests 2.19.0 has known vulnerabilities (requirements.txt:2)", "plain_words": "p", "fixed_in": "2.33.0",
        "location": {"file": "requirements.txt", "line": 2}, "sources": ["pip-audit"]})
    (tmp_path / "requirements.txt").write_text("Flask>=3\nrequests==2.19.0\n", encoding="utf-8")
    assert tier_a.bump_dependency(tmp_path, f).replace(chr(13) + chr(10), chr(10)) == "Flask>=3\nrequests==2.33.0\n"
    (tmp_path / "package.json").write_text('{"dependencies": {"requests": "^1.0.0"}}', encoding="utf-8")
    g = f.model_copy(update={"location": f.location.model_copy(update={"file": "package.json"})})
    assert '"requests": "2.33.0"' in tier_a.bump_dependency(tmp_path, g)
    assert tier_a.bump_dependency(tmp_path, f.model_copy(update={"fixed_in": None})) is None


# ============================================================================= Tier B + tournament on the corpus
APPS = {"cross-user-read": "v01_idor_read", "cross-user-write": "v02_idor_write", "cross-user-list": "v03_idor_param",
        "admin-route-missing-role-check": "v04_missing_role", "admin-route-unauthenticated": "v05_unauth_admin",
        "mass-assignment": "v06_mass_assign", "sql-injection": "v07_sqli", "command-injection": "v08_cmdi"}


@pytest.fixture(scope="module")
def probes():
    """{app: (ProbeOutcome, findings, baseline)} for the eight vulnerable apps, computed once."""
    async def go():
        res = {}
        for app in sorted(set(APPS.values())):
            out, findings = await probe_findings(CORPUS / app)
            res[app] = (out, findings, await compute_baseline(CORPUS / app, out.contract))
        return res

    return asyncio.run(go())


@pytest.mark.parametrize("rule,app", sorted(APPS.items()))
def test_generated_fix_is_accepted_and_really_closes_the_hole(probes, tmp_path, rule, app):
    out, findings, base = probes[app]
    f = next(x for x in findings if x.rule == rule)

    async def go():
        before = tree_hash(CORPUS / app)
        res = await fix_finding(CORPUS / app, f, out.contract, baseline=base)
        assert tree_hash(CORPUS / app) == before  # Guard A: the real project is untouched
        assert res.accepted and res.applied_in == "temp_copy" and res.winner.diff_lines <= MAX_DIFF_LINES
        g = res.gates
        assert (g.exploit_blocked, g.feature_works, g.tests_pass, g.no_new_findings, g.diff_is_small) == (True,) * 5
        # now apply it for real, in a copy, and attack again
        proj = copy(CORPUS / app, tmp_path)
        apply_patch(proj, res.winner.patch)
        again = await run_probe(proj)
        assert rule not in {c.rule for c in again.result.proven if c.actor == f.evidence.actor}, rule
        assert all(v is True for v in again.result.oracles.values()), again.result.oracles
        return res

    res = asyncio.run(go())
    assert res.learned_rule and res.pre_fix_commit is None or res.pre_fix_commit


@pytest.mark.parametrize("fix_name,app,rule", [
    ("v01", "v01_idor_read", "cross-user-read"), ("v05", "v05_unauth_admin", "admin-route-unauthenticated"),
    ("v06", "v06_mass_assign", "mass-assignment"), ("v07", "v07_sqli", "sql-injection")])
@pytest.mark.parametrize("kind", ["correct", "lazy", "partial"])
def test_the_twelve_candidate_fixes(probes, fix_name, app, rule, kind):
    """T7: correct accepted; lazy and partial rejected with the right reason."""
    out, findings, base = probes[app]
    f = next(x for x in findings if x.rule == rule)
    old = (CORPUS / app / "app.py").read_text(encoding="utf-8")
    new = (FIXES / f"{fix_name}_{kind}" / "app.py").read_text(encoding="utf-8")
    cand = Candidate(make_diff("app.py", old, new), "B", f"{fix_name}_{kind}")
    res = asyncio.run(run_tournament(CORPUS / app, f, [cand], out.contract, baseline=base))
    json_meta = json.loads((FIXES / "fixes.json").read_text(encoding="utf-8"))[f"{fix_name}_{kind}"]
    assert res.accepted == json_meta["should_accept"], res.rejected
    if kind == "lazy":
        assert res.rejected[0].reason.split(": ", 1)[1].startswith("feature_works=false: owner can no longer") or \
               "feature_works=false: admin can no longer" in res.rejected[0].reason
        assert res.gates.exploit_blocked and not res.gates.feature_works
    if kind == "partial":
        assert "exploit_blocked=false" in res.rejected[0].reason and not res.gates.exploit_blocked


def test_lazy_v01_reason_matches_the_master_guide_wording(probes):
    out, findings, base = probes["v01_idor_read"]
    f = findings[0]
    old = (CORPUS / "v01_idor_read" / "app.py").read_text(encoding="utf-8")
    new = (FIXES / "v01_lazy" / "app.py").read_text(encoding="utf-8")
    res = asyncio.run(run_tournament(CORPUS / "v01_idor_read", f, [Candidate(make_diff("app.py", old, new), "B", "lazy")], out.contract, baseline=base))
    assert "feature_works=false: owner can no longer read own notes" in res.rejected[0].reason


def test_smallest_passing_candidate_wins_and_every_loser_has_a_reason(probes):
    out, findings, base = probes["v01_idor_read"]
    f = findings[0]
    old = (CORPUS / "v01_idor_read" / "app.py").read_text(encoding="utf-8")
    cands = [Candidate(make_diff("app.py", old, (FIXES / f"v01_{k}" / "app.py").read_text(encoding="utf-8")), "B", k)
             for k in ("lazy", "correct", "partial")]
    res = asyncio.run(run_tournament(CORPUS / "v01_idor_read", f, cands, out.contract, baseline=base))
    assert res.accepted and res.candidates == 3 and len(res.rejected) == 2
    assert {r.reason.split(":")[0] for r in res.rejected} == {"lazy", "partial"}


def test_nothing_passes_means_needs_human_with_every_reason(probes):
    out, findings, base = probes["v01_idor_read"]
    f = findings[0]
    old = (CORPUS / "v01_idor_read" / "app.py").read_text(encoding="utf-8")
    cands = [Candidate(make_diff("app.py", old, (FIXES / f"v01_{k}" / "app.py").read_text(encoding="utf-8")), "B", k) for k in ("lazy", "partial")]
    res = asyncio.run(run_tournament(CORPUS / "v01_idor_read", f, cands, out.contract, baseline=base))
    assert not res.accepted and res.winner is None and len(res.rejected) == 2


# ----------------------------------------------------------------------------- the other gates
def test_gate_5_rejects_big_diffs_and_other_files(probes, tmp_path):
    out, findings, base = probes["v01_idor_read"]
    f = findings[0]
    proj = CORPUS / "v01_idor_read"
    old = (proj / "app.py").read_text(encoding="utf-8")
    good = tier_b.owner_filter(old, f, out.contract)
    big = good + "".join(f"# filler {i}\n" for i in range(60))
    res = asyncio.run(run_tournament(proj, f, [Candidate(make_diff("app.py", old, big), "B", "big")], out.contract, baseline=base))
    assert not res.accepted and "diff_is_small=false" in res.rejected[0].reason and "limit 40" in res.rejected[0].reason

    other = make_diff("app.py", old, good) + make_diff("extra.py", None, "print('hi')\n")
    res = asyncio.run(run_tournament(proj, f, [Candidate(other, "B", "two-files")], out.contract, baseline=base))
    assert not res.accepted and "outside the finding" in res.rejected[0].reason and "extra.py" in res.rejected[0].reason


def test_patch_that_does_not_apply_or_is_not_a_diff(probes):
    out, findings, base = probes["v01_idor_read"]
    f = findings[0]
    bad = make_diff("app.py", "totally different\n", "text\n")
    res = asyncio.run(run_tournament(CORPUS / "v01_idor_read", f, [Candidate(bad, "B", "stale"), Candidate("hello", "B", "junk")],
                                     out.contract, baseline=base))
    assert [("does not apply" in r.reason) or ("not a valid diff" in r.reason) for r in res.rejected] == [True, True]


def test_gate_4_rejects_a_fix_that_adds_a_new_vulnerability(probes):
    out, findings, base = probes["v01_idor_read"]
    f = findings[0]
    proj = CORPUS / "v01_idor_read"
    old = (proj / "app.py").read_text(encoding="utf-8")
    good = tier_b.owner_filter(old, f, out.contract)
    sneaky = good.replace('if __name__ == "__main__":', 'def _x(n):\n    import subprocess\n    subprocess.run(f"echo {n}", shell=True)\n\n\nif __name__ == "__main__":')
    res = asyncio.run(run_tournament(proj, f, [Candidate(make_diff("app.py", old, sneaky), "B", "sneaky")], out.contract, baseline=base))
    assert not res.accepted and "no_new_findings=false: introduces proofgate.py-shell-true" in res.rejected[0].reason
    assert res.gates.exploit_blocked and res.gates.feature_works  # the attack is closed; the new hole is what rejects it


def test_gate_3_rejects_a_fix_that_breaks_the_projects_tests(probes, tmp_path):
    out, findings, base0 = probes["v01_idor_read"]
    f = findings[0]
    proj = copy(CORPUS / "v01_idor_read", tmp_path)
    (proj / "tests").mkdir()
    (proj / "tests" / "test_guard.py").write_text(
        "def test_vulnerable_lookup_is_still_there():\n"
        "    text = open('app.py', encoding='utf-8').read()\n"
        "    assert '    if note is None:' + chr(10) + '        abort(404)' + chr(10) + '    return jsonify' in text\n",
        encoding="utf-8")
    # passes on the original, fails once the vulnerable lookup is fixed: a contrived "regression"
    base = asyncio.run(compute_baseline(proj, out.contract))
    res = asyncio.run(fix_finding(proj, f, out.contract, baseline=base))
    assert not res.accepted and "tests_pass=false" in res.rejected[0].reason and not res.gates.tests_pass


def test_tests_that_already_fail_are_not_blamed_on_the_patch(probes, tmp_path):
    out, findings, _ = probes["v01_idor_read"]
    f = findings[0]
    proj = copy(CORPUS / "v01_idor_read", tmp_path)
    (proj / "tests").mkdir()
    (proj / "tests" / "test_red.py").write_text("def test_red():\n    assert False\n", encoding="utf-8")
    res = asyncio.run(fix_finding(proj, f, out.contract))
    assert res.accepted and any("already failing" in n for n in res.notes)


def test_no_template_means_needs_human(tmp_path, probes):
    out, findings, _ = probes["v01_idor_read"]
    f = findings[0].model_copy(update={"rule": "cross-user-read", "location": findings[0].location.model_copy(update={"function": "nope", "line": 1})})
    proj = copy(CORPUS / "v01_idor_read", tmp_path)
    res = asyncio.run(fix_finding(proj, f, out.contract))
    assert not res.accepted and res.candidates == 0 and "needs a human" in res.rejected[0].reason


def test_unknown_rules_need_human_review():
    f = Finding.model_validate({"id": "f_1", "layer": 2, "category": "web", "rule": "proofgate.js-eval", "severity": "high", "title": "t",
                                "plain_words": "p", "location": {"file": "a.ts", "line": 1}, "sources": ["x"]})
    assert classify(f) == "C"


# ----------------------------------------------------------------------------- Tier A end to end (static layers)
def test_secret_fix_is_accepted_and_the_secret_never_appears_in_the_result(tmp_path, no_leaks):
    proj = copy(CORPUS / "v09_hardcoded_keys", tmp_path)
    src = (proj / "app.py").read_text(encoding="utf-8")
    raw = [t for t in src.replace('"', " ").split() if t.startswith(("sk_", "eyJ"))]
    findings = check_file(proj / "app.py", project_root=proj, cache=PackageCache(tmp_path / "c.json")).findings
    stripe = next(f for f in findings if f.rule == "stripe-live-secret-key")
    res = asyncio.run(fix_finding(proj, stripe, load_contract(proj)))
    assert res.accepted and res.tier == "A" and "rotate" in res.learned_rule.lower() or res.accepted
    no_leaks(res.model_dump_json(), secrets=raw)
    assert any("shown masked" in n and "rotate" in n for n in res.notes)
    assert "SECRET:" in res.winner.patch


def test_debug_and_tls_fixes_are_accepted_for_v13(tmp_path):
    proj = copy(CORPUS / "v13_debug_tls", tmp_path)
    for f in check_file(proj / "app.py", project_root=proj, cache=PackageCache(tmp_path / "c.json")).findings:
        res = asyncio.run(fix_finding(proj, f, load_contract(proj)))
        assert res.accepted and res.winner.diff_lines == 2, f.rule


def test_dependency_fix_goes_through_the_gates(tmp_path):
    proj = copy(CORPUS / "v12_outdated_dep", tmp_path)
    f = Finding.model_validate({
        "id": "f_1", "layer": 3, "category": "deps", "rule": "known-vulnerable-dependency", "severity": "medium",
        "title": "requests 2.19.0 has known vulnerabilities (requirements.txt:2)", "plain_words": "p", "fixed_in": "2.33.0",
        "fix_tier": "A", "location": {"file": "requirements.txt", "line": 2}, "sources": ["pip-audit"]})
    res = asyncio.run(fix_finding(proj, f, load_contract(proj)))
    assert res.accepted and "requests==2.33.0" in res.winner.patch
    wrong = Candidate(make_diff("requirements.txt", (proj / "requirements.txt").read_text(encoding="utf-8"), "Flask>=3.0\nrequests==2.20.0\n"), "A", "still-old")
    res = asyncio.run(run_tournament(proj, f, [wrong], load_contract(proj)))
    assert not res.accepted and "exploit_blocked=false" in res.rejected[0].reason


# ============================================================================= Supabase: guard B
def supabase_project(tmp_path: Path, letter: str) -> Path:
    proj = tmp_path / "sb"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    names = {"A": "a_rls_off.sql", "B": "b_auth_role.sql", "C": "c_owner_only.sql"}
    shutil.copy(DEMO / "supabase" / "variants" / names[letter], proj / "supabase" / "migrations" / "20240201000000_rls_variant.sql")
    return proj


async def l5_finding(proj: Path, rule: str):
    res = await l5.run(proj)
    return next(f for f in res.findings if f.rule.endswith(rule))


@pytest.mark.parametrize("letter,rule", [("A", "rls-disabled"), ("B", "policy-role-without-uid")])
def test_rls_migration_fix_is_accepted_by_static_replay(tmp_path, letter, rule):
    proj = supabase_project(tmp_path, letter)
    f = asyncio.run(l5_finding(proj, rule))
    contract = load_contract(proj)
    before = tree_hash(proj)
    res = asyncio.run(fix_finding(proj, f, contract))
    assert tree_hash(proj) == before
    assert res.accepted and res.tier == "B" and res.gates.migrations_replayed is True
    assert "enable row level security" in res.winner.patch and "auth.uid() = user_id" in res.winner.patch
    assert any("static replay" in n and "--backend hosted --i-own-this" in n for n in res.notes)  # says how to verify it on a real database
    assert "--- /dev/null" in res.winner.patch  # a NEW file, never an edit
    # applying it leaves the project with no RLS finding on notes
    apply_patch(proj, res.winner.patch)
    left = asyncio.run(l5.run(proj))
    assert not [x for x in left.findings if "rls" in x.rule or "policy" in x.rule]


def test_editing_an_old_migration_is_rejected(tmp_path):
    proj = supabase_project(tmp_path, "A")
    f = asyncio.run(l5_finding(proj, "rls-disabled"))
    old_path = "supabase/migrations/20240201000000_rls_variant.sql"
    old = (proj / old_path).read_text(encoding="utf-8")
    fixed = "alter table public.notes enable row level security;\ncreate policy p on public.notes for all using (auth.uid() = user_id);\n"
    res = asyncio.run(run_tournament(proj, f, [Candidate(make_diff(old_path, old, fixed), "B", "edit-history")], load_contract(proj)))
    assert not res.accepted
    assert "existing migration" in res.rejected[0].reason and res.gates.migrations_replayed is False and not res.gates.diff_is_small


def test_lazy_rls_fix_using_false_is_rejected_for_breaking_the_owner(tmp_path):
    proj = supabase_project(tmp_path, "A")
    f = asyncio.run(l5_finding(proj, "rls-disabled"))
    sql = "alter table public.notes enable row level security;\ncreate policy nobody on public.notes for select using (false);\n"
    res = asyncio.run(run_tournament(proj, f, [Candidate(make_diff("supabase/migrations/20990101000000_lazy.sql", None, sql), "B", "lazy")],
                                     load_contract(proj)))
    assert not res.accepted and res.gates.exploit_blocked and not res.gates.feature_works
    assert "feature_works=false: owner can no longer read own notes" in res.rejected[0].reason


def test_partial_rls_fix_using_true_is_rejected_for_the_new_hole(tmp_path):
    proj = supabase_project(tmp_path, "A")
    f = asyncio.run(l5_finding(proj, "rls-disabled"))
    sql = "alter table public.notes enable row level security;\ncreate policy anyone on public.notes for select using (true);\n"
    res = asyncio.run(run_tournament(proj, f, [Candidate(make_diff("supabase/migrations/20990101000000_partial.sql", None, sql), "B", "partial")],
                                     load_contract(proj)))
    assert not res.accepted and "no_new_findings=false: introduces proofgate.sql-policy-using-true" in res.rejected[0].reason


def test_a_migration_with_a_syntax_error_fails_the_replay(tmp_path):
    proj = supabase_project(tmp_path, "A")
    f = asyncio.run(l5_finding(proj, "rls-disabled"))
    res = asyncio.run(run_tournament(proj, f, [Candidate(make_diff("supabase/migrations/20990101000000_bad.sql", None, "alter table notes enabel rls;\n"), "B", "bad")],
                                     load_contract(proj)))
    assert not res.accepted and res.gates.migrations_replayed is False and "migrations_replayed=false" in " ".join(r.reason for r in res.rejected)


def test_correct_owner_policies_leave_nothing_to_fix(tmp_path):
    proj = supabase_project(tmp_path, "C")
    res = asyncio.run(l5.run(proj))
    assert not any("rls" in f.rule or "policy" in f.rule for f in res.findings)


# ============================================================================= Next.js route
def test_nextjs_service_role_route_is_switched_to_the_request_scoped_client(tmp_path):
    proj = tmp_path / "next"
    for rel in ("app/api/notes/[id]/route.ts", "lib/supabase/server.ts"):
        (proj / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(DEMO / rel, proj / rel)
    f = next(x for x in check_file(proj / "app/api/notes/[id]/route.ts", project_root=proj, cache=PackageCache(tmp_path / "c.json")).findings
             if x.rule == "proofgate.next-route-service-role-client")
    res = asyncio.run(fix_finding(proj, f, load_contract(proj)))
    assert res.accepted and res.tier == "B"
    p = res.winner.patch
    assert "-const admin = createClient" in p and "+  const supabase = createServer();" in p
    assert p.count('.eq("user_id", user.id)') == 2  # both handlers now filter by the signed-in user
    assert any("feature_works not exercised" in n for n in res.notes)
    apply_patch(proj, p)
    fixed = (proj / "app/api/notes/[id]/route.ts").read_text(encoding="utf-8")
    assert "SERVICE_ROLE" not in fixed and "createClient" not in fixed and "admin." not in fixed


# ============================================================================= CLI end to end
def run_cli(capsys, *argv):
    from proofgate.cli import main

    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_cli_fix_and_verify_end_to_end(capsys, tmp_path):
    from proofgate.models import FixResult

    proj = copy(CORPUS / "v01_idor_read", tmp_path)
    code, out, _ = run_cli(capsys, "prove", str(proj))
    fid = json.loads(out)["findings"][0]["id"]
    before = tree_hash(proj)
    code, out, _ = run_cli(capsys, "fix", str(proj), "--finding", fid)
    res = FixResult.model_validate_json(out)
    assert code == 0 and res.accepted and res.winner.patch.startswith("--- a/app.py")
    assert tree_hash(proj) == before  # `fix` never edits the project

    patch = tmp_path / "lazy.diff"
    patch.write_text(make_diff("app.py", (proj / "app.py").read_text(encoding="utf-8"), (FIXES / "v01_lazy" / "app.py").read_text(encoding="utf-8")), encoding="utf-8")
    code, out, _ = run_cli(capsys, "verify", str(proj), "--finding", fid, "--patch", str(patch))
    assert code == 1 and not FixResult.model_validate_json(out).accepted
    good = tmp_path / "good.diff"
    good.write_text(make_diff("app.py", (proj / "app.py").read_text(encoding="utf-8"), (FIXES / "v01_correct" / "app.py").read_text(encoding="utf-8")), encoding="utf-8")
    code, out, _ = run_cli(capsys, "verify", str(proj), "--finding", fid, "--patch", str(good))
    assert code == 0 and FixResult.model_validate_json(out).accepted

