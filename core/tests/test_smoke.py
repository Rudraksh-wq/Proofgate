"""`make smoke`: the twelve integration tests of plan section 11 (T1-T12), run end to end in under five minutes.

Everything here is hermetic (PROOFGATE_OFFLINE=1, no network, throwaway databases). Where a check needs the live Supabase stack,
Docker, Semgrep or a built website, the test says so with pytest.skip and covers the part that can run here: it never fakes a pass.
"""
import asyncio
import importlib.metadata
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from proofgate import hook
from proofgate.fix.patching import apply_patch, make_diff
from proofgate.fix.pipeline import fix_finding
from proofgate.fix.tournament import Candidate, compute_baseline, run_tournament
from proofgate.fix.vaccinate import AGENT_FILES, build_vaccine
from proofgate.inline import check_file
from proofgate.layers import l5_database as l5
from proofgate.mcpserver import FENCE_CLOSE, TOOL_NAMES
from proofgate.models import LIMITS_STATEMENT, Report
from proofgate.orchestrator import run_scan
from proofgate.pkgcache import PackageCache
from proofgate.probe import load_contract, run_probe
from proofgate.redact import find_leaks
from proofgate.runner import ToolResult

from conftest import fake_secrets
from corpus_harness import CORPUS, FIXES, ROOT
from test_mcp_server import Session, data_of
from test_probe_flask import CORPUS_APPS, EXPECTED_RULES, app_dir

pytestmark = pytest.mark.smoke

DEMO = ROOT / "demo-apps" / "nextjs-supabase"
KEY = fake_secrets()["stripe"]
FIXTURES = Path(__file__).parent / "fixtures" / "tool_outputs"


def copy(src: Path, tmp_path: Path, name: str = "proj") -> Path:
    dst = tmp_path / name
    shutil.copytree(src, dst)
    return dst


def hook_payload(root: Path, content: str, name: str = "app.py") -> str:
    return json.dumps({"cwd": str(root), "hook_event_name": "PreToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": str(root / name), "content": content}})


# ============================================================================= T1 install
def test_t1_install_doctor_entry_points_and_plugin():
    scripts = {e.name for e in importlib.metadata.entry_points(group="console_scripts")}
    assert {"proofgate", "proofgate-mcp"} <= scripts
    r = subprocess.run([sys.executable, "-m", "proofgate.cli", "doctor"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "docker" in r.stdout, r.stdout + r.stderr  # no checksum mismatch; missing tools are only recorded
    assert "mismatch" not in r.stdout
    claude = shutil.which("claude")
    if claude:
        for target in (ROOT / "plugin", ROOT):
            v = subprocess.run([claude, "plugin", "validate", str(target)], capture_output=True, text=True, timeout=120)
            assert v.returncode == 0 and "Validation passed" in v.stdout, v.stdout


def test_t1_the_built_wheel_ships_its_data_files(tmp_path):
    r = subprocess.run([sys.executable, "-m", "pip", "wheel", str(ROOT / "core"), "--no-deps", "--no-build-isolation", "-w", str(tmp_path), "-q"],
                       capture_output=True, text=True, timeout=240)
    if r.returncode != 0:
        pytest.skip("cannot build a wheel offline in this environment: " + (r.stderr or r.stdout)[-200:])
    import zipfile

    names = zipfile.ZipFile(next(tmp_path.glob("proofgate-*.whl"))).namelist()
    for needle in ("proofgate/tools.lock.json", "proofgate/rules/python.yaml", "proofgate/rules/javascript.yaml", "proofgate/rules/route.yaml",
                   "proofgate/data/top_packages.json", "proofgate/cli.py", "proofgate/mcpserver.py"):
        assert needle in names, needle
    assert not any(n.startswith("proofgate/rules/") and n.endswith((".py", ".ts")) for n in names)  # no vulnerable samples shipped


# ============================================================================= T2 inline block
async def test_t2_live_key_is_blocked_then_the_ai_moves_it_to_env_and_rotation_is_mentioned(tmp_path):
    proj = tmp_path / "app"
    proj.mkdir()
    code = f'import os\nSTRIPE_KEY = "{KEY}"\n'
    blocked = hook.run_hook("pre", hook_payload(proj, code), project_dir=str(proj))
    assert blocked.exit_code == 2 and "environment variable" in blocked.stderr and "rotate" in blocked.stderr
    assert KEY not in blocked.stderr

    # what the AI does next: the deterministic Tier A fix (move to .env.example + os.environ), verified by the tournament
    (proj / "app.py").write_text(code, encoding="utf-8")
    finding = next(f for f in check_file(proj / "app.py", project_root=proj, cache=PackageCache(tmp_path / "c.json")).findings if f.layer == 1)
    res = await fix_finding(proj, finding, load_contract(proj))
    assert res.accepted and any("rotate" in n for n in res.notes)
    assert "SECRET:" in res.winner.patch  # the diff shows the key masked; the file is edited by hand as the patch describes
    (proj / "app.py").write_text('import os\nSTRIPE_KEY = os.environ.get("STRIPE_KEY")\n', encoding="utf-8")
    allowed = hook.run_hook("pre", hook_payload(proj, (proj / "app.py").read_text(encoding="utf-8")), project_dir=str(proj))
    assert allowed.exit_code == 0 and allowed.allowed


# ============================================================================= T3 precision bait
async def test_t3_the_bait_app_has_no_critical_finding():
    out = await run_scan(CORPUS / "c03_bait", offline=True)
    assert [f for f in out.report.findings if f.severity == "critical"] == []  # the anon key and the allow-listed SQL are not flagged
    assert not out.tool_error


# ============================================================================= T4 layers 1-4 flag v09-v13
def _recorded_runner():
    bandit = (FIXTURES / "bandit_corpus.json").read_text(encoding="utf-8").replace("{{PROJECT}}", str(CORPUS).replace("\\", "\\\\"))
    pip_audit = (FIXTURES / "pip_audit_requests_2_19_0.json").read_text(encoding="utf-8")

    async def runner(name, args, **kw):
        out = {"bandit": bandit, "pip-audit": pip_audit}.get(name)
        if out is None:
            return ToolResult(name, "skipped", reason=f"{name} not installed here")
        return ToolResult(name, "ok", 0, out, "", 0.1, sha256="0" * 64)

    return runner


async def test_t4_layers_flag_v09_to_v13_and_the_three_counts_are_printed(tmp_path, capsys):
    fake = json.loads((CORPUS / "registry_check.json").read_text(encoding="utf-8"))["package"]
    cache = PackageCache(tmp_path / "packages.json")
    cache.put("pypi", fake, exists=False)
    cache.put("pypi", "Flask", exists=True, first_release="2010-04-06", weekly_downloads=10**7)
    cache.put("pypi", "requests", exists=True, first_release="2011-02-14", weekly_downloads=10**7)
    out = await run_scan(CORPUS, runner=_recorded_runner(), offline=False, cache=cache, fast=True)
    r = out.report
    print(f"{r.raw_warning_count} raw -> {r.unique_count} unique -> {r.proven_count} proven")
    assert re.search(r"\d+ raw -> \d+ unique -> 0 proven", capsys.readouterr().out)
    by_app: dict[str, set[str]] = {}
    for f in r.findings:
        by_app.setdefault(f.location.file.split("/")[0], set()).add(f.rule)
    assert {"stripe-live-secret-key", "supabase-service-role-key"} <= by_app["v09_hardcoded_keys"]  # L1
    assert "supabase-service-role-key" in by_app["v10_service_role_in_bundle"]  # L1 on the bundle
    assert "package-does-not-exist" in by_app["v11_hallucinated_dep"]  # L4
    assert "known-vulnerable-dependency" in by_app["v12_outdated_dep"]  # L3 (recorded real pip-audit output)
    v13 = [f for f in r.findings if f.location.file.startswith("v13_debug_tls")]
    assert {"CWE-489", "CWE-295"} <= {f.cwe for f in v13}  # L2: debug mode and disabled TLS (merged with Bandit's report of the same lines)
    assert not any(app in by_app for app in ("c01_clean", "c02_clean_helper"))
    assert r.raw_warning_count >= r.unique_count


# ============================================================================= T5 the probe proves v01-v08, nothing on c01-c03
@pytest.fixture(scope="module")
def probed():
    async def go():
        gate = asyncio.Semaphore(8)

        async def one(n):
            async with gate:
                return await run_probe(app_dir(n))

        return dict(zip(CORPUS_APPS, await asyncio.gather(*(one(n) for n in CORPUS_APPS))))

    return asyncio.run(go())


def test_t5_prove_marks_v01_to_v08_proven_and_nothing_on_the_clean_apps(probed):
    for name, rules in EXPECTED_RULES.items():
        if name not in probed:
            continue  # fix apps are covered by T7
        out = probed[name]
        assert out.error is None and {c.rule for c in out.result.proven} == rules, name
        assert out.result.untested == [], name  # nothing silently skipped: untested items would be listed here
    for clean in ("c01_clean", "c02_clean_helper", "c03_bait"):
        assert probed[clean].result.proven == []
    assert all(v is True for v in probed["c01_clean"].result.oracles.values())  # every owner oracle is true on c01
    assert sum(1 for n in probed if probed[n].result.proven) == 8 and all(probed[f"v0{i}" + s].result.proven for i, s in
                                                                           ((1, "_idor_read"), (2, "_idor_write"), (3, "_idor_param"), (4, "_missing_role"),
                                                                            (5, "_unauth_admin"), (6, "_mass_assign"), (7, "_sqli"), (8, "_cmdi")))


# ============================================================================= T6 Supabase
@pytest.mark.parametrize("letter,rule", [("A", "rls-disabled"), ("B", "policy-role-without-uid")])
async def test_t6_variants_a_and_b_are_flagged_statically(tmp_path, letter, rule):
    proj = tmp_path / "sb"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    names = {"A": "a_rls_off.sql", "B": "b_auth_role.sql"}
    shutil.copy(DEMO / "supabase" / "variants" / names[letter], proj / "supabase" / "migrations" / "20240201000000_rls_variant.sql")
    res = await l5.run(proj)
    assert any(f.rule.endswith(rule) and f.severity in ("critical", "high") for f in res.findings)


async def test_t6_variant_c_is_clean_and_select_using_true_on_an_owner_table_is_flagged(tmp_path):
    proj = tmp_path / "sb"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    shutil.copy(DEMO / "supabase/variants/c_owner_only.sql", proj / "supabase/migrations/20240201000000_rls_variant.sql")
    assert not [f for f in (await l5.run(proj)).findings if "rls" in f.rule or "policy" in f.rule]
    (proj / "supabase/migrations/20240201000000_rls_variant.sql").write_text(
        "alter table public.notes enable row level security;\ncreate policy anyone on public.notes for select using (true);\n", encoding="utf-8")
    flagged = [f for f in (await l5.run(proj)).findings if f.rule.endswith("policy-using-true")]
    assert flagged and flagged[0].severity == "high"  # Splinter 0024 skips SELECT on purpose; the contract does not


def test_t6_live_probe_of_variants_a_b_c():
    pytest.skip("needs live stack (supabase start + Docker) - verified in chore/verify-live-tools; the static half above runs here")
