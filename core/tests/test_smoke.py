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
