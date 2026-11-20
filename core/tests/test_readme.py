import re
import subprocess
import sys
from pathlib import Path

from proofgate.mcpserver import TOOL_NAMES
from proofgate.models import LIMITS_STATEMENT
from proofgate.orchestrator import IMPLEMENTED

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_benchmark_block_matches_the_measured_results():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "update_readme_bench.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, "README.md is out of date: run `python scripts/update_readme_bench.py`"


def test_readme_has_the_required_sections_and_the_pitch():
    for heading in ("## What it does", "## The nine layers", "## Install", "## Limits", "## Benchmark (measured, not claimed)", "## Privacy and safety"):
        assert heading in README, heading
    assert "ProofGate shows you the stolen data, and only accepts a fix that provably stops it" in README
    assert LIMITS_STATEMENT in README
    assert "/plugin install proofgate@proofgate" in README and "pipx install proofgate" in README and "proofgate-mcp" in README


def test_readme_layer_status_matches_what_is_built():
    rows = re.findall(r"^\| (\d) \| [^|]+\|[^|]+\| ([^|]+) \|$", README, re.MULTILINE)
    assert len(rows) == 9
    for n, status in rows:
        built = int(n) in IMPLEMENTED
        assert status.startswith("built") == built, (n, status)
        assert (not built) == status.startswith("not built"), (n, status)


def test_readme_names_all_six_mcp_tools_and_never_claims_security():
    for t in TOOL_NAMES:
        assert t in README
    for m in re.finditer(r"(?:is|are|be|now|becomes?) (?:completely |fully )?(?:secure|safe)\b", README, re.IGNORECASE):
        ctx = README[max(0, m.start() - 60): m.end() + 5].lower()
        assert "doesn't mean" in ctx or "never says" in ctx, ctx


def test_readme_make_targets_exist():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("corpus", "test", "smoke", "bench"):
        assert re.search(rf"^{target}:", makefile, re.MULTILINE), target
