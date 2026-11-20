import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def steps(wf: dict):
    for job in wf["jobs"].values():
        yield from job["steps"]


def test_there_is_a_proofgate_workflow():
    assert (ROOT / ".github" / "workflows" / "proofgate.yml").is_file()


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_by_a_full_commit_sha(path):
    for s in steps(load(path)):
        uses = s.get("uses")
        if uses and not uses.startswith("./"):
            name, _, ref = uses.partition("@")
            assert FULL_SHA.match(ref), f"{uses} is not pinned by a full commit SHA"
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        if "uses:" in line and not line.strip().startswith("#"):
            assert re.search(r"@[0-9a-f]{40}\s+# v\d", line), f"missing version comment: {line.strip()}"


def test_workflow_uses_least_privilege_and_no_dangerous_triggers():
    wf = load(ROOT / ".github/workflows/proofgate.yml")
    assert wf["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in wf[True if True in wf else "on"]
    job = wf["jobs"]["scan"]
    assert job["permissions"] == {"contents": "read", "security-events": "write"}
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False
    assert "secrets." not in (ROOT / ".github/workflows/proofgate.yml").read_text(encoding="utf-8")


def test_scan_runs_the_fast_layers_fails_on_high_and_uploads_sarif():
    wf = load(ROOT / ".github/workflows/proofgate.yml")
    runs = " ".join(s.get("run", "") for s in steps(wf))
    assert "proofgate scan" in runs and "--fast" in runs and "--fail-on high" in runs and "--format sarif" in runs
    sarif = next(s for s in steps(wf) if s.get("uses", "").startswith("github/codeql-action/upload-sarif"))
    assert sarif["with"]["sarif_file"].endswith("/.proofgate/report.sarif") and sarif["with"]["category"] == "proofgate"
    assert "always()" in sarif["if"]  # findings must still be uploaded when the gate fails


def test_gate_step_propagates_the_exit_code_and_never_treats_a_tool_error_as_clean():
    wf = load(ROOT / ".github/workflows/proofgate.yml")
    gate = next(s for s in steps(wf) if s.get("name") == "Gate")
    assert gate["if"] == "steps.scan.outputs.code != '0'" and 'exit "${{ steps.scan.outputs.code }}"' in gate["run"]
    assert "2 = a layer or tool failed" in gate["run"]


def test_pinned_shas_exist_upstream():
    """The SHAs and the version comments next to them must agree with the remote (skipped offline)."""
    text = (ROOT / ".github/workflows/proofgate.yml").read_text(encoding="utf-8")
    pins = re.findall(r"uses: ([\w./-]+)@([0-9a-f]{40}) # (v[\d.]+)", text)
    assert len(pins) == 4
    for repo, sha, tag in pins:
        repo = "/".join(repo.split("/")[:2])
        try:
            r = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
                               capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pytest.skip("git or network unavailable")
        if r.returncode != 0 or not r.stdout.strip():
            pytest.skip("cannot reach GitHub")
        assert sha in r.stdout, f"{repo}@{tag} is not {sha}"


def test_the_scan_target_is_clean_with_the_tools_available_here(tmp_path):
    """The workflow scans core/proofgate; make sure ProofGate does not fail its own gate on its own source."""
    import asyncio

    from proofgate.orchestrator import run_scan

    out = asyncio.run(run_scan(ROOT / "core" / "proofgate", fast=True, offline=True))
    assert not out.tool_error
    assert [f for f in out.report.findings if f.severity in ("high", "critical")] == []


# ---------------------------------------------------------------------------- live-stack.yml (Linux runner: Docker, Supabase CLI, Semgrep, ZAP)
LIVE = ROOT / ".github" / "workflows" / "live-stack.yml"


def test_live_stack_triggers_are_push_to_main_and_manual_only():
    on = load(LIVE)[True]
    assert set(on) == {"push", "workflow_dispatch"} and on["push"]["branches"] == ["main"]


def test_live_stack_has_no_secrets_and_least_privilege():
    text = LIVE.read_text(encoding="utf-8")
    assert "secrets." not in text and "pull_request_target" not in text
    wf = load(LIVE)
    assert wf["permissions"] == {"contents": "read"}
    for job in wf["jobs"].values():
        assert "permissions" not in job or job["permissions"] == {"contents": "read"}
        co = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))
        assert co["with"]["persist-credentials"] is False


def test_live_stack_runs_what_the_laptop_cannot():
    wf = load(LIVE)
    assert {"supabase-live", "semgrep-rules", "zap-baseline", "smoke"} <= set(wf["jobs"])
    runs = {name: " ".join(s.get("run", "") for s in job["steps"]) for name, job in wf["jobs"].items()}
    assert "supabase start" in runs["supabase-live"] and "--backend local" in runs["supabase-live"]
    assert all(v in runs["supabase-live"] for v in ("for v in A B C", "ci_live_check.py", "reset_demo.py"))
    assert "semgrep --test" in runs["semgrep-rules"] and "core/rule_tests" in runs["semgrep-rules"]
    assert "--layers 7" in runs["zap-baseline"] and "zap-docker" in runs["zap-baseline"]
    assert "make smoke" in runs["smoke"]
    assert all(job["runs-on"] == "ubuntu-latest" for job in wf["jobs"].values())
    uploads = [s for job in wf["jobs"].values() for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact")]
    assert len(uploads) >= 3 and all("always()" in s["if"] for s in uploads)  # reports are kept even when a step fails


def test_live_stack_pinned_shas_exist_upstream():
    pins = re.findall(r"uses: ([\w./-]+)@([0-9a-f]{40}) # (v[\d.]+)", LIVE.read_text(encoding="utf-8"))
    assert {p[0] for p in pins} >= {"actions/checkout", "actions/setup-python", "actions/setup-node", "supabase/setup-cli", "actions/upload-artifact"}
    for repo, sha, tag in sorted(set(pins)):
        try:
            r = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
                               capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pytest.skip("git or network unavailable")
        if r.returncode != 0 or not r.stdout.strip():
            pytest.skip("cannot reach GitHub")
        assert sha in r.stdout, f"{repo}@{tag} is not {sha}"


def test_the_splinter_pin_is_a_full_commit_sha():
    assert re.search(r"SPLINTER_SHA: [0-9a-f]{40}\b", LIVE.read_text(encoding="utf-8"))


def test_ci_live_check_expects_what_the_variants_promise():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_live_check", ROOT / "scripts" / "ci_live_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.EXPECTED == {"A": (True, True), "B": (False, True), "C": (False, False)}
    assert mod.main([]) == 2 and mod.main(["Z"]) == 2
