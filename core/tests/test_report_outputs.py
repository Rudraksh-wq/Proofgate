import asyncio
import json
import re
from html import unescape
from pathlib import Path

import pytest

from proofgate import orchestrator
from proofgate.layers import l1_secrets
from proofgate.models import LIMITS_STATEMENT, Finding, Report
from proofgate.orchestrator import ScanOutcome, report_hash, run_scan, write_outputs
from proofgate.report_html import to_html
from proofgate.runner import ToolResult
from proofgate.sarif import to_sarif

from corpus_harness import CORPUS

FIXTURES = Path(__file__).parent / "fixtures" / "tool_outputs"


def bandit_recording() -> str:
    return (FIXTURES / "bandit_corpus.json").read_text(encoding="utf-8").replace("{{PROJECT}}", str(CORPUS).replace("\\", "\\\\"))


def runner_with(outputs=None):
    outputs = outputs or {}

    async def runner(name, args, **kw):
        if name in outputs:
            return ToolResult(name, "ok", 0, outputs[name], "", 0.1, sha256="0" * 64)
        return ToolResult(name, "skipped", reason=f"{name} not found on PATH")

    return runner


async def scan_corpus(**kw) -> ScanOutcome:
    return await run_scan(CORPUS, runner=runner_with({"bandit": bandit_recording()}), offline=True, **kw)


# ----------------------------------------------------------------------------- orchestrator
async def test_whole_corpus_prints_the_three_counts():
    out = await scan_corpus()
    r = out.report
    assert r.layers_run == [1, 2, 3, 4, 5]
    assert r.raw_warning_count >= r.unique_count >= r.proven_count == 0
    print(f"corpus: {r.raw_warning_count} raw -> {r.unique_count} unique -> {r.proven_count} proven")
    files = {(f.location.file) for f in r.findings}
    assert {"v09_hardcoded_keys/app.py", "v10_service_role_in_bundle/static/bundle.js", "v08_cmdi/app.py",
            "v13_debug_tls/app.py", "v07_sqli/app.py"} <= files


async def test_bandit_and_layer1_agree_on_the_hardcoded_key_and_both_secrets_survive():
    r = (await scan_corpus()).report
    v09 = [f for f in r.findings if f.location.file == "v09_hardcoded_keys/app.py"]
    assert {f.rule for f in v09} == {"stripe-live-secret-key", "supabase-service-role-key"}
    stripe = next(f for f in v09 if f.rule == "stripe-live-secret-key")
    assert stripe.confirmed_by >= 2 and "bandit" in stripe.sources  # bandit B105 merged in
    assert r.raw_warning_count > r.unique_count


async def test_clean_apps_and_bait_have_no_findings_end_to_end():
    r = (await scan_corpus()).report
    clean = [f for f in r.findings if f.location.file.startswith(("c01_clean", "c02_clean_helper"))]
    assert clean == []
    bait = [f for f in r.findings if f.location.file.startswith("c03_bait")]
    assert all(f.severity != "critical" for f in bait)  # T3: no critical on the precision bait


async def test_report_has_limits_tools_notes_and_a_verifiable_hash():
    r = (await scan_corpus()).report
    assert r.limits_statement == LIMITS_STATEMENT
    assert {t.name: t.status for t in r.tools}["semgrep"] == "skipped"
    assert any("layer 6: not built yet" in n for n in r.notes) and any("semgrep" in n and "skipped" in n for n in r.notes)
    assert r.receipt.report_hash == report_hash(r) and r.receipt.report_hash.startswith("sha256:")
    changed = r.model_copy(update={"unique_count": r.unique_count + 1})
    assert report_hash(changed) != r.receipt.report_hash


async def test_a_crashing_layer_is_isolated_and_counts_as_a_tool_error(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("kaboom with key " + "sk_" + "live_" + "Ab3dE6gH9jK2mN5pQ8sT1vX4")

    monkeypatch.setattr(l1_secrets, "run", boom)
    out = await run_scan(CORPUS / "v09_hardcoded_keys", runner=runner_with(), offline=True)
    assert out.tool_error and 1 not in out.report.layers_run and 2 in out.report.layers_run
    note = next(n for n in out.report.notes if n.startswith("layer 1: failed"))
    assert "kaboom" in note and "Ab3dE6gH9jK2" not in note  # even error text is redacted


async def test_fast_mode_times_out_a_slow_layer_and_says_so(monkeypatch):
    from proofgate.layers import l2_sast

    async def slow(*a, **k):
        await asyncio.sleep(5)

    monkeypatch.setattr(l2_sast, "run", slow)
    out = await run_scan(CORPUS / "c01_clean", fast=True, fast_timeout=0.05, runner=runner_with(), offline=True)
    assert out.tool_error and 2 not in out.report.layers_run
    assert any("timed out" in n and "layer 2" in n for n in out.report.notes)


async def test_nothing_ran_is_an_error_not_clean():
    out = await run_scan(CORPUS / "c01_clean", layers=[6, 7], runner=runner_with(), offline=True)
    assert out.tool_error and out.report.layers_run == [] and len(out.report.notes) == 2


async def test_skipped_tools_are_not_errors_but_mismatches_are():
    ok = await run_scan(CORPUS / "c01_clean", layers=[1], runner=runner_with(), offline=True)
    assert not ok.tool_error

    async def mismatch(name, args, **kw):
        return ToolResult(name, "mismatch", reason="SHA-256 differs")

    bad = await run_scan(CORPUS / "c01_clean", layers=[1], runner=mismatch, offline=True)
    assert bad.tool_error and any(t.status == "mismatch" for t in bad.report.tools)


async def test_fast_layers_are_one_to_four_six_nine_where_built():
    out = await run_scan(CORPUS / "c01_clean", fast=True, runner=runner_with(), offline=True)
    assert out.report.layers_run == [1, 2, 3, 4, 5]
    assert any("layer 6" in n for n in out.report.notes) and any("layer 9" in n for n in out.report.notes)
    assert not any("layer 5" in n or "layer 8" in n for n in out.report.notes)


# ----------------------------------------------------------------------------- write_outputs / html / sarif
@pytest.fixture
async def v09_report(tmp_path):
    import shutil

    dst = tmp_path / "v09"
    shutil.copytree(CORPUS / "v09_hardcoded_keys", dst)
    out = await run_scan(dst, runner=runner_with(), offline=True)
    return dst, out.report


async def test_write_outputs_creates_local_files(v09_report):
    dst, report = v09_report
    paths = write_outputs(dst, report, sarif=True)
    assert set(paths) == {"json", "html", "sarif"} and all(p.is_file() and p.parent.name == ".proofgate" for p in paths.values())
    assert Report.model_validate_json(paths["json"].read_text(encoding="utf-8")) == report
    assert json.loads(paths["sarif"].read_text(encoding="utf-8"))["version"] == "2.1.0"


async def test_html_is_self_contained_escaped_and_honest(v09_report, no_leaks):
    dst, report = v09_report
    html = to_html(report)
    assert html.startswith("<!doctype html>") and "<script" not in html.lower()
    assert not re.search(r"""(?:src|href)\s*=\s*["']https?://""", html) and "@import" not in html
    assert LIMITS_STATEMENT.replace("'", "&#x27;") in html or "mean your app is secure" in html
    assert f"<b>{report.raw_warning_count}</b>" in html and "raw" in html and "proven" in html
    # never claims the app is secure: the only "is secure" is inside the negated limits sentence
    text = unescape(html)
    assert all("n't mean your app" in text[max(0, m.start() - 40):m.start()] for m in re.finditer("is secure", text))
    src = (dst / "app.py").read_text(encoding="utf-8")
    raw = [t for t in src.replace('"', " ").split() if t.startswith(("sk_", "eyJ"))]
    no_leaks(html, secrets=raw)


def test_html_escapes_hostile_text():
    f = Finding.model_validate({
        "id": "f_x", "layer": 2, "category": "web", "rule": "r<script>", "severity": "high",
        "title": "<img src=x onerror=alert(1)>", "plain_words": "</p><script>alert(1)</script>",
        "location": {"file": "a<b>.py", "line": 1}, "sources": ["semgrep"],
    })
    report = Report.model_validate({
        "project": "<b>proj</b>", "scanned_at": "now", "layers_run": [2], "raw_warning_count": 1, "unique_count": 1,
        "proven_count": 0, "findings": [f.to_json_dict()], "fixes": [], "receipt": {"rules_attacked": 0, "rules_held": 0},
        "notes": ["<script>x</script>"], "limits_statement": LIMITS_STATEMENT,
    })
    html = to_html(report)
    assert "<script" not in html.lower().replace("&lt;script", "") and "onerror=alert" not in html.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert "&lt;img" in html and "&lt;b&gt;proj" in html


def test_html_shows_a_proven_finding_and_fix_with_five_ticks():
    from proofgate.sample import SAMPLE_FINDING, SAMPLE_FIX

    d = {"project": "demo", "scanned_at": "t", "layers_run": [8], "raw_warning_count": 3, "unique_count": 1,
         "proven_count": 1, "findings": [SAMPLE_FINDING], "fixes": [SAMPLE_FIX], "receipt": {"rules_attacked": 1, "rules_held": 0, "commit": "abc1234"},
         "limits_statement": LIMITS_STATEMENT}
    html = to_html(Report.model_validate(d))
    assert "badge proven" in html and "PGCANARY_A_" in html and html.count("&#10003;") == 5
    assert "1 rules attacked, 0 held, commit abc1234" in html


async def test_sarif_structure(v09_report):
    _, report = v09_report
    doc = to_sarif(report)
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "ProofGate"
    rules = run["tool"]["driver"]["rules"]
    assert len(run["results"]) == report.unique_count
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] and loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["proofgateFingerprint/v1"].startswith("sha256:")
    crit = next(r for r in run["results"] if r["properties"]["severity"] == "critical")
    assert crit["level"] == "error" and rules[crit["ruleIndex"]]["properties"]["security-severity"] == "9.5"
    assert run["properties"]["limitsStatement"] == LIMITS_STATEMENT and run["invocations"][0]["executionSuccessful"] is True


async def test_sarif_marks_unsuccessful_runs(v09_report):
    _, report = v09_report
    bad = report.model_copy(update={"tools": [*report.tools, report.tools[0].model_copy(update={"status": "error"})]})
    assert to_sarif(bad)["runs"][0]["invocations"][0]["executionSuccessful"] is False


async def test_sarif_has_no_secrets(v09_report, no_leaks):
    dst, report = v09_report
    src = (dst / "app.py").read_text(encoding="utf-8")
    raw = [t for t in src.replace('"', " ").split() if t.startswith(("sk_", "eyJ"))]
    no_leaks(json.dumps(to_sarif(report)), secrets=raw)
