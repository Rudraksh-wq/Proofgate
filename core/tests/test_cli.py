import io
import json
import shutil

import pytest

from proofgate.cli import main
from proofgate.models import AcceptedRisk, Contract, Finding, FixResult, Report

from corpus_harness import CORPUS


def run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.fixture
def app(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    return d


@pytest.fixture
def vuln_app(tmp_path):
    """A copy of the v09 corpus app (a live-format Stripe key and a service_role key in app.py)."""
    dst = tmp_path / "v09"
    shutil.copytree(CORPUS / "v09_hardcoded_keys", dst)
    return dst


def test_scan_vulnerable_app_writes_a_real_report_and_exits_1(capsys, vuln_app):
    code, out, _ = run(capsys, "scan", str(vuln_app))
    assert code == 1
    report = Report.model_validate_json((vuln_app / ".proofgate" / "report.json").read_text(encoding="utf-8"))
    assert report.layers_run == [1, 2, 3, 4, 5, 6, 9]
    assert {f.rule for f in report.findings} >= {"stripe-live-secret-key", "supabase-service-role-key"}
    assert report.limits_statement and "doesn't mean your app is secure" in report.limits_statement
    assert not any("not built yet" in n for n in report.notes)  # layers 6 and 9 are built; nothing is silently unbuilt
    assert (vuln_app / ".proofgate" / "report.html").is_file()
    assert json.loads(out)["schema"] == "proofgate.report/v1"


def test_scan_clean_dir_exits_0(capsys, app):
    code, out, _ = run(capsys, "scan", str(app))
    assert code == 0 and json.loads(out)["unique_count"] == 0


def test_scan_layers_option(capsys, vuln_app):
    code, out, _ = run(capsys, "scan", str(vuln_app), "--layers", "1")
    assert json.loads(out)["layers_run"] == [1] and code == 1


def test_scan_only_unbuilt_layers_is_a_tool_error_not_clean(capsys, vuln_app):
    code, _, err = run(capsys, "scan", str(vuln_app), "--layers", "7")
    assert code == 2 and "NOT a clean bill of health" in err


def test_scan_fail_on_threshold(capsys, vuln_app):
    assert run(capsys, "scan", str(vuln_app), "--fail-on", "critical")[0] == 1
    assert run(capsys, "scan", str(vuln_app), "--layers", "3", "--fail-on", "low")[0] == 0  # nothing from L3 here


def test_scan_fast_runs_the_fast_layers(capsys, vuln_app):
    code, out, _ = run(capsys, "scan", str(vuln_app), "--fast")
    assert code == 1 and json.loads(out)["layers_run"] == [1, 2, 3, 4, 5, 6, 9]


@pytest.mark.parametrize("fmt", ["sarif", "agent", "html"])
def test_scan_formats(capsys, vuln_app, fmt):
    code, out, _ = run(capsys, "scan", str(vuln_app), "--format", fmt)
    assert code == 1 and out.strip()
    if fmt == "sarif":
        doc = json.loads(out)
        assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]
        assert (vuln_app / ".proofgate" / "report.sarif").is_file()
    if fmt == "agent":
        assert len(out.strip().splitlines()) <= 20 and "raw ->" in out


def test_scan_output_never_contains_the_planted_secret(capsys, vuln_app, no_leaks):
    src = (vuln_app / "app.py").read_text(encoding="utf-8")
    raw = [t for t in src.replace('"', " ").split() if t.startswith(("sk_", "eyJ"))]
    assert raw
    _, out, _ = run(capsys, "scan", str(vuln_app))
    no_leaks(out, (vuln_app / ".proofgate" / "report.json").read_text(encoding="utf-8"),
             (vuln_app / ".proofgate" / "report.html").read_text(encoding="utf-8"), secrets=raw)


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "{missing}"],
        ["scan", "{app}", "--layers", "x"],
        ["scan", "{app}", "--layers", "0,10"],
        ["bogus"],
        ["fix", "{app}"],
        ["scan", "{app}", "--fast", "--full"],
        ["scan", "{app}", "--format", "xml"],
        ["verify", "{app}", "--finding", "f_1", "--patch", "{missing}"],
        ["report", "{app}"],  # no report yet
        ["prove", "{app}", "--target", "http://example.com"],
    ],
)
def test_tool_errors_exit_2(capsys, app, tmp_path, argv):
    argv = [x.format(app=app, missing=tmp_path / "nope") for x in argv]
    assert main(argv) == 2


def test_prove_with_i_own_this_allows_the_target_and_logs_it(capsys, vuln_app):
    code, out, _ = run(capsys, "prove", str(vuln_app), "--target", "http://proofgate-test.invalid", "--i-own-this")
    assert json.loads(out)["target_overrides"] == ["http://proofgate-test.invalid (--i-own-this)"]


def test_contract_confirm(capsys, app):
    code, out, _ = run(capsys, "contract", str(app), "--confirm")
    c = Contract.model_validate_json(out)
    assert code == 0 and c.confirmed_by_user


def test_fix_and_verify_need_a_report_and_a_known_finding(capsys, app, tmp_path):
    patch = tmp_path / "p.diff"
    patch.write_text("--- a/x\n+++ b/x\n", encoding="utf-8")
    assert main(["fix", str(app), "--finding", "f_9"]) == 2  # no report yet
    assert main(["verify", str(app), "--finding", "f_9", "--patch", str(patch)]) == 2
    run(capsys, "scan", str(app))
    assert main(["fix", str(app), "--finding", "f_9"]) == 2  # report exists, finding does not
    assert main(["verify", str(app), "--finding", "f_9", "--patch", str(tmp_path / "missing.diff")]) == 2


def test_prove_attacks_the_app_and_reports_a_proven_finding(capsys, tmp_path):
    dst = tmp_path / "v01"
    shutil.copytree(CORPUS / "v01_idor_read", dst)
    code, out, _ = run(capsys, "prove", str(dst))
    report = Report.model_validate_json(out)
    assert code == 1 and report.layers_run == [8] and report.proven_count == 1
    assert report.findings[0].rule == "cross-user-read" and report.findings[0].proven


def test_prove_on_a_clean_app_exits_0(capsys, tmp_path):
    dst = tmp_path / "c01"
    shutil.copytree(CORPUS / "c01_clean", dst)
    code, out, _ = run(capsys, "prove", str(dst))
    assert code == 0 and json.loads(out)["proven_count"] == 0


def test_contract_is_saved_as_a_draft_and_can_be_confirmed(capsys, tmp_path):
    dst = tmp_path / "c01"
    shutil.copytree(CORPUS / "c01_clean", dst)
    code, out, err = run(capsys, "contract", str(dst))
    c = Contract.model_validate_json(out)
    assert code == 0 and not c.confirmed_by_user and c.owned_resources[0].name == "notes" and "draft contract" in err
    assert (dst / ".proofgate" / "contract.json").is_file()
    code, out, _ = run(capsys, "contract", str(dst), "--confirm")
    assert Contract.model_validate_json(out).confirmed_by_user
    assert Contract.model_validate_json((dst / ".proofgate" / "contract.json").read_text(encoding="utf-8")).confirmed_by_user


def test_accept_parses_relative_expiry(capsys):
    code, out, _ = run(capsys, "accept", "sha256:x", "--reason", "why", "--expires", "30d")
    assert code == 0 and "expires" in out
    assert main(["accept", "sha256:x", "--reason", "r", "--expires", "soon"]) == 2


def test_report_requires_prior_scan(capsys, app):
    run(capsys, "scan", str(app))
    assert run(capsys, "report", str(app))[0] == 0


def test_rollback_needs_a_recorded_fix(capsys, app):
    code, out, err = run(capsys, "rollback", "f_7c1a", "--dir", str(app))
    assert code == 2 and "not found" in err  # real rollback behaviour is covered in test_vaccinate_rollback.py


@pytest.mark.parametrize("stdin", ['{"tool_input": {"file_path": "a.py"}}', "", "not json", "[1,2]"])
@pytest.mark.parametrize("phase", ["pre", "post"])
def test_hook_never_breaks_the_agent(capsys, monkeypatch, stdin, phase):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert main(["hook", phase]) == 0


def test_hook_bad_args_still_exit_0(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert main(["hook", "sideways"]) == 0


def test_accepted_risk_model_matches_cli_output(capsys, tmp_path):
    _, out, _ = run(capsys, "accept", "sha256:x", "--reason", "why", "--expires", "2030-01-01", "--dir", str(tmp_path))
    body = out[out.index("{"):]
    assert AcceptedRisk.model_validate_json(body).fingerprint == "sha256:x"


def test_cli_output_is_redacted(capsys, app, monkeypatch, no_leaks):
    from conftest import fake_secrets
    from proofgate import sample

    raw = fake_secrets()["stripe"]
    monkeypatch.setitem(sample.SAMPLE_FINDING, "title", f"key {raw} in code")
    code, out, _ = run(capsys, "prove", str(app))
    no_leaks(out, secrets=[raw])
