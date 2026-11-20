import io
import json

import pytest

from proofgate.cli import main
from proofgate.models import AcceptedRisk, Contract, Finding, FixResult, Report


def run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.fixture
def app(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    return d


def test_scan_writes_valid_report_and_exits_1(capsys, app):
    code, out, _ = run(capsys, "scan", str(app))
    assert code == 1  # sample has a critical finding, default --fail-on high
    report = Report.model_validate_json((app / ".proofgate" / "report.json").read_text(encoding="utf-8"))
    assert report.layers_run == list(range(1, 10))
    assert report.limits_statement and "doesn't mean your app is secure" in report.limits_statement
    assert json.loads(out)["schema"] == "proofgate.report/v1"


def test_scan_layers_option(capsys, app):
    code, out, _ = run(capsys, "scan", str(app), "--layers", "1,2,3")
    assert json.loads(out)["layers_run"] == [1, 2, 3]


def test_scan_fail_on_critical_still_trips_on_critical_sample(capsys, app):
    assert run(capsys, "scan", str(app), "--fail-on", "critical")[0] == 1


@pytest.mark.parametrize("fmt", ["sarif", "agent", "html"])
def test_scan_formats(capsys, app, fmt):
    code, out, _ = run(capsys, "scan", str(app), "--format", fmt)
    assert code == 1 and out.strip()
    if fmt == "sarif":
        assert json.loads(out)["version"] == "2.1.0"


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "{missing}"],
        ["scan", "{app}", "--layers", "x"],
        ["scan", "{app}", "--layers", "0,10"],
        ["bogus"],
        ["fix", "{app}"],
        ["scan", "{app}", "--fast", "--full"],
        ["verify", "{app}", "--finding", "f_1", "--patch", "{missing}"],
        ["report", "{app}"],  # no report yet
        ["prove", "{app}", "--target", "http://example.com"],
    ],
)
def test_tool_errors_exit_2(capsys, app, tmp_path, argv):
    argv = [x.format(app=app, missing=tmp_path / "nope") for x in argv]
    assert main(argv) == 2


def test_prove_with_i_own_this_allows_remote_target(capsys, app):
    code, _, _ = run(capsys, "prove", str(app), "--target", "http://example.com", "--i-own-this")
    assert code == 1


def test_contract_confirm(capsys, app):
    code, out, _ = run(capsys, "contract", str(app), "--confirm")
    c = Contract.model_validate_json(out)
    assert code == 0 and c.confirmed_by_user


def test_fix_and_verify_return_fixresult(capsys, app, tmp_path):
    patch = tmp_path / "p.diff"
    patch.write_text("--- a\n+++ b\n", encoding="utf-8")
    code, out, _ = run(capsys, "fix", str(app), "--finding", "f_9")
    assert code == 0 and FixResult.model_validate_json(out).finding_id == "f_9"
    code, out, _ = run(capsys, "verify", str(app), "--finding", "f_9", "--patch", str(patch))
    assert code == 0 and FixResult.model_validate_json(out).accepted


def test_prove_returns_finding(capsys, app):
    code, out, _ = run(capsys, "prove", str(app))
    assert code == 1 and Finding.model_validate_json(out).proven


def test_accept_parses_relative_expiry(capsys):
    code, out, _ = run(capsys, "accept", "sha256:x", "--reason", "why", "--expires", "30d")
    assert code == 0 and "expires" in out
    assert main(["accept", "sha256:x", "--reason", "r", "--expires", "soon"]) == 2


def test_report_requires_prior_scan(capsys, app):
    run(capsys, "scan", str(app))
    assert run(capsys, "report", str(app))[0] == 0


def test_rollback_prints_command_only(capsys):
    code, out, _ = run(capsys, "rollback", "f_7c1a")
    assert code == 0 and "git revert" in out


@pytest.mark.parametrize("stdin", ['{"tool_input": {"file_path": "a.py"}}', "", "not json", "[1,2]"])
@pytest.mark.parametrize("phase", ["pre", "post"])
def test_hook_never_breaks_the_agent(capsys, monkeypatch, stdin, phase):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert main(["hook", phase]) == 0


def test_hook_bad_args_still_exit_0(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    assert main(["hook", "sideways"]) == 0


def test_accepted_risk_model_matches_cli_output(capsys):
    _, out, _ = run(capsys, "accept", "sha256:x", "--reason", "why", "--expires", "2030-01-01")
    body = out[out.index("{"):]
    assert AcceptedRisk.model_validate_json(body).fingerprint == "sha256:x"
