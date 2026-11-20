import json
from pathlib import Path

import pytest

from proofgate.layers import l3_deps as l3
from proofgate.layers.l3_deps import highest, lowest_fix, pinned_requirements
from proofgate.models import Finding
from proofgate.runner import ToolResult

from corpus_harness import CORPUS

FIXTURES = Path(__file__).parent / "fixtures" / "tool_outputs"
PIP = (FIXTURES / "pip_audit_requests_2_19_0.json").read_text(encoding="utf-8")  # REAL pip-audit 2.10.1 output
NPM = (FIXTURES / "npm_audit_lodash.json").read_text(encoding="utf-8")  # REAL npm 11 audit output


def osv_text(project: Path) -> str:
    return (FIXTURES / "osv_scanner_sample.json").read_text(encoding="utf-8").replace("{{PROJECT}}", project.as_posix())


def fake_runner(outputs: dict[str, tuple[str, int]]):
    calls = []

    async def runner(name, args, **kw):
        calls.append((name, list(args), kw.get("cwd")))
        if name not in outputs:
            return ToolResult(name, "skipped", reason=f"{name} not found on PATH")
        out, rc = outputs[name]
        return ToolResult(name, "ok", rc, out, "", 0.1, sha256="0" * 64)

    runner.calls = calls
    return runner


# ----------------------------------------------------------------------------- version helpers
def test_lowest_fix_picks_nearest_upgrade_at_or_above_installed():
    assert lowest_fix(["2.20.0", "3.0.0"], "2.19.0") == "2.20.0"
    assert lowest_fix(["1.0.0", "2.20.0"], "2.19.0") == "2.20.0"  # 1.0.0 is a downgrade
    assert lowest_fix(["1.0.0"], "2.19.0") is None and lowest_fix([], "1") is None


def test_highest_compares_versions_not_strings():
    assert highest(["2.9.0", "2.20.0", None]) == "2.20.0" and highest([None]) is None


def test_pinned_requirements_split():
    pinned, unpinned = pinned_requirements("# c\nFlask>=3.0\nrequests==2.19.0\n-r x.txt\nPyYAML==6.0 ; python_version>'3'\n")
    assert pinned == [("requests", "2.19.0", 3), ("PyYAML", "6.0", 5)] and unpinned == ["Flask"]


# ----------------------------------------------------------------------------- parsers (real output)
def test_real_pip_audit_output_aggregates_to_one_package():
    (p,) = l3.parse_pip_audit(PIP, "requirements.txt")
    assert (p.ecosystem, p.name, p.version, p.source) == ("pypi", "requests", "2.19.0", "pip-audit")
    assert p.fixed_in == "2.33.0"  # the lowest version that fixes all ten advisories
    assert "CVE-2018-18074" in p.ids and p.severity is None  # pip-audit does not report severity


def test_real_npm_audit_output():
    (p,) = l3.parse_npm_audit(NPM, "package-lock.json", {"lodash": "4.17.15"})
    assert (p.name, p.version, p.severity, p.source) == ("lodash", "4.17.15", "high", "npm-audit")
    assert p.fixed_in == "4.18.1" and any(i.startswith("GHSA-") for i in p.ids)


def test_osv_sample_parses_and_ignores_paths_outside_the_project(tmp_path):
    items = l3.parse_osv(osv_text(tmp_path), tmp_path)
    assert [(i.name, i.version, i.file) for i in items] == [("requests", "2.19.0", "requirements.txt")]
    assert items[0].severity == "high" and items[0].fixed_in == "2.31.0"


# ----------------------------------------------------------------------------- findings
def test_findings_flag_v12_with_the_fixed_version():
    items = l3.parse_pip_audit(PIP, "requirements.txt")
    (f,) = l3.to_findings(items, CORPUS / "v12_outdated_dep")
    assert f.layer == 3 and f.category == "deps" and f.rule == "known-vulnerable-dependency"
    assert f.fixed_in == "2.33.0" and f.fix_tier == "A" and f.location.file == "requirements.txt"
    assert f.location.line == 2  # the requests== line
    assert f.severity == "medium"  # unknown severity is never rounded up
    assert "2.33.0" in f.plain_words and f.sources == ["pip-audit"]
    Finding.model_validate(f.to_json_dict())


def test_merge_across_tools_takes_max_severity_highest_fix_and_counts_sources(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask>=3\nrequests==2.19.0\n", encoding="utf-8")
    items = l3.parse_pip_audit(PIP, "requirements.txt") + l3.parse_osv(osv_text(tmp_path), tmp_path)
    (f,) = l3.to_findings(items, tmp_path)
    assert f.severity == "high" and f.fixed_in == "2.33.0"
    assert f.sources == ["osv-scanner", "pip-audit"] and f.confirmed_by == 2


def test_fingerprint_is_stable_across_line_moves(tmp_path):
    items = l3.parse_pip_audit(PIP, "requirements.txt")
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    a = l3.to_findings(items, tmp_path)[0]
    (tmp_path / "requirements.txt").write_text("\n\n# c\nrequests==2.19.0\n", encoding="utf-8")
    b = l3.to_findings(items, tmp_path)[0]
    assert a.fingerprint == b.fingerprint and a.location.line != b.location.line


# ----------------------------------------------------------------------------- run()
async def test_run_v12_online_with_pip_audit_only():
    runner = fake_runner({"pip-audit": (PIP, 1)})
    res = await l3.run(CORPUS / "v12_outdated_dep", runner=runner, offline=False)
    (f,) = res.findings
    assert f.fixed_in == "2.33.0" and f.location.file == "requirements.txt"
    statuses = {t.name: t.status for t in res.tools}
    assert statuses == {"osv-scanner": "skipped", "pip-audit": "ok"}
    assert any("not audited" in n and "Flask" in n for n in res.notes)  # Flask>=3.0 is unpinned
    pip_args = next(a for n, a, _ in runner.calls if n == "pip-audit")
    assert "--no-deps" in pip_args and "--disable-pip" in pip_args


async def test_run_clean_corpus_apps_have_no_findings():
    res = await l3.run(CORPUS / "c01_clean", runner=fake_runner({"pip-audit": ('{"dependencies": []}', 0)}), offline=False)
    assert res.findings == []


async def test_offline_skips_network_tools_and_passes_offline_to_osv(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"packages": {}}', encoding="utf-8")
    runner = fake_runner({"osv-scanner": (osv_text(tmp_path), 1)})
    res = await l3.run(tmp_path, runner=runner, offline=True)
    called = [n for n, _, _ in runner.calls]
    assert "pip-audit" not in called and "npm" not in called
    assert "--offline" in next(a for n, a, _ in runner.calls if n == "osv-scanner")
    assert {t.name: t.status for t in res.tools} == {"osv-scanner": "ok", "pip-audit": "skipped", "npm": "skipped"}
    (f,) = res.findings
    assert f.sources == ["osv-scanner"] and f.fixed_in == "2.31.0"


async def test_env_var_turns_offline_on(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFGATE_OFFLINE", "1")
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    runner = fake_runner({})
    await l3.run(tmp_path, runner=runner)
    assert "pip-audit" not in [n for n, _, _ in runner.calls]


async def test_npm_audit_runs_only_with_a_lockfile(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}', encoding="utf-8")
    res = await l3.run(tmp_path, runner=fake_runner({"npm": (NPM, 1)}), offline=False)
    assert res.findings == [] and any("no package-lock.json" in n for n in res.notes)

    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}}}, indent=2), encoding="utf-8")
    runner = fake_runner({"npm": (NPM, 1)})
    res = await l3.run(tmp_path, runner=runner, offline=False)
    (f,) = res.findings
    assert (f.location.file, f.severity, f.fixed_in, f.sources) == ("package-lock.json", "high", "4.18.1", ["npm-audit"])
    assert "lodash" in f.title and next(c for n, _, c in runner.calls if n == "npm") == tmp_path.resolve()


async def test_node_modules_are_not_audited(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package-lock.json").write_text("{}", encoding="utf-8")
    runner = fake_runner({})
    await l3.run(tmp_path, runner=runner, offline=False)
    assert runner.calls[0][0] == "osv-scanner" and len(runner.calls) == 1


@pytest.mark.parametrize("out,rc", [("{not json", 1), ("[]", 1), ('{"dependencies": [{}]}', 1), ("{}", 5)])
async def test_garbage_output_never_crashes(out, rc):
    res = await l3.run(CORPUS / "v12_outdated_dep", runner=fake_runner({"pip-audit": (out, rc), "osv-scanner": (out, rc)}), offline=False)
    assert res.layer == 3 and res.notes


async def test_no_tools_installed_is_recorded_not_fatal():
    res = await l3.run(CORPUS / "v12_outdated_dep", runner=fake_runner({}), offline=False)
    assert res.findings == [] and {t.status for t in res.tools} == {"skipped"}
    assert any("osv-scanner: skipped" in n for n in res.notes)
