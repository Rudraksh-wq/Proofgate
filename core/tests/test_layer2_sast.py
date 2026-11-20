import asyncio
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from proofgate.doctor import pin_tool
from proofgate.layers import l2_sast as l2
from proofgate.models import Finding
from proofgate.runner import ToolResult, run_tool
from proofgate.toollock import ToolEntry, ToolLock, platform_key

from corpus_harness import CORPUS

FIXTURES = Path(__file__).parent / "fixtures" / "tool_outputs"
RULES = l2.RULES_DIR
CATEGORIES = {"secrets", "injection", "access", "deps", "supply-chain", "database", "config", "web", "bundle"}
RULE_FILES = {"python.yaml": "python.py", "javascript.yaml": "javascript.ts", "route.yaml": "route.ts"}


def load_rules() -> list[dict]:
    rules = []
    for name in RULE_FILES:
        rules += yaml.safe_load((RULES / name).read_text(encoding="utf-8"))["rules"]
    return rules


# ----------------------------------------------------------------------------- own rules
def test_about_twenty_own_rules():
    assert 18 <= len(load_rules()) <= 25


def test_rule_ids_are_unique_and_namespaced():
    ids = [r["id"] for r in load_rules()]
    assert len(ids) == len(set(ids)) and all(i.startswith("proofgate.") for i in ids)


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r["id"])
def test_rule_is_well_formed(rule):
    assert rule["languages"] and rule["severity"] in {"ERROR", "WARNING", "INFO"} and rule["message"]
    meta = rule["metadata"]
    assert meta["category"] in CATEGORIES and meta["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert meta["plain_words"] and all(re.match(r"CWE-\d+:", c) for c in meta["cwe"])
    if rule.get("mode") == "taint":
        assert rule["pattern-sources"] and rule["pattern-sinks"]
    else:
        assert any(k in rule for k in ("pattern", "patterns", "pattern-either"))


@pytest.mark.parametrize("rule_file,test_file", RULE_FILES.items())
def test_every_rule_has_a_positive_and_a_negative_case(rule_file, test_file):
    ids = [r["id"] for r in yaml.safe_load((RULES / rule_file).read_text(encoding="utf-8"))["rules"]]
    text = (RULES / test_file).read_text(encoding="utf-8")
    for rid in ids:
        assert re.search(rf"(?:#|//)\s*ruleid:\s*{re.escape(rid)}\b", text), f"no positive case for {rid}"
        assert re.search(rf"(?:#|//)\s*ok:\s*{re.escape(rid)}\b", text), f"no negative case for {rid}"


def test_no_third_party_rules_are_vendored():
    assert sorted(p.name for p in RULES.glob("*.yaml")) == sorted(RULE_FILES)


def _semgrep_binary():
    import os

    return shutil.which("semgrep") or shutil.which("semgrep", path=os.environ.get("PROOFGATE_TOOLS_DIR") or "")


@pytest.mark.skipif(_semgrep_binary() is None, reason="semgrep not installed: pending real-tool verification")
def test_semgrep_own_rule_tests_pass():
    r = subprocess.run([_semgrep_binary(), "--test", "--metrics=off", str(RULES)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]


# ----------------------------------------------------------------------------- arg building
def test_semgrep_args_disable_metrics_and_use_local_rules_only(tmp_path):
    args = l2.semgrep_args(tmp_path, [RULES])
    assert "--metrics=off" in args and "--json" in args
    assert args.count("--config") == 1 and args[args.index("--config") + 1] == str(RULES)
    assert not any(a.startswith(("p/", "r/", "auto", "http")) for a in args)


def test_extra_rules_dir_comes_from_tools_dir(tmp_path):
    assert l2.semgrep_rule_dirs(tmp_path) == [RULES]
    (tmp_path / "semgrep-rules").mkdir()
    assert l2.semgrep_rule_dirs(tmp_path) == [RULES, tmp_path / "semgrep-rules"]


def test_extra_rules_dir_comes_from_env(tmp_path, monkeypatch):
    (tmp_path / "semgrep-rules").mkdir()
    monkeypatch.setenv("PROOFGATE_TOOLS_DIR", str(tmp_path))
    assert l2.semgrep_rule_dirs()[-1] == tmp_path / "semgrep-rules"


# ----------------------------------------------------------------------------- semgrep parsing
def test_parse_semgrep_sample(tmp_path):
    (tmp_path / "app.py").write_text("import os\nimport sqlite3\nc.execute(f'x{q}')\n\nh = md5(x)\n", encoding="utf-8")
    findings = l2.parse_semgrep((FIXTURES / "semgrep_sample.json").read_text(encoding="utf-8"), tmp_path)
    assert len(findings) == 2  # the path outside the project is dropped
    own, other = findings
    assert (own.rule, own.category, own.cwe, own.severity, own.confidence, own.fix_tier) == (
        "proofgate.py-sql-injection", "injection", "CWE-89", "high", "high", "A")
    assert own.sources == ["proofgate-rule:py-sql-injection"] and own.layer == 2
    assert (other.rule, other.category, other.severity, other.sources) == ("insecure-hash", "web", "medium", ["semgrep"])
    assert other.cwe == "CWE-327"


def test_semgrep_fingerprint_ignores_line_numbers(tmp_path):
    base = json.loads((FIXTURES / "semgrep_sample.json").read_text(encoding="utf-8"))
    (tmp_path / "app.py").write_text("\n\nsame line\n\n\nsame line\n", encoding="utf-8")
    a = l2.parse_semgrep(json.dumps(base), tmp_path)[0]
    base["results"][0]["start"]["line"] = 6
    b = l2.parse_semgrep(json.dumps(base), tmp_path)[0]
    assert a.fingerprint == b.fingerprint and a.location.line != b.location.line


# ----------------------------------------------------------------------------- bandit parsing (REAL recorded output)
def bandit_fixture() -> str:
    text = (FIXTURES / "bandit_corpus.json").read_text(encoding="utf-8")
    return text.replace("{{PROJECT}}", str(CORPUS).replace("\\", "\\\\"))


def test_parse_real_bandit_output_for_the_corpus():
    findings = l2.parse_bandit(bandit_fixture(), CORPUS)
    got = {(f.location.file, f.rule) for f in findings}
    assert ("v08_cmdi/app.py", "bandit-B602") in got  # shell=True
    assert ("v13_debug_tls/app.py", "bandit-B201") in got and ("v13_debug_tls/app.py", "bandit-B501") in got
    assert ("v07_sqli/app.py", "bandit-B608") in got
    shell = next(f for f in findings if f.rule == "bandit-B602")
    assert shell.category == "injection" and shell.cwe == "CWE-78" and shell.severity == "high"
    assert shell.sources == ["bandit"] and shell.layer == 2
    assert all(f.severity != "critical" for f in findings)  # only a proof makes something critical


def test_bandit_flags_the_c03_bait_but_never_above_medium():
    # honest false positive: Bandit cannot see that the interpolated ORDER BY column is allow-listed
    bait = [f for f in l2.parse_bandit(bandit_fixture(), CORPUS) if f.location.file.startswith("c03_bait")]
    assert bait and all(f.severity in ("low", "medium") for f in bait)


def test_assert_used_noise_is_skipped():
    out = json.dumps({"results": [{"test_id": "B101", "filename": "a.py", "line_number": 1, "issue_text": "assert",
                                   "issue_severity": "LOW", "issue_confidence": "HIGH", "issue_cwe": {"id": 703}}]})
    assert l2.parse_bandit(out, Path(".").resolve()) == []


def test_bandit_text_containing_a_secret_is_redacted(tmp_path, no_leaks):
    from conftest import fake_secrets

    raw = fake_secrets()["stripe"]
    (tmp_path / "a.py").write_text("k = 1\n", encoding="utf-8")
    out = json.dumps({"results": [{
        "test_id": "B999", "filename": str(tmp_path / "a.py"), "line_number": 1,
        "issue_text": f"Possible hardcoded password: '{raw}'", "issue_severity": "LOW",
        "issue_confidence": "MEDIUM", "issue_cwe": {"id": 259}}]})
    (f,) = l2.parse_bandit(out, tmp_path)
    no_leaks(f.to_json(), secrets=[raw])
    assert f.category == "secrets"


# ----------------------------------------------------------------------------- run()
def fake_runner(outputs: dict[str, tuple[str, int]]):
    async def runner(name, args, **kw):
        if name not in outputs:
            return ToolResult(name, "skipped", reason=f"{name} not found on PATH")
        out, rc = outputs[name]
        return ToolResult(name, "ok", rc, out, "", 0.1, sha256="0" * 64)

    return runner


async def test_run_records_skipped_semgrep_and_keeps_bandit_findings():
    res = await l2.run(CORPUS, runner=fake_runner({"bandit": (bandit_fixture(), 0)}))
    statuses = {t.name: t.status for t in res.tools}
    assert statuses == {"semgrep": "skipped", "bandit": "ok"}
    assert any("semgrep" in n and "skipped" in n for n in res.notes)
    assert res.findings and all(isinstance(f, Finding) for f in res.findings)


async def test_run_merges_both_tools_and_dedupes(tmp_path):
    (tmp_path / "app.py").write_text("import os\nimport sqlite3\nc.execute(f'x{q}')\n\nh = md5(x)\n", encoding="utf-8")
    sem = (FIXTURES / "semgrep_sample.json").read_text(encoding="utf-8")
    res = await l2.run(tmp_path, runner=fake_runner({"semgrep": (sem, 0), "bandit": ('{"results": []}', 0)}))
    assert [f.location.line for f in res.findings] == [3, 5]
    again = await l2.run(tmp_path, runner=fake_runner({"semgrep": (sem + "", 0), "bandit": ('{"results": []}', 0)}))
    assert [f.id for f in again.findings] == [f.id for f in res.findings]


@pytest.mark.parametrize("out,rc", [("{not json", 0), ("[]", 0), ('{"results": [{}]}', 0), ("{}", 3)])
async def test_garbage_tool_output_never_crashes(out, rc):
    res = await l2.run(CORPUS, runner=fake_runner({"semgrep": (out, rc), "bandit": (out, rc)}))
    assert res.layer == 2 and isinstance(res.notes, list)


async def test_run_with_no_tools_at_all(tmp_path):
    res = await l2.run(tmp_path, runner=fake_runner({}))
    assert res.findings == [] and {t.status for t in res.tools} == {"skipped"}


# ----------------------------------------------------------------------------- real Bandit (installed in the venv)
BANDIT_EXE = Path(sys.executable).parent / ("bandit.exe" if sys.platform == "win32" else "bandit")


@pytest.mark.skipif(not BANDIT_EXE.is_file(), reason="bandit not installed in this environment")
async def test_real_bandit_end_to_end_through_the_runner(tmp_path, monkeypatch):
    lock = ToolLock(tools={
        "bandit": ToolEntry(binary="bandit", version_args=["--version"]),
        "semgrep": ToolEntry(binary="semgrep"),
    })
    await asyncio.to_thread(pin_tool, "bandit", lock, BANDIT_EXE.parent)  # a deliberate "I trust this binary" step
    res = await l2.run(CORPUS / "v08_cmdi", lock=lock, tools_dir=BANDIT_EXE.parent)
    statuses = {t.name: t.status for t in res.tools}
    assert statuses["bandit"] == "ok" and statuses["semgrep"] in ("skipped", "ok")
    assert any(f.rule == "bandit-B602" and f.location.file == "app.py" for f in res.findings)
    assert all(f.severity != "critical" for f in res.findings)


async def test_unpinned_real_bandit_is_refused_not_run():
    lock = ToolLock(tools={"bandit": ToolEntry(binary="bandit"), "semgrep": ToolEntry(binary="semgrep")})
    res = await l2.run(CORPUS / "v08_cmdi", lock=lock, tools_dir=BANDIT_EXE.parent)
    assert {t.name: t.status for t in res.tools}["bandit"] in ("unpinned", "skipped")
    assert res.findings == []
