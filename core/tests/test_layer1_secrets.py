import base64
import json
from pathlib import Path

import pytest

from proofgate.layers import l1_secrets as l1
from proofgate.layers.base import LayerResult
from proofgate.models import Finding
from proofgate.runner import ToolResult

from conftest import fake_secrets
from corpus_harness import CORPUS

FIXTURES = Path(__file__).parent / "fixtures" / "tool_outputs"


def make_jwt(role: str | None) -> str:
    def enc(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

    payload = {"iss": "supabase", "ref": "abcdefghijklmnopqrst"}
    if role:
        payload["role"] = role
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.c2lnbmF0dXJlMTIzNDU2Nzg"


def stripe() -> str:
    return "sk_" + "live_" + "Ab3dE6gH9jK2mN5pQ8sT1vX4"


# ----------------------------------------------------------------------------- JWT decoder
def test_jwt_roles():
    assert l1.jwt_role(make_jwt("anon")) == "anon"
    assert l1.jwt_role(make_jwt("service_role")) == "service_role"
    assert l1.jwt_role(make_jwt(None)) is None
    assert l1.jwt_role("not.a.jwt") is None and l1.decode_jwt("eyJ.eyJ") is None


def test_anon_is_not_a_finding_but_service_role_is_critical():
    assert l1.scan_text(f'KEY = "{make_jwt("anon")}"', "a.py") == []
    (f,) = l1.scan_text(f'KEY = "{make_jwt("service_role")}"', "a.py")
    assert f.severity == "critical" and f.rule == "supabase-service-role-key" and f.interrupt_human
    assert f.sources == ["proofgate-jwt"] and f.fix_tier == "A" and f.cwe == "CWE-798"


def test_authenticated_user_jwt_is_medium():
    (f,) = l1.scan_text(make_jwt("authenticated"), "a.py")
    assert f.severity == "medium"


# ----------------------------------------------------------------------------- placeholder filter
@pytest.mark.parametrize(
    "value",
    ["changeme", "your-api-key-here", "<YOUR_KEY>", "${STRIPE_KEY}", "xxxxxxxxxxxxxxxx", "process.env.KEY", "example", "", "aaaaaaaaaaaaaaaa"],
)
def test_placeholders_filtered(value):
    assert l1.is_placeholder(value)


def test_real_looking_values_kept():
    assert not l1.is_placeholder(stripe(), check_entropy=False)
    assert not l1.is_placeholder("k8Jd92mXq0LpZ7vTn4RbYh3W")


def test_placeholder_stripe_key_not_flagged():
    assert l1.scan_text('KEY = "sk_' + 'live_' + 'x' * 24 + '"', "a.py") == []


# ----------------------------------------------------------------------------- built-in rules
@pytest.mark.parametrize(
    "kind,rule,sev",
    [("stripe", "stripe-live-secret-key", "critical"), ("aws", "aws-access-key-id", "high"),
     ("github", "github-token", "high"), ("slack", "slack-token", "high"), ("google", "google-api-key", "medium")],
)
def test_builtin_rules(kind, rule, sev, no_leaks):
    raw = fake_secrets()[kind]
    (f,) = l1.scan_text(f"line1\nkey = '{raw}'\n", "cfg.py")
    assert (f.rule, f.severity, f.location.line, f.location.file) == (rule, sev, 2, "cfg.py")
    no_leaks(f.to_json(), secrets=[raw])  # a finding never carries the secret


def test_private_key_block_is_critical():
    (f,) = l1.scan_text("-----BEGIN RSA PRIV" + "ATE KEY-----\nabc\n", "k.pem")  # built at run time
    assert f.severity == "critical"


def test_stripe_live_message_tells_user_to_rotate():
    (f,) = l1.scan_text(stripe(), "a.py")
    assert "rotate" in f.plain_words.lower()


def test_same_secret_same_fingerprint_different_line_still_stable():
    a = l1.scan_text(stripe(), "a.py")[0]
    b = l1.scan_text("\n\n\n" + stripe(), "a.py")[0]
    assert a.fingerprint == b.fingerprint and a.id == b.id and a.location.line != b.location.line


# ----------------------------------------------------------------------------- tool output parsing
def project_for_fixture(tmp_path: Path, key: str) -> Path:
    (tmp_path / "app.py").write_text(
        "import os\n"
        "# demo\n"
        f'STRIPE = "{key}"\n'
        f'ANON = "{make_jwt("anon")}"\n'
        'API_KEY = "changeme"\n',
        encoding="utf-8",
    )
    return tmp_path


def fake_runner(stdout: str, name_ok: str = "betterleaks", rc: int = 0):
    calls = []

    async def runner(name, args, **kw):
        calls.append((name, list(args)))
        if name != name_ok:
            return ToolResult(name, "skipped", reason=f"{name} not installed")
        return ToolResult(name, "ok", rc, stdout, "", 0.01, sha256="0" * 64)

    runner.calls = calls
    return runner


async def test_recorded_betterleaks_output_stripe_kept_anon_and_placeholder_dropped(tmp_path):
    key = stripe()
    project = project_for_fixture(tmp_path, key)
    recorded = (FIXTURES / "gitleaks_report_sample.json").read_text(encoding="utf-8")
    runner = fake_runner(recorded)
    res = await l1.run(project, runner=runner)
    rules = {(f.location.line, f.rule) for f in res.findings}
    assert (3, "stripe-live-secret-key") in rules
    assert not any(f.location.line in (4, 5) for f in res.findings)  # anon JWT + changeme are not secrets
    stripe_f = next(f for f in res.findings if f.location.line == 3)
    assert set(stripe_f.sources) == {"betterleaks", "proofgate-builtin"} and stripe_f.confirmed_by == 2
    assert runner.calls[0][0] == "betterleaks" and "--redact" in runner.calls[0][1]
    assert {t.name: t.status for t in res.tools}["betterleaks"] == "ok"


async def test_tool_only_finding_is_kept_when_builtin_misses_it(tmp_path):
    (tmp_path / "x.py").write_text("tok = 'k8Jd92mXq0LpZ7vTn4RbYh3WqE5s'\n", encoding="utf-8")
    report = json.dumps([{"RuleID": "generic-api-key", "File": "x.py", "StartLine": 1, "StartColumn": 8,
                          "EndColumn": 36, "Secret": "REDACTED"}])
    res = await l1.run(tmp_path, runner=fake_runner(report))
    (f,) = res.findings
    assert f.sources == ["betterleaks"] and f.severity == "medium" and f.confidence == "low"


async def test_service_role_reported_by_tool_as_jwt_becomes_critical(tmp_path):
    (tmp_path / "c.js").write_text(f'const k = "{make_jwt("service_role")}"\n', encoding="utf-8")
    report = json.dumps([{"RuleID": "jwt", "File": "c.js", "StartLine": 1, "StartColumn": 1, "EndColumn": 5, "Secret": "REDACTED"}])
    res = await l1.run(tmp_path, runner=fake_runner(report))
    (f,) = res.findings
    assert f.severity == "critical" and set(f.sources) == {"betterleaks", "proofgate-jwt"}


async def test_falls_back_to_gitleaks_and_records_the_skip(tmp_path):
    project = project_for_fixture(tmp_path, stripe())
    res = await l1.run(project, runner=fake_runner("[]", name_ok="gitleaks"))
    statuses = {t.name: t.status for t in res.tools}
    assert statuses["betterleaks"] == "skipped" and statuses["gitleaks"] == "ok"


async def test_no_tool_installed_still_finds_builtin_and_records_skips(tmp_path):
    project = project_for_fixture(tmp_path, stripe())
    res = await l1.run(project, runner=fake_runner("[]", name_ok="none"))
    assert [f.rule for f in res.findings] == ["stripe-live-secret-key"]
    statuses = {t.name: t.status for t in res.tools}
    assert statuses["betterleaks"] == statuses["gitleaks"] == "skipped"
    assert any("not installed" in n for n in res.notes)


@pytest.mark.parametrize("stdout,rc", [("{not json", 0), ('{"a": 1}', 0), ("[]", 2)])
async def test_bad_tool_output_never_crashes(tmp_path, stdout, rc):
    project = project_for_fixture(tmp_path, stripe())
    res = await l1.run(project, runner=fake_runner(stdout, rc=rc))
    assert isinstance(res, LayerResult) and res.findings  # built-in findings survive
    assert res.notes


async def test_missing_real_tool_does_not_crash(tmp_path):
    # real runner with the shipped (unpinned) lock: tools are skipped/refused, never run
    project = project_for_fixture(tmp_path, stripe())
    res = await l1.run(project)
    assert any(f.rule == "stripe-live-secret-key" for f in res.findings)


# ----------------------------------------------------------------------------- the corpus (done-when)
async def test_flags_v09_and_v10_but_not_c03_or_clean_apps():
    results = {name: await l1.run(CORPUS / name, runner=fake_runner("[]", name_ok="none"))
               for name in ("v09_hardcoded_keys", "v10_service_role_in_bundle", "c03_bait", "c01_clean", "c02_clean_helper", "v01_idor_read")}
    v09 = results["v09_hardcoded_keys"].findings
    assert {f.rule for f in v09} == {"stripe-live-secret-key", "supabase-service-role-key"}
    assert all(f.severity == "critical" and f.location.file == "app.py" for f in v09)
    v10 = results["v10_service_role_in_bundle"].findings
    assert [(f.rule, f.location.file) for f in v10] == [("supabase-service-role-key", "static/bundle.js")]
    for clean in ("c03_bait", "c01_clean", "c02_clean_helper", "v01_idor_read"):
        assert results[clean].findings == [], clean


async def test_findings_validate_and_do_not_leak(no_leaks):
    res = await l1.run(CORPUS / "v09_hardcoded_keys", runner=fake_runner("[]", name_ok="none"))
    src = (CORPUS / "v09_hardcoded_keys" / "app.py").read_text(encoding="utf-8")
    raw = [t for t in src.replace('"', " ").split() if t.startswith(("sk_", "eyJ"))]
    assert raw
    for f in res.findings:
        Finding.model_validate(f.to_json_dict())
        no_leaks(f.to_json(), secrets=raw)


def test_env_files_are_not_scanned(tmp_path):
    (tmp_path / ".env").write_text(f"STRIPE={stripe()}\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(f'k = "{stripe()}"\n', encoding="utf-8")
    import asyncio

    res = asyncio.run(l1.run(tmp_path, runner=fake_runner("[]", name_ok="none")))
    assert [f.location.file for f in res.findings] == ["app.py"]
