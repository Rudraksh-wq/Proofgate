import datetime as dt
import json
from pathlib import Path

import httpx
import pytest

from proofgate.layers import l4_supply_chain as l4
from proofgate.layers.l4_supply_chain import evaluate_record, is_one_edit, typosquat_target
from proofgate.models import Finding
from proofgate.pkgcache import PackageCache
from proofgate.registry import RegistryClient
from proofgate.runner import ToolResult

from corpus_harness import CORPUS

NOW = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "tool_outputs"
FAKE = json.loads((CORPUS / "registry_check.json").read_text(encoding="utf-8"))["package"]


def rules(findings):
    return sorted(f.rule for f in findings)


# ----------------------------------------------------------------------------- typosquat distance
@pytest.mark.parametrize("a,b,expected", [
    ("requests", "reqeusts", True), ("requests", "request", True), ("requests", "requestss", True),
    ("requests", "requesys", True), ("requests", "requests", False), ("requests", "reqests2", False),
    ("numpy", "nunpy", True), ("numpy", "pandas", False), ("ab", "abc", True), ("abc", "xyz", False),
])
def test_is_one_edit(a, b, expected):
    assert is_one_edit(a, b) is expected


def test_typosquat_target_finds_the_popular_name():
    assert typosquat_target("pypi", "reqeusts") == "requests"
    assert typosquat_target("npm", "lodsh") == "lodash"
    assert typosquat_target("pypi", "requests") is None  # the real thing
    assert typosquat_target("pypi", "flask-notes-sanitizer-pgx7k2") is None
    assert typosquat_target("npm", "@scope/lodsh") is None and typosquat_target("pypi", "abc") is None


def test_pypi_names_are_normalised_before_comparing():
    assert typosquat_target("pypi", "Python_Dateutil") is None


# ----------------------------------------------------------------------------- evaluate_record (pure)
def ev(rec, name="shiny", eco="pypi"):
    return evaluate_record(eco, name, rec, "requirements.txt", 3, NOW)


def test_nonexistent_is_critical_and_asks_for_a_human():
    (f,) = ev({"exists": False}, name=FAKE)
    assert (f.rule, f.severity, f.category, f.layer, f.interrupt_human) == ("package-does-not-exist", "critical", "supply-chain", 4, True)
    Finding.model_validate(f.to_json_dict())


def test_new_package_is_high_and_old_one_is_not():
    assert rules(ev({"exists": True, "first_release": "2026-11-10"})) == ["package-very-new"]
    assert ev({"exists": True, "first_release": "2020-01-01", "weekly_downloads": 5_000_000}) == []


def test_low_downloads_is_a_medium_warning():
    (f,) = ev({"exists": True, "first_release": "2024-01-01", "weekly_downloads": 12})
    assert f.rule == "package-low-downloads" and f.severity == "medium"


def test_typosquat_flagged_only_when_not_established():
    young = ev({"exists": True, "first_release": "2026-09-01", "weekly_downloads": 40}, name="reqeusts")
    assert "package-typosquat" in rules(young)
    old = ev({"exists": True, "first_release": "2018-01-01", "weekly_downloads": 3}, name="reqeusts")
    assert "package-typosquat" not in rules(old)  # a long-lived package is not a fresh squat
    unknown = ev({"exists": True, "first_release": None, "weekly_downloads": None}, name="reqeusts")
    assert "package-typosquat" in rules(unknown)


def test_fingerprint_is_stable_across_lines():
    a = evaluate_record("pypi", "x-y", {"exists": False}, "requirements.txt", 3, NOW)[0]
    b = evaluate_record("pypi", "x_y", {"exists": False}, "requirements.txt", 9, NOW)[0]
    assert a.fingerprint == b.fingerprint  # normalised name


# ----------------------------------------------------------------------------- registry client (mock transport)
def mock_client(handler) -> RegistryClient:
    return RegistryClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def pypi_handler(exists=True, stats_status=200):
    def handler(req: httpx.Request):
        url = str(req.url)
        if url.startswith("https://pypi.org/pypi/"):
            if not exists:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json={"releases": {
                "1.0": [{"upload_time_iso_8601": "2019-03-04T10:00:00.000000Z"}],
                "2.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00.000000Z"}], "0.1": []}})
        if url.startswith("https://pypistats.org/"):
            return httpx.Response(stats_status, json={"data": {"last_week": 1234}})
        return httpx.Response(500)

    return handler


async def test_pypi_existing_package():
    rc = mock_client(pypi_handler())
    assert await rc.lookup("pypi", "Some_Pkg") == {"exists": True, "first_release": "2019-03-04", "weekly_downloads": 1234}


async def test_pypi_missing_package_is_404_not_error():
    assert (await mock_client(pypi_handler(exists=False)).lookup("pypi", FAKE))["exists"] is False


async def test_pypistats_failure_only_loses_the_download_count():
    rec = await mock_client(pypi_handler(stats_status=429)).lookup("pypi", "pkg")
    assert rec["exists"] is True and rec["weekly_downloads"] is None


def npm_handler(downloads=50, created="2026-11-15T00:00:00.000Z", exists=True, hits=None):
    def handler(req: httpx.Request):
        if hits is not None:
            hits.append(str(req.url))
        if req.url.host == "api.npmjs.org":
            return httpx.Response(200, json={"downloads": downloads}) if exists else httpx.Response(404, json={"error": "not found"})
        if not exists:
            return httpx.Response(404, json={"error": "Not found"})
        return httpx.Response(200, json={"time": {"created": created}})

    return handler


async def test_npm_new_package():
    rec = await mock_client(npm_handler()).lookup("npm", "tiny-lib")
    assert rec == {"exists": True, "first_release": "2026-11-15", "weekly_downloads": 50}


async def test_npm_established_package_skips_the_big_metadata_document():
    hits: list[str] = []
    rec = await mock_client(npm_handler(downloads=9_000_000, hits=hits)).lookup("npm", "react")
    assert rec["exists"] and rec["first_release"] is None and not any("registry.npmjs.org" in h for h in hits)


async def test_npm_missing_and_scoped():
    assert (await mock_client(npm_handler(exists=False)).lookup("npm", "nope-nope"))["exists"] is False
    hits: list[str] = []
    await mock_client(npm_handler(hits=hits)).lookup("npm", "@supabase/ssr")
    assert any("registry.npmjs.org/@supabase%2Fssr" in h for h in hits)


@pytest.mark.parametrize("handler", [lambda r: httpx.Response(500), lambda r: httpx.Response(200, text="not json")])
async def test_server_errors_and_garbage_are_unknown_not_missing(handler):
    rc = mock_client(handler)
    assert await rc.lookup("pypi", "x") is None and await rc.lookup("npm", "x") is None


async def test_network_error_is_unknown_not_missing():
    def boom(req):
        raise httpx.ConnectError("offline")

    assert await mock_client(boom).lookup("pypi", "x") is None


# ----------------------------------------------------------------------------- run()
def counting(handler):
    calls = []

    def wrapped(req):
        calls.append(str(req.url))
        return handler(req)

    return wrapped, calls


def registry_for_corpus():
    def handler(req: httpx.Request):
        url = str(req.url)
        if f"/pypi/{FAKE}/json" in url:
            return httpx.Response(404, json={})
        return pypi_handler()(req)

    return handler


async def test_v11_fake_package_is_flagged_and_cached(tmp_path):
    cache = PackageCache(tmp_path / "c.json")
    handler, calls = counting(registry_for_corpus())
    res = await l4.run(CORPUS / "v11_hallucinated_dep", cache=cache, client=mock_client(handler), offline=False, now=NOW,
                       runner=skip_runner())
    (f,) = [f for f in res.findings if f.rule == "package-does-not-exist"]
    assert f.severity == "critical" and f.location.file == "requirements.txt" and f.location.line == 2 and FAKE in f.title
    assert {f.rule for f in res.findings} <= {"package-does-not-exist", "package-low-downloads"}
    assert len(calls) > 0
    # second run: everything is answered from disk, zero network
    handler2, calls2 = counting(lambda r: httpx.Response(500))
    again = await l4.run(CORPUS / "v11_hallucinated_dep", cache=PackageCache(tmp_path / "c.json"), client=mock_client(handler2),
                         offline=False, now=NOW, runner=skip_runner())
    assert calls2 == [] and [f.id for f in again.findings] == [f.id for f in res.findings]


async def test_offline_uses_only_the_cache_and_says_what_it_could_not_check(tmp_path):
    cold = await l4.run(CORPUS / "v11_hallucinated_dep", cache=PackageCache(tmp_path / "c.json"), offline=True, now=NOW,
                        runner=skip_runner())
    assert cold.findings == [] and any("PROOFGATE_OFFLINE" in n and FAKE in n for n in cold.notes)
    assert {t.status for t in cold.tools if t.name.endswith("-registry")} == {"skipped"}

    warm = PackageCache(tmp_path / "w.json")
    warm.put("pypi", FAKE, exists=False)
    warm.put("pypi", "flask", exists=True, first_release="2010-04-06", weekly_downloads=10**7)
    res = await l4.run(CORPUS / "v11_hallucinated_dep", cache=warm, offline=True, now=NOW, runner=skip_runner())
    assert rules(res.findings) == ["package-does-not-exist"]


async def test_env_var_turns_offline_on(tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFGATE_OFFLINE", "1")
    handler, calls = counting(lambda r: httpx.Response(500))
    await l4.run(CORPUS / "v11_hallucinated_dep", cache=PackageCache(tmp_path / "c.json"), client=mock_client(handler),
                 now=NOW, runner=skip_runner())
    assert calls == []


async def test_unreachable_registry_is_a_note_not_a_finding(tmp_path):
    def boom(req):
        raise httpx.ConnectError("no wifi")

    res = await l4.run(CORPUS / "v11_hallucinated_dep", cache=PackageCache(tmp_path / "c.json"), client=mock_client(boom),
                       offline=False, now=NOW, runner=skip_runner())
    assert res.findings == [] and any("not a finding" in n for n in res.notes)
    assert any(t.status == "error" for t in res.tools)
    assert not (tmp_path / "c.json").exists() or FAKE not in (tmp_path / "c.json").read_text(encoding="utf-8")


async def test_clean_and_outdated_apps_have_no_l4_findings(tmp_path):
    for app in ("c01_clean", "v12_outdated_dep"):
        res = await l4.run(CORPUS / app, cache=PackageCache(tmp_path / f"{app}.json"), client=mock_client(registry_for_corpus()),
                           offline=False, now=NOW, runner=skip_runner())
        assert [f for f in res.findings if f.layer == 4 and f.rule != "package-low-downloads"] == [], app


async def test_package_json_dependencies_are_checked(tmp_path):
    (tmp_path / "package.json").write_text(
        '{\n  "dependencies": {\n    "lodsh": "1.0.0",\n    "@supabase/ssr": "^0.5.0"\n  }\n}\n', encoding="utf-8")
    res = await l4.run(tmp_path, cache=PackageCache(tmp_path / "c.json"), offline=False, now=NOW, runner=skip_runner(),
                       client=mock_client(npm_handler(downloads=20, created="2026-11-18T00:00:00Z")))
    assert {(f.location.line, f.rule) for f in res.findings if f.rule == "package-typosquat"} == {(3, "package-typosquat")}
    assert all(f.location.file == "package.json" for f in res.findings)


# ----------------------------------------------------------------------------- GuardDog (optional)
def skip_runner():
    async def runner(name, args, **kw):
        return ToolResult(name, "skipped", reason=f"{name} not found on PATH")

    return runner


def test_parse_guarddog_sample():
    text = (FIXTURES / "guarddog_sample.json").read_text(encoding="utf-8")
    findings = l4.parse_guarddog(text, CORPUS / "v11_hallucinated_dep" / "requirements.txt", "requirements.txt", "pypi")
    (f,) = findings
    assert f.sources == ["guarddog"] and f.rule == "guarddog-suspicious-behaviour" and f.location.line == 2
    assert "exec-base64" in f.plain_words and "empty-information" not in f.plain_words


async def test_guarddog_runs_through_the_runner_when_listed_in_the_lock(tmp_path):
    from proofgate.toollock import ToolEntry, ToolLock

    sample = (FIXTURES / "guarddog_sample.json").read_text(encoding="utf-8")
    seen = []

    async def runner(name, args, **kw):
        seen.append((name, args[:2]))
        return ToolResult(name, "ok", 0, sample, "", 0.1) if name == "guarddog" else ToolResult(name, "skipped", reason="x")

    lock = ToolLock(tools={"guarddog": ToolEntry(binary="guarddog")})
    cache = PackageCache(tmp_path / "c.json")
    cache.put("pypi", FAKE, exists=True, first_release="2020-01-01", weekly_downloads=10**6)
    cache.put("pypi", "flask", exists=True, first_release="2010-01-01", weekly_downloads=10**7)
    res = await l4.run(CORPUS / "v11_hallucinated_dep", cache=cache, offline=True, now=NOW, runner=runner, lock=lock)
    assert seen == [("guarddog", ["pypi", "verify"])]
    assert [f.sources for f in res.findings] == [["guarddog"]]


async def test_guarddog_not_installed_is_recorded(tmp_path):
    from proofgate.toollock import ToolEntry, ToolLock

    cache = PackageCache(tmp_path / "c.json")
    cache.put("pypi", FAKE, exists=True, first_release="2020-01-01", weekly_downloads=10**6)
    cache.put("pypi", "flask", exists=True, first_release="2010-01-01", weekly_downloads=10**7)
    res = await l4.run(CORPUS / "v11_hallucinated_dep", cache=cache, offline=True, now=NOW, runner=skip_runner(),
                       lock=ToolLock(tools={"guarddog": ToolEntry(binary="guarddog")}))
    assert any(t.name == "guarddog" and t.status == "skipped" for t in res.tools)
