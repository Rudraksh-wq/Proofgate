"""Layer 7: native ZAP, optional Docker ZAP and the built-in dast-lite checks. No real ZAP, no Docker, no network."""
import asyncio
import json
import shutil
from pathlib import Path

import httpx
import pytest

from proofgate.layers import l7_web
from proofgate.orchestrator import run_scan
from proofgate.runner import ToolResult

from corpus_harness import CORPUS

FIX = Path(__file__).parent / "fixtures" / "tool_outputs"
BASE = "http://127.0.0.1:5999"
HARDENED = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}


def client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


def page(body="<html><body>hi</body></html>", headers=None, status=200, ctype="text/html"):
    return httpx.Response(status, text=body, headers={"content-type": ctype, **(headers or {})})


async def lite(handler):
    findings, pages = await l7_web.dast_lite(BASE, client(handler))
    return {f.rule.split(":", 1)[1] for f in findings}, findings, pages


@pytest.fixture(autouse=True)
def hermetic(monkeypatch):
    monkeypatch.setattr(l7_web, "find_zap", lambda: None)
    monkeypatch.setattr(l7_web, "docker_available", lambda timeout=5.0: False)
    monkeypatch.delenv("PROOFGATE_DAST_REFRESH", raising=False)


# ------------------------------------------------------------------------------------------- dast-lite checks
async def test_a_hardened_app_gives_zero_findings():
    rules, findings, pages = await lite(lambda r: page(headers=HARDENED))
    assert findings == [] and pages == 1


async def test_missing_headers_are_reported_once_each_with_the_pages_they_were_seen_on():
    def h(r):
        if r.url.path == "/":
            return page('<a href="/notes">n</a>')
        return page()

    rules, findings, pages = await lite(h)
    assert rules == {"csp-missing", "nosniff-missing", "referrer-policy-missing", "clickjacking"} and pages == 2
    csp = next(f for f in findings if f.rule.endswith("csp-missing"))
    assert "/notes" in csp.plain_words and csp.sources == ["dast-lite"] and csp.layer == 7 and csp.category == "web"


async def test_frame_ancestors_counts_as_clickjacking_protection():
    rules, *_ = await lite(lambda r: page(headers={**HARDENED, "content-security-policy": "frame-ancestors 'self'"}))
    assert "clickjacking" not in rules


async def test_cookie_flags():
    def h(r):
        return page(headers={**HARDENED, "set-cookie": "sid=abc; Path=/"})

    rules, findings, _ = await lite(h)
    assert rules == {"cookie-no-httponly", "cookie-no-samesite"}  # Secure is only expected over https
    ok = await lite(lambda r: page(headers={**HARDENED, "set-cookie": "sid=abc; HttpOnly; SameSite=Lax"}))
    assert ok[0] == set()


async def test_secure_flag_and_hsts_are_checked_over_https():
    base = "https://localhost:5999"
    findings, _ = await l7_web.dast_lite(base, client(lambda r: page(headers={**HARDENED, "set-cookie": "sid=a; HttpOnly; SameSite=Lax"})))
    assert {f.rule.split(":")[1] for f in findings} == {"cookie-no-secure", "hsts-missing"}


async def test_cors_reflecting_the_origin_with_credentials_is_high_and_wildcard_is_low():
    reflect = lambda r: page(headers={**HARDENED, "access-control-allow-origin": r.headers.get("origin", ""), "access-control-allow-credentials": "true"})  # noqa: E731
    _, findings, _ = await lite(reflect)
    f = next(x for x in findings if x.rule.endswith("cors-reflects-origin"))
    assert f.severity == "high"
    _, findings, _ = await lite(lambda r: page(headers={**HARDENED, "access-control-allow-origin": "*"}))
    assert [(x.rule.split(":")[1], x.severity) for x in findings] == [("cors-wildcard", "low")]
    assert (await lite(lambda r: page(headers={**HARDENED, "access-control-allow-origin": "https://app.example"})))[1] == []


async def test_exposed_source_map_and_directory_listing():
    def h(r):
        p = r.url.path
        if p == "/":
            return page('<script src="/static/app.js"></script>', headers=HARDENED)
        if p == "/static/app.js.map":
            return page('{"version":3,"sources":["a.ts"]}', ctype="application/json")
        if p == "/uploads/":
            return page("<html><head><title>Index of /uploads</title></head></html>")
        return httpx.Response(404, text="nope")

    rules, findings, _ = await lite(h)
    assert {"source-map-exposed", "directory-listing"} <= rules
    assert next(f for f in findings if f.rule.endswith("source-map-exposed")).location.file == "/static/app.js.map"


async def test_a_404_for_the_map_is_not_a_finding_and_version_headers_are():
    rules, *_ = await lite(lambda r: page(headers={**HARDENED, "server": "Werkzeug/3.0.1 Python/3.12", "x-powered-by": "Express"}) if r.url.path == "/" else httpx.Response(404))
    assert rules == {"version-disclosure"}  # "Express" alone has no version number


async def test_an_unreachable_target_does_not_crash():
    def boom(r):
        raise httpx.ConnectError("down")

    findings, pages = await l7_web.dast_lite(BASE, client(boom))
    assert findings == [] and pages == 0


async def test_it_follows_same_origin_links_only_and_stops_at_the_page_limit():
    seen = []

    def h(r):
        seen.append(str(r.url))
        links = "".join(f'<a href="/p{i}">x</a>' for i in range(40)) + '<a href="https://other.example/x">o</a>'
        return page(links, headers=HARDENED)

    _, pages = await l7_web.dast_lite(BASE, client(h))
    assert pages == l7_web.MAX_PAGES and not any("other.example" in u for u in seen)


# ------------------------------------------------------------------------------------------- ZAP report parsing
def test_zap_report_parsing_skips_informational_and_maps_risk():
    found = l7_web.parse_zap_report((FIX / "zap_report_sample.json").read_text(encoding="utf-8"))
    got = {(f.rule, f.location.file, f.severity, f.cwe) for f in found}
    assert ("zap:10038", "/", "medium", "CWE-693") in got and ("zap:10038", "/notes", "medium", "CWE-693") in got
    assert ("zap:10021", "/", "low", "CWE-693") in got and not any(f.rule == "zap:10049" for f in found)
    assert all(f.sources == ["zap"] and "<p>" not in f.plain_words for f in found)


def test_the_automation_plan_names_the_target_and_the_report_template():
    plan = l7_web.automation_plan("http://127.0.0.1:5000", "C:/tmp/z")
    assert "http://127.0.0.1:5000" in plan and "traditional-json" in plan and "spider" in plan and "passiveScan-wait" in plan and "activeScan" not in plan


# ------------------------------------------------------------------------------------------- the layer
def corpus_copy(tmp_path, name="c01_clean"):
    dst = tmp_path / name
    shutil.copytree(CORPUS / name, dst, ignore=shutil.ignore_patterns(".proofgate"))
    return dst


async def test_without_zap_or_docker_it_falls_back_to_dast_lite_on_the_running_app(tmp_path):
    res = await l7_web.run(corpus_copy(tmp_path))
    status = {t.name: t.status for t in res.tools}
    assert status == {"zap": "skipped", "zap-docker": "skipped", "dast-lite": "ok"}
    assert any("NOT equivalent to a ZAP scan" in n for n in res.notes)
    assert any("zap: skipped" in n for n in res.notes) and any("Docker is not available" in n for n in res.notes)
    assert res.findings and all(f.sources == ["dast-lite"] for f in res.findings)  # labelled dast-lite, never "zap"


async def test_zero_findings_is_reported_as_such_not_a_crash(tmp_path, monkeypatch):
    async def none(base, client=None):
        return [], 3

    monkeypatch.setattr(l7_web, "dast_lite", none)
    res = await l7_web.run(corpus_copy(tmp_path))
    assert res.findings == [] and any("dast-lite: 0 finding(s) over 3 page(s)" in n for n in res.notes)


async def test_a_non_localhost_target_is_refused_with_no_override(tmp_path):
    for url in ("https://example.com", "http://192.168.1.20:8000", "http://evil.localhost.example.com"):
        res = await l7_web.run(tmp_path, target=url, i_own_this=True)
        assert res.findings == [] and {t.name: t.status for t in res.tools} == {"proofgate-dast": "error"} and any("only scans localhost" in n for n in res.notes)


async def test_an_already_running_localhost_app_can_be_scanned(tmp_path, monkeypatch):
    called = []

    async def fake(base, client=None):
        called.append(base)
        return [], 1

    monkeypatch.setattr(l7_web, "dast_lite", fake)
    res = await l7_web.run(tmp_path, target="http://127.0.0.1:5000/")
    assert called == ["http://127.0.0.1:5000"] and res.tools[-1].status == "ok"


async def test_a_project_that_cannot_be_started_is_a_recorded_skip(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    res = await l7_web.run(tmp_path)
    assert {t.name: t.status for t in res.tools} == {"proofgate-dast": "skipped"} and any("could not be started" in n for n in res.notes)


async def test_native_zap_runs_through_its_plan_and_its_report_is_parsed(tmp_path, monkeypatch):
    fake_zap = tmp_path / "zap.bat"
    fake_zap.write_text("", encoding="utf-8")
    monkeypatch.setattr(l7_web, "find_zap", lambda: fake_zap)
    sample = (FIX / "zap_report_sample.json").read_text(encoding="utf-8")
    seen = {}

    async def fake_exec(path, args, *, name, timeout=60.0, **kw):
        seen.update(path=path, args=list(args), name=name)
        plan = Path(args[args.index("-autorun") + 1]).read_text(encoding="utf-8")
        report_dir = next(line.split('"')[1] for line in plan.splitlines() if "reportDir" in line)
        Path(report_dir, "zap-report.json").write_text(sample, encoding="utf-8")
        return ToolResult("zap", "ok", 0, "", "", 1.0, path=str(path), sha256="0" * 64)

    monkeypatch.setattr(l7_web, "exec_binary", fake_exec)
    res = await l7_web.run(corpus_copy(tmp_path))
    assert seen["args"][:2] == ["-cmd", "-autorun"] and seen["name"] == "zap"
    assert {f.sources[0] for f in res.findings} == {"zap"} and {t.name for t in res.tools} >= {"zap"}
    assert not any("NOT equivalent" in n for n in res.notes)  # ZAP really ran: no dast-lite disclaimer


async def test_a_zap_that_fails_falls_back_to_dast_lite_and_says_so(tmp_path, monkeypatch):
    fake_zap = tmp_path / "zap.bat"
    fake_zap.write_text("", encoding="utf-8")
    monkeypatch.setattr(l7_web, "find_zap", lambda: fake_zap)

    async def broken(path, args, *, name, **kw):
        return ToolResult("zap", "error", 1, "", "java not found", 0.1, reason="java not found")

    monkeypatch.setattr(l7_web, "exec_binary", broken)
    res = await l7_web.run(corpus_copy(tmp_path))
    assert any("native ZAP failed: falling back" in n for n in res.notes) and {t.name for t in res.tools} >= {"zap", "dast-lite"}
    assert res.findings and all(f.sources == ["dast-lite"] for f in res.findings)


async def test_docker_zap_is_used_only_when_docker_answers(tmp_path, monkeypatch):
    monkeypatch.setattr(l7_web, "docker_available", lambda timeout=5.0: True)
    monkeypatch.setattr(l7_web.shutil, "which", lambda n: "/usr/bin/docker" if n == "docker" else None)
    sample = (FIX / "zap_report_sample.json").read_text(encoding="utf-8")
    seen = {}

    async def fake_exec(path, args, *, name, **kw):
        seen["args"] = list(args)
        wrk = next(a.split(":/zap/wrk")[0] for a in args if a.endswith(":/zap/wrk:rw"))
        Path(wrk, "report.json").write_text(sample, encoding="utf-8")
        return ToolResult("zap-docker", "ok", 0, "", "", 1.0)

    monkeypatch.setattr(l7_web, "exec_binary", fake_exec)
    res = await l7_web.run(corpus_copy(tmp_path))
    assert "zap-baseline.py" in seen["args"] and any(("127.0.0.1" in a or "host.docker.internal" in a) for a in seen["args"])
    assert {f.sources[0] for f in res.findings} == {"zap"}


async def test_the_result_is_cached_for_unchanged_source_and_refreshed_on_change(tmp_path, monkeypatch):
    proj = corpus_copy(tmp_path)
    calls = []
    real = l7_web.dast_lite

    async def counting(base, client=None):
        calls.append(base)
        return await real(base, client)

    monkeypatch.setattr(l7_web, "dast_lite", counting)
    first = await l7_web.run(proj)
    second = await l7_web.run(proj)
    assert len(calls) == 1 and [f.id for f in second.findings] == [f.id for f in first.findings] and any("cached" in n for n in second.notes)
    assert any("NOT equivalent" in n for n in second.notes)  # the label survives the cache
    (proj / "app.py").write_text((proj / "app.py").read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    await l7_web.run(proj)
    assert len(calls) == 2
    monkeypatch.setenv("PROOFGATE_DAST_REFRESH", "1")
    await l7_web.run(proj)
    assert len(calls) == 3


async def test_layer7_runs_in_full_scans_not_in_the_default_set(tmp_path):
    from proofgate.orchestrator import ALL_LAYERS, DEFAULT_LAYERS, IMPLEMENTED

    assert 7 in ALL_LAYERS and 7 in IMPLEMENTED and 7 not in DEFAULT_LAYERS  # a plain scan never starts the app
    out = await run_scan(corpus_copy(tmp_path), layers=[7], offline=True)
    assert out.report.layers_run == [7] and not out.tool_error and any(f.layer == 7 for f in out.report.findings)
