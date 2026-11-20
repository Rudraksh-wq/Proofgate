"""Layer 7: a passive scan of the RUNNING app (plan 2). Localhost only, and only with `--full` (it starts the app).

Backends, tried in this order, always recorded in the report:

  1. native ZAP   `zap.bat` / `zap.sh` (PROOFGATE_ZAP_PATH, PATH, usual install folders) with an Automation Framework plan: spider + passive scan.
  2. Docker ZAP   `zap-baseline.py` in the ZAP image, only when `docker info` answers. Optional; never required.
  3. dast-lite    built-in checks over plain HTTP: security headers, cookie flags, CORS, exposed `.map` files, directory listing.
                  Findings carry source `dast-lite`. It is NOT a replacement for ZAP and is never described as equal to it.

The ZAP paths are pending real-tool verification (their report parser is tested on a hand-written sample of ZAP's traditional-json report).
A target that is not localhost is refused: there is no override for layer 7.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..models import Finding, ToolRecord
from ..redact import redact
from ..runner import exec_binary
from ..supabase_target import docker_available
from .base import LayerResult, finding_id

LAYER = 7
LITE = "dast-lite"
LITE_NOTE = ("dast-lite: ZAP was not used; only built-in checks ran (security headers, cookie flags, CORS, exposed source maps, directory listing). "
             "This is NOT equivalent to a ZAP scan.")
MAX_PAGES = 12
ZAP_TIMEOUT_S = 300.0
CACHE_REL = ".proofgate/dast_cache.json"


class DastRefused(Exception):
    """The target is not localhost."""


def check_localhost(url: str) -> str:
    from ..probe.guard import _is_local_host

    p = urlparse(url if "://" in url else f"http://{url}")
    if p.scheme not in ("http", "https") or not p.hostname or not _is_local_host(p.hostname):
        raise DastRefused(f"layer 7 only scans localhost, got {p.hostname or url!r}; there is no override")
    return p.geturl().rstrip("/")


# ------------------------------------------------------------------------------------------- findings
def _finding(rule: str, route: str, *, severity: str, title: str, plain: str, cwe: str | None, source: str, confidence: str = "medium") -> Finding:
    fp = f"sha256:{source}:{rule}|{route}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category="web", rule=f"{source}:{rule}", cwe=cwe, severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        title=redact(f"{title} ({route})"), plain_words=redact(plain), location={"file": route, "line": 1}, sources=[source])


# ------------------------------------------------------------------------------------------- dast-lite
_HEADERS = (
    ("content-security-policy", "csp-missing", "medium", "No Content-Security-Policy header", "CWE-693",
     "Pages are served without a Content-Security-Policy, so the browser has no second line of defence against injected scripts."),
    ("x-content-type-options", "nosniff-missing", "low", "No X-Content-Type-Options header", "CWE-693",
     "Without 'X-Content-Type-Options: nosniff' browsers may guess a file's type and run it as a script."),
    ("referrer-policy", "referrer-policy-missing", "low", "No Referrer-Policy header", "CWE-200",
     "Without a Referrer-Policy the full address of your pages, including ids, can leak to other sites through links."),
)
_VERSIONED = re.compile(r"\d+\.\d+")
_HREF = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_LISTING = re.compile(r"<title>\s*(?:Index of /|Directory listing for)|<h1>\s*Index of /", re.IGNORECASE)


def _has_frame_protection(h: httpx.Headers) -> bool:
    return "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "").lower()


def _cookie_findings(resp: httpx.Response, route: str, https: bool) -> list[Finding]:
    out = []
    for raw in resp.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        flags = raw.lower()
        if "httponly" not in flags:
            out.append(_finding("cookie-no-httponly", f"{route} [cookie {name}]", severity="medium", cwe="CWE-1004", source=LITE,
                                title=f"Cookie '{name}' can be read by page scripts", confidence="high",
                                plain="The cookie has no HttpOnly flag, so any script injected into a page can read it. Set HttpOnly on session cookies."))
        if "samesite" not in flags:
            out.append(_finding("cookie-no-samesite", f"{route} [cookie {name}]", severity="low", cwe="CWE-1275", source=LITE,
                                title=f"Cookie '{name}' has no SameSite setting", confidence="high",
                                plain="Without SameSite the browser sends the cookie on cross-site requests. Set SameSite=Lax or Strict."))
        if https and "secure" not in flags:
            out.append(_finding("cookie-no-secure", f"{route} [cookie {name}]", severity="medium", cwe="CWE-614", source=LITE,
                                title=f"Cookie '{name}' is sent over plain HTTP", confidence="high",
                                plain="The cookie has no Secure flag, so it can travel over an unencrypted connection."))
    return out


async def dast_lite(base: str, client: httpx.AsyncClient | None = None) -> tuple[list[Finding], int]:
    """Run the built-in checks against `base` (already verified as localhost). Returns (findings, pages fetched)."""
    https = base.startswith("https://")
    own = client is None
    client = client or httpx.AsyncClient(timeout=5.0, follow_redirects=False)
    findings: dict[str, Finding] = {}
    missing: dict[str, list[str]] = {}
    pages: list[tuple[str, httpx.Response]] = []

    def add(f: Finding) -> None:
        findings.setdefault(f.fingerprint or f.id, f)

    try:
        todo, seen = ["/"], set()
        while todo and len(pages) < MAX_PAGES:
            path = todo.pop(0)
            if path in seen:
                continue
            seen.add(path)
            try:
                r = await client.get(base + path)
            except httpx.HTTPError:
                continue
            pages.append((path, r))
            if "text/html" in r.headers.get("content-type", ""):
                for href in _HREF.findall(r.text[:200_000]):
                    u = urlparse(urljoin(base + path, href))
                    if u.netloc == urlparse(base).netloc and u.path not in seen and not u.path.endswith((".png", ".jpg", ".ico", ".css", ".svg")):
                        todo.append(u.path or "/")
        # --- headers and cookies on every page we reached (a missing header is reported once per kind, listing the pages)
        for path, r in pages:
            for header, rule, _sev, _t, _cwe, _plain in _HEADERS:
                if header not in r.headers:
                    missing.setdefault(rule, []).append(path)
            if "text/html" in r.headers.get("content-type", "") and not _has_frame_protection(r.headers):
                missing.setdefault("clickjacking", []).append(path)
            for h in ("server", "x-powered-by"):
                if _VERSIONED.search(r.headers.get(h, "")):
                    add(_finding("version-disclosure", f"/ [{h}]", severity="low", cwe="CWE-200", source=LITE, confidence="high",
                                 title=f"The {h} header reveals a software version",
                                 plain=f"The response header '{h}: {redact(r.headers[h])[:60]}' tells attackers exactly which version to look up. Remove or generalise it."))
            for f in _cookie_findings(r, path, https):
                add(f)
        by_rule = {h[1]: h for h in _HEADERS}
        for rule, paths in missing.items():
            where = ", ".join(sorted(set(paths))[:4])
            if rule == "clickjacking":
                add(_finding(rule, "/ [headers]", severity="low", cwe="CWE-1021", source=LITE,
                             title="Pages can be framed by other sites", plain=f"No X-Frame-Options or CSP frame-ancestors on {where}: another site can embed these pages invisibly and trick clicks."))
            else:
                _h, _r, sev, title, cwe, plain = by_rule[rule]
                add(_finding(rule, "/ [headers]", severity=sev, cwe=cwe, source=LITE, title=title, plain=f"{plain} Seen on: {where}."))
        if https and pages and "strict-transport-security" not in pages[0][1].headers:
            add(_finding("hsts-missing", "/ [headers]", severity="low", cwe="CWE-319", source=LITE, title="No Strict-Transport-Security header",
                         plain="The site is served over HTTPS without HSTS, so a first visit can be downgraded to HTTP."))
        # --- CORS: ask as a stranger's website
        evil = "https://evil.example"
        try:
            r = await client.get(base + "/", headers={"Origin": evil})
            acao, acac = r.headers.get("access-control-allow-origin", ""), r.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == evil or acao == "null":
                add(_finding("cors-reflects-origin", "/ [cors]", severity="high" if acac else "medium", cwe="CWE-942", source=LITE, confidence="high",
                             title="Any website may read responses" + (" with the visitor's login" if acac else ""),
                             plain="The server copies the caller's Origin into Access-Control-Allow-Origin" + (" and allows credentials" if acac else "")
                             + ", so a stranger's page can read this API. List the origins you trust."))
            elif acao == "*":
                add(_finding("cors-wildcard", "/ [cors]", severity="high" if acac else "low", cwe="CWE-942", source=LITE, confidence="high",
                             title="Any website may read public responses", plain="Access-Control-Allow-Origin is '*'. Fine for public data, wrong for anything per-user."))
        except httpx.HTTPError:
            pass
        # --- exposed source maps next to scripts we saw
        scripts = {p for p, r in pages if p.endswith(".js")}
        for _p, r in pages:
            if "text/html" in r.headers.get("content-type", ""):
                scripts |= {urlparse(urljoin(base + "/", h)).path for h in _HREF.findall(r.text[:200_000]) if h.split("?")[0].endswith(".js")}
        for js in sorted(scripts)[:10]:
            try:
                r = await client.get(base + js + ".map")
            except httpx.HTTPError:
                continue
            if r.status_code == 200 and '"sources"' in r.text[:4000]:
                add(_finding("source-map-exposed", js + ".map", severity="medium", cwe="CWE-540", source=LITE, confidence="high",
                             title="A source map is served", plain=f"{js}.map is publicly readable and contains your original source. Do not publish source maps."))
        # --- directory listings
        for d in ("/", "/static/", "/uploads/", "/files/", "/assets/", "/backup/"):
            try:
                r = await client.get(base + d)
            except httpx.HTTPError:
                continue
            if r.status_code == 200 and _LISTING.search(r.text[:4000]):
                add(_finding("directory-listing", d, severity="medium", cwe="CWE-548", source=LITE, confidence="high",
                             title="A folder's file list is public", plain=f"{d} lists its files to anyone. Turn directory listing off."))
    finally:
        if own:
            await client.aclose()
    return sorted(findings.values(), key=lambda f: (f.location.file, f.rule)), len(pages)


# ------------------------------------------------------------------------------------------- ZAP
def find_zap() -> Path | None:
    cands: list[str | None] = [os.environ.get("PROOFGATE_ZAP_PATH")]
    names = ["zap.bat", "zap.sh"] if sys.platform == "win32" else ["zap.sh", "zap.bat"]
    cands += [shutil.which(n) for n in names]
    if sys.platform == "win32":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base:
                cands.append(str(Path(base) / "ZAP" / "Zed Attack Proxy" / "zap.bat"))
    else:
        cands += ["/usr/share/zaproxy/zap.sh", "/opt/zaproxy/zap.sh", "/Applications/ZAP.app/Contents/Java/zap.sh"]
    for c in cands:
        if c and Path(c).is_file():
            return Path(c)
    return None


_RISK = {"3": "high", "2": "medium", "1": "low"}  # riskcode 0 = informational: not a finding


def parse_zap_report(text: str) -> list[Finding]:
    """ZAP `traditional-json` report -> findings. One finding per alert type and path."""
    data = json.loads(text)
    out: dict[str, Finding] = {}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            sev = _RISK.get(str(a.get("riskcode", "0")))
            if sev is None:
                continue
            cwe = f"CWE-{a['cweid']}" if str(a.get("cweid", "")).isdigit() and int(a["cweid"]) > 0 else None
            desc = re.sub(r"<[^>]+>", " ", str(a.get("desc", ""))).strip()
            sol = re.sub(r"<[^>]+>", " ", str(a.get("solution", ""))).strip()
            paths = sorted({urlparse(i.get("uri", "")).path or "/" for i in a.get("instances", [])}) or ["/"]
            for path in paths[:5]:
                f = _finding(str(a.get("pluginid", "zap")), path, severity=sev, cwe=cwe, source="zap", confidence="medium",
                             title=str(a.get("alert") or a.get("name") or "ZAP alert"), plain=f"{desc[:300]} {('Fix: ' + sol[:200]) if sol else ''}".strip())
                out.setdefault(f.fingerprint or f.id, f)
    return sorted(out.values(), key=lambda f: (f.location.file, f.rule))


def automation_plan(url: str, report_dir: str) -> str:
    return (f"env:\n  contexts:\n    - name: proofgate\n      urls:\n        - \"{url}\"\n"
            "jobs:\n  - type: spider\n    parameters:\n      maxDuration: 1\n"
            "  - type: passiveScan-wait\n    parameters:\n      maxDuration: 2\n"
            f"  - type: report\n    parameters:\n      template: traditional-json\n      reportDir: \"{report_dir}\"\n      reportFile: zap-report\n")


async def _run_native_zap(zap: Path, url: str, result: LayerResult) -> list[Finding] | None:
    with tempfile.TemporaryDirectory(prefix="proofgate-zap-") as td:
        plan = Path(td) / "plan.yaml"
        plan.write_text(automation_plan(url, td.replace("\\", "/")), encoding="utf-8")
        res = await exec_binary(zap, ["-cmd", "-autorun", str(plan)], name="zap", timeout=ZAP_TIMEOUT_S)
        result.tools.append(res.to_record())
        if res.status != "ok":
            result.notes.append(f"zap: {res.status}: {redact(res.reason)}")
            return None
        report = Path(td) / "zap-report.json"
        if not report.is_file():
            result.notes.append(f"zap exited {res.returncode} without a report: {redact((res.stderr or res.stdout)[-300:])}")
            return None
        try:
            return parse_zap_report(report.read_text(encoding="utf-8"))
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            result.notes.append(f"zap: could not parse its report: {redact(str(e))}")
            return None


async def _run_docker_zap(url: str, port: int, result: LayerResult) -> list[Finding] | None:
    docker = shutil.which("docker")
    if not docker:
        return None
    with tempfile.TemporaryDirectory(prefix="proofgate-zapdocker-") as td:
        os.chmod(td, 0o777)
        args = ["run", "--rm", "--add-host", "host.docker.internal:host-gateway", "-v", f"{td}:/zap/wrk:rw", "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py", "-t", f"http://host.docker.internal:{port}", "-J", "report.json", "-I"]
        res = await exec_binary(docker, args, name="zap-docker", timeout=ZAP_TIMEOUT_S)
        result.tools.append(res.to_record())
        report = Path(td) / "report.json"
        if res.status != "ok" or not report.is_file():
            result.notes.append(f"zap (docker): {res.status}: {redact(res.reason or (res.stderr or res.stdout)[-200:])}")
            return None
        try:
            return parse_zap_report(report.read_text(encoding="utf-8"))
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            result.notes.append(f"zap (docker): could not parse its report: {redact(str(e))}")
            return None


# ------------------------------------------------------------------------------------------- cache + run
def _cache_key(project: Path, target: str | None) -> str:
    h = hashlib.sha256((target or "local").encode())
    skip = {".git", "node_modules", ".venv", "__pycache__", ".proofgate", ".next", "dist", "build"}
    n = 0
    for dp, dns, fns in os.walk(project):
        dns[:] = sorted(d for d in dns if d not in skip)
        for fn in sorted(fns):
            p = Path(dp) / fn
            if p.suffix in {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".json", ".mjs"} and n < 500:
                try:
                    h.update(p.relative_to(project).as_posix().encode() + p.read_bytes())
                    n += 1
                except OSError:
                    pass
    return h.hexdigest()


def _load_cache(project: Path, key: str) -> dict | None:
    try:
        d = json.loads((project / CACHE_REL).read_text(encoding="utf-8"))
        return d if d.get("key") == key else None
    except (OSError, ValueError):
        return None


def _save_cache(project: Path, key: str, backend: str, findings: list[Finding], pages: int) -> None:
    try:
        p = project / CACHE_REL
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"key": key, "backend": backend, "pages": pages, "findings": [f.to_json_dict() for f in findings]}), encoding="utf-8")
    except OSError:
        pass


async def _scan(project: Path, base: str, port: int, result: LayerResult, *, backend: str | None) -> tuple[str, list[Finding], int]:
    zap = None if backend == "lite" else find_zap()
    if zap is not None:
        found = await _run_native_zap(zap, base, result)
        if found is not None:
            return "zap", found, 0
        result.notes.append("native ZAP failed: falling back")
    else:
        result.tools.append(ToolRecord(name="zap", status="skipped"))
        result.notes.append("zap: skipped: native ZAP not found (set PROOFGATE_ZAP_PATH to zap.bat / zap.sh)")
    if backend != "lite" and docker_available():
        found = await _run_docker_zap(base, port, result)
        if found is not None:
            return "zap-docker", found, 0
    else:
        result.tools.append(ToolRecord(name="zap-docker", status="skipped"))
        result.notes.append("zap (docker): skipped: Docker is not available (optional)")
    found, pages = await dast_lite(base)
    result.tools.append(ToolRecord(name=LITE, status="ok"))
    result.notes.append(LITE_NOTE)
    return LITE, found, pages


async def run(project_dir: str | Path, *, target: str | None = None, backend: str | None = None, refresh: bool | None = None, **_ignored) -> LayerResult:
    """`target`: None / "local" starts the app from the project; a localhost URL scans an app that is already running."""
    project = Path(project_dir).resolve()
    result = LayerResult(layer=LAYER)
    external = target if target and target != "local" else None
    try:
        if external:
            base = check_localhost(external)
    except DastRefused as e:
        result.tools.append(ToolRecord(name="proofgate-dast", status="error"))
        result.notes.append(f"layer 7 refused: {redact(str(e))}")
        return result
    key = _cache_key(project, external)
    if refresh is None:
        refresh = os.environ.get("PROOFGATE_DAST_REFRESH") == "1"
    cached = None if refresh else _load_cache(project, key)
    if cached:
        result.findings = [Finding.model_validate(f) for f in cached["findings"]]
        result.tools.append(ToolRecord(name=cached["backend"], status="ok"))
        result.notes.append(f"reused the cached {cached['backend']} result for unchanged source (set PROOFGATE_DAST_REFRESH=1 to scan again)")
        if cached["backend"] == LITE:
            result.notes.append(LITE_NOTE)
        return result
    if external:
        port = urlparse(base).port or (443 if base.startswith("https") else 80)
        name, found, pages = await _scan(project, base, port, result, backend=backend)
    else:
        from ..probe.launcher import AppProcess, LaunchError

        try:
            app = AppProcess.start(project)
        except LaunchError as e:
            result.tools.append(ToolRecord(name="proofgate-dast", status="skipped"))
            result.notes.append(f"layer 7: skipped: {redact(str(e))} (the app could not be started here)")
            return result
        try:
            async with app:
                name, found, pages = await _scan(project, app.url, app.port, result, backend=backend)
        except LaunchError as e:
            result.tools.append(ToolRecord(name="proofgate-dast", status="error"))
            result.notes.append(f"layer 7: the app did not start: {redact(str(e))}")
            return result
    result.findings = found
    result.notes.append(f"{name}: {len(found)} finding(s)" + (f" over {pages} page(s)" if pages else ""))
    _save_cache(project, key, name, found, pages)
    return result
