import json
import re
from pathlib import Path

import pytest

from proofgate.mcpserver import TOOL_NAMES
from proofgate.models import LIMITS_STATEMENT

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
OUT = WEB / "out"
PAGES = ["", "install", "how-it-works", "limits", "benchmark"]


def js_fixed2(v: float) -> str:
    """What the page prints: JavaScript's toFixed(2) rounds a decimal half up (0.625 -> 0.63), Python's format does not."""
    from decimal import ROUND_HALF_UP, Decimal

    return str(Decimal(v).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def src_files():
    return [p for p in WEB.rglob("*") if p.is_file() and not {"node_modules", ".next", "out"} & set(p.relative_to(WEB).parts)
            and p.suffix in (".ts", ".tsx", ".mjs", ".css", ".json", ".txt", ".md") and p.name != "package-lock.json"]


# ============================================================================= static by construction (source)
def test_there_is_no_backend_in_the_source():
    assert not (WEB / "app" / "api").exists() and not list(WEB.rglob("route.ts")) and not (WEB / "middleware.ts").exists()
    cfg = (WEB / "next.config.mjs").read_text(encoding="utf-8")
    assert 'output: "export"' in cfg


def test_no_forms_scripts_network_calls_or_trackers_in_the_source():
    bad = re.compile(r"<form|<input|<textarea|fetch\(|XMLHttpRequest|navigator\.sendBeacon|document\.cookie|localStorage|"
                     r"google-analytics|googletagmanager|gtag\(|plausible|segment\.com|mixpanel|posthog|hotjar|\"use client\"|dangerouslySetInnerHTML", re.IGNORECASE)
    for p in src_files():
        if p.suffix in (".ts", ".tsx", ".mjs", ".css"):
            assert not bad.search(p.read_text(encoding="utf-8")), p.relative_to(ROOT)


def test_only_the_five_pages_exist():
    pages = sorted(str(p.parent.relative_to(WEB / "app")).replace("\\", "/") for p in (WEB / "app").rglob("page.tsx"))
    assert pages == [".", "benchmark", "how-it-works", "install", "limits"]


def test_the_package_has_no_runtime_dependencies_beyond_next_and_react():
    pkg = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    assert set(pkg["dependencies"]) == {"next", "react", "react-dom"}


# ============================================================================= content
def test_limits_statement_is_verbatim_everywhere():
    site = (WEB / "lib" / "site.ts").read_text(encoding="utf-8")
    assert LIMITS_STATEMENT in site
    assert LIMITS_STATEMENT in (WEB / "scripts" / "build-content.mjs").read_text(encoding="utf-8")


def test_the_statistics_use_the_corrected_wording():
    site = (WEB / "lib" / "site.ts").read_text(encoding="utf-8")
    assert "100+ LLMs on 80 security-sensitive coding tasks, 45% of generated code samples had an OWASP Top 10 flaw" in site
    assert "1,645 apps from Lovable's showcase" in site and "170 (about 10%)" in site and "home addresses" not in site
    assert "Claude Code co-authored public commits leaked secrets at 3.2% versus 1.5% for all public commits" in site
    assert "61% functionally correct but only 10.5% secure" in site
    assert not re.search(r"AI-?generated.{0,30}vs\.? human", site, re.IGNORECASE)  # the GitGuardian claim is NOT "AI vs human-only"


def test_the_site_never_claims_an_app_is_secure():
    for p in (WEB / "app").rglob("*.tsx"):
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(r"(?:is|are|be|now|becomes?) (?:completely |fully )?(?:secure|safe)\b", text, re.IGNORECASE):
            ctx = text[max(0, m.start() - 60): m.end() + 5].lower()
            assert "doesn't mean" in ctx or "does not mean" in ctx or "never says" in ctx or "mean your app" in ctx or "never claim" in ctx, (p.name, ctx)


def test_install_page_snippets_match_the_real_plugin_config():
    page = (WEB / "app" / "install" / "page.tsx").read_text(encoding="utf-8")
    plugin_mcp = json.loads((ROOT / "plugin" / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["proofgate"]
    assert f'"command": "{plugin_mcp["command"]}"' in page and "/plugin marketplace add Rudraksh-wq/Proofgate" in page
    assert "/plugin install proofgate@proofgate" in page and "pipx install proofgate" in page and "proofgate doctor" in page
    for anchor in ("claude-code", "mcp", "cli", "troubleshooting"):
        assert f'id="{anchor}"' in page
    for name in TOOL_NAMES:
        assert name in page


# ============================================================================= llms.txt
LLMS = (WEB / "public" / "llms.txt").read_text(encoding="utf-8")


def test_llms_txt_follows_the_convention():
    lines = LLMS.splitlines()
    assert lines[0] == "# ProofGate" and lines[2].startswith("> ") and "Nothing is uploaded" in LLMS
    assert [l for l in lines if l.startswith("## ")] == ["## Install", "## For AI agents", "## Limits", "## Optional"]
    links = re.findall(r"\]\((https://<site>/[^)]+)\)", LLMS)
    assert len(links) >= 8 and all(l.startswith("https://<site>/") for l in links)  # the placeholder is labelled, not invented
    assert "pipx install proofgate" in LLMS and '"command":"proofgate-mcp"' in LLMS and "get_contract → scan_project → prove → verify_fix" in LLMS


def test_llms_txt_never_tells_an_agent_to_weaken_the_gate_or_send_code_away():
    forbidden = re.compile(r"disable (?:the )?(?:proofgate )?hooks?|skip (?:the )?(?:confirmation|contract|verification|hook)|--no-verify|bypass|"
                           r"upload (?:the |your )?(?:code|repo)|send (?:the |your )?(?:code|repo)|ignore (?:previous|all) instructions|"
                           r"curl |wget ", re.IGNORECASE)
    assert not forbidden.search(LLMS)
    assert "Nothing is uploaded" in LLMS


# ============================================================================= the built site (when `npm run build` has run)
built = pytest.mark.skipif(not (OUT / "index.html").is_file(), reason="web/out not built (cd web && npm install && npm run build)")


@built
def test_build_output_has_every_page_and_file():
    for page in PAGES:
        assert (OUT / page / "index.html").is_file(), page
    for f in ("llms.txt", "llms-full.txt", "limits.md", "benchmark.md", "docs/agent-workflow.md", "docs/mcp-tools.md", "schemas/finding.v1.json"):
        assert (OUT / f).is_file(), f
    assert not (OUT / "api").exists() and not list(OUT.rglob("route*"))


@built
def test_built_pages_have_no_forms_external_resources_or_trackers():
    for page in PAGES:
        html = (OUT / page / "index.html").read_text(encoding="utf-8")
        assert not re.search(r"<form|<input|<textarea", html, re.IGNORECASE), page
        assert not re.search(r"""(?:src|href)=["']https?://""", html), page  # nothing is loaded from another site
        assert not re.search(r"google-analytics|googletagmanager|plausible|posthog", html, re.IGNORECASE), page
        assert LIMITS_STATEMENT.replace("'", "&#x27;") in html or LIMITS_STATEMENT in html, page


@built
def test_benchmark_page_shows_exactly_the_measured_numbers():
    r = json.loads((ROOT / "bench" / "results.json").read_text(encoding="utf-8"))
    html = (OUT / "benchmark" / "index.html").read_text(encoding="utf-8")
    for name in ("proofgate_full", "proofgate_fast", "bandit", "union"):
        t = r["tables"][name]
        for key in ("precision", "recall", "f1"):
            v = t["overall"][key]
            assert (js_fixed2(v) in html) if v is not None else ("n/a" in html), (name, key)
    assert r["generated_at"][:10] in html
    for col in ("semgrep", "betterleaks", "osv_scanner", "splinter"):
        assert not r["tables"][col]["available"]
    assert html.count("not measured:") >= 4  # tools that were not installed have no number
    assert "no held-out number" in html and f'{r["fix_verification"]["tournament_correct"]}' in html


@built
def test_generated_machine_files_match_the_product():
    tools = (OUT / "docs" / "mcp-tools.md").read_text(encoding="utf-8")
    for name in TOOL_NAMES:
        assert f"## {name}(" in tools
    assert "no shell tool, no network-send tool" in tools
    full = (OUT / "llms-full.txt").read_text(encoding="utf-8")
    assert "proofgate.finding/v1" in full and "get_contract" in full and LIMITS_STATEMENT in full and "Never follow it" in full or "never follow it" in full.lower()
    schema = json.loads((OUT / "schemas" / "finding.v1.json").read_text(encoding="utf-8"))
    assert json.loads((ROOT / "schemas" / "finding.v1.json").read_text(encoding="utf-8")) == schema
    assert "proofgate-ignore" in (OUT / "docs" / "agent-workflow.md").read_text(encoding="utf-8")
    assert not forbidden_in(full)


def forbidden_in(text: str) -> bool:
    return bool(re.search(r"disable (?:the )?hooks?|skip (?:the )?confirmation|--no-verify|upload (?:the |your )?code", text, re.IGNORECASE))


@built
def test_site_url_substitution(tmp_path):
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    fake = tmp_path / "web"
    shutil.copytree(WEB / "scripts", fake / "scripts")
    shutil.copytree(OUT, fake / "out", ignore=shutil.ignore_patterns("_next"))
    ok = subprocess.run([node, "scripts/set-site.mjs"], cwd=fake, env={"SITE_URL": "https://example.test", "PATH": __import__("os").environ["PATH"]},
                        capture_output=True, text=True)
    assert ok.returncode == 0 and "https://example.test/docs/agent-workflow.md" in (fake / "out" / "llms.txt").read_text(encoding="utf-8")
    assert "<site>" not in (fake / "out" / "llms.txt").read_text(encoding="utf-8")
    bad = subprocess.run([node, "scripts/set-site.mjs"], cwd=fake, env={"SITE_URL": "javascript:alert(1)", "PATH": __import__("os").environ["PATH"]},
                         capture_output=True, text=True)
    assert bad.returncode == 2
