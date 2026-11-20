"""Layers 6 (config) and 9 (browser bundle). Secrets are built at run time; nothing key-shaped is committed."""
import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from proofgate.layers import l6_config, l9_bundle
from proofgate.orchestrator import run_scan
from proofgate.runner import ToolResult

from conftest import fake_secrets
from corpus_harness import ROOT

DEMO = ROOT / "demo-apps" / "nextjs-supabase"
FIX = Path(__file__).parent / "fixtures" / "tool_outputs"
SERVICE = fake_secrets()["jwt"]  # role claim = service_role


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


ANON = "eyJ" + _b64({"alg": "HS256"})[3:] + "." + _b64({"role": "anon", "iss": "supabase"}) + "." + "c2lnbmF0dXJlMTIzNDU2"


def fake_build(root: Path, *, key: str | None, maps: bool = True) -> Path:
    chunks = root / ".next" / "static" / "chunks"
    chunks.mkdir(parents=True)
    js = f'(self.webpackChunk=[]).push([[1],{{1:function(){{return createClient("https://x.test","{key}")}}}}]);' if key else "console.log(1);"
    if maps:
        js += "\n//# sourceMapping" + "URL=app.js.map"
        (chunks / "app.js.map").write_text('{"version":3,"sources":["../../app/page.tsx"]}', encoding="utf-8")
    (chunks / "app.js").write_text(js, encoding="utf-8")
    return chunks / "app.js"


# ----------------------------------------------------------------------------------- layer 9
async def test_service_role_in_the_bundle_is_critical_and_source_maps_are_flagged(tmp_path):
    fake_build(tmp_path, key=SERVICE)
    res = await l9_bundle.run(tmp_path)
    crit = [f for f in res.findings if f.rule == "supabase-service-role-key"]
    assert len(crit) == 1 and crit[0].severity == "critical" and crit[0].category == "bundle" and crit[0].layer == 9
    assert crit[0].location.file == ".next/static/chunks/app.js" and SERVICE not in crit[0].model_dump_json()
    maps = [f for f in res.findings if f.rule == "source-maps-published"]
    assert len(maps) == 1 and "app.js.map" in maps[0].location.file


async def test_the_anon_key_in_the_bundle_is_not_a_finding(tmp_path):
    fake_build(tmp_path, key=ANON, maps=False)
    assert (await l9_bundle.run(tmp_path)).findings == []


async def test_a_clean_bundle_gives_zero_findings(tmp_path):
    fake_build(tmp_path, key=None, maps=False)
    assert (await l9_bundle.run(tmp_path)).findings == []


async def test_no_build_folder_is_skipped_quietly_and_said_aloud_with_full(tmp_path):
    assert (await l9_bundle.run(tmp_path)).notes == []
    res = await l9_bundle.run(tmp_path, full=True)
    assert res.findings == [] and any("no build output" in n for n in res.notes)


async def test_a_dangling_source_map_comment_is_flagged(tmp_path):
    js = fake_build(tmp_path, key=None, maps=True)
    (js.parent / "app.js.map").unlink()
    res = await l9_bundle.run(tmp_path)
    assert [f.rule for f in res.findings] == ["source-maps-published"] and res.findings[0].location.file.endswith("app.js")


async def test_server_side_next_output_is_not_scanned(tmp_path):
    server = tmp_path / ".next" / "server"
    server.mkdir(parents=True)
    (server / "page.js").write_text(f'const k = "{SERVICE}"', encoding="utf-8")
    assert (await l9_bundle.run(tmp_path)).findings == []  # only what browsers download counts


async def test_layer1_and_layer9_hits_on_one_secret_merge_into_one_finding(tmp_path):
    fake_build(tmp_path, key=SERVICE, maps=False)
    out = await run_scan(tmp_path, layers=[1, 9], offline=True)
    hits = [f for f in out.report.findings if f.rule == "supabase-service-role-key"]
    assert len(hits) == 1 and hits[0].confirmed_by == 2
    assert {"proofgate-bundle", "proofgate-jwt"} <= set(hits[0].sources)


# ----------------------------------------------------------------------------------- layer 6
def project(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


async def run6(path: Path):
    async def no_tool(name, args, **kw):
        return ToolResult(name, "skipped", reason="not installed here")

    return await l6_config.run(path, runner=no_tool)


async def test_committed_env_file_is_flagged_but_example_and_ignored_files_are_not(tmp_path):
    p = project(tmp_path, {".env": "API_TOKEN=abc123\n", ".env.example": "API_TOKEN=\n", ".env.local": "X=1\n", ".gitignore": ".env.local\n"})
    found = [f for f in (await run6(p)).findings if f.rule == "env-file-committed"]
    assert [f.location.file for f in found] == [".env"] and found[0].severity == "high"


async def test_env_file_ignored_by_git_is_not_flagged(tmp_path):
    p = project(tmp_path, {".env": "A=1\n", ".gitignore": ".env\n"})
    subprocess.run(["git", "init", "-q"], cwd=p, check=True)
    assert [f for f in (await run6(p)).findings if f.rule == "env-file-committed"] == []


async def test_next_public_secret_names_are_flagged_in_env_and_code_not_in_comments(tmp_path):
    p = project(tmp_path, {
        ".env.example": "NEXT_PUBLIC_API_URL=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n# NEXT_PUBLIC_OLD_SECRET=\n",
        "lib/a.ts": "// uses NEXT_PUBLIC_HIDDEN_SECRET once\nconst k = process.env.NEXT_PUBLIC_STRIPE_PRIVATE_KEY;\n"})
    found = {(f.location.file, f.title.split(" is ")[0]): f.severity for f in (await run6(p)).findings if f.rule == "next-public-secret-name"}
    assert found == {(".env.example", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"): "critical", ("lib/a.ts", "NEXT_PUBLIC_STRIPE_PRIVATE_KEY"): "high"}


@pytest.mark.parametrize("src,flagged", [
    ("app.use(cors({ origin: '*', credentials: true }))\n", True),
    ("CORS(app, origins='*', supports_credentials=True)\n", True),
    ("headers: [{key: 'Access-Control-Allow-Origin', value: '*'}, {key: 'Access-Control-Allow-Credentials', value: 'true'}]\n", False),
    ("app.use(cors({ origin: '*' }))\n", False),
    ("app.use(cors({ origin: 'https://app.example.com', credentials: true }))\n", False),
])
async def test_cors_wildcard_with_credentials(tmp_path, src, flagged):
    p = project(tmp_path, {"server.js": src})
    assert bool([f for f in (await run6(p)).findings if f.rule == "cors-wildcard-with-credentials"]) is flagged


async def test_next_production_source_maps(tmp_path):
    p = project(tmp_path, {"next.config.mjs": "export default {\n  productionBrowserSourceMaps: true,\n};\n"})
    found = [f for f in (await run6(p)).findings if f.rule == "next-production-source-maps"]
    assert len(found) == 1 and found[0].location.line == 2
    off = project(tmp_path / "off", {"next.config.mjs": "export default { productionBrowserSourceMaps: false };\n"})
    assert (await run6(off)).findings == []


async def test_demo_nextjs_app_layer6_flags_the_public_service_role_name_and_the_source_maps_setting():
    rules = {(f.rule, f.title.split(" is ")[0]) for f in (await run6(DEMO)).findings}
    assert ("next-public-secret-name", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY") in rules
    assert any(r == "next-production-source-maps" for r, _ in rules)


async def test_a_clean_fixture_gives_zero_findings_for_both_layers(tmp_path):
    p = project(tmp_path, {"app.py": "print('hi')\n", "next.config.mjs": "export default {};\n", ".env.example": "KEY=\n"})
    fake_build(p, key=None, maps=False)
    out = await run_scan(p, layers=[6, 9], offline=True)
    assert out.report.findings == [] and out.report.unique_count == 0


# ----------------------------------------------------------------------------------- Checkov adapter (recorded sample output)
def test_checkov_sarif_is_parsed(tmp_path):
    """The fixture is a REAL `checkov 3.4.6 -o sarif` run on a Dockerfile and an S3 bucket (recorded on 2026-11-21)."""
    found = l6_config.parse_checkov_sarif((FIX / "checkov_sample.sarif").read_text(encoding="utf-8"), tmp_path)
    got = {(f.rule, f.location.file, f.location.line) for f in found}
    assert ("checkov:CKV_DOCKER_2", "Dockerfile", 1) in got and ("checkov:CKV_AWS_20", "infra/main.tf", 1) in got and len(found) == 10
    assert all(f.sources == ["checkov"] and f.category == "config" and f.severity == "high" for f in found)  # Checkov reports every failed check as level "error"


async def test_checkov_runs_through_the_runner_and_a_missing_checkov_is_recorded(tmp_path):
    sample = (FIX / "checkov_sample.sarif").read_text(encoding="utf-8")

    async def fake(name, args, **kw):
        assert name == "checkov" and "sarif" in args
        out_dir = Path(args[args.index("--output-file-path") + 1])
        (out_dir / "results_sarif.sarif").write_text(sample, encoding="utf-8")  # what the real tool does: it writes a file, stdout is text
        return ToolResult(name, "ok", 1, "Passed checks: 3, Failed checks: 10", "", 0.1, sha256="0" * 64)

    res = await l6_config.run(tmp_path, runner=fake)
    assert {"checkov:CKV_DOCKER_2", "checkov:CKV_AWS_20"} <= {f.rule for f in res.findings} and len(res.findings) == 10
    missing = await run6(tmp_path)
    assert missing.findings == [] and any("checkov: skipped" in n for n in missing.notes)


async def test_a_broken_checkov_report_is_a_note_not_a_crash(tmp_path):
    async def fake(name, args, **kw):
        (Path(args[args.index("--output-file-path") + 1]) / "results_sarif.sarif").write_text("not json", encoding="utf-8")
        return ToolResult(name, "ok", 0, "", "", 0.1, sha256="0" * 64)

    res = await l6_config.run(tmp_path, runner=fake)
    assert res.findings == [] and any("could not parse" in n for n in res.notes)


async def test_failed_checks_without_a_report_file_are_a_note(tmp_path):
    async def fake(name, args, **kw):
        return ToolResult(name, "ok", 1, "Failed checks: 3", "", 0.1, sha256="0" * 64)

    res = await l6_config.run(tmp_path, runner=fake)
    assert res.findings == [] and any("wrote no SARIF file" in n for n in res.notes)
