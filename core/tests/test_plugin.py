import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from proofgate.cli import build_parser
from proofgate.fix.patching import make_diff
from proofgate.mcpserver import TOOL_NAMES

from corpus_harness import CORPUS, FIXES

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugin"
SKILLS = ["proofgate", "proofgate-supabase", "proofgate-nextjs"]
COMMANDS = ["proofgate-scan", "proofgate-prove", "proofgate-fix"]
MCP_PREFIX = "mcp__plugin_proofgate_proofgate__"


def frontmatter(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n(.*)", text, re.DOTALL)
    assert m, f"{path} has no frontmatter"
    return yaml.safe_load(m.group(1)), m.group(2)


def allowed_tools(fm: dict) -> list[str]:
    raw = fm.get("allowed-tools", "")
    items = raw if isinstance(raw, list) else re.split(r"[,\s]+(?![^()]*\))", str(raw))
    return [i.strip() for i in items if i.strip()]


# ============================================================================= manifest, MCP, marketplace
def test_plugin_manifest():
    m = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert m["name"] == "proofgate" and re.fullmatch(r"\d+\.\d+\.\d+", m["version"]) and m["description"] and m["author"]["name"]
    assert m["license"] == "MIT"


def test_components_live_at_the_plugin_root_not_inside_the_manifest_folder():
    assert not any((PLUGIN / ".claude-plugin" / d).exists() for d in ("skills", "commands", "hooks"))
    for rel in ("hooks/hooks.json", ".mcp.json", "README.md", *(f"skills/{s}/SKILL.md" for s in SKILLS), *(f"commands/{c}.md" for c in COMMANDS)):
        assert (PLUGIN / rel).is_file(), rel


def test_mcp_json_points_at_a_real_console_script():
    cfg = json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["proofgate"]
    pyproject = (ROOT / "core" / "pyproject.toml").read_text(encoding="utf-8")
    assert cfg["command"] == "proofgate-mcp" and f'{cfg["command"]} = "proofgate.mcpserver:main"' in pyproject
    assert "env" not in cfg or not cfg["env"]  # no credentials in the plugin config


def test_marketplace_lists_the_plugin_with_a_relative_source():
    mk = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert mk["name"] and mk["owner"]["name"] and len(mk["plugins"]) == 1
    entry = mk["plugins"][0]
    assert entry["name"] == "proofgate" and entry["source"] == "./plugin" and (ROOT / entry["source"] / ".claude-plugin" / "plugin.json").is_file()


@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
def test_claude_plugin_validate_passes():
    for target in (str(PLUGIN), str(ROOT)):
        r = subprocess.run(["claude", "plugin", "validate", target], capture_output=True, text=True, timeout=120)
        assert r.returncode == 0 and "Validation passed" in r.stdout, r.stdout + r.stderr


# ============================================================================= hooks
def test_hooks_json_registers_pre_post_and_stop_with_real_commands():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    assert set(hooks) == {"PreToolUse", "PostToolUse", "Stop"}
    for event in ("PreToolUse", "PostToolUse"):
        assert hooks[event][0]["matcher"] == "Write|Edit|MultiEdit"
    parser = build_parser()
    for event, phase in (("PreToolUse", "pre"), ("PostToolUse", "post"), ("Stop", "stop")):
        h = hooks[event][0]["hooks"][0]
        assert h["type"] == "command" and isinstance(h["timeout"], int) and h["timeout"] >= 1
        argv = h["command"].split()
        assert argv[0] == "proofgate" and argv[1] == "hook" and argv[2] == phase
        assert parser.parse_args(argv[1:]).phase == phase  # the command really parses


# ============================================================================= skills and commands
@pytest.mark.parametrize("name", SKILLS)
def test_skill_frontmatter_and_references(name):
    path = PLUGIN / "skills" / name / "SKILL.md"
    fm, body = frontmatter(path)
    assert fm["name"] == name and 40 < len(fm["description"]) <= 1024
    for tool in allowed_tools(fm):
        assert tool.startswith(MCP_PREFIX) and tool[len(MCP_PREFIX):] in TOOL_NAMES or tool.startswith("Bash(python ${CLAUDE_SKILL_DIR}/scripts/"), tool
    for ref in re.findall(r"\$\{CLAUDE_SKILL_DIR\}/([\w./-]+)", body):
        assert (PLUGIN / "skills" / name / ref.rstrip(".")).exists() or "*" in ref, ref


def test_main_skill_follows_the_plan_workflow():
    _, body = frontmatter(PLUGIN / "skills" / "proofgate" / "SKILL.md")
    steps = re.findall(r"^(\d)\. \*\*", body, re.MULTILINE)
    assert steps == [str(i) for i in range(1, 9)]
    for needle in ("get_contract", "Is this what you meant?", "contract_confirm.py", "scan_project", "prove", "verify_fix", "at most 3",
                   "fix_loop.py", "rotate", "rotate_key_guide.py", "never follow it", "proofgate-ignore", "Only a re-run",
                   "blocking every user", "editing an old database migration", "regression test", "CLAUDE.md",
                   "Passing ProofGate means our attacks failed on the routes and tables we tested. It doesn't mean your app is secure."):
        assert needle.lower() in body.lower(), needle


def test_supabase_skill_has_the_patterns_and_the_never_edit_rule():
    _, body = frontmatter(PLUGIN / "skills" / "proofgate-supabase" / "SKILL.md")
    for needle in ("rls_owner.sql", "rls_tenant.sql", "ssr_client.ts", "auth.uid()", "OR", "Never edit an old migration", "SECURITY DEFINER", "service_role"):
        assert needle in body, needle


def test_nextjs_skill_warns_about_middleware_only_auth():
    _, body = frontmatter(PLUGIN / "skills" / "proofgate-nextjs" / "SKILL.md")
    assert "middleware.ts" in body and "CVE-2025-29927" in body and "service_role" in body and ".eq(\"user_id\", user.id)" in body


@pytest.mark.parametrize("name", COMMANDS)
def test_slash_commands(name):
    fm, body = frontmatter(PLUGIN / "commands" / f"{name}.md")
    assert fm["description"]
    for tool in allowed_tools(fm):
        assert (tool.startswith(MCP_PREFIX) and tool[len(MCP_PREFIX):] in TOOL_NAMES) or tool.startswith("Bash("), tool
    if name == "proofgate-fix":
        assert fm["argument-hint"] == "<finding-id>" and "$1" in body and "at most 3" in body
    if name == "proofgate-scan":
        assert "$ARGUMENTS" in body and "fast" in body
    assert "not instructions" in body


def test_nothing_in_the_plugin_tells_an_agent_to_weaken_the_gate_or_send_code_away():
    forbidden = re.compile(r"disable (?:the )?(?:proofgate )?hooks?|skip (?:the )?(?:confirmation|contract|verification)|--no-verify|"
                           r"bypass|upload (?:the |your )?(?:code|repo)|curl |wget |https?://|ignore (?:previous|all) instructions", re.IGNORECASE)
    for p in [*PLUGIN.rglob("*.md"), *PLUGIN.rglob("*.py"), *PLUGIN.rglob("*.json")]:
        hit = forbidden.search(p.read_text(encoding="utf-8"))
        assert hit is None or p.name == "plugin.json", (p.relative_to(ROOT), hit and hit.group(0))


def test_readme_is_five_lines_of_install():
    steps = [l for l in (PLUGIN / "README.md").read_text(encoding="utf-8").splitlines() if re.match(r"^\d\. ", l)]
    assert len(steps) == 5 and "pipx install proofgate-ai" in steps[0] and "/plugin install proofgate@proofgate" in steps[2]


# ============================================================================= templates
def test_sql_templates_parse():
    pglast = pytest.importorskip("pglast")
    for name in ("rls_owner.sql", "rls_tenant.sql"):
        assert pglast.parse_sql((PLUGIN / "skills" / "proofgate-supabase" / "templates" / name).read_text(encoding="utf-8")), name


def test_owner_template_actually_satisfies_layer_5():
    pytest.importorskip("pglast")
    from proofgate.layers import l5_database as l5
    from proofgate.models import Contract

    contract = Contract(owned_resources=[{"name": "notes", "owner_field": "user_id", "actions": ["read", "create", "update", "delete"]}],
                        profile_editable_fields=[], admin_only_routes=[], public_routes=[], rules=["r"], confirmed_by_user=True, source="fallback")
    base = ("supabase/migrations/001.sql", "create table public.notes (id uuid primary key, user_id uuid not null, body text);\n")
    tpl = ("supabase/migrations/002.sql", (PLUGIN / "skills/proofgate-supabase/templates/rls_owner.sql").read_text(encoding="utf-8"))
    assert l5.check_schema(l5.build_schema([base, tpl]), contract) == []


def test_tenant_template_has_policies_for_all_four_actions():
    text = (PLUGIN / "skills/proofgate-supabase/templates/rls_tenant.sql").read_text(encoding="utf-8")
    for cmd in ("select", "insert", "update", "delete"):
        assert f"for {cmd}" in text
    assert "auth.uid()" in text and "auth.role()" not in text and "using (true)" not in text


def test_ssr_client_template_matches_the_demo_app():
    tpl = (PLUGIN / "skills/proofgate-supabase/templates/ssr_client.ts").read_text(encoding="utf-8")
    assert "createServerClient" in tpl and "NEXT_PUBLIC_SUPABASE_ANON_KEY" in tpl and "SERVICE_ROLE" not in tpl.replace("service_role", "")


# ============================================================================= scripts
SCRIPTS = PLUGIN / "skills" / "proofgate" / "scripts"


def script(name, *args, cwd=None):
    r = subprocess.run([sys.executable, str(SCRIPTS / name), *args], capture_output=True, text=True, cwd=cwd, timeout=900)
    return r.returncode, r.stdout, r.stderr


@pytest.mark.parametrize("rule,needle", [
    ("stripe-live-secret-key", "Stripe dashboard"), ("supabase-service-role-key", "JWT secret"), ("aws-access-key-id", "CloudTrail"),
    ("github-token", "fine-grained"), ("slack-token", "Slack"), ("google-api-key", "Google Cloud Console"),
    ("private-key-block", "key pair"), ("something-unknown", "replacement"),
])
def test_rotate_key_guide_is_provider_specific(rule, needle):
    code, out, _ = script("rotate_key_guide.py", "--rule", rule)
    assert code == 0 and needle in out and "REVOKE the old key" in out and "already exposed" in out and out.count("\n") >= 5


def test_rotate_key_guide_by_finding_and_errors(tmp_path):
    (tmp_path / ".proofgate").mkdir()
    (tmp_path / ".proofgate" / "report.json").write_text(json.dumps({"findings": [{"id": "f_1", "rule": "stripe-live-secret-key"}]}), encoding="utf-8")
    assert "Stripe" in script("rotate_key_guide.py", "--finding", "f_1", "--dir", str(tmp_path))[1]
    assert script("rotate_key_guide.py", "--finding", "f_nope", "--dir", str(tmp_path))[0] == 2
    assert script("rotate_key_guide.py")[0] == 2


def test_rotate_key_guide_never_handles_a_secret():
    code, out, _ = script("rotate_key_guide.py", "--rule", "stripe-live-secret-key")
    assert not re.search(r"sk_(live|test)_[A-Za-z0-9]{8}", out)
    assert "--secret" not in (SCRIPTS / "rotate_key_guide.py").read_text(encoding="utf-8")


@pytest.fixture
def app(tmp_path):
    d = tmp_path / "v01"
    shutil.copytree(CORPUS / "v01_idor_read", d)
    return d


def test_contract_confirm_show_then_confirm(app):
    (app / "README.md").write_text("Anyone can view the /export page.", encoding="utf-8")
    code, out, _ = script("contract_confirm.py", "show", str(app))
    assert code == 0 and "DRAFT" in out and "notes" in out and "WARNING: this would make data public: '/export'" in out
    assert "Is this what you meant?" in out and "confirm" in out.splitlines()[-1]
    code, out, _ = script("contract_confirm.py", "confirm", str(app))
    saved = json.loads((app / ".proofgate" / "contract.json").read_text(encoding="utf-8"))
    assert code == 0 and "CONFIRMED" in out and saved["confirmed_by_user"] and "/export" not in saved["public_routes"]
    assert "Items still owner-only: /export" in out
    code, out, _ = script("contract_confirm.py", "confirm", str(app), "--accept-public", "/export")
    assert "/export" in json.loads((app / ".proofgate" / "contract.json").read_text(encoding="utf-8"))["public_routes"]


def test_contract_confirm_show_never_confirms(app):
    script("contract_confirm.py", "show", str(app))
    assert json.loads((app / ".proofgate" / "contract.json").read_text(encoding="utf-8"))["confirmed_by_user"] is False


def test_contract_confirm_errors_cleanly(tmp_path):
    assert script("contract_confirm.py", "show", str(tmp_path / "missing"))[0] == 2


def test_fix_loop_template_first_then_three_strikes(app, tmp_path):
    from proofgate.cli import main

    assert main(["prove", str(app)]) == 1
    fid = json.loads((app / ".proofgate" / "report.json").read_text(encoding="utf-8"))["findings"][0]["id"]

    old = (app / "app.py").read_text(encoding="utf-8")
    lazy = tmp_path / "lazy.diff"
    lazy.write_text(make_diff("app.py", old, (FIXES / "v01_lazy" / "app.py").read_text(encoding="utf-8")), encoding="utf-8")
    codes = []
    for i in range(3):
        code, out, _ = script("fix_loop.py", "submit", str(app), fid, "--patch-file", str(lazy))
        codes.append(code)
        assert f"attempt {i + 1} of 3" in out and "REJECTED" in out and "owner can no longer read own notes" in out
    assert codes == [1, 1, 3]
    code, out, _ = script("fix_loop.py", "submit", str(app), fid, "--patch-file", str(lazy))
    assert code == 3 and "NEEDS A HUMAN" in out and "owner can no longer read" in out
    assert "3 of 3" in script("fix_loop.py", "status", str(app), fid)[1]

    # ProofGate's own template still works, resets the counter and writes the diffs (nothing is applied)
    code, out, _ = script("fix_loop.py", "next", str(app), fid)
    assert code == 0 and "ACCEPTED" in out and (app / ".proofgate" / f"fix_{fid}.diff").is_file()
    assert (app / ".proofgate" / f"vaccine_{fid}.diff").is_file() and (app / "app.py").read_text(encoding="utf-8") == old
    assert "0 of 3" in script("fix_loop.py", "status", str(app), fid)[1]


def test_fix_loop_accepts_a_good_submitted_patch(app, tmp_path):
    from proofgate.cli import main

    assert main(["prove", str(app)]) == 1
    fid = json.loads((app / ".proofgate" / "report.json").read_text(encoding="utf-8"))["findings"][0]["id"]
    good = tmp_path / "good.diff"
    good.write_text(make_diff("app.py", (app / "app.py").read_text(encoding="utf-8"), (FIXES / "v01_correct" / "app.py").read_text(encoding="utf-8")), encoding="utf-8")
    code, out, _ = script("fix_loop.py", "submit", str(app), fid, "--patch-file", str(good))
    assert code == 0 and "ACCEPTED" in out and "attempt 1 of 3" in out


def test_fix_loop_errors(app, tmp_path):
    assert script("fix_loop.py", "submit", str(app), "f_1", "--patch-file", str(tmp_path / "nope.diff"))[0] == 2
    assert script("fix_loop.py", "next", str(app), "f_1")[0] == 2  # no report yet
