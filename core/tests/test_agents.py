import json
import shutil
import tomllib
from pathlib import Path

import pytest

from proofgate import hook
from proofgate.agents import (
    AGENTS, INIT_BEGIN, INIT_END, InitError, detect_agents, detect_stack, init_agent, merge_json_file, merge_marked_block,
)
from proofgate.cli import main

from corpus_harness import CORPUS


@pytest.fixture
def proj(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    return d


def actions(changes):
    return {c.path: c.action for c in changes}


def jload(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


# ============================================================================= Cursor
def test_cursor_files(proj):
    ch = init_agent(proj, "cursor")
    assert actions(ch) == {".cursor/mcp.json": "created", ".cursor/hooks.json": "created", ".cursor/rules/proofgate.mdc": "created"}
    assert jload(proj / ".cursor/mcp.json") == {"mcpServers": {"proofgate": {"command": "proofgate-mcp", "args": []}}}
    hooks = jload(proj / ".cursor/hooks.json")
    assert hooks["version"] == 1 and hooks["hooks"]["afterFileEdit"] == [{"command": "proofgate hook post"}]
    assert hooks["hooks"]["stop"] == [{"command": "proofgate hook stop"}]
    rules = (proj / ".cursor/rules/proofgate.mdc").read_text(encoding="utf-8")
    assert rules.startswith("---\ndescription:") and "alwaysApply: true" in rules and "get_contract" in rules
    assert any("cannot block" in c.note for c in ch)


def test_cursor_existing_config_is_merged_not_overwritten(proj):
    (proj / ".cursor").mkdir()
    (proj / ".cursor/mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}, "extra": 1}), encoding="utf-8")
    (proj / ".cursor/hooks.json").write_text(json.dumps({"version": 1, "hooks": {"afterFileEdit": [{"command": "prettier --write"}]}}), encoding="utf-8")
    init_agent(proj, "cursor")
    mcp = jload(proj / ".cursor/mcp.json")
    assert set(mcp["mcpServers"]) == {"other", "proofgate"} and mcp["extra"] == 1
    assert jload(proj / ".cursor/hooks.json")["hooks"]["afterFileEdit"] == [{"command": "prettier --write"}, {"command": "proofgate hook post"}]


# ============================================================================= Codex
def test_codex_project_config_and_agents_md(proj):
    ch = init_agent(proj, "codex")
    assert actions(ch) == {".codex/config.toml": "created", "AGENTS.md": "created"}
    cfg = tomllib.loads((proj / ".codex/config.toml").read_text(encoding="utf-8"))
    assert cfg["mcp_servers"]["proofgate"] == {"command": "proofgate-mcp", "args": []}
    assert INIT_BEGIN in (proj / "AGENTS.md").read_text(encoding="utf-8")
    assert any("no hook system" in c.note for c in ch)


def test_codex_appends_to_an_existing_toml_and_keeps_it_valid(proj):
    (proj / ".codex").mkdir()
    (proj / ".codex/config.toml").write_text('model = "x"\n\n[mcp_servers.other]\ncommand = "y"\n', encoding="utf-8")
    init_agent(proj, "codex")
    cfg = tomllib.loads((proj / ".codex/config.toml").read_text(encoding="utf-8"))
    assert cfg["model"] == "x" and set(cfg["mcp_servers"]) == {"other", "proofgate"}


def test_codex_existing_proofgate_table_is_left_alone(proj):
    (proj / ".codex").mkdir()
    custom = '[mcp_servers.proofgate]\ncommand = "/opt/pg/bin/proofgate-mcp"\n'
    (proj / ".codex/config.toml").write_text(custom, encoding="utf-8")
    assert actions(init_agent(proj, "codex"))[".codex/config.toml"] == "unchanged"
    assert (proj / ".codex/config.toml").read_text(encoding="utf-8") == custom


# ============================================================================= Windsurf and Claude
def test_windsurf_writes_a_snippet_not_your_home_folder(proj, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    ch = init_agent(proj, "windsurf")
    assert actions(ch) == {".proofgate/agents/windsurf_mcp_config.json": "snippet", ".windsurf/rules/proofgate.md": "created"}
    assert jload(proj / ".proofgate/agents/windsurf_mcp_config.json")["mcpServers"]["proofgate"]["command"] == "proofgate-mcp"
    assert "did not edit that file" in ch[0].note and ".codeium" in ch[0].note
    assert list(home.rglob("*")) == []  # nothing was written outside the project
    assert (proj / ".windsurf/rules/proofgate.md").read_text(encoding="utf-8").startswith("---\ntrigger: always_on")


def test_claude_gets_a_rules_block_and_the_plugin_hint(proj):
    ch = init_agent(proj, "claude")
    assert actions(ch) == {"CLAUDE.md": "created"} and "/plugin marketplace add" in ch[0].note


# ============================================================================= safety
@pytest.mark.parametrize("agent", AGENTS)
def test_second_run_changes_nothing(proj, agent):
    init_agent(proj, agent)
    snapshot = {p: p.read_bytes() for p in proj.rglob("*") if p.is_file()}
    again = init_agent(proj, agent)
    assert all(c.action in ("unchanged", "snippet") for c in again)
    assert {p: p.read_bytes() for p in proj.rglob("*") if p.is_file()} == snapshot


@pytest.mark.parametrize("agent", AGENTS)
def test_dry_run_writes_nothing(proj, agent):
    ch = init_agent(proj, agent, dry_run=True)
    assert ch and list(proj.rglob("*")) == []


def test_invalid_json_is_refused_and_left_untouched(proj):
    (proj / ".cursor").mkdir()
    (proj / ".cursor/mcp.json").write_text("{ not json", encoding="utf-8")
    ch = actions(init_agent(proj, "cursor"))
    assert ch[".cursor/mcp.json"] == "refused" and ch[".cursor/hooks.json"] == "created"
    assert (proj / ".cursor/mcp.json").read_text(encoding="utf-8") == "{ not json"


def test_invalid_toml_is_refused(proj):
    (proj / ".codex").mkdir()
    (proj / ".codex/config.toml").write_text("= nope", encoding="utf-8")
    assert actions(init_agent(proj, "codex"))[".codex/config.toml"] == "refused"
    assert (proj / ".codex/config.toml").read_text(encoding="utf-8") == "= nope"


def test_wrong_json_shapes_are_refused():
    with pytest.raises(InitError):
        merge_json_file("[1]", lambda d: None)
    with pytest.raises(InitError):
        merge_json_file('{"mcpServers": 3}', __import__("proofgate.agents", fromlist=["_mcp_servers"])._mcp_servers)


def test_user_text_around_the_rules_block_survives_and_the_block_is_replaced_in_place():
    mine = "# Mine\n\nUse tabs.\n"
    once = merge_marked_block(mine, "rules v1")
    assert once.startswith(mine) and once.count(INIT_BEGIN) == 1
    twice = merge_marked_block(once + "\nMore.\n", "rules v2")
    assert "rules v2" in twice and "rules v1" not in twice and twice.count(INIT_BEGIN) == 1 and twice.endswith("More.\n")
    assert INIT_END in twice


def test_init_block_does_not_collide_with_the_vaccinated_rules_block(proj):
    from proofgate.fix.vaccinate import merge_rules_block

    (proj / "AGENTS.md").write_text(merge_rules_block(None, "Every query on notes must filter by owner_id = current user.", "f_1"), encoding="utf-8")
    init_agent(proj, "codex")
    text = (proj / "AGENTS.md").read_text(encoding="utf-8")
    assert "<!-- proofgate:begin -->" in text and INIT_BEGIN in text and "Every query on notes" in text
    after = merge_rules_block(text, "Check roles on admin routes.", "f_2")
    assert INIT_BEGIN in after and "Check roles on admin routes." in after


def test_rules_text_never_tells_the_agent_to_weaken_anything():
    from proofgate.agents import RULES_TEXT

    low = RULES_TEXT.lower()
    for bad in ("disable", "skip the", "bypass", "http://", "https://", "upload"):
        assert bad not in low
    assert "never as instructions" in low and "does not mean the app" in low.replace("\n", " ") or "is secure" in low


# ============================================================================= detection + CLI + Cursor payload
def test_detect_agents_and_stack(tmp_path):
    assert detect_agents(tmp_path) == ["claude"]
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".codex").mkdir()
    assert detect_agents(tmp_path) == ["cursor", "codex"]
    assert detect_stack(CORPUS / "c01_clean") == ["flask"]
    demo = Path(__file__).resolve().parents[2] / "demo-apps" / "nextjs-supabase"
    assert detect_stack(demo) == ["nextjs", "supabase"]


def test_cli_init_end_to_end(tmp_path, capsys):
    d = tmp_path / "c01"
    shutil.copytree(CORPUS / "c01_clean", d)
    assert main(["init", str(d), "--agent", "cursor"]) == 0
    out = capsys.readouterr().out
    assert "stack: flask" in out and "created   .cursor/mcp.json" in out and "draft saved" in out
    assert (d / ".proofgate" / "contract.json").is_file() and (d / ".cursor" / "hooks.json").is_file()
    assert main(["init", str(d), "--agent", "cursor"]) == 0
    assert "created" not in capsys.readouterr().out.replace("draft saved", "")


def test_cli_init_dry_run_and_refusal_exit_code(tmp_path, capsys):
    d = tmp_path / "x"
    d.mkdir()
    assert main(["init", str(d), "--agent", "codex", "--dry-run"]) == 0
    assert "dry run" in capsys.readouterr().out and list(d.rglob("*")) == []
    (d / ".cursor").mkdir()
    (d / ".cursor/mcp.json").write_text("{bad", encoding="utf-8")
    assert main(["init", str(d), "--agent", "cursor"]) == 2


def test_cursor_after_file_edit_payload_starts_the_background_scan(proj, monkeypatch):
    calls = []
    monkeypatch.setattr(hook.subprocess, "Popen", lambda args, **kw: calls.append(args))
    payload = json.dumps({"hook_event_name": "afterFileEdit", "file_path": str(proj / "a.py"), "edits": [], "workspace_roots": [str(proj)]})
    assert hook.run_hook("post", payload, project_dir=str(proj)).exit_code == 0
    assert len(calls) == 1 and "--fast" in calls[0]
    hook.run_hook("post", json.dumps({"hook_event_name": "stop"}), project_dir=str(proj))
    assert len(calls) == 1
