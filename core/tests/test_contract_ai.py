import json
import shutil
from pathlib import Path

import pytest

from proofgate.ai import contract as C
from proofgate.ai.contract import (
    ContractProposal, ProposedResource, build_contract, confirm_contract, gather_context, keyword_proposal, merge,
)
from proofgate.ai.fallback import draft_contract
from proofgate.cli import main
from proofgate.models import Contract

from conftest import fake_secrets
from corpus_harness import CORPUS

BASE_APP = CORPUS / "c01_clean"


@pytest.fixture
def app(tmp_path):
    dst = tmp_path / "app"
    shutil.copytree(BASE_APP, dst)
    return dst


def proposal(**kw) -> ContractProposal:
    base = dict(owned_resources=[], profile_editable_fields=[], admin_only_routes=[], public_routes=[], public_reads=[], rules=[])
    return ContractProposal(**{**base, **kw})


def ctx_for(app):
    return gather_context(app)


# ----------------------------------------------------------------------------- context + prompt
def test_context_has_tables_columns_routes_and_prose(app):
    (app / "README.md").write_text("Users edit their display name.", encoding="utf-8")
    ctx = ctx_for(app)
    assert {"notes", "users"} <= set(ctx.tables) and "owner_id" in ctx.tables["notes"] and "display_name" in ctx.tables["users"]
    assert "GET /notes/<int:note_id>" in ctx.routes and "/admin/users" in ctx.route_paths and "display name" in ctx.prose


def test_next_routes_are_discovered_too():
    ctx = gather_context(Path(__file__).resolve().parents[2] / "demo-apps" / "nextjs-supabase")
    assert "GET /api/notes/[id]" in ctx.routes and "GET /api/search" in ctx.routes and "notes" in ctx.tables


# ----------------------------------------------------------------------------- offline: heuristic + keywords
async def test_offline_uses_the_heuristic_and_keywords(app, tmp_path):
    (app / "README.md").write_text("Users can edit their display name. Anyone can view the /export page.", encoding="utf-8")
    res = await build_contract(app)
    c = res.contract
    assert c.source == "fallback" and not c.confirmed_by_user
    assert [(r.name, r.owner_field) for r in c.owned_resources] == [("notes", "owner_id")]
    assert c.profile_editable_fields == ["display_name"] and c.admin_only_routes == ["/admin/*"]
    assert "/export" in c.needs_confirmation and "/export" not in c.public_routes  # never auto-public
    assert any("deterministic keyword fallback" in n for n in res.notes)
    assert any("NOT applied" in n for n in res.notes)


def test_keyword_rules_ignore_negated_sentences():
    ctx = C.Context(prose="Nobody can see the notes without logging in. The /export page is not public.",
                    tables={"notes": ["id", "owner_id"]}, routes=["GET /export"])
    p = keyword_proposal(ctx)
    assert p.public_reads == [] and p.public_routes == []


def test_keyword_rules_find_public_intent_for_tables_and_routes():
    ctx = C.Context(prose="Profiles are public: anyone can read profiles.", tables={"profiles": ["id", "bio"]}, routes=[])
    assert keyword_proposal(ctx).public_reads == ["profiles"]


# ----------------------------------------------------------------------------- the guarded merge
def test_valid_additions_are_accepted(app):
    ctx = ctx_for(app)
    base = draft_contract(app)
    p = proposal(
        owned_resources=[ProposedResource(name="users", owner_field="id", actions=["read", "bogus", "update"])],
        profile_editable_fields=["display_name", "not_a_column"], admin_only_routes=["/admin/*", "/nope/*"],
        rules=["  Only the owner may   edit\nprofile.  "])
    c = merge(base, p, ctx, source="fallback")
    assert c.source == "fallback" and not c.confirmed_by_user
    users = next(r for r in c.owned_resources if r.name == "users")
    assert users.owner_field == "id" and users.actions == ["read", "update"]
    assert c.profile_editable_fields == ["display_name"] and c.admin_only_routes == ["/admin/*"]
    assert "Only the owner may edit profile." in c.rules


def test_heuristic_wins_a_tie_and_invented_tables_and_columns_are_dropped(app):
    ctx, base = ctx_for(app), draft_contract(app)
    p = proposal(owned_resources=[
        ProposedResource(name="notes", owner_field="id", actions=["read"]),  # tie: heuristic says owner_id
        ProposedResource(name="secrets_vault", owner_field="owner_id", actions=["read"]),  # no such table
        ProposedResource(name="users", owner_field="no_such_column", actions=["read"]),  # no such column
    ])
    c = merge(base, p, ctx, source="fallback")
    assert [(r.name, r.owner_field) for r in c.owned_resources] == [("notes", "owner_id")]


def test_anything_public_is_held_for_confirmation_not_applied(app):
    ctx, base = ctx_for(app), draft_contract(app)
    p = proposal(public_routes=["/export", "/signup"], public_reads=["notes"],
                 rules=["Anyone can read all notes.", "Notes are public to logged-out visitors.", "Users own their notes."])
    c = merge(base, p, ctx, source="fallback")
    assert c.public_routes == ["/login", "/signup"]  # unchanged: only the heuristic's login/signup
    assert set(c.needs_confirmation) == {"/export", "notes", "Anyone can read all notes.", "Notes are public to logged-out visitors."}
    assert "Users own their notes." in c.rules and not any("Anyone" in r for r in c.rules)


def test_rule_limits(app):
    ctx, base = ctx_for(app), draft_contract(app)
    c = merge(base, proposal(rules=[f"Rule number {i} " + "x" * 400 for i in range(30)] + [""]), ctx, source="fallback")
    extra = [r for r in c.rules if r.startswith("Rule number")]
    assert len(extra) == C.MAX_RULES and all(len(r) <= C.MAX_RULE_LEN for r in extra)


def test_the_proposal_can_never_remove_or_loosen_what_the_heuristic_found(app):
    ctx, base = ctx_for(app), draft_contract(app)
    c = merge(base, proposal(), ctx, source="fallback")
    assert c.admin_only_routes == base.admin_only_routes and c.owned_resources == base.owned_resources
    assert c.public_routes == base.public_routes and c.rules[: len(base.rules)] == base.rules


# ----------------------------------------------------------------------------- the confirmation guard
def test_confirming_keeps_unaccepted_items_owner_only():
    c = Contract(owned_resources=[], profile_editable_fields=[], admin_only_routes=[], public_routes=["/login"], rules=[],
                 confirmed_by_user=False, source="fallback", needs_confirmation=["/export", "profiles", "Anyone may read x."])
    confirmed, unresolved = confirm_contract(c, [])
    assert confirmed.confirmed_by_user and confirmed.public_routes == ["/login"] and unresolved == c.needs_confirmation


def test_accepting_specific_items_applies_only_those():
    c = Contract(owned_resources=[], profile_editable_fields=[], admin_only_routes=[], public_routes=["/login"], rules=[],
                 confirmed_by_user=False, source="fallback", needs_confirmation=["/export", "profiles", "Anyone may read x.", "/other"])
    confirmed, unresolved = confirm_contract(c, ["/export", "profiles", "Anyone may read x.", "not-listed"])
    assert confirmed.public_routes == ["/login", "/export"] and confirmed.public_reads_confirmed == ["profiles"]
    assert unresolved == ["/other"] and "Anyone may read x." not in confirmed.rules


# ----------------------------------------------------------------------------- CLI
def run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_cli_builds_saves_and_reuses_the_contract(capsys, app, monkeypatch):
    (app / "README.md").write_text("Anyone can view the /export page.", encoding="utf-8")
    code, out, err = run(capsys, "contract", str(app))
    c = Contract.model_validate_json(out)
    assert code == 0 and c.needs_confirmation == ["/export"] and "keyword fallback" in err and "draft contract" in err
    saved = app / ".proofgate" / "contract.json"
    assert Contract.model_validate_json(saved.read_text(encoding="utf-8")) == c

    async def must_not_run(*a, **k):
        raise AssertionError("rebuilt a saved contract")

    monkeypatch.setattr(C, "build_contract", must_not_run)
    assert run(capsys, "contract", str(app))[0] == 0
    monkeypatch.undo()
    (app / "README.md").write_text("Nothing public here.", encoding="utf-8")
    code, out, _ = run(capsys, "contract", str(app), "--refresh")
    assert Contract.model_validate_json(out).needs_confirmation == []


def test_cli_confirm_leaves_public_items_out_unless_accepted(capsys, app):
    (app / "README.md").write_text("Anyone can view the /export page.", encoding="utf-8")
    code, out, err = run(capsys, "contract", str(app), "--confirm")
    c = Contract.model_validate_json(out)
    assert c.confirmed_by_user and "/export" not in c.public_routes and c.needs_confirmation == ["/export"]
    assert "still owner-only" in err and "--accept-public" in err
    code, out, _ = run(capsys, "contract", str(app), "--confirm", "--accept-public", "/export")
    c2 = Contract.model_validate_json(out)
    assert "/export" in c2.public_routes and c2.needs_confirmation == []


def test_cli_accept_public_needs_confirm(capsys, app):
    assert run(capsys, "contract", str(app), "--accept-public", "/x")[0] == 2


def test_the_probe_picks_up_the_saved_contract(capsys, app):
    from proofgate.probe import load_contract

    run(capsys, "contract", str(app), "--confirm")
    assert load_contract(app).confirmed_by_user
