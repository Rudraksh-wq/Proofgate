"""Layer 5, static part: RLS checks over SQL migrations with the real Postgres parser. Splinter (live DB) is pending."""
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pglast")

from proofgate.layers import l5_database as l5  # noqa: E402
from proofgate.models import Contract, Finding  # noqa: E402

DEMO = Path(__file__).resolve().parents[2] / "demo-apps" / "nextjs-supabase"
VARIANTS = {"A": "a_rls_off.sql", "B": "b_auth_role.sql", "C": "c_owner_only.sql"}

CONTRACT = Contract(
    owned_resources=[{"name": "notes", "owner_field": "user_id", "actions": ["read", "update", "delete"]}],
    profile_editable_fields=[], admin_only_routes=[], public_routes=[], rules=["User B must never read or change User A's notes."],
    confirmed_by_user=True, source="fallback")
TABLE = "create table public.notes (id uuid primary key, user_id uuid not null, body text);\n"
ENABLE = "alter table public.notes enable row level security;\n"


def rules(sql: str, contract: Contract = CONTRACT, extra: list[tuple[str, str]] | None = None) -> dict[str, Finding]:
    files = [("supabase/migrations/001.sql", sql), *(extra or [])]
    found = l5.check_schema(l5.build_schema(files), contract)
    return {f.rule.removeprefix("proofgate.sql-"): f for f in found}


def demo_with_variant(tmp_path: Path, letter: str | None) -> Path:
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    if letter:
        shutil.copy(DEMO / "supabase" / "variants" / VARIANTS[letter], tmp_path / "supabase" / "migrations" / "20240201000000_rls_variant.sql")
    return tmp_path


# ----------------------------------------------------------------------------- the three demo variants (done-when, static)
async def test_variant_a_rls_off_is_critical_on_the_owned_table(tmp_path):
    res = await l5.run(demo_with_variant(tmp_path, "A"))
    f = next(f for f in res.findings if f.rule.endswith("rls-disabled"))
    assert (f.severity, f.category, f.layer, f.cwe, f.fix_tier) == ("critical", "database", 5, "CWE-862", "B")
    assert f.location.file.endswith("20240101000000_notes.sql") and f.location.line == 3  # the create table line


async def test_variant_b_role_instead_of_ownership(tmp_path):
    res = await l5.run(demo_with_variant(tmp_path, "B"))
    f = next(f for f in res.findings if f.rule.endswith("policy-role-without-uid"))
    assert f.severity == "high" and "4 policies" in f.title and "auth.role()" in f.plain_words
    assert not any(x.rule.endswith("rls-disabled") for x in res.findings)


async def test_variant_c_has_no_rls_finding(tmp_path):
    res = await l5.run(demo_with_variant(tmp_path, "C"))
    assert [f.rule for f in res.findings] == ["proofgate.sql-function-security-definer"]  # only the planted run_sql()


async def test_without_an_installed_variant_the_table_is_reported_as_unprotected(tmp_path):
    res = await l5.run(demo_with_variant(tmp_path, None))
    assert any(f.rule.endswith("rls-disabled") for f in res.findings)


async def test_run_records_the_skipped_splinter_and_the_draft_contract(tmp_path):
    res = await l5.run(demo_with_variant(tmp_path, "C"))
    assert {t.name: t.status for t in res.tools} == {"proofgate-sql": "ok", "splinter": "skipped"}
    assert any("splinter: skipped" in n for n in res.notes) and any("DRAFT contract" in n for n in res.notes)


async def test_project_without_sql_is_quiet(tmp_path):
    res = await l5.run(tmp_path)
    assert res.findings == [] and res.notes == [] and res.tools == []


# ----------------------------------------------------------------------------- contract-aware rules
def test_select_using_true_on_an_owned_table_is_flagged():
    f = rules(TABLE + ENABLE + "create policy p on public.notes for select using (true);")
    assert f["policy-using-true"].severity == "high" and "Splinter does not flag" in f["policy-using-true"].plain_words


def test_using_true_on_a_table_the_contract_does_not_own_is_not_flagged():
    sql = "create table public.posts (id int, user_id uuid);\nalter table public.posts enable row level security;\ncreate policy p on public.posts for select using (true);"
    assert rules(sql) == {}  # public blog posts can be readable by everyone: unknown means no claim


def test_permissive_policies_are_ored_into_a_hole():
    sql = (TABLE + ENABLE + "create policy mine on public.notes for select using (auth.uid() = user_id);\n"
           "create policy anyone on public.notes for select using (true);")
    f = rules(sql)
    assert "policy-permissive-or-hole" in f and "policy-using-true" not in f
    assert "OR" in f["policy-permissive-or-hole"].plain_words and f["policy-permissive-or-hole"].location.line == 4


def test_for_all_policy_that_is_weak_cancels_every_action():
    sql = (TABLE + ENABLE + "create policy mine on public.notes for update using (auth.uid() = user_id);\n"
           "create policy wide on public.notes for all using (auth.role() = 'authenticated');")
    assert "policy-permissive-or-hole" in rules(sql)


def test_uid_is_null_fails_open_on_any_table():
    sql = ("create table public.pages (id int);\nalter table public.pages enable row level security;\n"
           "create policy p on public.pages for select to anon using (auth.uid() is null);")
    f = rules(sql)
    assert f["policy-uid-is-null"].severity == "high" and f["policy-uid-is-null"].cwe == "CWE-285"


def test_role_check_that_also_checks_uid_is_fine():
    sql = TABLE + ENABLE + "create policy p on public.notes for select using (auth.role() = 'authenticated' and auth.uid() = user_id);"
    assert rules(sql) == {}


def test_subselect_form_of_uid_is_recognised_as_strong():
    sql = TABLE + ENABLE + "create policy p on public.notes for select using ((select auth.uid()) = user_id);"
    assert rules(sql) == {}


def test_wrong_owner_column_is_a_low_confidence_medium():
    sql = TABLE + ENABLE + "create policy p on public.notes for select using (auth.uid() = id);"
    f = rules(sql)["policy-wrong-owner-column"]
    assert (f.severity, f.confidence) == ("medium", "low") and "user_id" in f.plain_words


def test_service_role_only_policies_are_ignored():
    sql = TABLE + ENABLE + "create policy sr on public.notes for all to service_role using (true);"
    assert rules(sql) == {}


def test_rls_enabled_without_any_policy_is_a_low_note():
    f = rules(TABLE + ENABLE)["rls-enabled-no-policy"]
    assert f.severity == "low" and "locked" in f.plain_words


def test_table_not_in_the_contract_without_rls_is_high_not_critical():
    f = rules("create table public.posts (id int);")["rls-disabled"]
    assert f.severity == "high" and "contract" not in f.plain_words


# ----------------------------------------------------------------------------- migration replay semantics
def test_later_migrations_override_earlier_ones():
    sql_off = TABLE
    on = ("supabase/migrations/002.sql", ENABLE + "create policy p on public.notes for all using (auth.uid() = user_id);")
    assert rules(sql_off, extra=[on]) == {}  # RLS enabled later: no finding
    off_again = ("supabase/migrations/003.sql", "alter table public.notes disable row level security;")
    assert "rls-disabled" in rules(sql_off, extra=[on, off_again])


def test_dropped_policy_and_dropped_table():
    weak = TABLE + ENABLE + "create policy p on public.notes for select using (true);"
    assert "policy-using-true" in rules(weak)
    assert "policy-using-true" not in rules(weak, extra=[("supabase/migrations/002.sql", "drop policy p on public.notes;")])
    assert rules(weak, extra=[("supabase/migrations/002.sql", "drop table public.notes;")]) == {}


def test_force_row_security_does_not_count_as_enabling():
    assert "rls-disabled" in rules(TABLE + "alter table public.notes force row level security;")


def test_schema_qualified_names_and_other_schemas():
    sql = "create table private.secrets (id int);\ncreate table notes (id int, user_id uuid);"
    assert list(rules(sql)) == ["rls-disabled"]  # only the unqualified (public) table counts


# ----------------------------------------------------------------------------- functions and views
def test_security_definer_function_in_public():
    sql = "create function public.f() returns int language sql security definer as $$ select 1 $$;"
    f = rules(sql)["function-security-definer"]
    assert f.severity == "high" and "anon" in f.plain_words


def test_revoking_execute_lowers_a_definer_function_to_medium():
    sql = ("create function public.f(text) returns int language sql security definer as $$ select 1 $$;\n"
           "revoke execute on function public.f(text) from public, anon;")
    assert rules(sql)["function-security-definer"].severity == "medium"


def test_security_invoker_function_and_private_schema_definer_are_fine():
    assert rules("create function public.f() returns int language sql as $$ select 1 $$;") == {}
    assert rules("create function private.f() returns int language sql security definer as $$ select 1 $$;") == {}


def test_view_without_security_invoker():
    assert "view-bypasses-rls" in rules("create view public.v as select 1;")
    assert rules("create view public.v with (security_invoker = true) as select 1;") == {}


# ----------------------------------------------------------------------------- robustness
async def test_syntax_error_in_one_migration_is_a_note_not_a_crash(tmp_path):
    m = tmp_path / "supabase" / "migrations"
    m.mkdir(parents=True)
    (m / "001.sql").write_text(TABLE + "alter table public.notes enable row level security;\n", encoding="utf-8")
    (m / "002.sql").write_text("this is not sql;\n", encoding="utf-8")
    res = await l5.run(tmp_path, contract=CONTRACT)
    assert any("syntax error" in n and "002.sql" in n for n in res.notes)
    assert any(f.rule.endswith("rls-enabled-no-policy") for f in res.findings)  # the good file still counted


def test_findings_are_valid_stable_and_line_independent():
    a = rules("-- c\n" + TABLE)["rls-disabled"]
    b = rules("\n\n\n-- c\n" + TABLE)["rls-disabled"]
    Finding.model_validate(a.to_json_dict())
    assert a.fingerprint == b.fingerprint and a.location.line != b.location.line


def test_draft_contract_reads_owned_tables_from_sql():
    from proofgate.ai.fallback import draft_contract

    c = draft_contract(DEMO)
    assert [(r.name, r.owner_field) for r in c.owned_resources] == [("notes", "user_id")]
