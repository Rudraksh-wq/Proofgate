"""The Next.js + Supabase demo app: files, RLS variants, planted flaws. (No Docker/Supabase needed: the live run
against `supabase start` is pending real-tool verification.)"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from proofgate.inline import check_file
from proofgate.layers.l4_supply_chain import dependency_lines
from proofgate.pkgcache import PackageCache

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo-apps" / "nextjs-supabase"
VARIANTS = DEMO / "supabase" / "variants"
MIGRATIONS = DEMO / "supabase" / "migrations"
NODE = shutil.which("node")


def rules(rel: str) -> set[str]:
    res = check_file(DEMO / rel, project_root=DEMO, cache=PackageCache(Path("nope.json")))
    return {f.rule for f in res.findings}


# ----------------------------------------------------------------------------- SQL
SQL_FILES = sorted([*MIGRATIONS.glob("*.sql"), *VARIANTS.glob("*.sql")])


def test_expected_sql_files_exist():
    assert [p.name for p in SQL_FILES] == [
        "20240101000000_notes.sql", "20240101000100_run_sql.sql", "a_rls_off.sql", "b_auth_role.sql", "c_owner_only.sql"]


@pytest.mark.parametrize("path", SQL_FILES, ids=lambda p: p.name)
def test_sql_parses_with_the_postgres_parser(path):
    pglast = pytest.importorskip("pglast")
    assert pglast.parse_sql(path.read_text(encoding="utf-8"))  # raises on a syntax error


def stmts(name: str) -> list[str]:
    pglast = pytest.importorskip("pglast")
    return [type(s.stmt).__name__ for s in pglast.parse_sql((VARIANTS / name).read_text(encoding="utf-8"))]


def test_variant_a_turns_rls_off_and_adds_no_policy():
    text = (VARIANTS / "a_rls_off.sql").read_text(encoding="utf-8").lower()
    assert "disable row level security" in text and "create policy" not in text
    assert stmts("a_rls_off.sql") == ["AlterTableStmt"]


def test_variant_b_uses_the_role_not_the_owner():
    text = (VARIANTS / "b_auth_role.sql").read_text(encoding="utf-8")
    assert stmts("b_auth_role.sql").count("CreatePolicyStmt") == 4
    assert "auth.role() = 'authenticated'" in text and "auth.uid()" not in text and "user_id" not in text.split("--", 2)[-1].replace("whose", "")


def test_variant_c_compares_the_owner_for_all_four_actions():
    text = (VARIANTS / "c_owner_only.sql").read_text(encoding="utf-8")
    assert stmts("c_owner_only.sql").count("CreatePolicyStmt") == 4
    for action in ("select", "insert", "update", "delete"):
        assert re.search(rf"for {action}\b", text)
    assert text.count("auth.uid() = user_id") >= 5 and "auth.role()" not in text and "enable row level security" in text


def test_run_sql_function_is_the_planted_security_definer():
    text = (MIGRATIONS / "20240101000100_run_sql.sql").read_text(encoding="utf-8").lower()
    assert "security definer" in text and "execute format" in text and "planted flaw" in text


def test_base_migration_leaves_rls_to_the_variant():
    text = (MIGRATIONS / "20240101000000_notes.sql").read_text(encoding="utf-8").lower()
    assert "create table public.notes" in text and "user_id uuid not null references auth.users" in text
    assert "row level security" not in text.replace("-- row-level security", "")


# ----------------------------------------------------------------------------- variant switching (node script)
@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_set_variant_installs_the_chosen_file_and_the_target_is_git_ignored():
    target = MIGRATIONS / "20240201000000_rls_variant.sql"
    existed = target.exists()
    try:
        for letter, src in (("A", "a_rls_off.sql"), ("b", "b_auth_role.sql"), ("C", "c_owner_only.sql")):
            r = subprocess.run([NODE, "scripts/set-variant.mjs", letter], cwd=DEMO, capture_output=True, text=True)
            assert r.returncode == 0, r.stderr
            assert target.read_bytes() == (VARIANTS / src).read_bytes()
        git = shutil.which("git")
        if git:
            assert subprocess.run([git, "check-ignore", "-q", str(target)], cwd=ROOT).returncode == 0
    finally:
        if not existed:
            target.unlink(missing_ok=True)


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_unknown_variant_is_an_error():
    r = subprocess.run([NODE, "scripts/set-variant.mjs", "Z"], cwd=DEMO, capture_output=True, text=True)
    assert r.returncode == 2 and "use A, B or C" in r.stderr


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_reset_demo_without_the_supabase_cli_fails_cleanly(tmp_path):
    target = MIGRATIONS / "20240201000000_rls_variant.sql"
    existed = target.exists()
    env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "COMSPEC", "TEMP", "TMP")}
    env["PATH"] = str(tmp_path)  # a PATH that cannot contain a `supabase` binary
    try:
        r = subprocess.run([NODE, "scripts/reset-demo.mjs", "C"], cwd=DEMO, env=env, capture_output=True, text=True)
        assert r.returncode == 2 and "Install the Supabase CLI" in r.stderr
    finally:
        if not existed:
            target.unlink(missing_ok=True)


# ----------------------------------------------------------------------------- planted flaws are visible to ProofGate
def test_service_role_in_a_route_handler_is_flagged():
    assert "proofgate.next-route-service-role-client" in rules("app/api/notes/[id]/route.ts")


def test_string_built_sql_through_rpc_is_flagged():
    assert "proofgate.js-supabase-rpc-string-sql" in rules("app/api/search/route.ts")


def test_service_role_under_a_public_name_is_flagged():
    assert "proofgate.js-public-env-secret" in rules("lib/admin-client.ts")


@pytest.mark.parametrize("rel", ["lib/supabase/client.ts", "lib/supabase/server.ts", "app/layout.tsx", "app/page.tsx",
                                 "app/notes-client.tsx", "middleware.ts", "next.config.mjs"])
def test_the_other_files_have_no_inline_findings(rel):
    assert rules(rel) == set()


def test_notes_route_checks_login_but_not_ownership():
    src = (DEMO / "app" / "api" / "notes" / "[id]" / "route.ts").read_text(encoding="utf-8")
    assert "auth.getUser()" in src and "user.id" not in src and "SUPABASE_SERVICE_ROLE_KEY" in src


def test_search_route_has_no_auth_check_and_trusts_the_middleware():
    src = (DEMO / "app" / "api" / "search" / "route.ts").read_text(encoding="utf-8")
    mw = (DEMO / "middleware.ts").read_text(encoding="utf-8")
    assert "getUser" not in src and "getUser" in mw and '"/api/:path*"' in mw


def test_source_maps_are_planted_for_layer_9():
    assert "productionBrowserSourceMaps: true" in (DEMO / "next.config.mjs").read_text(encoding="utf-8")


def test_old_package_is_pinned_for_layer_3():
    pkg = json.loads((DEMO / "package.json").read_text(encoding="utf-8"))
    assert pkg["dependencies"]["lodash"] == "4.17.15"
    deps = {name for _, name, _ in dependency_lines((DEMO / "package.json").read_text(encoding="utf-8"), "package.json")}
    assert {"lodash", "next", "@supabase/ssr", "@supabase/supabase-js"} <= deps


def test_env_example_has_names_only():
    for line in (DEMO / ".env.example").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            assert name and value == "", line


def test_demo_never_points_at_a_hosted_project():
    for p in DEMO.rglob("*"):
        if p.is_file() and "node_modules" not in p.parts and ".next" not in p.parts and p.suffix in (".ts", ".tsx", ".mjs", ".toml", ".json", ".md", ".sql"):
            if p.name == "package-lock.json":
                continue
            assert ".supabase.co" not in p.read_text(encoding="utf-8", errors="replace"), p
