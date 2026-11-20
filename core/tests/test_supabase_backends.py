"""Supabase backends, the project-ref guard, the psycopg runner and Splinter. No network, no Docker, no real database."""
import contextlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from proofgate import supabase_db as db
from proofgate import supabase_target as st
from proofgate.cli import main
from proofgate.layers import l5_database as l5

from conftest import fake_secrets
from corpus_harness import ROOT

DEMO = ROOT / "demo-apps" / "nextjs-supabase"
REF = "abcdefghijklmnopqrst"  # fake project refs: nothing here is a real project
OTHER = "zzzzzzzzzzzzzzzzzzzz"
URL = f"https://{REF}.supabase.co"
DBURL = f"postgresql://postgres.{REF}:pw@aws-0-eu.pooler.supabase.com:5432/postgres"
KEY = fake_secrets()["jwt"]  # a fake service_role JWT, built at run time


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in st.ENV_NAMES + ("PROOFGATE_I_OWN_THIS", "PROOFGATE_SPLINTER_SQL"):
        monkeypatch.delenv(k, raising=False)


def cfg(**kw) -> st.SupabaseConfig:
    base = dict(url=URL, anon_key="anon", service_role_key=KEY, db_url=DBURL, allowed_refs=(REF,), backend="auto")
    base.update(kw)
    return st.SupabaseConfig(**base)


# ------------------------------------------------------------------------------------------- the guard
def test_a_ref_that_is_not_allow_listed_is_refused():
    with pytest.raises(st.SupabaseTargetRefused, match="not in PROOFGATE_ALLOWED_PROJECT_REFS"):
        st.guard_supabase(URL, allowed_refs=(OTHER,), i_own_this=True)


def test_an_empty_allow_list_refuses_everything_hosted():
    with pytest.raises(st.SupabaseTargetRefused, match=r"\(empty\)"):
        st.guard_supabase(URL, allowed_refs=(), i_own_this=True)


def test_a_listed_ref_is_still_refused_without_i_own_this():
    with pytest.raises(st.SupabaseTargetRefused, match="--i-own-this"):
        st.guard_supabase(URL, allowed_refs=(REF,))


def test_listed_ref_with_the_flag_or_the_test_env_var_is_allowed_and_logged():
    d = st.guard_supabase(URL, allowed_refs=(REF,), i_own_this=True)
    assert not d.local and d.ref == REF and REF in d.override_note
    assert st.guard_supabase(URL, allowed_refs=(REF,), i_own_this_env=True).ref == REF


@pytest.mark.parametrize("url", ["http://localhost:54321", "http://127.0.0.1:54321", "http://[::1]:54321", "http://api.localhost:54321"])
def test_localhost_needs_neither_the_allow_list_nor_the_flag(url):
    d = st.guard_supabase(url)
    assert d.local and d.override_note is None


@pytest.mark.parametrize("url", [
    "https://example.com", f"https://{REF}.supabase.co.evil.example", f"https://evil.example/{REF}.supabase.co",
    f"https://{REF}.supabase.co@evil.example", "https://supabase.co", "ftp://" + REF, ""])
def test_hosts_that_only_look_like_a_project_are_refused(url):
    with pytest.raises(st.SupabaseTargetRefused):
        st.guard_supabase(url, allowed_refs=(REF,), i_own_this=True)


def test_the_database_url_must_belong_to_the_same_project():
    other = f"postgresql://postgres.{OTHER}:pw@aws-0-eu.pooler.supabase.com:5432/postgres"
    with pytest.raises(st.SupabaseTargetRefused, match="different database|not"):
        st.guard_supabase(URL, db_url=other, allowed_refs=(REF,), i_own_this=True)
    direct = f"postgresql://postgres:pw@db.{REF}.supabase.co:5432/postgres"
    assert st.guard_supabase(URL, db_url=direct, allowed_refs=(REF,), i_own_this=True).ref == REF
    assert st.guard_supabase(URL, db_url="postgresql://postgres:pw@127.0.0.1:5432/postgres", allowed_refs=(REF,), i_own_this=True).ref == REF


def test_a_local_api_with_a_remote_database_is_refused():
    with pytest.raises(st.SupabaseTargetRefused, match="remote database"):
        st.guard_supabase("http://127.0.0.1:54321", db_url=DBURL)


@pytest.mark.parametrize("text", ["*", "abc,*", "ab cd", "UPPER_case!"])
def test_wildcards_and_malformed_refs_are_rejected(text):
    with pytest.raises(st.SupabaseTargetRefused):
        st.parse_refs(text)


def test_refs_are_matched_exactly_and_case_insensitively():
    assert st.parse_refs(f" {REF.upper()} , {OTHER} ") == (REF, OTHER)
    with pytest.raises(st.SupabaseTargetRefused):
        st.guard_supabase(URL, allowed_refs=(REF[:-1],), i_own_this=True)  # a prefix is not a match


# ------------------------------------------------------------------------------------------- config + .env
def test_config_reads_env_then_the_dotenv_file_and_never_shows_a_value(tmp_path):
    (tmp_path / ".env").write_text(f'SUPABASE_URL="{URL}"\nSUPABASE_SERVICE_ROLE_KEY={KEY}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF} # mine\n'
                                   "SUPABASE_ANON_KEY=from-file\n", encoding="utf-8")
    c = st.load_config(tmp_path, environ={"SUPABASE_ANON_KEY": "from-env"})
    assert c.url == URL and c.anon_key == "from-env" and c.allowed_refs == (REF,)
    text = repr(c) + str(c)
    assert KEY not in text and "from-env" not in text and "<set>" in text
    assert KEY not in repr(st.resolve_target(c, i_own_this=True))


def test_a_bad_backend_setting_is_refused(tmp_path):
    with pytest.raises(st.SupabaseTargetRefused):
        st.load_config(tmp_path, environ={"PROOFGATE_SUPABASE_BACKEND": "docker"})


# ------------------------------------------------------------------------------------------- backend choice
NO_LOCAL = (False, "Docker is not running or not installed")


def test_auto_picks_hosted_when_a_hosted_url_is_configured():
    t = st.resolve_target(cfg(), i_own_this=True, local_ok=NO_LOCAL)
    assert t.backend == "hosted" and t.ref == REF and t.override_note


def test_hosted_is_refused_through_resolve_target_too():
    with pytest.raises(st.SupabaseTargetRefused):
        st.resolve_target(cfg(allowed_refs=()), i_own_this=True, local_ok=NO_LOCAL)
    with pytest.raises(st.SupabaseTargetRefused, match="--i-own-this"):
        st.resolve_target(cfg(), local_ok=NO_LOCAL)


def test_nothing_configured_is_a_recorded_skip_not_a_crash():
    with pytest.raises(st.BackendUnavailable, match="not configured"):
        st.resolve_target(cfg(url="", db_url=""), backend="hosted", local_ok=NO_LOCAL)
    with pytest.raises(st.BackendUnavailable):
        st.resolve_target(cfg(url="", db_url=""), local_ok=NO_LOCAL)


def test_local_without_docker_is_unavailable_but_a_local_url_still_works():
    with pytest.raises(st.BackendUnavailable, match="local backend"):
        st.resolve_target(cfg(url="", db_url=""), backend="local", local_ok=NO_LOCAL)
    t = st.resolve_target(cfg(url="http://127.0.0.1:54321", db_url=""), backend="local", local_ok=NO_LOCAL)
    assert t.backend == "local" and t.override_note is None and "127.0.0.1" in t.db_url


def test_a_backend_that_contradicts_the_url_is_refused():
    with pytest.raises(st.SupabaseTargetRefused):
        st.resolve_target(cfg(url="http://127.0.0.1:54321", db_url=""), backend="hosted", i_own_this=True)
    with pytest.raises(st.SupabaseTargetRefused):
        st.resolve_target(cfg(), backend="local", i_own_this=True, local_ok=(True, "x"))


def test_the_env_var_chooses_the_backend(tmp_path):
    c = st.load_config(tmp_path, environ={"SUPABASE_URL": URL, "PROOFGATE_SUPABASE_BACKEND": "local", "PROOFGATE_ALLOWED_PROJECT_REFS": REF})
    assert c.backend == "local"
    with pytest.raises(st.SupabaseTargetRefused):
        st.resolve_target(c, i_own_this=True)  # local was chosen but the URL is hosted


def test_missing_docker_and_a_hanging_docker_both_mean_unavailable(monkeypatch):
    monkeypatch.setattr(st.shutil, "which", lambda n: None)
    assert st.docker_available() is False
    monkeypatch.setattr(st.shutil, "which", lambda n: "/bin/docker")

    def hang(*a, **k):
        raise subprocess.TimeoutExpired("docker", 5)

    monkeypatch.setattr(st.subprocess, "run", hang)
    assert st.docker_available() is False


def test_status_rows_with_an_empty_config_say_not_configured_cleanly():
    rows = {n: (s, d) for n, s, d in st.backend_status(st.SupabaseConfig(), local_ok=NO_LOCAL)}
    assert rows["hosted"][0] == "not configured" and rows["local"][0] == "unavailable" and rows["backend"][1] == "auto"


def test_status_rows_name_what_is_missing_without_showing_values():
    rows = {n: (s, d) for n, s, d in st.backend_status(cfg(allowed_refs=(), db_url=""), local_ok=NO_LOCAL)}
    s, d = rows["hosted"]
    assert s == "blocked" and "PROOFGATE_ALLOWED_PROJECT_REFS" in d and "SUPABASE_DB_URL is empty" in d and KEY not in d


def test_doctor_prints_hosted_not_configured_with_an_empty_env_and_no_docker(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(st.shutil, "which", lambda n: None)
    assert main(["doctor", "--dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "hosted   not configured" in out and "local    unavailable" in out and "Docker is optional" in out
    assert main(["doctor", "--json", "--dir", str(tmp_path)]) == 0
    assert {r["name"]: r["status"] for r in json.loads(capsys.readouterr().out)}["supabase:hosted"] == "not configured"


# ------------------------------------------------------------------------------------------- migrations over psycopg (fake connection)
class FakeCursor:
    def __init__(self, rows=(), names=()):
        self._rows, self.description = list(rows), [(n,) for n in names]

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows

    def nextset(self):
        return False


class FakeConn:
    def __init__(self, rows=(), names=()):
        self.executed, self.closed, self.in_tx, self.tx_count = [], False, False, 0
        self._cur = FakeCursor(rows, names)

    @contextlib.contextmanager
    def transaction(self):
        self.in_tx = True
        self.tx_count += 1
        yield
        self.in_tx = False

    def execute(self, sql):
        self.executed.append((sql, self.in_tx))
        return self._cur

    def close(self):
        self.closed = True


def target(backend="hosted", ref=REF):
    return st.SupabaseTarget(backend, URL, "a", KEY, DBURL, ref, "note")


def test_reset_drops_only_demo_objects_and_replays_migrations_then_the_variant_in_one_transaction():
    conn = FakeConn()
    applied = db.reset_demo_schema(conn, DEMO, "c", target=target())
    assert applied == ["20240101000000_notes.sql", "20240101000100_run_sql.sql", "c_owner_only.sql"]
    assert conn.tx_count == 1 and all(in_tx for _, in_tx in conn.executed)
    assert conn.executed[0][0] == db.DEMO_DROP_SQL and "public.notes" in db.DEMO_DROP_SQL and "run_sql" in db.DEMO_DROP_SQL
    assert db.DEMO_DROP_SQL.count("drop ") == 2 and "schema" not in db.DEMO_DROP_SQL and "auth" not in db.DEMO_DROP_SQL
    assert "create table public.notes" in conn.executed[1][0] and "owner" in conn.executed[3][0].lower()


@pytest.mark.parametrize("letter,needle", [("A", "disable row level security"), ("B", "auth.role()"), ("C", "auth.uid()")])
def test_each_variant_is_the_one_that_gets_applied(letter, needle):
    conn = FakeConn()
    db.reset_demo_schema(conn, DEMO, letter, target=target())
    assert needle in conn.executed[-1][0]


def test_the_installed_variant_copy_is_not_replayed_twice(tmp_path):
    proj = tmp_path / "demo"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    shutil.copy(DEMO / "supabase/variants/a_rls_off.sql", proj / "supabase/migrations/20240201000000_rls_variant.sql")
    assert all("rls_variant" not in f.name for f in db.migration_files(proj))


def test_reset_refuses_a_project_that_is_not_the_demo_and_an_unknown_variant(tmp_path):
    (tmp_path / "supabase" / "migrations").mkdir(parents=True)
    with pytest.raises(st.SupabaseTargetRefused, match="not the ProofGate demo"):
        db.reset_demo_schema(FakeConn(), tmp_path, "A", target=target())
    with pytest.raises(ValueError):
        db.reset_demo_schema(FakeConn(), DEMO, "Z", target=target())


def test_reset_refuses_a_hosted_target_without_a_ref():
    with pytest.raises(st.SupabaseTargetRefused):
        db.reset_demo_schema(FakeConn(), DEMO, "A", target=target(ref=None))


def test_a_connection_failure_is_a_skip_that_never_echoes_the_url(monkeypatch):
    import psycopg

    def boom(*a, **k):
        raise psycopg.OperationalError(f"could not connect to {DBURL}")

    monkeypatch.setattr(psycopg, "connect", boom)
    with pytest.raises(st.BackendUnavailable) as e:
        target().connect()
    assert DBURL not in str(e.value) and "pw" not in str(e.value)


# ------------------------------------------------------------------------------------------- Splinter
NAMES = db.SPLINTER_COLUMNS
ROWS = [
    ("rls_disabled_in_public", "RLS Disabled in Public", "ERROR", "EXTERNAL", ["SECURITY"], "Detects tables without RLS.", "Table `public.notes` has no RLS",
     "https://supabase.com/docs/rls", {}, "rls_disabled_in_public_public_notes"),
    ("unindexed_foreign_keys", "Unindexed foreign keys", "INFO", "INTERNAL", ["PERFORMANCE"], "d", "x", None, {}, "unindexed_fk_1"),
    ("auth_rls_initplan", "Auth RLS initplan", "WARN", "INTERNAL", ["PERFORMANCE"], "d", "y", None, {}, "initplan_1"),
]


def test_splinter_rows_become_layer_5_findings():
    found = db.run_splinter(FakeConn(ROWS, NAMES), "select 1")
    by_rule = {f.rule: f for f in found}
    assert set(by_rule) == {"splinter:rls_disabled_in_public", "splinter:unindexed_foreign_keys", "splinter:auth_rls_initplan"}
    f = by_rule["splinter:rls_disabled_in_public"]
    assert f.layer == 5 and f.category == "database" and f.severity == "high" and f.sources == ["splinter"] and "public.notes" in f.plain_words
    assert by_rule["splinter:auth_rls_initplan"].severity == "medium" and by_rule["splinter:unindexed_foreign_keys"].severity == "low"
    assert db.run_splinter(FakeConn([], NAMES), "select 1") == []


def test_splinter_sql_is_found_through_the_env_var_or_tools_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the ./tools fallback must not see this repository's real download
    assert db.find_splinter_sql([tmp_path]) is None
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "splinter.sql").write_text("select 1", encoding="utf-8")
    assert db.find_splinter_sql([tmp_path]) == tmp_path / "tools" / "splinter.sql"
    other = tmp_path / "x.sql"
    other.write_text("select 2", encoding="utf-8")
    monkeypatch.setenv("PROOFGATE_SPLINTER_SQL", str(other))
    assert db.find_splinter_sql([tmp_path]) == other


def test_splinter_without_its_sql_file_is_unavailable_not_a_crash():
    with pytest.raises(st.BackendUnavailable, match="splinter.sql"):
        db.splinter_for_target(target(), None)


# ------------------------------------------------------------------------------------------- layer 5 live hook
async def test_layer5_static_only_notes_that_the_live_check_needs_full(tmp_path):
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    res = await l5.run(tmp_path)
    assert any("splinter: skipped" in n and "--full" in n for n in res.notes) and {t.name: t.status for t in res.tools}["splinter"] == "skipped"


async def test_layer5_full_with_nothing_configured_records_a_skip(tmp_path):
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    res = await l5.run(tmp_path, full=True)
    assert any("splinter: skipped" in n and "not configured" in n for n in res.notes) and res.target_overrides == []
    assert res.findings  # the static findings are still there


async def test_layer5_full_refusal_is_a_skip_with_the_reason(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    (tmp_path / ".env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_DB_URL={DBURL}\n", encoding="utf-8")  # no allow-list
    res = await l5.run(tmp_path, full=True, i_own_this=True)
    assert any("splinter: skipped: refused" in n and "PROOFGATE_ALLOWED_PROJECT_REFS" in n for n in res.notes) and not res.target_overrides


async def test_layer5_full_runs_splinter_for_an_allowed_project_and_logs_the_override(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    (tmp_path / ".env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_DB_URL={DBURL}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n", encoding="utf-8")
    monkeypatch.setattr(db, "splinter_for_target", lambda t, p: db.splinter_findings([dict(zip(NAMES, ROWS[0]))]))
    res = await l5.run(tmp_path, full=True, i_own_this=True)
    assert {t.name: t.status for t in res.tools}["splinter"] == "ok"
    assert any(f.rule == "splinter:rls_disabled_in_public" for f in res.findings) and any(REF in o for o in res.target_overrides)


async def test_layer5_full_without_the_ownership_flag_does_not_touch_the_project(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    (tmp_path / ".env").write_text(f"SUPABASE_URL={URL}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n", encoding="utf-8")
    called = []
    monkeypatch.setattr(db, "splinter_for_target", lambda t, p: called.append(1) or [])
    res = await l5.run(tmp_path, full=True)
    assert called == [] and any("--i-own-this" in n for n in res.notes)


async def test_a_live_failure_is_an_error_not_a_clean_result(tmp_path, monkeypatch):
    shutil.copytree(DEMO / "supabase", tmp_path / "supabase")
    (tmp_path / ".env").write_text(f"SUPABASE_URL={URL}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n", encoding="utf-8")

    def boom(t, p):
        raise RuntimeError(f"secret detail {DBURL}")

    monkeypatch.setattr(db, "splinter_for_target", boom)
    res = await l5.run(tmp_path, full=True, i_own_this=True)
    assert {t.name: t.status for t in res.tools}["splinter"] == "error" and DBURL not in " ".join(res.notes)


# ------------------------------------------------------------------------------------------- scripts/reset_demo.py
def load_script():
    spec = importlib.util.spec_from_file_location("reset_demo", ROOT / "scripts" / "reset_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_reset_script_with_an_empty_env_is_a_clean_skip(capsys, tmp_path):
    proj = tmp_path / "demo"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    assert load_script().main(["--project", str(proj), "--backend", "hosted"]) == 2
    assert "skipped: hosted backend: not configured" in capsys.readouterr().err


def test_reset_script_refuses_without_the_allow_list_or_the_flag(capsys, tmp_path):
    proj = tmp_path / "demo"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    (proj / ".env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_DB_URL={DBURL}\n", encoding="utf-8")
    assert load_script().main(["--project", str(proj), "--backend", "hosted", "--i-own-this"]) == 2
    assert "refused" in capsys.readouterr().err
    (proj / ".env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_DB_URL={DBURL}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n", encoding="utf-8")
    assert load_script().main(["--project", str(proj), "--backend", "hosted"]) == 2
    assert "--i-own-this" in capsys.readouterr().err


def test_reset_script_runs_for_an_allowed_project_and_prints_no_secret(capsys, tmp_path, monkeypatch):
    proj = tmp_path / "demo"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    (proj / ".env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_SERVICE_ROLE_KEY={KEY}\nSUPABASE_DB_URL={DBURL}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n", encoding="utf-8")
    conn = FakeConn(rows=[(1,)])
    monkeypatch.setattr(st.SupabaseTarget, "connect", lambda self: conn)
    assert load_script().main(["--project", str(proj), "--variant", "B", "--backend", "hosted", "--i-own-this"]) == 0
    out = capsys.readouterr()
    assert "applied: 20240101000000_notes.sql" in out.out and "b_auth_role.sql" in out.out and conn.closed
    assert KEY not in out.out + out.err and DBURL not in out.out + out.err and "pw@" not in out.out + out.err


def test_reset_script_driver_errors_print_only_the_type(capsys, tmp_path, monkeypatch):
    proj = tmp_path / "demo"
    shutil.copytree(DEMO / "supabase", proj / "supabase")
    (proj / ".env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_DB_URL={DBURL}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n", encoding="utf-8")

    class Boom(FakeConn):
        def execute(self, sql):
            raise RuntimeError(f"failed on {DBURL}")

    monkeypatch.setattr(st.SupabaseTarget, "connect", lambda self: Boom())
    assert load_script().main(["--project", str(proj), "--backend", "hosted", "--i-own-this"]) == 2
    err = capsys.readouterr().err
    assert "failed: RuntimeError" in err and DBURL not in err


def test_env_example_lists_the_six_names_with_no_values():
    names = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            names[k] = v
    for n in ("SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_DB_URL", "PROOFGATE_ALLOWED_PROJECT_REFS", "PROOFGATE_SUPABASE_BACKEND"):
        assert n in names
    assert [k for k in st.ENV_NAMES if k not in ("PROOFGATE_SUPABASE_BACKEND",) and names.get(k)] == []


def test_no_hard_docker_requirement_remains_in_the_code():
    import re

    for p in (ROOT / "core" / "proofgate").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        assert not re.search(r"\bdocker\s+(run|compose|pull)\b", text), p  # Docker is only ever probed with `docker info`, never required


# ------------------------------------------------------------------------------------------- new key format (sb_publishable_ / sb_secret_)
NEW_SECRET = fake_secrets()["supabase_secret"]
NEW_PUBLISHABLE = "sb_" + "publishable_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3"


def test_key_kinds_are_told_apart_by_shape():
    assert st.key_kind(NEW_SECRET) == "secret" and st.key_kind(NEW_PUBLISHABLE) == "publishable" and st.key_kind(KEY) == "jwt"
    assert st.key_kind("") == "empty" and st.key_kind(None) == "empty" and st.key_kind("whatever") == "unknown"


def test_new_keys_go_in_apikey_only_and_legacy_jwts_keep_the_bearer_header():
    assert st.api_headers(NEW_SECRET) == {"apikey": NEW_SECRET}  # an sb_ key is not a JWT: never a Bearer token
    assert st.api_headers(NEW_PUBLISHABLE, "user.jwt.here") == {"apikey": NEW_PUBLISHABLE, "Authorization": "Bearer user.jwt.here"}
    assert st.api_headers(KEY) == {"apikey": KEY, "Authorization": f"Bearer {KEY}"}


def test_the_new_secret_key_is_a_critical_finding_and_the_publishable_key_is_not():
    from proofgate.layers import l1_secrets as l1

    found = l1.scan_text(f'const a = "{NEW_PUBLISHABLE}";\nconst b = "{NEW_SECRET}";\n', "app.ts")
    assert [(f.rule, f.severity, f.location.line) for f in found] == [("supabase-secret-key", "critical", 2)]
    assert NEW_SECRET not in found[0].model_dump_json()


def test_the_new_secret_key_is_masked_everywhere_and_the_publishable_one_is_left_alone():
    from proofgate.redact import redact

    out = redact(f"apikey: {NEW_SECRET} / {NEW_PUBLISHABLE}")
    assert NEW_SECRET not in out and "«SECRET:supabase-secret-key:" in out and NEW_PUBLISHABLE in out


def test_the_inline_hook_blocks_a_new_secret_key_but_not_the_publishable_key(tmp_path):
    import json as _json

    from proofgate import hook

    def run(content):
        payload = _json.dumps({"cwd": str(tmp_path), "hook_event_name": "PreToolUse", "tool_name": "Write",
                               "tool_input": {"file_path": str(tmp_path / "a.ts"), "content": content}})
        return hook.run_hook("pre", payload, project_dir=str(tmp_path))

    blocked = run(f'export const k = "{NEW_SECRET}";\n')
    assert blocked.exit_code == 2 and NEW_SECRET not in blocked.stderr and "rotate" in blocked.stderr
    assert run(f'export const k = "{NEW_PUBLISHABLE}";\n').exit_code == 0


def test_the_secret_literal_guard_knows_the_new_shape():
    import importlib.util

    spec = importlib.util.spec_from_file_location("csl", ROOT / "scripts" / "check_secret_literals.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.PATTERN.search(f'x = "{NEW_SECRET}"') and not mod.PATTERN.search(f'x = "{NEW_PUBLISHABLE}"')


def test_doctor_rows_name_the_key_kinds_without_values():
    c = cfg(anon_key=NEW_PUBLISHABLE, service_role_key=NEW_SECRET)
    detail = {n: d for n, s, d in st.backend_status(c, local_ok=NO_LOCAL)}["hosted"]
    assert "anon key: publishable" in detail and "service key: secret" in detail and NEW_SECRET not in detail


def test_a_dotenv_that_is_a_folder_of_env_files_is_read(tmp_path):
    (tmp_path / ".env").mkdir()
    (tmp_path / ".env" / "SUPABASE.env").write_text(f"SUPABASE_URL={URL}\nSUPABASE_SERVICE_ROLE_KEY={NEW_SECRET}\n", encoding="utf-8")
    c = st.load_config(tmp_path, environ={})
    assert c.url == URL and st.key_kind(c.service_role_key) == "secret"


def test_a_password_with_an_at_sign_or_other_url_characters_is_encoded():
    pw = "p@ss/w#rd:1"  # fake
    raw = f"postgresql://postgres.{REF}:{pw}@aws-0-eu.pooler.supabase.com:5432/postgres"
    fixed = st.normalize_db_url(raw)
    from urllib.parse import urlparse, unquote

    u = urlparse(fixed)
    assert u.hostname == "aws-0-eu.pooler.supabase.com" and unquote(u.password) == pw and u.path == "/postgres" and u.port == 5432
    assert st.db_url_ref(fixed) == REF
    assert st.normalize_db_url(fixed) == fixed  # already encoded: unchanged
    assert st.normalize_db_url(DBURL) == DBURL and st.normalize_db_url("") == ""


def test_load_config_normalises_the_database_url(tmp_path):
    (tmp_path / ".env").write_text(f"SUPABASE_DB_URL=postgresql://postgres.{REF}:a@b@aws-0-eu.pooler.supabase.com:5432/postgres\n", encoding="utf-8")
    assert "a%40b" in st.load_config(tmp_path, environ={}).db_url


def test_the_env_file_is_found_in_a_parent_folder_up_to_the_repository_root(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "demo" / "app").mkdir(parents=True)
    (repo / ".env").write_text(f"SUPABASE_URL={URL}\n", encoding="utf-8")
    assert st.load_config(repo / "demo" / "app", environ={}).url == URL
    (tmp_path / "outside").mkdir()
    (tmp_path / ".env").write_text(f"SUPABASE_URL={URL}\n", encoding="utf-8")
    assert st.load_config(tmp_path / "outside", environ={}).url == URL  # no repository boundary: the nearest .env wins
    (tmp_path / "outside" / ".git").mkdir()
    assert st.load_config(tmp_path / "outside", environ={}).url == ""  # a repository boundary stops the search


class MultiSetCursor:
    """Like psycopg after a multi-statement string: SET -> no columns, DO -> no columns, SELECT -> rows."""

    def __init__(self):
        self._sets = [(None, []), (None, []), ([("name",), ("level",), ("title",), ("detail",), ("cache_key",)], [("rls_disabled_in_public", "ERROR", "RLS Disabled", "x", "k1")])]
        self._i = 0

    @property
    def description(self):
        return self._sets[self._i][0]

    def fetchall(self):
        return self._sets[self._i][1]

    def nextset(self):
        if self._i + 1 < len(self._sets):
            self._i += 1
            return True
        return False


def test_splinter_reads_the_last_result_set_of_a_multi_statement_script():
    class C:
        def execute(self, sql):
            return MultiSetCursor()

    found = db.run_splinter(C(), "set local search_path = ''; do $$ begin end $$; select 1")
    assert [f.rule for f in found] == ["splinter:rls_disabled_in_public"]
