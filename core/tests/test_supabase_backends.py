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
    assert {r["backend"]: r["status"] for r in json.loads(capsys.readouterr().out)["supabase"]}["hosted"] == "not configured"


# ------------------------------------------------------------------------------------------- migrations over psycopg (fake connection)
class FakeCursor:
    def __init__(self, rows=(), names=()):
        self._rows, self.description = list(rows), [(n,) for n in names]

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


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
