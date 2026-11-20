"""The Supabase probe against an in-memory Supabase (variants A, B, C). No network, no real project."""
import asyncio
import json
import shutil

import httpx
import pytest

from proofgate.models import Contract, OwnedResource
from proofgate.probe import run_probe
from proofgate.probe import supabase as sp
from proofgate.supabase_target import SupabaseTarget

from fake_supabase import PUBLISHABLE, SECRET, FakeDb, FakeSupabase
from corpus_harness import ROOT

DEMO = ROOT / "demo-apps" / "nextjs-supabase"
REF = "abcdefghijklmnopqrst"
CONTRACT = Contract(owned_resources=[OwnedResource(name="notes", owner_field="user_id", actions=["read", "write"])], profile_editable_fields=[],
                    admin_only_routes=[], public_routes=[], rules=["Users can only read and change their own notes."], confirmed_by_user=True, source="fallback")


def target() -> SupabaseTarget:
    return SupabaseTarget("hosted", f"https://{REF}.supabase.co", PUBLISHABLE, SECRET, "postgresql://x", REF, "note")


async def probe(fake: FakeSupabase, *, db=True, contract=CONTRACT):
    api = sp.SupabaseApi(target(), httpx.AsyncClient(transport=fake.transport(), timeout=5), delay=0)
    fdb = FakeDb(fake) if db else None
    res = await sp.SupabaseProbe(target(), contract, fdb, api).run()
    return res, fdb


def verdicts(res):
    return {(c.rule, c.actor, c.route_label.split(" ")[0]): c.verdict for c in res.checks}


async def test_variant_a_rls_off_everything_is_proven_including_anon():
    fake = FakeSupabase("A")
    res, _ = await probe(fake)
    v = verdicts(res)
    assert set(v.values()) == {"PROVEN"} and ("cross-user-list", "anon", "GET") in v and ("cross-user-write", "B", "DELETE") in v
    assert all(res.oracles.values()) and res.untested == []


async def test_variant_b_role_only_policy_leaks_to_signed_in_users_but_not_to_anon():
    res, _ = await probe(FakeSupabase("B"))
    v = verdicts(res)
    assert v[("cross-user-list", "anon", "GET")] == "HELD"
    assert {v[("cross-user-list", "B", "GET")], v[("cross-user-read", "B", "GET")], v[("cross-user-write", "B", "PATCH")], v[("cross-user-write", "B", "DELETE")]} == {"PROVEN"}


async def test_variant_c_owner_only_holds_and_the_owner_oracles_pass():
    res, _ = await probe(FakeSupabase("C"))
    assert {c.verdict for c in res.checks} == {"HELD"} and all(res.oracles.values()) and res.proven == []
    assert res.oracles == {"A can read own notes": True, "A can update own notes": True}


async def test_a_held_result_is_inconclusive_when_the_owner_cannot_use_the_table_either():
    class BrokenOwner(FakeSupabase):
        def _visible(self, caller, row):
            return False  # nobody can see anything, not even the owner

    res, _ = await probe(BrokenOwner("C"))
    assert {c.verdict for c in res.checks} == {"INCONCLUSIVE"} and res.oracles["A can read own notes"] is False
    assert all("proves nothing" in c.note for c in res.checks)


async def test_cleanup_removes_users_and_rows_and_says_so_even_after_a_failure():
    fake = FakeSupabase("C")
    res, db = await probe(fake)
    assert fake.users == {} and fake.notes == {} and db.closed
    assert any("cleanup verified: no probe user is left" in n for n in res.notes)


async def test_cleanup_runs_when_the_attacks_blow_up_midway():
    fake = FakeSupabase("C")
    real = fake.handle

    def explode(req):
        if req.method == "PATCH":
            raise httpx.ConnectError("network died")
        return real(req)

    fake.handle = explode  # type: ignore[method-assign]
    res, db = await probe(fake)
    assert fake.users == {} and fake.notes == {} and db.closed  # users and rows are gone even though the run died
    assert any("could not reach the project" in u for u in res.untested)


async def test_a_flaky_user_delete_is_retried_until_no_probe_user_is_left(monkeypatch):
    fake = FakeSupabase("C", flaky_user_deletes=2)
    res, _ = await probe(fake)
    assert fake.users == {} and any("cleanup verified" in n for n in res.notes)


async def test_a_user_that_cannot_be_deleted_is_reported_loudly():
    fake = FakeSupabase("C", flaky_user_deletes=999)
    res, _ = await probe(fake)
    assert len(fake.users) == 2 and any("cleanup WARNING: 2 probe user(s) may remain" in n and "proofgate-probe-" in n for n in res.notes)


async def test_the_seed_falls_back_to_the_database_when_the_api_refuses_the_insert():
    res, _ = await probe(FakeSupabase("C", insert_denied=True))
    assert {c.verdict for c in res.checks} == {"HELD"} and any("trying the database" in n for n in res.notes)


async def test_without_a_database_and_a_refused_insert_the_table_is_untested_not_safe():
    res, _ = await probe(FakeSupabase("C", insert_denied=True), db=False)
    assert res.checks == [] and any("could not plant a row" in u for u in res.untested)


async def test_a_required_column_that_cannot_be_filled_makes_the_table_untested():
    fake = FakeSupabase("C")
    api = sp.SupabaseApi(target(), httpx.AsyncClient(transport=fake.transport()), delay=0)
    cols = [{"name": "id", "type": "uuid", "nullable": False, "default": "x"}, {"name": "user_id", "type": "uuid", "nullable": False, "default": None},
            {"name": "amount", "type": "integer", "nullable": False, "default": None}]
    res = await sp.SupabaseProbe(target(), CONTRACT, FakeDb(fake, cols), api).run()
    assert res.checks == [] and any("amount" in n for n in res.notes) and any("could not plant" in u for u in res.untested)


async def test_rate_limits_are_retried_with_backoff():
    fake = FakeSupabase("C", rate_limit_first=3)
    res, _ = await probe(fake)
    assert {c.verdict for c in res.checks} == {"HELD"} and sum(1 for _ in fake.calls) > 15


async def test_missing_keys_or_no_owned_tables_are_untested():
    res = await sp.SupabaseProbe(SupabaseTarget("hosted", "https://x.supabase.co", "", "", "", REF, None), CONTRACT).run()
    assert any("both needed" in u for u in res.untested) and res.checks == []
    empty = Contract(owned_resources=[], profile_editable_fields=[], admin_only_routes=[], public_routes=[], rules=[], confirmed_by_user=True, source="fallback")
    assert any("no owned tables" in u for u in (await sp.SupabaseProbe(target(), empty).run()).untested)


async def test_new_style_keys_are_sent_as_apikey_only_and_users_get_their_own_bearer():
    fake = FakeSupabase("C")
    await probe(fake)
    for h in fake.seen_headers:
        assert h.get("authorization", "") == "" or h["authorization"].startswith("Bearer fakejwt-")  # never "Bearer sb_..."
        assert SECRET not in h.get("authorization", "") and PUBLISHABLE not in h.get("authorization", "")
    assert any(h["apikey"] == SECRET for h in fake.seen_headers) and any(h["apikey"] == PUBLISHABLE for h in fake.seen_headers)


async def test_findings_are_proven_critical_and_redacted_and_use_the_standard_rules():
    res, _ = await probe(FakeSupabase("A"))
    findings = res.to_findings(CONTRACT)
    assert {f.rule for f in findings} == {"cross-user-list", "cross-user-read", "cross-user-write"} and all(f.proven and f.severity == "critical" for f in findings)
    dump = " ".join(f.model_dump_json() for f in findings)
    assert "PGCANARY_A_«masked»" in dump and SECRET not in dump and PUBLISHABLE not in dump and "fakejwt-" not in dump
    assert all(f.location.file == "supabase:public.notes" for f in findings)


async def test_no_probe_user_email_collides_and_all_are_marked():
    fake = FakeSupabase("C")
    api = sp.SupabaseApi(target(), httpx.AsyncClient(transport=fake.transport()), delay=0)
    s = await api.create_user("A")
    assert s.email.startswith(sp.PROBE_EMAIL_PREFIX) and s.email.endswith("-a@example.com") and s.password not in repr(s)


# ------------------------------------------------------------------------------------------- run_probe wiring
def project(tmp_path, env: str | None = None):
    dst = tmp_path / "demo"
    shutil.copytree(DEMO / "supabase", dst / "supabase")
    (dst / "package.json").write_text('{"dependencies": {"@supabase/ssr": "0"}}', encoding="utf-8")
    if env is not None:
        (dst / ".env").write_text(env, encoding="utf-8")
    return dst


async def test_run_probe_dispatches_to_supabase_and_with_nothing_configured_says_untested(tmp_path):
    out = await run_probe(project(tmp_path), CONTRACT)
    assert out.error is None and out.result.checks == [] and any("not probed" in u and "not configured" in u for u in out.result.untested)


async def test_run_probe_refuses_an_unlisted_hosted_project(tmp_path):
    out = await run_probe(project(tmp_path, f"SUPABASE_URL=https://{REF}.supabase.co\n"), CONTRACT, i_own_this=True)
    assert out.error and "PROOFGATE_ALLOWED_PROJECT_REFS" in out.error


async def test_run_probe_runs_for_an_allowed_project_and_logs_the_override(tmp_path, monkeypatch):
    fake = FakeSupabase("A")
    real = sp.SupabaseApi.__init__

    def init(self, t, client=None, **kw):
        real(self, t, httpx.AsyncClient(transport=fake.transport()), delay=0)

    monkeypatch.setattr(sp.SupabaseApi, "__init__", init)
    env = f"SUPABASE_URL=https://{REF}.supabase.co\nSUPABASE_ANON_KEY={PUBLISHABLE}\nSUPABASE_SERVICE_ROLE_KEY={SECRET}\nPROOFGATE_ALLOWED_PROJECT_REFS={REF}\n"
    out = await run_probe(project(tmp_path, env), CONTRACT, i_own_this=True)
    assert out.error is None and len(out.result.proven) == 5 and any(REF in o for o in out.overrides)
    assert any("SUPABASE_DB_URL is not set" in n for n in out.result.notes)  # no database: still ran through the API


async def test_flask_projects_still_use_the_flask_probe(tmp_path):
    from corpus_harness import CORPUS

    dst = tmp_path / "v01"
    shutil.copytree(CORPUS / "v01_idor_read", dst, ignore=shutil.ignore_patterns(".proofgate"))
    (dst / "supabase").mkdir()  # even with a supabase folder next to it, an app.py entry means the Flask probe
    out = await run_probe(dst)
    assert out.result.launched and [c.rule for c in out.result.proven] == ["cross-user-read"]


# ------------------------------------------------------------------------------------------- Next.js route replay
import base64
import re as _re

from proofgate.probe import nextjs as nx


def test_routes_are_discovered_from_the_demo_with_their_dynamic_segments_and_tables():
    routes = nx.discover_routes(DEMO)
    by = {(r.method, r.pattern): r for r in routes}
    get = by[("GET", "/api/notes/[id]")]
    assert get.params == ("id",) and get.tables == ("notes",) and get.file == "app/api/notes/[id]/route.ts" and get.line > 1
    assert ("PUT", "/api/notes/[id]") in by and get.fill("abc") == "/api/notes/abc"
    search = by[("GET", "/api/search")]
    assert search.params == () and search.query_params == ("q",) and "notes" in search.tables  # the table is named inside SQL text


def test_the_session_cookie_is_base64url_json_and_is_chunked_when_large():
    cookies = nx.session_cookies("myref", {"access_token": "a.b.c", "user": {"id": "u"}})
    (name, value), = cookies.items()
    assert name == "sb-myref-auth-token" and value.startswith("base64-")
    raw = value.removeprefix("base64-")
    assert json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))["user"]["id"] == "u"
    big = nx.session_cookies("myref", {"access_token": "x" * 7000})
    assert list(big) == ["sb-myref-auth-token.0", "sb-myref-auth-token.1", "sb-myref-auth-token.2"] and all(len(v) <= 3180 for v in big.values())
    assert "".join(big.values()).startswith("base64-")


class FakeNext:
    """A stand-in for the demo's /api/notes/[id] handler. `leaky` = the planted flaw (service-role client, no owner check)."""

    def __init__(self, fake: FakeSupabase, leaky: bool):
        self.fake, self.leaky, self.requests = fake, leaky, []

    def transport(self):
        return httpx.MockTransport(self.handle)

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        cookie = req.headers.get("cookie", "")
        m = _re.search(r"sb-\w+-auth-token=base64-([\w-]+)", cookie)
        if not m:
            return httpx.Response(401, json={"error": "not signed in"})
        raw = m.group(1)
        uid = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))["user"]["id"]
        if req.url.path == "/api/search":
            q = req.url.params.get("q", "")
            rows = [n for n in self.fake.notes.values() if (self.leaky and "OR '1'='1'" in q) or q in n["title"] or q in n["body"]]
            return httpx.Response(200, json=rows if self.leaky else [n for n in rows if n["user_id"] == uid])
        note = self.fake.notes.get(req.url.path.rsplit("/", 1)[1])
        if note is None:
            return httpx.Response(404, json={"error": "no"})
        if not self.leaky and note["user_id"] != uid:
            return httpx.Response(404, json={"error": "no"})
        if req.method == "PUT":
            note.update(json.loads(req.content))
        return httpx.Response(200, json=note)


class FakeDev:
    url = "http://127.0.0.1:1"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


def replay_for(nxt: FakeNext, project=DEMO):
    return nx.NextReplay(project, "abcdefghijklmnopqrst", nx.discover_routes(project), {}, dev_factory=lambda: FakeDev(), transport=nxt.transport())


async def probe_with_next(fake, nxt):
    api = sp.SupabaseApi(target(), httpx.AsyncClient(transport=fake.transport(), timeout=5), delay=0)
    return await sp.SupabaseProbe(target(), CONTRACT, FakeDb(fake), api, next_replay=replay_for(nxt)).run()


async def test_a_route_that_uses_the_service_role_client_is_proven_even_when_rls_holds():
    fake = FakeSupabase("C")  # RLS is correct...
    res = await probe_with_next(fake, FakeNext(fake, leaky=True))  # ...but the route skips it
    routes = [c for c in res.checks if c.file and c.file.startswith("app/")]
    assert {(c.rule, c.verdict) for c in routes} == {("cross-user-read", "PROVEN"), ("cross-user-write", "PROVEN"), ("sql-injection", "PROVEN")}
    assert all(c.verdict == "HELD" for c in res.checks if c.file == "supabase:public.notes")  # PostgREST itself holds
    f = next(x for x in res.to_findings(CONTRACT) if x.rule == "cross-user-read")
    assert f.location.file == "app/api/notes/[id]/route.ts" and f.location.function == "GET" and "PGCANARY_A_«masked»" in f.evidence.response_excerpt
    assert fake.users == {}  # cleanup still ran


async def test_a_route_that_checks_ownership_is_held_and_the_owner_oracles_pass():
    fake = FakeSupabase("C")
    res = await probe_with_next(fake, FakeNext(fake, leaky=False))
    assert res.proven == [] and {c.verdict for c in res.checks} == {"HELD"}
    assert res.oracles["A can use GET /api/notes/[id] for own notes"] is True and res.oracles["A can use PUT /api/notes/[id] for own notes"] is True
    assert "GET /api/notes/[id]" in res.tested_routes
    assert "GET /api/search" in res.tested_routes and res.oracles["A can search own notes through GET /api/search"] is True  # the injection payload found nothing


async def test_the_replay_sends_the_users_session_and_never_a_key():
    fake = FakeSupabase("C")
    nxt = FakeNext(fake, leaky=True)
    await probe_with_next(fake, nxt)
    assert nxt.requests and all("cookie" in r.headers and SECRET not in str(r.headers) and PUBLISHABLE not in str(r.headers) for r in nxt.requests)


async def test_without_node_modules_the_routes_are_untested_not_safe(tmp_path):
    proj = tmp_path / "app-copy"
    shutil.copytree(DEMO / "app", proj / "app")
    replay = nx.NextReplay(proj, "abcdefghijklmnopqrst", nx.discover_routes(proj), {})  # the real dev server: node_modules is missing here
    fake = FakeSupabase("C")
    api = sp.SupabaseApi(target(), httpx.AsyncClient(transport=fake.transport(), timeout=5), delay=0)
    res = await sp.SupabaseProbe(target(), CONTRACT, FakeDb(fake), api, next_replay=replay).run()
    assert any("not replayed" in u and "npm install" in u for u in res.untested) and not [c for c in res.checks if c.file.startswith("app/")]
