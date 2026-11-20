"""The Doppelganger probe for Supabase tables (plan 3.2), over HTTP, against a target that passed the guard.

For each table the contract says belongs to individual users:

  1. create user A and user B through the Auth ADMIN API (email_confirm: true), then sign both in for real JWTs;
  2. plant a row owned by A holding a random canary (PGCANARY_A_...), through PostgREST as A (or directly in the database if that is refused);
  3. owner oracles: A can read and update their own row (otherwise a "held" result proves nothing);
  4. attacks: anon lists the table, B lists it, B reads A's row by id, B updates A's row, B deletes A's row;
  5. ALWAYS (try/finally) delete both users and every row they own, and check no probe user is left behind.

A canary in a response to someone who must not see it, or a changed/deleted row, is PROVEN. A response that holds is HELD only if the oracle passed,
else INCONCLUSIVE. Anything that cannot be set up is UNTESTED, never safe. Calls are spaced out and retried with backoff (Supabase rate limits).
Keys are never part of a request label, evidence or note; JWTs and canaries are masked by the redactor on the way out.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from ..models import Contract
from ..redact import new_canary, redact
from ..supabase_target import SupabaseTarget, api_headers
from .result import Check, ProbeResult

PROBE_EMAIL_PREFIX = "proofgate-probe-"
RETRY_STATUS = {429, 502, 503, 504}
LIVE_FILE_PREFIX = "supabase:public."


class LiveDb(Protocol):
    """What the probe needs from the database connection (a fake in tests; psycopg for real)."""

    def columns(self, table: str) -> list[dict[str, Any]]: ...
    def delete_owned_rows(self, table: str, owner_col: str, owner_ids: list[str]) -> int: ...
    def insert_row(self, table: str, row: dict[str, Any]) -> str | None: ...
    def close(self) -> None: ...


class PsycopgDb:
    def __init__(self, conn: Any):
        self.conn = conn

    def columns(self, table: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "select column_name, data_type, is_nullable, column_default from information_schema.columns "
            "where table_schema = 'public' and table_name = %s order by ordinal_position", (table,)).fetchall()
        return [{"name": r[0], "type": r[1], "nullable": r[2] == "YES", "default": r[3]} for r in rows]

    def delete_owned_rows(self, table: str, owner_col: str, owner_ids: list[str]) -> int:
        from psycopg import sql

        with self.conn.transaction():
            cur = self.conn.execute(sql.SQL("delete from public.{} where {}::text = any(%s)").format(sql.Identifier(table), sql.Identifier(owner_col)), (owner_ids,))
        return cur.rowcount or 0

    def insert_row(self, table: str, row: dict[str, Any]) -> str | None:
        from psycopg import sql

        cols = list(row)
        q = sql.SQL("insert into public.{} ({}) values ({}) returning id").format(
            sql.Identifier(table), sql.SQL(", ").join(map(sql.Identifier, cols)), sql.SQL(", ").join(sql.Placeholder() * len(cols)))
        with self.conn.transaction():
            self.conn.execute("set local session_replication_role = replica")  # the owner row in auth.users may be a moment old: skip the FK for this throwaway row
            r = self.conn.execute(q, [row[c] for c in cols]).fetchone()
        return str(r[0]) if r else None

    def close(self) -> None:
        self.conn.close()


# ------------------------------------------------------------------------------------------- Supabase HTTP
@dataclass
class Session:
    name: str
    user_id: str
    email: str
    password: str = field(repr=False)
    access_token: str = field(default="", repr=False)
    session: dict[str, Any] = field(default_factory=dict, repr=False)  # the whole token response (for a Next.js cookie)


class SupabaseApi:
    def __init__(self, target: SupabaseTarget, client: httpx.AsyncClient | None = None, *, delay: float = 0.15, retries: int = 4):
        self.t = target
        self.client = client or httpx.AsyncClient(timeout=20.0)
        self.delay, self.retries = delay, retries
        self.calls = 0

    async def aclose(self) -> None:
        await self.client.aclose()

    async def request(self, method: str, path: str, *, key: str, user_jwt: str | None = None, headers: dict[str, str] | None = None, **kw: Any) -> httpx.Response:
        h = {**api_headers(key, user_jwt), **(headers or {})}
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            if self.delay:
                await asyncio.sleep(self.delay)
            self.calls += 1
            try:
                r = await self.client.request(method, self.t.url + path, headers=h, **kw)
            except httpx.HTTPError as e:
                last = e
            else:
                if r.status_code not in RETRY_STATUS:
                    return r
                last = None
                retry_after = r.headers.get("retry-after", "")
                await asyncio.sleep(min(float(retry_after), 10.0) if retry_after.replace(".", "", 1).isdigit() else 0.5 * 2 ** attempt * (1 if self.delay else 0))
            if attempt < self.retries:
                await asyncio.sleep(0.5 * 2 ** attempt * (1 if self.delay else 0))
        if last is not None:
            raise last
        return r  # type: ignore[possibly-undefined]

    # --- Auth admin
    async def create_user(self, name: str) -> Session:
        email = f"{PROBE_EMAIL_PREFIX}{secrets.token_hex(4)}-{name.lower()}@example.com"
        password = secrets.token_urlsafe(18)
        r = await self.request("POST", "/auth/v1/admin/users", key=self.t.service_role_key,
                               json={"email": email, "password": password, "email_confirm": True})
        if r.status_code >= 300:
            raise ProbeSetupError(f"could not create user {name}: HTTP {r.status_code}")
        return Session(name, str(r.json()["id"]), email, password)

    async def sign_in(self, s: Session) -> None:
        r = await self.request("POST", "/auth/v1/token?grant_type=password", key=self.t.anon_key, json={"email": s.email, "password": s.password})
        if r.status_code >= 300 or "access_token" not in r.json():
            raise ProbeSetupError(f"could not sign in user {s.name}: HTTP {r.status_code}")
        s.session = r.json()
        s.access_token = s.session["access_token"]

    async def delete_user(self, user_id: str) -> bool:
        r = await self.request("DELETE", f"/auth/v1/admin/users/{user_id}", key=self.t.service_role_key)
        return r.status_code < 300 or r.status_code == 404

    async def leftover_probe_users(self) -> list[str]:
        r = await self.request("GET", "/auth/v1/admin/users?per_page=200", key=self.t.service_role_key)
        if r.status_code >= 300:
            raise ProbeSetupError(f"could not list users to verify the cleanup: HTTP {r.status_code}")
        body = r.json()
        users = body.get("users", body) if isinstance(body, dict) else body
        return [u["id"] for u in users if str(u.get("email", "")).startswith(PROBE_EMAIL_PREFIX)]

    # --- PostgREST
    async def rest(self, method: str, table: str, query: str = "", *, who: Session | None, json_body: Any = None) -> httpx.Response:
        h = {"Prefer": "return=representation", "Content-Type": "application/json"}
        key = self.t.anon_key  # a table is reached with the PUBLIC key plus (if signed in) the user's own JWT
        return await self.request(method, f"/rest/v1/{table}" + (f"?{query}" if query else ""), key=key, user_jwt=who.access_token if who else None,
                                  headers=h, json=json_body)


class ProbeSetupError(Exception):
    pass


# ------------------------------------------------------------------------------------------- the probe
def _rows(r: httpx.Response) -> list[dict[str, Any]]:
    try:
        data = r.json()
    except ValueError:
        return []
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else ([data] if isinstance(data, dict) and "message" not in data else [])


class SupabaseProbe:
    def __init__(self, target: SupabaseTarget, contract: Contract, db: LiveDb | None = None, api: SupabaseApi | None = None):
        self.t, self.contract, self.db = target, contract, db
        self.api = api or SupabaseApi(target)
        self.result = ProbeResult(launched=True)
        self.sessions: list[Session] = []
        self.cleanup_notes: list[str] = []

    async def run(self) -> ProbeResult:
        res = self.result
        owned = [(r.name, r.owner_field) for r in self.contract.owned_resources]
        if not owned:
            res.untested.append("no owned tables in the contract: nothing to attack through the Supabase API")
            return res
        if not (self.t.anon_key and self.t.service_role_key):
            res.untested.append("SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY are both needed to create and sign in test users")
            return res
        try:
            a = await self._user("A")
            b = await self._user("B")
            for s in (a, b):
                await self.api.sign_in(s)
            for table, owner_col in owned:
                await self._table(table, owner_col, a, b)
        except ProbeSetupError as e:
            res.untested.append(f"Supabase probe could not start: {redact(str(e))}")
        except httpx.HTTPError as e:
            res.untested.append(f"Supabase probe could not reach the project: {type(e).__name__}")
        finally:
            await self._cleanup([t for t, _ in owned], dict(owned))
            await self.api.aclose()
        res.notes.append(f"supabase probe: {self.api.calls} API call(s) to the {self.t.backend} backend; test users and rows deleted" )
        res.notes += self.cleanup_notes
        return res

    async def _user(self, name: str) -> Session:
        s = await self.api.create_user(name)
        self.sessions.append(s)  # registered BEFORE anything else can fail, so the finally block always removes it
        return s

    # -------------------------------------------------------------------------------- one table
    async def _table(self, table: str, owner_col: str, a: Session, b: Session) -> None:
        res = self.result
        res.tested_tables.append(table)
        cols = self.db.columns(table) if self.db else []
        text_col = next((c["name"] for c in cols if c["type"] in ("text", "character varying") and c["name"] != owner_col and c["name"] != "id"), "title")
        canary = new_canary("A")
        row = await self._seed(table, owner_col, text_col, cols, a, canary)
        if row is None:
            res.untested.append(f"{table}: could not plant a row owned by user A (see notes)")
            return
        row_id = str(row["id"])
        label = f"/rest/v1/{table}"
        file = LIVE_FILE_PREFIX + table

        # --- owner oracles
        r = await self.api.rest("GET", table, f"select=*&id=eq.{row_id}", who=a)
        reads = canary in r.text
        res.oracles[f"A can read own {table}"] = reads
        mark = new_canary("A")
        r = await self.api.rest("PATCH", table, f"id=eq.{row_id}", who=a, json_body={text_col: mark})
        updates = bool(_rows(r)) and r.status_code < 300
        res.oracles[f"A can update own {table}"] = updates

        def check(attack: str, rule: str, actor: str, method: str, route: str, r: httpx.Response, hit: bool, oracle_ok: bool) -> None:
            verdict = "PROVEN" if hit else ("HELD" if oracle_ok else "INCONCLUSIVE")
            note = "" if verdict != "INCONCLUSIVE" else "the owner cannot use this table either, so a held result proves nothing"
            res.checks.append(Check(attack=attack, rule=rule, verdict=verdict, actor=actor, resource=table, route_label=f"{method} {route}", file=file, line=1,
                                    function=table, request=f"{method} {route} as {actor}", status=r.status_code, response_text=r.text, note=note))
            res.tested_routes.append(f"{method} {route}")

        # --- attacks
        r = await self.api.rest("GET", table, "select=*&limit=100", who=None)
        check("b", "cross-user-list", "anon", "GET", f"{label}?select=*", r, canary in r.text or mark in r.text, reads)
        r = await self.api.rest("GET", table, "select=*&limit=100", who=b)
        check("b", "cross-user-list", "B", "GET", f"{label}?select=*", r, canary in r.text or mark in r.text, reads)
        r = await self.api.rest("GET", table, f"select=*&id=eq.{row_id}", who=b)
        check("a", "cross-user-read", "B", "GET", f"{label}?id=eq.<A's id>", r, canary in r.text or mark in r.text, reads)
        evil = new_canary("B")
        r = await self.api.rest("PATCH", table, f"id=eq.{row_id}", who=b, json_body={text_col: evil})
        check("d", "cross-user-write", "B", "PATCH", f"{label}?id=eq.<A's id>", r, r.status_code < 300 and bool(_rows(r)), updates)
        r = await self.api.rest("DELETE", table, f"id=eq.{row_id}", who=b)
        check("d", "cross-user-write", "B", "DELETE", f"{label}?id=eq.<A's id>", r, r.status_code < 300 and bool(_rows(r)), updates)

    async def _seed(self, table: str, owner_col: str, text_col: str, cols: list[dict[str, Any]], a: Session, canary: str) -> dict[str, Any] | None:
        res = self.result
        body: dict[str, Any] = {owner_col: a.user_id, text_col: canary}
        for c in cols:  # every other required text column also gets a canary; anything we cannot fill makes the table UNTESTED
            if c["name"] in body or c["default"] or c["nullable"] or c["name"] == "id":
                continue
            if c["type"] in ("text", "character varying"):
                body[c["name"]] = canary
            else:
                res.notes.append(f"{table}: required column {c['name']} ({c['type']}) cannot be filled automatically")
                return None
        r = await self.api.rest("POST", table, "", who=a, json_body=body)
        rows = _rows(r)
        if r.status_code < 300 and rows and "id" in rows[0]:
            return rows[0]
        res.notes.append(f"{table}: inserting as user A through the API failed (HTTP {r.status_code}); trying the database")
        if self.db:
            rid = self.db.insert_row(table, body)
            if rid:
                return {"id": rid, **body}
        return None

    # -------------------------------------------------------------------------------- cleanup (always)
    async def _cleanup(self, tables: list[str], owners: dict[str, str]) -> None:
        ids = [s.user_id for s in self.sessions]
        if self.db:
            for table in tables:
                try:
                    n = self.db.delete_owned_rows(table, owners[table], ids)
                    self.cleanup_notes.append(f"cleanup: removed {n} probe row(s) from {table}")
                except Exception as e:  # noqa: BLE001
                    self.cleanup_notes.append(f"cleanup: could not remove probe rows from {table}: {type(e).__name__}")
        failed = []
        for s in self.sessions:
            try:
                if not await self.api.delete_user(s.user_id):
                    failed.append(s.user_id)
            except Exception:  # noqa: BLE001 - keep going: delete as many as possible
                failed.append(s.user_id)
        try:
            left: list[str] = []
            for attempt in range(4):  # a deleted user can still be listed for a moment, or a delete can hit a transient error: look again, delete again
                try:
                    left = await self.api.leftover_probe_users()
                except Exception as e:  # noqa: BLE001
                    self.cleanup_notes.append(f"cleanup: could not verify that no probe user is left ({type(e).__name__})")
                    return
                if not left:
                    break
                for uid in left:
                    try:
                        await self.api.delete_user(uid)
                    except Exception:  # noqa: BLE001
                        pass
                if self.api.delay:
                    await asyncio.sleep(1.0 * (attempt + 1))
            else:
                try:
                    left = await self.api.leftover_probe_users()
                except Exception:  # noqa: BLE001
                    pass
            if left:
                self.cleanup_notes.append(f"cleanup WARNING: {len(left)} probe user(s) may remain in the project: delete users whose email starts with '{PROBE_EMAIL_PREFIX}'")
            else:
                self.cleanup_notes.append("cleanup verified: no probe user is left in the project")
        finally:
            if self.db:
                try:
                    self.db.close()
                except Exception:  # noqa: BLE001
                    pass
