"""An in-memory stand-in for the parts of Supabase the probe talks to: the Auth admin API, password sign-in and PostgREST with row-level security.

`variant` decides what RLS does to the `notes` table, exactly like the demo's variants:
  A  RLS off: everyone (even anon) reads and changes every row
  B  policy checks the ROLE: any signed-in user can use every row, anon cannot
  C  owner only: a row is visible and changeable only by its owner
Used with httpx.MockTransport, so no network is involved.
"""
from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

SECRET = "sb_" + "secret_" + "FAKEfakeFAKEfakeFAKE1234"
PUBLISHABLE = "sb_" + "publishable_" + "FAKEfakeFAKEfakeFAKE1234"


class FakeSupabase:
    def __init__(self, variant: str = "C", *, flaky_user_deletes: int = 0, insert_denied: bool = False, rate_limit_first: int = 0):
        self.variant = variant
        self.users: dict[str, dict[str, Any]] = {}
        self.notes: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.flaky_user_deletes = flaky_user_deletes
        self.insert_denied = insert_denied
        self.rate_limit_first = rate_limit_first
        self.seen_headers: list[dict[str, str]] = []

    # ---------------------------------------------------------------------------------
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _json(self, status: int, body: Any) -> httpx.Response:
        return httpx.Response(status, json=body)

    def _caller(self, req: httpx.Request) -> str | None:
        auth = req.headers.get("authorization", "")
        if auth.startswith("Bearer fakejwt-"):
            uid = auth.removeprefix("Bearer fakejwt-")
            return uid if uid in self.users else None
        return None

    def handle(self, req: httpx.Request) -> httpx.Response:
        url = urlparse(str(req.url))
        path, q = url.path, parse_qs(url.query)
        self.calls.append((req.method, path))
        self.seen_headers.append(dict(req.headers))
        if self.rate_limit_first > 0:
            self.rate_limit_first -= 1
            return httpx.Response(429, headers={"retry-after": "0"}, json={"message": "slow down"})
        key = req.headers.get("apikey", "")
        # --- Auth
        if path == "/auth/v1/admin/users" and req.method == "POST":
            if key != SECRET:
                return self._json(401, {"message": "bad key"})
            body = json.loads(req.content)
            uid = str(uuid.uuid4())
            self.users[uid] = {"id": uid, "email": body["email"], "password": body["password"]}
            return self._json(200, {"id": uid, "email": body["email"]})
        if path == "/auth/v1/admin/users" and req.method == "GET":
            return self._json(200, {"users": [{"id": u["id"], "email": u["email"]} for u in self.users.values()]})
        if path.startswith("/auth/v1/admin/users/") and req.method == "DELETE":
            uid = path.rsplit("/", 1)[1]
            if self.flaky_user_deletes > 0:
                self.flaky_user_deletes -= 1
                return self._json(500, {"message": "transient"})
            self.users.pop(uid, None)
            for nid in [n for n, r in self.notes.items() if r["user_id"] == uid]:
                del self.notes[nid]  # ON DELETE CASCADE
            return self._json(200, {})
        if path == "/auth/v1/token" and req.method == "POST":
            body = json.loads(req.content)
            for u in self.users.values():
                if u["email"] == body["email"] and u["password"] == body["password"]:
                    return self._json(200, {"access_token": f"fakejwt-{u['id']}", "token_type": "bearer", "user": {"id": u["id"]}})
            return self._json(400, {"message": "invalid login"})
        # --- PostgREST
        if path == "/rest/v1/notes":
            return self._rest(req, q)
        return self._json(404, {"message": "not found"})

    def _visible(self, caller: str | None, row: dict[str, Any]) -> bool:
        if self.variant == "A":
            return True
        if self.variant == "B":
            return caller is not None
        return caller is not None and row["user_id"] == caller

    def _filter(self, q: dict[str, list[str]], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if "id" in q and q["id"][0].startswith("eq."):
            rows = [r for r in rows if r["id"] == q["id"][0][3:]]
        return rows

    def _rest(self, req: httpx.Request, q: dict[str, list[str]]) -> httpx.Response:
        caller = self._caller(req)
        if req.method == "POST":
            if self.insert_denied:
                return self._json(403, {"message": "new row violates row-level security policy"})
            body = json.loads(req.content)
            if self.variant == "C" and body.get("user_id") != caller:
                return self._json(403, {"message": "new row violates row-level security policy"})
            if self.variant == "B" and caller is None:
                return self._json(401, {"message": "permission denied"})
            nid = str(uuid.uuid4())
            row = {"id": nid, "user_id": body["user_id"], "title": body.get("title", ""), "body": body.get("body", "")}
            self.notes[nid] = row
            return self._json(201, [row])
        rows = [r for r in self._filter(q, list(self.notes.values())) if self._visible(caller, r)]
        if req.method == "GET":
            return self._json(200, rows)
        if req.method == "PATCH":
            patch = json.loads(req.content)
            for r in rows:
                r.update(patch)
            return self._json(200, rows)
        if req.method == "DELETE":
            for r in rows:
                self.notes.pop(r["id"], None)
            return self._json(200, rows)
        return self._json(405, {})


class FakeDb:
    """Stands in for LiveDb."""

    def __init__(self, fake: FakeSupabase, columns: list[dict[str, Any]] | None = None):
        self.fake = fake
        self._cols = columns if columns is not None else [
            {"name": "id", "type": "uuid", "nullable": False, "default": "gen_random_uuid()"},
            {"name": "user_id", "type": "uuid", "nullable": False, "default": None},
            {"name": "title", "type": "text", "nullable": False, "default": "''::text"},
            {"name": "body", "type": "text", "nullable": False, "default": "''::text"},
        ]
        self.closed = False

    def columns(self, table):
        return self._cols

    def delete_owned_rows(self, table, owner_col, owner_ids):
        gone = [n for n, r in self.fake.notes.items() if r[owner_col] in owner_ids]
        for n in gone:
            del self.fake.notes[n]
        return len(gone)

    def insert_row(self, table, row):
        nid = str(uuid.uuid4())
        self.fake.notes[nid] = {"id": nid, **row}
        return nid

    def close(self):
        self.closed = True
