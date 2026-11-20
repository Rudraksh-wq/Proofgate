"""HTTP identities for the probe: User A, User B, User C, admin and anonymous (plan 3.2 step 3)."""
from __future__ import annotations

import asyncio
import re
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

TOKEN_KEYS = ("token", "access_token", "jwt", "api_key", "auth_token", "key")
ID_KEYS = ("id", "user_id", "uid")
TIMEOUT = 15.0


@dataclass
class Resp:
    status: int | None  # None = timeout / connection error
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def server_error(self) -> bool:
        return self.status is None or self.status >= 500

    def json(self) -> Any:
        import json

        try:
            return json.loads(self.text)
        except ValueError:
            return None


@dataclass
class Identity:
    name: str
    email: str
    password: str
    token: str | None = None
    user_id: int | None = None
    client: httpx.AsyncClient | None = field(default=None, repr=False)

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}


class Http:
    """One base URL, many identities. Never raises: a failed request becomes Resp(status=None)."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self._anon = httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)
        self._identities: list[Identity] = []

    async def aclose(self) -> None:
        await self._anon.aclose()
        for i in self._identities:
            if i.client:
                await i.client.aclose()

    async def request(self, who: Identity | None, method: str, path: str, **kw: Any) -> Resp:
        client = who.client if who and who.client else self._anon
        headers = {**(who.headers() if who else {}), **kw.pop("headers", {})}
        last = Resp(None, error="unknown")
        for attempt in range(2):  # one retry: a loaded machine can drop a single connection without the app being at fault
            try:
                r = await client.request(method, self.base + path, headers=headers, **kw)
                return Resp(r.status_code, r.text)
            except httpx.TimeoutException:
                last = Resp(None, error="timeout")
            except httpx.HTTPError as e:
                last = Resp(None, error=type(e).__name__)
            await asyncio.sleep(0.3)
        return last

    async def new_identity(self, name: str, signup_path: str, login_path: str | None) -> Identity | None:
        tag = secrets.token_hex(3)
        ident = Identity(name, f"pg-{name.lower()}-{tag}@probe.example.test", "Pg!" + secrets.token_hex(8),
                         client=httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False))
        self._identities.append(ident)
        body = {"email": ident.email, "password": ident.password, "display_name": f"probe {name}",
                "username": f"pg_{name.lower()}_{tag}", "name": f"probe {name}"}
        r = await self.request(ident, "POST", signup_path, json=body)
        if not r.ok:
            return None
        data = r.json() if isinstance(r.json(), dict) else {}
        ident.token = next((str(data[k]) for k in TOKEN_KEYS if data.get(k)), None)
        ident.user_id = next((int(data[k]) for k in ID_KEYS if isinstance(data.get(k), int)), None)
        if ident.token is None and login_path:
            r = await self.request(ident, "POST", login_path, json={"email": ident.email, "password": ident.password,
                                                                    "username": body["username"]})
            data = r.json() if r.ok and isinstance(r.json(), dict) else {}
            ident.token = next((str(data[k]) for k in TOKEN_KEYS if data.get(k)), None)
            ident.user_id = ident.user_id or next((int(data[k]) for k in ID_KEYS if isinstance(data.get(k), int)), None)
        return ident


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")


def ident(name: str) -> str:
    """An SQL identifier that is safe to put between double quotes; anything else is refused."""
    if not isinstance(name, str) or not _IDENT.fullmatch(name):
        raise ValueError(f"not a plain SQL identifier: {name!r}")
    return name


def safe_assignments(columns: dict) -> str:
    """'"a" = ?, "b" = ?' for validated column names."""
    return ", ".join(f'"{ident(c)}" = ?' for c in columns)


class TempDb:
    """Read/write access to the throwaway SQLite database the app under test is using."""

    def __init__(self, path: Path | None):
        self.path = path

    def _conn(self) -> sqlite3.Connection:
        assert self.path is not None
        c = sqlite3.connect(self.path, timeout=5)
        c.row_factory = sqlite3.Row
        return c

    @property
    def available(self) -> bool:
        return self.path is not None and self.path.is_file()

    def tables(self) -> list[str]:
        if not self.available:
            return []
        with closing(self._conn()) as c:
            return [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]

    def columns(self, table: str) -> list[sqlite3.Row]:
        if not self.available or table not in self.tables():
            return []
        with closing(self._conn()) as c:
            return list(c.execute(f'PRAGMA table_info("{ident(table)}")'))

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        if not self.available:
            return None
        with closing(self._conn()) as c:
            return c.execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple = ()) -> None:
        if self.available:
            with closing(self._conn()) as c:
                c.execute(sql, params)
                c.commit()
