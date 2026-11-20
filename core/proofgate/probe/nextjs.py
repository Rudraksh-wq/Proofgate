"""Next.js route-handler replay for the Supabase probe (plan 3.2).

The probe already attacks the database through the API. This module attacks the APP's own route handlers: it finds `app/**/route.ts` files with a
dynamic id segment that read or write a table the contract says is owned (`from("notes")`), starts `next dev` on a random localhost port pointed at
the SAME Supabase project, and calls those routes as user B with user A's row id. A canary from A's row in B's response, or A's row changed by B, is
PROVEN: it catches a route that checks "someone is signed in" and then uses the service-role client, which RLS can never stop.

Routes that cannot be replayed (no dynamic id, no node_modules, the dev server did not start) are listed as UNTESTED, never as safe.
The dev server gets ONLY the three Supabase variables the app reads; our own environment (Gemini keys, tokens) is not passed on.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ..layers.base import SKIP_DIRS, iter_files, read_text
from ..redact import new_canary, redact
from ..runner import _kill_tree
from .result import Check

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_EXPORT = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b")
_FROM = re.compile(r"""\.from\(\s*["'](\w+)["']\s*\)""")
_SQL_FROM = re.compile(r"""(?i)\bfrom\s+(?:public\.)?(\w+)""")  # a table named inside SQL text (rpc("run_sql", {query: `select ... from public.notes ...`}))
_QUERY = re.compile(r"""searchParams\.get\(\s*["'](\w+)["']""")
SQLI_PAYLOAD = "zzz%' OR '1'='1' OR title LIKE '%"  # comment-free on purpose: some drivers reject `--` and `/*`
_SEG = re.compile(r"\[(?:\.\.\.)?(\w+)\]")
READY_TIMEOUT_S = 120.0
REQUEST_TIMEOUT_S = 90.0  # the first request to a route compiles it


class NextUnavailable(Exception):
    """The replay cannot run here (no node_modules, no node, the dev server did not start): UNTESTED, never safe."""


@dataclass(frozen=True)
class NextRoute:
    file: str  # relative to the project, e.g. app/api/notes/[id]/route.ts
    method: str
    line: int
    pattern: str  # /api/notes/[id]
    params: tuple[str, ...]
    tables: tuple[str, ...]
    query_params: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.method} {self.pattern}"

    def fill(self, value: str) -> str:
        return _SEG.sub(value, self.pattern)


def discover_routes(project: Path) -> list[NextRoute]:
    out: list[NextRoute] = []
    app = project / "app"
    if not app.is_dir():
        return out
    for p in iter_files(project):
        if p.name not in ("route.ts", "route.js", "route.tsx", "route.jsx") or app not in p.parents:
            continue
        text = read_text(p) or ""
        rel = p.relative_to(project).as_posix()
        pattern = "/" + "/".join(s for s in p.parent.relative_to(app).parts if not (s.startswith("(") and s.endswith(")")))
        tables = tuple(sorted(set(_FROM.findall(text)) | set(_SQL_FROM.findall(text))))
        query = tuple(dict.fromkeys(_QUERY.findall(text)))
        for m in _EXPORT.finditer(text):
            out.append(NextRoute(rel, m.group(1), text.count("\n", 0, m.start()) + 1, pattern or "/", tuple(_SEG.findall(pattern)), tables, query))
    return sorted(out, key=lambda r: (r.file, r.line))


# ------------------------------------------------------------------------------------------- the session cookie @supabase/ssr reads
def session_cookies(ref: str, session: dict[str, Any]) -> dict[str, str]:
    """`sb-<ref>-auth-token` holding the signed-in session, in the base64url form @supabase/ssr writes, chunked at 3180 characters like the library does."""
    value = "base64-" + base64.urlsafe_b64encode(json.dumps(session, separators=(",", ":")).encode()).decode().rstrip("=")
    name = f"sb-{ref}-auth-token"
    if len(value) <= 3180:
        return {name: value}
    return {f"{name}.{i}": value[k:k + 3180] for i, k in enumerate(range(0, len(value), 3180))}


def cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ------------------------------------------------------------------------------------------- next dev
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class NextDev:
    """`next dev` on a random localhost port with a minimal environment. Use: `async with NextDev(project, env) as dev: dev.url`."""

    def __init__(self, project: Path, supabase_env: dict[str, str]):
        self.project, self.supabase_env = Path(project).resolve(), supabase_env
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._proc: asyncio.subprocess.Process | None = None
        self._dir = Path(tempfile.mkdtemp(prefix="proofgate-next-"))
        self._log = self._dir / "next.log"

    async def __aenter__(self) -> "NextDev":
        # node_modules may be in a parent folder (a fix-tournament copy lives inside the real project, so Node finds the real packages by walking up)
        nxt = next((d / "node_modules" / "next" / "dist" / "bin" / "next" for d in (self.project, *self.project.parents)
                    if (d / "node_modules" / "next" / "dist" / "bin" / "next").is_file()), self.project / "node_modules" / "next" / "dist" / "bin" / "next")
        node = shutil.which("node")
        if not nxt.is_file() or not node:
            shutil.rmtree(self._dir, ignore_errors=True)
            raise NextUnavailable("node_modules/next or node is missing: run `npm install` in the project")
        keep = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT"}
        env = {k: v for k, v in os.environ.items() if k.upper() in keep}
        env.update(self.supabase_env)
        env.update({"NEXT_TELEMETRY_DISABLED": "1", "PORT": str(self.port)})
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        log = open(self._log, "wb")
        try:
            self._proc = await asyncio.create_subprocess_exec(node, str(nxt), "dev", "-p", str(self.port), "-H", "127.0.0.1", cwd=str(self.project), env=env,
                                                              stdin=asyncio.subprocess.DEVNULL, stdout=log, stderr=log, **kwargs)
        finally:
            log.close()
        try:
            await self._wait_ready()
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self

    async def _wait_ready(self) -> None:
        assert self._proc is not None
        deadline = time.monotonic() + READY_TIMEOUT_S
        async with httpx.AsyncClient(timeout=10.0) as c:
            while time.monotonic() < deadline:
                if self._proc.returncode is not None:
                    raise NextUnavailable(f"next dev exited during start-up (code {self._proc.returncode}): {self.log_tail()}")
                try:
                    await c.get(self.url + "/")
                    return  # any answer (even an error page) means the server is up
                except httpx.TransportError:
                    await asyncio.sleep(0.5)
        raise NextUnavailable(f"next dev did not answer within {READY_TIMEOUT_S:g}s: {self.log_tail()}")

    def log_tail(self, n: int = 300) -> str:
        try:
            return redact(self._log.read_text(encoding="utf-8", errors="replace")[-n:].strip())
        except OSError:
            return ""

    async def __aexit__(self, *exc) -> None:
        if self._proc is not None:
            _kill_tree(self._proc)
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=15)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
        for _ in range(25):
            shutil.rmtree(self._dir, ignore_errors=True)
            if not self._dir.exists():
                break
            await asyncio.sleep(0.2)


# ------------------------------------------------------------------------------------------- the replay
class NextReplay:
    """Called by the Supabase probe for each table, while user A's planted row exists."""

    def __init__(self, project: Path, ref: str, routes: list[NextRoute], supabase_env: dict[str, str], *, dev_factory=None, transport=None):
        self.project, self.ref, self.routes, self.env = project, ref, routes, supabase_env
        self._transport = transport
        self._dev_factory = dev_factory or (lambda: NextDev(project, supabase_env))
        self._dev: NextDev | None = None
        self.unavailable: str | None = None

    async def _server(self) -> NextDev | None:
        if self._dev is None and self.unavailable is None:
            dev = self._dev_factory()
            try:
                await dev.__aenter__()
                self._dev = dev
            except NextUnavailable as e:
                self.unavailable = str(e)
        return self._dev

    async def close(self) -> None:
        if self._dev is not None:
            await self._dev.__aexit__(None, None, None)
            self._dev = None

    def routes_for(self, table: str) -> tuple[list[NextRoute], list[NextRoute], list[NextRoute]]:
        """(routes with a dynamic id, GET routes with a query parameter, other routes that touch the table and cannot be replayed)."""
        touching = [r for r in self.routes if table in r.tables]
        by_id = [r for r in touching if r.params and r.method in ("GET", "PUT", "PATCH", "DELETE")]
        by_query = [r for r in touching if not r.params and r.method == "GET" and r.query_params]
        rest = [r for r in touching if r not in by_id and r not in by_query]
        return by_id, by_query, rest

    async def replay_table(self, result, table: str, row_id: str, canaries: list[str], text_col: str, a, b) -> None:
        replayable, searchable, other = self.routes_for(table)
        for r in other:
            result.untested.append(f"{r.label} ({r.file}) touches {table} but has no dynamic id or query parameter to replay with")
        if not replayable and not searchable:
            return
        dev = await self._server()
        if dev is None:
            result.untested.append(f"Next.js routes for {table} not replayed: {redact(self.unavailable or '')}")
            return
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S, transport=self._transport) as c:
            owner_ok: dict[str, bool] = {}

            async def call(route: NextRoute, who, body: dict | None = None) -> httpx.Response | None:
                headers = {"Cookie": cookie_header(session_cookies(self.ref, who.session)), "Content-Type": "application/json"}
                try:
                    return await c.request(route.method, dev.url + route.fill(row_id), headers=headers, json=body if route.method in ("PUT", "PATCH") else None)
                except httpx.HTTPError as e:
                    result.notes.append(f"{route.label}: request failed ({type(e).__name__})")
                    return None

            for route in searchable:  # first, while A's row still holds its canary: a query parameter that may reach SQL, asked as B with a comment-free injection payload
                result.tested_routes.append(route.label)
                param = route.query_params[0]

                async def search(who, value: str) -> httpx.Response | None:
                    headers = {"Cookie": cookie_header(session_cookies(self.ref, who.session))}
                    try:
                        return await c.get(dev.url + route.pattern, params={param: value}, headers=headers)
                    except httpx.HTTPError as e:
                        result.notes.append(f"{route.label}: request failed ({type(e).__name__})")
                        return None

                mine = await search(a, canaries[-1])  # the owner searches for their own text: the route works if it finds it
                ok = mine is not None and mine.status_code < 300 and canaries[-1] in mine.text
                result.oracles[f"A can search own {table} through {route.label}"] = ok
                theirs = await search(b, SQLI_PAYLOAD)
                if theirs is None:
                    result.untested.append(f"{route.label}: no answer when replayed as user B")
                    continue
                hit = theirs.status_code < 300 and any(c_ in theirs.text for c_ in canaries)
                verdict = "PROVEN" if hit else ("HELD" if ok else "INCONCLUSIVE")
                result.checks.append(Check(
                    attack="e", rule="sql-injection", verdict=verdict, actor="B", resource=table, route_label=route.label, file=route.file, line=route.line,
                    function=route.method, request=f"{route.method} {route.pattern}?{param}=<injection payload> as B", status=theirs.status_code,
                    response_text=theirs.text, note="" if verdict != "INCONCLUSIVE" else "the owner cannot search their own rows either, so a held result proves nothing"))
            for route in sorted(replayable, key=lambda r: r.method != "GET"):  # reads first: a write would replace the canary
                result.tested_routes.append(route.label)
                oracle_key = f"A can use {route.label} for own {table}"
                evil = new_canary("B")
                writes = route.method in ("PUT", "PATCH")
                body = {text_col: evil} if writes else None
                mine = await call(route, a, {text_col: new_canary("A")} if writes else None)
                owner_ok[route.label] = mine is not None and mine.status_code < 300
                result.oracles[oracle_key] = owner_ok[route.label]
                theirs = await call(route, b, body)
                if mine is not None and mine.status_code >= 500:
                    result.notes.append(f"{route.label}: the app answered HTTP {mine.status_code} to its owner. dev server log: {dev.log_tail(400)}")
                if theirs is None:
                    result.untested.append(f"{route.label}: no answer when replayed as user B")
                    continue
                if route.method == "GET":
                    hit = theirs.status_code < 300 and any(c_ in theirs.text for c_ in canaries)
                    rule = "cross-user-read"
                else:
                    hit = theirs.status_code < 300 and evil in theirs.text
                    rule = "cross-user-write"
                verdict = "PROVEN" if hit else ("HELD" if owner_ok[route.label] else "INCONCLUSIVE")
                result.checks.append(Check(
                    attack="a" if route.method == "GET" else "d", rule=rule, verdict=verdict, actor="B", resource=table, route_label=route.label,
                    file=route.file, line=route.line, function=route.method, request=f"{route.method} {route.pattern} as B (with A's id)",
                    status=theirs.status_code, response_text=theirs.text,
                    note="" if verdict != "INCONCLUSIVE" else "the owner cannot use this route either, so a held result proves nothing"))
