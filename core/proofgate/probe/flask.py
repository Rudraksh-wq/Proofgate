"""Doppelganger probe for Flask apps (plan 3.2).

Creates User A, User B, User C, an admin and an anonymous visitor against a throwaway copy of the app, seeds User A's
data with canary strings, then attacks as the other identities in a fixed order so tests do not pollute each other:

  a) read A's item as B and anonymous        b) list with ?user_id=<A> as B (and a plain list as B)
  c) admin routes as anonymous and as B      d) SQL and shell injection as B
  e) write A's item as B, then look at it    f) fresh user C sends role=admin to its own profile, then tries an admin route

Verdicts: PROVEN (a canary or A's e-mail crossed a boundary) | HELD (refused) | INCONCLUSIVE (5xx/timeout/ambiguous)
| UNTESTED (could not be set up: reported, never called safe). Owner oracles ("the feature still works") run first, on
pristine data.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import quote

from ..models import Contract
from ..redact import new_canary
from .discover import Route, discover_routes, matches_any
from .result import Check, ProbeResult
from .session import Http, Identity, Resp, TempDb

ADMIN_FIELDS = ({"role": "admin"}, {"is_admin": 1}, {"is_admin": True}, {"admin": True}, {"is_superuser": True})
ADMIN_COLUMNS = {"role": "admin", "is_admin": 1, "admin": 1, "is_superuser": 1}
SQLI_PAYLOADS = [  # comment-free payloads FIRST: a partial fix may strip "--"
    "zzz%' OR '1'='1' OR title LIKE '%", "x' OR '1'='1", "zzz%' OR 1=1 OR title LIKE '%", "x' OR '1'='1' --",
    "x\" OR \"1\"=\"1",
]
SHELL_PAYLOADS_POSIX = ["$((6*7))", "; expr 6 \\* 7 #"]
SHELL_PAYLOADS_WINDOWS = ["& set /a 6*7", "$((6*7))"]
OWNER_PARAMS = ("user_id", "owner_id", "owner", "author_id", "uid")
SEARCH_WORDS = ("search", "find", "query", "export", "lookup")
_SKIP_COLS = re.compile(r"(_at$|^created|^updated|token|password|hash)", re.IGNORECASE)


def _masked(route: Route, resource: str) -> str:
    """The route path with its id placeholder replaced by a label, so a report never holds a real row id."""
    return re.sub(r"<[^>]+>", f"«A_{resource}_id»", route.path)


def shell_payloads() -> list[str]:
    return SHELL_PAYLOADS_WINDOWS if sys.platform == "win32" else SHELL_PAYLOADS_POSIX


class FlaskProbe:
    def __init__(self, project: str | Path, contract: Contract, base_url: str, *, db_path: Path | None = None,
                 routes: list[Route] | None = None):
        self.project = Path(project).resolve()
        self.contract = contract
        self.http = Http(base_url)
        self.db = TempDb(db_path)
        self.routes = routes if routes is not None else discover_routes(self.project)
        self.result = ProbeResult(launched=True)
        self.A = self.B = self.C = self.admin = None  # type: ignore[assignment]
        self.canary_a = new_canary("A")
        self.canary_b = new_canary("B")
        self.seeded: dict[str, dict] = {}  # resource -> {"id": int, "canary": str}

    # ------------------------------------------------------------------ route helpers
    def _routes(self, method: str, *, with_id: bool | None = None, mention: str | None = None) -> list[Route]:
        out = [r for r in self.routes if r.method == method]
        if with_id is not None:
            out = [r for r in out if r.has_id == with_id]
        if mention:
            out = [r for r in out if mention.lower() in r.path.lower()]
        return out

    def _find(self, method: str, word: str, *, with_id: bool | None = None) -> Route | None:
        hits = self._routes(method, with_id=with_id, mention=word)
        return hits[0] if hits else None

    def _admin_routes(self) -> list[Route]:
        pats = self.contract.admin_only_routes
        return [r for r in self.routes if r.method == "GET" and not r.has_id and matches_any(r.path, pats)]

    def _resource_routes(self, name: str) -> dict[str, Route | None]:
        return {
            "create": self._find("POST", name, with_id=False),
            "list": self._find("GET", name, with_id=False),
            "read": self._find("GET", name, with_id=True),
            "update": self._find("PUT", name, with_id=True) or self._find("PATCH", name, with_id=True),
        }

    def _check(self, **kw) -> Check:
        c = Check(**kw)
        self.result.checks.append(c)
        if c.route_label and c.verdict != "UNTESTED" and c.route_label not in self.result.tested_routes:
            self.result.tested_routes.append(c.route_label)
        return c

    def _verdict(self, resp: Resp, leaked: bool) -> str:
        if leaked:
            return "PROVEN"
        return "INCONCLUSIVE" if resp.server_error else "HELD"

    # ------------------------------------------------------------------ setup: identities + seed
    async def setup(self) -> bool:
        signup = next((r for r in self.routes if r.method == "POST" and re.search(r"sign-?up|register", r.path, re.I)), None)
        login = next((r for r in self.routes if r.method == "POST" and re.search(r"log-?in|sign-?in|token", r.path, re.I)), None)
        if signup is None:
            self.result.untested.append("everything: no signup/register route was found, so no second user could be created "
                                        "(add the route to proofgate.routes.yml)")
            return False
        made = {}
        for name in ("A", "B", "C", "admin"):
            made[name] = await self.http.new_identity(name, signup.path, login.path if login else None)
        self.A, self.B, self.C, self.admin = made["A"], made["B"], made["C"], made["admin"]
        if self.A is None or self.B is None:
            self.result.untested.append("everything: could not create two ordinary users through the signup route")
            return False
        for ident in (self.A, self.B, self.C, self.admin):
            if ident and ident.user_id is None:
                row = self.db.one("SELECT id FROM users WHERE email = ?", (ident.email,))
                ident.user_id = int(row["id"]) if row else None
        if self.admin is not None:
            self._promote_admin(self.admin)
        return True

    def _promote_admin(self, ident: Identity) -> None:
        cols = {r["name"] for r in self.db.columns("users")}
        sets = {c: v for c, v in ADMIN_COLUMNS.items() if c in cols}
        if not sets:
            self.admin = None
            self.result.untested.append("admin: no role/is_admin column in the users table, so no admin user could be seeded")
            return
        assign = ", ".join(f'"{c}" = ?' for c in sets)
        self.db.execute(f"UPDATE users SET {assign} WHERE email = ?", (*sets.values(), ident.email))

    def _row_body(self, table: str, owner_field: str, canary: str) -> dict:
        body: dict = {}
        for col in self.db.columns(table):
            name, typ = col["name"], (col["type"] or "").upper()
            if col["pk"] or name == owner_field or _SKIP_COLS.search(name):
                continue
            if "INT" in typ or "BOOL" in typ:
                body[name] = 1
            elif "REAL" in typ or "FLOAT" in typ or "DOUBLE" in typ or "NUM" in typ:
                body[name] = 1.5
            elif "BLOB" in typ:
                continue
            else:
                body[name] = f"{canary} {name}"
        return body

    async def _seed_item(self, resource, who: Identity, canary: str) -> dict | None:
        routes = self._resource_routes(resource.name)
        create = routes["create"]
        if create is None or not self.db.columns(resource.name) or who.user_id is None:
            return None
        r = await self.http.request(who, "POST", create.path, json=self._row_body(resource.name, resource.owner_field, canary))
        if not r.ok:
            return None
        row = self.db.one(f'SELECT id FROM "{resource.name}" WHERE "{resource.owner_field}" = ? ORDER BY id DESC LIMIT 1',
                          (who.user_id,))
        data = r.json() if isinstance(r.json(), dict) else {}
        item_id = int(row["id"]) if row else (data.get("id") if isinstance(data.get("id"), int) else None)
        return {"id": item_id, "canary": canary} if item_id is not None else None

    # ------------------------------------------------------------------ owner oracles ("the feature still works")
    async def oracles(self) -> dict[str, bool | None]:
        o: dict[str, bool | None] = {k: None for k in (
            "owner_can_read", "owner_can_list", "owner_can_update", "owner_can_search", "admin_can_use_admin_routes",
            "owner_can_edit_profile_field")}
        for res in self.contract.owned_resources:
            if res.name not in self.db.tables() or self.A is None:
                continue
            routes = self._resource_routes(res.name)
            canary = new_canary("A")
            item = await self._seed_item(res, self.A, canary)
            if item is None:
                continue
            if routes["read"]:
                r = await self.http.request(self.A, "GET", routes["read"].fill(item["id"]))
                o["owner_can_read"] = r.ok and canary in r.text
            if routes["list"]:
                r = await self.http.request(self.A, "GET", routes["list"].path)
                o["owner_can_list"] = r.ok and canary in r.text
            search = next((r for r in self.routes if r.method == "GET" and not r.has_id and "search" in r.path.lower()), None)
            if search:  # a search route whose parameter we could not read from the source is still searched with ?q=
                r = await self.http.request(self.A, "GET", search.path, params={(search.query_params or ("q",))[0]: canary})
                o["owner_can_search"] = r.ok and canary in r.text
            if routes["update"]:
                new = new_canary("A")
                body = self._row_body(res.name, res.owner_field, new)
                r = await self.http.request(self.A, routes["update"].method, routes["update"].fill(item["id"]), json=body)
                o["owner_can_update"] = r.ok
            break  # one owned resource is enough to calibrate the oracles
        admin_routes = self._admin_routes()
        if admin_routes and self.admin is not None:
            r = await self.http.request(self.admin, "GET", admin_routes[0].path)
            o["admin_can_use_admin_routes"] = r.ok
        profile = self._profile_route()
        field = next(iter(self.contract.profile_editable_fields), None)
        if profile and field and self.A is not None:
            value = "ProofGate " + new_canary("A")[-6:]
            r = await self.http.request(self.A, profile.method, profile.path, json={field: value})
            reflected = None
            if self.db.available:
                row = self.db.one(f'SELECT "{field}" AS v FROM users WHERE email = ?', (self.A.email,))
                reflected = bool(row and row["v"] == value)
            o["owner_can_edit_profile_field"] = r.ok and (reflected if reflected is not None else True)
        return o

    def _profile_route(self) -> Route | None:
        for method in ("PUT", "PATCH", "POST"):
            hit = next((r for r in self._routes(method, with_id=False) if re.search(r"profile|/me\b|account", r.path, re.I)), None)
            if hit:
                return hit
        return None

    # ------------------------------------------------------------------ the attacks, in order a..f
    async def run(self) -> ProbeResult:
        try:
            if not await self.setup():
                return self.result
            self.result.oracles = await self.oracles()
            for res in self.contract.owned_resources:
                if res.name not in self.db.tables():
                    self.result.untested.append(f"{res.name}: no table of that name in the app's database")
                    continue
                item = await self._seed_item(res, self.A, self.canary_a)
                if item is None:
                    self.result.untested.append(f"{res.name}: could not seed a row for User A (no create route or body rejected)")
                    continue
                self.seeded[res.name] = item
                if res.name not in self.result.tested_tables:
                    self.result.tested_tables.append(res.name)
            await self._a_read()
            await self._b_list()
            await self._c_admin()
            await self._d_sqli()
            await self._d_shell()
            await self._e_write()
            await self._f_mass_assign()
        finally:
            await self.http.aclose()
        return self.result

    def _leak(self, text: str, canary: str | None = None) -> bool:
        return (canary or self.canary_a) in text

    # a) read A's item as B and as anonymous
    async def _a_read(self) -> None:
        for res in self.contract.owned_resources:
            item, route = self.seeded.get(res.name), self._resource_routes(res.name)["read"]
            if item is None or route is None:
                if item is not None:
                    self.result.untested.append(f"{res.name}: no GET route with an id was found")
                continue
            for actor, ident in (("B", self.B), ("anon", None)):
                r = await self.http.request(ident, "GET", route.fill(item["id"]))
                self._check(attack="a", rule="cross-user-read", verdict=self._verdict(r, self._leak(r.text)), actor=actor,
                            resource=res.name, route_label=route.label, file=route.file, line=route.line,
                            function=route.function, request=f"GET {_masked(route, res.name)} as {actor}",
                            status=r.status, response_text=r.text)

    # b) list with ?user_id=<A> as B, and a plain list as B
    async def _b_list(self) -> None:
        for res in self.contract.owned_resources:
            item, route = self.seeded.get(res.name), self._resource_routes(res.name)["list"]
            if item is None or route is None or self.A is None:
                continue
            candidates = [*dict.fromkeys([res.owner_field, *route.query_params, *OWNER_PARAMS])]
            plain = await self.http.request(self.B, "GET", route.path)
            self._check(attack="b", rule="cross-user-list", verdict=self._verdict(plain, self._leak(plain.text)), actor="B",
                        resource=res.name, route_label=route.label, file=route.file, line=route.line, function=route.function,
                        request=f"GET {route.path} as B", status=plain.status, response_text=plain.text)
            if self._leak(plain.text):
                continue
            proven = None
            for param in candidates:
                r = await self.http.request(self.B, "GET", route.path, params={param: self.A.user_id})
                if self._leak(r.text):
                    proven = (param, r)
                    break
            if proven:
                param, r = proven
                self._check(attack="b", rule="cross-user-list", verdict="PROVEN", actor="B", resource=res.name,
                            route_label=route.label, file=route.file, line=route.line, function=route.function,
                            request=f"GET {route.path}?{param}=«A_user_id» as B", status=r.status, response_text=r.text)

    # c) admin routes as anonymous and as B (leak = A's e-mail shows up)
    async def _c_admin(self) -> None:
        routes = self._admin_routes()
        if not routes:
            self.result.untested.append("admin routes: no GET route matched the contract's admin-only patterns")
            return
        for route in routes:
            for actor, ident in (("anon", None), ("B", self.B)):
                r = await self.http.request(ident, "GET", route.path)
                leaked = r.ok and self.A is not None and self.A.email in r.text
                verdict = "PROVEN" if leaked else ("INCONCLUSIVE" if (r.server_error or r.ok) else "HELD")
                rule = "admin-route-unauthenticated" if actor == "anon" else "admin-route-missing-role-check"
                self._check(attack="c", rule=rule, verdict=verdict, actor=actor, route_label=route.label, file=route.file,
                            line=route.line, function=route.function, request=f"GET {route.path} as {actor}", status=r.status,
                            response_text=r.text, note="reachable but no other user's data was seen" if (r.ok and not leaked) else "")

    # d) SQL injection as B (leak = A's canary in B's response)
    async def _d_sqli(self) -> None:
        for route in (r for r in self._routes("GET", with_id=False) if r.query_params):
            if route.path in {a.path for a in self._admin_routes()}:
                continue
            res = next((x for x in self.contract.owned_resources if x.name in self.seeded), None)
            if res is None or self.B is None:
                return
            for param in route.query_params:
                base = await self.http.request(self.B, "GET", route.path, params={param: "zzz"})
                if self._leak(base.text) or base.status in (401, 403, 404):
                    continue
                for payload in SQLI_PAYLOADS:
                    r = await self.http.request(self.B, "GET", route.path, params={param: payload})
                    if self._leak(r.text):
                        self._check(attack="d", rule="sql-injection", verdict="PROVEN", actor="B", resource=res.name,
                                    route_label=route.label, file=route.file, line=route.line, function=route.function,
                                    request=f"GET {route.path}?{param}={quote(payload)} as B", status=r.status, response_text=r.text)
                        break
                    if r.server_error:
                        self._check(attack="d", rule="sql-injection", verdict="INCONCLUSIVE", actor="B", resource=res.name,
                                    route_label=route.label, file=route.file, line=route.line, function=route.function,
                                    request=f"GET {route.path}?{param}={quote(payload)} as B", status=r.status,
                                    note="server error on an injection payload")
                        break
                else:
                    self._check(attack="d", rule="sql-injection", verdict="HELD", actor="B", resource=res.name,
                                route_label=route.label, file=route.file, line=route.line, function=route.function,
                                request=f"GET {route.path}?{param}=<payloads> as B", status=base.status)

    # d) shell injection as B (proof = a shell computed 42; the payload text itself contains no "42")
    async def _d_shell(self) -> None:
        if self.B is None:
            return
        for route in (r for r in self._routes("GET", with_id=False) if r.query_params):
            if route.path in {a.path for a in self._admin_routes()}:
                continue
            for param in route.query_params:
                base = await self.http.request(self.B, "GET", route.path, params={param: "proofgate"})
                if base.status in (401, 403, 404) or "42" in base.text:
                    continue
                proven = None
                for payload in shell_payloads():
                    r = await self.http.request(self.B, "GET", route.path, params={param: "pg" + payload})
                    if r.ok and "42" in r.text and "42" not in payload:
                        proven = (payload, r)
                        break
                if proven:
                    payload, r = proven
                    self._check(attack="d", rule="command-injection", verdict="PROVEN", actor="B", route_label=route.label,
                                file=route.file, line=route.line, function=route.function,
                                request=f"GET {route.path}?{param}={quote('pg' + payload)} as B", status=r.status,
                                response_text=r.text, note="a shell evaluated the payload and returned 42")

    # e) write A's item as B, then look at it
    async def _e_write(self) -> None:
        for res in self.contract.owned_resources:
            item, route = self.seeded.get(res.name), self._resource_routes(res.name)["update"]
            if item is None or route is None or self.B is None:
                continue
            body = self._row_body(res.name, res.owner_field, self.canary_b)
            r = await self.http.request(self.B, route.method, route.fill(item["id"]), json=body)
            changed, seen = False, ""
            row = self.db.one(f'SELECT * FROM "{res.name}" WHERE id = ?', (item["id"],))
            if row is not None:
                seen = " ".join(str(row[k]) for k in row.keys())
                changed = self.canary_b in seen
            elif self.A is not None and (read := self._resource_routes(res.name)["read"]):
                after = await self.http.request(self.A, "GET", read.fill(item["id"]))
                seen, changed = after.text, self.canary_b in after.text
            self._check(attack="e", rule="cross-user-write", verdict=self._verdict(r, changed), actor="B", resource=res.name,
                        route_label=route.label, file=route.file, line=route.line, function=route.function,
                        request=f"{route.method} {_masked(route, res.name)} as B", status=r.status,
                        response_text=seen if changed else r.text,
                        note="A's row now holds B's canary" if changed else "")

    # f) a fresh user C sends role=admin to its own profile, then tries an admin route
    async def _f_mass_assign(self) -> None:
        profile, admin_routes = self._profile_route(), self._admin_routes()
        if self.C is None or profile is None:
            self.result.untested.append("profile: no profile-update route or no third user, so mass assignment was not tried")
            return
        before = None
        if admin_routes:
            before = await self.http.request(self.C, "GET", admin_routes[0].path)
        escalated: tuple[dict, Resp] | None = None
        for fields in ADMIN_FIELDS:
            r = await self.http.request(self.C, profile.method, profile.path, json=fields)
            if admin_routes:
                after = await self.http.request(self.C, "GET", admin_routes[0].path)
                if after.ok and (before is None or not before.ok):
                    escalated = (fields, after)
                    break
            else:
                row = self.db.one("SELECT * FROM users WHERE email = ?", (self.C.email,))
                key = next(iter(fields))
                if row is not None and key in row.keys() and str(row[key]).lower() in ("admin", "1", "true"):
                    escalated = (fields, r)
                    break
            if r.server_error:
                break
        if escalated:
            fields, r = escalated
            self._check(attack="f", rule="mass-assignment", verdict="PROVEN", actor="C", victim="admin", route_label=profile.label,
                        file=profile.file, line=profile.line, function=profile.function,
                        request=f"{profile.method} {profile.path} {fields} as C, then the admin route", status=r.status,
                        response_text=r.text, note="C became an admin")
        else:
            self._check(attack="f", rule="mass-assignment", verdict="HELD", actor="C", victim="admin", route_label=profile.label,
                        file=profile.file, line=profile.line, function=profile.function,
                        request=f"{profile.method} {profile.path} <admin fields> as C", status=None)
