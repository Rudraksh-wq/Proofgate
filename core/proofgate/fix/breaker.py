"""Opt-in Fix Breaker: re-attack a patched app with variants of the original exploit."""
from __future__ import annotations

import asyncio
import inspect
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..redact import new_canary, redact

MAX_VARIANTS = 30
REQUEST_TIMEOUT_S = 3.0
TOTAL_TIMEOUT_S = 45.0


def _label(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def _sibling_path(sibling: str, victim_id: str) -> str:
    text = sibling.strip()
    parts = text.split()
    if len(parts) >= 2 and re.fullmatch(r"[A-Za-z]+", parts[0]):
        text = " ".join(parts[1:])
    text = re.sub(r"<(?:[a-z]+:)?[^>]+>", victim_id, text)
    text = re.sub(r"/\d+(?=/|$)", f"/{victim_id}", text)
    return text


def generate_variants(method: str, path: str, victim_id: str | int, siblings: list[str]) -> list[dict]:
    """Build a deterministic, de-duplicated, 30-item variant list."""
    original_method = method.upper()
    original_path = path
    victim = str(victim_id)
    candidates: list[tuple[str, str, str]] = []

    for swapped in ("PUT", "PATCH", "DELETE"):
        if swapped != original_method:
            candidates.append((swapped, original_path, f"method {original_method} -> {swapped}"))

    toggled = original_path.rstrip("/") + "/" if not original_path.endswith("/") else original_path.rstrip("/")
    candidates.append((original_method, toggled, "trailing-slash toggle"))
    candidates.append((original_method, original_path.upper(), "upper-cased path"))

    padded = victim.zfill(max(2, len(victim)))
    padded_path = re.sub(r"/\d+(?=/|$)", f"/{padded}", original_path)
    padded_path = re.sub(r"<(?:[a-z]+:)?[^>]+>", padded, padded_path)
    if padded != victim:
        candidates.append((original_method, padded_path, f"zero-padded id {padded}"))

    for sibling in siblings:
        sibling_path = _sibling_path(sibling, victim)
        if sibling_path:
            candidates.append((original_method, sibling_path, f"sibling route {sibling_path}"))

    seen: set[tuple[str, str]] = set()
    variants: list[dict] = []
    for variant_method, variant_path, reason in candidates:
        key = (variant_method, variant_path)
        if key in seen or key == (original_method, original_path):
            continue
        seen.add(key)
        variants.append({"method": variant_method, "path": variant_path, "label": reason})
        if len(variants) >= MAX_VARIANTS:
            break
    return variants


@dataclass
class BreakResult(Mapping[str, Any]):
    ran: bool
    generated: int
    routable: int
    survived: int
    broken: list[dict[str, Any]]
    duration_ms: int

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __iter__(self):
        return iter(("ran", "generated", "routable", "survived", "broken", "duration_ms"))

    def __len__(self) -> int:
        return 6

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran": self.ran,
            "generated": self.generated,
            "routable": self.routable,
            "survived": self.survived,
            "broken": [dict(item) for item in self.broken],
            "duration_ms": self.duration_ms,
        }

    def __repr__(self) -> str:
        return f"BreakResult(ran={self.ran!r}, generated={self.generated}, routable={self.routable}, " \
               f"survived={self.survived}, broken={redact(repr(self.broken))}, duration_ms={self.duration_ms})"


def _is_write(method: str) -> bool:
    return method.upper() in ("POST", "PUT", "PATCH", "DELETE")


async def _await_maybe(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _reseed(handle: Any, canary: str) -> None:
    for name in ("reseed", "reseed_a", "reseed_a_canary"):
        fn = getattr(handle, name, None)
        if fn:
            await _await_maybe(fn(canary))
            return


def _response_parts(resp: Any) -> tuple[int | None, str]:
    status = getattr(resp, "status", None)
    if status is None:
        status = getattr(resp, "status_code", None)
    text = getattr(resp, "text", "")
    if not isinstance(text, str):
        text = str(text)
    return status, text


async def _request(handle: Any, actor: str, method: str, path: str) -> Any:
    method = method.upper()
    fn = getattr(handle, f"request_as_{actor}", None)
    kwargs: dict[str, Any] = {"timeout": REQUEST_TIMEOUT_S} if _is_write(method) else {}
    if _is_write(method):
        kwargs["json"] = {"title": "proofgate-breaker"}
    if fn:
        return await asyncio.wait_for(_await_maybe(fn(method, path, **kwargs)), REQUEST_TIMEOUT_S)

    fn = getattr(handle, "request", None)
    if not fn:
        return None
    if "request_as" in getattr(fn, "__annotations__", {}):
        pass
    try:
        return await asyncio.wait_for(_await_maybe(fn(actor, method, path, **kwargs)), REQUEST_TIMEOUT_S)
    except TypeError:
        return await asyncio.wait_for(_await_maybe(fn(method, path, actor=actor, **kwargs)), REQUEST_TIMEOUT_S)


def _exploit_parts(exploit: Any) -> tuple[str, str, str]:
    if isinstance(exploit, Mapping):
        method = str(exploit.get("method") or exploit.get("request_method") or "GET").upper()
        path = str(exploit.get("path") or exploit.get("route") or "")
        victim = str(exploit.get("victim_id") or exploit.get("id") or "1")
        return method, path, victim
    method = "GET"
    route = getattr(getattr(exploit, "location", None), "route", None)
    evidence = getattr(exploit, "evidence", None)
    request = getattr(evidence, "request", "") if evidence else ""
    if isinstance(request, str) and request:
        pieces = request.split()
        if len(pieces) >= 2:
            method = pieces[0].upper()
            path = pieces[1].split("?", 1)[0]
        else:
            path = route or ""
    else:
        path = route or ""
    victim = str(getattr(exploit, "victim_id", None) or "1")
    return method, path, victim


async def run_fix_breaker(handle: Any, exploit: Any, siblings: list[str]) -> BreakResult:
    """Run variants safely. A leak requires the live A canary in B/anonymous response text."""
    started = time.monotonic()
    method, path, victim_id = _exploit_parts(exploit)
    variants = generate_variants(method, path, victim_id, siblings)
    routable = 0
    broken: list[dict[str, Any]] = []

    for variant in sorted(variants, key=lambda v: (0 if v["method"] in ("GET", "HEAD") else (2 if v["method"] == "DELETE" else 1), v["label"])):
        remaining = TOTAL_TIMEOUT_S - (time.monotonic() - started)
        if remaining <= 0:
            break
        try:
            canary = new_canary("A")
            await asyncio.wait_for(_reseed(handle, canary), min(REQUEST_TIMEOUT_S, remaining))

            owner = await _request(handle, "a", variant["method"], variant["path"])
            owner_status, _ = _response_parts(owner)
            if owner_status is None or not 200 <= owner_status < 300:
                continue
            routable += 1

            await _reseed(handle, canary)
            actor_b = await _request(handle, "b", variant["method"], variant["path"])
            status_b, text_b = _response_parts(actor_b)
            if canary in text_b:
                broken.append({"label": variant["label"], "status": status_b})
                continue

            await _reseed(handle, canary)
            anon = await _request(handle, "anon", variant["method"], variant["path"])
            status_a, text_a = _response_parts(anon)
            if canary in text_a:
                broken.append({"label": variant["label"], "status": status_a})
        except Exception:
            continue

    duration_ms = int((time.monotonic() - started) * 1000)
    survived = routable - len(broken)
    return BreakResult(ran=True, generated=len(variants), routable=routable,
                       survived=survived, broken=broken, duration_ms=duration_ms)


class FlaskBreakerHandle:
    """Probe-backed handle for running the breaker against a temporary Flask app."""

    def __init__(self, probe: Any, finding: Any):
        self.probe = probe
        self.finding = finding
        self.resource = None
        self.item_id: int | None = None
        self.victim_id: str = "1"
        self._canary = ""

    async def setup(self) -> bool:
        if not await self.probe.setup():
            return False
        if self.probe.A is None:
            return False
        location_route = getattr(getattr(self.finding, "location", None), "route", "") or ""
        route_word = re.findall(r"/[A-Za-z0-9_-]+", location_route.lower())
        for resource in self.probe.contract.owned_resources:
            if route_word and not any(resource.name.lower() in part for part in route_word):
                continue
            item = await self.probe._seed_item(resource, self.probe.A, new_canary("A"))
            if item:
                self.resource = resource
                self.item_id = int(item["id"])
                self.victim_id = str(item["id"])
                return True
        return False

    async def reseed(self, canary: str) -> None:
        from ..probe.session import ident as sql_ident, safe_assignments

        self._canary = canary
        if self.resource is None or self.item_id is None or not self.probe.db.available:
            return
        table = self.resource.name
        owner_field = self.resource.owner_field
        cols = [str(c["name"]) for c in self.probe.db.columns(table)]
        text_cols = []
        for c in self.probe.db.columns(table):
            name, typ = str(c["name"]), str(c["type"] or "").upper()
            if c["pk"] or name == owner_field or re.search(r"(_at$|^created|^updated|token|password|hash)", name, re.I):
                continue
            if "CHAR" in typ or "TEXT" in typ or "CLOB" in typ or not typ:
                text_cols.append(name)
        if not text_cols:
            return
        values = {name: canary + " " + name for name in text_cols}
        update_sql = 'UPDATE "' + sql_ident(table) + '" SET ' + safe_assignments(values) + ' WHERE id = ?'
        self.probe.db.execute(update_sql, (*values.values(), self.item_id))

    async def request_as_a(self, method: str, path: str, **kwargs: Any) -> Any:
        return await self.probe.http.request(self.probe.A, method, path, **kwargs)

    async def request_as_b(self, method: str, path: str, **kwargs: Any) -> Any:
        return await self.probe.http.request(self.probe.B, method, path, **kwargs)

    async def request_as_anon(self, method: str, path: str, **kwargs: Any) -> Any:
        return await self.probe.http.request(None, method, path, **kwargs)
