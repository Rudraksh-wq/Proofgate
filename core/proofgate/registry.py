"""Public package-registry lookups (PyPI, npm) for Layer 4.

Only the package NAME is sent, to the public registry, over HTTPS. If your private package names must not
reach a public registry, run with PROOFGATE_OFFLINE=1 (cache only).

`lookup` returns a record {"exists", "first_release", "weekly_downloads"} or None when the registry could not
be reached. A network error is never treated as "package missing".
"""
from __future__ import annotations

import datetime as dt
from typing import Any
from urllib.parse import quote

import httpx

from .pkgcache import normalize

ESTABLISHED_WEEKLY_DOWNLOADS = 100_000  # above this, skip fetching the (large) npm metadata document
USER_AGENT = "proofgate-l4 (package-existence check)"


class RegistryClient:
    def __init__(self, client: httpx.AsyncClient | None = None, timeout: float = 10.0):
        self._own = client is None
        self.client = client or httpx.AsyncClient(timeout=timeout, headers={"User-Agent": USER_AGENT},
                                                  follow_redirects=True)

    async def aclose(self) -> None:
        if self._own:
            await self.client.aclose()

    async def lookup(self, ecosystem: str, name: str) -> dict[str, Any] | None:
        try:
            if ecosystem == "pypi":
                return await self._pypi(name)
            if ecosystem == "npm":
                return await self._npm(name)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return None
        return None

    # ------------------------------------------------------------------ PyPI
    async def _pypi(self, name: str) -> dict[str, Any] | None:
        r = await self.client.get(f"https://pypi.org/pypi/{quote(normalize('pypi', name))}/json")
        if r.status_code == 404:
            return {"exists": False, "first_release": None, "weekly_downloads": None}
        if r.status_code != 200:
            return None
        uploads = [f["upload_time_iso_8601"] for files in (r.json().get("releases") or {}).values() for f in files
                   if f.get("upload_time_iso_8601")]
        first = min(uploads)[:10] if uploads else None
        downloads = None
        try:  # best effort: pypistats is a separate service and may rate-limit
            d = await self.client.get(f"https://pypistats.org/api/packages/{quote(normalize('pypi', name))}/recent")
            if d.status_code == 200:
                downloads = int(d.json()["data"]["last_week"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass
        return {"exists": True, "first_release": first, "weekly_downloads": downloads}

    # ------------------------------------------------------------------ npm
    async def _npm(self, name: str) -> dict[str, Any] | None:
        enc = quote(name, safe="@").replace("/", "%2F")
        downloads = None
        d = await self.client.get(f"https://api.npmjs.org/downloads/point/last-week/{quote(name, safe='@/')}")
        if d.status_code == 200:
            try:
                downloads = int(d.json()["downloads"])
            except (ValueError, KeyError, TypeError):
                downloads = None
            if downloads is not None and downloads >= ESTABLISHED_WEEKLY_DOWNLOADS:
                return {"exists": True, "first_release": None, "weekly_downloads": downloads}
        r = await self.client.get(f"https://registry.npmjs.org/{enc}")
        if r.status_code == 404:
            return {"exists": False, "first_release": None, "weekly_downloads": None}
        if r.status_code != 200:
            return None
        created = (r.json().get("time") or {}).get("created")
        first = None
        if created:
            first = dt.datetime.fromisoformat(created.replace("Z", "+00:00")).date().isoformat()
        return {"exists": True, "first_release": first, "weekly_downloads": downloads}
