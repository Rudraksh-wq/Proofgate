"""Deterministic draft Intent Contract (no LLM). The Gemini contract (feat/17) builds on this and this wins ties.

Heuristic (plan 3.1): a table with an owner-looking column (`owner_id`, `user_id`, `author_id`, `created_by`) is an
owned resource; routes under /admin are admin-only; login/signup routes are public. Everything is owner-only by
default and the draft is never marked confirmed: results are labelled "against draft contract" until a human confirms.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..layers.base import iter_files, read_text
from ..models import Contract, OwnedResource

OWNER_COLUMNS = ("owner_id", "user_id", "author_id", "created_by")
_CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`]?(\w+)[\"`]?\s*\((.*?)\)\s*;", re.IGNORECASE | re.DOTALL)
_USER_TABLES = {"users", "user", "profiles", "accounts", "auth_users"}


def draft_contract(project: str | Path) -> Contract:
    from ..probe.discover import discover_routes

    project = Path(project).resolve()
    resources: dict[str, OwnedResource] = {}
    source_text = ""
    for p in iter_files(project):
        if p.suffix not in (".py", ".sql"):
            continue
        text = read_text(p) or ""
        source_text += text
        for m in _CREATE.finditer(text):
            table, body = m.group(1), m.group(2)
            if table.lower() in _USER_TABLES:
                continue
            col = next((c for c in OWNER_COLUMNS if re.search(rf"\b{c}\b", body, re.IGNORECASE)), None)
            if col:
                resources.setdefault(table, OwnedResource(name=table, owner_field=col, actions=["read", "update", "delete"]))

    routes = discover_routes(project)
    admin = sorted({"/" + r.path.strip("/").split("/")[0] + "/*" for r in routes if r.path.lower().startswith("/admin")})
    public = sorted({r.path for r in routes if re.search(r"sign-?up|log-?in|register", r.path, re.IGNORECASE)})
    editable = ["display_name"] if "display_name" in source_text else []
    rules = [f"User B must never read or change User A's {name}." for name in resources]
    if admin:
        rules.append("Only admins may use the admin routes.")
    return Contract(
        owned_resources=list(resources.values()), profile_editable_fields=editable, admin_only_routes=admin,
        public_routes=public, rules=rules, confirmed_by_user=False, source="fallback",
    )
