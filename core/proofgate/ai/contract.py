"""Intent Contract builder (plan 3.1, 8).

Pipeline: deterministic column heuristic (wins ties) -> keyword rules -> a guarded merge.

The merge is the security boundary. The description text is UNTRUSTED data: it can only ADD restrictions or
VALIDATED facts, never loosen anything.
  * owned resources must be real tables (and owner fields real columns); the heuristic's entry wins a tie;
  * admin-only patterns must match a real route; editable fields must be real columns;
  * anything that would make data MORE public (public routes, public reads, "anyone may..." rules) is NOT applied:
    it is listed in `needs_confirmation` and stays owner-only until a human accepts it explicitly;
  * the result is never marked confirmed: probe results stay labelled "against draft contract" until a human confirms.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

from ..layers.base import iter_files, read_text
from ..models import Contract, OwnedResource
from .fallback import OWNER_COLUMNS, draft_contract
PROSE_FILES = ("PROMPT.md", "PRD.md", "README.md", "readme.md")
MAX_PROSE = 6000
MAX_RULES, MAX_RULE_LEN = 10, 200
PUBLIC_WORDS = re.compile(
    r"\b(anyone|everyone|every ?one|public(?:ly)?|anonymous|logged[- ]out|without (?:logging in|login|signing in|auth\w*)|any (?:user|visitor))\b",
    re.IGNORECASE)
_CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?[\"`]?(\w+)[\"`]?\s*\((.*?)\)\s*;", re.IGNORECASE | re.DOTALL)
_COLUMN = re.compile(r"^\s*[\"`]?([A-Za-z_]\w*)[\"`]?\s+[A-Za-z]", re.MULTILINE)
_SQL_KEYWORDS = {"primary", "foreign", "unique", "constraint", "check", "create", "index", "key"}


# ------------------------------------------------------------------------------------ the proposal (what an LLM may suggest)
class ProposedResource(BaseModel):
    name: str
    owner_field: str
    actions: list[str]


class ContractProposal(BaseModel):
    owned_resources: list[ProposedResource]
    profile_editable_fields: list[str]
    admin_only_routes: list[str]
    public_routes: list[str]
    public_reads: list[str]
    rules: list[str]


@dataclass
class Context:
    prose: str = ""
    tables: dict[str, list[str]] = field(default_factory=dict)  # table -> columns
    routes: list[str] = field(default_factory=list)  # "METHOD /path"

    @property
    def route_paths(self) -> list[str]:
        return sorted({r.split(" ", 1)[1] for r in self.routes})


@dataclass
class ContractResult:
    contract: Contract
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------------------ gathering context
def _next_routes(project: Path) -> list[str]:
    out = []
    for p in iter_files(project):
        rel = p.relative_to(project).as_posix()
        m = re.search(r"(?:^|/)app/(.*)/route\.(?:ts|js|tsx)$", rel)
        if not m:
            continue
        path = "/" + m.group(1)
        text = read_text(p) or ""
        for verb in sorted(set(re.findall(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", text))):
            out.append(f"{verb} {path}")
    return out


def gather_context(project: str | Path) -> Context:
    from ..probe.discover import discover_routes

    project = Path(project).resolve()
    ctx = Context()
    prose = []
    for name in PROSE_FILES:
        p = project / name
        if p.is_file():
            prose.append((read_text(p) or "")[:MAX_PROSE])
    ctx.prose = "\n\n".join(prose)[: MAX_PROSE + 2000]
    for p in iter_files(project):
        if p.suffix not in (".py", ".sql"):
            continue
        for m in _CREATE.finditer(read_text(p) or ""):
            cols = [c for c in _COLUMN.findall(m.group(2)) if c.lower() not in _SQL_KEYWORDS]
            ctx.tables.setdefault(m.group(1), cols)
    ctx.routes = [r.label for r in discover_routes(project)] + _next_routes(project)
    return ctx


# ------------------------------------------------------------------------------------ deterministic keyword proposal
_EDITABLE_KEYWORDS = {
    "display name": "display_name", "display_name": "display_name", "avatar": "avatar_url", "profile picture": "avatar_url",
    "bio": "bio", "username": "username",
}


def keyword_proposal(ctx: Context) -> ContractProposal:
    """What plain keyword rules can say about the description. Deliberately conservative."""
    all_cols = {c.lower() for cols in ctx.tables.values() for c in cols}
    text = ctx.prose.lower()
    editable = sorted({col for kw, col in _EDITABLE_KEYWORDS.items() if kw in text and col in all_cols})
    public_routes: list[str] = []
    public_reads: list[str] = []
    for sentence in re.split(r"(?<=[.!?\n])\s+", ctx.prose):
        if not PUBLIC_WORDS.search(sentence) or re.search(r"\b(never|not|no one|nobody|cannot|can't|must not)\b", sentence, re.I):
            continue
        low = sentence.lower()
        public_reads += [t for t in ctx.tables if re.search(rf"\b{re.escape(t.lower())}\b", low)]
        public_routes += [p for p in ctx.route_paths if len(p) > 1 and re.search(rf"(?<![\w/]){re.escape(p.lower())}(?![\w])", low)]
    return ContractProposal(owned_resources=[], profile_editable_fields=editable, admin_only_routes=[],
                            public_routes=sorted(set(public_routes)), public_reads=sorted(set(public_reads)), rules=[])


# ------------------------------------------------------------------------------------ the guarded merge
def _clean_rule(rule: str) -> str | None:
    one = re.sub(r"\s+", " ", rule).strip()
    return one[:MAX_RULE_LEN] if one else None


def merge(base: Contract, proposal: ContractProposal, ctx: Context, *, source: str) -> Contract:
    tables = {t.lower(): cols for t, cols in ctx.tables.items()}
    resources = {r.name.lower(): r for r in base.owned_resources}
    for pr in proposal.owned_resources:
        cols = {c.lower() for c in tables.get(pr.name.lower(), [])}
        if pr.name.lower() in resources or not cols or pr.owner_field.lower() not in cols:
            continue  # the heuristic wins a tie; an invented table or column is dropped
        actions = [a for a in pr.actions if a in ("read", "create", "update", "delete", "list")] or ["read", "update", "delete"]
        resources[pr.name.lower()] = OwnedResource(name=pr.name, owner_field=pr.owner_field, actions=actions)

    all_cols = {c.lower() for cols in ctx.tables.values() for c in cols}
    editable = list(dict.fromkeys([*base.profile_editable_fields, *(f for f in proposal.profile_editable_fields if f.lower() in all_cols)]))
    admin = list(dict.fromkeys([*base.admin_only_routes, *(p for p in proposal.admin_only_routes
                                if any(fnmatch.fnmatch(r, p) for r in ctx.route_paths))]))

    needs = list(base.needs_confirmation)
    public = list(base.public_routes)
    for route in proposal.public_routes:
        if route not in public and route not in base.public_routes:
            needs.append(route)  # would open a route to everyone: a human must say so
    for table in proposal.public_reads:
        needs.append(table)

    rules = list(base.rules)
    for rule in proposal.rules[:MAX_RULES]:
        cleaned = _clean_rule(rule)
        if not cleaned:
            continue
        if PUBLIC_WORDS.search(cleaned):
            needs.append(cleaned)  # "anyone can read ..." is a request to loosen access, not a rule to enforce
        elif cleaned not in rules:
            rules.append(cleaned)

    return Contract(
        owned_resources=list(resources.values()), profile_editable_fields=editable, admin_only_routes=admin,
        public_routes=public, rules=rules, confirmed_by_user=False, source=source,  # type: ignore[arg-type]
        needs_confirmation=list(dict.fromkeys(needs)), public_reads_confirmed=list(base.public_reads_confirmed),
    )


# ------------------------------------------------------------------------------------ entry points
async def build_contract(project: str | Path) -> ContractResult:
    project = Path(project).resolve()
    base = draft_contract(project)
    ctx = gather_context(project)
    proposal = keyword_proposal(ctx)
    notes = ["used the deterministic keyword fallback"]
    contract = merge(base, proposal, ctx, source="fallback")
    if contract.needs_confirmation:
        notes.append(f"{len(contract.needs_confirmation)} item(s) would make data more public and were NOT applied: "
                     + ", ".join(contract.needs_confirmation))
    return ContractResult(contract, notes)


def confirm_contract(contract: Contract, accept_public: list[str] | None = None) -> tuple[Contract, list[str]]:
    """A human confirms the contract. Items in needs_confirmation stay owner-only unless named in `accept_public`.
    Returns (confirmed contract, items still unresolved)."""
    accepted = [a for a in (accept_public or []) if a in contract.needs_confirmation]
    public_routes, reads = list(contract.public_routes), list(contract.public_reads_confirmed)
    for item in accepted:
        if item.startswith("/"):
            public_routes.append(item)
        elif " " not in item:  # a table name; a free-text rule is simply resolved, never enforced as "public"
            reads.append(item)
    unresolved = [n for n in contract.needs_confirmation if n not in accepted]
    return contract.model_copy(update={
        "confirmed_by_user": True, "public_routes": list(dict.fromkeys(public_routes)),
        "public_reads_confirmed": list(dict.fromkeys(reads)), "needs_confirmation": unresolved}), unresolved
