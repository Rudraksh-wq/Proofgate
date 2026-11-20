"""Tier B: contract templates (plan 4). The Intent Contract says WHO may do WHAT; these templates enforce it.

  owner filter        look the row up, then 404 unless its owner column equals the current user   (cross-user read/write)
  list by owner       ignore a ?user_id= parameter and always use the current user                (cross-user list)
  require_role        authenticate, then 403 unless the user is an admin                           (admin routes)
  field allow-list    only the contract's profile fields may be written                            (mass assignment)
  Supabase RLS        a NEW migration: RLS on, old policies dropped, four auth.uid() = owner policies
  Next.js ssr client  swap the service_role client in a route handler for the request-scoped one + an ownership filter

Like Tier A, each returns None instead of guessing when the code is not in a shape it understands.
"""
from __future__ import annotations

import ast
import datetime as dt
import re
from pathlib import Path

from ..layers import l5_database as l5
from ..layers.base import read_text
from ..models import Contract, Finding, OwnedResource
from .patching import diff_texts
from .tier_a import Source, _dotted, apply_edits, function_range

_AUTH_HELPERS = ("login_required", "current_user", "get_current_user", "require_login", "get_user", "authenticate")


def _resource_for(contract: Contract, finding: Finding, func_src: str) -> OwnedResource | None:
    hay = f"{finding.location.route or ''} {func_src}".lower()
    for r in contract.owned_resources:
        if re.search(rf"\b{re.escape(r.name.lower())}\b", hay):
            return r
    return contract.owned_resources[0] if len(contract.owned_resources) == 1 else None


def _find_function(tree: ast.Module, name: str | None, line: int):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and (n.name == name or n.lineno == line):
            return n
    return None


def _user_var(fn: ast.AST) -> tuple[str, ast.stmt] | None:
    for st in ast.walk(fn):
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) \
                and isinstance(st.value, ast.Call) and _dotted(st.value.func).split(".")[-1] in _AUTH_HELPERS:
            return st.targets[0].id, st
    return None


def _indent_of(src: Source, node: ast.AST) -> str:
    line = src.text.split("\n")[node.lineno - 1]
    return line[: len(line) - len(line.lstrip())]


def _flask_import_with(text: str, name: str) -> str:
    if re.search(rf"^from flask import [^\n]*\b{name}\b", text, re.MULTILINE):
        return text
    m = re.search(r"^from flask import ([^\n(]+)$", text, re.MULTILINE)
    if not m:
        return text
    names = sorted({n.strip() for n in m.group(1).split(",")} | {name})
    return text[: m.start()] + "from flask import " + ", ".join(names) + text[m.end():]


# ------------------------------------------------------------------------------------ Flask templates
def owner_filter(text: str, finding: Finding, contract: Contract) -> str | None:
    tree = ast.parse(text)
    fn = _find_function(tree, finding.location.function, finding.location.line)
    if fn is None:
        return None
    src = Source(text)
    res = _resource_for(contract, finding, src.seg(fn))
    uv = _user_var(fn)
    if res is None or uv is None:
        return None
    user = uv[0]
    row = next((st for st in ast.walk(fn) if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)
                and ".fetchone" in src.seg(st.value) and res.name.lower() in src.seg(st.value).lower()), None)
    if row is None:
        return None
    rv = row.targets[0].id
    check = f'{rv}["{res.owner_field}"] != {user}["id"]'
    edits: list[tuple[int, int, str]] = []
    existing = None
    for st in ast.walk(fn):
        if isinstance(st, ast.If) and src.seg(st.test).strip() == f"{rv} is None":
            existing = st
            break
    if existing is not None:
        edits.append((*src.span(existing.test), f"{rv} is None or {check}"))
    else:
        ind = _indent_of(src, row)
        end = src.offset(row.end_lineno, row.end_col_offset)
        edits.append((end, end, f"\n{ind}if {rv} is None or {check}:\n{ind}    abort(404)"))
    new = _flask_import_with(apply_edits(src, edits), "abort")
    return new if new != text else None


def list_by_owner(text: str, finding: Finding, contract: Contract) -> str | None:
    tree = ast.parse(text)
    fn = _find_function(tree, finding.location.function, finding.location.line)
    uv = _user_var(fn) if fn else None
    if fn is None or uv is None:
        return None
    src, edits = Source(text), []
    for st in ast.walk(fn):
        if isinstance(st, ast.Assign) and "request.args" in src.seg(st.value) and re.search(r"user_id|owner|author|uid", src.seg(st.value)):
            edits.append((*src.span(st.value), f'{uv[0]}["id"]'))
    return apply_edits(src, edits) if edits else None


def require_role(text: str, finding: Finding, contract: Contract) -> str | None:
    tree = ast.parse(text)
    fn = _find_function(tree, finding.location.function, finding.location.line)
    if fn is None:
        return None
    src = Source(text)
    module_funcs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    helper = next((h for h in _AUTH_HELPERS if h in module_funcs), None)
    check_helper = next((h for h in ("_is_admin", "is_admin") if h in module_funcs), None)
    if helper is None:
        return None
    first = fn.body[0]
    body_start = fn.body[1] if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and len(fn.body) > 1 else first
    ind = _indent_of(src, body_start)
    uv = _user_var(fn)
    bare = next((st for st in fn.body if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call)
                 and _dotted(st.value.func).split(".")[-1] == helper), None)
    cond = f"not {check_helper}(user)" if check_helper else 'user["role"] != "admin"'
    guard = f"{ind}if {cond}:\n{ind}    abort(403)\n"
    edits: list[tuple[int, int, str]] = []
    if uv is not None:
        user = uv[0]
        guard = guard.replace("(user)", f"({user})").replace('user["role"]', f'{user}["role"]')
        end = src.offset(uv[1].end_lineno, uv[1].end_col_offset)
        edits.append((end, end, "\n" + guard.rstrip("\n")))
    elif bare is not None:
        a, b = src.span(bare)
        edits.append((a, b, f"user = {helper}()\n{guard.rstrip(chr(10))}"))
    else:
        at = src.offset(body_start.lineno, 0)
        edits.append((at, at, f"{ind}user = {helper}()\n{guard}"))
    new = _flask_import_with(apply_edits(src, edits), "abort")
    return new if new != text else None


def field_allow_list(text: str, finding: Finding, contract: Contract) -> str | None:
    fields = contract.profile_editable_fields
    if not fields:
        return None
    tree = ast.parse(text)
    fn = _find_function(tree, finding.location.function, finding.location.line)
    if fn is None:
        return None
    src, edits = Source(text), []
    for loop in ast.walk(fn):
        if not (isinstance(loop, ast.For) and isinstance(loop.target, ast.Tuple) and loop.target.elts
                and isinstance(loop.target.elts[0], ast.Name) and ".items()" in src.seg(loop.iter)):
            continue
        key = loop.target.elts[0].id
        for st in ast.walk(loop):
            if isinstance(st, ast.If) and re.search(rf"\b{key}\b", src.seg(st.test)) and " in " in src.seg(st.test):
                edits.append((*src.span(st.test), f"{key} in PROFILE_EDITABLE"))
                break
    if not edits:
        return None
    first_def = min(min([n.lineno, *(d.lineno for d in n.decorator_list)]) for n in tree.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    const = "PROFILE_EDITABLE = (" + ", ".join(repr(f) for f in fields) + ("," if len(fields) == 1 else "") + ")\n"
    at = src.offset(first_def, 0)
    edits.append((at, at, const + "\n\n"))
    return apply_edits(src, edits)


# ------------------------------------------------------------------------------------ Supabase RLS migration
def rls_migration(project: Path, finding: Finding, contract: Contract) -> dict[str, str] | None:
    files = l5.sql_files(project)
    if not files:
        return None
    sch = l5.build_schema(files)
    mig_dir = next((Path(f).parent for f, _ in reversed(files) if "migrations" in Path(f).parts), Path("supabase/migrations"))
    last = max((re.match(r"(\d{8,14})", Path(f).name).group(1) for f, _ in files if re.match(r"\d{8,14}", Path(f).name)), default="0")
    stamp = max(dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S"), str(int(last.ljust(14, "0")) + 1))
    changes: dict[str, str] = {}
    for res in contract.owned_resources:
        t = sch.tables.get(res.name)
        if t is None:
            continue
        o = res.owner_field
        drops = "".join(f'drop policy if exists "{n}" on public.{t.name};\n' for n in t.policies)
        sql = (
            f"-- ProofGate fix: only the owner may use public.{t.name} (contract rule: User B must never read or change User A's {t.name}).\n"
            f"alter table public.{t.name} enable row level security;\n{drops}\n"
            f'create policy "{t.name}_select_own" on public.{t.name}\n  for select using (auth.uid() = {o});\n\n'
            f'create policy "{t.name}_insert_own" on public.{t.name}\n  for insert with check (auth.uid() = {o});\n\n'
            f'create policy "{t.name}_update_own" on public.{t.name}\n  for update using (auth.uid() = {o}) with check (auth.uid() = {o});\n\n'
            f'create policy "{t.name}_delete_own" on public.{t.name}\n  for delete using (auth.uid() = {o});\n')
        changes[(mig_dir / f"{stamp}_proofgate_rls_{t.name}.sql").as_posix()] = sql
        stamp = str(int(stamp) + 1)
    return changes or None


# ------------------------------------------------------------------------------------ Next.js
def next_ssr_switch(text: str, finding: Finding) -> str | None:
    m = re.search(r"^const (\w+) = createClient\([^;]*SERVICE_ROLE[^;]*\);\n", text, re.MULTILINE | re.DOTALL)
    if not m:
        return None
    admin = m.group(1)
    new = text[: m.start()] + text[m.end():]
    new = re.sub(rf"\b{admin}\.from\(", "supabase.from(", new)
    if len(re.findall(r"\bcreateClient\(", new)) == 0:
        new = re.sub(r'^import \{ createClient \} from "@supabase/supabase-js";\n', "", new, flags=re.MULTILINE)
    new = re.sub(r"await createServer\(\)\.auth\.getUser\(\)", "await supabase.auth.getUser()", new)
    new = re.sub(r"(export async function \w+\([^)]*\)[^{]*\{\n)", r"\1  const supabase = createServer();\n", new)
    if "supabase.auth.getUser()" not in new or "const supabase = createServer();" not in new:
        return None
    new, n = re.subn(r'(\.eq\("id", params\.id\))', r'\1.eq("user_id", user.id)', new)
    return new if n and new != text else None


# ------------------------------------------------------------------------------------ dispatch
def tier_b_patch(project: Path, finding: Finding, contract: Contract) -> tuple[str, str] | None:
    rel = finding.location.file
    rule = finding.rule
    if finding.layer == 5 and any(k in rule for k in ("rls-disabled", "policy-role-without-uid", "policy-using-true",
                                                    "policy-permissive-or-hole", "policy-wrong-owner-column", "uid-is-null")):
        changes = rls_migration(project, finding, contract)
        return (diff_texts(project, changes), "Every table must have RLS on, with policies that compare auth.uid() to the owner column.") \
            if changes else None
    text = read_text(project / rel)
    if text is None:
        return None
    try:
        if rel.endswith("route.ts") and "service-role" in rule:
            new = next_ssr_switch(text, finding)
            learned = "Route handlers must use the request-scoped Supabase client and filter by the signed-in user, never the service_role key."
        elif rule == "cross-user-list":
            new, learned = list_by_owner(text, finding, contract), "Never take the owner from the request; always use the current user."
        elif rule in ("cross-user-read", "cross-user-write"):
            r = contract.owned_resources[0] if contract.owned_resources else None
            new = owner_filter(text, finding, contract)
            learned = (f"Every query on {r.name} must filter by {r.owner_field} = current user." if r else "Check ownership on every lookup.")
        elif rule.startswith("admin-route"):
            new, learned = require_role(text, finding, contract), "Admin routes must authenticate AND check the admin role."
        elif rule == "mass-assignment":
            new, learned = field_allow_list(text, finding, contract), "Only allow-listed profile fields may be written from a request."
        else:
            return None
    except SyntaxError:
        return None
    return (diff_texts(project, {rel: new}), learned) if new and new != text else None
