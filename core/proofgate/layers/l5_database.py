"""Layer 5: Supabase / Postgres row-level-security checks (plan 2, 3.3).

STATIC part (this module): the project's SQL migrations are replayed in order into a small model (tables, RLS on/off,
policies, functions, views) using the real Postgres parser (pglast), then checked against the Intent Contract:

  rls-disabled              RLS is off on a public table                       (critical if the contract says it is owned)
  rls-enabled-no-policy     RLS on, no policy: nothing can read it
  policy-role-without-uid   auth.role() = 'authenticated' with no auth.uid()  -> any signed-in user passes
  policy-using-true         USING (true) / WITH CHECK (true) on an owned table (SELECT using(true) is not in Splinter)
  policy-permissive-or-hole a weak permissive policy ORed with a correct one cancels the correct one
  policy-uid-is-null        auth.uid() IS NULL fails open for anonymous callers
  policy-wrong-owner-column auth.uid() compared to something other than the contract's owner column (heuristic)
  function-security-definer SECURITY DEFINER function in public: runs as its owner, skips RLS
  view-bypasses-rls         a public view without security_invoker runs as its owner

A migration that is not in the project (for example an RLS variant that was never installed) is not applied, so a table
nobody enabled RLS on is reported as exactly that.

LIVE part (Splinter lint SQL against a running local Postgres) needs `supabase start` and is skipped and recorded here;
it is pending real-tool verification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Contract, Finding, ToolRecord
from ..redact import redact
from .base import LayerResult, finding_id, iter_files, read_text, short_hash

LAYER = 5
PUBLIC = "public"
_SECURITY_TYPES = ("AT_EnableRowSecurity", "AT_DisableRowSecurity", "AT_ForceRowSecurity")


@dataclass
class Policy:
    name: str
    table: str
    cmd: str  # all | select | insert | update | delete
    permissive: bool
    roles: list[str]
    qual: str | None
    check: str | None
    file: str
    line: int


@dataclass
class Table:
    name: str
    file: str
    line: int
    rls: bool = False
    policies: dict[str, Policy] = field(default_factory=dict)


@dataclass
class Func:
    name: str
    schema: str
    definer: bool
    file: str
    line: int
    revoked: bool = False


@dataclass
class View:
    name: str
    invoker: bool
    file: str
    line: int


@dataclass
class Schema:
    tables: dict[str, Table] = field(default_factory=dict)
    funcs: dict[str, Func] = field(default_factory=dict)
    views: dict[str, View] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------------------ parsing
def _first_code_offset(sql_bytes: bytes, start: int) -> int:
    """Offset of the first real character of a statement (skips whitespace and `--` comments pglast leaves in)."""
    i, n = start, len(sql_bytes)
    while i < n:
        if sql_bytes[i:i + 1] in (b" ", b"\t", b"\r", b"\n", b";"):
            i += 1
        elif sql_bytes[i:i + 2] == b"--":
            j = sql_bytes.find(b"\n", i)
            i = n if j < 0 else j + 1
        else:
            break
    return i


def _rel(node) -> tuple[str, str]:
    return (getattr(node, "schemaname", None) or PUBLIC), node.relname


def build_schema(files: list[tuple[str, str]]) -> Schema:
    """files: [(relative path, sql text)] in application order."""
    import pglast
    from pglast.stream import RawStream

    def show(n) -> str | None:
        return RawStream()(n) if n is not None else None

    sch = Schema()
    for rel, sql in files:
        try:
            stmts = pglast.parse_sql(sql)
        except pglast.parser.ParseError as e:
            sch.errors.append(f"{rel}: SQL syntax error: {e}")
            continue
        raw = sql.encode("utf-8")
        for rs in stmts:
            s, kind = rs.stmt, type(rs.stmt).__name__
            line = raw[:_first_code_offset(raw, rs.stmt_location or 0)].count(b"\n") + 1
            if kind == "CreateStmt":
                schema, name = _rel(s.relation)
                if schema == PUBLIC:
                    sch.tables[name] = Table(name, rel, line)
            elif kind == "AlterTableStmt" and s.objtype is not None:
                schema, name = _rel(s.relation)
                t = sch.tables.get(name) if schema == PUBLIC else None
                for cmd in s.cmds or ():
                    st = getattr(cmd.subtype, "name", "")
                    if t is not None and st == "AT_EnableRowSecurity":
                        t.rls = True
                    elif t is not None and st == "AT_DisableRowSecurity":
                        t.rls = False
            elif kind == "CreatePolicyStmt":
                schema, name = _rel(s.table)
                t = sch.tables.get(name) if schema == PUBLIC else None
                if t is not None:
                    roles = [r.rolename or "public" for r in (s.roles or [])] or ["public"]
                    t.policies[s.policy_name] = Policy(s.policy_name, name, s.cmd_name or "all", bool(s.permissive), roles,
                                                       show(s.qual), show(s.with_check), rel, line)
            elif kind == "DropStmt":
                _apply_drop(sch, s)
            elif kind == "CreateFunctionStmt":
                names = [x.sval for x in s.funcname]
                schema, name = (names[0], names[-1]) if len(names) > 1 else (PUBLIC, names[0])
                definer = any(o.defname == "security" and getattr(o.arg, "boolval", False) for o in (s.options or ()))
                sch.funcs[f"{schema}.{name}"] = Func(name, schema, definer, rel, line)
            elif kind == "ViewStmt":
                schema, name = _rel(s.view)
                if schema == PUBLIC:
                    invoker = any(o.defname == "security_invoker" and str(getattr(o.arg, "sval", o.arg)).lower() in ("true", "on", "1")
                                  for o in (s.options or ()))
                    sch.views[name] = View(name, invoker, rel, line)
            elif kind == "GrantStmt" and not s.is_grant:
                _apply_revoke(sch, s)
    return sch


def _apply_drop(sch: Schema, s) -> None:
    rtype = getattr(s.removeType, "name", "")
    for obj in s.objects or ():
        parts = [getattr(p, "sval", None) for p in (obj if isinstance(obj, (list, tuple)) else getattr(obj, "items", []))]
        parts = [p for p in parts if p]
        if rtype == "OBJECT_POLICY" and len(parts) >= 2:
            t = sch.tables.get(parts[-2])
            if t:
                t.policies.pop(parts[-1], None)
        elif rtype == "OBJECT_TABLE" and parts:
            sch.tables.pop(parts[-1], None)


def _apply_revoke(sch: Schema, s) -> None:
    if getattr(s.objtype, "name", "") != "OBJECT_FUNCTION":
        return
    who = {getattr(g.roletype, "name", ""): g for g in (s.grantees or ())}
    names = {getattr(g, "rolename", None) for g in (s.grantees or ())}
    if "ROLESPEC_PUBLIC" not in who and "anon" not in names:
        return
    for obj in s.objects or ():
        parts = [x.sval for x in getattr(obj, "objname", ())]
        if parts:
            key = f"{parts[0]}.{parts[-1]}" if len(parts) > 1 else f"{PUBLIC}.{parts[0]}"
            if key in sch.funcs:
                sch.funcs[key].revoked = True


# ------------------------------------------------------------------------------------ classification
def _compact(expr: str | None) -> str:
    return re.sub(r"\s+", " ", (expr or "").strip().lower())


def policy_kind(p: Policy, owner_field: str | None) -> str:
    """strong | true | role_only | uid_null | wrong_column | other, judged on the expressions that gate the policy."""
    exprs = [_compact(e) for e in (p.qual, p.check) if e]
    if not exprs:
        return "other"
    if any(re.search(r"auth\.uid\(\)\s+is\s+null", e) for e in exprs):
        return "uid_null"
    if all(e in ("true", "(true)") for e in exprs) or any(e in ("true", "(true)") for e in exprs):
        return "true"
    if any("auth.role()" in e for e in exprs) and not any("auth.uid()" in e for e in exprs):
        return "role_only"
    if any("auth.uid()" in e for e in exprs):
        if owner_field and not any(owner_field.lower() in e for e in exprs):
            return "wrong_column"
        return "strong"
    return "other"


_WEAK = {"true", "role_only", "uid_null"}


def _only_service_role(p: Policy) -> bool:
    return p.roles == ["service_role"]


def _cmds(p: Policy) -> set[str]:
    return {"select", "insert", "update", "delete"} if p.cmd in ("all", "*") else {p.cmd}


# ------------------------------------------------------------------------------------ findings
_ROTATE_NOTE = " Fix it with a migration that enables RLS and compares auth.uid() to the owner column."


def _mk(rule: str, severity: str, confidence: str, cwe: str, tier: str | None, file: str, line: int, title: str,
        plain: str, key: str) -> Finding:
    fp = f"sha256:{rule}|{file}|{short_hash(key)}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category="database", rule=f"proofgate.sql-{rule}", cwe=cwe,
        severity=severity, confidence=confidence, title=redact(f"{title} ({file}:{line})"), plain_words=redact(plain),
        location={"file": file, "line": line}, sources=[f"proofgate-rule:sql-{rule}"], fix_tier=tier,
    )


def check_schema(sch: Schema, contract: Contract) -> list[Finding]:
    owned = {r.name.lower(): r.owner_field for r in contract.owned_resources}
    out: list[Finding] = []

    for t in sch.tables.values():
        owner = owned.get(t.name.lower())
        is_owned = owner is not None
        live = [p for p in t.policies.values() if not _only_service_role(p)]
        if not t.rls:
            out.append(_mk("rls-disabled", "critical" if is_owned else "high", "high", "CWE-862", "B", t.file, t.line,
                           f"Row-level security is off on public.{t.name}",
                           f"Anyone holding your public anon key can read and change every row of {t.name}."
                           + (" The contract says these rows belong to individual users." if is_owned else "") + _ROTATE_NOTE,
                           t.name))
            continue
        if not t.policies:
            out.append(_mk("rls-enabled-no-policy", "low", "high", "CWE-862", None, t.file, t.line,
                           f"public.{t.name} has RLS on but no policy",
                           f"Row-level security is on for {t.name} and nothing allows any access, so the table is locked "
                           "(your app probably cannot use it). Add the policies you intend.", t.name))
            continue
        for p in live:  # fail-open on any table
            if policy_kind(p, owner) == "uid_null":
                out.append(_mk("policy-uid-is-null", "high", "high", "CWE-285", "B", p.file, p.line,
                               f"Policy {p.name} on {t.name} passes when nobody is signed in",
                               "The policy lets a request through when auth.uid() is null, which is exactly an anonymous "
                               "visitor." + _ROTATE_NOTE, f"{t.name}|{p.name}"))
        if not is_owned:
            continue
        kinds = {p.name: policy_kind(p, owner) for p in live}
        for cmd in ("select", "insert", "update", "delete"):
            applicable = [p for p in live if p.permissive and cmd in _cmds(p)]
            weak = [p for p in applicable if kinds[p.name] in _WEAK - {"uid_null"}]
            strong = [p for p in applicable if kinds[p.name] == "strong"]
            if weak and strong:
                for p in weak:
                    out.append(_mk("policy-permissive-or-hole", "high", "high", "CWE-863", "B", p.file, p.line,
                                   f"Policy {p.name} on {t.name} cancels the owner check for {cmd}",
                                   f"Policies for the same action are combined with OR. {p.name} lets people through "
                                   f"without an ownership check, so the correct {t.name} policy next to it protects nothing.",
                                   f"{t.name}|{p.name}|{cmd}"))
        in_hole = {p.name for p in live if p.permissive and kinds[p.name] in _WEAK and any(
            kinds[q.name] == "strong" and _cmds(q) & _cmds(p) for q in live if q.permissive)}
        role_only = [p for p in live if kinds[p.name] == "role_only" and p.name not in in_hole]
        if role_only:
            first = role_only[0]
            out.append(_mk("policy-role-without-uid", "high", "high", "CWE-863", "B", first.file, first.line,
                           f"{len(role_only)} polic{'y' if len(role_only) == 1 else 'ies'} on {t.name} check the role, not the owner",
                           f"The policies ({', '.join(p.name for p in role_only)}) only ask 'is this person signed in?' "
                           f"(auth.role()), never 'does this row belong to them?' (auth.uid()), so any signed-in user can use "
                           f"everyone's {t.name}." + _ROTATE_NOTE, f"{t.name}|role"))
        using_true = [p for p in live if kinds[p.name] == "true" and p.name not in in_hole]
        if using_true:
            first = using_true[0]
            actions = sorted({c for p in using_true for c in _cmds(p)})
            out.append(_mk("policy-using-true", "high", "high", "CWE-862", "B", first.file, first.line,
                           f"A policy on {t.name} allows every row ({'/'.join(actions)})",
                           f"The policy ({', '.join(p.name for p in using_true)}) is simply 'true', so it lets everyone use "
                           f"every row of {t.name}. Splinter does not flag SELECT using(true); the contract does."
                           + _ROTATE_NOTE, f"{t.name}|true"))
        for p in live:
            if kinds[p.name] == "wrong_column":
                out.append(_mk("policy-wrong-owner-column", "medium", "low", "CWE-639", "B", p.file, p.line,
                               f"Policy {p.name} on {t.name} does not compare auth.uid() to {owner}",
                               f"The contract says {t.name} rows are owned through the column {owner}, but this policy compares "
                               "auth.uid() to something else. Check it is the right column.", f"{t.name}|{p.name}|col"))

    for f in sch.funcs.values():
        if f.definer and f.schema == PUBLIC:
            risky = not f.revoked
            out.append(_mk("function-security-definer", "high" if risky else "medium", "high", "CWE-250", None, f.file, f.line,
                           f"SECURITY DEFINER function {f.name}() in the public schema",
                           f"{f.name}() runs with its owner's rights, so it skips row-level security."
                           + (" Nobody revoked EXECUTE from anon, so anyone with the public key can call it." if risky else "")
                           + " Prefer SECURITY INVOKER, or move it out of the public schema and revoke public access.",
                           f"fn|{f.schema}.{f.name}"))
    for v in sch.views.values():
        if not v.invoker:
            out.append(_mk("view-bypasses-rls", "medium", "medium", "CWE-863", None, v.file, v.line,
                           f"View public.{v.name} runs as its owner",
                           f"Views run with the rights of whoever created them, which skips row-level security on the tables "
                           f"behind {v.name}. Create it WITH (security_invoker = true).", f"view|{v.name}"))
    return sorted(out, key=lambda f: (f.location.file, f.location.line, f.rule))


# ------------------------------------------------------------------------------------ run
def sql_files(project: Path) -> list[tuple[str, str]]:
    found = []
    for p in iter_files(project):
        rel = p.relative_to(project)
        if p.suffix == ".sql" and ("migrations" in rel.parts or p.name == "schema.sql"):
            text = read_text(p)
            if text:
                found.append((rel.as_posix(), text))
    return sorted(found)


async def run(project_dir: str | Path, *, contract: Contract | None = None, **_ignored) -> LayerResult:
    project = Path(project_dir).resolve()
    res = LayerResult(layer=LAYER)
    try:
        import pglast  # noqa: F401
    except ImportError:
        res.tools.append(ToolRecord(name="proofgate-sql", status="skipped"))
        res.notes.append("proofgate-sql: skipped: the pglast package is not installed")
        return res
    files = sql_files(project)
    if not files:
        return res
    if contract is None:
        from ..probe import load_contract

        contract = load_contract(project)
    sch = build_schema(files)
    res.tools.append(ToolRecord(name="proofgate-sql", status="ok"))
    res.notes += [redact(e) for e in sch.errors]
    res.findings = check_schema(sch, contract)
    res.tools.append(ToolRecord(name="splinter", status="skipped"))
    res.notes.append("splinter: skipped: needs a running local Postgres (`supabase start`); static checks ran instead")
    if not contract.confirmed_by_user and contract.owned_resources:
        res.notes.append("contract-aware SQL checks used a DRAFT contract")
    return res
