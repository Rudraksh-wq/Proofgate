"""Database work over one psycopg connection, with no Supabase CLI and no Docker (plan 3.3).

  * reset_demo_schema: drops and recreates ONLY the demo's own objects (public.notes, public.run_sql) and replays the migrations plus the
    chosen RLS variant (A, B or C). It runs only for a target that passed the guard (localhost, or an allow-listed project with --i-own-this).
  * run_splinter: Supabase's lint SQL (splinter.sql) run over the same connection; rows become layer-5 findings.

The connection is passed in, so tests use a fake one. Nothing here prints a connection string or a key.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable

from .models import Finding
from .redact import redact
from .supabase_target import BackendUnavailable, SupabaseTarget, SupabaseTargetRefused

VARIANTS = {"A": "a_rls_off.sql", "B": "b_auth_role.sql", "C": "c_owner_only.sql"}
# the only things a reset may drop: the demo's own objects
DEMO_DROP_SQL = "drop table if exists public.notes cascade;\ndrop function if exists public.run_sql(text);\n"
_VARIANT_COPY = re.compile(r"_rls_variant\.sql$")  # the installed copy `npm run variant` writes: the python runner reads variants/ directly


def migration_files(project: Path) -> list[Path]:
    d = Path(project) / "supabase" / "migrations"
    return [p for p in sorted(d.glob("*.sql")) if not _VARIANT_COPY.search(p.name)] if d.is_dir() else []


def variant_file(project: Path, variant: str) -> Path:
    key = str(variant or "").upper()
    if key not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}; use A, B or C")
    p = Path(project) / "supabase" / "variants" / VARIANTS[key]
    if not p.is_file():
        raise FileNotFoundError(f"missing {p}")
    return p


def reset_demo_schema(conn: Any, project: Path, variant: str, *, target: SupabaseTarget) -> list[str]:
    """Drop and recreate the demo objects, then apply the base migrations and the RLS variant in ONE transaction. Returns the files applied."""
    if target.backend == "hosted" and not target.ref:
        raise SupabaseTargetRefused("refusing to reset a hosted database whose project ref is unknown")
    project = Path(project)
    if not (project / "supabase" / "variants").is_dir():
        raise SupabaseTargetRefused(f"{project} is not the ProofGate demo (no supabase/variants): reset-demo only touches the demo's own objects")
    files = migration_files(project) + [variant_file(project, variant)]
    applied: list[str] = []
    with conn.transaction():
        conn.execute(DEMO_DROP_SQL)
        for f in files:
            conn.execute(f.read_text(encoding="utf-8"))
            applied.append(f.name)
    return applied


def select_one(conn: Any) -> bool:
    cur = conn.execute("select 1")
    row = cur.fetchone()
    return bool(row and row[0] == 1)


# ------------------------------------------------------------------------------------------- Splinter
_LEVEL = {"ERROR": "high", "WARN": "medium", "INFO": "low"}
SPLINTER_COLUMNS = ("name", "title", "level", "facing", "categories", "description", "detail", "remediation", "metadata", "cache_key")


def find_splinter_sql(extra_dirs: Iterable[Path] = ()) -> Path | None:
    """splinter.sql from PROOFGATE_SPLINTER_SQL or ./tools/splinter.sql. It is Supabase's own file and is not bundled."""
    cands = [Path(p) for p in [os.environ.get("PROOFGATE_SPLINTER_SQL", "")] if p]
    cands += [Path(d) / "tools" / "splinter.sql" for d in extra_dirs] + [Path("tools") / "splinter.sql"]
    return next((c for c in cands if c.is_file()), None)


def splinter_findings(rows: list[dict[str, Any]]) -> list[Finding]:
    from .layers.base import finding_id

    out: list[Finding] = []
    for r in rows:
        name = str(r.get("name") or "splinter")
        key = str(r.get("cache_key") or f"{name}|{r.get('detail', '')}")
        fp = f"sha256:splinter:{key}"
        plain = redact(f"{r.get('description', '')} {r.get('detail', '')} {('Fix: ' + str(r['remediation'])) if r.get('remediation') else ''}".strip())
        out.append(Finding(
            id=finding_id(fp), fingerprint=fp, layer=5, category="database", rule=f"splinter:{name}",
            severity=_LEVEL.get(str(r.get("level", "")).upper(), "medium"), confidence="high",
            title=redact(f"{r.get('title') or name} (live database)"), plain_words=plain, location={"file": "live-database", "line": 1},
            sources=["splinter"]))
    return sorted(out, key=lambda f: (f.rule, f.fingerprint or ""))


def run_splinter(conn: Any, sql_text: str) -> list[Finding]:
    """Run the lint SQL over the connection (read-only: Splinter only selects) and map its rows to findings."""
    cur = conn.execute(sql_text)
    names = [getattr(d, "name", d[0] if isinstance(d, (tuple, list)) else d) for d in (cur.description or [])]
    rows = [dict(zip(names, row)) for row in cur.fetchall()]
    return splinter_findings(rows)


def splinter_for_target(target: SupabaseTarget, sql_path: Path | None) -> list[Finding]:
    if sql_path is None:
        raise BackendUnavailable("splinter.sql not found (set PROOFGATE_SPLINTER_SQL or put it in tools/splinter.sql; it is Supabase's file and is not bundled)")
    conn = target.connect()
    try:
        return run_splinter(conn, sql_path.read_text(encoding="utf-8"))
    finally:
        conn.close()
