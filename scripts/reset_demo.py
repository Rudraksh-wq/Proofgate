#!/usr/bin/env python3
"""Reset the demo's database to one RLS variant: `make reset-demo VARIANT=A|B|C BACKEND=hosted`.

Drops and recreates ONLY the demo's own objects (public.notes, public.run_sql) and replays the migrations plus the chosen variant, over
SUPABASE_DB_URL with psycopg. No Supabase CLI and no Docker. A hosted project is touched only when its ref is in
PROOFGATE_ALLOWED_PROJECT_REFS AND you pass --i-own-this (or set PROOFGATE_I_OWN_THIS=1). Keys and the database URL are never printed.

Exit codes: 0 done, 2 refused / not configured / failed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core"))

from proofgate.supabase_db import reset_demo_schema, select_one  # noqa: E402
from proofgate.supabase_target import BackendUnavailable, SupabaseTargetRefused, load_config, resolve_target  # noqa: E402

DEMO = ROOT / "demo-apps" / "nextjs-supabase"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--variant", default="A", help="A (RLS off), B (role instead of owner) or C (owner only)")
    ap.add_argument("--backend", choices=["hosted", "local", "auto"], default=None)
    ap.add_argument("--i-own-this", action="store_true", help="confirm the hosted project is your own test project")
    ap.add_argument("--project", default=str(DEMO))
    a = ap.parse_args(argv)
    project = Path(a.project)
    env_file = next((p for p in (project / ".env", ROOT / ".env") if p.is_file()), project / ".env")
    try:
        cfg = load_config(project, env_file=env_file)
        target = resolve_target(cfg, backend=a.backend, i_own_this=a.i_own_this)
        print(f"reset-demo: variant {a.variant.upper()} on the {target.backend} backend" + (f" (project {target.ref})" if target.ref else ""))
        conn = target.connect()
        try:
            applied = reset_demo_schema(conn, project, a.variant, target=target)
            ok = select_one(conn)
        finally:
            conn.close()
    except BackendUnavailable as e:
        print(f"reset-demo: skipped: {e}", file=sys.stderr)
        return 2
    except (SupabaseTargetRefused, ValueError, FileNotFoundError) as e:
        print(f"reset-demo: refused: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - driver errors can carry the connection string: print only the type
        print(f"reset-demo: failed: {type(e).__name__}", file=sys.stderr)
        return 2
    print("applied: " + ", ".join(applied))
    print(f"database answers select 1: {ok}")
    if target.override_note:
        print(f"note: {target.override_note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
