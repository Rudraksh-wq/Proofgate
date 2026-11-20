#!/usr/bin/env python3
"""CI check: after `reset_demo.py --variant X`, the database must really behave like variant X (plan section 3.3).

Connects with SUPABASE_DB_URL (the local stack's postgres user), inserts one note owned by user U1 inside a transaction, then reads it back as
  * `anon`, and
  * `authenticated` signed in as a DIFFERENT user U2,
and always rolls back. Expected:

    variant   anon sees U1's note   another signed-in user sees it
    A         yes (RLS off)         yes
    B         no                    yes (policy checks the role, not the owner)
    C         no                    no  (owner only)

    python scripts/ci_live_check.py A
"""
from __future__ import annotations

import json
import os
import sys
import uuid

EXPECTED = {"A": (True, True), "B": (False, True), "C": (False, False)}


def sees(conn, role: str, claims: dict, note_id: str) -> bool:
    with conn.transaction():
        conn.execute(f"set local role {role}")
        conn.execute("select set_config('request.jwt.claims', %s, true)", (json.dumps(claims),))
        row = conn.execute("select count(*) from public.notes where id = %s", (note_id,)).fetchone()
    return row[0] > 0


def main(argv: list[str]) -> int:
    variant = (argv[0] if argv else "").upper()
    if variant not in EXPECTED:
        print("usage: ci_live_check.py A|B|C", file=sys.stderr)
        return 2
    url = os.environ.get("SUPABASE_DB_URL", "")
    if not url:
        print("SUPABASE_DB_URL is not set", file=sys.stderr)
        return 2
    import psycopg

    u1, u2, note = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    with psycopg.connect(url, connect_timeout=15) as conn:
        try:
            with conn.transaction():
                conn.execute("set local session_replication_role = replica")  # skip the auth.users foreign key for this throwaway row
                conn.execute("insert into public.notes (id, user_id, title, body) values (%s, %s, 'canary', 'canary')", (note, u1))
                got_anon = sees(conn, "anon", {"role": "anon"}, note)
                got_other = sees(conn, "authenticated", {"sub": u2, "role": "authenticated"}, note)
                raise _Rollback((got_anon, got_other))
        except _Rollback as r:
            got_anon, got_other = r.args[0]
    want_anon, want_other = EXPECTED[variant]
    print(f"variant {variant}: anon sees the note: {got_anon} (expected {want_anon}); another signed-in user sees it: {got_other} (expected {want_other})")
    return 0 if (got_anon, got_other) == (want_anon, want_other) else 1


class _Rollback(Exception):
    pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
