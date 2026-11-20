"""The live Supabase backend for the fix tournament (plan 4, Guard B).

When a fix is verified against a real Supabase project (your own hosted test project, `--backend hosted --i-own-this`), each candidate is replayed on
the DATABASE: the demo's objects are dropped and every migration is applied again from scratch, the RLS variant included, then the probe attacks the
patched copy through the API. After every candidate the ORIGINAL state is replayed, so a rejected (or merely evaluated) candidate never leaves the
test project changed. Only the ProofGate demo can be replayed this way (`supabase/variants` must exist); other projects keep the static replay.
"""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LiveCtx:
    backend: str | None = None
    i_own_this: bool = False
    variant: str | None = None  # the demo's RLS variant (A, B or C) that is installed in the database being fixed
    config_dir: Path | None = None  # where `.env` lives: the ORIGINAL project (a temporary copy has none)


SCHEMA_RELOAD_WAIT_S = 2.0
current_live: ContextVar[LiveCtx | None] = ContextVar("proofgate_live", default=None)


def live_from_env(project: Path) -> LiveCtx | None:
    """For the MCP server and hooks, where an agent (not a person) calls: live verification is ON only if the HUMAN wrote
    `PROOFGATE_I_OWN_THIS=1` and `PROOFGATE_SUPABASE_BACKEND=hosted|local` into the environment or the git-ignored `.env`. There is no tool argument
    for it. (The allow-list of project refs still applies. An agent that can edit `.env` can change these too: the guard protects against an
    accidental target, not against an agent with write access to your files.)"""
    from ..supabase_target import SupabaseTargetRefused, load_config

    try:
        cfg = load_config(project)
    except SupabaseTargetRefused:
        return None
    if not cfg.i_own_this_env or cfg.backend not in ("hosted", "local"):
        return None
    import os

    return LiveCtx(cfg.backend, True, (os.environ.get("PROOFGATE_DEMO_VARIANT") or "").upper() or None, Path(project).resolve())


def live_applies(project: Path, live: LiveCtx | None) -> bool:
    """Live replay is only for Supabase/Next.js projects without a Flask entry file, and only when the caller asked for it."""
    if live is None:
        return False
    from ..probe import is_supabase_project
    from ..probe.launcher import find_entry

    return find_entry(project) is None and is_supabase_project(project)


def _replay_sync(project: Path, live: LiveCtx) -> list[str]:
    from ..supabase_db import replay_project
    from ..supabase_target import load_config, resolve_target

    target = resolve_target(load_config(live.config_dir or project), backend=live.backend, i_own_this=live.i_own_this)
    conn = target.connect()
    try:
        return replay_project(conn, project, live.variant, target=target)
    finally:
        conn.close()


async def live_replay(project: Path, live: LiveCtx) -> list[str]:
    """Replay `project`'s migrations on the live database. Raises BackendUnavailable / SupabaseTargetRefused / a database error."""
    applied = await asyncio.to_thread(_replay_sync, project, live)
    await asyncio.sleep(SCHEMA_RELOAD_WAIT_S)  # let PostgREST pick up the new schema before anything attacks it
    return applied
