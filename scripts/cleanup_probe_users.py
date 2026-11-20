#!/usr/bin/env python3
"""Delete leftover probe users (emails starting with `proofgate-probe-`) from an allow-listed Supabase test project.

A probe run that is killed (Ctrl+C, a crash, a closed laptop) cannot clean up after itself. This does it afterwards. Same guard as everything
else: the project ref must be in PROOFGATE_ALLOWED_PROJECT_REFS and you must pass --i-own-this. Keys are never printed.

    python scripts/cleanup_probe_users.py --i-own-this
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core"))

from proofgate.probe.supabase import PROBE_EMAIL_PREFIX, SupabaseApi  # noqa: E402
from proofgate.supabase_target import BackendUnavailable, SupabaseTargetRefused, load_config, resolve_target  # noqa: E402


async def clean(api: SupabaseApi) -> tuple[int, int]:
    ids = await api.leftover_probe_users()
    for uid in ids:
        await api.delete_user(uid)
    return len(ids), len(await api.leftover_probe_users())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--backend", choices=["hosted", "local", "auto"], default=None)
    ap.add_argument("--i-own-this", action="store_true")
    ap.add_argument("--project", default=str(ROOT / "demo-apps" / "nextjs-supabase"))
    a = ap.parse_args(argv)
    try:
        target = resolve_target(load_config(Path(a.project)), backend=a.backend, i_own_this=a.i_own_this)
        api = SupabaseApi(target, delay=0.2)
        found, left = asyncio.run(clean(api))
    except BackendUnavailable as e:
        print(f"cleanup: skipped: {e}", file=sys.stderr)
        return 2
    except SupabaseTargetRefused as e:
        print(f"cleanup: refused: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"cleanup: failed: {type(e).__name__}", file=sys.stderr)
        return 2
    print(f"found {found} probe user(s) ('{PROBE_EMAIL_PREFIX}...'); {left} left")
    return 0 if left == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
