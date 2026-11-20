#!/usr/bin/env python3
"""`make smoke`: render the corpus, build the website (when Node is available), run the twelve integration tests of plan section 11
(T1-T12) and fail if the whole thing takes five minutes or more.

    python scripts/smoke.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUDGET_S = 300


def step(title: str, cmd: list[str], cwd: Path = ROOT, required: bool = True) -> bool:
    print(f"\n== {title}", flush=True)
    r = subprocess.run(cmd, cwd=cwd)
    if r.returncode != 0 and required:
        print(f"smoke: FAILED at: {title}", file=sys.stderr)
        sys.exit(r.returncode)
    return r.returncode == 0


def main() -> int:
    started = time.monotonic()
    step("render the fake-secret corpus files", [sys.executable, "demo-apps/generate_corpus.py"])

    npm = shutil.which("npm")
    web = ROOT / "web"
    if npm and (web / "node_modules").is_dir():
        step("build the static website (T12)", [npm, "run", "build"], cwd=web, required=False)
    else:
        print("\n== website: skipped (run `cd web && npm install` once to include T12's build checks)")

    step("T1-T12", [sys.executable, "-m", "pytest", "-m", "smoke", "-q", "-rs", "--durations=5", "core/tests/test_smoke.py"])
    took = time.monotonic() - started
    print(f"\nsmoke finished in {took:.0f} s (budget {BUDGET_S} s)")
    if took >= BUDGET_S:
        print("smoke: TOO SLOW: the smoke run must stay under five minutes", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
