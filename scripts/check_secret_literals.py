"""Fail if any committable file (or unpushed commit) contains a secret-shaped literal.

    python scripts/check_secret_literals.py             # tracked + untracked-not-ignored files
    python scripts/check_secret_literals.py --unpushed  # also `git log origin/main..HEAD -p`

Fake test secrets must be built at run time ("sk_" + "live_" + ...), never written out, so GitHub push
protection and our own secret scan stay quiet. Run the --unpushed form before every push.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERN = re.compile(r"sk_(live|test)_[A-Za-z0-9]{8,}|sb_secret_[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout


def scan_files() -> list[str]:
    hits = []
    for rel in _git("ls-files", "-co", "--exclude-standard", "-z").split("\0"):
        path = ROOT / rel
        if not rel or not path.is_file() or path.suffix == ".pdf":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if PATTERN.search(line):
                hits.append(f"{rel}:{n}")
    return hits


def scan_unpushed(base: str = "origin/main") -> list[str]:
    log = _git("log", f"{base}..HEAD", "-p")
    return [f"unpushed diff line {n}" for n, line in enumerate(log.splitlines(), start=1) if PATTERN.search(line)]


def main(argv: list[str]) -> int:
    hits = scan_files() + (scan_unpushed() if "--unpushed" in argv else [])
    for h in hits:
        print(f"secret-shaped literal: {h}", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
