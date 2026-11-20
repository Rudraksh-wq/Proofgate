"""Export JSON Schemas for every ProofGate model to schemas/*.v1.json.

Usage: python scripts/export_schemas.py [--check]
--check exits 1 if the committed files are out of date.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from proofgate.models import AcceptedRisk, Contract, Finding, FixResult, Report

OUT = Path(__file__).resolve().parent.parent / "schemas"
MODELS = {
    "finding.v1.json": Finding,
    "contract.v1.json": Contract,
    "fixresult.v1.json": FixResult,
    "report.v1.json": Report,
    "accepted.v1.json": AcceptedRisk,
}


def render() -> dict[str, str]:
    return {
        name: json.dumps(m.model_json_schema(by_alias=True), indent=2, sort_keys=True) + "\n"
        for name, m in MODELS.items()
    }


def main(argv: list[str]) -> int:
    rendered = render()
    if "--check" in argv:
        stale = [
            n for n, t in rendered.items()
            if not (OUT / n).is_file() or (OUT / n).read_text(encoding="utf-8") != t
        ]
        for n in stale:
            print(f"stale: schemas/{n}", file=sys.stderr)
        return 1 if stale else 0
    OUT.mkdir(exist_ok=True)
    for name, text in rendered.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote schemas/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
