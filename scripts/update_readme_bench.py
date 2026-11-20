#!/usr/bin/env python3
"""Fill the benchmark table in README.md from bench/results.json, so the README never holds a number that was not measured.

    python scripts/update_readme_bench.py          # rewrite the block
    python scripts/update_readme_bench.py --check  # exit 1 if README.md is out of date
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BEGIN, END = "<!-- bench:begin -->", "<!-- bench:end -->"
LABELS = {"bandit": "Bandit", "pip_audit": "pip-audit", "semgrep": "Semgrep", "betterleaks": "Betterleaks", "osv_scanner": "OSV-Scanner",
          "splinter": "Splinter", "union": "Union of the available tools above", "proofgate_fast": "ProofGate fast", "proofgate_full": "ProofGate full"}


def f2(x) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def render(results: dict) -> str:
    r = results
    rows = []
    for name, t in r["tables"].items():
        if t["available"]:
            o = t["overall"]
            rows.append(f"| {LABELS.get(name, name)} | {f2(o['precision'])} | {f2(o['recall'])} | {f2(o['f1'])} | {f2(t['by_category']['access']['recall'])} |")
        else:
            rows.append(f"| {LABELS.get(name, name)} | not measured: {t['reason'].split(';')[0]} | | | |")
    fv = r["fix_verification"]
    held = "no held-out set has been provided, so there is no held-out number" if r["heldout"]["apps"] == 0 else f"held-out apps: {r['heldout']['apps']}"
    return (
        f"Measured on {r['generated_at'][:10]} (`bench/results.json`; re-run with `make bench`) on {r['corpus']['apps']} small synthetic Flask apps "
        f"with {r['corpus']['ground_truth_items']} planted flaws; {held}.\n\n"
        "| Column | Precision | Recall | F1 | Access recall |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
        f"Judging {fv['cases']} candidate fixes: a re-scan-says-clean gate was right {f2(fv['rescan_accuracy'])} of the time, "
        f"the tournament {f2(fv['tournament_accuracy'])} ({fv['tournament_correct']}). "
        f"Inline check: median {r['latency']['inline_check_median_ms_per_file']} ms per file (50 runs).\n"
    )


def main(argv: list[str]) -> int:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    results = json.loads((ROOT / "bench" / "results.json").read_text(encoding="utf-8"))
    block = f"{BEGIN}\n{render(results)}{END}"
    new = re.sub(rf"{re.escape(BEGIN)}.*?{re.escape(END)}", lambda m: block, text, flags=re.DOTALL)
    if "--check" in argv:
        return 0 if new == text else 1
    readme.write_text(new, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
