#!/usr/bin/env python3
"""Run the ProofGate benchmark and write bench/results.json. One command:

    python bench/run_bench.py                 # everything (needs network for pip-audit and the package registry)
    python bench/run_bench.py --skip-network  # offline: no pip-audit column, no registry lookups
    python bench/run_bench.py --apps c01_clean,v01_idor_read --out /tmp/r.json   # a quick subset

Every number is measured on this machine, now. A column whose tool is not installed is reported as unavailable, never guessed.
Methodology and disclosure rules: bench/README.md.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import platform
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "demo-apps"))

import generate_corpus  # noqa: E402
from benchlib import CATEGORIES, TOLERANCE, Row, Truth, accuracy, median, score, truth_from_json, union_rows  # noqa: E402

from proofgate import __version__  # noqa: E402
from proofgate.fix.patching import make_diff  # noqa: E402
from proofgate.fix.tournament import Candidate, compute_baseline, run_tournament  # noqa: E402
from proofgate.hook import read_fail_open_count, run_hook  # noqa: E402
from proofgate.inline import check_file  # noqa: E402
from proofgate.layers import l1_secrets, l2_sast, l3_deps  # noqa: E402
from proofgate.layers.base import iter_files  # noqa: E402
from proofgate.models import ToolRecord  # noqa: E402
from proofgate.orchestrator import run_scan  # noqa: E402
from proofgate.pkgcache import PackageCache  # noqa: E402
from proofgate.probe import run_probe  # noqa: E402
from proofgate.runner import ToolResult, run_tool  # noqa: E402
from proofgate.toollock import ToolEntry, ToolLock, find_binary, platform_key, sha256_file  # noqa: E402

CORPUS = ROOT / "demo-apps" / "flask-corpus"
FIXES = ROOT / "demo-apps" / "flask-fixes"
HELDOUT = ROOT / "demo-apps" / "heldout"
TOOLS_DIR = Path(sys.executable).parent
BASELINE_TOOLS = ["bandit", "semgrep", "betterleaks", "gitleaks", "osv-scanner", "pip-audit"]
TARGETS = {  # from plan section 14: targets, never results
    "access_recall_corpus": 0.85, "access_recall_heldout": 0.70, "proven_precision": 0.95,
    "tournament_correct_decisions": "12/12", "inline_median_ms": 200, "raw_secrets_in_outputs": 0,
}


# ------------------------------------------------------------------------------------ tools
def pinned_lock() -> tuple[ToolLock, list[dict]]:
    """A lock that pins every tool found on this machine (an explicit 'I trust these binaries for this run')."""
    lock = ToolLock.load()
    info = []
    for name, entry in lock.tools.items():
        path = find_binary(entry.binary, TOOLS_DIR)
        if path and entry.verify == "sha256":
            entry.sha256[platform_key()] = sha256_file(path)
            info.append({"name": name, "path_name": path.name, "sha256": sha256_file(path), "status": "found"})
        elif path:
            info.append({"name": name, "path_name": path.name, "sha256": None, "status": "found (presence only)"})
        else:
            info.append({"name": name, "path_name": None, "sha256": None, "status": "not installed"})
    return lock, info


def app_dirs(base: Path, only: set[str] | None = None) -> list[Path]:
    return sorted(p for p in base.iterdir() if p.is_dir() and (only is None or p.name in only)) if base.is_dir() else []


def rows_of(app: str, findings, tool: str) -> list[Row]:
    return [Row(app, f.category, f.location.file, f.location.line, f.rule, tool) for f in findings]


# ------------------------------------------------------------------------------------ baseline columns
async def run_baselines(apps: list[Path], lock: ToolLock, skip_network: bool) -> dict[str, dict]:
    cols: dict[str, dict] = {}

    async def runner(name, args, **kw):
        return await run_tool(name, args, **{**kw, "lock": lock, "tools_dir": TOOLS_DIR})

    # Bandit
    if find_binary("bandit", TOOLS_DIR):
        rows = []
        for app in apps:
            res = await runner("bandit", l2_sast.bandit_args(app.resolve()), cwd=app, timeout=300)
            if res.status == "ok":
                rows += rows_of(app.name, l2_sast.parse_bandit(res.stdout, app.resolve()), "bandit")
        cols["bandit"] = {"available": True, "rows": rows}
    else:
        cols["bandit"] = {"available": False, "reason": "bandit is not installed"}

    # pip-audit (a vulnerability database check; stands in for the OSV column when osv-scanner is missing)
    if skip_network:
        cols["pip_audit"] = {"available": False, "reason": "skipped with --skip-network"}
    elif find_binary("pip-audit", TOOLS_DIR):
        rows = []
        for app in apps:
            async def only_pip(name, args, **kw):
                if name != "pip-audit":
                    return ToolResult(name, "skipped", reason="bench: only pip-audit is measured in this column")
                return await runner(name, args, **kw)

            res = await l3_deps.run(app, runner=only_pip, offline=False)
            rows += rows_of(app.name, res.findings, "pip-audit")
        cols["pip_audit"] = {"available": True, "rows": rows}
    else:
        cols["pip_audit"] = {"available": False, "reason": "pip-audit is not installed"}

    # Tools that are not installed here are reported as such.
    for col, tool in (("semgrep", "semgrep"), ("betterleaks", "betterleaks"), ("osv_scanner", "osv-scanner")):
        found = find_binary(tool, TOOLS_DIR)
        cols[col] = {"available": False, "reason": f"{tool} is not installed in this environment" if not found else
                     f"{tool} is installed but its benchmark adapter has not been verified yet (pending real-tool verification)"}
    cols["splinter"] = {"available": False, "reason": "Splinter needs a live local Postgres (`supabase start`); the corpus is Flask, so it has no rows to lint either way"}

    avail = {k: v["rows"] for k, v in cols.items() if v.get("available")}
    cols["union"] = {"available": bool(avail), "rows": union_rows(avail), "of": sorted(avail),
                     "reason": "" if avail else "no baseline tool was available"}
    return cols


# ------------------------------------------------------------------------------------ ProofGate columns
async def run_proofgate(apps: list[Path], lock: ToolLock, skip_network: bool, cache_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    gate = asyncio.Semaphore(3)

    async def one(app: Path, full: bool):
        async with gate:
            t = time.perf_counter()
            res = await run_scan(app, fast=not full, full=full, lock=lock, tools_dir=TOOLS_DIR, offline=skip_network,
                                 cache=PackageCache(cache_dir / "packages.json"))
            return app, res, time.perf_counter() - t

    for mode, full in (("proofgate_fast", False), ("proofgate_full", True)):
        rows, proven_rows, per_app, secs = [], [], {}, []
        for app, res, dt_s in await asyncio.gather(*(one(a, full) for a in apps)):
            r = res.report
            rows += rows_of(app.name, r.findings, mode)
            proven_rows += rows_of(app.name, [f for f in r.findings if f.proven], mode)
            per_app[app.name] = {"raw": r.raw_warning_count, "unique": r.unique_count, "proven": r.proven_count,
                                 "seconds": round(dt_s, 2), "layers_run": r.layers_run, "tool_error": res.tool_error}
            secs.append(dt_s)
        out[mode] = {"available": True, "rows": rows, "proven_rows": proven_rows, "per_app": per_app,
                     "seconds_median": median(secs), "seconds_max": round(max(secs), 2) if secs else None}
    return out


# ------------------------------------------------------------------------------------ fixes: re-scan vs tournament
async def fix_verification(lock: ToolLock, skip_network: bool) -> dict:
    meta = json.loads((FIXES / "fixes.json").read_text(encoding="utf-8"))
    truth = truth_from_json(json.loads((CORPUS / "ground_truth.json").read_text(encoding="utf-8")))
    details, naive, tournament = [], [], []
    for name, m in sorted(meta.items()):
        app = CORPUS / m["app"]
        orig = (app / "app.py").read_text(encoding="utf-8")
        fixed = (FIXES / name / "app.py").read_text(encoding="utf-8")
        patch = make_diff("app.py", orig, fixed)
        gt = [t for t in truth if t.app == m["app"]]

        # (a) "re-scan says clean": apply the patch to a copy, run the fast static layers, ask whether the flaw is still reported
        with tempfile.TemporaryDirectory(prefix="proofgate-bench-", ignore_cleanup_errors=True) as td:
            copy = Path(td) / m["app"]
            shutil.copytree(app, copy, ignore=shutil.ignore_patterns(".proofgate", "__pycache__"))
            (copy / "app.py").write_text(fixed, encoding="utf-8")
            scan = await run_scan(copy, layers=[1, 2, 5], lock=lock, tools_dir=TOOLS_DIR, offline=True)
            after = rows_of(m["app"], scan.report.findings, "rescan")
        still_flagged = any(any(r.category == t.category and abs(r.line - t.line) <= TOLERANCE and r.file == t.file for r in after) for t in gt)
        naive_accept = not still_flagged

        # (b) the tournament
        out = await run_probe(app)
        findings = out.result.to_findings(out.contract)
        want = {"v01": "cross-user-read", "v05": "admin-route-unauthenticated", "v06": "mass-assignment", "v07": "sql-injection"}[name[:3]]
        finding = next(f for f in findings if f.rule == want)
        base = await compute_baseline(app, out.contract)
        res = await run_tournament(app, finding, [Candidate(patch, "B", name)], out.contract, baseline=base)
        naive.append((naive_accept, m["should_accept"]))
        tournament.append((res.accepted, m["should_accept"]))
        details.append({"fix": name, "kind": m["kind"], "should_accept": m["should_accept"], "rescan_says_clean": naive_accept,
                        "tournament_accepts": res.accepted, "tournament_reason": res.rejected[0].reason if res.rejected else None})
    return {"cases": len(details), "rescan_accuracy": accuracy(naive), "tournament_accuracy": accuracy(tournament),
            "tournament_correct": f"{sum(1 for p, s in tournament if p == s)}/{len(tournament)}", "details": details}


# ------------------------------------------------------------------------------------ latency
def latency(apps: list[Path]) -> dict:
    medians = {}
    for app in apps:
        f = app / "app.py"
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8")
        samples = []
        for _ in range(50):
            t = time.perf_counter()
            check_file(f, text, project_root=app)
            samples.append((time.perf_counter() - t) * 1000)
        medians[app.name] = statistics.median(samples)
    # the real hook entry point, including JSON parsing and the thread hand-off
    with tempfile.TemporaryDirectory(prefix="proofgate-bench-hook-") as td:
        root = Path(td)
        src = (CORPUS / "v07_sqli" / "app.py").read_text(encoding="utf-8")
        payload = json.dumps({"cwd": str(root), "tool_name": "Write", "tool_input": {"file_path": str(root / "app.py"), "content": src}})
        samples = []
        for _ in range(50):
            t = time.perf_counter()
            run_hook("pre", payload, project_dir=str(root))
            samples.append((time.perf_counter() - t) * 1000)
        fail_open = read_fail_open_count(root)
    return {"inline_check_median_ms_per_file": median(list(medians.values())), "inline_check_worst_median_ms": round(max(medians.values()), 3) if medians else None,
            "hook_pre_median_ms": median(samples), "hook_fail_open_count": fail_open, "runs_per_file": 50, "files": len(medians)}


# ------------------------------------------------------------------------------------ assembling
def tables(columns: dict[str, dict], truth: list[Truth], apps: list[Path]) -> dict:
    out = {}
    for name, col in columns.items():
        if not col.get("available"):
            out[name] = {"available": False, "reason": col.get("reason", "")}
            continue
        s = score(col["rows"], truth)
        out[name] = {"available": True, **s}
        if name == "union":
            out[name]["of"] = col["of"]
    return out


def secret_leak_check(results: dict) -> int:
    from proofgate.redact import find_leaks

    return len(find_leaks(json.dumps(results)))


async def run(args) -> dict:
    only = set(args.apps.split(",")) if args.apps else None
    generate_corpus.materialize()
    lock, tool_info = pinned_lock()
    apps = app_dirs(CORPUS, only)
    truth_all = truth_from_json(json.loads((CORPUS / "ground_truth.json").read_text(encoding="utf-8")))
    truth = [t for t in truth_all if only is None or t.app in only]
    started = time.time()

    baselines = await run_baselines(apps, lock, args.skip_network)
    with tempfile.TemporaryDirectory(prefix="proofgate-bench-cache-") as cache:
        pg = await run_proofgate(apps, lock, args.skip_network, Path(cache))
    columns = {**baselines, **pg}

    held_apps = app_dirs(HELDOUT)
    held_truth_file = HELDOUT / "ground_truth.json"
    heldout = None
    if held_apps and held_truth_file.is_file():
        h_truth = truth_from_json(json.loads(held_truth_file.read_text(encoding="utf-8")))
        h_base = await run_baselines(held_apps, lock, args.skip_network)
        with tempfile.TemporaryDirectory(prefix="proofgate-bench-cache-") as cache:
            h_pg = await run_proofgate(held_apps, lock, args.skip_network, Path(cache))
        heldout = {"apps": len(held_apps), "tables": tables({**h_base, **h_pg}, h_truth, held_apps)}

    result = {
        "schema": "proofgate.bench/v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "proofgate_version": __version__,
        "environment": {"python": platform.python_version(), "platform": platform.platform(), "network": not args.skip_network,
                        "subset": sorted(only) if only else None, "tolerance_lines": TOLERANCE, "bench_seconds": None},
        "tools": tool_info,
        "corpus": {"apps": len(apps), "ground_truth_items": len(truth), "clean_apps": sum(1 for a in apps if a.name.startswith("c")),
                   "categories": CATEGORIES},
        "tables": tables(columns, truth, apps),
        "heldout": heldout if heldout else {"apps": 0, "note": "the sealed held-out set (plan 14) was not provided: demo-apps/heldout/ is empty, so no held-out number exists"},
        "counts": {name: {"raw": sum(v["raw"] for v in col["per_app"].values()), "unique": sum(v["unique"] for v in col["per_app"].values()),
                          "proven": sum(v["proven"] for v in col["per_app"].values()), "per_app": col["per_app"],
                          "seconds_median_per_app": col["seconds_median"], "seconds_max_per_app": col["seconds_max"]}
                   for name, col in pg.items()},
    }
    proven_scored = score(pg["proofgate_full"]["proven_rows"], [t for t in truth if t.category in ("access", "injection")])
    result["proof_rate"] = {"definition": "share of access + injection ground-truth items that ProofGate PROVED (a canary crossed a boundary)",
                            "recall": proven_scored["overall"]["recall"], "proven_precision": proven_scored["overall"]["precision"],
                            "proven_findings": proven_scored["overall"]["matching_findings"] + proven_scored["overall"]["false_positives"],
                            "false_positives": proven_scored["false_positives"]}
    result["latency"] = latency(apps)
    if not only:
        result["fix_verification"] = await fix_verification(lock, args.skip_network)
    else:
        result["fix_verification"] = {"note": "skipped for a subset run"}
    result["misses_and_false_positives"] = {n: {"misses": t["misses"], "false_positives": t["false_positives"]}
                                            for n, t in result["tables"].items() if t.get("available")}
    access_pg = result["tables"]["proofgate_full"]["by_category"]["access"]["recall"]
    result["targets"] = {
        "plan_targets_not_results": TARGETS,
        "access_recall_corpus": {"measured": access_pg, "target": TARGETS["access_recall_corpus"], "met": access_pg is not None and access_pg >= 0.85},
        "proven_precision": {"measured": proven_scored["overall"]["precision"], "target": 0.95,
                             "met": proven_scored["overall"]["precision"] is not None and proven_scored["overall"]["precision"] >= 0.95},
        "inline_median_ms": {"measured": result["latency"]["inline_check_median_ms_per_file"], "target": 200,
                             "met": (result["latency"]["inline_check_median_ms_per_file"] or 1e9) <= 200},
    }
    result["notes"] = [
        "Small synthetic corpus: 16 Flask apps with one planted flaw each. These numbers say how ProofGate does on THIS corpus, not on real apps.",
        "The corpus and ProofGate's rules were written by the same team. Rules were not tuned after seeing results; any later tuning must be "
        "disclosed in bench/README.md.",
        "Layers 6, 7 and 9 are not built yet, so 'bundle' and 'config' recall mostly reflect layer 1-5 only.",
        "The 'union' column combines the baseline tools that were available on this machine, listed in tables.union.of.",
    ]
    result["environment"]["bench_seconds"] = round(time.time() - started, 1)
    leaks = secret_leak_check(result)
    result["targets"]["raw_secrets_in_outputs"] = {"measured": leaks, "target": 0, "met": leaks == 0}
    return result


def print_table(result: dict) -> None:
    print(f"\nProofGate benchmark: {result['corpus']['apps']} apps, {result['corpus']['ground_truth_items']} ground-truth items "
          f"(network: {result['environment']['network']})\n")
    print(f"{'column':16} {'precision':>9} {'recall':>7} {'F1':>6}   {'access recall':>13}")
    for name, t in result["tables"].items():
        if not t.get("available"):
            print(f"{name:16} {'unavailable: ' + t['reason'][:70]}")
            continue
        o, a = t["overall"], t["by_category"]["access"]
        f = lambda x: "-" if x is None else f"{x:.2f}"  # noqa: E731
        print(f"{name:16} {f(o['precision']):>9} {f(o['recall']):>7} {f(o['f1']):>6}   {f(a['recall']):>13}")
    fv = result.get("fix_verification", {})
    if "cases" in fv:
        print(f"\nfix verification on {fv['cases']} fixes: re-scan-says-clean {fv['rescan_accuracy']}, tournament {fv['tournament_accuracy']} ({fv['tournament_correct']})")
    lat = result["latency"]
    print(f"inline check median {lat['inline_check_median_ms_per_file']} ms/file; hook median {lat['hook_pre_median_ms']} ms; fail-open {lat['hook_fail_open_count']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip-network", action="store_true")
    ap.add_argument("--apps", help="comma-separated corpus app names (subset run)")
    ap.add_argument("--out", default=str(ROOT / "bench" / "results.json"))
    args = ap.parse_args(argv)
    result = asyncio.run(run(args))
    Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8", newline="\n")
    print_table(result)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
