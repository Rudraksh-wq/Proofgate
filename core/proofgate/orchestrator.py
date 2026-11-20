"""Runs the layers, merges their findings and builds the Report (plan 6.1).

Layers that exist run concurrently. A layer that is not built yet, or that crashes, is recorded in
`report.notes`; a crash also sets `tool_error`, so the CLI exits 2 and the result is never read as "clean".
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from .layers import l1_secrets, l2_sast, l3_deps, l4_supply_chain, l5_database, l8_access
from .layers.base import LayerResult, Runner, run_tool
from .models import LIMITS_STATEMENT, Receipt, Report, Tested, ToolRecord
from .normalize import normalize
from .redact import redact
from .sarif import to_sarif
from .report_html import to_html

ALL_LAYERS = list(range(1, 10))  # --full: everything, including the probe (L8) which starts the app
FAST_LAYERS = [1, 2, 3, 4, 5, 6, 9]  # L5 here is the static SQL check; Splinter needs the live stack  # plan 2 tiering: fast = L1-L4, L6, L9 on the changed files
DEFAULT_LAYERS = FAST_LAYERS  # a plain `scan` never launches the app; use --full or `prove`
FAST_TIMEOUT_S = 10.0
_STATUS_BADNESS = ["ok", "skipped", "unpinned", "timeout", "mismatch", "error"]
_TOOL_ERRORS = {"error", "mismatch"}  # skipped/unpinned are recorded, not errors: the user can see and fix them


@dataclass
class ScanOutcome:
    report: Report
    layer_results: list[LayerResult] = field(default_factory=list)
    tool_error: bool = False


async def _call(layer: int, project: Path, runner: Runner, kw: dict[str, Any]) -> LayerResult:
    common = {"runner": runner, "lock": kw.get("lock")}
    if layer == 1:
        return await l1_secrets.run(project, **common)
    if layer == 2:
        return await l2_sast.run(project, tools_dir=kw.get("tools_dir"), **common)
    if layer == 3:
        return await l3_deps.run(project, tools_dir=kw.get("tools_dir"), offline=kw.get("offline"), **common)
    if layer == 4:
        return await l4_supply_chain.run(project, cache=kw.get("cache"), client=kw.get("client"), offline=kw.get("offline"),
                                         tools_dir=kw.get("tools_dir"), **common)
    if layer == 5:
        return await l5_database.run(project, contract=kw.get("contract"))
    if layer == 8:
        return await l8_access.run(project, contract=kw.get("contract"), target=kw.get("target"),
                                   i_own_this=bool(kw.get("i_own_this")))
    raise NotImplementedError(layer)


IMPLEMENTED = {1, 2, 3, 4, 5, 8}


def _git_commit(project: Path) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(project), "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                           timeout=5)
        return r.stdout.strip() or None if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def report_hash(report: Report) -> str:
    body = report.to_json_dict()
    body["receipt"] = {**body["receipt"], "report_hash": None}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _worst_tools(results: list[LayerResult]) -> list[ToolRecord]:
    best: dict[str, ToolRecord] = {}
    for res in results:
        for t in res.tools:
            cur = best.get(t.name)
            if cur is None or _STATUS_BADNESS.index(t.status) > _STATUS_BADNESS.index(cur.status):
                best[t.name] = t
    return sorted(best.values(), key=lambda t: t.name)


async def run_scan(project_dir: str | Path, *, layers: list[int] | None = None, fast: bool = False, full: bool = False,
                   runner: Runner = run_tool, fast_timeout: float = FAST_TIMEOUT_S, **layer_kwargs: Any) -> ScanOutcome:
    """layer_kwargs: lock, tools_dir, offline, cache, client (layers 1-4); contract, target, i_own_this (layer 8)."""
    project = Path(project_dir).resolve()
    requested = sorted(set(layers if layers else (FAST_LAYERS if fast else ALL_LAYERS if full else DEFAULT_LAYERS)))
    runnable = [n for n in requested if n in IMPLEMENTED]
    notes = [f"layer {n}: not built yet in this version: not run" for n in requested if n not in IMPLEMENTED]
    tool_error = False

    async def one(n: int) -> tuple[int, LayerResult | None, str | None]:
        try:
            coro: Awaitable[LayerResult] = _call(n, project, runner, layer_kwargs)
            res = await (asyncio.wait_for(coro, fast_timeout) if fast else coro)
            return n, res, None
        except asyncio.TimeoutError:
            return n, None, f"layer {n}: timed out after {fast_timeout:g}s in --fast mode: not completed"
        except Exception as e:  # noqa: BLE001 - one broken layer must not hide the others
            return n, None, f"layer {n}: failed: {redact(f'{type(e).__name__}: {e}')}"

    results: list[LayerResult] = []
    layers_run: list[int] = []
    for n, res, err in await asyncio.gather(*(one(n) for n in runnable)):
        if res is None:
            notes.append(err or f"layer {n}: failed")
            tool_error = True
            continue
        layers_run.append(n)
        results.append(res)
        notes += [f"layer {n}: {x}" for x in res.notes]

    tools = _worst_tools(results)
    # no layer ran at all (e.g. only unbuilt layers requested) must never look like a clean scan
    tool_error = tool_error or not layers_run or any(t.status in _TOOL_ERRORS for t in tools)
    raw = [f for res in results for f in res.findings]
    norm = normalize(raw)

    probe = next((r for r in results if r.layer == 8), None)
    attacked, held = (probe.receipt_counts or (0, 0)) if probe else (0, 0)
    report = Report(
        project=project.name, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        layers_run=sorted(layers_run), raw_warning_count=norm.raw_warning_count, unique_count=norm.unique_count,
        proven_count=norm.proven_count, findings=norm.findings, fixes=[],
        receipt=Receipt(rules_attacked=attacked, rules_held=held, commit=_git_commit(project)),
        tested=Tested(tables=probe.tested_tables if probe else [], routes=probe.tested_routes if probe else []),
        untested=probe.untested if probe else [], tools=tools, limits_statement=LIMITS_STATEMENT, notes=notes,
        target_overrides=probe.target_overrides if probe else [],
    )
    report = report.model_copy(update={"receipt": report.receipt.model_copy(update={"report_hash": report_hash(report)})})
    return ScanOutcome(report, results, tool_error)


def write_outputs(project_dir: str | Path, report: Report, *, sarif: bool = False) -> dict[str, Path]:
    """Write .proofgate/report.json and report.html (and report.sarif). Local files only; nothing is uploaded."""
    out = Path(project_dir) / ".proofgate"
    out.mkdir(exist_ok=True)
    paths = {"json": out / "report.json", "html": out / "report.html"}
    paths["json"].write_text(report.to_json(), encoding="utf-8", newline="\n")
    paths["html"].write_text(to_html(report), encoding="utf-8", newline="\n")
    if sarif:
        paths["sarif"] = out / "report.sarif"
        paths["sarif"].write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8", newline="\n")
    return paths
