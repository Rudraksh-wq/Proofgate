"""Layer 8: access-control proof by attacking the app as a second user (plan 2, 3).

A thin wrapper over `proofgate.probe.run_probe`. Findings are only created for PROVEN checks; everything the probe
could not test is listed as untested, never reported as safe.
"""
from __future__ import annotations

from pathlib import Path

from ..models import Contract, ToolRecord
from ..redact import redact
from .base import LayerResult

LAYER = 8


async def run(project_dir: str | Path, *, contract: Contract | None = None, target: str | None = None,
              i_own_this: bool = False, **_ignored) -> LayerResult:
    from ..probe import run_probe

    out = await run_probe(project_dir, contract, target=target, i_own_this=i_own_this)
    res = LayerResult(layer=LAYER)
    if out.error:
        res.tools.append(ToolRecord(name="proofgate-probe", status="error"))
        res.notes.append(f"probe did not run: {redact(out.error)}")
        res.untested = [f"layer 8: not run ({redact(out.error)[:160]})"]
        return res
    res.tools.append(ToolRecord(name="proofgate-probe", status="ok"))
    res.findings = out.result.to_findings(out.contract)
    res.untested = list(out.result.untested)
    res.tested_tables = list(out.result.tested_tables)
    res.tested_routes = list(out.result.tested_routes)
    res.receipt_counts = out.result.rules_attacked_held(out.contract)
    res.target_overrides = list(out.overrides)
    res.notes += out.result.notes
    inconclusive = [c for c in out.result.checks if c.verdict == "INCONCLUSIVE"]
    res.notes += [f"inconclusive: {c.attack}) {c.request} -> {c.status} {c.note}".strip() for c in inconclusive]
    if not out.contract.confirmed_by_user:
        res.notes.append("results are against a DRAFT contract: confirm it with `proofgate contract <dir> --confirm`")
    return res
