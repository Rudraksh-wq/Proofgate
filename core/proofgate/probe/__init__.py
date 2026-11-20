"""The Doppelganger probe (layer 8). Entry point: `run_probe`."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Contract
from ..redact import redact
from .flask import FlaskProbe
from .guard import TargetRefused, check_target
from .launcher import AppProcess, LaunchError
from .result import ProbeResult


@dataclass
class ProbeOutcome:
    result: ProbeResult
    contract: Contract
    overrides: list[str] = field(default_factory=list)  # non-local targets allowed by --i-own-this (logged in the report)
    error: str | None = None  # the app could not be started or the target was refused: NOT a clean result


def load_contract(project: Path) -> Contract:
    saved = project / ".proofgate" / "contract.json"
    if saved.is_file():
        try:
            return Contract.model_validate(json.loads(saved.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            pass
    from ..ai.fallback import draft_contract

    return draft_contract(project)


async def run_probe(project: str | Path, contract: Contract | None = None, *, target: str | None = None,
                    i_own_this: bool = False, python: str | None = None) -> ProbeOutcome:
    project = Path(project).resolve()
    contract = contract or load_contract(project)
    result = ProbeResult(launched=False)
    decision = None
    if target and target != "local":
        try:
            decision = check_target(target, i_own_this=i_own_this)  # the guard always runs first
        except TargetRefused as e:
            return ProbeOutcome(result, contract, error=str(e))
    if not contract.owned_resources and not contract.admin_only_routes:
        result.untested.append("no owned resources or admin routes in the contract: nothing to attack")
        return ProbeOutcome(result, contract)

    if decision is not None:
        overrides = [f"{decision.url} (--i-own-this)"] if decision.override else []
        probe = FlaskProbe(project, contract, decision.url, db_path=None)
        res = await probe.run()
        res.notes.append("attached to a running app: no database access, so admin seeding and row checks were skipped")
        return ProbeOutcome(res, contract, overrides)

    try:
        async with AppProcess.start(project, python) as app:
            probe = FlaskProbe(project, contract, app.url, db_path=app.db_path)
            res = await probe.run()
    except LaunchError as e:
        return ProbeOutcome(result, contract, error=redact(str(e)))
    return ProbeOutcome(res, contract)
