"""The Doppelganger probe (layer 8). Entry point: `run_probe`."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Contract
from ..redact import redact
from .flask import FlaskProbe
from .guard import TargetRefused, check_target
from .launcher import AppProcess, LaunchError, find_entry
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


def is_supabase_project(project: Path) -> bool:
    if (project / "supabase").is_dir():
        return True
    pkg = project / "package.json"
    try:
        return pkg.is_file() and "@supabase/" in pkg.read_text(encoding="utf-8")
    except OSError:
        return False


async def run_supabase_probe(project: Path, contract: Contract, *, backend: str | None, i_own_this: bool) -> ProbeOutcome:
    """Attack the project's Supabase tables through the API of the configured backend (hosted test project, or a local stack)."""
    from ..supabase_target import BackendUnavailable, SupabaseTargetRefused, load_config, resolve_target
    from .supabase import PsycopgDb, SupabaseProbe

    result = ProbeResult(launched=False)
    try:
        tgt = resolve_target(load_config(project), backend=backend, i_own_this=i_own_this)
    except BackendUnavailable as e:  # nothing to attack with: UNTESTED, never "safe"
        result.untested.append(f"Supabase tables not probed: {redact(str(e))}")
        return ProbeOutcome(result, contract)
    except SupabaseTargetRefused as e:
        return ProbeOutcome(result, contract, error=redact(str(e)))
    db = None
    if tgt.db_url:
        try:
            db = PsycopgDb(tgt.connect())
        except BackendUnavailable as e:
            result_note = f"no database connection ({redact(str(e))}): rows cannot be seeded or cleaned up directly"
        else:
            result_note = ""
    else:
        result_note = "SUPABASE_DB_URL is not set: table columns cannot be inspected and rows cannot be cleaned up directly"
    res = await SupabaseProbe(tgt, contract, db).run()
    if result_note:
        res.notes.append(result_note)
    return ProbeOutcome(res, contract, [tgt.override_note] if tgt.override_note else [])


async def run_probe(project: str | Path, contract: Contract | None = None, *, target: str | None = None,
                    i_own_this: bool = False, python: str | None = None, backend: str | None = None) -> ProbeOutcome:
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
    if decision is None and find_entry(project) is None and is_supabase_project(project):
        return await run_supabase_probe(project, contract, backend=backend, i_own_this=i_own_this)

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
