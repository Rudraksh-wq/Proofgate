"""ProofGate CLI (plan 6.1). `scan` and `report` are real; the other commands are still stubs that return SAMPLE data.

Exit codes: 0 = clean at --fail-on, 1 = findings, 2 = tool error (never "clean").
`hook` is the exception: it must never break the agent, so errors are logged and exit 0.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

from .models import AcceptedRisk, Contract, Finding, FixResult, Report
from .redact import redact, redact_obj
from .sample import SAMPLE_FIX

SEV = ["low", "medium", "high", "critical"]
FORMATS = ["json", "sarif", "html", "agent"]


class CliError(Exception):
    """Tool error -> exit code 2."""


def _dump(model) -> str:
    # every output path goes through the redactor (plan 8)
    return redact_obj(model).model_dump_json(indent=2, by_alias=True)


def _exit_for(findings: list[Finding], fail_on: str) -> int:
    t = SEV.index(fail_on)
    return 1 if any(SEV.index(f.severity) >= t and f.status != "accepted-risk" for f in findings) else 0  # accepted risks never fail the gate


def _project(path: str) -> Path:
    d = Path(path)
    if not d.is_dir():
        raise CliError(f"not a directory: {d}")
    return d


def _check_target(a) -> None:
    target = getattr(a, "target", "local")
    if target != "local" and not getattr(a, "i_own_this", False):
        raise CliError("remote targets are refused unless --i-own-this is given")


def cmd_init(a) -> int:
    """Detect the stack, save a DRAFT contract, and write the agent integration files (MCP config, hooks, rules).
    Existing files are merged, never overwritten; Windsurf's global MCP config is written as a snippet, not edited."""
    import asyncio

    from .agents import InitError, detect_agents, detect_stack, init_agent
    from .ai.contract import build_contract

    d = _project(a.dir)
    stack = detect_stack(d)
    print(f"stack: {', '.join(stack) or 'not recognised'}")
    agents = [a.agent] if a.agent else detect_agents(d)
    refused = False
    for agent in agents:
        try:
            changes = init_agent(d, agent, dry_run=a.dry_run)
        except InitError as e:
            raise CliError(str(e))
        print(f"{agent}:" + (" (dry run, nothing written)" if a.dry_run else ""))
        for c in changes:
            refused |= c.action == "refused"
            print(f"  {c.action:9} {c.path}" + (f"  - {c.note}" if c.note else ""))
    saved = d / ".proofgate" / "contract.json"
    if not saved.is_file() and not a.dry_run:
        res = asyncio.run(build_contract(d))
        saved.parent.mkdir(exist_ok=True)
        saved.write_text(_dump(res.contract), encoding="utf-8", newline="\n")
        print("contract: draft saved to .proofgate/contract.json; check it, then `proofgate contract <dir> --confirm`")
    print("next: `proofgate doctor` to verify the tools, then scan with `proofgate scan <dir>`")
    return 2 if refused else 0


def cmd_contract(a) -> int:
    """Build, show and confirm the Intent Contract. Gemini proposes (redacted, optional); a deterministic heuristic wins
    ties; anything that would make data MORE public is listed in needs_confirmation and NOT applied until you name it
    with --accept-public. Without --confirm the contract stays a draft ("against draft contract")."""
    import asyncio

    from .ai.contract import build_contract, confirm_contract
    from .models import Contract as ContractModel

    d = _project(a.dir)
    saved = d / ".proofgate" / "contract.json"
    contract = None
    if saved.is_file() and not a.refresh:
        try:
            contract = ContractModel.model_validate_json(saved.read_text(encoding="utf-8"))
        except ValueError:
            contract = None
    if contract is None:
        result = asyncio.run(build_contract(d))
        contract = result.contract
        for note in result.notes:
            print(f"note: {note}", file=sys.stderr)
    if a.confirm:
        contract, unresolved = confirm_contract(contract, a.accept_public)
        if unresolved:
            print("note: still owner-only (not accepted): " + ", ".join(unresolved)
                  + "\n      pass --accept-public <item> for each one you really want public", file=sys.stderr)
    elif a.accept_public:
        raise CliError("--accept-public only makes sense together with --confirm")
    out = d / ".proofgate"
    out.mkdir(exist_ok=True)
    saved.write_text(_dump(contract), encoding="utf-8", newline="\n")
    print(_dump(contract))
    if not contract.confirmed_by_user:
        print("note: draft contract. Check the rules, then run `proofgate contract <dir> --confirm`.", file=sys.stderr)
    return 0


def _agent_text(report: Report) -> str:
    """Short plain text for an AI agent: counts, the top findings, the limits sentence. At most 20 lines."""
    lines = [f"ProofGate: {report.raw_warning_count} raw -> {report.unique_count} unique -> {report.proven_count} proven."]
    for f in report.findings[:14]:
        lines.append(f"- [{f.severity}{', proven' if f.proven else ''}] {f.title.split(' (')[0]} ({f.location.file}:{f.location.line})")
    if len(report.findings) > 14:
        lines.append(f"... and {len(report.findings) - 14} more in .proofgate/report.json")
    from .accepted import forced_lines

    lines.extend(forced_lines(report.accepted_risks))  # forced acceptances of proven criticals are never hidden
    if report.accepted_risks:
        lines.append(f"{len(report.accepted_risks)} accepted risk(s) are excluded from the exit code (see .proofgate/accepted.yml).")
    lines.extend(f"note: {n}" for n in report.notes[:2])
    lines.append(report.limits_statement or "")
    return "\n".join(lines[:20])


def cmd_scan(a) -> int:
    import asyncio

    from .orchestrator import run_scan, write_outputs

    d = _project(a.dir)
    layers = None
    if a.layers:
        try:
            layers = [int(x) for x in a.layers.split(",")]
        except ValueError:
            raise CliError(f"--layers must be comma-separated integers 1-9, got {a.layers!r}")
        if any(not 1 <= x <= 9 for x in layers):
            raise CliError("--layers values must be between 1 and 9")
    outcome = asyncio.run(run_scan(d, layers=layers, fast=a.fast, full=a.full, backend=a.backend, i_own_this=a.i_own_this))
    report = outcome.report
    paths = write_outputs(d, report, sarif=a.format == "sarif")
    if a.format == "json":
        print(_dump(report))
    elif a.format == "sarif":
        print(paths["sarif"].read_text(encoding="utf-8"))
    elif a.format == "agent":
        print(redact(_agent_text(report)))
    else:
        print(f"wrote {paths['html']}")
    _print_accepted_summary(report)
    if outcome.tool_error:
        print("error: a layer or tool failed; this result is NOT a clean bill of health (see notes in the report)",
              file=sys.stderr)
        return 2
    return _exit_for(report.findings, a.fail_on)


def _print_accepted_summary(report: Report) -> None:
    from .accepted import forced_lines

    if report.accepted_risks:
        print(f"accepted risks: {len(report.accepted_risks)} (not counted toward --fail-on)", file=sys.stderr)
    for line in forced_lines(report.accepted_risks):
        print(redact(line), file=sys.stderr)


def cmd_prove(a) -> int:
    """Run layer 8 only: attack the app as a second user on a throwaway database. Writes .proofgate/report.json."""
    import asyncio

    from .orchestrator import run_scan, write_outputs

    d = _project(a.dir)
    outcome = asyncio.run(run_scan(d, layers=[8], target=a.target, i_own_this=a.i_own_this, backend=a.backend))
    report = outcome.report
    write_outputs(d, report)
    print(_dump(report))
    if outcome.tool_error:
        print("error: the probe could not run; this result is NOT a clean bill of health (see notes in the report)",
              file=sys.stderr)
        return 2
    return _exit_for(report.findings, a.fail_on)


def _load_finding(d: Path, finding_id: str) -> Finding:
    p = d / ".proofgate" / "report.json"
    if not p.is_file():
        raise CliError(f"{p} not found; run `proofgate scan` or `proofgate prove` first")
    report = Report.model_validate_json(p.read_text(encoding="utf-8"))
    for f in report.findings:
        if f.id == finding_id:
            return f
    raise CliError(f"no finding {finding_id!r} in {p}; known: {', '.join(f.id for f in report.findings[:8]) or 'none'}")


def cmd_fix(a) -> int:
    """Classify the finding, build Tier A/B candidates, run the tournament in a temp copy, then vaccinate (a regression
    test that fails before and passes after, plus the learned rule). Prints the FixResult; nothing is applied to your
    project: apply `winner.patch` and `vaccine_patch` yourself (or let your agent). The result is recorded in report.json."""
    import asyncio

    from .fix.pipeline import fix_finding
    from .fix.record import record_fix
    from .fix.vaccinate import build_vaccine
    from .probe import load_contract

    d = _project(a.dir)
    finding = _load_finding(d, a.finding)
    contract = load_contract(d)

    async def go():
        result = await fix_finding(d, finding, contract)
        if result.accepted and not a.no_vaccine:
            vac = await build_vaccine(d, finding, result, contract)
            result = result.model_copy(update={
                "vaccine_patch": vac.patch or None,
                "regression_test": vac.test_id if vac.verified is not False else None,
                "notes": sorted({*result.notes, *vac.notes})})
        return result

    result = asyncio.run(go())
    record_fix(d, result)
    print(_dump(result))
    return 0 if result.accepted else 1


def cmd_verify(a) -> int:
    """Run a patch somebody else wrote (an AI agent, a human) through the same gates."""
    import asyncio

    from .fix.pipeline import verify_patch
    from .probe import load_contract

    d = _project(a.dir)
    finding = _load_finding(d, a.finding)
    patch_file = Path(a.patch)
    if not patch_file.is_file():
        raise CliError(f"patch file not found: {patch_file}")
    result = asyncio.run(verify_patch(d, finding, patch_file.read_text(encoding="utf-8"), load_contract(d)))
    print(_dump(result))
    return 0 if result.accepted else 1


def _parse_expires(text: str) -> dt.date:
    m = re.fullmatch(r"(\d+)d", text)
    if m:
        return dt.date.today() + dt.timedelta(days=int(m.group(1)))
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        raise CliError("--expires must look like 90d or YYYY-MM-DD")


def _last_report(d: Path) -> Report | None:
    try:
        return Report.model_validate_json((d / ".proofgate" / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def cmd_accept(a) -> int:
    """A PERSON accepts a risk (agents must never run this). Writes .proofgate/accepted.yml, which is committed."""
    from . import accepted

    d = _project(a.dir)
    try:
        if a.list:
            risks = accepted.load(d)
            if not risks:
                print("no accepted risks")
            for r in risks:
                state = "EXPIRED" if r.is_expired() else "active"
                print(f"{state}  {r.fingerprint}  owner={r.owner}  expires={r.expires.isoformat()}{'  FORCED' if r.forced else ''}  reason: {redact(r.reason)}")
            return 0
        if not a.fingerprint or not a.reason:
            raise CliError('usage: proofgate accept <fingerprint> --reason "..." [--expires 90d] [--owner NAME] [--force]  (or --list)')
        report = _last_report(d)
        fingerprint, finding = a.fingerprint, None
        if report is not None:
            finding = next((f for f in report.findings if f.fingerprint == fingerprint or f.id == fingerprint), None)
            if finding is not None and finding.fingerprint:
                fingerprint = finding.fingerprint
        if finding is None:
            if fingerprint.startswith("f_"):
                raise CliError(f"finding id {fingerprint} is not in .proofgate/report.json: run `proofgate scan` first, or pass the fingerprint")
            print("note: this fingerprint is not in the last report, so ProofGate cannot check whether it is a proven critical problem; "
                  "such an entry is ignored unless it was made with --force", file=sys.stderr)
        risk = accepted.add(d, fingerprint, reason=a.reason, expires=_parse_expires(a.expires), owner=a.owner, force=a.force, finding=finding)
    except accepted.AcceptedError as e:
        raise CliError(str(e))
    print(_dump(risk))
    warn = "\nWARNING: forced acceptance of a proven critical problem; it will be shown in every summary" if a.force and finding and accepted.needs_force(finding) else ""
    print(f"recorded in {accepted.FILE_REL}: commit this file so the decision is reviewed with the code{warn}", file=sys.stderr)
    return 0


def cmd_hook(a) -> int:
    """Hook entry point for Claude Code / Cursor (JSON on stdin). PRE blocks a write that would add a critical secret or a
    package that does not exist (exit 2, or a JSON deny with --mode json). Any crash or slow check is logged, counted and
    ALLOWED: a hook must never break the agent."""
    from .hook import run_hook

    try:
        outcome = run_hook(a.phase, sys.stdin.read(), mode=a.mode)
    except Exception as e:  # noqa: BLE001 - belt and braces: run_hook already never raises
        print(f"proofgate hook error (allowing): {e}", file=sys.stderr)
        return 0
    if outcome.stdout:
        print(outcome.stdout)
    if outcome.stderr:
        print(outcome.stderr, file=sys.stderr)
    return outcome.exit_code


def cmd_report(a) -> int:
    d = _project(a.dir)
    p = d / ".proofgate" / "report.json"
    if not p.is_file():
        raise CliError(f"{p} not found; run `proofgate scan` first")
    from .report_html import to_html

    report = Report.model_validate_json(p.read_text(encoding="utf-8"))
    html_path = p.with_name("report.html")
    html_path.write_text(to_html(report), encoding="utf-8", newline="\n")
    print(f"report: {p}\nhtml:   {html_path}\n(local files only; nothing is uploaded)")
    if a.open:
        import webbrowser

        webbrowser.open(html_path.resolve().as_uri())
    return 0


def cmd_rollback(a) -> int:
    """Print (never run) the command that undoes the recorded fix for a finding."""
    from .fix.record import rollback_commands

    try:
        cmds = rollback_commands(_project(a.dir), a.finding_id)
    except LookupError as e:
        raise CliError(str(e))
    print(chr(10).join(cmds))
    print("(ProofGate only prints this command; it never runs it.)", file=sys.stderr)
    return 0


def cmd_doctor(a) -> int:
    """Exit 1 if any tool's checksum/version mismatches the lock (never run those). --strict: also
    fail on missing/unpinned tools. Exit 2 if the lock file itself is unusable."""
    import asyncio

    from .doctor import check_all, pin_tool
    from .toollock import ToolLock

    try:
        lock = ToolLock.load()
    except Exception as e:  # noqa: BLE001
        raise CliError(f"cannot read tools.lock.json: {e}")
    if a.pin:
        try:
            res = pin_tool(a.pin, lock)
        except (KeyError, FileNotFoundError) as e:
            raise CliError(str(e))
        path = lock.save()
        print(f"pinned {res.name} {res.version or '(version unknown)'} -> {path}")
        return 0
    checks = asyncio.run(check_all(lock))
    backends = _backend_rows(a.dir)
    if a.json:
        # the tool list keeps its shape; Supabase backends follow as entries named "supabase:<backend>"
        print(json.dumps([c.__dict__ for c in checks] + [{"name": f"supabase:{n}", "status": st, "version": None, "detail": d} for n, st, d in backends], indent=2))
    else:
        for c in checks:
            print(f"{c.status:9} {c.name:12} {c.version or '-'}" + (f"  ({c.detail})" if c.detail else ""))
        print("\nsupabase backends (Docker is optional):")
        for name, status, detail in backends:
            print(f"  {name:8} {status:15} {detail}")
    bad = {"mismatch"} | ({"missing", "unpinned"} if a.strict else set())
    return 1 if any(c.status in bad for c in checks) else 0


def _backend_rows(directory: str | None) -> list[tuple[str, str, str]]:
    from .supabase_target import SupabaseTargetRefused, backend_status, load_config

    try:
        return backend_status(load_config(directory or "."))
    except SupabaseTargetRefused as e:
        return [("config", "invalid", redact(str(e)))]


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2 by default; keep it but via CliError for clarity
        raise CliError(message)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="proofgate", description="Local security gate for the AI coding loop.")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_Parser)

    def add(name, fn, *, dir_=True, fail_on=False, help=None):
        s = sub.add_parser(name, help=help)
        if dir_:
            s.add_argument("dir")
        if fail_on:
            s.add_argument("--fail-on", choices=SEV, default="high")
        s.set_defaults(fn=fn)
        return s

    s = add("init", cmd_init, help="detect stack, draft contract, write agent configs")
    s.add_argument("--agent", choices=["cursor", "codex", "windsurf", "claude"], help="default: detect from the project")
    s.add_argument("--dry-run", action="store_true")
    s = add("contract", cmd_contract, help="build/show/confirm the Intent Contract")
    s.add_argument("--confirm", action="store_true")
    s.add_argument("--refresh", action="store_true", help="rebuild instead of reusing .proofgate/contract.json")
    s.add_argument("--accept-public", action="append", default=[], metavar="ITEM",
                   help="allow one item from needs_confirmation to become public (repeatable; only with --confirm)")
    s = add("scan", cmd_scan, fail_on=True, help="run the layers, write .proofgate/report.json")
    s.add_argument("--layers")
    mode = s.add_mutually_exclusive_group()
    mode.add_argument("--fast", action="store_true")
    mode.add_argument("--full", action="store_true")
    s.add_argument("--format", choices=FORMATS, default="json")
    s.add_argument("--backend", choices=["hosted", "local", "auto"], default=None, help="Supabase backend (default: PROOFGATE_SUPABASE_BACKEND or auto)")
    s.add_argument("--i-own-this", action="store_true", help="confirm that a hosted Supabase test project is yours (needed for hosted live checks)")
    s = add("prove", cmd_prove, fail_on=True, help="run the Doppelganger probe")
    s.add_argument("--target", default="local")
    s.add_argument("--i-own-this", action="store_true")
    s.add_argument("--backend", choices=["hosted", "local", "auto"], default=None, help="Supabase backend (default: PROOFGATE_SUPABASE_BACKEND or auto)")
    s = add("fix", cmd_fix, help="run the fix pipeline for one finding")
    s.add_argument("--finding", required=True)
    s.add_argument("--no-vaccine", action="store_true", help="skip the regression test and the learned rule")
    s = add("verify", cmd_verify, help="run the tournament gates on a patch")
    s.add_argument("--finding", required=True)
    s.add_argument("--patch", required=True)
    s = add("accept", cmd_accept, dir_=False, help="record an accepted risk (a person, never an agent)")
    s.add_argument("fingerprint", nargs="?", help="finding fingerprint (or finding id from the last report)")
    s.add_argument("--reason")
    s.add_argument("--owner", default=None, help="default: the current user")
    s.add_argument("--expires", default="90d", help="30d, 90d... or YYYY-MM-DD")
    s.add_argument("--force", action="store_true", help="required to accept a finding that is proven and critical")
    s.add_argument("--list", action="store_true", help="list accepted risks")
    s.add_argument("--dir", default=".", help="project folder (default: current)")
    s = add("hook", cmd_hook, dir_=False, help="hook entry point (JSON on stdin)")
    s.add_argument("phase", choices=["pre", "post", "stop"])
    s.add_argument("--mode", choices=["exit2", "json"], default="exit2",
                   help="how PRE blocks: exit code 2 + stderr (default) or a JSON permissionDecision deny")
    s = add("report", cmd_report, help="validate and locate the local report")
    s.add_argument("--open", action="store_true")
    s = add("rollback", cmd_rollback, dir_=False, help="print the git command to undo a fix")
    s.add_argument("finding_id")
    s.add_argument("--dir", default=".")
    s = add("doctor", cmd_doctor, dir_=False, help="check external tools and checksums")
    s.add_argument("--pin", metavar="TOOL", help="record the SHA-256 + version of the installed tool")
    s.add_argument("--strict", action="store_true", help="fail on missing or unpinned tools too")
    s.add_argument("--json", action="store_true")
    s.add_argument("--dir", default=".", help="project folder whose .env configures the Supabase backends (default: current)")
    return p


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    is_hook = bool(args_list) and args_list[0] == "hook"
    try:
        try:
            a = build_parser().parse_args(args_list)
        except SystemExit as e:  # --help / --version
            return 0 if e.code in (0, None) else 2
        return a.fn(a)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return 0 if is_hook else 2
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 0 if is_hook else 2


if __name__ == "__main__":
    sys.exit(main())
