"""ProofGate CLI (plan 6.1). Stubs: every command returns correctly shaped SAMPLE data.

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
from .sample import SAMPLE_CONTRACT, SAMPLE_FINDING, SAMPLE_FIX, SAMPLE_TOOLS, sample_report

SEV = ["low", "medium", "high", "critical"]
FORMATS = ["json", "sarif", "html", "agent"]


class CliError(Exception):
    """Tool error -> exit code 2."""


def _dump(model) -> str:
    return model.model_dump_json(indent=2, by_alias=True)


def _exit_for(findings: list[Finding], fail_on: str) -> int:
    t = SEV.index(fail_on)
    return 1 if any(SEV.index(f.severity) >= t for f in findings) else 0


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
    d = _project(a.dir)
    print(f"[stub] would detect stack, draft contract, install hooks and verify tools in {d}")
    return 0


def cmd_contract(a) -> int:
    _project(a.dir)
    data = dict(SAMPLE_CONTRACT)
    if a.confirm:
        data["confirmed_by_user"] = True
    print(_dump(Contract.model_validate(data)))
    return 0


def _sarif_stub(report: Report) -> str:
    results = [
        {
            "ruleId": f.rule,
            "level": "error" if f.severity in ("critical", "high") else "warning",
            "message": {"text": f.title},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.location.file},
                "region": {"startLine": f.location.line},
            }}],
        }
        for f in report.findings
    ]
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "ProofGate"}}, "results": results}],
    }
    return json.dumps(doc, indent=2)


def _agent_text(report: Report) -> str:
    lines = [f"ProofGate: {report.unique_count} unique, {report.proven_count} proven."]
    for f in report.findings[:10]:
        lines.append(f"- [{f.severity}] {f.title} ({f.location.file}:{f.location.line})")
    lines.append(report.limits_statement or "")
    return "\n".join(lines)


def cmd_scan(a) -> int:
    d = _project(a.dir)
    layers = None
    if a.layers:
        try:
            layers = [int(x) for x in a.layers.split(",")]
        except ValueError:
            raise CliError(f"--layers must be comma-separated integers 1-9, got {a.layers!r}")
        if any(not 1 <= x <= 9 for x in layers):
            raise CliError("--layers values must be between 1 and 9")
    report = Report.model_validate(sample_report(d.name, layers))
    out = d / ".proofgate"
    out.mkdir(exist_ok=True)
    (out / "report.json").write_text(_dump(report), encoding="utf-8", newline="\n")
    if a.format == "json":
        print(_dump(report))
    elif a.format == "sarif":
        print(_sarif_stub(report))
    elif a.format == "agent":
        print(_agent_text(report))
    else:
        (out / "report.html").write_text(
            "<!doctype html><title>ProofGate (stub)</title><p>Sample report, not a scan result.</p>",
            encoding="utf-8",
        )
        print(f"wrote {out / 'report.html'}")
    return _exit_for(report.findings, a.fail_on)


def cmd_prove(a) -> int:
    _project(a.dir)
    _check_target(a)
    f = Finding.model_validate(SAMPLE_FINDING)
    print(_dump(f))
    return _exit_for([f], a.fail_on)


def cmd_fix(a) -> int:
    _project(a.dir)
    print(_dump(FixResult.model_validate({**SAMPLE_FIX, "finding_id": a.finding})))
    return 0


def cmd_verify(a) -> int:
    _project(a.dir)
    if not Path(a.patch).is_file():
        raise CliError(f"patch file not found: {a.patch}")
    res = FixResult.model_validate({**SAMPLE_FIX, "finding_id": a.finding})
    print(_dump(res))
    return 0 if res.accepted else 1


def _parse_expires(text: str) -> dt.date:
    m = re.fullmatch(r"(\d+)d", text)
    if m:
        return dt.date.today() + dt.timedelta(days=int(m.group(1)))
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        raise CliError("--expires must look like 90d or YYYY-MM-DD")


def cmd_accept(a) -> int:
    risk = AcceptedRisk(fingerprint=a.fingerprint, reason=a.reason, owner=a.owner, expires=_parse_expires(a.expires))
    print(f"[stub] would append to .proofgate/accepted.yml:\n{_dump(risk)}")
    return 0


def cmd_hook(a) -> int:
    """PreToolUse/PostToolUse entry point. Must never break the agent: log and allow."""
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
        print(json.dumps({"ok": True, "phase": a.phase, "decision": "allow"}))
    except Exception as e:  # noqa: BLE001 - fail-safe by design (plan 6.3)
        print(f"proofgate hook error (allowing): {e}", file=sys.stderr)
    return 0


def cmd_report(a) -> int:
    d = _project(a.dir)
    p = d / ".proofgate" / "report.json"
    if not p.is_file():
        raise CliError(f"{p} not found; run `proofgate scan` first")
    Report.model_validate_json(p.read_text(encoding="utf-8"))
    print(f"report: {p} (local only; nothing is uploaded)")
    return 0


def cmd_rollback(a) -> int:
    commit = SAMPLE_FIX["pre_fix_commit"]
    print(f"[stub] to undo {a.finding_id}, run:\n  git revert {commit}")
    return 0


def cmd_doctor(a) -> int:
    for t in SAMPLE_TOOLS:
        print(f"{t['name']}: {t['status']}")
    print("[stub] real checksum verification arrives with feat/03")
    return 0


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

    add("init", cmd_init, help="detect stack, draft contract, install hooks")
    s = add("contract", cmd_contract, help="build/show/confirm the Intent Contract")
    s.add_argument("--confirm", action="store_true")
    s = add("scan", cmd_scan, fail_on=True, help="run the layers, write .proofgate/report.json")
    s.add_argument("--layers")
    mode = s.add_mutually_exclusive_group()
    mode.add_argument("--fast", action="store_true")
    mode.add_argument("--full", action="store_true")
    s.add_argument("--format", choices=FORMATS, default="json")
    s = add("prove", cmd_prove, fail_on=True, help="run the Doppelganger probe")
    s.add_argument("--target", default="local")
    s.add_argument("--i-own-this", action="store_true")
    s = add("fix", cmd_fix, help="run the fix pipeline for one finding")
    s.add_argument("--finding", required=True)
    s = add("verify", cmd_verify, help="run the tournament gates on a patch")
    s.add_argument("--finding", required=True)
    s.add_argument("--patch", required=True)
    s = add("accept", cmd_accept, dir_=False, help="record an accepted risk")
    s.add_argument("fingerprint")
    s.add_argument("--reason", required=True)
    s.add_argument("--owner", default="unknown")
    s.add_argument("--expires", default="90d")
    s = add("hook", cmd_hook, dir_=False, help="hook entry point (JSON on stdin)")
    s.add_argument("phase", choices=["pre", "post"])
    s = add("report", cmd_report, help="validate and locate the local report")
    s.add_argument("--open", action="store_true")
    s = add("rollback", cmd_rollback, dir_=False, help="print the git command to undo a fix")
    s.add_argument("finding_id")
    add("doctor", cmd_doctor, dir_=False, help="check external tools and checksums")
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
