import argparse
import json
import sys
from pathlib import Path

from .models import Contract, Finding, FixResult, Report
from .sample import SAMPLE_CONTRACT, SAMPLE_FINDING, SAMPLE_FIX, sample_report

SEV = ["low", "medium", "high", "critical"]


def _exit_for(findings: list[Finding], fail_on: str) -> int:
    t = SEV.index(fail_on)
    return 1 if any(SEV.index(f.severity) >= t for f in findings) else 0


def _dump(model) -> str:
    return model.model_dump_json(indent=2)


def cmd_contract(a) -> int:
    print(_dump(Contract(**SAMPLE_CONTRACT)))
    return 0


def cmd_scan(a) -> int:
    d = Path(a.dir)
    if not d.is_dir():
        print(f"error: not a directory: {d}", file=sys.stderr)
        return 2
    data = sample_report(d.name)
    if a.layers:
        data["layers_run"] = [int(x) for x in a.layers.split(",")]
    report = Report(**data)
    out = d / ".proofgate" / "report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(_dump(report), encoding="utf-8")
    print(_dump(report))
    return _exit_for(report.findings, a.fail_on)


def cmd_prove(a) -> int:
    f = Finding(**SAMPLE_FINDING)
    print(_dump(f))
    return _exit_for([f], a.fail_on)


def cmd_fix(a) -> int:
    print(_dump(FixResult(**{**SAMPLE_FIX, "finding_id": a.finding})))
    return 0


def cmd_verify(a) -> int:
    print(_dump(FixResult(**{**SAMPLE_FIX, "finding_id": a.finding})))
    return 0


def cmd_hook(a) -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        keys = sorted(payload) if isinstance(payload, dict) else []
        print(json.dumps({"ok": True, "received_keys": keys}))
    except Exception as e:  # a hook must never block the agent
        print(f"proofgate hook error: {e}", file=sys.stderr)
    return 0


def cmd_report(a) -> int:
    p = Path(a.dir) / ".proofgate" / "report.json"
    if not p.is_file():
        print(f"error: {p} not found; run `proofgate scan` first", file=sys.stderr)
        return 2
    Report(**json.loads(p.read_text(encoding="utf-8")))
    print(f"[stub] would upload {p} to {a.upload} (no network call made)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="proofgate")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, dir_=True, fail_on=False):
        s = sub.add_parser(name)
        if dir_:
            s.add_argument("dir")
        if fail_on:
            s.add_argument("--fail-on", choices=SEV, default="low")
        s.set_defaults(fn=fn)
        return s

    add("contract", cmd_contract)
    s = add("scan", cmd_scan, fail_on=True)
    s.add_argument("--layers")
    s.add_argument("--fast", action="store_true")
    add("prove", cmd_prove, fail_on=True)
    s = add("fix", cmd_fix)
    s.add_argument("--finding", required=True)
    s = add("verify", cmd_verify)
    s.add_argument("--finding", required=True)
    s.add_argument("--patch", required=True)
    add("hook", cmd_hook, dir_=False)
    s = add("report", cmd_report)
    s.add_argument("--upload", required=True)
    return p


def main(argv=None) -> int:
    try:
        a = build_parser().parse_args(argv)
        return a.fn(a)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
