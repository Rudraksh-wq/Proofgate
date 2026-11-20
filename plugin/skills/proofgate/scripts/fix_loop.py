#!/usr/bin/env python3
"""Drive the fix loop for one finding: ProofGate's own templates first, then your patch, at most 3 submissions.

  fix_loop.py next   <dir> <finding-id>                  try ProofGate's own Tier A/B fix; writes .proofgate/fix_<id>.diff
  fix_loop.py submit <dir> <finding-id> --patch-file F   verify YOUR patch (a unified diff); counts attempts
  fix_loop.py status <dir> <finding-id>

Exit codes: 0 accepted, 1 rejected (try again), 3 needs a human (3 rejections), 2 error.
Nothing is applied to the project: apply the written diff yourself (git apply .proofgate/fix_<id>.diff).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pg  # noqa: E402

MAX_ATTEMPTS = 3


def state_path(d):
    return os.path.join(d, ".proofgate", "fix_loop.json")


def load(d):
    try:
        with open(state_path(d), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(d, st):
    os.makedirs(os.path.dirname(state_path(d)), exist_ok=True)
    with open(state_path(d), "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1)


def write_diff(d, name, text):
    path = os.path.join(d, ".proofgate", name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text if text.endswith("\n") else text + "\n")
    return path


def show(res):
    g = res.get("gates", {})
    ticks = ", ".join(f"{k}={'yes' if g.get(k) else 'NO'}" for k in ("exploit_blocked", "feature_works", "tests_pass", "no_new_findings", "diff_is_small"))
    print(("ACCEPTED" if res.get("accepted") else "REJECTED") + f" (tier {res.get('tier')}, {res.get('candidates')} candidate(s))")
    print("gates: " + ticks)
    for r in res.get("rejected", []):
        print("- " + r["reason"])
    for n in res.get("notes", []):
        print("note: " + n)


def finish_accepted(d, fid, res, st):
    patch = (res.get("winner") or {}).get("patch")
    if patch:
        print("winning diff written to " + write_diff(d, f"fix_{fid}.diff", patch))
    if res.get("vaccine_patch"):
        print("regression test + rule diff written to " + write_diff(d, f"vaccine_{fid}.diff", res["vaccine_patch"]))
    if res.get("learned_rule"):
        print("rule for future sessions: " + res["learned_rule"])
    st.pop(fid, None)
    save(d, st)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("next", "status"):
        p = sub.add_parser(name)
        p.add_argument("dir")
        p.add_argument("finding")
    p = sub.add_parser("submit")
    p.add_argument("dir")
    p.add_argument("finding")
    p.add_argument("--patch-file", required=True)
    a = ap.parse_args(argv)
    d, fid = a.dir, a.finding
    st = load(d)
    entry = st.setdefault(fid, {"attempts": 0, "reasons": []})

    if a.cmd == "status":
        print(f"{fid}: {entry['attempts']} of {MAX_ATTEMPTS} submissions used")
        return 0

    if a.cmd == "next":
        code, res, err = _pg.run_json("fix", d, "--finding", fid)
        if not isinstance(res, dict):
            print(f"could not run the fix pipeline: {err}".strip(), file=sys.stderr)
            return 2
        show(res)
        if res.get("accepted"):
            finish_accepted(d, fid, res, st)
            return 0
        print("ProofGate has no verified template fix. Write the smallest fix yourself and submit it with: submit --patch-file <diff>")
        return 1

    if entry["attempts"] >= MAX_ATTEMPTS:
        print(f"NEEDS A HUMAN: {MAX_ATTEMPTS} patches were rejected for {fid}. Stop and tell the user, with these reasons:")
        for r in entry["reasons"]:
            print("- " + r)
        return 3
    if not os.path.isfile(a.patch_file):
        print(f"patch file not found: {a.patch_file}", file=sys.stderr)
        return 2
    entry["attempts"] += 1
    code, res, err = _pg.run_json("verify", d, "--finding", fid, "--patch", a.patch_file)
    if not isinstance(res, dict):
        entry["attempts"] -= 1
        print(f"could not run the tournament: {err}".strip(), file=sys.stderr)
        return 2
    print(f"attempt {entry['attempts']} of {MAX_ATTEMPTS}")
    show(res)
    if res.get("accepted"):
        finish_accepted(d, fid, res, st)
        return 0
    entry["reasons"] += [r["reason"] for r in res.get("rejected", [])]
    save(d, st)
    if entry["attempts"] >= MAX_ATTEMPTS:
        print(f"NEEDS A HUMAN: {MAX_ATTEMPTS} patches were rejected. Stop and tell the user, with the reasons above.")
        return 3
    print(f"Read every reason, fix the cause, and submit again ({MAX_ATTEMPTS - entry['attempts']} left).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
