#!/usr/bin/env python3
"""Show the Intent Contract in plain words, and record the user's confirmation.

  contract_confirm.py show <dir>
  contract_confirm.py confirm <dir> [--accept-public ITEM ...]

`show` never changes anything about the contract's status. `confirm` must only be run after the USER has said the contract
is right. Items in needs_confirmation would make data more public: they stay owner-only unless named with --accept-public.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pg  # noqa: E402


def describe(c):
    lines = ["The contract says who may do what in this project:"]
    for r in c.get("owned_resources", []):
        lines.append(f"- {r['name']}: each row belongs to one user (column {r['owner_field']}); only the owner may {', '.join(r['actions'])} it.")
    if c.get("admin_only_routes"):
        lines.append("- Only admins may use: " + ", ".join(c["admin_only_routes"]))
    if c.get("public_routes"):
        lines.append("- Anyone may use (no login): " + ", ".join(c["public_routes"]))
    if c.get("profile_editable_fields"):
        lines.append("- A user may edit these fields of their own profile: " + ", ".join(c["profile_editable_fields"]))
    for rule in c.get("rules", []):
        lines.append(f"- Rule: {rule}")
    state = "CONFIRMED by the user" if c.get("confirmed_by_user") else "a DRAFT, not confirmed yet"
    lines.append(f"Status: {state} (source: {c.get('source')}).")
    for item in c.get("needs_confirmation", []):
        lines.append(f"WARNING: this would make data public: {item!r}. It is kept owner-only. Confirm only if the user really wants it public.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    show = sub.add_parser("show")
    show.add_argument("dir")
    conf = sub.add_parser("confirm")
    conf.add_argument("dir")
    conf.add_argument("--accept-public", action="append", default=[], metavar="ITEM")
    a = ap.parse_args(argv)

    args = ["contract", a.dir]
    if a.cmd == "confirm":
        args.append("--confirm")
        for item in a.accept_public:
            args += ["--accept-public", item]
    code, contract, err = _pg.run_json(*args)
    if code != 0 or not isinstance(contract, dict):
        print(f"could not read the contract: {err}".strip(), file=sys.stderr)
        return 2
    print(describe(contract))
    if a.cmd == "show" and not contract.get("confirmed_by_user"):
        print("\nAsk the user: 'Is this what you meant?' Only if they say yes, run:\n"
              f"  python {os.path.abspath(__file__)} confirm {a.dir}")
    if a.cmd == "confirm":
        print("\nConfirmation recorded." + (" Items still owner-only: " + ", ".join(contract["needs_confirmation"]) if contract.get("needs_confirmation") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
