#!/usr/bin/env python3
"""Step-by-step key rotation for a leaked secret. It never reads, prints or accepts the secret itself.

  rotate_key_guide.py --rule stripe-live-secret-key
  rotate_key_guide.py --provider supabase
  rotate_key_guide.py --finding f_ab12cd34 --dir .
"""
import argparse
import json
import os
import sys

COMMON_AFTER = [
    "Put the NEW key only in an environment variable (a local .env that is in .gitignore, and your hosting provider's secret settings). Never in code.",
    "Redeploy, then REVOKE the old key. Until it is revoked it still works for whoever copied it.",
    "Look at the provider's logs or dashboard for use you do not recognise since the key was written in code.",
    "Removing the key from git history does not un-leak it: if the repository was ever pushed or shared, the key is exposed. Rotating is the fix.",
]

PROVIDERS = {
    "stripe": ("Stripe", ["Open the Stripe dashboard > Developers > API keys.", "Roll the secret key (\"Roll key\"); choose to expire the old key now, or within hours if a live service depends on it.", "Create restricted keys with only the permissions this app needs instead of the full secret key."]),
    "supabase": ("Supabase service_role key", ["Open the Supabase dashboard > Project Settings > API.", "Rotate the JWT secret (this changes the anon and service_role keys together). Plan for a short outage: update every place that uses either key.", "Check Auth and Database logs for requests made with the leaked service_role key; it skipped all row-level security."]),
    "aws": ("AWS access key", ["Open IAM > Users > the user > Security credentials.", "Create a second access key, switch the app to it, then set the old key to Inactive and delete it.", "Check CloudTrail for calls made with the old key id."]),
    "github": ("GitHub token", ["Open GitHub > Settings > Developer settings > Personal access tokens (or the app's installation).", "Revoke the leaked token and create a new fine-grained token with the smallest scopes.", "Review the audit log and recent commits for activity you do not recognise."]),
    "slack": ("Slack token", ["Open api.slack.com/apps > your app > OAuth & Permissions.", "Revoke the leaked token (or regenerate the signing secret) and reinstall the app to get a new one."]),
    "google": ("Google API key", ["Open Google Cloud Console > APIs & Services > Credentials.", "Create a new key with application and API restrictions, switch the app to it, then delete the old key."]),
    "private-key": ("a private key", ["Generate a NEW key pair; the leaked private key can never be trusted again.", "Replace the public key wherever it is installed (servers, CI, certificate authority) and remove the old one."]),
    "generic": ("the leaked secret", ["Open the dashboard of the service that issued it and create a replacement.", "Switch the app to the replacement, then revoke the old secret."]),
}

RULE_TO_PROVIDER = [
    ("stripe", "stripe"), ("service-role", "supabase"), ("supabase", "supabase"), ("aws", "aws"), ("github", "github"),
    ("slack", "slack"), ("google", "google"), ("private-key", "private-key"),
]


def provider_for(text):
    t = (text or "").lower()
    return next((p for needle, p in RULE_TO_PROVIDER if needle in t), "generic")


def guide(provider):
    name, steps = PROVIDERS[provider]
    lines = [f"Rotate {name}. A key that was ever written in code must be treated as already exposed.", ""]
    n = 0
    for s in steps + COMMON_AFTER:
        n += 1
        lines.append(f"{n}. {s}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rule")
    ap.add_argument("--provider")
    ap.add_argument("--finding")
    ap.add_argument("--dir", default=".")
    a = ap.parse_args(argv)
    rule = a.rule or a.provider
    if a.finding:
        try:
            with open(os.path.join(a.dir, ".proofgate", "report.json"), encoding="utf-8") as f:
                report = json.load(f)
            rule = next(x["rule"] for x in report["findings"] if x["id"] == a.finding)
        except (OSError, ValueError, StopIteration, KeyError):
            print("could not find that finding in .proofgate/report.json", file=sys.stderr)
            return 2
    if not rule:
        print("give --rule, --provider or --finding", file=sys.stderr)
        return 2
    print(guide(provider_for(rule)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
