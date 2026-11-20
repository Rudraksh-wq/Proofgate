"""Fake-but-correctly-shaped sample data (Hour 0-1 stubs)."""
from datetime import datetime, timezone

SAMPLE_FINDING = {
    "id": "f_7c1a", "layer": 8, "category": "access", "rule": "cross-user-read", "cwe": "CWE-639",
    "severity": "critical", "title": "User B can read User A's notes",
    "plain_words": "Your app checks that someone is logged in, but not that the note is theirs.",
    "location": {"file": "app.py", "line": 88, "function": "get_note", "route": "GET /notes/<id>"},
    "sources": ["proofgate-probe", "semgrep"], "proven": True,
    "evidence": {"request": "GET /notes/12 as user B", "response_excerpt": "...PGCANARY_A_7f3c...", "status": 200},
    "contract_rule": "User B must never read or change User A's notes.", "fix_tier": "B", "status": "open",
}

SAMPLE_CONTRACT = {
    "owned_resources": [{"name": "notes", "owner_field": "owner_id", "actions": ["read", "update", "delete"]}],
    "profile_editable_fields": ["display_name"], "admin_only_routes": ["/admin/*"],
    "public_routes": ["/signup", "/login"], "rules": ["User B must never read or change User A's notes."],
    "confirmed_by_user": False, "source": "gemini",
}

SAMPLE_FIX = {
    "finding_id": "f_7c1a", "tier": "B", "candidates": 3,
    "winner": {"patch": "--- a/app.py\n+++ b/app.py\n...", "diff_lines": 3},
    "gates": {"exploit_blocked": True, "feature_works": True, "tests_pass": True,
              "no_new_findings": True, "diff_is_small": True},
    "rejected": [{"reason": "feature_works=false: owner can no longer read own note"}],
    "regression_test": "tests/test_proofgate_regressions.py::test_f_7c1a",
    "learned_rule": "Every query on notes must filter by owner_id = current user.", "accepted": True,
}


def sample_report(project: str = "demo") -> dict:
    return {
        "project": project,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "layers_run": list(range(1, 10)),
        "raw_warning_count": 1, "unique_count": 1, "proven_count": 1,
        "findings": [SAMPLE_FINDING], "fixes": [SAMPLE_FIX],
        "receipt": {"rules_attacked": 1, "rules_held": 0, "hash": "sha256:0000sample"},
    }
