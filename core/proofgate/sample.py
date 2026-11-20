"""Fake-but-correctly-shaped sample data used by CLI stubs until real features replace them.

Everything here is a placeholder, not a scan result.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .models import LIMITS_STATEMENT

SAMPLE_FINDING: dict = {
    "schema": "proofgate.finding/v1",
    "id": "f_7c1a",
    "fingerprint": "sha256:cross-user-read|app.py|get_note|notes|read|B>A",
    "layer": 8,
    "category": "access",
    "rule": "cross-user-read",
    "cwe": "CWE-639",
    "severity": "critical",
    "confidence": "proven",
    "title": "User B can read User A's notes",
    "plain_words": "Your app checks that someone is logged in, but not that the note is theirs.",
    "location": {"file": "app.py", "line": 88, "function": "get_note", "route": "GET /notes/<id>"},
    "sources": ["proofgate-probe", "semgrep"],
    "confirmed_by": 2,
    "proven": True,
    "evidence": {
        "actor": "B",
        "victim": "A",
        "request": "GET /notes/12 as user B",
        "status": 200,
        "response_excerpt": "...PGCANARY_A_«masked»...",
    },
    "contract_rule": "User B must never read or change User A's notes.",
    "contract_confirmed": False,
    "fix_tier": "B",
    "interrupt_human": True,
    "status": "open",
}

SAMPLE_CONTRACT: dict = {
    "schema": "proofgate.contract/v1",
    "owned_resources": [{"name": "notes", "owner_field": "owner_id", "actions": ["read", "update", "delete"]}],
    "profile_editable_fields": ["display_name"],
    "admin_only_routes": ["/admin/*"],
    "public_routes": ["/signup", "/login"],
    "rules": ["User B must never read or change User A's notes."],
    "confirmed_by_user": False,
    "source": "fallback",
    "needs_confirmation": [],
    "public_reads_confirmed": [],
}

SAMPLE_FIX: dict = {
    "schema": "proofgate.fixresult/v1",
    "finding_id": "f_7c1a",
    "tier": "B",
    "candidates": 3,
    "winner": {"patch": "--- a/app.py\n+++ b/app.py\n...", "diff_lines": 3},
    "gates": {
        "exploit_blocked": True,
        "feature_works": True,
        "tests_pass": True,
        "no_new_findings": True,
        "diff_is_small": True,
        "migrations_replayed": None,
    },
    "rejected": [{"reason": "feature_works=false: owner can no longer read own note"}],
    "regression_test": "tests/test_proofgate_regressions.py::test_f_7c1a",
    "learned_rule": "Every query on notes must filter by owner_id = current user.",
    "accepted": True,
    "applied_in": "temp_copy",
    "pre_fix_commit": "a1b2c3d",
}

SAMPLE_TOOLS: list[dict] = [
    {"name": "betterleaks", "version": None, "sha256": None, "status": "skipped"},
]


def sample_report(project: str, layers: list[int] | None = None) -> dict:
    return {
        "schema": "proofgate.report/v1",
        "project": project,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "layers_run": layers or list(range(1, 10)),
        "raw_warning_count": 1,
        "unique_count": 1,
        "proven_count": 1,
        "findings": [SAMPLE_FINDING],
        "fixes": [SAMPLE_FIX],
        "receipt": {"rules_attacked": 1, "rules_held": 0, "commit": None, "report_hash": "sha256:SAMPLE"},
        "tested": {"tables": [], "routes": ["GET /notes/<id>"]},
        "untested": [],
        "tools": SAMPLE_TOOLS,
        "limits_statement": LIMITS_STATEMENT,
        "fail_open_count": 0,
        "target_overrides": [],
    }
