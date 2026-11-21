from proofgate.models import FixResult, Report
from proofgate.report_html import to_html


def _report(fix_breaker):
    fix = FixResult.model_validate({
        "finding_id": "f1",
        "tier": "B",
        "candidates": 1,
        "gates": {
            "exploit_blocked": True,
            "feature_works": True,
            "tests_pass": True,
            "no_new_findings": True,
            "diff_is_small": True,
            "fix_breaker": fix_breaker,
        },
        "rejected": [],
        "accepted": True,
    })
    return Report.model_validate({
        "project": "demo",
        "scanned_at": "now",
        "layers_run": [8],
        "raw_warning_count": 1,
        "unique_count": 1,
        "proven_count": 1,
        "findings": [],
        "fixes": [fix.model_dump(mode="json")],
        "receipt": {"rules_attacked": 1, "rules_held": 0},
    })


def test_report_shows_fix_breaker_rejection():
    html = to_html(_report({
        "ran": True,
        "generated": 6,
        "routable": 2,
        "survived": 1,
        "broken": [{"label": "PATCH /api/notes/1", "status": "PROVEN"}],
    }))
    assert "Rejected. PATCH /api/notes/1 still leaks." in html


def test_report_shows_fix_breaker_survival_and_honesty_sentence():
    html = to_html(_report({
        "ran": True,
        "generated": 14,
        "routable": 14,
        "survived": 14,
        "broken": [],
    }))
    assert "Survived 14 of 14 routable variants tried (14 generated)" in html
    assert "The attacks we tried failed; this does not mean the fix is unbreakable." in html
