"""SARIF 2.1.0 export (`proofgate scan --format sarif`), for GitHub code scanning (plan 5, 6.1)."""
from __future__ import annotations

from typing import Any

from . import __version__
from .models import Finding, Report
from .redact import redact

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}  # GitHub's 0-10 scale


def _rule_entry(f: Finding) -> dict[str, Any]:
    props: dict[str, Any] = {"category": f.category, "security-severity": _SECURITY_SEVERITY[f.severity],
                             "tags": ["security", f.category]}
    if f.cwe:
        props["tags"].append(f"external/cwe/{f.cwe.lower()}")
    return {
        "id": f.rule,
        "name": f.rule,
        "shortDescription": {"text": redact(f.title.split(" (")[0])},
        "fullDescription": {"text": redact(f.plain_words)},
        "defaultConfiguration": {"level": _LEVEL[f.severity]},
        "properties": props,
    }


def to_sarif(report: Report) -> dict[str, Any]:
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for f in report.findings:
        if f.rule not in rule_index:
            rule_index[f.rule] = len(rules)
            rules.append(_rule_entry(f))
        result: dict[str, Any] = {
            "ruleId": f.rule,
            "ruleIndex": rule_index[f.rule],
            "level": _LEVEL[f.severity],
            "message": {"text": redact(f"{f.title}. {f.plain_words}")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.location.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(f.location.line, 1)},
            }}],
            "properties": {
                "severity": f.severity, "confidence": f.confidence, "proven": f.proven, "layer": f.layer,
                "sources": f.sources, "confirmedBy": f.confirmed_by, "status": f.status,
            },
        }
        if f.fingerprint:
            result["partialFingerprints"] = {"proofgateFingerprint/v1": f.fingerprint}
        if f.fixed_in:
            result["properties"]["fixedIn"] = f.fixed_in
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ProofGate", "version": __version__, "rules": rules,
                                "informationUri": "https://github.com/Rudraksh-wq/Proofgate"}},
            "results": results,
            "invocations": [{"executionSuccessful": not any(t.status in ("error", "mismatch") for t in report.tools),
                             "toolExecutionNotifications": [{"level": "note", "message": {"text": redact(n)}} for n in report.notes]}],
            "properties": {"limitsStatement": report.limits_statement, "layersRun": report.layers_run,
                           "rawWarningCount": report.raw_warning_count, "uniqueCount": report.unique_count,
                           "provenCount": report.proven_count},
        }],
    }
