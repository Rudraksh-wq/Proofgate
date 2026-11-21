"""Plain-words, deterministic finding explanations.

An explanation is TEXT ONLY. It cannot change a finding's status (only a re-run test can), it never claims the app is
secure, and it never contains a secret or a canary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..models import LIMITS_STATEMENT, Finding
from ..redact import redact

Level = Literal["beginner", "developer"]

_WHAT_TO_DO = {
    "secrets": "Move the key out of the code into an environment variable (and keep that file out of git). Then replace the key "
               "in the provider's dashboard: a key that was ever written in code should be treated as already exposed.",
    "injection": "Never build a query or command by gluing text together. Use placeholders for database queries and an argument "
                 "list for programs. ProofGate can write this change for you.",
    "access": "Make the server check, on every request, who the caller is and whether this item belongs to them (or whether they "
              "are an admin). Do not rely on hiding the link. ProofGate can write this check and prove it works.",
    "deps": "Upgrade the package to a fixed version and run your tests.",
    "supply-chain": "Check the package name on the registry. If it does not exist or you did not mean it, remove it. Real "
                    "packages with a similar name may be a typo-squat.",
    "database": "Turn row-level security on for the table and add policies that compare the signed-in user (auth.uid()) to the "
                "row's owner column. Add the change as a NEW migration; never edit an old one.",
    "config": "Change the setting so the cautious choice is the default, and read any risky value from an environment variable.",
    "web": "Change the code so the browser or the connection is protected as intended (escape output, keep certificate checks on).",
    "bundle": "Remove the secret from anything shipped to the browser, rotate it, and stop publishing source maps you do not need.",
}
_CONFIDENCE = {
    "proven": "We proved it: ProofGate acted as a second user and really got the data or the power.",
    "high": "A rule that is almost always right found this. It was not attacked live.",
    "medium": "This is a good hint, not a certainty. Look at the line before acting.",
    "low": "This might be a false alarm. Look at the line before acting.",
}


@dataclass(frozen=True)
class Explanation:
    text: str
    source: Literal["template"]


def explain_finding(finding: Finding, level: Level = "beginner") -> Explanation:
    """Deterministic explanation built only from the finding's own fields."""
    where = f"{finding.location.file}, line {finding.location.line}"
    todo = _WHAT_TO_DO.get(finding.category, "Review the line and fix it.")
    if finding.fixed_in:
        todo += f" The fixed version is {finding.fixed_in}."
    lines = [
        f"What we found: {finding.title.split(' (')[0]}.",
        f"In plain words: {finding.plain_words}",
        f"Where: {where}.",
        f"How sure we are: {_CONFIDENCE.get(finding.confidence or 'high', _CONFIDENCE['high'])}",
        f"What to do: {todo}",
    ]
    if level == "developer":
        meta = [f"rule {finding.rule}", f"layer {finding.layer}", finding.severity]
        if finding.cwe:
            meta.append(finding.cwe)
        if finding.fix_tier:
            meta.append(f"fix tier {finding.fix_tier}")
        lines.append("Details: " + ", ".join(meta) + f"; found by {', '.join(finding.sources)}.")
        if finding.evidence:
            ev = finding.evidence
            who = f" ({ev.actor} acting on {ev.victim}'s data)" if ev.actor and ev.victim else ""
            lines.append(f"Evidence{who}: {ev.request} -> HTTP {ev.status}; response excerpt: {ev.response_excerpt}")
        if finding.contract_rule:
            lines.append(f"Rule it breaks: {finding.contract_rule}" + ("" if finding.contract_confirmed else " (draft contract)"))
    lines.append(LIMITS_STATEMENT)
    return Explanation(redact("\n".join(lines)), "template")

