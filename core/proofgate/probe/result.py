"""Probe results and their conversion to Findings (plan 3.2 step 7, section 5.1)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ..layers.base import finding_id, short_hash
from ..models import Contract, Finding
from ..redact import excerpt

Verdict = Literal["PROVEN", "HELD", "INCONCLUSIVE", "UNTESTED"]
LAYER = 8

# rule -> (cwe, category, severity, fix_tier, title template, plain-words template). {r} = resource name.
RULES: dict[str, tuple[str, str, str, str | None, str, str]] = {
    "cross-user-read": ("CWE-639", "access", "critical", "B", "User B can read User A's {r}",
        "Your app checks that someone is logged in, but not that the {r} item is theirs."),
    "cross-user-write": ("CWE-639", "access", "critical", "B", "User B can change User A's {r}",
        "Your app lets any signed-in person overwrite someone else's {r} item."),
    "cross-user-list": ("CWE-639", "access", "critical", "B", "User B can list User A's {r}",
        "A signed-in person can list other people's {r} items by asking for them."),
    "admin-route-unauthenticated": ("CWE-306", "access", "critical", "B", "Anyone can open an admin page without logging in",
        "An admin-only page answers visitors who are not logged in, and shows other people's data."),
    "admin-route-missing-role-check": ("CWE-862", "access", "critical", "B", "Any signed-in user can open an admin page",
        "An admin-only page checks that you are logged in, but not that you are an admin."),
    "sql-injection": ("CWE-89", "injection", "critical", "A", "A search box lets User B read User A's {r} (SQL injection)",
        "Text typed into the search is pasted into a database query, so a visitor can make it return other people's data."),
    "command-injection": ("CWE-78", "injection", "critical", "A", "A request parameter runs commands on your server",
        "A value from the URL is passed to a shell, so a visitor can run their own commands on your server."),
    "mass-assignment": ("CWE-915", "access", "critical", "B", "A normal user can make themselves an admin",
        "The profile update accepts any field, including the one that decides who is an admin."),
}


_WHO = {"B": "User B", "C": "User C", "anon": "A visitor who is not logged in"}


@dataclass
class Check:
    attack: str  # a..f
    rule: str
    verdict: Verdict
    actor: str
    victim: str = "A"
    resource: str | None = None
    route_label: str | None = None  # e.g. "GET /notes/<int:note_id>"
    file: str | None = None
    line: int = 1
    function: str | None = None
    request: str = ""
    status: int | None = None
    response_text: str = ""  # raw, kept in memory only; findings carry the redacted excerpt
    note: str = ""


@dataclass
class ProbeResult:
    checks: list[Check] = field(default_factory=list)
    oracles: dict[str, bool | None] = field(default_factory=dict)
    untested: list[str] = field(default_factory=list)
    tested_routes: list[str] = field(default_factory=list)
    tested_tables: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    launched: bool = False

    @property
    def proven(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == "PROVEN"]

    def rules_attacked_held(self, contract: Contract) -> tuple[int, int]:
        """Contract rules with at least one real check, and how many of those no check broke."""
        attacked = held = 0
        for rule_text in contract.rules:
            related = [c for c in self.checks if c.verdict != "UNTESTED" and _related(rule_text, c, contract)]
            if not related:
                continue
            attacked += 1
            held += not any(c.verdict == "PROVEN" for c in related)
        return attacked, held

    def to_findings(self, contract: Contract) -> list[Finding]:
        out: dict[str, Finding] = {}
        for c in self.proven:
            cwe, category, severity, tier, title, plain = RULES[c.rule]
            r = c.resource or "data"
            who = f"{c.actor}>{c.victim}"
            fp = f"sha256:{c.rule}|{c.file}|{short_hash(f'{c.function}|{c.resource}|{c.route_label}|{who}')}"
            out.setdefault(fp, Finding(
                id=finding_id(fp), fingerprint=fp, layer=LAYER, category=category, rule=c.rule, cwe=cwe,
                severity=severity, confidence="proven", proven=True, confirmed_by=1,
                title=title.format(r=r).replace("User B", _WHO.get(c.actor, f"User {c.actor}")),
                plain_words=plain.format(r=r),
                location={"file": c.file or "unknown", "line": c.line, "function": c.function, "route": c.route_label},
                sources=["proofgate-probe"],
                evidence={"actor": c.actor, "victim": c.victim, "request": c.request, "status": c.status or 0,
                          "response_excerpt": excerpt(_around_leak(c.response_text), 200)},
                contract_rule=_rule_for(contract, c), contract_confirmed=contract.confirmed_by_user,
                fix_tier=tier, interrupt_human=True,
            ))
        return sorted(out.values(), key=lambda f: (f.location.file, f.location.line, f.rule))


def _around_leak(text: str) -> str:
    i = text.find("PGCANARY_")
    if i < 0:
        i = text.find("@")  # leaked email
    if i < 0:
        return text[:200]
    return text[max(0, i - 60): i + 120]


def _related(rule_text: str, c: Check, contract: Contract) -> bool:
    t = rule_text.lower()
    if c.resource and c.resource.lower() in t:
        return True
    if "admin" in t and c.attack == "c":
        return True
    if ("profile" in t or "role" in t) and c.attack == "f":
        return True
    names = [res.name.lower() for res in contract.owned_resources]
    return not any(n in t for n in names) and "admin" not in t and "profile" not in t and "role" not in t


def _rule_for(contract: Contract, c: Check) -> str | None:
    for rule in contract.rules:
        if _related(rule, c, contract):
            return rule
    return contract.rules[0] if contract.rules else None
