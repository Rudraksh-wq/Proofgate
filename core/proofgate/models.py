"""ProofGate data models (plan section 5).

Source of truth: Master Guide section 4 (the original shapes) plus the v3 extras from
docs/PROOFGATE_FINAL_PLAN.md section 5.1-5.3. Where the two differ, v3 wins.
Every v3 extra has a default, so the original Master Guide JSON still validates.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FINDING_SCHEMA = "proofgate.finding/v1"
CONTRACT_SCHEMA = "proofgate.contract/v1"
FIXRESULT_SCHEMA = "proofgate.fixresult/v1"
REPORT_SCHEMA = "proofgate.report/v1"
ACCEPTED_SCHEMA = "proofgate.accepted/v1"

Category = Literal["secrets", "injection", "access", "deps", "supply-chain", "database", "config", "web", "bundle"]
Severity = Literal["critical", "high", "medium", "low"]
Confidence = Literal["proven", "high", "medium", "low"]
Status = Literal[
    "open", "fixing", "fixed", "fix-rejected", "needs-human", "accepted-risk", "untested", "inconclusive"
]
FixTier = Literal["A", "B", "C"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class _Versioned(_Strict):
    """Adds the `schema` key. Python name is `schema_id` because BaseModel owns `schema`."""

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent, by_alias=True)


# ---------------------------------------------------------------- Finding (5.1)
class Location(_Strict):
    file: str
    line: int
    function: str | None = None
    route: str | None = None


class Evidence(_Strict):
    request: str
    status: int
    response_excerpt: str
    actor: str | None = None
    victim: str | None = None
    repro_test: str | None = None


class Finding(_Versioned):
    schema_id: Literal["proofgate.finding/v1"] = Field(FINDING_SCHEMA, alias="schema")
    id: str
    fingerprint: str | None = None
    layer: int = Field(ge=1, le=9)
    category: Category
    rule: str
    cwe: str | None = None
    severity: Severity
    confidence: Confidence | None = None  # derived from `proven` when omitted
    title: str
    plain_words: str
    location: Location
    sources: list[str]
    confirmed_by: int = 1
    proven: bool = False
    evidence: Evidence | None = None
    contract_rule: str | None = None
    contract_confirmed: bool = False
    fix_tier: FixTier | None = None
    fixed_in: str | None = None  # L3 dependency findings: first safe version (Tier A input)
    interrupt_human: bool = False
    status: Status = "open"
    first_seen_commit: str | None = None

    @model_validator(mode="after")
    def _proven_consistent(self) -> "Finding":
        if self.confidence is None:
            self.confidence = "proven" if self.proven else "high"
        if self.proven and self.confidence != "proven":
            raise ValueError("proven=true requires confidence='proven'")
        if self.confidence == "proven" and not self.proven:
            raise ValueError("confidence='proven' requires proven=true")
        return self


# --------------------------------------------------------------- Contract (5.2)
class OwnedResource(_Strict):
    name: str
    owner_field: str
    actions: list[str]


class Contract(_Versioned):
    schema_id: Literal["proofgate.contract/v1"] = Field(CONTRACT_SCHEMA, alias="schema")
    owned_resources: list[OwnedResource]
    profile_editable_fields: list[str]
    admin_only_routes: list[str]
    public_routes: list[str]
    rules: list[str]
    confirmed_by_user: bool
    source: Literal["gemini", "fallback"]
    needs_confirmation: list[str] = Field(default_factory=list)
    public_reads_confirmed: list[str] = Field(default_factory=list)


# ------------------------------------------------------------- FixResult (5.2)
class Winner(_Strict):
    patch: str
    diff_lines: int


class Gates(_Strict):
    exploit_blocked: bool
    feature_works: bool
    tests_pass: bool
    no_new_findings: bool
    diff_is_small: bool
    migrations_replayed: bool | None = None  # only meaningful for Supabase fixes


class Rejected(_Strict):
    reason: str


class FixResult(_Versioned):
    schema_id: Literal["proofgate.fixresult/v1"] = Field(FIXRESULT_SCHEMA, alias="schema")
    finding_id: str
    tier: FixTier
    candidates: int
    winner: Winner | None = None  # None when no candidate passed (needs-human)
    gates: Gates
    rejected: list[Rejected]
    regression_test: str | None = None
    learned_rule: str | None = None
    accepted: bool
    applied_in: Literal["temp_copy"] = "temp_copy"
    pre_fix_commit: str | None = None
    notes: list[str] = Field(default_factory=list)  # what a gate could not exercise (e.g. live Supabase replay pending)
    vaccine_patch: str | None = None  # second diff: the regression test + the learned rule in the agent files


# ----------------------------------------------------------------- Report (5.2)
class Receipt(_Strict):
    """Wording rule: 'N rules attacked, N held, commit X'. Never 'secure'."""

    rules_attacked: int
    rules_held: int
    commit: str | None = None
    report_hash: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _legacy_hash(cls, data: Any) -> Any:
        # Master Guide called it `hash`; v3 calls it `report_hash`.
        if isinstance(data, dict) and "hash" in data:
            data = dict(data)
            legacy = data.pop("hash")
            data.setdefault("report_hash", legacy)
        return data


class Tested(_Strict):
    tables: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)


class ToolRecord(_Strict):
    name: str
    version: str | None = None
    sha256: str | None = None
    status: Literal["ok", "skipped", "mismatch", "unpinned", "timeout", "error"]


class AcceptedSummary(_Strict):
    """One accepted risk as listed in a report (the finding itself stays in `findings` with status accepted-risk)."""
    fingerprint: str
    finding_id: str
    title: str
    severity: Severity
    proven: bool = False
    reason: str
    owner: str
    expires: dt.date
    forced: bool = False


class Report(_Versioned):
    schema_id: Literal["proofgate.report/v1"] = Field(REPORT_SCHEMA, alias="schema")
    project: str
    scanned_at: str
    layers_run: list[int]
    raw_warning_count: int
    unique_count: int
    proven_count: int
    findings: list[Finding]
    fixes: list[FixResult]
    receipt: Receipt
    tested: Tested = Field(default_factory=Tested)
    untested: list[str] = Field(default_factory=list)
    tools: list[ToolRecord] = Field(default_factory=list)
    limits_statement: str | None = None
    fail_open_count: int = 0  # hook fail-open events (plan 6.3)
    target_overrides: list[str] = Field(default_factory=list)  # --i-own-this targets (plan 3.2)
    accepted_risks: list[AcceptedSummary] = Field(default_factory=list)  # findings a person accepted (proofgate accept)
    notes: list[str] = Field(default_factory=list)  # skipped tools, offline lookups, layers not run (never silent)


# ------------------------------------------------------------ AcceptedRisk (5.3)
class AcceptedRisk(_Versioned):
    schema_id: Literal["proofgate.accepted/v1"] = Field(ACCEPTED_SCHEMA, alias="schema")
    fingerprint: str
    reason: str
    owner: str
    expires: dt.date
    forced: bool = False  # written with --force: required to accept a finding that is proven and critical
    created: dt.date | None = None

    def is_expired(self, today: dt.date | None = None) -> bool:
        return (today or dt.date.today()) > self.expires


LIMITS_STATEMENT = (
    "Passing ProofGate means our attacks failed on the routes and tables we tested. "
    "It doesn't mean your app is secure."
)
