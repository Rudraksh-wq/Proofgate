from typing import Literal

from pydantic import BaseModel, ConfigDict

Category = Literal["secrets", "injection", "access", "deps", "supply-chain", "database", "config", "web", "bundle"]
Severity = Literal["critical", "high", "medium", "low"]
Status = Literal["open", "fixing", "fixed", "fix-rejected", "needs-human"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(_Strict):
    file: str
    line: int
    function: str
    route: str


class Evidence(_Strict):
    request: str
    response_excerpt: str
    status: int


class Finding(_Strict):
    id: str
    layer: int
    category: Category
    rule: str
    cwe: str
    severity: Severity
    title: str
    plain_words: str
    location: Location
    sources: list[str]
    proven: bool
    evidence: Evidence
    contract_rule: str
    fix_tier: str
    status: Status


class OwnedResource(_Strict):
    name: str
    owner_field: str
    actions: list[str]


class Contract(_Strict):
    owned_resources: list[OwnedResource]
    profile_editable_fields: list[str]
    admin_only_routes: list[str]
    public_routes: list[str]
    rules: list[str]
    confirmed_by_user: bool
    source: Literal["gemini", "fallback"]


class Winner(_Strict):
    patch: str
    diff_lines: int


class Gates(_Strict):
    exploit_blocked: bool
    feature_works: bool
    tests_pass: bool
    no_new_findings: bool
    diff_is_small: bool


class Rejected(_Strict):
    reason: str


class FixResult(_Strict):
    finding_id: str
    tier: str
    candidates: int
    winner: Winner
    gates: Gates
    rejected: list[Rejected]
    regression_test: str
    learned_rule: str
    accepted: bool


class Receipt(_Strict):
    rules_attacked: int
    rules_held: int
    hash: str


class Report(_Strict):
    project: str
    scanned_at: str
    layers_run: list[int]
    raw_warning_count: int
    unique_count: int
    proven_count: int
    findings: list[Finding]
    fixes: list[FixResult]
    receipt: Receipt
