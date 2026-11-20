import datetime as dt
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from proofgate.models import AcceptedRisk, Contract, Finding, FixResult, Report

SAMPLES = Path(__file__).parent / "fixtures" / "samples"


def load(name: str) -> dict:
    return json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "kind,model",
    [("finding", Finding), ("contract", Contract), ("fixresult", FixResult), ("report", Report)],
)
@pytest.mark.parametrize("prefix", ["pdf", "v3"])
def test_samples_validate(prefix, kind, model):
    model.model_validate(load(f"{prefix}_{kind}"))


def test_pdf_finding_gets_derived_confidence():
    f = Finding.model_validate(load("pdf_finding"))
    assert f.confidence == "proven" and f.schema_id == "proofgate.finding/v1"


def test_legacy_receipt_hash_maps_to_report_hash():
    r = Report.model_validate(load("pdf_report"))
    assert r.receipt.report_hash == "sha256:abc"


def test_v3_roundtrip_keeps_schema_key():
    f = Finding.model_validate(load("v3_finding"))
    out = f.to_json_dict()
    assert out["schema"] == "proofgate.finding/v1" and "schema_id" not in out
    assert Finding.model_validate(out) == f


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(category="nope"),
        lambda d: d.update(severity="urgent"),
        lambda d: d.update(status="done"),
        lambda d: d.update(extra_field=1),
        lambda d: d.update(layer=10),
        lambda d: d.update(confidence="low"),  # proven=true but low confidence
    ],
)
def test_finding_rejects_bad_values(mutate):
    d = load("v3_finding")
    mutate(d)
    with pytest.raises(ValidationError):
        Finding.model_validate(d)


def test_new_statuses_accepted():
    for s in ("accepted-risk", "untested", "inconclusive"):
        d = load("v3_finding")
        d["status"] = s
        Finding.model_validate(d)


def test_contract_source_restricted():
    d = load("pdf_contract")
    d["source"] = "other"
    with pytest.raises(ValidationError):
        Contract.model_validate(d)


def test_fix_without_winner_is_allowed():
    d = load("v3_fixresult")
    d["winner"] = None
    d["accepted"] = False
    FixResult.model_validate(d)


def test_accepted_risk_expiry():
    a = AcceptedRisk.model_validate(load("accepted"))
    assert not a.is_expired(dt.date(2027, 1, 31))
    assert a.is_expired(dt.date(2027, 2, 1))
