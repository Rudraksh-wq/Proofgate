import logging
import re

import pytest

from proofgate.models import Finding
from proofgate.redact import (
    CANARY_RE, excerpt, find_leaks, install_logging_filter, new_canary, redact, redact_obj,
)

from conftest import fake_secrets

TAG = re.compile(r"\u00abSECRET:[a-z0-9-]+:[0-9a-f]{8}\u00bb")


@pytest.mark.parametrize("kind", sorted(fake_secrets()))
def test_each_secret_type_is_masked(kind, no_leaks):
    raw = fake_secrets()[kind]
    out = redact(f"value is {raw} here")
    assert raw not in out and TAG.search(out)
    no_leaks(out, secrets=[raw])


def test_mask_format_has_type_and_stable_hash():
    raw = fake_secrets()["stripe"]
    a, b = redact(raw), redact(f"x {raw} y")
    assert a.startswith("\u00abSECRET:stripe-key:") and a in b


def test_canary_masked():
    c = new_canary("A")
    out = redact(f"body: {c} end")
    assert c not in out and "PGCANARY_A_\u00abmasked\u00bb" in out
    assert CANARY_RE.fullmatch(c)


def test_canaries_are_unique():
    assert new_canary("A") != new_canary("A")


def test_redact_is_idempotent():
    raw = fake_secrets()["github"]
    once = redact(f"token={raw} canary={new_canary('B')}")
    assert redact(once) == once


def test_env_style_assignments_masked_but_references_kept():
    out = redact('STRIPE_SECRET=abcdef123456\nDB_PASSWORD="hunter2hunter2"\napi_key = os.environ["API_KEY"]')
    assert "abcdef123456" not in out and "hunter2hunter2" not in out
    assert 'os.environ["API_KEY"]' in out  # code that reads env is not a secret


def test_js_env_reference_kept():
    assert redact("const token = process.env.SERVICE_TOKEN_VALUE") == "const token = process.env.SERVICE_TOKEN_VALUE"


def test_db_url_password_masked_user_and_host_kept():
    out = redact("postgres://admin:s3cretPassw0rd@db.local:5432/app")
    assert "s3cretPassw0rd" not in out and "admin" in out and "db.local" in out


def test_private_key_block_masked():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----"
    out = redact(f"k:\n{pem}\nend")
    assert "MIIBOg" not in out and "end" in out


def test_bearer_masked():
    out = redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
    assert "abcdefghijklmnop" not in out and out.startswith("Authorization: Bearer ")


def test_plain_text_untouched():
    text = "GET /notes/12 as user B -> 200 OK, nothing secret here: password reset page"
    assert redact(text) == text


def test_non_strings_pass_through():
    assert redact(None) is None and redact("") == ""
    assert redact_obj(5) == 5


def test_redact_obj_walks_nested_structures(no_leaks):
    raw, canary = fake_secrets()["aws"], new_canary("A")
    data = {"a": [raw, {"b": f"x {canary}"}], "t": (raw,), "n": 1}
    out = redact_obj(data)
    no_leaks(repr(out), secrets=[raw], canaries=[canary])
    assert out["n"] == 1 and isinstance(out["t"], tuple)


def test_redact_model_keeps_it_valid(no_leaks):
    raw, canary = fake_secrets()["stripe"], new_canary("A")
    f = Finding.model_validate({
        "id": "f_1", "layer": 1, "category": "secrets", "rule": "r", "severity": "high", "title": f"key {raw}",
        "plain_words": "p", "location": {"file": "a.py", "line": 1}, "sources": ["betterleaks"],
        "evidence": {"request": "GET /", "status": 200, "response_excerpt": f"..{canary}.."},
    })
    out = redact_obj(f)
    assert isinstance(out, Finding)
    no_leaks(out.to_json(), secrets=[raw], canaries=[canary])


def test_excerpt_redacts_before_truncating():
    raw = fake_secrets()["github"]
    out = excerpt("x" * 190 + raw, limit=200)
    assert raw[:12] not in out and len(out) <= 200


def test_find_leaks_detects_raw_and_unmasked_values():
    raw, canary = fake_secrets()["stripe"], new_canary("A")
    assert find_leaks(f"a {raw}") and find_leaks(f"b {canary}")
    assert find_leaks("clean text") == []
    assert find_leaks(redact(f"{raw} {canary}"), secrets_=[raw], canaries=[canary]) == []


def test_logging_filter_redacts_message_and_args():
    import io

    raw = fake_secrets()["google"]
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    logger = logging.getLogger("proofgate.test.redact")
    logger.propagate = False
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    install_logging_filter(logger)
    logger.info("calling with key %s", raw)
    assert raw not in buf.getvalue() and "SECRET:google-api-key" in buf.getvalue()


def test_redaction_is_fast_on_long_blobs():
    """Regression: an unbounded name prefix in the env-secret pattern made a long alphanumeric run take minutes."""
    import time

    for blob in ("x" * 200_000, "ab12" * 50_000, "a" * 100_000 + "=" + "b" * 100_000):
        t = time.perf_counter()
        redact(blob)
        assert time.perf_counter() - t < 5
