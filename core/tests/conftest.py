"""Shared test helpers. Fake secrets are built at runtime so this repo never contains
literal key-shaped strings (our own secret scan must stay clean)."""
from __future__ import annotations

import pytest

from proofgate.redact import find_leaks


def fake_secrets() -> dict[str, str]:
    return {
        "stripe": "sk_" + "live_" + "Ab3dE6gH9jK2mN5pQ8sT1vX4",
        "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
        "github": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "google": "AIza" + "Sy" + "A" * 33,
        "slack": "xoxb-" + "1234567890-abcdefghij",
        "jwt": "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "yb2xlIjoic2VydmljZV9yb2xlIn0" + "." + "c2lnbmF0dXJlMTIzNDU2",
    }


@pytest.fixture
def secrets_map() -> dict[str, str]:
    return fake_secrets()


@pytest.fixture
def no_leaks():
    """Usage: no_leaks(output_text, secrets=[...], canaries=[...]) -> raises AssertionError on a leak.

    Later features call this on logs, hook output, MCP replies and cached LLM payloads (plan T10)."""

    def check(*texts: str, secrets=(), canaries=()) -> None:
        for t in texts:
            leaked = find_leaks(t, secrets_=secrets, canaries=canaries)
            assert not leaked, f"leak detected: {leaked!r}"

    return check
