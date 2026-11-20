"""Shared test helpers. Fake secrets are built at runtime so this repo never contains
literal key-shaped strings (our own secret scan must stay clean)."""
from __future__ import annotations

import sys
from pathlib import Path

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


@pytest.fixture(scope="session", autouse=True)
def corpus_rendered():
    """Render the git-ignored, secret-bearing corpus files (v09, v10, c03) from their *.tmpl once per
    session, so tests, Layer 1, the hook and the benchmark all see real secret-shaped literals on disk."""
    demo_apps = str(Path(__file__).resolve().parents[2] / "demo-apps")
    if demo_apps not in sys.path:
        sys.path.insert(0, demo_apps)
    import generate_corpus

    return generate_corpus.materialize()
