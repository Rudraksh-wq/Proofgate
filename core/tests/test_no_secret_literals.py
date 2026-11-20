import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")


def _script():
    spec = importlib.util.spec_from_file_location("check_secret_literals", ROOT / "scripts" / "check_secret_literals.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_committable_file_contains_a_secret_shaped_literal():
    assert _script().scan_files() == []


def test_the_check_itself_catches_secret_shaped_text():
    mod = _script()
    fake = "sk_" + "live_" + "a1b2c3d4e5f6a7b8"
    jwt = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "yb2xlIjoiYW5vbiJ9", "c2lnbmF0dXJl"])
    assert mod.PATTERN.search(f"KEY = '{fake}'") and mod.PATTERN.search(jwt)
    assert not mod.PATTERN.search("sk_live_ is a prefix")


def test_generated_secret_files_are_git_ignored():
    for rel in (
        "demo-apps/flask-corpus/v09_hardcoded_keys/app.py",
        "demo-apps/flask-corpus/c03_bait/app.py",
        "demo-apps/flask-corpus/v10_service_role_in_bundle/static/bundle.js",
    ):
        r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT)
        assert r.returncode == 0, f"{rel} must be git-ignored"
