import tempfile
from pathlib import Path

import pytest

from proofgate.probe.guard import TargetRefused, check_target, ensure_temp_db


@pytest.mark.parametrize("url", [
    "http://localhost:5000", "http://127.0.0.1:8000/x", "http://127.9.9.9", "http://[::1]:3000", "localhost:5000",
    "http://app.localhost:3000", "https://LOCALHOST",
])
def test_local_targets_are_allowed_without_a_flag(url):
    d = check_target(url)
    assert d.local and not d.override


@pytest.mark.parametrize("url", [
    "http://example.com", "https://my-app.vercel.app", "http://10.0.0.5:5000", "http://192.168.1.10", "http://0.0.0.0:5000",
    "http://localhost.evil.com", "http://127.0.0.1.evil.com", "http://169.254.169.254", "http://example.com@127.0.0.1.evil.com",
])
def test_everything_else_is_refused(url):
    with pytest.raises(TargetRefused, match="only probes localhost"):
        check_target(url)


def test_override_needs_the_flag_and_is_marked():
    d = check_target("https://my-staging.example.com", i_own_this=True)
    assert not d.local and d.override


@pytest.mark.parametrize("url", ["", "ftp://localhost", "http://", "file:///etc/passwd"])
def test_garbage_targets_are_refused_even_with_the_flag(url):
    with pytest.raises(TargetRefused):
        check_target(url, i_own_this=True)


def test_database_must_live_in_the_temp_directory(tmp_path):
    ok = ensure_temp_db(Path(tempfile.gettempdir()) / "proofgate-x" / "probe.db")
    assert ok.name == "probe.db"
    with pytest.raises(TargetRefused, match="must live under"):
        ensure_temp_db(Path.home() / "important.db")
    with pytest.raises(TargetRefused):
        ensure_temp_db(Path(tempfile.gettempdir()) / ".." / "evil.db")
