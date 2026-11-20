import json
import sys
import time

import pytest

from proofgate.cli import main
from proofgate.doctor import check_all, pin_tool
from proofgate.runner import run_tool
from proofgate.toollock import (
    DEFAULT_LOCK_PATH, ToolEntry, ToolLock, find_binary, platform_key, sha256_file, verify_tool,
)

PY = sys.executable


def lock_with(name="faketool", binary=PY, sha=None, verify="sha256", version=None) -> ToolLock:
    entry = ToolEntry(binary=binary, verify=verify, version=version,
                      sha256={platform_key(): sha} if sha else {}, version_args=["--version"])
    return ToolLock(tools={name: entry})


def pinned_lock(**kw) -> ToolLock:
    return lock_with(sha=sha256_file(find_binary(PY)), **kw)


def test_shipped_lock_is_valid_and_has_no_fake_hashes():
    lock = ToolLock.load(DEFAULT_LOCK_PATH)
    assert {"betterleaks", "gitleaks", "semgrep", "osv-scanner"} <= set(lock.tools)
    assert all(not e.sha256 for e in lock.tools.values()), "never ship invented hashes"


async def test_missing_tool_is_skipped_not_crash():
    res = await run_tool("faketool", lock=lock_with(binary="definitely-not-installed-xyz"))
    assert res.status == "skipped" and not res.ran and "not found" in res.reason


async def test_unknown_tool_is_refused():
    res = await run_tool("nope", lock=lock_with())
    assert res.status == "unpinned"


async def test_unpinned_binary_is_not_run():
    res = await run_tool("faketool", ["-c", "print('x')"], lock=lock_with())
    assert res.status == "unpinned" and res.stdout == "" and res.sha256


async def test_checksum_mismatch_refuses_to_run(tmp_path):
    marker = tmp_path / "ran.txt"
    code = f"open(r'{marker}', 'w').write('1')"
    res = await run_tool("faketool", ["-c", code], lock=lock_with(sha="0" * 64))
    assert res.status == "mismatch"
    assert not marker.exists()


async def test_pinned_tool_runs_and_captures_output():
    res = await run_tool("faketool", ["-c", "import sys; print('hi'); print('err', file=sys.stderr); sys.exit(3)"],
                         lock=pinned_lock())
    assert res.status == "ok" and res.ran
    assert res.stdout.strip() == "hi" and res.stderr.strip() == "err" and res.returncode == 3


async def test_stdin_is_passed():
    res = await run_tool("faketool", ["-c", "import sys; print(sys.stdin.read().upper())"],
                         lock=pinned_lock(), stdin="abc")
    assert res.stdout.strip() == "ABC"


async def test_timeout_kills_and_reports():
    t = time.monotonic()
    res = await run_tool("faketool", ["-c", "import time; time.sleep(30)"], lock=pinned_lock(), timeout=0.5)
    assert res.status == "timeout" and time.monotonic() - t < 15


async def test_binary_that_cannot_start_is_an_error(tmp_path):
    bad = tmp_path / "notexec.bin"
    bad.write_bytes(b"not a program")
    lock = lock_with(binary=str(bad), sha=sha256_file(bad))
    res = await run_tool("faketool", lock=lock)
    assert res.status == "error"


async def test_broken_lock_file_does_not_crash(tmp_path, monkeypatch):
    bad = tmp_path / "bad.lock.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("PROOFGATE_TOOLS_LOCK", str(bad))
    res = await run_tool("semgrep")
    assert res.status == "error"


def test_presence_tools_need_no_hash():
    v = verify_tool("faketool", lock_with(verify="presence"))
    assert v.status == "ok"


def test_tools_dir_is_searched_first(tmp_path):
    exe = tmp_path / ("mytool.exe" if sys.platform == "win32" else "mytool")
    exe.write_bytes(b"x")
    exe.chmod(0o755)
    assert find_binary("mytool", tools_dir=tmp_path) == exe


def test_result_converts_to_report_record():
    from proofgate.runner import ToolResult

    rec = ToolResult("semgrep", "skipped", reason="x").to_record()
    assert rec.name == "semgrep" and rec.status == "skipped"


async def test_check_all_flags_mismatch_and_version_drift():
    lock = lock_with(sha="0" * 64)
    assert (await check_all(lock))[0].status == "mismatch"
    drift = pinned_lock(version="not-the-real-version")
    assert (await check_all(drift))[0].status == "mismatch"


def test_pin_tool_records_hash_and_then_verifies(tmp_path):
    lock = lock_with()
    pin_tool("faketool", lock)
    assert lock.tools["faketool"].sha256[platform_key()] == sha256_file(find_binary(PY))
    assert verify_tool("faketool", lock).status == "ok"
    with pytest.raises(KeyError):
        pin_tool("unknown", lock)


def test_doctor_cli_exit_codes(tmp_path, monkeypatch, capsys):
    path = tmp_path / "lock.json"
    monkeypatch.setenv("PROOFGATE_TOOLS_LOCK", str(path))

    lock_with(sha="0" * 64).save(path)
    assert main(["doctor"]) == 1  # mismatch -> refuse

    lock_with(binary="not-installed-abc").save(path)
    assert main(["doctor"]) == 0  # missing is a warning...
    assert main(["doctor", "--strict"]) == 1  # ...unless strict

    path.write_text("garbage", encoding="utf-8")
    assert main(["doctor"]) == 2  # unreadable lock is a tool error

    lock_with().save(path)
    assert main(["doctor", "--pin", "faketool"]) == 0
    assert main(["doctor"]) == 0
    capsys.readouterr()
    assert main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["status"] == "ok"
    assert main(["doctor", "--pin", "ghost"]) == 2
