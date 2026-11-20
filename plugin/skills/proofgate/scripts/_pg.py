"""Shared helper for the skill scripts: run the `proofgate` CLI. Standard library only."""
import json
import shutil
import subprocess
import sys


def command():
    exe = shutil.which("proofgate")
    return [exe] if exe else [sys.executable, "-m", "proofgate.cli"]


def run(*args):
    """Run `proofgate <args>`; returns (exit code, stdout, stderr)."""
    try:
        r = subprocess.run(command() + list(args), capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        return 2, "", f"could not run proofgate: {e}"
    return r.returncode, r.stdout, r.stderr


def run_json(*args):
    code, out, err = run(*args)
    try:
        return code, json.loads(out), err
    except ValueError:
        return code, None, err or out
