"""`proofgate hook pre|post|stop`: the entry points Claude Code (and other agents) call around file edits (plan 6.3).

PRE   runs the inline checks (L1 secrets, L2 AST, L4 package cache) on what is ABOUT to be written. A critical secret or a
      package that does not exist is blocked, with the reason and the exact fix for the AI to act on. Everything else is allowed.
POST  starts a fast scan in the background (never waits for it) and returns immediately.
STOP  prints a short, non-blocking summary of open proven findings.

Fail-safe: a crash or anything slower than 500 ms is logged and ALLOWED (exit 0). Every fail-open event is counted in
`.proofgate/hook_state.json` and shown in the report, so it is visible, never silent.
The message to the AI is built from Finding fields only (<= 20 lines); nothing from the file's own text is echoed back, so
file content cannot talk to the agent through ProofGate. `// proofgate-ignore` comments do nothing.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding
from .redact import redact

HOOK_TIMEOUT_S = 0.5
MAX_MESSAGE_LINES = 20
MAX_CONTENT_BYTES = 1_000_000
WRITE_TOOLS = ("Write", "Edit", "MultiEdit")

FIX_HINTS = {
    "secrets": "Put the value in an environment variable (for example os.environ.get(\"NAME\") or process.env.NAME), add NAME= "
               "to .env.example, keep .env out of git, then tell the user to rotate this key: a key that was written in code is "
               "already exposed.",
    "supply-chain": "Do not add this package. Use the real package the user meant (check the exact name on the registry), or write "
                    "the code without a new dependency.",
}


@dataclass
class HookOutcome:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    allowed: bool = True
    findings: list[Finding] = field(default_factory=list)


# ------------------------------------------------------------------------------------ the message to the AI
def block_message(blockers: list[Finding]) -> str:
    """At most 20 lines, from Finding fields only."""
    lines = ["ProofGate blocked this write: it would put a serious problem into the project."]
    for f in blockers[:3]:
        lines.append(f"- {f.title}")
        lines.append(f"  Why: {f.plain_words}")
        lines.append(f"  Fix: {FIX_HINTS.get(f.category, 'Remove or replace it, then try again.')}")
        if f.interrupt_human:
            lines.append("  Tell the user about this one.")
    if len(blockers) > 3:
        lines.append(f"- ... and {len(blockers) - 3} more of the same kind.")
    lines.append("After fixing, write the file again. ProofGate cannot prove an app secure; it blocks only what it can see is wrong.")
    return redact("\n".join(lines[:MAX_MESSAGE_LINES]))


# ------------------------------------------------------------------------------------ reading what Claude is about to write
def _project_root(payload: dict[str, Any], project_dir: str | None) -> Path:
    return Path(project_dir or os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()).resolve()


def planned_content(tool: str, tool_input: dict[str, Any], path: Path) -> str | None:
    """The text the file will hold after the tool runs (or the new text, when the old text cannot be matched)."""
    if tool == "Write":
        c = tool_input.get("content")
        return c if isinstance(c, str) else None
    try:
        current = path.read_text(encoding="utf-8") if path.is_file() else ""
    except (OSError, UnicodeDecodeError):
        current = ""
    edits: list[tuple[str, str, bool]] = []
    if tool == "Edit":
        edits = [(tool_input.get("old_string", ""), tool_input.get("new_string", ""), bool(tool_input.get("replace_all")))]
    elif tool == "MultiEdit":
        edits = [(e.get("old_string", ""), e.get("new_string", ""), bool(e.get("replace_all"))) for e in tool_input.get("edits", []) if isinstance(e, dict)]
    if not edits:
        return None
    text, matched = current, True
    for old, new, every in edits:
        if old and old in text:
            text = text.replace(old, new) if every else text.replace(old, new, 1)
        else:
            matched = False
    if matched:
        return text
    return "\n".join(new for _, new, _ in edits)  # could not locate the old text: judge the new text on its own


# ------------------------------------------------------------------------------------ pre
def _check(path: Path, content: str, root: Path) -> list[Finding]:
    from .inline import check_file

    return check_file(path, content, project_root=root).findings


def _blocking(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if (f.layer == 1 and f.severity == "critical") or (f.layer == 4 and f.rule == "package-does-not-exist")]


def _deny(outcome: HookOutcome, reason: str, mode: str) -> HookOutcome:
    outcome.allowed = False
    if mode == "json":
        outcome.stdout = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                            "permissionDecisionReason": reason}})
        outcome.exit_code = 0
    else:
        outcome.stderr = reason
        outcome.exit_code = 2
    return outcome


def pre(payload: dict[str, Any], *, project_dir: str | None = None, mode: str = "exit2") -> HookOutcome:
    out = HookOutcome()
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if tool not in WRITE_TOOLS or not isinstance(tool_input, dict) or not isinstance(tool_input.get("file_path"), str):
        return out
    root = _project_root(payload, project_dir)
    path = Path(tool_input["file_path"])
    path = path if path.is_absolute() else root / path
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return out  # outside the project: not ours to judge
    content = planned_content(tool, tool_input, path)
    if content is None or len(content.encode("utf-8", "ignore")) > MAX_CONTENT_BYTES:
        return out
    out.findings = _check(path, content, root)
    blockers = _blocking(out.findings)
    return _deny(out, block_message(blockers), mode) if blockers else out


# ------------------------------------------------------------------------------------ post + stop
def post(payload: dict[str, Any], *, project_dir: str | None = None) -> HookOutcome:
    """Start `proofgate scan --fast` detached and return at once."""
    out = HookOutcome()
    if payload.get("tool_name") not in WRITE_TOOLS:
        return out
    root = _project_root(payload, project_dir)
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "cwd": str(root)}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, "-m", "proofgate.cli", "scan", str(root), "--fast", "--format", "agent"], **kwargs)
    return out


def stop(payload: dict[str, Any], *, project_dir: str | None = None) -> HookOutcome:
    """A non-blocking summary of OPEN PROVEN findings from the last report."""
    out = HookOutcome()
    if payload.get("stop_hook_active"):
        return out  # never loop
    report = _project_root(payload, project_dir) / ".proofgate" / "report.json"
    try:
        from .models import Report

        r = Report.model_validate_json(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    proven = [f for f in r.findings if f.proven and f.status in ("open", "fixing")]
    if not proven:
        return out
    lines = [f"ProofGate: {len(proven)} proven problem(s) are still open in this project:"]
    lines += [f"- {f.title.split(' (')[0]} ({f.location.file}:{f.location.line})" for f in proven[:5]]
    lines.append("Ask ProofGate to fix them: /proofgate-fix <id>. " + (r.limits_statement or ""))
    out.stdout = json.dumps({"systemMessage": redact("\n".join(lines[:MAX_MESSAGE_LINES]))})
    return out


# ------------------------------------------------------------------------------------ fail-safe wrapper
def _state_path(root: Path) -> Path:
    return root / ".proofgate" / "hook_state.json"


def record_fail_open(root: Path, why: str) -> None:
    p = _state_path(root)
    try:
        state = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except (OSError, ValueError):
        state = {}
    state["fail_open_count"] = int(state.get("fail_open_count", 0)) + 1
    state["last_fail_open"] = redact(why)[:200]
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def read_fail_open_count(root: Path) -> int:
    try:
        return int(json.loads(_state_path(root).read_text(encoding="utf-8")).get("fail_open_count", 0))
    except (OSError, ValueError, TypeError):
        return 0


def run_hook(phase: str, stdin_text: str, *, project_dir: str | None = None, mode: str = "exit2",
             timeout: float = HOOK_TIMEOUT_S) -> HookOutcome:
    """Never raises. A crash or a timeout allows the action and is counted."""
    started = time.monotonic()
    root = Path(project_dir or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
        root = _project_root(payload, project_dir)
        fn = {"pre": lambda: pre(payload, project_dir=project_dir, mode=mode), "post": lambda: post(payload, project_dir=project_dir),
              "stop": lambda: stop(payload, project_dir=project_dir)}[phase]
        box: dict[str, Any] = {}

        def work() -> None:
            try:
                box["out"] = fn()
            except BaseException as e:  # noqa: BLE001
                box["err"] = e

        t = threading.Thread(target=work, daemon=True)  # daemon: a stuck check can never keep the process alive
        t.start()
        t.join(max(timeout - (time.monotonic() - started), 0.01))
        if t.is_alive():
            raise TimeoutError
        if "err" in box:
            raise box["err"]
        return box["out"]
    except TimeoutError:
        record_fail_open(root, f"{phase} hook timed out after {timeout:g}s")
        return HookOutcome(stderr=f"proofgate hook timed out (allowing): {phase}")
    except Exception as e:  # noqa: BLE001 - fail-safe by design (plan 6.3)
        record_fail_open(root, f"{phase} hook crashed: {type(e).__name__}")
        return HookOutcome(stderr=redact(f"proofgate hook error (allowing): {type(e).__name__}: {e}"))
