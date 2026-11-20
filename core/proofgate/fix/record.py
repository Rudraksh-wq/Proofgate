"""Remember fix results in .proofgate/report.json and print (never run) the command that undoes a fix."""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from ..models import FixResult, Report
from ..report_html import to_html
from .patching import PatchError, parse_patch


def record_fix(project: str | Path, result: FixResult) -> Report | None:
    """Store `result` in the report's `fixes` (replacing an older one for the same finding) and update the finding's status:
    accepted -> `fixing` (a verified diff exists, not applied yet), rejected -> `fix-rejected`, nothing to try -> `needs-human`.
    Only a tournament verdict changes a status; nothing a repo file says can."""
    path = Path(project) / ".proofgate" / "report.json"
    if not path.is_file():
        return None
    report = Report.model_validate_json(path.read_text(encoding="utf-8"))
    status = "fixing" if result.accepted else ("needs-human" if result.candidates == 0 else "fix-rejected")
    findings = [f.model_copy(update={"status": status}) if f.id == result.finding_id and f.status != "accepted-risk" else f
                for f in report.findings]
    fixes = [x for x in report.fixes if x.finding_id != result.finding_id] + [result]
    report = report.model_copy(update={"findings": findings, "fixes": fixes})
    path.write_text(report.to_json(), encoding="utf-8", newline="\n")
    path.with_name("report.html").write_text(to_html(report), encoding="utf-8", newline="\n")
    return report


def _git(project: Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(project), *args], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def rollback_commands(project: str | Path, finding_id: str) -> list[str]:
    """The shell commands that would undo the fix for `finding_id`. Pure advice: nothing is executed here except
    read-only `git log`. Raises LookupError when there is no recorded fix."""
    project = Path(project).resolve()
    path = project / ".proofgate" / "report.json"
    if not path.is_file():
        raise LookupError(f"{path} not found")
    report = Report.model_validate_json(path.read_text(encoding="utf-8"))
    fix = next((x for x in report.fixes if x.finding_id == finding_id), None)
    if fix is None or fix.winner is None:
        raise LookupError(f"no accepted fix is recorded for {finding_id}")
    try:
        files = [fp.path for fp in parse_patch(fix.winner.patch)]
    except PatchError:
        files = []
    if fix.pre_fix_commit and _git(project, "rev-parse", "--git-dir") is not None:
        commits = (_git(project, "log", "--format=%h", f"{fix.pre_fix_commit}..HEAD", "--", *files) or "").split()
        if commits:  # newest first is the order git revert wants
            return [f"git revert {' '.join(commits)}"]
        return ["# the fix has not been committed: restore the files instead",
                f"git checkout -- {' '.join(shlex.quote(f) for f in files)}  # then delete any files the fix created"]
    return [f"# no git history recorded: undo the diff by hand in {', '.join(files) or 'the files it touched'}"]
