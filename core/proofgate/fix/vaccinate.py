"""Vaccinate (plan 4): after a fix is accepted, turn the exploit into a regression test and teach the AI agents.

  * a regression test that FAILS on the original code and PASSES with the fix (verified here, in temp copies):
        pytest for Python/Flask, Vitest for Next.js routes, pgTAP for Supabase RLS
  * the learned rule, written into ONE marked block per agent file (CLAUDE.md, AGENTS.md, .cursor/rules/proofgate.mdc),
    deduplicated, so it shows up in the diff and in code review.

Rules written into agent instruction files come only from ProofGate's own fixed templates, never from LLM output:
a poisoned model must not be able to plant instructions into the files future agents obey.
Nothing is applied to the real project: the result is a second diff (`vaccine_patch`) the caller applies with the fix.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..layers.base import read_text
from ..models import Contract, Finding, FixResult
from .patching import apply_patch, copy_project, diff_texts

BEGIN = "<!-- proofgate:begin -->"
END = "<!-- proofgate:end -->"
AGENT_FILES = ("CLAUDE.md", "AGENTS.md", ".cursor/rules/proofgate.mdc")
CURSOR_HEADER = "---\ndescription: ProofGate security rules learned from verified fixes\nalwaysApply: true\n---\n\n"
BLOCK_TITLE = "## ProofGate security rules (added by verified fixes)"
PY_TEST_FILE = "tests/test_proofgate_regressions.py"
PY_HEADER = '''"""Regression tests written by ProofGate. Each one replays the attack behind a verified fix.

Every test FAILS while the hole exists and PASSES once it is fixed. They need ProofGate importable (pip install proofgate);
without it they are skipped, never silently green.
"""
import asyncio
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _assert_no_proven_attack(fingerprint, file, function, route):
    probe = pytest.importorskip("proofgate.probe")
    out = asyncio.run(probe.run_probe(ROOT))
    assert out.error is None, out.error
    left = [f for f in out.result.to_findings(out.contract)
            if f.fingerprint == fingerprint or (f.location.file, f.location.function, f.location.route) == (file, function, route)]
    assert not left, "the attack still works: " + ", ".join(f.rule for f in left)


def _assert_not_detected(fingerprint, file):
    inline = pytest.importorskip("proofgate.inline")
    found = inline.check_file(ROOT / file, project_root=ROOT).findings
    assert fingerprint not in {f.fingerprint for f in found}, "ProofGate still detects this problem"


def _assert_min_version(file, package, minimum):
    from packaging.version import Version

    text = (ROOT / file).read_text(encoding="utf-8")
    m = re.search(r"^\\s*" + re.escape(package) + r"\\s*==\\s*([\\w.]+)", text, re.IGNORECASE | re.MULTILINE)
    assert m, f"{package} is not pinned in {file}"
    assert Version(m.group(1)) >= Version(minimum), f"{package} {m.group(1)} is older than {minimum}"
'''


@dataclass
class Vaccine:
    patch: str  # unified diff: test file + rule blocks. Empty when nothing could be built
    files: list[str] = field(default_factory=list)
    test_id: str | None = None  # e.g. tests/test_proofgate_regressions.py::test_f_7c1a
    verified: bool | None = None  # failed before the fix and passed after it; None = could not be run here
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------------------ the rules block
def _norm(text: str) -> str:
    return re.sub(r"\W+", " ", text).strip().lower()


def merge_rules_block(existing: str | None, rule: str, finding_id: str, *, new_file_header: str = "") -> str:
    """Add `rule` to the ProofGate block of an agent file; create the block (or the file) if needed. Idempotent."""
    bullet = f"- {rule} <!-- pg:{finding_id} -->"
    if existing is None:
        return f"{new_file_header}{BEGIN}\n{BLOCK_TITLE}\n\n{bullet}\n{END}\n"
    m = re.search(rf"{re.escape(BEGIN)}(.*?){re.escape(END)}", existing, re.DOTALL)
    if m is None:
        sep = "" if existing.endswith("\n\n") else ("\n" if existing.endswith("\n") else "\n\n")
        return f"{existing}{sep}{BEGIN}\n{BLOCK_TITLE}\n\n{bullet}\n{END}\n"
    if any(_norm(re.sub(r"<!--.*?-->", "", ln).lstrip("- ")) == _norm(rule) for ln in m.group(1).splitlines()):
        return existing  # already taught
    inner = m.group(1).rstrip("\n") + "\n" + bullet + "\n"
    return existing[: m.start()] + BEGIN + inner + END + existing[m.end():]


def rule_changes(project: Path, rule: str, finding_id: str) -> dict[str, str]:
    changes: dict[str, str] = {}
    for rel in AGENT_FILES:
        existing = read_text(project / rel)
        header = CURSOR_HEADER if rel.endswith(".mdc") else ("# Project instructions\n\n" if rel == "CLAUDE.md" else "# Agents\n\n")
        new = merge_rules_block(existing, rule, finding_id, new_file_header=header)
        if new != existing:
            changes[rel] = new
    return changes


# ------------------------------------------------------------------------------------ regression tests
def _slug(finding_id: str) -> str:
    return re.sub(r"\W", "_", finding_id)


def _py_test(finding: Finding, fn: str) -> str | None:
    doc = f"[{finding.confidence}] {finding.rule}: {finding.title.split(' (')[0]}".replace('"', "'")
    loc = finding.location
    if finding.layer == 8:
        return (f'\n\ndef {fn}():\n    """{doc}"""\n    _assert_no_proven_attack({finding.fingerprint!r}, {loc.file!r}, {loc.function!r}, {loc.route!r})\n')
    if finding.layer == 3 and finding.fixed_in and finding.fix_tier:
        pkg = finding.title.split(" ")[0]
        return f'\n\ndef {fn}():\n    """{doc}"""\n    _assert_min_version({loc.file!r}, {pkg!r}, {finding.fixed_in!r})\n'
    if finding.layer in (1, 2) and loc.file.endswith(".py"):
        return f'\n\ndef {fn}():\n    """{doc}"""\n    _assert_not_detected({finding.fingerprint!r}, {loc.file!r})\n'
    return None


def vitest_for(finding: Finding) -> tuple[str, str, Callable[[str], bool]] | None:
    """(path, text, dry-run) for a Next.js route finding. The dry run checks the same property in Python."""
    if not (finding.location.file.endswith("route.ts") and "service-role" in finding.rule):
        return None
    rel, slug = finding.location.file, _slug(finding.id)
    text = (
        'import { describe, expect, it } from "vitest";\nimport { readFileSync } from "node:fs";\n\n'
        f'describe("{finding.id}: route handler must not use the service_role key", () => {{\n'
        f'  const src = readFileSync({rel!r}, "utf8");\n'
        '  it("does not read the service_role key", () => {\n    expect(src).not.toMatch(/SERVICE_ROLE/);\n  });\n'
        '  it("filters rows by the signed-in user", () => {\n    expect(src).toMatch(/\\.eq\\("user_id", user\\.id\\)/);\n  });\n});\n')
    ok = lambda src: "SERVICE_ROLE" not in src and re.search(r'\.eq\("user_id", user\.id\)', src) is not None  # noqa: E731
    return f"tests/proofgate/test_{slug}.spec.ts", text, ok


def pgtap_for(finding: Finding, table: str, owner: str) -> tuple[str, str]:
    slug = _slug(finding.id)
    sql = (
        f"-- pgTAP test written by ProofGate for {finding.id}: {finding.title.split(' (')[0]}\n"
        "begin;\nselect plan(5);\n"
        f"select ok((select relrowsecurity from pg_class where oid = 'public.{table}'::regclass), 'RLS is enabled on public.{table}');\n"
        + "".join(
            f"select ok(exists (select 1 from pg_policies where schemaname = 'public' and tablename = '{table}' and cmd = '{cmd}' "
            f"and coalesce(qual, with_check) like '%auth.uid()%{owner}%'), '{cmd.lower()} policy compares auth.uid() to {owner}');\n"
            for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"))
        + "select * from finish();\nrollback;\n")
    return f"supabase/tests/proofgate_{slug}.test.sql", sql


def _run_pytest(root: Path, test_rel: str, timeout: float = 240.0) -> tuple[bool, str]:
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider", test_rel], cwd=root,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "timed out"
    return r.returncode == 0, (r.stdout or r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr).strip() else ""


async def build_vaccine(project: str | Path, finding: Finding, result: FixResult, contract: Contract, *, verify: bool = True) -> Vaccine:
    """Regression test + learned rule for an ACCEPTED fix, as one diff. Never touches the real project."""
    project = Path(project).resolve()
    v = Vaccine(patch="")
    if not result.accepted or result.winner is None:
        v.notes.append("no vaccine: the fix was not accepted")
        return v
    fn = f"test_{_slug(finding.id)}"
    changes: dict[str, str] = {}

    pytest_text = _py_test(finding, fn)
    vitest = vitest_for(finding)
    if pytest_text is not None:
        existing = read_text(project / PY_TEST_FILE)
        if existing is None:
            existing = PY_HEADER
        if f"def {fn}(" not in existing:
            existing += pytest_text
        changes[PY_TEST_FILE] = existing
        v.test_id = f"{PY_TEST_FILE}::{fn}"
    elif vitest is not None:
        path, text, _dry = vitest
        changes[path] = text
        v.test_id = f"{path}::{finding.id}"
    elif finding.layer == 5 and contract.owned_resources:
        res = contract.owned_resources[0]
        path, text = pgtap_for(finding, res.name, res.owner_field)
        changes[path] = text
        v.test_id = f"{path}"
        v.notes.append("pgTAP test written; run it with `supabase test db` (needs the live stack: pending verification)")
    else:
        v.notes.append("no regression test template for this kind of finding")

    if result.learned_rule:
        changes.update(rule_changes(project, result.learned_rule, finding.id))
    else:
        v.notes.append("no rule written: only ProofGate's own templates may write into agent instruction files")

    changes = {rel: text for rel, text in changes.items() if read_text(project / rel) != text}  # idempotent
    if not changes:
        return v
    v.patch = diff_texts(project, changes)
    v.files = sorted(changes)

    if verify and pytest_text is not None:
        v.verified, why = await asyncio.to_thread(_verify_python, project, result.winner.patch, PY_TEST_FILE, fn, changes[PY_TEST_FILE])
        if why:
            v.notes.append(why)
    elif verify and vitest is not None:
        v.verified = await asyncio.to_thread(_verify_dry, project, result.winner.patch, finding.location.file, vitest[2])
        v.notes.append("Vitest test checked by an equivalent static check; run `npx vitest` to execute it")
    return v


def _verify_python(project: Path, fix_patch: str, test_rel: str, fn: str, test_text: str) -> tuple[bool, str]:
    """The test must FAIL on the original and PASS once the fix is applied."""
    with tempfile.TemporaryDirectory(prefix="proofgate-vaccine-", ignore_cleanup_errors=True) as td:
        before = copy_project(project, Path(td) / "before")
        (before / test_rel).parent.mkdir(parents=True, exist_ok=True)
        (before / test_rel).write_text(test_text, encoding="utf-8")
        passed_before, _ = _run_pytest(before, f"{test_rel}::{fn}")
        after = copy_project(project, Path(td) / "after")
        apply_patch(after, fix_patch)
        (after / test_rel).parent.mkdir(parents=True, exist_ok=True)
        (after / test_rel).write_text(test_text, encoding="utf-8")
        passed_after, msg = _run_pytest(after, f"{test_rel}::{fn}")
    if passed_before:  # green before the fix means the test does not catch the hole
        return False, "the regression test PASSED on the original code, so it does not catch the hole"
    if not passed_after:
        return False, f"the regression test still fails with the fix applied: {msg}"
    return True, ""


def _verify_dry(project: Path, fix_patch: str, rel: str, ok: Callable[[str], bool]) -> bool:
    with tempfile.TemporaryDirectory(prefix="proofgate-vaccine-", ignore_cleanup_errors=True) as td:
        copy = copy_project(project, Path(td) / "c")
        before = ok(read_text(copy / rel) or "")
        apply_patch(copy, fix_patch)
        after = ok(read_text(copy / rel) or "")
    return (not before) and after
