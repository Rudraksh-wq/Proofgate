"""Unified-diff plumbing for the fix pipeline: make, parse, apply (in a temp copy only), and measure patches.

Guard A (plan 4): a patch is NEVER applied to the real project. `apply_patch` is only ever pointed at a temporary copy.
Paths inside a patch must stay inside the root they are applied to.
"""
from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

COPY_IGNORE = shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__", ".proofgate", ".next",
                                     ".pytest_cache", "*.pyc")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchError(Exception):
    """The patch is malformed, unsafe, or does not apply."""


@dataclass
class Hunk:
    old_start: int
    old_lines: list[str]  # context + removed, without the leading marker
    new_lines: list[str]  # context + added


@dataclass
class FilePatch:
    path: str  # the "after" path, relative, forward slashes
    is_new: bool = False
    is_delete: bool = False
    hunks: list[Hunk] = field(default_factory=list)


@dataclass(frozen=True)
class Stats:
    added: int
    removed: int
    files: tuple[str, ...]
    new_files: tuple[str, ...]
    modified_files: tuple[str, ...]

    @property
    def changed_lines(self) -> int:
        return self.added + self.removed


# ------------------------------------------------------------------------------------ making diffs
def make_diff(path: str, old: str | None, new: str) -> str:
    """Unified diff for one file. `old=None` means the file is new."""
    a = (old or "").replace("\r\n", "\n").splitlines(keepends=True)  # patches are always LF; apply_patch keeps the file's EOL
    b = new.replace("\r\n", "\n").splitlines(keepends=True)
    if a and not a[-1].endswith("\n"):
        a[-1] += "\n"
    if b and not b[-1].endswith("\n"):
        b[-1] += "\n"
    fromfile = "/dev/null" if old is None else f"a/{path}"
    return "".join(difflib.unified_diff(a, b, fromfile=fromfile, tofile=f"b/{path}", n=3))


def diff_texts(project: Path, changes: dict[str, str | None]) -> str:
    """Patch turning `project` into `changes` ({relative path: new text}). A missing file is created."""
    parts = []
    for rel, new in changes.items():
        if new is None:
            continue
        f = project / rel
        old = f.read_text(encoding="utf-8") if f.is_file() else None
        if old != new:
            parts.append(make_diff(rel, old, new))
    return "".join(parts)


# ------------------------------------------------------------------------------------ parsing + stats
def _clean_path(raw: str) -> str:
    raw = raw.split("\t")[0].strip()
    for prefix in ("a/", "b/"):
        if raw.startswith(prefix):
            return raw[2:]
    return raw


def parse_patch(patch: str) -> list[FilePatch]:
    files: list[FilePatch] = []
    lines = patch.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("--- "):
            old_path = lines[i][4:].strip()
            if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                raise PatchError("'---' line without a following '+++' line")
            new_path = lines[i + 1][4:].strip()
            fp = FilePatch(path=_clean_path(new_path if new_path != "/dev/null" else old_path),
                           is_new=old_path.split("\t")[0] == "/dev/null", is_delete=new_path.split("\t")[0] == "/dev/null")
            i += 2
            while i < len(lines) and not lines[i].startswith("--- "):
                m = _HUNK.match(lines[i])
                if not m:
                    if lines[i].startswith("@@"):
                        raise PatchError(f"bad hunk header: {lines[i]!r}")
                    i += 1
                    continue
                old_n = int(m.group(2)) if m.group(2) is not None else 1
                new_n = int(m.group(4)) if m.group(4) is not None else 1
                h = Hunk(int(m.group(1)), [], [])
                i += 1
                while i < len(lines) and (len(h.old_lines) < old_n or len(h.new_lines) < new_n):
                    ln = lines[i]
                    tag, text = (ln[:1], ln[1:]) if ln else (" ", "")
                    if tag == " ":
                        h.old_lines.append(text); h.new_lines.append(text)
                    elif tag == "-":
                        h.old_lines.append(text)
                    elif tag == "+":
                        h.new_lines.append(text)
                    elif tag == "\\":
                        pass  # "\ No newline at end of file"
                    else:
                        raise PatchError(f"unexpected line in hunk: {ln!r}")
                    i += 1
                while i < len(lines) and lines[i].startswith("\\"):
                    i += 1
                if len(h.old_lines) != old_n or len(h.new_lines) != new_n:
                    raise PatchError("hunk is shorter than its header says")
                fp.hunks.append(h)
            files.append(fp)
        else:
            i += 1
    if not files:
        raise PatchError("no file sections found: not a unified diff")
    return files


def diff_stats(patch: str) -> Stats:
    files = parse_patch(patch)
    added = removed = 0
    for fp in files:
        for h in fp.hunks:
            old, new = list(h.old_lines), list(h.new_lines)
            sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
            for op, a0, a1, b0, b1 in sm.get_opcodes():
                if op in ("replace", "delete"):
                    removed += a1 - a0
                if op in ("replace", "insert"):
                    added += b1 - b0
    return Stats(added, removed, tuple(f.path for f in files), tuple(f.path for f in files if f.is_new),
                 tuple(f.path for f in files if not f.is_new))


# ------------------------------------------------------------------------------------ applying
def _safe(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError:
        raise PatchError(f"patch path escapes the project: {rel!r}") from None
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise PatchError(f"unsafe path in patch: {rel!r}")
    return p


def _find_block(lines: list[str], block: list[str], hint: int) -> int:
    """Index where `block` occurs in `lines`, preferring the spot nearest `hint`. -1 if absent."""
    if not block:
        return min(max(hint, 0), len(lines))
    hits = [i for i in range(len(lines) - len(block) + 1) if lines[i:i + len(block)] == block]
    return min(hits, key=lambda i: abs(i - hint)) if hits else -1


def apply_patch(root: Path, patch: str) -> list[str]:
    """Apply `patch` under `root` (a temp copy!). Returns the changed relative paths. All-or-nothing per call."""
    plan: list[tuple[Path, str | None]] = []
    for fp in parse_patch(patch):
        target = _safe(root, fp.path)
        if fp.is_delete:
            plan.append((target, None))
            continue
        if fp.is_new:
            if target.exists():
                raise PatchError(f"{fp.path}: patch creates a file that already exists")
            text = "\n".join(l for h in fp.hunks for l in h.new_lines)
            plan.append((target, text + "\n" if text else ""))
            continue
        if not target.is_file():
            raise PatchError(f"{fp.path}: file to patch does not exist")
        raw = target.read_bytes().decode("utf-8")
        eol = "\r\n" if "\r\n" in raw else "\n"
        raw = raw.replace("\r\n", "\n")
        ends_nl = raw.endswith("\n")
        lines = raw.split("\n")
        if ends_nl:
            lines.pop()
        offset = 0
        for h in fp.hunks:
            at = _find_block(lines, h.old_lines, h.old_start - 1 + offset)
            if at < 0:
                raise PatchError(f"{fp.path}: hunk at line {h.old_start} does not match the file")
            lines[at:at + len(h.old_lines)] = h.new_lines
            offset += len(h.new_lines) - len(h.old_lines)
        plan.append((target, ("\n".join(lines) + ("\n" if ends_nl or lines else "")).replace("\n", eol)))
    for target, text in plan:
        if text is None:
            target.unlink(missing_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode("utf-8"))
    return [str(t.relative_to(root.resolve())).replace("\\", "/") for t, _ in plan]


def copy_project(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst, ignore=COPY_IGNORE, dirs_exist_ok=True)
    return dst
