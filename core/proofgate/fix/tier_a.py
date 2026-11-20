"""Tier A: deterministic codemods (plan 4). No LLM. Each fixer returns the NEW text of one file (or several), or None
when the code is not in a shape it can change safely: it never guesses.

  secret in code        -> read it from an environment variable, add NAME= to .env.example, ignore .env, say "rotate it"
  string-built SQL      -> placeholders with a parameter tuple (AST positions, so it cannot touch other code)
  shell=True            -> an argument list (only when the command has no shell syntax)
  debug=True            -> read the flag from the environment, default off
  verify=False          -> removed
  vulnerable dependency -> bump to the `fixed_in` version
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from ..models import Finding
from ..layers.base import read_text
from .patching import diff_texts

_SHELL_SYNTAX = re.compile(r"""[|&;<>$`()\\"'*?~{}\[\]]""")


# ------------------------------------------------------------------------------------ source splicing
class Source:
    """Text with AST node ranges mapped to character offsets, so edits touch exactly one node."""

    def __init__(self, text: str):
        self.text = text
        self.starts = [0]
        for ln in text.splitlines(keepends=True):
            self.starts.append(self.starts[-1] + len(ln))
        self._bytes_lines = [ln.encode("utf-8") for ln in text.splitlines(keepends=True)]

    def offset(self, lineno: int, col: int) -> int:
        line = self._bytes_lines[lineno - 1] if lineno - 1 < len(self._bytes_lines) else b""
        return self.starts[lineno - 1] + len(line[:col].decode("utf-8", "ignore"))

    def span(self, node: ast.AST) -> tuple[int, int]:
        return self.offset(node.lineno, node.col_offset), self.offset(node.end_lineno, node.end_col_offset)  # type: ignore[attr-defined]

    def seg(self, node: ast.AST) -> str:
        a, b = self.span(node)
        return self.text[a:b]


def apply_edits(src: Source, edits: list[tuple[int, int, str]]) -> str:
    out = src.text
    for a, b, new in sorted(edits, key=lambda e: e[0], reverse=True):
        out = out[:a] + new + out[b:]
    return out


def _parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def calls_in(tree: ast.AST, lo: int, hi: int):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and lo <= n.lineno <= hi:
            yield n


def function_range(tree: ast.Module, name: str | None, line: int) -> tuple[int, int]:
    """(first line, last line) of the function the finding points at, else a small window around the line."""
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and (n.name == name or n.lineno == line):
            first = min([n.lineno, *(d.lineno for d in n.decorator_list)])
            return first, n.end_lineno or n.lineno
    return max(line - 1, 1), line + 3


def ensure_import(text: str, module: str) -> str:
    """Add `import <module>` after the last top-level import if it is missing."""
    tree = _parse(text)
    if tree is None:
        return text
    for n in tree.body:
        if isinstance(n, ast.Import) and any(a.name == module for a in n.names):
            return text
    last = max((n.end_lineno or n.lineno for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))), default=0)
    if last == 0:  # no imports: after the module docstring if any
        first = tree.body[0] if tree.body else None
        last = (first.end_lineno or 1) if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) else 0
    lines = text.splitlines(keepends=True)
    lines.insert(last, f"import {module}\n")
    return "".join(lines)


# ------------------------------------------------------------------------------------ SQL placeholders
def _fstring_src(parts: list[tuple[str, str]]) -> str | None:
    body = ""
    for kind, val in parts:
        if kind == "lit":
            body += val.replace("\\", "\\\\").replace("{", "{{").replace("}", "}}").replace('"', '\\"').replace("\n", "\\n")
        else:
            if '"' in val or "\\" in val:
                return None
            body += "{" + val + "}"
    return 'f"' + body + '"'


def sql_to_placeholders(sql: ast.JoinedStr, marker: str) -> tuple[str, list[str]] | None:
    out, params = "", []
    in_quote, seg = False, []  # seg: parts of the quoted literal being collected
    for v in sql.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            for ch in v.value:
                if ch == "'":
                    if not in_quote:
                        in_quote, seg = True, []
                    else:
                        in_quote = False
                        if any(k == "expr" for k, _ in seg):
                            if len(seg) == 1:
                                params.append(seg[0][1])
                            else:
                                f = _fstring_src(seg)
                                if f is None:
                                    return None
                                params.append(f)
                            out += marker
                        else:
                            out += "'" + "".join(t for _, t in seg) + "'"
                elif in_quote:
                    if seg and seg[-1][0] == "lit":
                        seg[-1] = ("lit", seg[-1][1] + ch)
                    else:
                        seg.append(("lit", ch))
                else:
                    out += ch
        elif isinstance(v, ast.FormattedValue):
            expr = ast.unparse(v.value)
            if v.format_spec is not None or v.conversion not in (-1, None):
                return None
            if in_quote:
                seg.append(("expr", expr))
            else:
                out += marker
                params.append(expr)
        else:
            return None
    return (out, params) if not in_quote and params else None


def fix_sql_placeholders(text: str, line: int, function: str | None) -> str | None:
    tree = _parse(text)
    if tree is None:
        return None
    lo, hi = function_range(tree, function, line)
    marker = "%s" if re.search(r"psycopg|pymysql|mysql", text) else "?"
    src, edits = Source(text), []
    for call in calls_in(tree, lo, hi):
        if not (isinstance(call.func, ast.Attribute) and call.func.attr == "execute" and call.args and len(call.args) == 1
                and isinstance(call.args[0], ast.JoinedStr)):
            continue
        res = sql_to_placeholders(call.args[0], marker)
        if res is None:
            continue
        sql, params = res
        tup = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
        edits.append((*src.span(call.args[0]), f"{json.dumps(sql)}, {tup}"))
    return apply_edits(src, edits) if edits else None


# ------------------------------------------------------------------------------------ shell=True
def _remove_keyword(src: Source, call: ast.Call, kw: ast.keyword) -> tuple[int, int]:
    a, b = src.span(kw)
    # also remove the separating comma (before the keyword, or after it when it is the first argument)
    before = src.text[:a].rstrip()
    if before.endswith(","):
        return len(before) - 1, b
    after = re.match(r"\s*,\s*", src.text[b:])
    return a, b + (after.end() if after else 0)


def fix_shell_true(text: str, line: int, function: str | None) -> str | None:
    tree = _parse(text)
    if tree is None:
        return None
    lo, hi = function_range(tree, function, line)
    src, edits = Source(text), []
    for call in calls_in(tree, lo, hi):
        if not _dotted(call.func).startswith("subprocess."):
            continue
        kw = next((k for k in call.keywords if k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True), None)
        if kw is None or not call.args:
            continue
        cmd = call.args[0]
        words: list[list[tuple[str, str]]] = [[]]
        values = cmd.values if isinstance(cmd, ast.JoinedStr) else [cmd] if isinstance(cmd, ast.Constant) and isinstance(cmd.value, str) else None
        if values is None:
            continue
        bad = False
        for v in values:
            if isinstance(v, ast.Constant):
                for tok in re.split(r"(\s+)", v.value):
                    if tok.isspace():
                        words.append([])
                    elif tok:
                        if _SHELL_SYNTAX.search(tok):
                            bad = True
                        words[-1].append(("lit", tok))
            elif isinstance(v, ast.FormattedValue) and v.format_spec is None and v.conversion in (-1, None):
                words[-1].append(("expr", ast.unparse(v.value)))
            else:
                bad = True
        words = [w for w in words if w]
        if bad or not words:
            continue
        elems = []
        for w in words:
            if len(w) == 1 and w[0][0] == "expr":
                elems.append(f"str({w[0][1]})")
            elif all(k == "lit" for k, _ in w):
                elems.append(json.dumps("".join(t for _, t in w)))
            else:
                f = _fstring_src(w)
                if f is None:
                    bad = True
                    break
                elems.append(f)
        if bad:
            continue
        edits.append((*src.span(cmd), "[" + ", ".join(elems) + "]"))
        edits.append((*_remove_keyword(src, call, kw), ""))
    return apply_edits(src, edits) if edits else None


# ------------------------------------------------------------------------------------ small config fixes
def fix_debug_true(text: str, line: int, function: str | None) -> str | None:
    tree = _parse(text)
    if tree is None:
        return None
    lo, hi = function_range(tree, function, line)
    src, edits = Source(text), []
    for call in calls_in(tree, lo, hi):
        kw = next((k for k in call.keywords if k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True), None)
        if kw is not None and isinstance(call.func, ast.Attribute) and call.func.attr == "run":
            edits.append((*src.span(kw.value), 'os.environ.get("FLASK_DEBUG") == "1"'))
    return ensure_import(apply_edits(src, edits), "os") if edits else None


def fix_verify_false(text: str, line: int, function: str | None) -> str | None:
    tree = _parse(text)
    if tree is None:
        return None
    lo, hi = function_range(tree, function, line)
    src, edits = Source(text), []
    for call in calls_in(tree, lo, hi):
        if _dotted(call.func) == "ssl._create_unverified_context":
            edits.append((*src.span(call.func), "ssl.create_default_context"))
        kw = next((k for k in call.keywords if k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False), None)
        if kw is not None and _dotted(call.func).startswith("requests."):
            edits.append((*_remove_keyword(src, call, kw), ""))
    return apply_edits(src, edits) if edits else None


_PY_SECRET = re.compile(r"""^(?P<ind>\s*)(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<q>["'])(?P<val>[^"']+)(?P=q)\s*$""")
_JS_SECRET = re.compile(r"""^(?P<ind>\s*)(?P<decl>(?:export\s+)?(?:const|let|var)\s+)(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<q>["'`])(?P<val>[^"'`]+)(?P=q);?\s*$""")


def fix_hardcoded_secret(project: Path, rel: str, line: int) -> dict[str, str] | None:
    """{path: new text} moving the literal at `line` into an environment variable. Python and JS/TS assignments only."""
    text = read_text(project / rel)
    if text is None:
        return None
    lines = text.split("\n")
    if not 1 <= line <= len(lines):
        return None
    py = rel.endswith(".py")
    m = (_PY_SECRET if py else _JS_SECRET).match(lines[line - 1])
    if not m:
        return None
    name = m.group("name")
    if py:
        lines[line - 1] = f'{m.group("ind")}{name} = os.environ.get("{name}")'
        new = ensure_import("\n".join(lines), "os")
    else:
        lines[line - 1] = f'{m.group("ind")}{m.group("decl")}{name} = process.env.{name};'
        new = "\n".join(lines)
    changes = {rel: new}
    env_path = ".env.example"
    env = read_text(project / env_path) or ""
    if not re.search(rf"^{re.escape(name)}=", env, re.MULTILINE):
        changes[env_path] = env + ("" if env.endswith("\n") or not env else "\n") + f"{name}=\n"
    gi = read_text(project / ".gitignore") or ""
    if not re.search(r"^\.env\s*$", gi, re.MULTILINE):
        changes[".gitignore"] = gi + ("" if gi.endswith("\n") or not gi else "\n") + ".env\n"
    return changes


def bump_dependency(project: Path, finding: Finding) -> str | None:
    if not finding.fixed_in:
        return None
    rel = finding.location.file
    text = read_text(project / rel)
    if text is None:
        return None
    name = finding.title.split(" ")[0]
    if rel.endswith("package.json"):
        new, n = re.subn(rf'("{re.escape(name)}"\s*:\s*")[\^~]?[\w.\-]+(")', rf"\g<1>{finding.fixed_in}\g<2>", text, count=1)
    else:
        new, n = re.subn(rf"^(\s*{re.escape(name)}\s*==\s*)[\w.]+", rf"\g<1>{finding.fixed_in}", text, count=1,
                         flags=re.IGNORECASE | re.MULTILINE)
    return new if n else None


# ------------------------------------------------------------------------------------ dispatch
def tier_a_patch(project: Path, finding: Finding) -> tuple[str, str] | None:
    """(unified diff, learned rule) or None."""
    rel, line, fn = finding.location.file, finding.location.line, finding.location.function
    rule = finding.rule
    text = read_text(project / rel)
    if finding.layer == 3:
        new = bump_dependency(project, finding)
        return (diff_texts(project, {rel: new}), "Pin dependencies at versions without known vulnerabilities.") if new else None
    if finding.category == "secrets" and finding.layer == 1:
        changes = fix_hardcoded_secret(project, rel, line)
        return (diff_texts(project, changes), "Never write keys in code: read them from environment variables and rotate any "
                "key that was ever committed.") if changes else None
    if text is None:
        return None
    fixers = (
        (("sql-injection", "B608"), fix_sql_placeholders, "Build SQL with placeholders and parameters, never by string formatting."),
        (("shell-true", "os-system", "B602", "B605", "command-injection"), fix_shell_true,
         "Run programs with an argument list, never through a shell string."),
        (("flask-debug-true", "B201"), fix_debug_true, "Read debug mode from the environment and default it to off."),
        (("verify-false", "B501"), fix_verify_false, "Never turn off TLS certificate checks."),
    )
    for keys, fn_fix, learned in fixers:
        if any(k in rule for k in keys):
            new = fn_fix(text, line, fn)
            return (diff_texts(project, {rel: new}), learned) if new and new != text else None
    return None
