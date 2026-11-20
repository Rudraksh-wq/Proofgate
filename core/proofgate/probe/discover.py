"""Route discovery for Flask apps, by regex over the source (plan 3.2, Master Guide P1 step 6).

Finds `@app.get("/x")`, `@app.route("/x", methods=[...])` and blueprint equivalents, the function they decorate, the
`<int:id>` path parameters, and the query parameters the function reads (`request.args.get("q")`).
Routes that cannot be discovered this way are reported as UNTESTED by the probe, never as safe.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from ..layers.base import iter_files, read_text

_VERB = re.compile(r"""^\s*@(\w+)\.(get|post|put|patch|delete)\(\s*["']([^"']+)["']""")
_ROUTE = re.compile(r"""^\s*@(\w+)\.route\(\s*["']([^"']+)["'](.*)\)\s*$""")
_METHODS = re.compile(r"""methods\s*=\s*[\[\(]([^\]\)]*)[\]\)]""")
_DEF = re.compile(r"""^\s*(?:async\s+)?def\s+(\w+)\s*\(""")
_QUERY = re.compile(r"""request\.args(?:\.get\(|\[)\s*["'](\w+)["']""")
_PATH_PARAM = re.compile(r"<(?:[a-z]+:)?(\w+)>")
_SKIP_PATH_PARTS = {"tests", "test", "migrations", "node_modules"}


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    file: str  # relative to the project
    line: int
    function: str
    path_params: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def has_id(self) -> bool:
        return bool(self.path_params)

    def fill(self, value: object) -> str:
        """The concrete path with every `<converter:name>` replaced by `value`."""
        return re.sub(r"<[^>]+>", str(value), self.path)


def _func_info(lines: list[str], start: int) -> tuple[str, int, tuple[str, ...]]:
    """(function name, def line (1-based), query params) for the decorator that ends at lines[start]."""
    i = start + 1
    while i < len(lines) and not _DEF.match(lines[i]):
        if lines[i].strip() and not lines[i].lstrip().startswith("@"):
            break
        i += 1
    if i >= len(lines) or not _DEF.match(lines[i]):
        return "", start + 1, ()
    name = _DEF.match(lines[i]).group(1)
    indent = len(lines[i]) - len(lines[i].lstrip())
    j = i + 1
    while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
        j += 1
    params = []
    for body_line in lines[i:j]:
        for m in _QUERY.finditer(body_line):
            if m.group(1) not in params:
                params.append(m.group(1))
    return name, i + 1, tuple(params)


def discover_routes(project: str | Path) -> list[Route]:
    project = Path(project).resolve()
    routes: list[Route] = []
    for p in iter_files(project):
        rel = p.relative_to(project)
        if p.suffix != ".py" or _SKIP_PATH_PARTS & set(rel.parts[:-1]):
            continue
        text = read_text(p)
        if not text or "@" not in text:
            continue
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            m = _VERB.match(line)
            methods: list[str]
            if m:
                methods, path = [m.group(2).upper()], m.group(3)
            else:
                r = _ROUTE.match(line)
                if not r:
                    continue
                path = r.group(2)
                ms = _METHODS.search(r.group(3))
                methods = [x.strip(" '\"").upper() for x in ms.group(1).split(",") if x.strip(" '\"")] if ms else ["GET"]
            func, def_line, query = _func_info(lines, idx)
            for method in methods:
                routes.append(Route(method, path, rel.as_posix(), def_line, func, tuple(_PATH_PARAM.findall(path)), query))
    return sorted(routes, key=lambda r: (r.file, r.line, r.method))


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat.rstrip("*").rstrip("/") + "/*") for pat in patterns)


def route_mentions(route: Route, word: str) -> bool:
    return word.lower() in route.path.lower()
