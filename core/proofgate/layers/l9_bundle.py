"""Layer 9: what the build ships to the browser (plan 2).

Looks only at build output that already exists (`.next/static`, `dist/`, `build/`); with `--full` a missing build is reported as a note
instead of being silently skipped. Nothing here builds, starts or contacts anything.

  * Layer 1's secret patterns and the JWT role decoder run over the bundle. A `service_role` key in the bundle is critical (it reaches
    every visitor). An `anon` key is public by design and is not a finding. Findings use Layer 1's fingerprints, so a secret seen by both
    layers merges into one finding with confirmed_by = 2.
  * Served source maps (`*.map`) and `sourceMappingURL` comments publish the original source next to the bundle.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..models import Finding, ToolRecord
from . import l1_secrets
from .base import LayerResult, finding_id

LAYER = 9
SOURCE = "proofgate-bundle"
MAX_BUNDLE_FILE = 8_000_000
# for Next.js only `.next/static` is sent to browsers; `.next/server` is server-side code and may legitimately hold server env values
BUNDLE_ROOTS = (".next/static", "dist", "build")
_TEXT_EXT = {".js", ".mjs", ".cjs", ".css", ".html", ".json", ".txt"}
_MAP_REF = "sourceMappingURL="


def _bundle_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != "node_modules")
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or p.stat().st_size > MAX_BUNDLE_FILE:
                    continue
            except OSError:
                continue
            yield p


def _source_map_finding(root_rel: str, maps: list[str], refs: list[str]) -> Finding:
    examples = ", ".join((maps or refs)[:3])
    what = f"{len(maps)} source map file(s)" if maps else f"{len(refs)} file(s) pointing to source maps"
    fp = f"sha256:bundle-source-maps|{root_rel}"
    return Finding(
        id=finding_id(fp), fingerprint=fp, layer=LAYER, category="bundle", rule="source-maps-published", cwe="CWE-540",
        severity="medium", confidence="high", title=f"Source maps are published with the browser bundle ({root_rel})",
        plain_words=(f"The build in {root_rel} ships {what} ({examples}). Source maps let anyone read your original source code, comments and "
                     "internal route names in the browser. Turn off production source maps (Next.js: productionBrowserSourceMaps)."),
        location={"file": (maps or refs)[0], "line": 1}, sources=[SOURCE], fix_tier="A",
    )


def scan_bundle(project: Path, root: Path) -> tuple[list[Finding], int]:
    """Findings for one build folder and the number of files read."""
    findings: list[Finding] = []
    maps: list[str] = []
    refs: list[str] = []
    root_rel = root.relative_to(project).as_posix()
    n = 0
    for p in _bundle_files(root):
        rel = p.relative_to(project).as_posix()
        if p.suffix == ".map":
            maps.append(rel)
            continue
        if p.suffix not in _TEXT_EXT:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        n += 1
        for f in l1_secrets.scan_text(text, rel):  # same fingerprints as layer 1: the same secret merges into one finding
            findings.append(f.model_copy(update={
                "layer": LAYER, "category": "bundle", "sources": [SOURCE], "fix_tier": None,
                "title": f.title.replace(" in code", " in the browser bundle"),
                "plain_words": f.plain_words + " It is in the files your visitors download, so assume it has already been copied.",
            }))
        if p.suffix in (".js", ".mjs", ".css") and _MAP_REF in text[-2000:] and rel + ".map" not in maps:
            refs.append(rel)
    if maps or refs:
        findings.append(_source_map_finding(root_rel, maps, refs))
    return findings, n


async def run(project_dir: str | Path, *, full: bool = False, **_ignored) -> LayerResult:
    project = Path(project_dir).resolve()
    result = LayerResult(layer=LAYER)
    result.tools.append(ToolRecord(name="proofgate-bundle", status="ok"))
    roots = [project / r for r in BUNDLE_ROOTS if (project / r).is_dir()]
    if not roots:
        if full:
            result.notes.append("no build output found (.next, dist, build): nothing to check; run your build first and scan again")
        return result
    scanned = 0
    for root in roots:
        found, n = scan_bundle(project, root)
        result.findings += found
        scanned += n
    # a service_role key that two files carry is still one secret per file: keep each location, sorted for stable output
    result.findings.sort(key=lambda f: (f.location.file, f.location.line, f.rule))
    result.notes.append(f"scanned {scanned} bundle file(s) in {', '.join(r.relative_to(project).as_posix() for r in roots)}")
    return result
