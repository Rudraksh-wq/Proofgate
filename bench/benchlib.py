"""Benchmark maths and runners (plan 14). Everything here MEASURES; nothing is typed in by hand.

A ground-truth item {category, cwe, label, file, line} is FOUND by a tool when the tool reports a finding of the same category in
the same file within TOLERANCE lines. A finding that matches no ground-truth item is a false positive (every finding on a clean app
is one). Precision = TP / (TP + FP), recall = found / items, F1 as usual; None when the denominator is zero.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

CATEGORIES = ["secrets", "injection", "access", "deps", "supply-chain", "database", "config", "web", "bundle"]
TOLERANCE = 12  # lines: the corpus functions are short; the ground truth points at the function or the offending line


@dataclass(frozen=True)
class Row:
    """One finding from one tool on one app."""
    app: str
    category: str
    file: str
    line: int
    rule: str = ""
    tool: str = ""


@dataclass(frozen=True)
class Truth:
    app: str
    category: str
    file: str
    line: int
    label: str = ""


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def matches(t: Truth, r: Row, tol: int = TOLERANCE) -> bool:
    return t.app == r.app and t.category == r.category and _norm(t.file) == _norm(r.file) and abs(t.line - r.line) <= tol


def prf(tp_rows: int, fp_rows: int, found_items: int, missed_items: int) -> dict[str, Any]:
    """Precision is over FINDINGS (matching rows / all rows); recall is over GROUND-TRUTH ITEMS (found / all items). One finding can
    cover several adjacent items (two keys on neighbouring lines), so the two denominators are different units on purpose."""
    p = tp_rows / (tp_rows + fp_rows) if tp_rows + fp_rows else None
    r = found_items / (found_items + missed_items) if found_items + missed_items else None
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and p + r else (0.0 if p is not None and r is not None else None)
    return {"matching_findings": tp_rows, "false_positives": fp_rows, "items_found": found_items, "items_missed": missed_items,
            "precision": _round(p), "recall": _round(r), "f1": _round(f1)}


def _round(x: float | None) -> float | None:
    return None if x is None else round(x, 3)


def score(rows: Iterable[Row], truth: list[Truth], tol: int = TOLERANCE) -> dict[str, Any]:
    """Overall and per-category precision/recall/F1, plus a one-line explanation for every miss and every false positive."""
    rows = list(dict.fromkeys(rows))  # identical (app, category, file, line, rule, tool) rows count once
    found: set[int] = set()
    good_rows: set[int] = set()
    for ti, t in enumerate(truth):
        for ri, r in enumerate(rows):
            if matches(t, r, tol):
                found.add(ti)
                good_rows.add(ri)
    by_cat: dict[str, dict[str, Any]] = {}
    for cat in CATEGORIES:
        t_items = [i for i, t in enumerate(truth) if t.category == cat]
        r_items = [i for i, r in enumerate(rows) if r.category == cat]
        tp = sum(1 for i in r_items if i in good_rows)
        n_found = sum(1 for i in t_items if i in found)
        by_cat[cat] = prf(tp, len(r_items) - tp, n_found, len(t_items) - n_found) | {"items": len(t_items)}
    tp_all = len(good_rows)
    overall = prf(tp_all, len(rows) - tp_all, len(found), len(truth) - len(found)) | {"items": len(truth)}
    misses = [f"{t.app} - no finding of category {t.category} within {tol} lines of {t.file}:{t.line} ({t.label})"
              for i, t in enumerate(truth) if i not in found]
    false_pos = [f"{r.app} - reported {r.category} at {r.file}:{r.line} ({r.rule or r.tool}) where the ground truth lists nothing"
                 for i, r in enumerate(rows) if i not in good_rows]
    return {"overall": overall, "by_category": by_cat, "misses": misses, "false_positives": false_pos}


def union_rows(columns: dict[str, list[Row]]) -> list[Row]:
    """"What exists today": every finding any baseline tool reports, once per (app, category, file, line)."""
    seen: dict[tuple, Row] = {}
    for rows in columns.values():
        for r in rows:
            seen.setdefault((r.app, r.category, _norm(r.file), r.line), Row(r.app, r.category, r.file, r.line, r.rule, "union"))
    return list(seen.values())


def accuracy(decisions: list[tuple[bool, bool]]) -> float | None:
    """decisions: [(predicted_accept, should_accept)]."""
    return round(sum(1 for p, s in decisions if p == s) / len(decisions), 3) if decisions else None


def median(xs: list[float]) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    mid = len(s) // 2
    return round(s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2, 3)


def truth_from_json(ground_truth: dict[str, list[dict]]) -> list[Truth]:
    return [Truth(app, it["category"], it["file"], int(it["line"]), it.get("label", ""))
            for app, items in ground_truth.items() for it in items]
