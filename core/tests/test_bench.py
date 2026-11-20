import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bench"))

from benchlib import Row, Truth, accuracy, matches, median, prf, score, truth_from_json, union_rows  # noqa: E402


def T(app="a", cat="access", file="app.py", line=10, label="x"):
    return Truth(app, cat, file, line, label)


def R(app="a", cat="access", file="app.py", line=10, rule="r", tool="t"):
    return Row(app, cat, file, line, rule, tool)


# ============================================================================= matching and scoring
def test_match_needs_same_app_category_file_and_a_near_line():
    t = T(line=100)
    assert matches(t, R(line=100)) and matches(t, R(line=112)) and matches(t, R(file="./app.py", line=100)) and matches(t, R(file="app.py", line=99))
    assert not matches(t, R(line=113)) and not matches(t, R(cat="injection", line=100)) and not matches(t, R(file="b.py", line=100)) and not matches(t, R(app="b", line=100))
    assert matches(T(file="static\\bundle.js"), R(file="static/bundle.js"))


def test_prf_units_and_edge_cases():
    p = prf(3, 1, 2, 2)
    assert (p["precision"], p["recall"], p["f1"]) == (0.75, 0.5, 0.6)
    assert prf(0, 0, 0, 0) == {"matching_findings": 0, "false_positives": 0, "items_found": 0, "items_missed": 0,
                               "precision": None, "recall": None, "f1": None}
    assert prf(0, 2, 0, 1)["f1"] == 0.0 and prf(0, 0, 0, 3)["precision"] is None


def test_one_finding_can_cover_two_adjacent_items_without_recall_going_over_100_percent():
    truth = [T(cat="secrets", line=11), T(cat="secrets", line=12)]
    s = score([R(cat="secrets", line=11)], truth)
    assert s["overall"]["recall"] == 1.0 and s["overall"]["precision"] == 1.0 and s["overall"]["matching_findings"] == 1


def test_score_overall_by_category_and_explanations():
    truth = [T(cat="access", line=10, label="idor"), T(cat="injection", line=50, label="sqli"), T(app="c", cat="access", line=1, label="x")]
    rows = [R(cat="access", line=11), R(cat="deps", line=3, rule="old-dep"), R(app="clean", cat="web", line=9, rule="fp")]
    s = score(rows, truth[:2])
    assert s["overall"]["items_found"] == 1 and s["overall"]["items_missed"] == 1 and s["overall"]["false_positives"] == 2
    assert s["by_category"]["access"]["recall"] == 1.0 and s["by_category"]["injection"]["recall"] == 0.0
    assert s["by_category"]["deps"]["precision"] == 0.0 and s["by_category"]["secrets"]["recall"] is None
    assert any("injection" in m and "app.py:50" in m and "sqli" in m for m in s["misses"])
    assert any("old-dep" in f for f in s["false_positives"]) and any("fp" in f for f in s["false_positives"])


def test_every_finding_on_a_clean_app_is_a_false_positive():
    s = score([R(app="c01", cat="config")], [])
    assert s["overall"]["precision"] == 0.0 and s["overall"]["recall"] is None and len(s["false_positives"]) == 1


def test_duplicate_rows_count_once_and_empty_input():
    assert score([R(), R()], [T()])["overall"]["matching_findings"] == 1
    assert score([], [])["overall"]["f1"] is None


def test_union_dedupes_across_tools():
    cols = {"a": [R(tool="a"), R(line=20, tool="a")], "b": [R(tool="b"), R(cat="deps", tool="b")]}
    u = union_rows(cols)
    assert len(u) == 3 and {r.tool for r in u} == {"union"}


def test_accuracy_and_median():
    assert accuracy([(True, True), (True, False), (False, False), (False, True)]) == 0.5 and accuracy([]) is None
    assert median([3, 1, 2]) == 2 and median([1, 2, 3, 4]) == 2.5 and median([]) is None


def test_truth_loader_reads_the_committed_ground_truth():
    gt = json.loads((ROOT / "demo-apps/flask-corpus/ground_truth.json").read_text(encoding="utf-8"))
    truth = truth_from_json(gt)
    assert len(truth) == sum(len(v) for v in gt.values()) and all(t.line >= 1 and t.file for t in truth)
    assert {t.app for t in truth} <= set(gt) and not any(t.app.startswith("c") for t in truth)


# ============================================================================= the runner (a real, small, offline run)
@pytest.fixture(scope="module")
def small_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench") / "r.json"
    r = subprocess.run([sys.executable, str(ROOT / "bench/run_bench.py"), "--skip-network", "--apps", "c01_clean,v01_idor_read,v07_sqli,v09_hardcoded_keys",
                        "--out", str(out)], capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(out.read_text(encoding="utf-8")), r.stdout


def test_results_schema(small_run):
    res, stdout = small_run
    assert res["schema"] == "proofgate.bench/v1" and res["corpus"]["apps"] == 4 and res["corpus"]["ground_truth_items"] == 4
    assert {"bandit", "pip_audit", "semgrep", "betterleaks", "osv_scanner", "splinter", "union", "proofgate_fast", "proofgate_full"} <= set(res["tables"])
    assert res["environment"]["subset"] and res["environment"]["network"] is False
    assert "precision" in stdout and "proofgate_full" in stdout


def test_missing_tools_are_unavailable_never_numbers(small_run):
    res, _ = small_run
    for col in ("semgrep", "betterleaks", "osv_scanner", "splinter", "pip_audit"):
        t = res["tables"][col]
        assert t["available"] is False and t["reason"] and "overall" not in t, col


def test_measured_numbers_are_internally_consistent(small_run):
    res, _ = small_run
    full = res["tables"]["proofgate_full"]
    assert full["overall"]["recall"] == 1.0 and full["by_category"]["access"]["recall"] == 1.0  # v01 proven by the probe
    fast = res["tables"]["proofgate_fast"]
    assert fast["by_category"]["access"]["recall"] == 0.0  # the fast tier does not attack: access bugs need the probe
    assert res["tables"]["proofgate_full"]["overall"]["recall"] >= res["tables"]["union"]["overall"]["recall"]
    counts = res["counts"]["proofgate_full"]
    assert counts["raw"] >= counts["unique"] >= counts["proven"] >= 1
    assert res["proof_rate"]["recall"] is not None and res["proof_rate"]["proven_precision"] == 1.0


def test_latency_and_honesty_fields(small_run):
    res, _ = small_run
    lat = res["latency"]
    assert lat["runs_per_file"] == 50 and lat["inline_check_median_ms_per_file"] < 200 and lat["hook_fail_open_count"] == 0
    assert res["heldout"]["apps"] == 0 and "sealed" in res["heldout"]["note"]
    assert any("synthetic" in n for n in res["notes"]) and any("not tuned" in n for n in res["notes"])
    assert res["targets"]["raw_secrets_in_outputs"] == {"measured": 0, "target": 0, "met": True}
    assert res["fix_verification"] == {"note": "skipped for a subset run"}


def test_results_json_contains_no_secrets_or_canaries(small_run):
    from proofgate.redact import find_leaks

    assert find_leaks(json.dumps(small_run[0])) == []


# ============================================================================= the committed measurement
def test_committed_results_are_a_full_measured_run():
    path = ROOT / "bench" / "results.json"
    if not path.is_file():
        pytest.skip("bench/results.json not generated yet")
    res = json.loads(path.read_text(encoding="utf-8"))
    assert res["schema"] == "proofgate.bench/v1" and res["corpus"]["apps"] == 16 and res["environment"]["subset"] is None
    assert res["fix_verification"]["cases"] == 12 and res["generated_at"]
    for name, t in res["tables"].items():
        if t["available"]:
            assert t["overall"]["precision"] is None or 0 <= t["overall"]["precision"] <= 1, name
    assert res["targets"]["raw_secrets_in_outputs"]["measured"] == 0
