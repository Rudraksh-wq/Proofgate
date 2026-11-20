import pytest

from proofgate.models import Finding
from proofgate.normalize import normalize, tool_family


def mk(rule="r", file="app.py", line=10, layer=2, cwe="CWE-89", category="injection", severity="high", sources=("semgrep",),
       fp=None, proven=False, confidence=None, evidence=None, fixed_in=None):
    data = {
        "id": f"f_{abs(hash((rule, file, line, sources))) % 10**8:08d}", "fingerprint": fp, "layer": layer,
        "category": category, "rule": rule, "cwe": cwe, "severity": severity, "title": f"{rule} at {line}",
        "plain_words": "p", "location": {"file": file, "line": line}, "sources": list(sources), "proven": proven,
        "confidence": confidence or ("proven" if proven else "high"), "evidence": evidence, "fixed_in": fixed_in,
    }
    return Finding.model_validate(data)


def test_counts_raw_unique_proven():
    raw = [mk(fp="a", line=1), mk(fp="a", line=1, sources=("bandit",)), mk(fp="b", file="b.py", proven=True, sources=("proofgate-probe",), layer=8),
           mk(fp="c", file="c.py")]
    n = normalize(raw)
    assert (n.raw_warning_count, n.unique_count, n.proven_count) == (4, 3, 1)


def test_same_fingerprint_merges_sources_and_counts_tools():
    n = normalize([mk(fp="x", sources=("semgrep",)), mk(fp="x", sources=("bandit",)), mk(fp="x", sources=("proofgate-inline",))])
    (f,) = n.findings
    assert f.sources == ["bandit", "proofgate-inline", "semgrep"] and f.confirmed_by == 3


def test_fallback_key_merges_two_tools_on_nearby_lines_same_weakness():
    sem = mk(rule="proofgate.py-sql-injection", line=10, cwe="CWE-89", sources=("proofgate-rule:py-sql-injection",))
    ban = mk(rule="bandit-B608", line=12, cwe="CWE-89", sources=("bandit",))
    (f,) = normalize([ban, sem]).findings
    assert f.confirmed_by == 2 and set(f.sources) == {"bandit", "proofgate-rule:py-sql-injection"}


def test_line_window_is_two():
    a, b = mk(line=10, sources=("semgrep",)), mk(line=13, sources=("bandit",))
    assert normalize([a, b]).unique_count == 2
    assert normalize([a, mk(line=12, sources=("bandit",))]).unique_count == 1


def test_different_cwe_or_file_never_merge():
    assert normalize([mk(cwe="CWE-89"), mk(cwe="CWE-78", sources=("bandit",))]).unique_count == 2
    assert normalize([mk(file="a.py"), mk(file="b.py", sources=("bandit",))]).unique_count == 2


def test_cwe_families_merge_hardcoded_credentials_across_tools():
    stripe = mk(layer=1, category="secrets", cwe="CWE-798", sources=("proofgate-builtin",), rule="stripe-live-secret-key", line=11)
    bandit = mk(layer=2, category="secrets", cwe="CWE-259", sources=("bandit",), rule="bandit-B105", line=11, severity="low")
    (f,) = normalize([bandit, stripe]).findings
    assert f.rule == "stripe-live-secret-key" and set(f.sources) == {"bandit", "proofgate-builtin"}


def test_two_different_secrets_on_adjacent_lines_stay_separate():
    stripe = mk(layer=1, category="secrets", cwe="CWE-798", sources=("proofgate-builtin",), rule="stripe-live-secret-key", line=11, fp="s1")
    jwt = mk(layer=1, category="secrets", cwe="CWE-798", sources=("proofgate-jwt",), rule="supabase-service-role-key", line=12, fp="s2")
    bandit = mk(layer=2, category="secrets", cwe="CWE-259", sources=("bandit",), rule="bandit-B105", line=11, fp="s3", severity="low")
    n = normalize([stripe, jwt, bandit])
    assert n.unique_count == 2  # same tool family (secrets scanner) never merges with itself via the fallback key
    assert sorted(f.rule for f in n.findings) == ["stripe-live-secret-key", "supabase-service-role-key"]


def test_same_tool_two_issues_never_merge_by_fallback():
    assert normalize([mk(fp="a", line=10), mk(fp="b", line=11)]).unique_count == 2


def test_category_fallback_when_cwe_missing():
    a = mk(cwe=None, category="config", sources=("semgrep",), line=1)
    b = mk(cwe=None, category="config", sources=("bandit",), line=2)
    assert normalize([a, b]).unique_count == 1
    assert normalize([a, mk(cwe=None, category="web", sources=("bandit",), line=2)]).unique_count == 2


def test_merged_finding_takes_max_severity_best_confidence_and_proof():
    low = mk(fp="x", severity="medium", sources=("bandit",), confidence="medium", fixed_in="2.0")
    high = mk(fp="x", severity="high", sources=("semgrep",), confidence="high")
    (f,) = normalize([low, high]).findings
    assert (f.severity, f.confidence, f.fixed_in) == ("high", "high", "2.0")

    proven = mk(fp="x", layer=8, severity="critical", proven=True, sources=("proofgate-probe",),
                evidence={"request": "GET /n/1 as B", "status": 200, "response_excerpt": "..PGCANARY_A_«masked».."})
    (g,) = normalize([low, proven]).findings
    assert g.proven and g.confidence == "proven" and g.evidence is not None and g.severity == "critical"


def test_ranking_proven_then_multi_tool_then_single():
    single = mk(fp="s", file="a.py", severity="critical", sources=("semgrep",), layer=2)
    multi = mk(fp="m", file="b.py", severity="medium", sources=("semgrep",))
    multi2 = mk(fp="m", file="b.py", severity="medium", sources=("bandit",))
    proven = mk(fp="p", file="c.py", severity="low", proven=True, sources=("proofgate-probe",), layer=8)
    order = [f.location.file for f in normalize([single, multi, multi2, proven]).findings]
    assert order == ["c.py", "b.py", "a.py"]


def test_only_proven_or_critical_interrupt_the_human():
    n = normalize([mk(fp="a", file="a.py", severity="critical"), mk(fp="b", file="b.py", severity="high"),
                   mk(fp="c", file="c.py", severity="low", proven=True, sources=("proofgate-probe",), layer=8)])
    got = {f.location.file: f.interrupt_human for f in n.findings}
    assert got == {"a.py": True, "b.py": False, "c.py": True}


def test_findings_without_fingerprint_are_kept():
    n = normalize([mk(fp=None, line=1), mk(fp=None, line=50, sources=("bandit",))])
    assert n.unique_count == 2


def test_empty_input():
    n = normalize([])
    assert (n.findings, n.raw_warning_count, n.unique_count, n.proven_count) == ([], 0, 0, 0)


def test_input_is_not_mutated():
    a, b = mk(fp="x"), mk(fp="x", sources=("bandit",))
    normalize([a, b])
    assert a.sources == ["semgrep"] and b.sources == ["bandit"]


@pytest.mark.parametrize("src,fam", [("proofgate-rule:py-sql-injection", "semgrep"), ("proofgate-inline", "semgrep"),
                                      ("betterleaks", "secrets-scanner"), ("something-new", "something-new")])
def test_tool_family(src, fam):
    assert tool_family(src) == fam
