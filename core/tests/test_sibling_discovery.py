from pathlib import Path

from proofgate.probe.discover import sibling_routes


ROOT = Path(__file__).resolve().parents[2]
FB01 = ROOT / "demo-apps" / "fix-breaker" / "fb01_method"


def test_fb01_sibling_routes_include_aliases_and_export():
    siblings = sibling_routes(FB01, "/api/notes/<int:id>")

    assert "/api/notes/<int:id>/export" in siblings
    assert "/api/v1/notes/<int:id>" in siblings
    assert "/api/v1/notes/<int:id>/export" in siblings
    assert "/api/notes/<int:id>" not in siblings


def test_sibling_routes_never_raise():
    assert sibling_routes(ROOT / "demo-apps" / "missing", "/api/notes/<int:id>") == []
