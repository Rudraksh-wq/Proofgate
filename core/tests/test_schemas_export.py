import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_script():
    spec = importlib.util.spec_from_file_location("export_schemas", ROOT / "scripts" / "export_schemas.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_schemas_are_up_to_date():
    assert _load_script().main(["--check"]) == 0


def test_schema_files_are_valid_json_with_schema_key():
    for name in ("finding", "contract", "fixresult", "report", "accepted"):
        data = json.loads((ROOT / "schemas" / f"{name}.v1.json").read_text(encoding="utf-8"))
        assert "schema" in data["properties"], name
