import json
import re
import tomllib
from pathlib import Path

import yaml

import yaml
import proofgate

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = tomllib.loads((ROOT / "core" / "pyproject.toml").read_text(encoding="utf-8"))
SERVER = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
RELEASE = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")


def test_versions_and_names_match_across_pyproject_server_json_and_package():
    proj = PYPROJECT["project"]
    pkg = SERVER["packages"][0]
    assert proj["version"] == proofgate.__version__ == SERVER["version"] == pkg["version"]
    assert proj["name"] == pkg["identifier"] == "proofgate-ai"
    assert pkg["registryType"] == "pypi"
    assert SERVER["name"] == "io.github.Rudraksh-wq/proofgate"


def test_console_scripts_and_import_package_are_unchanged():
    assert set(PYPROJECT["project"]["scripts"]) == {"proofgate", "proofgate-mcp"}
    assert proofgate.__name__ == "proofgate"


def test_readme_carries_the_mcp_name_marker_for_the_registry():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "<!-- mcp-name: io.github.Rudraksh-wq/proofgate -->" in readme


def test_release_workflow_publishes_with_trusted_publishing_only():
    job = yaml.safe_load(RELEASE)["jobs"]["publish-pypi"]
    assert job["environment"] == "pypi"
    assert job["permissions"] == {"id-token": "write", "contents": "read"}
    assert "pypa/gh-action-pypi-publish@" in RELEASE
    for line in RELEASE.splitlines():
        m = re.search(r"uses:\s*(\S+)@(\S+)", line)
        if m:
            assert re.fullmatch(r"[0-9a-f]{40}", m.group(2)), f"action not pinned by commit SHA: {line.strip()}"
    low = RELEASE.lower()
    assert "password" not in low and "pypi_token" not in low and "pypi-api" not in low
    assert "login github-oidc" in RELEASE
    assert "refs/tags" in RELEASE or "tags:" in RELEASE  # only runs on a tag push; this repo never creates the tag
