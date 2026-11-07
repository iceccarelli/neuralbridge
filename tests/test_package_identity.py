"""Package, chart and dashboard metadata must describe the product the README and site describe.

pyproject.toml still advertised "Universal Enterprise Middleware ... ANY AI agent to ANY system ...
zero-trust security", while README.md (Current Supported Scope) says zero-trust and "any system" are
not promised. Package metadata is the first thing a registry or an AI crawler reads, so it is held to
the same rule as the pricing page: if it is not enforced in code it is not claimed.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

# Claims the README explicitly says are not part of the promise (or that are certification claims).
RETIRED = ("universal enterprise middleware", "any ai agent", "any system", "zero-trust", "cra compliance")
SURFACES = {
    "pyproject description": PYPROJECT["description"],
    "pyproject keywords": " ".join(PYPROJECT["keywords"]),
    "neuralbridge/__init__": (ROOT / "src/neuralbridge/__init__.py").read_text(encoding="utf-8"),
    "helm chart": (ROOT / "deploy/helm/Chart.yaml").read_text(encoding="utf-8"),
    "site layout": (ROOT / "app/layout.tsx").read_text(encoding="utf-8"),
}


def test_no_retired_claims_in_package_metadata():
    hits = [(name, phrase) for name, text in SURFACES.items() for phrase in RETIRED if phrase in text.lower().replace("cra-compliance", "cra compliance")]
    assert not hits, hits


def test_description_names_the_product_and_disclaims_certification():
    d = PYPROJECT["description"]
    assert d.startswith("Industrial Autonomous Assurance")
    assert "not a certification" in d


def test_runtime_version_matches_the_distribution_version():
    import re

    init = (ROOT / "src/neuralbridge/__init__.py").read_text(encoding="utf-8")
    assert re.search(rf'__version__ = "{re.escape(PYPROJECT["version"])}"', init)


def test_assurance_api_mcp_and_exported_contract_share_the_distribution_version():
    import json

    import assurance
    from assurance.api.service import create_app
    from assurance.mcp.server import mcp

    assert assurance.__version__ == PYPROJECT["version"]
    app = create_app()
    assert app.version == PYPROJECT["version"] and app.title == "Industrial Autonomous Assurance API"
    assert mcp.version == PYPROJECT["version"]
    info = json.loads((ROOT / "public" / "openapi.json").read_text(encoding="utf-8"))["info"]
    assert info["version"] == PYPROJECT["version"] and info["title"] == app.title
