"""Which adapters does shipped code actually register? (red-team 2, L2)

An adapter can be real and tested and still unreachable: ``RestApiAdapter`` is documented as configurable from
YAML, but nothing in ``src/`` reads that config or calls ``registry.register`` for it. The README and
docs/integrations.md therefore say "Library only", not "Supported". These tests pin the fact both ways: if a
loader is added, the label has to be re-examined; if the label says wired, a loader has to exist.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _python_sources():
    return [p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts]


def test_nothing_shipped_instantiates_the_rest_adapter() -> None:
    offenders = [
        p.relative_to(ROOT).as_posix() for p in _python_sources()
        if p != SRC / "neuralbridge" / "adapters" / "apis" / "rest.py"
        and re.search(r"\bRestApiAdapter\b|adapters\.apis\.rest\b", p.read_text(encoding="utf-8"))
    ]
    assert offenders == [], (
        f"{offenders} now reference the REST adapter: if a loader registers it, add an end-to-end test through "
        "the raw adapters route and the MCP gateway and re-label README / docs/integrations.md (shipped_loader)."
    )


def test_the_only_shipped_registrations_are_postgres_ones() -> None:
    sites = {}
    for p in _python_sources():
        for m in re.finditer(r"^\s*registry\.register\(([^\n]*)", p.read_text(encoding="utf-8"), re.M):
            sites.setdefault(p.relative_to(ROOT).as_posix(), []).append(m.group(1))
    assert set(sites) == {"src/neuralbridge/ai/connections.py"}, sites
    assert all("PostgresAdapter" in s or s.startswith("candidate") for s in sites["src/neuralbridge/ai/connections.py"])


def test_shipped_loader_flag_matches_reality() -> None:
    from neuralbridge.adapters.apis.rest import RestApiAdapter
    from neuralbridge.adapters.base import BaseAdapter
    from neuralbridge.adapters.databases.postgres import PostgresAdapter

    assert BaseAdapter.shipped_loader is False
    assert PostgresAdapter.shipped_loader is True
    assert RestApiAdapter.shipped_loader is False


def test_a_default_deployment_has_no_rest_adapter(monkeypatch, tmp_path) -> None:
    from fastapi.testclient import TestClient

    import neuralbridge.api.dependencies as deps
    from neuralbridge.main import create_app

    monkeypatch.setenv("ASSURANCE_API_KEYS", "nb-wiring-operator-key-0123456789abcdef0123456789")
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "ai.db"))
    monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "audit.db"))
    for k in ("ASSURANCE_ALLOW_UNAUTHENTICATED",):
        monkeypatch.delenv(k, raising=False)
    from assurance.api import deps as adeps

    adeps._register_for.cache_clear()
    adeps._accounts_for.cache_clear()
    deps._adapter_registry = deps._request_router = deps._audit_logger = deps._ai_store = None
    with TestClient(create_app()) as client:
        r = client.get("/api/v1/adapters", headers={"X-API-Key": "nb-wiring-operator-key-0123456789abcdef0123456789"})
        assert r.status_code == 200
        assert "rest" not in {a["type"] for a in r.json()["adapters"]}
