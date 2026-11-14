"""The combined service preserves one account store across both public APIs."""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_one_cell_key_authenticates_on_both_api_surfaces(tmp_path, monkeypatch):
    accounts_path = tmp_path / "accounts.db"
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(accounts_path))
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "register.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "supplier-feeds"))
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)

    monkeypatch.setenv("NEURALBRIDGE_ENV", "development")
    monkeypatch.setenv("NEURALBRIDGE_DEBUG", "true")
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "ai.db"))
    monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("NEURALBRIDGE_AUDIT_BACKEND", "sqlite")
    monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_JOURNAL", str(tmp_path.parent / "custody" / "credential-journal.jsonl"))

    # Clear process-local singletons so the test cannot inherit a database path
    # or account cache from a different test.
    from assurance.api import deps as assurance_deps
    from assurance.billing.accounts import AccountStore

    assurance_deps._accounts_for.cache_clear()
    store = AccountStore(str(accounts_path))
    account = store.upsert_account(
        email="combined-service@example.invalid",
        tier="cell",
        company="Combined Service Test",
        status="active",
    )
    api_key = store.issue_key(account.id, label="combined-service-test")

    from assurance.api.service import create_app as create_assurance_app
    from neuralbridge.api import dependencies as platform_dependencies
    from neuralbridge.combined import create_app as create_combined_app
    from neuralbridge.config import get_settings
    from neuralbridge.main import create_app as create_platform_app

    platform_dependencies._audit_logger = None
    platform_dependencies._ai_store = None
    platform_dependencies._adapter_registry = None
    platform_dependencies._request_router = None

    assurance_app = create_assurance_app()
    platform_app = create_platform_app(get_settings())
    combined_app = create_combined_app(
        assurance_app=assurance_app,
        platform_app=platform_app,
    )

    with TestClient(combined_app) as client:
        # The /ai surface resolves the same Cell account record.
        platform = client.get(
            "/api/v1/ai/session",
            headers={"X-API-Key": api_key},
        )
        assert platform.status_code == 200, platform.text
        assert platform.json()["tier"] == "cell"

        # The Assurance machine/case surface accepts that very same key.
        assurance = client.get(
            "/v1/change/cases",
            headers={"X-API-Key": api_key},
        )
        assert assurance.status_code == 200, assurance.text
        assert "cases" in assurance.json()

        # Both service health paths are routed to their intended application.
        assert client.get("/livez").status_code == 200
        assert client.get("/api/v1/health/live").status_code == 200
