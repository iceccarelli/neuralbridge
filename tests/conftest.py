"""
NeuralBridge Test Configuration — Shared Fixtures.

Provides reusable pytest fixtures for adapter testing, API testing,
and compliance module testing.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

# NEURALBRIDGE_REQUIRE_POSTGRES: a Postgres skip becomes a failure (see the module).
from .require_postgres_plugin import pytest_runtest_makereport  # noqa: F401


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def _isolated_audit_sink(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """The platform audit trail is a durable SQLite file by default; keep every test's
    file in its own tmp dir (never the working directory) and drop the process-wide
    logger so the next test builds its own. Tests of the default path / backend
    selection ``monkeypatch.delenv`` these."""
    if not os.environ.get("NEURALBRIDGE_AUDIT_DB"):
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "audit-default.db"))
    import neuralbridge.api.dependencies as deps

    deps._audit_logger = None
    yield
    deps._audit_logger = None


@pytest.fixture(autouse=True)
def _credential_custody(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Bound /ai connections need a credential key AND an anti-rollback journal kept outside the
    store's directory, or binding fails closed (neuralbridge.ai.credentials). Give every test its
    own throwaway key and journal; tests of the unconfigured / misconfigured paths ``delenv`` them.
    The journal sits in a SIBLING of ``tmp_path`` because it may not live inside the store's directory."""
    import base64

    if not os.environ.get("NEURALBRIDGE_CREDENTIAL_KEYS") and not os.environ.get("NEURALBRIDGE_CREDENTIAL_KEY_FILE"):
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", "test-key-1:" + base64.b64encode(os.urandom(32)).decode())
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY", raising=False)
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_JOURNAL", str(tmp_path.parent / f"{tmp_path.name}-custody" / "journal.jsonl"))
    yield


@pytest.fixture
def api_client() -> TestClient:
    """Create a FastAPI test client."""
    from neuralbridge.main import app
    return TestClient(app)


@pytest.fixture
def sample_adapter_config() -> dict:
    """Return a sample adapter configuration for testing."""
    return {
        "type": "postgres",
        "host": "localhost",
        "port": 5432,
        "database": "test_db",
        "username": "test_user",
        "password": "test_password",
    }


@pytest.fixture
def sample_connection_payload() -> dict:
    """Return a sample connection creation payload."""
    return {
        "name": "Test Connection",
        "description": "A test connection for unit testing.",
        "adapter_type": "postgres",
        "config": {"host": "localhost", "port": 5432, "database": "test_db"},
        "auth": {"type": "basic", "username": "test", "password": "secret"},
        "permissions": ["query", "execute"],
        "rate_limit": "100/minute",
        "enabled": True,
    }
