"""
NeuralBridge Test Configuration — Shared Fixtures.

Provides reusable pytest fixtures for adapter testing, API testing,
and compliance module testing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


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
