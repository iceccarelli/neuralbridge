"""
Tests for NeuralBridge Adapter Framework.

Verifies that adapters can be instantiated, connected, executed,
and disconnected correctly.  Uses mock implementations.
"""

from __future__ import annotations

import pytest


def _flagged_canned(result) -> bool:
    """A canned result must say so (AdapterResponse.metadata["mock"]), wherever the adapter put it."""
    if isinstance(result, dict):
        return result.get("mock") is True or (result.get("metadata") or {}).get("mock") is True
    return (getattr(result, "metadata", None) or {}).get("mock") is True


class TestBaseAdapter:
    """Tests for the abstract BaseAdapter contract."""

    def test_import_base_adapter(self):
        from neuralbridge.adapters.base import BaseAdapter
        assert BaseAdapter is not None

    def test_base_adapter_has_required_methods(self):
        from neuralbridge.adapters.base import BaseAdapter
        assert hasattr(BaseAdapter, "connect")
        assert hasattr(BaseAdapter, "disconnect")
        assert hasattr(BaseAdapter, "execute")
        assert hasattr(BaseAdapter, "validate_credentials")


class TestPostgresAdapter:
    """Tests for the PostgreSQL adapter (import and instantiation only, no live DB)."""

    def test_import(self):
        from neuralbridge.adapters.databases.postgres import PostgresAdapter
        assert PostgresAdapter is not None

    def test_instantiation(self):
        from neuralbridge.adapters.databases.postgres import PostgresAdapter
        adapter = PostgresAdapter(config={"host": "localhost", "port": 5432})
        assert adapter.adapter_type == "postgres"
        assert "query" in adapter.supported_operations

    @pytest.mark.asyncio
    async def test_connect_fails_without_db(self):
        """Connecting without a real DB returns a failed AdapterResponse."""
        from neuralbridge.adapters.databases.postgres import PostgresAdapter
        adapter = PostgresAdapter(config={"host": "localhost"})
        result = await adapter.connect()
        assert result.success is False


class TestSalesforceAdapter:
    """Tests for the Salesforce CRM adapter (mocked)."""

    def test_import(self):
        from neuralbridge.adapters.erp_crm.salesforce import SalesforceAdapter
        assert SalesforceAdapter is not None

    def test_instantiation(self):
        from neuralbridge.adapters.erp_crm.salesforce import SalesforceAdapter
        adapter = SalesforceAdapter(config={"instance_url": "https://test.salesforce.com"})
        assert adapter.adapter_type == "salesforce"

    @pytest.mark.asyncio
    async def test_soql_query(self):
        from neuralbridge.adapters.erp_crm.salesforce import SalesforceAdapter
        adapter = SalesforceAdapter(config={"allow_mock": True})  # canned: no Salesforce call is made
        await adapter.connect()
        result = await adapter.execute("query", {"soql": "SELECT Id FROM Account"})
        assert result is not None
        assert _flagged_canned(result)
        await adapter.disconnect()


class TestSlackAdapter:
    """Tests for the Slack messaging adapter."""

    def test_import(self):
        from neuralbridge.adapters.messaging.slack import SlackAdapter
        assert SlackAdapter is not None

    @pytest.mark.asyncio
    async def test_send_message(self):
        from neuralbridge.adapters.messaging.slack import SlackAdapter
        adapter = SlackAdapter(config={"bot_token": "xoxb-test", "allow_mock": True})  # canned: nothing is sent
        await adapter.connect()
        result = await adapter.execute("send_message", {
            "channel": "#general",
            "text": "Hello from NeuralBridge!"
        })
        assert result is not None
        assert _flagged_canned(result)
        await adapter.disconnect()


class TestRESTAdapter:
    """Tests for the generic REST API adapter."""

    def test_import(self):
        from neuralbridge.adapters.apis.rest import RestApiAdapter
        assert RestApiAdapter is not None

    @pytest.mark.asyncio
    async def test_get_request(self):
        from neuralbridge.adapters.apis.rest import RestApiAdapter
        adapter = RestApiAdapter(config={"base_url": "https://api.example.com", "allow_mock": True})  # canned: no request
        await adapter.connect()
        result = await adapter.execute("get", {"endpoint": "/users"})
        assert result is not None
        assert _flagged_canned(result)
        await adapter.disconnect()


class TestAdapterRegistry:
    """Tests for the adapter registry."""

    def test_registry_import(self):
        from neuralbridge.core.router import AdapterRegistry
        assert AdapterRegistry is not None

    def test_register_and_get(self):
        from neuralbridge.adapters.databases.postgres import PostgresAdapter
        from neuralbridge.core.router import AdapterRegistry

        registry = AdapterRegistry()
        adapter = PostgresAdapter(config={})
        registry.register(adapter)
        assert registry.get("postgres") is adapter

    def test_list_all(self):
        from neuralbridge.adapters.databases.postgres import PostgresAdapter
        from neuralbridge.core.router import AdapterRegistry

        registry = AdapterRegistry()
        registry.register(PostgresAdapter(config={}))
        assert "postgres" in registry.list_all()
