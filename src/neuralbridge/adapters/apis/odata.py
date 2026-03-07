'''
NeuralBridge Adapter for OData APIs (V4).

This adapter provides a standardized interface for interacting with OData v4 services,
which are common in enterprise environments, particularly with SAP and Microsoft products.
It supports querying, creating, updating, and deleting entities, as well as fetching
service metadata.

Configuration
-------------

The adapter is configured via a YAML file with the following structure:

.. code-block:: yaml

    service_url: "https://services.odata.org/V4/TripPinServiceRW/"
    auth_type: "none"  # or "bearer", "basic"
    auth_token: "your-secret-token"  # if auth_type is "bearer"
    api_version: "v4" # Currently, only v4 is supported

Supported Operations
--------------------
- **query**: Execute an OData query (e.g., GET /Users?$filter=FirstName eq 'Scott').
- **create**: Create a new entity (e.g., POST /Users).
- **update**: Update an existing entity (e.g., PATCH /Users('scott')).
- **delete**: Delete an entity (e.g., DELETE /Users('scott')).
- **get_metadata**: Retrieve the service's $metadata document.

'''
from __future__ import annotations

import asyncio
from typing import Any

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter


class ODataAdapter(BaseAdapter):
    """Connects to and interacts with an OData v4 API."""

    # --- Adapter Metadata --- #
    adapter_type: str = "odata"
    category: str = "apis"
    description: str = "Adapter for OData v4 APIs."
    version: str = "0.1.0"
    supported_operations: list[str] = [
        "query",
        "create",
        "update",
        "delete",
        "get_metadata",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the OData adapter.

        Args:
            config: Adapter configuration dictionary.
        """
        super().__init__(config)
        self.service_url = self.config.get("service_url")
        self.auth_type = self.config.get("auth_type", "none")
        self.auth_token = self.config.get("auth_token")
        self.api_version = self.config.get("api_version", "v4")

    # --- Abstract Method Implementations --- #

    async def _do_connect(self) -> None:
        """
        Establishes a connection to the OData service.

        For this mock adapter, this method simply validates that the
        service_url is configured.
        """
        if not self.service_url:
            raise ConnectionError("OData service_url is not configured.")
        # MOCK: In production, this would establish a session, perhaps using
        # a library like httpx.AsyncClient to manage connections and headers.
        await asyncio.sleep(0.05)  # Simulate network latency

    async def _do_disconnect(self) -> None:
        """
        Tears down the connection to the OData service.

        In this mock implementation, this is a no-op.
        """
        # MOCK: In a real implementation, this would close the client session.
        await asyncio.sleep(0.01)

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Executes a supported operation on the OData service.

        Args:
            operation: The name of the operation to execute.
            params: A dictionary of parameters for the operation.

        Returns:
            An AdapterResponse containing the result of the operation.
        """
        if operation == "query":
            return await self._execute_query(params)
        elif operation == "create":
            return await self._execute_create(params)
        elif operation == "update":
            return await self._execute_update(params)
        elif operation == "delete":
            return await self._execute_delete(params)
        elif operation == "get_metadata":
            return await self._execute_get_metadata()
        else:
            return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the configured credentials by making a simple metadata request.

        Returns:
            A dictionary with validation status and details.
        """
        # MOCK: This simulates a request to the metadata endpoint to check credentials.
        if self.auth_type != "none" and not self.auth_token:
            raise ValueError("auth_token is required for the selected auth_type.")

        try:
            # Simulate a quick check to the service
            await asyncio.sleep(0.1)
            return {"status": "validated", "message": "Successfully connected to the OData service."}
        except Exception as e:
            return {"status": "invalid", "message": f"Credential validation failed: {e}"}

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the OData adapter's configuration.

        Returns:
            A dictionary representing the JSON schema.
        """
        return {
            "type": "object",
            "properties": {
                "service_url": {
                    "type": "string",
                    "description": "The base URL of the OData v4 service.",
                },
                "auth_type": {
                    "type": "string",
                    "enum": ["none", "bearer", "basic"],
                    "default": "none",
                },
                "auth_token": {
                    "type": "string",
                    "description": "Authentication token (e.g., for bearer auth).",
                },
                "api_version": {
                    "type": "string",
                    "enum": ["v4"],
                    "default": "v4",
                },
            },
            "required": ["service_url"],
        }

    # --- Operation-Specific Implementations --- #

    async def _execute_query(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK implementation for an OData query operation."""
        entity_set = params.get("entity_set")
        if not entity_set:
            return AdapterResponse(success=False, error="'entity_set' parameter is required for query.")

        # MOCK: In production, this would use a library like `httpx` to make a GET request
        # to `{self.service_url}/{entity_set}` with OData query options.
        await asyncio.sleep(0.2)  # Simulate network request

        mock_data = {
            "@odata.context": f"{self.service_url}/$metadata#{entity_set}",
            "value": [
                {"UserName": "russellwhyte", "FirstName": "Russell", "LastName": "Whyte"},
                {"UserName": "scottkey", "FirstName": "Scott", "LastName": "Key"},
            ],
        }
        return AdapterResponse(success=True, data=mock_data)

    async def _execute_create(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK implementation for an OData create operation."""
        entity_set = params.get("entity_set")
        data = params.get("data")
        if not entity_set or not data:
            return AdapterResponse(success=False, error="'entity_set' and 'data' parameters are required.")

        # MOCK: In production, this would be a POST to `{self.service_url}/{entity_set}`.
        await asyncio.sleep(0.15)
        new_entity = {**data, "UserName": "newuser"}
        return AdapterResponse(success=True, data=new_entity, metadata={"status_code": 201})

    async def _execute_update(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK implementation for an OData update operation."""
        entity_key = params.get("entity_key")
        data = params.get("data")
        if not entity_key or not data:
            return AdapterResponse(success=False, error="'entity_key' and 'data' parameters are required.")

        # MOCK: In production, this would be a PATCH to `{self.service_url}/{entity_key}`.
        await asyncio.sleep(0.15)
        return AdapterResponse(success=True, data={"status": "updated"}, metadata={"status_code": 204})

    async def _execute_delete(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK implementation for an OData delete operation."""
        entity_key = params.get("entity_key")
        if not entity_key:
            return AdapterResponse(success=False, error="'entity_key' parameter is required.")

        # MOCK: In production, this would be a DELETE to `{self.service_url}/{entity_key}`.
        await asyncio.sleep(0.1)
        return AdapterResponse(success=True, data={"status": "deleted"}, metadata={"status_code": 204})

    async def _execute_get_metadata(self) -> AdapterResponse:
        """MOCK implementation for fetching OData service metadata."""
        # MOCK: In production, this would be a GET to `{self.service_url}/$metadata`.
        await asyncio.sleep(0.1)
        mock_metadata = """<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:DataServices>
    <Schema Namespace="Microsoft.OData.Service.Sample.Trippin.Models" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityType Name="Person" />
      <EntityType Name="Airline" />
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"""
        return AdapterResponse(success=True, data=mock_metadata, metadata={"content_type": "application/xml"})


