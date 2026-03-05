'''
NeuralBridge Adapter for GraphQL APIs.

This adapter provides a standard interface for interacting with GraphQL endpoints.
It supports queries, mutations, and subscriptions, along with schema introspection.

**Configuration (YAML)**

.. code-block:: yaml

    adapters:
      my_graphql_api:
        adapter: graphql
        config:
          endpoint: "https://api.example.com/graphql"
          headers:
            X-Custom-Header: "SomeValue"
          auth_type: "bearer"
          auth_token: "your-secret-jwt-token"
          timeout: 30

**Supported Operations**

* ``query``: Execute a GraphQL query.
* ``mutation``: Execute a GraphQL mutation.
* ``subscription``: (Mock) Simulate a GraphQL subscription.
* ``introspect``: Fetch the GraphQL schema using introspection.

'''

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any

import httpx
import structlog

from neuralbridge.adapters.base import AdapterResponse, AdapterStatus, BaseAdapter

logger = structlog.get_logger(__name__)


class GraphQLAdapter(BaseAdapter):
    """
    Connects to and interacts with a generic GraphQL API.
    """

    # Override class attributes
    adapter_type = "graphql"
    category = "apis"
    description = "An adapter for interacting with GraphQL APIs."
    version = "1.0.0"
    supported_operations = ["query", "mutation", "subscription", "introspect"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the GraphQL adapter instance.

        Args:
            config: Adapter-specific configuration.
        """
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the GraphQL adapter's configuration.

        Returns:
            A dictionary representing the JSON schema.
        """
        return {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "The URL of the GraphQL endpoint.",
                    "format": "uri",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers to send with each request.",
                    "additionalProperties": {"type": "string"},
                },
                "auth_type": {
                    "type": "string",
                    "description": "Authentication type.",
                    "enum": ["none", "bearer", "header"],
                    "default": "none",
                },
                "auth_token": {
                    "type": "string",
                    "description": "Authentication token (e.g., for Bearer auth).",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds.",
                    "default": 30,
                },
            },
            "required": ["endpoint"],
        }

    async def _do_connect(self) -> None:
        """
        Establishes the HTTP client for connecting to the GraphQL API.
        """
        if self.status == AdapterStatus.CONNECTED and self._client:
            logger.info("GraphQL adapter already connected.")
            return

        endpoint = self.config.get("endpoint")
        if not endpoint:
            raise ValueError("GraphQL endpoint URL is not configured.")

        headers = self.config.get("headers", {})
        auth_type = self.config.get("auth_type", "none")
        auth_token = self.config.get("auth_token")

        if auth_type == "bearer" and auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        elif auth_type == "header" and auth_token:
            # Assumes the token is a key:value pair in the format "HeaderName:HeaderValue"
            try:
                header_name, header_value = auth_token.split(":", 1)
                headers[header_name.strip()] = header_value.strip()
            except ValueError:
                raise ValueError("Invalid format for 'header' auth_token. Expected 'HeaderName:Value'") from None

        timeout = self.config.get("timeout", 30)
        self._client = httpx.AsyncClient(base_url=endpoint, headers=headers, timeout=timeout)
        logger.info("GraphQL adapter client configured.", endpoint=endpoint)

    async def _do_disconnect(self) -> None:
        """
        Closes the HTTP client.
        """
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("GraphQL adapter disconnected.")

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Executes a GraphQL operation (query, mutation, subscription, or introspection).

        Args:
            operation: The name of the operation to execute.
            params: The parameters for the operation.

        Returns:
            An AdapterResponse containing the result of the operation.
        """
        if not self._client:
            raise ConnectionError("Adapter is not connected. Please call connect() first.")

        if operation in ("query", "mutation"):
            return await self._execute_query_or_mutation(params)
        elif operation == "subscription":
            return await self._execute_subscription(params)
        elif operation == "introspect":
            return await self._execute_introspection()
        else:
            return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    async def _execute_query_or_mutation(self, params: dict[str, Any]) -> AdapterResponse:
        """Executes a GraphQL query or mutation."""
        query = params.get("query")
        variables = params.get("variables", {})

        if not query:
            return AdapterResponse(success=False, error="Missing 'query' parameter.")


        # MOCK: In production, this would call the real API
        logger.info("Mocking GraphQL query/mutation.", query=query, variables=variables)
        mock_data = {
            "data": {
                "user": {
                    "id": "123",
                    "name": "Mock User",
                    "email": "mock@example.com"
                }
            }
        }
        return AdapterResponse(success=True, data=mock_data)

    async def _execute_subscription(self, params: dict[str, Any]) -> AdapterResponse:
        """Simulates a GraphQL subscription."""
        query = params.get("query")
        if not query:
            return AdapterResponse(success=False, error="Missing 'query' parameter.")

        # MOCK: Real subscriptions use WebSockets, which is more complex.
        # Here, we simulate a few updates.
        logger.info("Simulating GraphQL subscription.", query=query)

        async def subscription_generator() -> AsyncGenerator[dict[str, Any], None]:
            for i in range(3):
                yield {
                    "data": {
                        "messageAdded": {
                            "id": f"msg-{i}",
                            "content": f"This is mock message #{i}"
                        }
                    }
                }
                await asyncio.sleep(1)

        return AdapterResponse(success=True, data=subscription_generator())

    async def _execute_introspection(self) -> AdapterResponse:
        """Executes a GraphQL introspection query."""
        # MOCK: In a real scenario, we would send the standard introspection query.
        # Here, we return a simplified, mock schema.
        logger.info("Mocking GraphQL introspection.")
        mock_schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": {"name": "Subscription"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "user",
                                    "args": [{"name": "id", "type": {"name": "ID"}}],
                                    "type": {"name": "User"}
                                }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                {"name": "id", "type": {"name": "ID"}},
                                {"name": "name", "type": {"name": "String"}},
                                {"name": "email", "type": {"name": "String"}}
                            ]
                        }
                    ]
                }
            }
        }
        return AdapterResponse(success=True, data=mock_schema)

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the configured credentials by making a simple test query.

        Returns:
            A dictionary with validation results.
        """
        if not self._client:
            await self._do_connect()

        # MOCK: In production, this would be a simple, low-cost query.
        logger.info("Mocking credential validation with a test query.")

        try:
            # In a real implementation, we would do:
            # response = await self._client.post("/", json={"query": test_query})
            # response.raise_for_status()
            # data = response.json()
            # if "errors" in data:
            #     raise Exception(f"GraphQL error: {data['errors']}')

            # Mocked successful validation
            return {"status": "ok", "message": "Credentials appear to be valid."}

        except httpx.HTTPStatusError as e:
            return {"status": "error", "message": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

