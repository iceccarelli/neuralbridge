
"""
NeuralBridge Adapter: REST API (Generic)

Description:
------------
This adapter provides a universal interface for interacting with any RESTful API.
It leverages the ``httpx`` library for asynchronous HTTP requests, ensuring
non-blocking I/O for high-performance integrations.

Supported Operations:
---------------------
- get: Perform an HTTP GET request to a specified endpoint.
- post: Perform an HTTP POST request with a JSON payload.
- put: Perform an HTTP PUT request with a JSON payload.
- patch: Perform an HTTP PATCH request with a JSON payload.
- delete: Perform an HTTP DELETE request to a specified endpoint.
- head: Perform an HTTP HEAD request to a specified endpoint.

Configuration (YAML):
---------------------
.. code-block:: yaml

    adapters:
      - name: my_rest_api
        type: rest
        config:
          base_url: "https://api.example.com/v1"
          headers:
            User-Agent: "NeuralBridge-Client/1.0"
            Accept: "application/json"
          auth_type: "bearer"  # Or "none", "basic"
          timeout: 30
          verify_ssl: true
          retry_count: 3

"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import structlog

from neuralbridge.adapters.base import BaseAdapter

logger = structlog.get_logger(__name__)


class RestApiAdapter(BaseAdapter):
    """A universal adapter for any RESTful API."""

    # ---
    # Subclass attributes
    # ---
    adapter_type: str = "rest"
    category: str = "apis"
    description: str = "A universal adapter for interacting with any RESTful API."
    version: str = "0.1.0"
    supported_operations: list[str] = [
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the REST API adapter."""
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    # ---
    # Abstract method implementations
    # ---

    async def _do_connect(self) -> None:
        """
        Establish the underlying httpx.AsyncClient session.

        This method configures and creates an asynchronous HTTP client based on the
        adapter's configuration. It handles setting the base URL, headers,
        authentication, and other client-side settings.
        """
        if self._client and not self._client.is_closed:
            logger.info("httpx_client_already_connected", adapter=self.adapter_type)
            return

        base_url = self.config.get("base_url", "")
        headers = self.config.get("headers", {})
        timeout = self.config.get("timeout", 30.0)
        verify_ssl = self.config.get("verify_ssl", True)
        auth_type = self.config.get("auth_type", "none")

        # MOCK: In production, this would handle real authentication secrets
        if auth_type == "bearer":
            # Example: headers["Authorization"] = f"Bearer {self.credentials['token']}"
            headers["Authorization"] = "Bearer MOCK_TOKEN"
        elif auth_type == "basic":
            # Example: auth = (self.credentials['username'], self.credentials['password'])
            pass  # httpx handles basic auth via the `auth` parameter

        transport = httpx.AsyncHTTPTransport(
            retries=self.config.get("retry_count", 3)
        )

        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            transport=transport,
        )
        logger.info("httpx_client_created", base_url=base_url, adapter=self.adapter_type)

    async def _do_disconnect(self) -> None:
        """Tear down the underlying httpx.AsyncClient session."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            logger.info("httpx_client_disconnected", adapter=self.adapter_type)
        self._client = None

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Verify credentials by making a HEAD request to the base URL.

        This provides a lightweight way to check if the API is reachable and if
        the provided authentication (if any) is accepted.
        """
        if not self._client:
            raise ConnectionError("Adapter is not connected. Cannot validate credentials.")

        try:
            # MOCK: In production, this would call the real API endpoint.
            logger.info("validating_credentials_mock", adapter=self.adapter_type)
            await asyncio.sleep(0.1) # Simulate network latency
            # response = await self._client.head("/")
            # response.raise_for_status() # Raise an exception for 4xx/5xx responses
            return {"status": "ok", "message": "Mock validation successful."}

        except httpx.RequestError as exc:
            logger.error("credential_validation_failed", error=str(exc))
            raise ConnectionError(f"API connection failed: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            logger.error("credential_validation_failed_status", status_code=exc.response.status_code)
            raise ValueError(f"Invalid credentials or endpoint: {exc}") from exc

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> Any:
        """
        Perform the requested HTTP operation.

        This method dispatches the operation to the corresponding httpx request method.
        It handles passing parameters, endpoint paths, and request bodies.
        """
        if not self._client:
            raise ConnectionError("HTTP client is not initialized. Please connect first.")

        endpoint = params.get("endpoint")
        if not endpoint:
            raise ValueError("Missing required parameter: endpoint")

        query_params = params.get("query_params")
        json_body = params.get("json_body")

        try:
            # MOCK: In production, these would call the real API.
            logger.info("executing_mock_request", operation=operation, endpoint=endpoint)
            await asyncio.sleep(0.2) # Simulate network latency

            if operation == "get":
                # response = await self._client.get(endpoint, params=query_params)
                return {"mock_data": f"GET result for {endpoint}", "params": query_params}

            elif operation == "post":
                # response = await self._client.post(endpoint, json=json_body, params=query_params)
                return {"mock_data": f"POST result for {endpoint}", "received_body": json_body}

            elif operation == "put":
                # response = await self._client.put(endpoint, json=json_body, params=query_params)
                return {"mock_data": f"PUT result for {endpoint}", "received_body": json_body}

            elif operation == "patch":
                # response = await self._client.patch(endpoint, json=json_body, params=query_params)
                return {"mock_data": f"PATCH result for {endpoint}", "received_body": json_body}

            elif operation == "delete":
                # response = await self._client.delete(endpoint, params=query_params)
                return {"mock_data": f"DELETE result for {endpoint}", "status": "success"}

            elif operation == "head":
                # response = await self._client.head(endpoint, params=query_params)
                return {"status_code": 200, "headers": {"Content-Type": "application/json"}}

            else:
                # This case should ideally not be reached due to the check in BaseAdapter
                raise ValueError(f"Unsupported operation: {operation}")

            # In a real implementation, you would process the response:
            # response.raise_for_status()
            # return response.json() or response.text

        except httpx.RequestError as exc:
            logger.error("rest_operation_failed", operation=operation, error=str(exc))
            raise ConnectionError(f"Request to {exc.request.url} failed: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            logger.error(
                "rest_operation_http_error",
                operation=operation,
                status_code=exc.response.status_code,
                response_text=exc.response.text,
            )
            raise OSError(
                f"HTTP error {exc.response.status_code} for {exc.request.url}: {exc.response.text}"
            ) from exc

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Return the JSON Schema for the REST adapter's configuration.
        """
        return {
            "type": "object",
            "properties": {
                "base_url": {
                    "type": "string",
                    "description": "The base URL for the API (e.g., https://api.example.com/v1).",
                    "format": "uri",
                },
                "headers": {
                    "type": "object",
                    "description": "A dictionary of HTTP headers to send with every request.",
                    "additionalProperties": {"type": "string"},
                },
                "auth_type": {
                    "type": "string",
                    "description": "Authentication method to use.",
                    "enum": ["none", "bearer", "basic"],
                    "default": "none",
                },
                "timeout": {
                    "type": "number",
                    "description": "Request timeout in seconds.",
                    "default": 30,
                    "minimum": 1,
                },
                "verify_ssl": {
                    "type": "boolean",
                    "description": "Whether to verify the server's SSL certificate.",
                    "default": True,
                },
                "retry_count": {
                    "type": "integer",
                    "description": "Number of times to retry a failed request.",
                    "default": 3,
                    "minimum": 0,
                },
            },
            "required": ["base_url"],
        }

