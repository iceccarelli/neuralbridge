"""

NeuralBridge Custom Adapter Template

This module serves as a comprehensive template for creating new, custom adapters
within the NeuralBridge ecosystem. It provides a clear, well-documented starting
point for integrating any external service, API, or database that is not already
supported out-of-the-box.

**Tutorial: Creating Your Own Adapter**

1.  **Copy this File**:
    Duplicate this file (`adapter_template.py`) and rename it to reflect the
    service you are integrating (e.g., `my_crm.py`). Place it in an appropriate
    subdirectory within `src/neuralbridge/adapters/` (e.g., `custom/` or `apis/`).

2.  **Rename the Class**:
    Change the class name from `CustomAdapterTemplate` to something descriptive,
    like `MyCrmAdapter`.

3.  **Update Class Attributes**:
    Modify the following class attributes to describe your adapter:
    - `adapter_type`: A unique, lowercase, snake_cased identifier (e.g., `"my_crm"`).
    - `category`: The type of service (e.g., `"crm"`, `"database"`, `"messaging"`).
    - `description`: A brief, one-sentence summary of the adapter's purpose.
    - `supported_operations`: A list of string names for the actions your adapter
      can perform (e.g., `["get_contact", "create_lead"]`).

4.  **Define Configuration Schema**:
    Implement the `_get_config_schema` method. This method returns a JSON Schema
    dictionary that defines the configuration parameters your adapter needs.
    This schema is used to validate the YAML configuration and to generate UI
    forms in the NeuralBridge dashboard.

5.  **Implement Connection Logic**:
    - `_do_connect`: Write the code to establish a connection to the external
      service. This could involve initializing an API client, creating a
      database connection pool, or authenticating to get a session token.
      Store any connection objects (like a client or session) on `self`.
    - `_do_disconnect`: Implement the cleanup logic. Close connections, log out,
      or release any resources acquired in `_do_connect`.

6.  **Implement Execution Logic**:
    - `_do_execute`: This is the core of your adapter. It receives an `operation`
      name and `params`. Use an `if/elif/else` block to dispatch to the
      appropriate helper method based on the `operation` string. Each helper
      should handle a single action defined in `supported_operations`.

7.  **Implement Credential Validation**:
    - `_do_validate_credentials`: Write a simple check to confirm that the
      provided credentials (from the config) are valid. This could be a
      lightweight API call like fetching the current user's profile.

8.  **Add YAML Configuration**:
    In your NeuralBridge `config.yml`, add a new entry for your adapter:

    ```yaml
    adapters:
      - name: my_unique_adapter_instance_name
        adapter: my_crm  # Matches adapter_type
        config:
          api_url: "https://api.mycrm.com/v1"
          api_key: "your-secret-api-key"
          custom_param: "some_value"
    ```

By following these steps, you can create a robust, production-ready adapter
that seamlessly integrates with the NeuralBridge platform.

"""


from __future__ import annotations

import asyncio
from typing import Any

import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

# Get a logger instance for this module, which will be automatically
# configured by NeuralBridge's logging setup.
logger = structlog.get_logger(__name__)


class CustomAdapterTemplate(BaseAdapter):
    """
    A template for creating custom NeuralBridge adapters.

    This adapter demonstrates the required structure and provides mock implementations
    for all necessary methods. It is intended to be copied and modified to integrate
    new services.
    """

    # --- 1. Update Class Attributes ---
    # These attributes provide metadata about the adapter to the NeuralBridge gateway.

    adapter_type: str = "custom_adapter_template"
    """A unique, lowercase, snake_cased identifier for this adapter type."""

    category: str = "custom"
    """The category of the adapter, used for grouping in the UI (e.g., 'database', 'api', 'messaging')."""

    description: str = "A template for building new custom adapters."
    """A brief, user-friendly description of what this adapter does."""

    version: str = "1.0.0"
    """The version of this adapter implementation."""

    supported_operations: list[str] = ["example_read", "example_write", "example_list"]
    """A list of all operations that the `_do_execute` method can handle."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the adapter instance.

        The constructor is called by NeuralBridge when the adapter is loaded.
        It's a good place to set up initial state, but avoid making network
        calls here. Connection logic should be in `_do_connect`.

        Args:
            config: A dictionary of configuration values, typically loaded from
                    the main NeuralBridge YAML configuration file.
        """
        super().__init__(config)

        # You can add custom instance variables here. For example, to hold a
        # client or session object after connecting.
        self._api_client: Any | None = None
        logger.info(
            "adapter_initialized",
            adapter=self.adapter_type,
            config_keys=list(self.config.keys()),
        )

    # --- 2. Define Configuration Schema ---
    def _get_config_schema(self) -> dict[str, Any]:
        """
        Return a JSON Schema for the adapter's configuration.

        This schema is used to validate the `config` section in the YAML file
        and to auto-generate forms in the NeuralBridge dashboard for easy
        configuration.

        Returns:
            A dictionary representing the JSON Schema.
        """
        return {
            "type": "object",
            "properties": {
                "api_url": {
                    "type": "string",
                    "description": "The base URL of the custom API.",
                    "default": "https://api.example.com/v1",
                },
                "api_key": {
                    "type": "string",
                    "description": "The API key for authentication.",
                    # The "format": "password" hint tells the UI to treat this
                    # as a sensitive field.
                    "format": "password",
                },
                "custom_param": {
                    "type": "string",
                    "description": "An example of a custom parameter for the adapter.",
                    "default": "default_value",
                },
            },
            # 'required' ensures that these keys must be present in the YAML config.
            "required": ["api_url", "api_key"],
        }

    # --- 3. Implement Connection Logic ---
    async def _do_connect(self) -> None:
        """
        Establish the connection to the external system.

        This method should contain the logic to authenticate and prepare for
        subsequent operations. For example, initialize an HTTP client with
        auth headers or connect to a database.

        Store the connection object (e.g., a client session) on `self`.

        Raises:
            Exception: If the connection fails for any reason.
        """
        logger.info("connecting_to_custom_service", url=self.config.get("api_url"))

        # MOCK: In a real implementation, you would use a library like `httpx`
        # or a vendor-specific SDK to create a client session.
        # Example:
        # headers = {"Authorization": f"Bearer {self.config.get('api_key')}"}
        # self._api_client = httpx.AsyncClient(base_url=self.config.get('api_url'), headers=headers)

        # For this template, we'll simulate a successful connection by setting
        # a mock client object after a short delay.
        await asyncio.sleep(0.1)  # Simulate network latency
        self._api_client = {"status": "connected", "url": self.config.get("api_url")}

        logger.info("mock_connection_successful", client=self._api_client)

    async def _do_disconnect(self) -> None:
        """
        Gracefully tear down the connection.

        This method should release any resources acquired in `_do_connect`.
        For example, close an HTTP client session or a database connection pool.
        """
        logger.info("disconnecting_from_custom_service")
        if self._api_client:
            # MOCK: In a real implementation, you would call the client's close method.
            # Example:
            # await self._api_client.aclose()
            await asyncio.sleep(0.05)  # Simulate cleanup
            self._api_client = None
            logger.info("mock_client_disconnected")

    # --- 4. Implement Credential Validation ---
    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Verify that the configured credentials are valid.

        This method should make a lightweight, inexpensive API call to confirm
        that authentication is working correctly. For example, fetching the
        current user's profile or a status endpoint.

        Returns:
            A dictionary with validation details, e.g., {"user": "test@example.com"}.
        """
        logger.info("validating_credentials", adapter=self.adapter_type)

        # MOCK: In a real scenario, this would be a network call.
        # For example:
        # try:
        #     response = await self._api_client.get("/me")
        #     response.raise_for_status()
        #     return {"success": True, "data": response.json()}
        # except httpx.HTTPStatusError as e:
        #     return {"success": False, "error": str(e)}

        # Simulate a check based on the provided API key.
        api_key = self.config.get("api_key")
        if not api_key or "invalid" in api_key:
            raise ValueError("Invalid or missing API key.")

        # Simulate a successful validation.
        await asyncio.sleep(0.1)
        return {"status": "ok", "message": "Credentials are valid."}

    # --- 5. Implement Execution Logic ---
    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Execute a specific operation supported by the adapter.

        This method acts as a dispatcher, routing the call to the appropriate
        private method based on the `operation` string.

        Args:
            operation: The name of the operation to perform.
            params: A dictionary of parameters for the operation.

        Returns:
            An AdapterResponse object containing the result.
        """
        logger.info("executing_operation", operation=operation, params=params)

        if operation == "example_read":
            return await self._example_read(params)
        elif operation == "example_write":
            return await self._example_write(params)
        elif operation == "example_list":
            return await self._example_list(params)
        else:
            # This case should ideally not be reached if `supported_operations`
            # is correctly defined, as the base class checks it.
            return AdapterResponse(success=False, error=f"Operation '{operation}' is not supported.")

    # --- Private Helper Methods for Operations ---

    async def _example_read(self, params: dict[str, Any]) -> AdapterResponse:
        """Handles the 'example_read' operation."""
        item_id = params.get("id")
        if not item_id:
            return AdapterResponse(success=False, error="Parameter 'id' is required for example_read.")

        # MOCK: In production, this would call the real API to fetch an item.
        # e.g., `response = await self._api_client.get(f"/items/{item_id}")`
        logger.info("mock_api_call", operation="example_read", item_id=item_id)
        await asyncio.sleep(0.2)  # Simulate network latency

        # Return a realistic mock response.
        mock_data = {
            "id": item_id,
            "name": f"Sample Item {item_id}",
            "value": 123.45,
            "created_at": "2023-10-27T10:00:00Z",
        }
        return AdapterResponse(success=True, data=mock_data)

    async def _example_write(self, params: dict[str, Any]) -> AdapterResponse:
        """Handles the 'example_write' operation."""
        item_data = params.get("data")
        if not isinstance(item_data, dict):
            return AdapterResponse(success=False, error="Parameter 'data' must be a dictionary.")

        # MOCK: In production, this would send data to the API.
        # e.g., `response = await self._api_client.post("/items", json=item_data)`
        logger.info("mock_api_call", operation="example_write", data=item_data)
        await asyncio.sleep(0.3)  # Simulate network latency

        # Return a mock success response.
        new_id = "item_" + str(abs(hash(str(item_data))))[:8]
        response_data = {"status": "created", "id": new_id}
        return AdapterResponse(success=True, data=response_data)

    async def _example_list(self, params: dict[str, Any]) -> AdapterResponse:
        """Handles the 'example_list' operation."""
        limit = params.get("limit", 10)
        if not isinstance(limit, int) or limit <= 0:
            return AdapterResponse(success=False, error="Parameter 'limit' must be a positive integer.")

        # MOCK: In production, this would fetch a list of items.
        # e.g., `response = await self._api_client.get(f"/items?limit={limit}")`
        logger.info("mock_api_call", operation="example_list", limit=limit)
        await asyncio.sleep(0.25)

        # Generate a list of mock items.
        mock_items = [
            {
                "id": f"item_{i}",
                "name": f"Listed Item {i}",
                "value": 100 + i,
            }
            for i in range(1, limit + 1)
        ]
        return AdapterResponse(success=True, data=mock_items)


