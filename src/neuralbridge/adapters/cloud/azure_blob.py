'''
NeuralBridge Adapter for Microsoft Azure Blob Storage.

This adapter provides a unified interface for interacting with Azure Blob Storage.
It allows for listing containers and blobs, uploading, downloading, and deleting blobs,
and retrieving blob properties.

Configuration
-------------
To use this adapter, configure it in your YAML file as follows:

.. code-block:: yaml

    adapters:
      - name: my_azure_storage
        type: azure_blob
        config:
          connection_string: "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net"
          # Alternatively, provide account name and key separately
          account_name: "your_storage_account_name"
          account_key: "your_storage_account_key"
          container_name: "your_default_container" # Optional default container

Supported Operations
--------------------
- ``list_containers``: List all containers in the storage account.
- ``list_blobs``: List all blobs within a specified container.
- ``upload_blob``: Upload data to a blob.
- ``download_blob``: Download data from a blob.
- ``delete_blob``: Delete a blob.
- ``get_blob_properties``: Retrieve properties of a specific blob.

'''

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from typing import Any

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter


class AzureBlobStorageAdapter(BaseAdapter):
    """
    Adapter for Microsoft Azure Blob Storage.
    """

    # --- Adapter Metadata ---
    adapter_type: str = "azure_blob"
    category: str = "cloud"
    description: str = "Adapter for Microsoft Azure Blob Storage."
    version: str = "0.1.0"
    supported_operations: list[str] = [
        "list_containers",
        "list_blobs",
        "upload_blob",
        "download_blob",
        "delete_blob",
        "get_blob_properties",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialise the Azure Blob Storage adapter.

        The connection client is initialized here but the actual connection
        is established in the `_do_connect` method.
        """
        super().__init__(config)
        self.blob_service_client: Any = None
        self.container_name = self.config.get("container_name")

    # --- Abstract Method Implementations ---

    async def _do_connect(self) -> None:
        """
        Establish a connection to Azure Blob Storage.

        This method would typically use the `azure.storage.blob.aio.BlobServiceClient`
        to create an authenticated client. For this mock implementation, we will
        simulate a successful connection.
        """
        # MOCK: In production, this would connect to the real Azure Blob Storage service.
        # from azure.storage.blob.aio import BlobServiceClient
        # if self.config.get("connection_string"):
        #     self.blob_service_client = BlobServiceClient.from_connection_string(
        #         self.config["connection_string"]
        #     )
        # else:
        #     self.blob_service_client = BlobServiceClient(
        #         account_url=f"https://{self.config['account_name']}.blob.core.windows.net",
        #         credential=self.config["account_key"]
        #     )
        await asyncio.sleep(0.1)  # Simulate network latency
        if not self.blob_service_client:
            self.blob_service_client = "mock_client" # Simulate a client object

    async def _do_disconnect(self) -> None:
        """
        Gracefully close the connection to Azure Blob Storage.
        """
        # MOCK: In production, this would close the client connection.
        # if self.blob_service_client:
        #     await self.blob_service_client.close()
        await asyncio.sleep(0.05) # Simulate network latency
        self.blob_service_client = None

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validate the configured Azure credentials.

        This mock implementation checks for the presence of required configuration.
        A real implementation would attempt a simple API call, like listing containers.
        """
        if not self.config.get("connection_string") and not (
            self.config.get("account_name") and self.config.get("account_key")
        ):
            raise ValueError(
                "Configuration must include either 'connection_string' or both 'account_name' and 'account_key'."
            )

        # MOCK: Simulate a successful validation call.
        await asyncio.sleep(0.2)
        return {
            "status": "validated",
            "account": self.config.get("account_name", "parsed_from_connection_string"),
        }

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Execute a supported operation on Azure Blob Storage.
        """
        if operation == "list_containers":
            return await self._list_containers()
        elif operation == "list_blobs":
            return await self._list_blobs(params)
        elif operation == "upload_blob":
            return await self._upload_blob(params)
        elif operation == "download_blob":
            return await self._download_blob(params)
        elif operation == "delete_blob":
            return await self._delete_blob(params)
        elif operation == "get_blob_properties":
            return await self._get_blob_properties(params)
        else:
            # This should not be reached due to the check in the base class
            raise ValueError(f"Unsupported operation: {operation}")

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Return the JSON schema for the adapter's configuration.
        """
        return {
            "type": "object",
            "properties": {
                "connection_string": {
                    "type": "string",
                    "title": "Connection String",
                    "description": "The full Azure Storage connection string.",
                },
                "account_name": {
                    "type": "string",
                    "title": "Storage Account Name",
                    "description": "The name of the Azure Storage account.",
                },
                "account_key": {
                    "type": "string",
                    "title": "Storage Account Key",
                    "description": "The access key for the Azure Storage account.",
                },
                "container_name": {
                    "type": "string",
                    "title": "Default Container Name",
                    "description": "The default container to use for operations if not specified.",
                },
            },
            "description": "Configuration for the Azure Blob Storage Adapter.",
        }

    # --- Operation-Specific Implementations ---

    async def _list_containers(self) -> AdapterResponse:
        """MOCK: List all containers."""
        # MOCK: In production, this would call the real API.
        # containers = []
        # async for container in self.blob_service_client.list_containers():
        #     containers.append(container.name)
        await asyncio.sleep(0.1)
        mock_data = [
            {"name": "container-one", "last_modified": datetime.now(UTC).isoformat()},
            {"name": "container-two", "last_modified": datetime.now(UTC).isoformat()},
        ]
        return AdapterResponse(success=True, data=mock_data)

    async def _list_blobs(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: List blobs in a container."""
        container_name = params.get("container_name") or self.container_name
        if not container_name:
            return AdapterResponse(success=False, error="Missing required parameter: container_name")

        # MOCK: In production, this would call the real API.
        await asyncio.sleep(0.1)
        mock_data = [
            {"name": "blob1.txt", "size": 1024, "content_type": "text/plain"},
            {"name": "image.png", "size": 524288, "content_type": "image/png"},
        ]
        return AdapterResponse(success=True, data=mock_data, metadata={"container": container_name})

    async def _upload_blob(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Upload a blob."""
        container_name = params.get("container_name") or self.container_name
        blob_name = params.get("blob_name")
        data = params.get("data") # Expects bytes or base64 encoded string

        if not all([container_name, blob_name, data]):
            return AdapterResponse(success=False, error="Missing required parameters: container_name, blob_name, data")

        # MOCK: In production, this would call the real API.
        await asyncio.sleep(0.2)
        try:
            if isinstance(data, str):
                # Assuming base64 encoded string
                bytes_data = base64.b64decode(data)
            else:
                bytes_data = bytes(data) if data else b""
        except (TypeError, ValueError):
            return AdapterResponse(success=False, error="Invalid format for 'data'. Expected bytes or base64 string.")

        return AdapterResponse(
            success=True,
            data={"status": "uploaded", "blob": blob_name, "size": len(bytes_data)},
            metadata={"container": container_name},
        )

    async def _download_blob(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Download a blob."""
        container_name = params.get("container_name") or self.container_name
        blob_name = params.get("blob_name")

        if not all([container_name, blob_name]):
            return AdapterResponse(success=False, error="Missing required parameters: container_name, blob_name")

        # MOCK: In production, this would call the real API.
        await asyncio.sleep(0.15)
        mock_content = b"This is the mock content of the downloaded blob."
        return AdapterResponse(
            success=True,
            data={"content": base64.b64encode(mock_content).decode('utf-8')},
            metadata={"container": container_name, "blob": blob_name, "encoding": "base64"},
        )

    async def _delete_blob(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Delete a blob."""
        container_name = params.get("container_name") or self.container_name
        blob_name = params.get("blob_name")

        if not all([container_name, blob_name]):
            return AdapterResponse(success=False, error="Missing required parameters: container_name, blob_name")

        # MOCK: In production, this would call the real API.
        await asyncio.sleep(0.1)
        return AdapterResponse(
            success=True,
            data={"status": "deleted", "blob": blob_name},
            metadata={"container": container_name},
        )

    async def _get_blob_properties(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Get blob properties."""
        container_name = params.get("container_name") or self.container_name
        blob_name = params.get("blob_name")

        if not all([container_name, blob_name]):
            return AdapterResponse(success=False, error="Missing required parameters: container_name, blob_name")

        # MOCK: In production, this would call the real API.
        await asyncio.sleep(0.05)
        mock_properties = {
            "name": blob_name,
            "container": container_name,
            "size": 12345,
            "content_type": "application/octet-stream",
            "creation_time": datetime.now(UTC).isoformat(),
            "last_modified": datetime.now(UTC).isoformat(),
            "etag": f'"0x8D8{str(abs(hash(blob_name)))[:10]}"',
        }
        return AdapterResponse(success=True, data=mock_properties)

