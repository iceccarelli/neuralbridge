'''
NeuralBridge Adapter for Amazon Web Services (AWS) S3

This adapter provides a unified interface for interacting with AWS S3, a scalable
object storage service. It allows for common operations such as listing buckets and
objects, and performing CRUD operations on objects.

Configuration
-------------
To use this adapter, configure it in your `config.yml` file under the `adapters`
section. The following parameters are required:

.. code-block:: yaml

    adapters:
      - name: my_s3_storage
        type: aws_s3
        config:
          access_key_id: YOUR_AWS_ACCESS_KEY_ID
          secret_access_key: YOUR_AWS_SECRET_ACCESS_KEY
          region: us-east-1
          default_bucket: my-default-bucket
          endpoint_url: https://s3.us-east-1.amazonaws.com  # Optional

Supported Operations
--------------------
- `list_buckets`: Retrieves a list of all S3 buckets.
- `list_objects`: Lists objects within a specified bucket.
- `get_object`: Downloads an object from a bucket.
- `put_object`: Uploads an object to a bucket.
- `delete_object`: Removes an object from a bucket.
- `generate_presigned_url`: Creates a temporary, shareable URL for an object.

'''

from __future__ import annotations

import asyncio
import datetime
from typing import Any

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter


class AWSS3Adapter(BaseAdapter):
    """
    Connects to and interacts with Amazon S3.
    """

    adapter_type = "aws_s3"
    category = "cloud"
    description = "Adapter for Amazon S3 object storage."
    version = "0.1.0"
    supported_operations = [
        "list_buckets",
        "list_objects",
        "get_object",
        "put_object",
        "delete_object",
        "generate_presigned_url",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the AWS S3 adapter.

        Args:
            config: Adapter-specific configuration.
        """
        super().__init__(config)
        self._s3_client: Any = None

    async def _do_connect(self) -> None:
        """
        Establishes a mock connection to the AWS S3 service.

        In a real-world scenario, this method would initialize the boto3 S3 client.
        """
        # MOCK: In production, this would initialize the boto3 client.
        await asyncio.sleep(0.1)
        self._s3_client = "mock_s3_client"

    async def _do_disconnect(self) -> None:
        """
        Closes the mock connection to the AWS S3 service.
        """
        # MOCK: In production, this would clean up the boto3 client.
        await asyncio.sleep(0.05)
        self._s3_client = None

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the provided AWS credentials by making a mock API call.

        Returns:
            A dictionary with validation results.
        """
        # MOCK: In production, this would call the real API to validate credentials.
        await asyncio.sleep(0.2)
        return {"status": "ok", "user": "mock_user"}

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the adapter's configuration.

        Returns:
            A dictionary representing the JSON schema.
        """
        return {
            "type": "object",
            "properties": {
                "access_key_id": {"type": "string", "title": "AWS Access Key ID"},
                "secret_access_key": {
                    "type": "string",
                    "title": "AWS Secret Access Key",
                },
                "region": {"type": "string", "title": "AWS Region"},
                "default_bucket": {"type": "string", "title": "Default S3 Bucket"},
                "endpoint_url": {"type": "string", "title": "S3 Endpoint URL"},
            },
            "required": ["access_key_id", "secret_access_key", "region"],
        }

    async def _do_execute(
        self, operation: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """
        Executes a given operation on the S3 service.

        Args:
            operation: The operation to perform.
            params: Operation-specific parameters.

        Returns:
            An AdapterResponse containing the result of the operation.
        """
        if operation == "list_buckets":
            return await self._list_buckets()
        elif operation == "list_objects":
            return await self._list_objects(params)
        elif operation == "get_object":
            return await self._get_object(params)
        elif operation == "put_object":
            return await self._put_object(params)
        elif operation == "delete_object":
            return await self._delete_object(params)
        elif operation == "generate_presigned_url":
            return await self._generate_presigned_url(params)
        else:
            return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    async def _list_buckets(self) -> AdapterResponse:
        """
        Mocks the listing of S3 buckets.

        Returns:
            An AdapterResponse with a list of mock buckets.
        """
        # MOCK: In production, this would call the real S3 API.
        await asyncio.sleep(0.1)
        mock_buckets = [
            {
                "Name": "neuralbridge-assets",
                "CreationDate": datetime.datetime.now(datetime.UTC).isoformat(),
            },
            {
                "Name": "neuralbridge-logs",
                "CreationDate": datetime.datetime.now(datetime.UTC).isoformat(),
            },
        ]
        return AdapterResponse(success=True, data=mock_buckets)

    async def _list_objects(self, params: dict[str, Any]) -> AdapterResponse:
        """
        Mocks the listing of objects in a bucket.

        Args:
            params: Parameters, including the bucket name.

        Returns:
            An AdapterResponse with a list of mock objects.
        """
        bucket = params.get("bucket", self.config.get("default_bucket"))
        if not bucket:
            return AdapterResponse(success=False, error="Bucket name is required.")

        # MOCK: In production, this would call the real S3 API.
        await asyncio.sleep(0.1)
        mock_objects = {
            "Contents": [
                {
                    "Key": "documents/report.pdf",
                    "LastModified": datetime.datetime.now(datetime.UTC).isoformat(),
                    "ETag": '''"mock-etag-1"''',
                    "Size": 1024,
                    "StorageClass": "STANDARD",
                },
                {
                    "Key": "images/logo.png",
                    "LastModified": datetime.datetime.now(datetime.UTC).isoformat(),
                    "ETag": '''"mock-etag-2"''',
                    "Size": 512,
                    "StorageClass": "STANDARD",
                },
            ]
        }
        return AdapterResponse(success=True, data=mock_objects)

    async def _get_object(self, params: dict[str, Any]) -> AdapterResponse:
        """
        Mocks retrieving an object from a bucket.

        Args:
            params: Parameters, including bucket and key.

        Returns:
            An AdapterResponse with the mock object data.
        """
        bucket = params.get("bucket", self.config.get("default_bucket"))
        key = params.get("key")
        if not bucket or not key:
            return AdapterResponse(success=False, error="Bucket and key are required.")

        # MOCK: In production, this would call the real S3 API.
        await asyncio.sleep(0.1)
        return AdapterResponse(
            success=True, data={"Body": b"mock file content", "ContentType": "text/plain"}
        )

    async def _put_object(self, params: dict[str, Any]) -> AdapterResponse:
        """
        Mocks uploading an object to a bucket.

        Args:
            params: Parameters, including bucket, key, and body.

        Returns:
            An AdapterResponse indicating success.
        """
        bucket = params.get("bucket", self.config.get("default_bucket"))
        key = params.get("key")
        body = params.get("body")
        if not bucket or not key or not body:
            return AdapterResponse(
                success=False, error="Bucket, key, and body are required."
            )

        # MOCK: In production, this would call the real S3 API.
        await asyncio.sleep(0.2)
        return AdapterResponse(
            success=True, data={"ETag": '''"mock-etag-new"''', "VersionId": "mock-version-id"}
        )

    async def _delete_object(self, params: dict[str, Any]) -> AdapterResponse:
        """
        Mocks deleting an object from a bucket.

        Args:
            params: Parameters, including bucket and key.

        Returns:
            An AdapterResponse indicating success.
        """
        bucket = params.get("bucket", self.config.get("default_bucket"))
        key = params.get("key")
        if not bucket or not key:
            return AdapterResponse(success=False, error="Bucket and key are required.")

        # MOCK: In production, this would call the real S3 API.
        await asyncio.sleep(0.15)
        return AdapterResponse(success=True, data={"DeleteMarker": True})

    async def _generate_presigned_url(self, params: dict[str, Any]) -> AdapterResponse:
        """
        Mocks generating a presigned URL for an S3 object.

        Args:
            params: Parameters, including bucket, key, and expiration.

        Returns:
            An AdapterResponse with the mock presigned URL.
        """
        bucket = params.get("bucket", self.config.get("default_bucket"))
        key = params.get("key")
        params.get("expiration", 3600)
        if not bucket or not key:
            return AdapterResponse(success=False, error="Bucket and key are required.")

        # MOCK: In production, this would call the real S3 API.
        await asyncio.sleep(0.05)
        mock_url = f"https://{bucket}.s3.amazonaws.com/{key}?AWSAccessKeyId=...&Expires=...&Signature=..."
        return AdapterResponse(success=True, data={"presigned_url": mock_url})

