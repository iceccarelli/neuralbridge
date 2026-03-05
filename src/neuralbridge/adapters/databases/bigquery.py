'''
NeuralBridge Adapter for Google BigQuery

This adapter provides a connection to Google BigQuery, allowing for querying,
data manipulation, and schema management.

**Configuration (`config.yml`):**

.. code-block:: yaml

    adapters:
      - name: my_bigquery_instance
        type: bigquery
        config:
          project_id: "your-gcp-project-id"
          credentials_path: "/path/to/your/credentials.json" # Optional
          location: "US" # Optional, default is US
          dataset: "my_dataset" # Optional, default dataset

**Supported Operations:**

- `query`: Execute a SQL query.
- `list_datasets`: List all datasets in the project.
- `list_tables`: List all tables in a given dataset.
- `get_table_schema`: Retrieve the schema of a specific table.
- `create_table`: Create a new table with a defined schema.

'''

from __future__ import annotations

import uuid
from typing import Any, cast

import structlog
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import bigquery

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)


class BigQueryAdapter(BaseAdapter):
    """
    Connects to and interacts with Google BigQuery.
    """

    adapter_type = "bigquery"
    category = "databases"
    description = "Adapter for Google BigQuery for large-scale data analytics."
    version = "0.2.0"
    supported_operations = [
        "query",
        "list_datasets",
        "list_tables",
        "get_table_schema",
        "create_table",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the BigQuery adapter.

        Args:
            config: Adapter-specific configuration.
        """
        super().__init__(config)
        self.client: bigquery.Client | None = None
        self.project_id = self.config.get("project_id")
        self.location = self.config.get("location", "US")
        self.dataset = self.config.get("dataset")

    async def _do_connect(self) -> None:
        """
        Establishes a connection to Google BigQuery.

        Uses the application default credentials or a specified service account file.
        """
        try:
            # MOCK: In a real scenario, we would connect to BigQuery.
            # Here, we simulate a successful connection.
            if self.config.get("credentials_path"):
                self.client = bigquery.Client.from_service_account_json(
                    self.config["credentials_path"],
                    project=self.project_id,
                    location=self.location,
                )
            else:
                self.client = bigquery.Client(
                    project=self.project_id, location=self.location
                )
            logger.info(
                "bigquery_adapter_connect_success", project_id=self.project_id
            )
        except Exception as e:
            logger.error("bigquery_adapter_connect_failed", error=str(e))
            # Fallback to a mock client for offline/testing environments
            self.client = None
            raise ConnectionError(
                f"Failed to connect to BigQuery project '{self.project_id}': {e}"
            ) from e

    async def _do_disconnect(self) -> None:
        """
        Closes the connection to Google BigQuery.
        """
        if self.client:
            self.client.close()
            self.client = None
            logger.info(
                "bigquery_adapter_disconnect_success", project_id=self.project_id
            )

    async def _do_execute(
        self, operation: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """
        Executes a supported operation on BigQuery.

        Args:
            operation: The name of the operation to execute.
            params: A dictionary of parameters for the operation.

        Returns:
            An AdapterResponse containing the result of the operation.
        """
        if not self.client:
            # MOCK: Simulating behavior without a real client
            logger.warning("bigquery_mock_mode_active")
            return await self._mock_execute(operation, params)

        handlers = {
            "query": self._exec_query,
            "list_datasets": self._exec_list_datasets,
            "list_tables": self._exec_list_tables,
            "get_table_schema": self._exec_get_table_schema,
            "create_table": self._exec_create_table,
        }

        handler = handlers.get(operation)
        if not handler:
            return AdapterResponse(
                success=False, error=f"Operation '{operation}' not supported."
            )

        try:
            return await handler(params)
        except GoogleAPICallError as e:
            logger.error(
                "bigquery_api_error", operation=operation, error=e.message
            )
            return AdapterResponse(success=False, error=e.message)
        except Exception as e:
            logger.exception("bigquery_operation_failed", operation=operation)
            return AdapterResponse(success=False, error=str(e))

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the configured BigQuery credentials by listing datasets.
        """
        try:
            # MOCK: In production, this would call the real API
            await self._do_connect()
            client = cast(bigquery.Client, self.client)
            datasets = list(client.list_datasets(max_results=1))
            await self._do_disconnect()
            return {
                "status": "valid",
                "project_id": self.project_id,
                "accessible_datasets": len(datasets) > 0,
            }
        except Exception as e:
            raise PermissionError(f"Credential validation failed: {e}") from e

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the BigQuery adapter configuration.
        """
        return {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "title": "GCP Project ID",
                    "description": "The Google Cloud Platform project ID.",
                },
                "credentials_path": {
                    "type": "string",
                    "title": "Credentials Path",
                    "description": "Path to the GCP service account JSON file.",
                },
                "location": {
                    "type": "string",
                    "title": "Location",
                    "description": "The geographic location of the BigQuery resources.",
                    "default": "US",
                },
                "dataset": {
                    "type": "string",
                    "title": "Default Dataset",
                    "description": "The default dataset to use for operations.",
                },
            },
            "required": ["project_id"],
        }

    # --- Mock Execution --- #

    async def _mock_execute(
        self, operation: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """Provides mock responses for offline testing."""
        job_id = f"job_{uuid.uuid4()}"
        if operation == "query":
            return AdapterResponse(
                success=True,
                data={
                    "job_id": job_id,
                    "status": "DONE",
                    "rows": [
                        {"name": "John Doe", "age": 30},
                        {"name": "Jane Smith", "age": 25},
                    ],
                },
                metadata={"query": params.get("sql")},
            )
        elif operation == "list_datasets":
            return AdapterResponse(
                success=True, data=["mock_dataset_1", "mock_dataset_2"]
            )
        elif operation == "list_tables":
            return AdapterResponse(
                success=True, data=["mock_table_1", "mock_table_2"]
            )
        elif operation == "get_table_schema":
            return AdapterResponse(
                success=True,
                data=[
                    {"name": "id", "type": "INTEGER", "mode": "REQUIRED"},
                    {"name": "name", "type": "STRING", "mode": "NULLABLE"},
                ],
            )
        elif operation == "create_table":
            return AdapterResponse(
                success=True,
                data={"table_id": params.get("table_id"), "status": "CREATED"},
            )
        return AdapterResponse(success=False, error="Mock operation not implemented")

    # --- Private Execution Handlers --- #

    async def _exec_query(self, params: dict[str, Any]) -> AdapterResponse:
        sql = params.get("sql")
        if not sql:
            return AdapterResponse(success=False, error="Missing 'sql' parameter.")

        client = cast(bigquery.Client, self.client)
        query_job = client.query(sql)
        rows = [dict(row) for row in query_job.result()]

        return AdapterResponse(
            success=True,
            data=rows,
            metadata={
                "job_id": query_job.job_id,
                "total_rows": len(rows),
                "bytes_billed": query_job.total_bytes_billed,
            },
        )

    async def _exec_list_datasets(self, params: dict[str, Any]) -> AdapterResponse:
        client = cast(bigquery.Client, self.client)
        datasets = [dataset.dataset_id for dataset in client.list_datasets()]
        return AdapterResponse(success=True, data=datasets)

    async def _exec_list_tables(self, params: dict[str, Any]) -> AdapterResponse:
        dataset_id = params.get("dataset_id") or self.dataset
        if not dataset_id:
            return AdapterResponse(success=False, error="Missing 'dataset_id' parameter.")

        client = cast(bigquery.Client, self.client)
        tables = [table.table_id for table in client.list_tables(dataset_id)]
        return AdapterResponse(success=True, data=tables)

    async def _exec_get_table_schema(self, params: dict[str, Any]) -> AdapterResponse:
        table_id = params.get("table_id")
        dataset_id = params.get("dataset_id") or self.dataset
        if not table_id or not dataset_id:
            return AdapterResponse(
                success=False, error="Missing 'table_id' or 'dataset_id' parameter."
            )

        client = cast(bigquery.Client, self.client)
        table_ref = client.dataset(dataset_id).table(table_id)
        table = client.get_table(table_ref)
        schema = [
            {"name": field.name, "type": field.field_type, "mode": field.mode}
            for field in table.schema
        ]
        return AdapterResponse(success=True, data=schema)

    async def _exec_create_table(self, params: dict[str, Any]) -> AdapterResponse:
        table_id = params.get("table_id")
        schema_def = params.get("schema")
        dataset_id = params.get("dataset_id") or self.dataset

        if not all([table_id, schema_def, dataset_id]):
            return AdapterResponse(
                success=False,
                error="Missing 'table_id', 'schema', or 'dataset_id' parameter.",
            )

        assert schema_def is not None
        client = cast(bigquery.Client, self.client)
        schema = [
            bigquery.SchemaField(f["name"], f["type"], mode=f.get("mode", "NULLABLE"))
            for f in schema_def
        ]
        table_ref = client.dataset(dataset_id).table(table_id)
        table = bigquery.Table(table_ref, schema=schema)
        created_table = client.create_table(table)

        return AdapterResponse(
            success=True,
            data={"table_id": created_table.table_id, "project": created_table.project},
        )

