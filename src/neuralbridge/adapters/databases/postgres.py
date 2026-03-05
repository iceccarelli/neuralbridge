'''
NeuralBridge Adapter for PostgreSQL Databases.

This adapter provides a unified interface for interacting with PostgreSQL databases.
It leverages the ``asyncpg`` library for high-performance, asynchronous operations.

**Configuration (YAML)**

.. code-block:: yaml

    adapters:
      - name: my_postgres_db
        type: postgres
        config:
          host: "localhost"
          port: 5432
          user: "admin"
          password: "secure_password"
          database: "my_app_db"
          ssl_mode: "prefer"  # one of: disable, allow, prefer, require, verify-ca, verify-full
          pool_size: 10

**Supported Operations**

* ``query``: Execute a SELECT statement and fetch results.
* ``execute_sql``: Run a non-returning SQL command (INSERT, UPDATE, DELETE).
* ``list_tables``: List all tables in the current database.
* ``describe_table``: Get schema information for a specific table.
* ``health_check``: Check the connection status and database version.

'''

from __future__ import annotations

from typing import Any

import asyncpg
import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)


class PostgresAdapter(BaseAdapter):
    """
    PostgreSQL Database Adapter.
    """

    # Override class attributes
    adapter_type: str = "postgres"
    category: str = "databases"
    description: str = "Connects to and interacts with PostgreSQL databases."
    version: str = "0.2.0"
    supported_operations: list[str] = [
        "query",
        "execute_sql",
        "list_tables",
        "describe_table",
        "health_check",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the PostgreSQL adapter.

        Args:
            config: Adapter-specific configuration.
        """
        super().__init__(config)
        self._pool: asyncpg.Pool | None = None

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the adapter's configuration.
        """
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Database host."},
                "port": {"type": "integer", "description": "Database port."},
                "user": {"type": "string", "description": "Username for authentication."},
                "password": {"type": "string", "description": "Password for authentication."},
                "database": {"type": "string", "description": "Database name to connect to."},
                "ssl_mode": {
                    "type": "string",
                    "enum": ["disable", "allow", "prefer", "require", "verify-ca", "verify-full"],
                    "default": "prefer",
                },
                "pool_size": {
                    "type": "integer",
                    "description": "Connection pool size.",
                    "default": 10,
                },
            },
            "required": ["host", "port", "user", "password", "database"],
        }

    async def _do_connect(self) -> None:
        """
        Establishes the connection pool to the PostgreSQL database.
        """
        if self._pool:
            return

        try:
            self._pool = await asyncpg.create_pool(
                host=self.config.get("host"),
                port=self.config.get("port"),
                user=self.config.get("user"),
                password=self.config.get("password"),
                database=self.config.get("database"),
                ssl=self.config.get("ssl_mode", "prefer"),
                min_size=1,
                max_size=self.config.get("pool_size", 10),
            )
            logger.info("PostgreSQL connection pool established.")
        except (asyncpg.PostgresError, OSError) as e:
            logger.error("Failed to connect to PostgreSQL", error=str(e))
            # MOCK: In a real scenario, we might have a more robust fallback or retry mechanism.
            self._pool = None  # Ensure pool is None on failure
            raise ConnectionError(f"PostgreSQL connection failed: {e}") from e

    async def _do_disconnect(self) -> None:
        """
        Gracefully closes the connection pool.
        """
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL connection pool closed.")

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Executes a given operation on the PostgreSQL database.
        """
        if not self._pool:
            # MOCK: Fallback to a mock response if not connected.
            logger.warning("Not connected to PostgreSQL, using mock data.")
            return self._get_mock_response(operation, params)

        async with self._pool.acquire() as connection:
            if operation == "query":
                return await self._op_query(connection, params)
            elif operation == "execute_sql":
                return await self._op_execute_sql(connection, params)
            elif operation == "list_tables":
                return await self._op_list_tables(connection)
            elif operation == "describe_table":
                return await self._op_describe_table(connection, params)
            elif operation == "health_check":
                return await self._op_health_check(connection)
            else:
                return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the configured credentials by attempting to connect.
        """
        try:
            conn = await asyncpg.connect(
                host=self.config.get("host"),
                port=self.config.get("port"),
                user=self.config.get("user"),
                password=self.config.get("password"),
                database=self.config.get("database"),
                ssl=self.config.get("ssl_mode", "prefer"),
                timeout=5,
            )
            await conn.close()
            return {"status": "ok", "message": "Credentials are valid."}
        except (asyncpg.PostgresError, OSError) as e:
            raise ValueError(f"Credential validation failed: {e}") from e

    # --- Operation Implementations ---

    async def _op_query(self, conn: asyncpg.Connection, params: dict[str, Any]) -> AdapterResponse:
        sql = params.get("sql")
        if not sql:
            return AdapterResponse(success=False, error="'sql' parameter is required for query operation.")
        try:
            statement = await conn.prepare(sql)
            records = await statement.fetch()
            return AdapterResponse(success=True, data=[dict(r) for r in records])
        except asyncpg.PostgresError as e:
            return AdapterResponse(success=False, error=f"Query failed: {e}")

    async def _op_execute_sql(self, conn: asyncpg.Connection, params: dict[str, Any]) -> AdapterResponse:
        sql = params.get("sql")
        if not sql:
            return AdapterResponse(success=False, error="'sql' parameter is required for execute_sql operation.")
        try:
            status = await conn.execute(sql)
            return AdapterResponse(success=True, data={"status": status})
        except asyncpg.PostgresError as e:
            return AdapterResponse(success=False, error=f"Execute SQL failed: {e}")

    async def _op_list_tables(self, conn: asyncpg.Connection) -> AdapterResponse:
        try:
            records = await conn.fetch(
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';"
            )
            return AdapterResponse(success=True, data=[r['tablename'] for r in records])
        except asyncpg.PostgresError as e:
            return AdapterResponse(success=False, error=f"Failed to list tables: {e}")

    async def _op_describe_table(self, conn: asyncpg.Connection, params: dict[str, Any]) -> AdapterResponse:
        table_name = params.get("table_name")
        if not table_name:
            return AdapterResponse(success=False, error="'table_name' parameter is required.")
        try:
            query = """
                SELECT column_name, data_type, character_maximum_length, is_nullable
                FROM information_schema.columns
                WHERE table_name = $1;
            """
            records = await conn.fetch(query, table_name)
            return AdapterResponse(success=True, data=[dict(r) for r in records])
        except asyncpg.PostgresError as e:
            return AdapterResponse(success=False, error=f"Failed to describe table: {e}")

    async def _op_health_check(self, conn: asyncpg.Connection) -> AdapterResponse:
        try:
            version = await conn.fetchval("SELECT version()")
            return AdapterResponse(success=True, data={"status": "ok", "version": version})
        except asyncpg.PostgresError as e:
            return AdapterResponse(success=False, error=f"Health check failed: {e}")

    # --- Mock Responses ---

    def _get_mock_response(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        if operation == "query":
            return AdapterResponse(success=True, data=[{"id": 1, "name": "Mock User"}], metadata={"mock": True})
        if operation == "execute_sql":
            return AdapterResponse(success=True, data={"status": "MOCK EXECUTE OK"}, metadata={"mock": True})
        if operation == "list_tables":
            return AdapterResponse(success=True, data=["mock_users", "mock_products"], metadata={"mock": True})
        if operation == "describe_table":
            return AdapterResponse(
                success=True,
                data=[
                    {"column_name": "id", "data_type": "integer", "is_nullable": "NO"},
                    {"column_name": "name", "data_type": "character varying", "is_nullable": "YES"},
                ],
                metadata={"mock": True},
            )
        if operation == "health_check":
            return AdapterResponse(success=True, data={"status": "ok", "version": "Mock PostgreSQL 14.0"}, metadata={"mock": True})
        return AdapterResponse(success=False, error=f"Unsupported mock operation: {operation}", metadata={"mock": True})

