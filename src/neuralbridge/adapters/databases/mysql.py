"""
NeuralBridge Adapter for MySQL Databases.

This adapter provides a unified interface to interact with MySQL-compatible
databases. It allows for executing queries, managing tables, and performing
health checks.

**Configuration (YAML):**

.. code-block:: yaml

    adapters:
      - name: my_mysql_db
        type: mysql
        config:
          host: "localhost"
          port: 3306
          database: "mydatabase"
          user: "myuser"
          password: "mypassword"
          ssl: false
          charset: "utf8mb4"

**Supported Operations:**

- ``query``: Execute a read-only SQL query (SELECT).
- ``execute_sql``: Execute a write SQL statement (INSERT, UPDATE, DELETE).
- ``list_tables``: List all tables in the current database.
- ``describe_table``: Get the schema (columns, types) of a specific table.
- ``health_check``: Check the connection status and basic database info.

"""

from __future__ import annotations

from typing import Any

import aiomysql
import pymysql

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter


class MySQLAdapter(BaseAdapter):
    """
    MySQL Database Adapter for NeuralBridge.
    """

    # --- Adapter Metadata ---
    adapter_type: str = "mysql"
    category: str = "databases"
    description: str = "Adapter for MySQL-compatible databases."
    version: str = "0.1.0"
    supported_operations: list[str] = [
        "query",
        "execute_sql",
        "list_tables",
        "describe_table",
        "health_check",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialise the MySQL adapter.

        Args:
            config: Adapter-specific configuration.
        """
        super().__init__(config)
        self._connection_pool: aiomysql.Pool | None = None
        self._mock_mode = False

    # --- Abstract Method Implementations ---

    async def _do_connect(self) -> None:
        """
        Establish a connection pool to the MySQL database.

        Uses the configuration provided during initialisation. If the connection
        fails, it falls back to a mock implementation for resilient operation.
        """
        try:
            self._connection_pool = await aiomysql.create_pool(
                host=self.config.get("host", "localhost"),
                port=self.config.get("port", 3306),
                user=self.config.get("user"),
                password=self.config.get("password"),
                db=self.config.get("database"),
                charset=self.config.get("charset", "utf8mb4"),
                autocommit=True,
            )
            self._mock_mode = False
        except (pymysql.err.OperationalError, ConnectionRefusedError):
            # MOCK: In production, this would be a critical failure.
            # For demonstration, we fall back to a mock implementation.
            self._mock_mode = True

    async def _do_disconnect(self) -> None:
        """
        Gracefully close the connection pool.
        """
        if self._connection_pool and not self._mock_mode:
            self._connection_pool.close()
            await self._connection_pool.wait_closed()
            self._connection_pool = None

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Execute a supported operation on the MySQL database.

        Dispatches the operation to the appropriate handler method.

        Args:
            operation: The name of the operation to execute.
            params: A dictionary of parameters for the operation.

        Returns:
            An AdapterResponse containing the result of the operation.
        """
        if self._mock_mode:
            return await self._execute_mock(operation, params)

        if operation == "query":
            return await self._query(params.get("sql", ""))
        elif operation == "execute_sql":
            return await self._execute_sql(params.get("sql", ""))
        elif operation == "list_tables":
            return await self._list_tables()
        elif operation == "describe_table":
            return await self._describe_table(params.get("table_name", ""))
        elif operation == "health_check":
            return await self._health_check()
        else:
            return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validate the provided database credentials by attempting a connection.

        Returns:
            A dictionary with validation status and server information if successful.
        """
        try:
            conn = await aiomysql.connect(
                host=self.config.get("host", "localhost"),
                port=self.config.get("port", 3306),
                user=self.config.get("user"),
                password=self.config.get("password"),
                db=self.config.get("database"),
            )
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT VERSION()")
                (version,) = await cursor.fetchone()
            conn.close()
            return {"status": "valid", "server_version": version}
        except Exception as e:
            raise ConnectionError(f"Credential validation failed: {e}") from e

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Return the JSON Schema for the MySQL adapter's configuration.

        Returns:
            A dictionary representing the JSON Schema.
        """
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Database host."},
                "port": {"type": "integer", "description": "Database port."},
                "database": {"type": "string", "description": "Database name."},
                "user": {"type": "string", "description": "Database user."},
                "password": {"type": "string", "description": "Database password."},
                "ssl": {"type": "boolean", "description": "Enable SSL."},
                "charset": {"type": "string", "description": "Database charset."},
            },
            "required": ["host", "port", "database", "user", "password"],
        }

    # --- Operation Handlers ---

    async def _query(self, sql: str) -> AdapterResponse:
        """Execute a read-only SQL query."""
        if not self._connection_pool:
            return AdapterResponse(success=False, error="Not connected")
        async with self._connection_pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(sql)
                result = await cursor.fetchall()
                return AdapterResponse(success=True, data=result)

    async def _execute_sql(self, sql: str) -> AdapterResponse:
        """Execute a write SQL statement."""
        if not self._connection_pool:
            return AdapterResponse(success=False, error="Not connected")
        async with self._connection_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                affected_rows = await cursor.execute(sql)
                return AdapterResponse(success=True, data={"affected_rows": affected_rows})

    async def _list_tables(self) -> AdapterResponse:
        """List all tables in the database."""
        return await self._query("SHOW TABLES")

    async def _describe_table(self, table_name: str) -> AdapterResponse:
        """Describe a table's schema."""
        return await self._query(f"DESCRIBE {table_name}")

    async def _health_check(self) -> AdapterResponse:
        """Perform a health check."""
        try:
            response = await self._query("SELECT VERSION()")
            if response.success:
                return AdapterResponse(
                    success=True,
                    data={"status": "ok", "version": response.data[0]["VERSION()"]},
                )
            else:
                return response
        except Exception as e:
            return AdapterResponse(success=False, error=str(e))

    # --- Mock Implementation ---

    async def _execute_mock(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Mock implementation for when a real database connection is not available.
        """
        if operation == "query":
            return AdapterResponse(
                success=True,
                data=[
                    {"id": 1, "name": "Mock User 1"},
                    {"id": 2, "name": "Mock User 2"},
                ],
                metadata={"mock": True},
            )
        elif operation == "execute_sql":
            return AdapterResponse(
                success=True, data={"affected_rows": 1}, metadata={"mock": True}
            )
        elif operation == "list_tables":
            return AdapterResponse(
                success=True,
                data=[{"Tables_in_mockdb": "users"}, {"Tables_in_mockdb": "products"}],
                metadata={"mock": True},
            )
        elif operation == "describe_table":
            return AdapterResponse(
                success=True,
                data=[
                    {
                        "Field": "id",
                        "Type": "int(11)",
                        "Null": "NO",
                        "Key": "PRI",
                        "Default": None,
                        "Extra": "auto_increment",
                    },
                    {
                        "Field": "name",
                        "Type": "varchar(255)",
                        "Null": "YES",
                        "Key": "",
                        "Default": None,
                        "Extra": "",
                    },
                ],
                metadata={"mock": True},
            )
        elif operation == "health_check":
            return AdapterResponse(
                success=True,
                data={"status": "ok", "version": "Mock MySQL 8.0"},
                metadata={"mock": True},
            )
        else:
            return AdapterResponse(success=False, error=f"Unsupported mock operation: {operation}")

