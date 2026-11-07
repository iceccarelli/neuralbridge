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
          statement_timeout_ms: 30000   # server-side cap per statement (default 30 s)
          acquire_timeout: 10           # seconds to wait for a free pooled connection
          connect_timeout: 10
          max_rows: 10000               # a larger result is refused, not buffered
          application_name: neuralbridge

**Failure behaviour** (every one is a structured ``AdapterResponse(success=False)``, never a raw exception or a hang)

* ``statement_timeout: ...`` - the server cancelled a statement that ran past ``statement_timeout_ms``.
* ``connection_lost: ...`` - the connection died mid-query; the pool discards it and the next call gets a fresh one.
* ``pool_exhausted: ...`` - no pooled connection became free within ``acquire_timeout``.
* ``permission_denied: ...`` - the database role lacks a privilege (the server's own message, which has no credential).
* ``read_only_violation: ...`` - a read operation tried to change data (see below).
* ``result_too_large: ...`` - the result had more than ``max_rows`` rows.
* ``Query failed: ...`` / ``Execute SQL failed: ...`` - any other error the server reported.
* Connecting problems raise ``ConnectionError("PostgreSQL connection failed: <ExceptionClass>")``: the exception class only,
  never the driver text (which can carry the host, port, user or DSN), and never the password.

**Read-only is enforced here, not only by the policy gate.** ``query``, ``list_tables``, ``describe_table`` and
``health_check`` run inside a ``READ ONLY`` transaction, so ``DELETE ... RETURNING``, ``WITH x AS (DELETE ...)``,
``nextval()``, DDL and ``SELECT ... FOR UPDATE`` fail in the database whatever the SQL text claims. Only
``execute_sql`` can write, and callers gate that one (``neuralbridge.ai``).

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


DEFAULT_STATEMENT_TIMEOUT_MS = 30_000
DEFAULT_ACQUIRE_TIMEOUT = 10.0
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_MAX_ROWS = 10_000
HARD_MAX_ROWS = 1_000_000


def _failure(code: str, detail: str) -> AdapterResponse:
    return AdapterResponse(success=False, error=f"{code}: {detail}", data=None)


def _connection_gone(conn: asyncpg.Connection | None) -> bool:
    """True if the connection is closed, or unusable (a released/terminated pool proxy raises on use)."""
    if conn is None:
        return True
    try:
        return conn.is_closed()
    except asyncpg.InterfaceError:
        return True


def _classify(exc: BaseException, conn: asyncpg.Connection | None, generic_prefix: str) -> AdapterResponse:
    """Map a driver exception to a structured failure. Never includes host, port, user or password."""
    if isinstance(exc, asyncpg.QueryCanceledError):
        return _failure("statement_timeout", "the statement exceeded statement_timeout_ms and was cancelled")
    if isinstance(exc, asyncpg.ReadOnlySQLTransactionError):
        return _failure("read_only_violation", "this operation is read-only and the statement tried to change data")
    if isinstance(exc, asyncpg.InsufficientPrivilegeError):
        return _failure("permission_denied", exc.message or "insufficient privilege")
    if isinstance(exc, (asyncpg.PostgresConnectionError, asyncpg.ConnectionDoesNotExistError, OSError)) or (
        isinstance(exc, asyncpg.InterfaceError) and _connection_gone(conn)
    ):
        return _failure("connection_lost", "the database connection was lost; the next call uses a fresh one")
    if isinstance(exc, asyncpg.PostgresError):
        return AdapterResponse(success=False, error=f"{generic_prefix}: {exc}")
    raise exc


class PostgresAdapter(BaseAdapter):
    """
    PostgreSQL Database Adapter.
    """

    # Override class attributes
    adapter_type: str = "postgres"
    backend: str = "real"
    #: Registered by ``neuralbridge.ai.connections`` (the env-seeded demo and ``POST /ai/connections``).
    shipped_loader: bool = True
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
                "statement_timeout_ms": {"type": "integer", "default": DEFAULT_STATEMENT_TIMEOUT_MS},
                "acquire_timeout": {"type": "number", "default": DEFAULT_ACQUIRE_TIMEOUT},
                "connect_timeout": {"type": "number", "default": DEFAULT_CONNECT_TIMEOUT},
                "max_rows": {"type": "integer", "default": DEFAULT_MAX_ROWS, "maximum": HARD_MAX_ROWS},
            },
            "required": ["host", "port", "user", "password", "database"],
        }

    async def _do_connect(self) -> None:
        """
        Establishes the connection pool to the PostgreSQL database.
        """
        if self._pool:
            return

        timeout_ms = self._int("statement_timeout_ms", DEFAULT_STATEMENT_TIMEOUT_MS, minimum=0)
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
                timeout=self._float("connect_timeout", DEFAULT_CONNECT_TIMEOUT),
                # client-side backstop a little beyond the server-side cap, so a stuck socket cannot hang a call
                command_timeout=(timeout_ms / 1000 + 5) if timeout_ms else None,
                server_settings={
                    "statement_timeout": str(timeout_ms),
                    "idle_in_transaction_session_timeout": "60000",
                    "application_name": str(self.config.get("application_name", "neuralbridge")),
                },
            )
            logger.info("PostgreSQL connection pool established.")
        except (asyncpg.PostgresError, OSError, TimeoutError) as e:
            # The exception class only: asyncpg/OS text carries the host, port and user.
            logger.error("Failed to connect to PostgreSQL", error_type=type(e).__name__)
            self._pool = None  # Ensure pool is None on failure
            raise ConnectionError(f"PostgreSQL connection failed: {type(e).__name__}") from e

    def _int(self, key: str, default: int, *, minimum: int = 1) -> int:
        try:
            return max(minimum, int(self.config.get(key, default)))
        except (TypeError, ValueError):
            return default

    def _float(self, key: str, default: float) -> float:
        try:
            value = float(self.config.get(key, default))
        except (TypeError, ValueError):
            return default
        return value if value > 0 else default

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
            if not self._mock_allowed():
                raise self._refuse_mock("it is not connected to PostgreSQL")
            logger.warning("Not connected to PostgreSQL, using mock data (allow_mock).")
            return self._get_mock_response(operation, params)

        try:
            connection = await self._pool.acquire(timeout=self._float("acquire_timeout", DEFAULT_ACQUIRE_TIMEOUT))
        except TimeoutError:
            return _failure("pool_exhausted", "no database connection became free in time; retry shortly")
        try:
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
        finally:
            try:
                await self._pool.release(connection)
            except Exception:  # a dead connection is discarded by the pool; nothing more to do
                logger.warning("postgres_release_failed")

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
        except (asyncpg.PostgresError, OSError, TimeoutError) as e:
            raise ValueError(f"Credential validation failed: {type(e).__name__}") from e

    # --- Operation Implementations ---

    async def _op_query(self, conn: asyncpg.Connection, params: dict[str, Any]) -> AdapterResponse:
        sql = params.get("sql")
        if not sql:
            return AdapterResponse(success=False, error="'sql' parameter is required for query operation.")
        max_rows = min(self._int("max_rows", DEFAULT_MAX_ROWS), HARD_MAX_ROWS)
        try:
            # READ ONLY: whatever the text says, the database refuses to change anything.
            async with conn.transaction(readonly=True):
                statement = await conn.prepare(sql)
                if statement.get_attributes():
                    rows = await (await statement.cursor()).fetch(max_rows + 1)
                else:  # returns no columns (SET, SHOW-less utility): run it, there is nothing to cap
                    rows = await statement.fetch()
            if len(rows) > max_rows:
                return _failure("result_too_large", f"the result has more than max_rows={max_rows} rows; add a LIMIT")
            return AdapterResponse(success=True, data=[dict(r) for r in rows])
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError) as e:
            return _classify(e, conn, "Query failed")

    async def _op_execute_sql(self, conn: asyncpg.Connection, params: dict[str, Any]) -> AdapterResponse:
        sql = params.get("sql")
        if not sql:
            return AdapterResponse(success=False, error="'sql' parameter is required for execute_sql operation.")
        try:
            status = await conn.execute(sql)
            return AdapterResponse(success=True, data={"status": status})
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError) as e:
            return _classify(e, conn, "Execute SQL failed")

    async def _read_only_fetch(self, conn: asyncpg.Connection, sql: str, *args: Any) -> list[Any]:
        async with conn.transaction(readonly=True):
            return list(await conn.fetch(sql, *args))

    async def _op_list_tables(self, conn: asyncpg.Connection) -> AdapterResponse:
        try:
            records = await self._read_only_fetch(
                conn,
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';",
            )
            return AdapterResponse(success=True, data=[r['tablename'] for r in records])
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError) as e:
            return _classify(e, conn, "Failed to list tables")

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
            records = await self._read_only_fetch(conn, query, table_name)
            return AdapterResponse(success=True, data=[dict(r) for r in records])
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError) as e:
            return _classify(e, conn, "Failed to describe table")

    async def _op_health_check(self, conn: asyncpg.Connection) -> AdapterResponse:
        try:
            async with conn.transaction(readonly=True):
                version = await conn.fetchval("SELECT version()")
            return AdapterResponse(success=True, data={"status": "ok", "version": version})
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError) as e:
            return _classify(e, conn, "Health check failed")

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

