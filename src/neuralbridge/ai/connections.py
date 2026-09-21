"""Connection discovery for the /ai surface — reuses the real connection store.

Deliberately does **not** invent a second, AI-specific connection list.
``GET /ai/connections`` reads from the exact same in-process store that
backs ``GET /connections`` (``neuralbridge.api.routes.connections._connections``
— see ``reports/NEURALBRIDGE-AI-DATA-MAP.md`` for why that store is an
in-memory dict, not a database, as of this slice). The only thing this
module adds is: if the deployment has a Postgres DSN configured via env
vars and no postgres connection has been registered yet, seed exactly one
— honestly labelled ``source: "seeded_from_env"`` so the UI never implies
a human clicked through the Connection Wizard for it.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

from neuralbridge.adapters.databases.postgres import PostgresAdapter
from neuralbridge.ai.schemas import ConnectionSummary
from neuralbridge.api.routes.connections import _connections
from neuralbridge.core.router import AdapterRegistry

ENV_PREFIX = "NEURALBRIDGE_AI_PG_"


def _pg_config_from_env() -> dict[str, Any] | None:
    host = os.environ.get(f"{ENV_PREFIX}HOST")
    database = os.environ.get(f"{ENV_PREFIX}DATABASE")
    user = os.environ.get(f"{ENV_PREFIX}USER")
    if not (host and database and user):
        return None
    return {
        "host": host,
        "port": int(os.environ.get(f"{ENV_PREFIX}PORT", "5432")),
        "user": user,
        "password": os.environ.get(f"{ENV_PREFIX}PASSWORD", ""),
        "database": database,
        "ssl_mode": os.environ.get(f"{ENV_PREFIX}SSLMODE", "prefer"),
    }


def ensure_seeded_connection(registry: AdapterRegistry) -> str | None:
    """Idempotently register one postgres connection + adapter from env.

    Returns the connection id if a postgres connection exists (freshly
    seeded or already present), or ``None`` if no DSN is configured — the
    honest answer for a deployment that hasn't set one, matching the
    fail-closed-not-fake pattern the rest of this repo uses rather than
    silently falling back to mock data.
    """
    for conn_id, conn in _connections.items():
        if conn.get("adapter_type") == "postgres":
            return conn_id

    config = _pg_config_from_env()
    if config is None:
        return None

    if "postgres" not in registry:
        registry.register(PostgresAdapter(config=config))

    connection_id = str(uuid.uuid4())
    _connections[connection_id] = {
        "id": connection_id,
        "name": f"{config['database']}@{config['host']}",
        "description": "Seeded from NEURALBRIDGE_AI_PG_* environment variables for the /ai slice.",
        "adapter_type": "postgres",
        "config": {"host": config["host"], "port": config["port"], "database": config["database"]},
        "auth": {"user": "***"},
        "permissions": ["query", "list_tables", "describe_table", "health_check", "execute_sql"],
        "rate_limit": "100/minute",
        "enabled": True,
        "status": "seeded",
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    return connection_id


def list_connections(registry: AdapterRegistry) -> list[ConnectionSummary]:
    """Real connections only — reads the shared store, seeding postgres if configured."""
    ensure_seeded_connection(registry)
    summaries = []
    for conn_id, conn in _connections.items():
        source = "seeded_from_env" if conn.get("status") == "seeded" else "connections_api"
        summaries.append(
            ConnectionSummary(
                id=conn_id,
                name=conn["name"],
                adapter_type=conn["adapter_type"],
                status=conn.get("status", "created"),
                source=source,
            )
        )
    return summaries


def get_connection(connection_id: str) -> dict[str, Any] | None:
    return _connections.get(connection_id)
