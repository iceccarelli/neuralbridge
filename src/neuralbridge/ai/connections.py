"""Connection discovery — and, for paid callers, creation — for /ai.

Backed by the durable ``AiStore`` (see ``neuralbridge.ai.store``), not an
in-memory dict — a restart keeps every connection record (Phase 2). The
free, always-present demo connection is still seeded from
``NEURALBRIDGE_AI_PG_*`` env vars the first time the store is empty, same
as Phase 1, honestly labelled ``source: "seeded_from_env"``. Register/Cell
callers can additionally bind their own connections via
``create_connection`` — each gets its own ``PostgresAdapter`` instance,
registered under a unique registry key
(``f"postgres:{connection_id}"``) so multiple Postgres connections can be
live at once without one overwriting another in the shared
``AdapterRegistry`` (which is otherwise one-instance-per-adapter-type).
"""

from __future__ import annotations

import os
from typing import Any

from neuralbridge.adapters.databases.postgres import PostgresAdapter
from neuralbridge.ai.schemas import ConnectionSummary
from neuralbridge.ai.store import AiStore, ConnectionRecord, new_id
from neuralbridge.core.router import AdapterRegistry

ENV_PREFIX = "NEURALBRIDGE_AI_PG_"
SEEDED_REGISTRY_KEY = "postgres"


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


def ensure_seeded_connection(registry: AdapterRegistry, store: AiStore) -> str | None:
    """Idempotently persist + register one postgres connection from env.

    Returns the connection id if a seeded connection exists (freshly
    created or already there from a prior run), or ``None`` if no DSN is
    configured — the honest answer, matching this repo's fail-closed
    pattern rather than falling back to mock data.
    """
    for record in store.list_connections():
        if record.source == "seeded_from_env":
            if SEEDED_REGISTRY_KEY not in registry:
                config = _pg_config_from_env()
                if config is not None:
                    registry.register(PostgresAdapter(config=config), key=SEEDED_REGISTRY_KEY)
            return record.id

    config = _pg_config_from_env()
    if config is None:
        return None

    if SEEDED_REGISTRY_KEY not in registry:
        registry.register(PostgresAdapter(config=config), key=SEEDED_REGISTRY_KEY)

    connection_id = new_id()
    store.create_connection(
        ConnectionRecord(
            id=connection_id,
            name=f"{config['database']}@{config['host']}",
            description="Seeded from NEURALBRIDGE_AI_PG_* environment variables for the /ai slice.",
            adapter_type="postgres",
            registry_key=SEEDED_REGISTRY_KEY,
            config={"host": config["host"], "port": config["port"], "database": config["database"]},
            source="seeded_from_env",
            status="seeded",
        )
    )
    return connection_id


def create_connection(
    registry: AdapterRegistry,
    store: AiStore,
    *,
    name: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    ssl_mode: str = "prefer",
) -> ConnectionRecord:
    """Bind an additional Postgres connection. Paid-gated at the route
    layer (``require_ai_control_plane``) — this function itself does not
    check entitlement, callers must."""
    connection_id = new_id()
    registry_key = f"postgres:{connection_id}"
    adapter_config = {
        "host": host, "port": port, "user": user, "password": password,
        "database": database, "ssl_mode": ssl_mode,
    }
    registry.register(PostgresAdapter(config=adapter_config), key=registry_key)

    record = ConnectionRecord(
        id=connection_id,
        name=name,
        description="Bound via POST /ai/connections.",
        adapter_type="postgres",
        registry_key=registry_key,
        # Never store the password — same rule Phase 1's connections.py
        # followed: a credential that isn't persisted can't leak from a
        # stolen store. It lives only in the live PostgresAdapter's pool.
        config={"host": host, "port": port, "database": database},
        source="bound_by_operator",
        status="created",
    )
    store.create_connection(record)
    return record


def list_connections(registry: AdapterRegistry, store: AiStore) -> list[ConnectionSummary]:
    """Real connections only — reads the durable store, seeding postgres if configured."""
    ensure_seeded_connection(registry, store)
    return [
        ConnectionSummary(
            id=r.id,
            name=r.name,
            adapter_type=r.adapter_type,
            status=r.status,
            source=r.source,
        )
        for r in store.list_connections()
    ]


def get_connection(store: AiStore, connection_id: str) -> ConnectionRecord | None:
    return store.get_connection(connection_id)
