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
from datetime import UTC, datetime
from typing import Any

import structlog

from neuralbridge.adapters.databases.postgres import PostgresAdapter
from neuralbridge.ai.schemas import ConnectionSummary
from neuralbridge.ai.store import REVOKED, AiStore, ConnectionRecord, new_id
from neuralbridge.ai.tenancy import Scope, can_delete_connection, can_read_connection
from neuralbridge.core.router import AdapterRegistry

logger = structlog.get_logger(__name__)

class ConnectionLifecycleError(Exception):
    """A connection lifecycle refusal. ``status_code`` maps to HTTP: 404 not found *or*
    not yours (one body, no existence oracle), 409 wrong state, 422 the target rejected the
    new credentials."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


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
    owner: str,
    name: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    ssl_mode: str = "prefer",
) -> ConnectionRecord:
    """Bind an additional Postgres connection, owned by ``owner`` — the
    account id from the validated principal (``entitlements.scope_for``),
    never a caller-supplied field. Paid-gated at the route layer
    (``require_ai_control_plane``) — this function itself does not check
    entitlement, callers must."""
    if not owner:
        raise ValueError("a bound connection must have an owner")
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
        config={"host": host, "port": port, "database": database, "ssl_mode": ssl_mode},
        source="bound_by_operator",
        status="created",
        owner=owner,
    )
    store.create_connection(record)
    return record


def list_connections(registry: AdapterRegistry, store: AiStore, scope: Scope) -> list[ConnectionSummary]:
    """Connections ``scope`` may see — its own plus the shared seeded demo
    (operator: all). Reads the durable store, seeding postgres if configured.
    Never returns anything but id/name/type/status/source: no config, no
    credential, no registry key, no owner."""
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
        if can_read_connection(scope, r)
    ]


def get_connection(store: AiStore, scope: Scope, connection_id: str) -> ConnectionRecord | None:
    """The connection if ``scope`` may see it; ``None`` otherwise — a
    connection someone else owns is indistinguishable from a missing one."""
    record = store.get_connection(connection_id)
    if record is None or not can_read_connection(scope, record):
        return None
    return record


async def delete_connection(registry: AdapterRegistry, store: AiStore, scope: Scope, connection_id: str) -> bool:
    """Unbind a connection ``scope`` owns (the seeded demo: operator only).
    ``False`` means not found *or* not yours — callers answer 404 either way.
    Closes and unregisters the live adapter so the credential leaves memory."""
    record = store.get_connection(connection_id)
    if record is None or not can_delete_connection(scope, record):
        return False
    if not store.delete_connection(connection_id):
        return False
    adapter = registry.get(record.registry_key)
    registry.unregister(record.registry_key)
    if adapter is not None:
        try:
            await adapter.disconnect()
        except Exception:  # best effort: the record is gone either way
            logger.warning("ai_connection_disconnect_failed", connection_id=connection_id)
    return True


def _not_found(connection_id: str) -> ConnectionLifecycleError:
    return ConnectionLifecycleError(404, f"Connection '{connection_id}' not found.")


def _manageable(store: AiStore, scope: Scope, connection_id: str) -> ConnectionRecord:
    record = store.get_connection(connection_id)
    if record is None or not can_delete_connection(scope, record):
        raise _not_found(connection_id)
    return record


async def _close(adapter: Any, connection_id: str) -> None:
    if adapter is None:
        return
    try:
        await adapter.disconnect()
    except Exception:  # best effort: the credential has left the registry either way
        logger.warning("ai_connection_disconnect_failed", connection_id=connection_id)


async def rotate_connection(
    registry: AdapterRegistry, store: AiStore, scope: Scope, connection_id: str, *, user: str, password: str,
) -> ConnectionRecord:
    """Replace a connection's credentials. Owner (or operator) only.

    The new credentials are **proven against the target first**; only then is the live
    adapter swapped (same registry key), so a mistyped password never takes a working
    connection down. Because a bound connection's password is never persisted, this is also
    how a connection is re-supplied with credentials after a restart. ``user`` is required
    every time for the same reason (only host/port/database/ssl_mode are stored).

    Errors: 404 (missing or not yours), 409 (revoked — permanent; or the env-seeded demo,
    whose credentials come from ``NEURALBRIDGE_AI_PG_*``), 422 (the target did not accept the
    new credentials; the old ones are untouched). The password appears in no error text."""
    record = _manageable(store, scope, connection_id)
    if record.status == REVOKED:
        raise ConnectionLifecycleError(409, f"Connection '{connection_id}' has been revoked; bind a new one.")
    if record.source == "seeded_from_env":
        raise ConnectionLifecycleError(
            409, "The seeded demo connection takes its credentials from NEURALBRIDGE_AI_PG_*; change them there.")
    cfg = record.config
    if not all(k in cfg for k in ("host", "port", "database")):
        raise ConnectionLifecycleError(409, f"Connection '{connection_id}' has no stored target to rotate.")
    candidate = PostgresAdapter(config={
        "host": cfg["host"], "port": cfg["port"], "database": cfg["database"],
        "ssl_mode": cfg.get("ssl_mode", "prefer"), "user": user, "password": password,
    })
    result = await candidate.connect()
    if not result.success:
        await _close(candidate, connection_id)
        logger.warning("ai_connection_rotate_rejected", connection_id=connection_id)
        raise ConnectionLifecycleError(
            422, "The target did not accept the new credentials (or could not be reached); "
                 "the existing credentials were left unchanged.")
    previous = registry.get(record.registry_key)
    registry.register(candidate, key=record.registry_key)
    updated = store.update_connection(
        connection_id, status="rotated",
        config_updates={"credential_rotated_at": datetime.now(UTC).isoformat()},
    )
    if updated is None or updated.status == REVOKED:  # revoked/deleted while we were connecting
        registry.unregister(record.registry_key)
        await _close(candidate, connection_id)
        raise ConnectionLifecycleError(409, f"Connection '{connection_id}' was revoked or removed meanwhile.")
    if previous is not candidate:
        await _close(previous, connection_id)
    return updated


async def revoke_connection(
    registry: AdapterRegistry, store: AiStore, scope: Scope, connection_id: str, *, by: str,
) -> bool:
    """Revoke a connection, permanently. Owner (or operator; the demo: operator only).

    Effective on the **next call**: the revoked status is stored, and every read, plan and
    approval re-reads it, so it holds in every worker process. Pending plans against the
    connection are denied in the same transaction; this process's live adapter is closed
    and unregistered. Idempotent: returns ``False`` if it was already revoked."""
    record = _manageable(store, scope, connection_id)
    changed = store.revoke_connection(connection_id, by=by)
    if changed is None:
        raise _not_found(connection_id)
    adapter = registry.get(record.registry_key)
    registry.unregister(record.registry_key)
    await _close(adapter, connection_id)
    return changed
