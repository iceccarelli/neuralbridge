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

A bound connection's credential is held by ``neuralbridge.ai.credentials`` (sealed in the shared
store and usable from every worker, or — only on explicit single-worker opt-in — process-local);
with neither configured, binding and rotating answer 503 rather than pretend.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import structlog

from neuralbridge.adapters.databases.postgres import PostgresAdapter
from neuralbridge.ai.credentials import (
    CUSTODY_PROCESS_LOCAL,
    CUSTODY_VAULT,
    SHARED,
    CredentialVault,
    CustodyError,
)
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


#: Roles whose membership lets SQL reach the server's filesystem or run OS commands.
_PRIVILEGED_MEMBERSHIPS = ("pg_execute_server_program", "pg_read_server_files", "pg_write_server_files")
# A fixed statement (nothing is interpolated). tests/test_ai_demo_role.py pins that it names every
# role in _PRIVILEGED_MEMBERSHIPS, so the two cannot drift apart.
_ROLE_PRIVILEGE_SQL = (
    "SELECT r.rolsuper AS superuser, "
    "pg_has_role(current_user, 'pg_execute_server_program', 'member') AS pg_execute_server_program, "
    "pg_has_role(current_user, 'pg_read_server_files', 'member') AS pg_read_server_files, "
    "pg_has_role(current_user, 'pg_write_server_files', 'member') AS pg_write_server_files "
    "FROM pg_roles r WHERE r.rolname = current_user"
)
_ROLE_CHECK_TTL_S = 60.0
_role_state: dict[str, Any] = {"at": 0.0, "value": None}


async def inspect_role_privileges(config: dict[str, Any]) -> dict[str, Any]:
    """Is the role this connection logs in as a superuser or a server-file/program member?

    The /ai/read policy refuses file and program SQL, but a READ ONLY transaction does not stop
    ``COPY .. TO PROGRAM`` or ``pg_read_file`` and the demo is free and anonymous: the demo role
    must be a plain read-only role. Never raises and never hard-fails startup (CI's own Postgres
    service user is a superuser): the answer is ``{"checked": False}`` when it cannot ask.
    """
    import asyncpg  # local: only this check needs a direct (non-pooled) connection

    try:
        conn = await asyncpg.connect(
            host=config["host"], port=config["port"], user=config["user"], password=config.get("password", ""),
            database=config["database"], ssl=config.get("ssl_mode", "prefer"), timeout=3,
        )
    except Exception as exc:  # noqa: BLE001 - the class only: driver text carries host/user
        return {"checked": False, "privileged": None, "reason": f"could not connect ({type(exc).__name__})"}
    try:
        row = await conn.fetchrow(_ROLE_PRIVILEGE_SQL)
    except Exception as exc:  # noqa: BLE001
        return {"checked": False, "privileged": None, "reason": f"could not inspect role ({type(exc).__name__})"}
    finally:
        await conn.close()
    reasons = []
    if row is not None:
        if row["superuser"]:
            reasons.append("superuser")
        reasons.extend(m for m in _PRIVILEGED_MEMBERSHIPS if row[m])
    return {"checked": True, "privileged": bool(reasons), "reasons": reasons}


async def check_seeded_role(*, force: bool = False) -> dict[str, Any] | None:
    """Inspect the env-seeded demo role (cached ~60 s); ``None`` when no DSN is configured.
    Logs a warning every time a fresh check finds it privileged."""
    import time

    config = _pg_config_from_env()
    if config is None:
        return None
    now = time.monotonic()
    cached: dict[str, Any] | None = _role_state["value"]
    if not force and cached is not None and now - _role_state["at"] < _ROLE_CHECK_TTL_S:
        return cached
    result = await inspect_role_privileges(config)
    if result.get("privileged"):
        logger.warning(
            "ai_demo_role_privileged", reasons=result["reasons"],
            detail="the seeded /ai demo role can reach server files or programs; use a plain read-only role "
                   "(docs/ai-local-setup.md)",
        )
    _role_state.update(at=now, value=result)
    return result


def register_seeded_adapter(registry: AdapterRegistry) -> bool:
    """Make sure THIS process holds the live adapter for the seeded connection.

    The connection record lives in the shared SQLite store, but the adapter (with its pool) is
    per process, built from ``NEURALBRIDGE_AI_PG_*``. Under ``uvicorn --workers N`` only the worker
    that happened to serve ``GET /ai/connections`` used to register it, so a read or an approval
    that landed on another worker answered 409 "no live adapter" (tests/test_multiworker_real.py).
    Idempotent; ``False`` when no DSN is configured (the honest answer, not a mock).
    """
    if SEEDED_REGISTRY_KEY in registry:
        return True
    config = _pg_config_from_env()
    if config is None:
        return False
    registry.register(PostgresAdapter(config=config), key=SEEDED_REGISTRY_KEY)
    return True


def ensure_seeded_connection(registry: AdapterRegistry, store: AiStore) -> str | None:
    """Idempotently persist + register one postgres connection from env.

    Returns the connection id if a seeded connection exists (freshly
    created or already there from a prior run), or ``None`` if no DSN is
    configured — the honest answer, matching this repo's fail-closed
    pattern rather than falling back to mock data.
    """
    for record in store.list_connections():
        if record.source == "seeded_from_env":
            register_seeded_adapter(registry)
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
    vault: CredentialVault,
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
    entitlement, callers must.

    Raises :class:`CustodyError` (503) when no safe custody is configured. In shared mode the
    credential is sealed and stored, the journal records the creation BEFORE the store does, and
    the new connection is usable from every worker at once."""
    if not owner:
        raise ValueError("a bound connection must have an owner")
    mode = vault.require_available()
    connection_id = new_id()
    registry_key = f"postgres:{connection_id}"
    target = {"host": host, "port": port, "database": database, "ssl_mode": ssl_mode}
    adapter_config = {**target, "user": user, "password": password}
    record = ConnectionRecord(
        id=connection_id,
        name=name,
        description="Bound via POST /ai/connections.",
        adapter_type="postgres",
        registry_key=registry_key,
        # The password is never in this record or in any plaintext column: only the non-secret target.
        config=dict(target),
        source="bound_by_operator",
        status="created",
        owner=owner,
        custody=CUSTODY_VAULT if mode == SHARED else CUSTODY_PROCESS_LOCAL,
        cred_version=1 if mode == SHARED else 0,
    )
    if mode == SHARED:
        sealed = vault.seal(owner=owner, connection_id=connection_id, version=1, target=target,
                            user=user, password=password)
        journal_id = vault.journal.append("create", connection_id=connection_id, owner=owner, version=1)
        vault.record_journal_id(journal_id)
        store.create_connection(record, credential=sealed)
        registry.register(PostgresAdapter(config=adapter_config), key=registry_key, version=1)
    else:
        registry.register(PostgresAdapter(config=adapter_config), key=registry_key)
        store.create_connection(record)
    return record


def list_connections(
    registry: AdapterRegistry, store: AiStore, scope: Scope, vault: CredentialVault | None = None,
    *, four_eyes: bool = False,
) -> list[ConnectionSummary]:
    """Connections ``scope`` may see — its own plus the shared seeded demo
    (operator: all). Reads the durable store, seeding postgres if configured.
    Never returns anything but id/name/type/status/source/live/custody: no config, no
    credential, no registry key, no owner. ``live`` says whether this process holds the adapter;
    ``usable`` whether any worker could use it now."""
    ensure_seeded_connection(registry, store)
    out = []
    for r in store.list_connections():
        if not can_read_connection(scope, r):
            continue
        vaulted = r.custody == CUSTODY_VAULT
        held = registry.get(r.registry_key) is not None  # this process only
        out.append(ConnectionSummary(
            id=r.id,
            name=r.name,
            adapter_type=r.adapter_type,
            status=REVOKED if _tombstoned(vault, r) else r.status,
            source=r.source,
            live=registry.get(r.registry_key) is not None,
            custody="env" if r.source == "seeded_from_env" else r.custody,
            usable=bool(vault is not None and vault.usable(r)) if vaulted else held,
            cred_version=r.cred_version if vaulted else None,
            four_eyes=four_eyes,
        ))
    return out


def _tombstoned(vault: CredentialVault | None, record: ConnectionRecord) -> bool:
    """Does the anti-rollback journal say this (vault) connection is revoked or deleted, whatever a
    restored store claims?"""
    if vault is None or record.custody != CUSTODY_VAULT or record.status == REVOKED:
        return False
    try:
        vault.authorize(record)
    except CustodyError as exc:
        return exc.code == "revoked"
    return False


def get_connection(store: AiStore, scope: Scope, connection_id: str) -> ConnectionRecord | None:
    """The connection if ``scope`` may see it; ``None`` otherwise — a
    connection someone else owns is indistinguishable from a missing one."""
    record = store.get_connection(connection_id)
    if record is None or not can_read_connection(scope, record):
        return None
    return record


def _journal_best_effort(vault: CredentialVault, op: str, record: ConnectionRecord) -> bool:
    """Record a shrinking action (revoke, delete) in the journal. Revocation must work even when the
    journal cannot be written, so a failure is logged loudly and reported, not raised."""
    if record.custody != CUSTODY_VAULT or vault.config.journal is None:
        return True
    try:
        vault.journal.append(op, connection_id=record.id, owner=record.owner, version=record.cred_version)
        return True
    except CustodyError:
        logger.error("ai_credential_journal_write_failed", op=op, connection_id=record.id)
        return False


async def delete_connection(
    registry: AdapterRegistry, store: AiStore, scope: Scope, connection_id: str, vault: CredentialVault | None = None,
) -> bool:
    """Unbind a connection ``scope`` owns (the seeded demo: operator only).
    ``False`` means not found *or* not yours — callers answer 404 either way.
    Closes and unregisters the live adapter so the credential leaves memory, and removes the
    stored ciphertext in the same transaction as the record."""
    record = store.get_connection(connection_id)
    if record is None or not can_delete_connection(scope, record):
        return False
    if vault is not None:
        _journal_best_effort(vault, "delete", record)
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
    vault: CredentialVault,
) -> ConnectionRecord:
    """Replace a connection's credentials. Owner (or operator) only.

    The new credentials are **proven against the target first**; only then are they stored and the
    live adapter swapped (same registry key), so a mistyped password never takes a working
    connection down. In shared custody the new version is sealed, written to the anti-rollback
    journal and installed with a compare-and-set on the version, so concurrent rotations on
    different workers cannot both win; every other worker rebuilds its adapter from the new
    ciphertext on its next use. This is also how a connection bound under process-local custody (or
    restored from an older backup) is re-supplied with credentials. ``user`` is required every time
    (only host/port/database/ssl_mode are stored).

    Errors: 404 (missing or not yours), 409 (revoked — permanent; the env-seeded demo; or lost a
    race with another rotation), 422 (the target did not accept the new credentials; the old ones
    are untouched), 503 (no safe custody configured)."""
    record = _manageable(store, scope, connection_id)
    if record.status == REVOKED:
        raise ConnectionLifecycleError(409, f"Connection '{connection_id}' has been revoked; bind a new one.")
    if record.source == "seeded_from_env":
        raise ConnectionLifecycleError(
            409, "The seeded demo connection takes its credentials from NEURALBRIDGE_AI_PG_*; change them there.")
    cfg = record.config
    if not all(k in cfg for k in ("host", "port", "database")):
        raise ConnectionLifecycleError(409, f"Connection '{connection_id}' has no stored target to rotate.")
    mode = vault.require_available()
    if mode == SHARED and record.custody == CUSTODY_VAULT:
        try:
            vault.authorize(record)
        except CustodyError as exc:
            # A rollback is exactly what rotation repairs; a revocation (per the journal) is final.
            if exc.code == "revoked":
                raise ConnectionLifecycleError(
                    409, f"Connection '{connection_id}' has been revoked; bind a new one.") from exc
            if exc.code not in ("credential_rolled_back", "credential_missing"):
                raise
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
    updated: ConnectionRecord | None
    if mode == SHARED:
        try:
            if record.custody == CUSTODY_VAULT:
                version = vault.next_version(record)
            else:  # moving a process-local (or legacy) connection into the vault: the journal must know it
                version = 1
                journal_id = vault.journal.append("create", connection_id=record.id, owner=record.owner, version=1)
                vault.record_journal_id(journal_id)
            sealed = vault.seal(owner=record.owner, connection_id=record.id, version=version, target=cfg,
                                user=user, password=password)
            journal_id = vault.journal.append("rotate", connection_id=record.id, owner=record.owner, version=version)
            vault.record_journal_id(journal_id)
            updated = store.rotate_credential(
                record.id, expected_version=record.cred_version, credential=sealed,
                config_updates={"credential_rotated_at": datetime.now(UTC).isoformat()})
        except CustodyError:
            await _close(candidate, connection_id)
            raise
        except ValueError as exc:
            await _close(candidate, connection_id)
            raise ConnectionLifecycleError(409, f"Connection '{connection_id}' changed meanwhile; retry.") from exc
        if updated is None:
            await _close(candidate, connection_id)
            raise ConnectionLifecycleError(
                409, f"Connection '{connection_id}' was rotated, revoked or removed by another request meanwhile.")
        registry.register(candidate, key=record.registry_key, version=updated.cred_version)
    else:
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
    vault: CredentialVault | None = None,
) -> bool:
    """Revoke a connection, permanently. Owner (or operator; the demo: operator only).

    Effective on the **next call** in every worker: the revoked status is stored (and written to
    the anti-rollback journal first), the stored ciphertext is deleted in the same transaction, and
    every read, plan and approval re-reads the record, drops a stale local adapter and refuses.
    Pending plans against the connection are denied in the same transaction; this process's live
    adapter is closed and unregistered. Idempotent: returns ``False`` if it was already revoked."""
    record = _manageable(store, scope, connection_id)
    if vault is not None:
        _journal_best_effort(vault, "revoke", record)
    changed = store.revoke_connection(connection_id, by=by)
    if changed is None:
        raise _not_found(connection_id)
    adapter = registry.get(record.registry_key)
    registry.unregister(record.registry_key)
    await _close(adapter, connection_id)
    return changed
