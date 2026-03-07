"""
NeuralBridge — Immutable, Hash-Chained Audit Logging for CRA Compliance.

This module provides a robust and secure system for creating and managing
immutable audit trails, a key requirement for compliance with regulations like
the Cyber Resilience Act (CRA).

The core components are:
- AuditEntry: A Pydantic model defining the structure of a single audit event.
- AuditStorage: An abstract base class defining the storage interface.
- InMemoryAuditStorage: A thread-safe, in-memory storage backend for
  development and testing.
- PostgresAuditStorage: A production-ready storage backend for PostgreSQL,
  designed to work with asyncpg.
- AuditLogger: The main interface for logging, querying, and exporting
  audit events. It uses a hash chain to ensure the integrity and
  tamper-resistance of the log.

Each log entry is cryptographically linked to the previous one, making it
computationally infeasible to alter past records without invalidating the
entire chain.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger(__name__)


class AuditEntry(BaseModel):
    """Represents a single, immutable entry in the audit log.

    This Pydantic model validates the structure of each audit event. The hash
    chain is implemented via the ``previous_hash`` and ``current_hash`` fields,
    linking each entry to its predecessor to ensure data integrity.

    Attributes:
        event_id: A unique identifier (UUIDv4) for the audit event.
        timestamp: The UTC timestamp when the event was created.
        event_type: A category for the event (e.g., 'auth', 'api_access').
        actor: The identifier of the user or system that initiated the event.
        resource: The resource that was affected.
        action: The specific action performed.
        result: The outcome of the action ('success', 'failure', 'pending').
        ip_address: The source IP address of the request, if applicable.
        details: A JSON object for storing arbitrary contextual information.
        previous_hash: The SHA-256 hash of the preceding audit entry.
        current_hash: The SHA-256 hash of this entry (excluding this field).
    """

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    event_type: str
    actor: str
    resource: str
    action: str
    result: str
    ip_address: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    current_hash: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc_timestamp(cls, v: Any) -> datetime:
        """Ensure the timestamp is timezone-aware and in UTC."""
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        if isinstance(v, datetime):
            return v
        return datetime.now(tz=UTC)

    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of the audit entry.

        The hash is computed over a canonical JSON representation of the
        entry, ensuring a consistent output. The ``current_hash`` field
        itself is excluded from the calculation.

        Returns:
            The hexadecimal SHA-256 hash of the entry's data.
        """
        hasher = hashlib.sha256()
        payload = self.model_dump_json(
            exclude={"current_hash"},
        ).encode("utf-8")
        hasher.update(payload)
        return hasher.hexdigest()


class AuditStorage(ABC):
    """Abstract base class for audit log storage backends.

    This protocol allows for interchangeable storage mechanisms (e.g.,
    in-memory, PostgreSQL) without changing the AuditLogger's core logic.
    """

    @abstractmethod
    async def add_event(self, entry: AuditEntry) -> None:
        """Atomically add a new audit entry to the storage.

        Args:
            entry: The ``AuditEntry`` object to be stored.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_last_event(self) -> AuditEntry | None:
        """Retrieve the most recent audit entry from the storage.

        Returns:
            An ``AuditEntry`` if the log is not empty, otherwise ``None``.
        """
        raise NotImplementedError

    @abstractmethod
    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AsyncGenerator[AuditEntry, None]:
        """Query audit events based on specified filter criteria.

        Args:
            actor: Filter events by the actor who performed them.
            event_type: Filter events by their type.
            start_time: Beginning of the time window (inclusive).
            end_time: End of the time window (inclusive).

        Yields:
            ``AuditEntry`` objects that match the query filters.
        """
        if False:  # pragma: no cover
            yield


class InMemoryAuditStorage(AuditStorage):
    """Thread-safe, in-memory storage backend for audit logs.

    Ideal for development, testing, or low-volume scenarios. All data is
    lost when the application restarts. Uses an ``asyncio.Lock`` to prevent
    race conditions during concurrent writes.
    """

    def __init__(self) -> None:
        self._log: list[AuditEntry] = []
        self._lock = asyncio.Lock()

    async def add_event(self, entry: AuditEntry) -> None:
        """Atomically append a new entry to the in-memory list."""
        async with self._lock:
            self._log.append(entry)
            logger.debug(
                "Appended new audit event to in-memory log",
                event_id=str(entry.event_id),
            )

    async def get_last_event(self) -> AuditEntry | None:
        """Retrieve the last entry from the list."""
        async with self._lock:
            if not self._log:
                return None
            return self._log[-1]

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AsyncGenerator[AuditEntry, None]:
        """Filter and yield events from the in-memory list."""
        async with self._lock:
            events = self._log.copy()

        for event in events:
            if actor and event.actor != actor:
                continue
            if event_type and event.event_type != event_type:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            yield event


class PostgresAuditStorage(AuditStorage):
    """Production-ready storage backend for PostgreSQL.

    This class provides the interface for persisting audit logs in a
    PostgreSQL database. It requires an ``asyncpg.Pool`` for connection
    management.
    """

    def __init__(self, pool: Any) -> None:
        self.pool = pool

    async def add_event(self, entry: AuditEntry) -> None:
        """Insert a new audit entry into the ``audit_log`` table."""
        query = """
            INSERT INTO audit_log (
                event_id, timestamp, event_type, actor, resource,
                action, result, ip_address, details,
                previous_hash, current_hash
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                query,
                entry.event_id,
                entry.timestamp,
                entry.event_type,
                entry.actor,
                entry.resource,
                entry.action,
                entry.result,
                entry.ip_address,
                json.dumps(entry.details),
                entry.previous_hash,
                entry.current_hash,
            )
        logger.info(
            "Stored new audit event in PostgreSQL",
            event_id=str(entry.event_id),
        )

    async def get_last_event(self) -> AuditEntry | None:
        """Retrieve the most recent entry from the ``audit_log`` table."""
        query = (
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 1;"
        )
        async with self.pool.acquire() as conn:
            record = await conn.fetchrow(query)
        return AuditEntry.model_validate(record) if record else None

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AsyncGenerator[AuditEntry, None]:
        """Query the ``audit_log`` table with filters and yield results."""
        conditions: list[str] = []
        params: list[Any] = []
        param_idx = 1

        if actor:
            conditions.append(f"actor = ${param_idx}")
            params.append(actor)
            param_idx += 1
        if event_type:
            conditions.append(f"event_type = ${param_idx}")
            params.append(event_type)
            param_idx += 1
        if start_time:
            conditions.append(f"timestamp >= ${param_idx}")
            params.append(start_time)
            param_idx += 1
        if end_time:
            conditions.append(f"timestamp <= ${param_idx}")
            params.append(end_time)
            param_idx += 1

        where = (
            f"WHERE {' AND '.join(conditions)}" if conditions else ""
        )
        query = (
            f"SELECT * FROM audit_log {where} ORDER BY timestamp ASC;"  # nosec B608
        )

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                async for record in conn.cursor(query, *params):
                    yield AuditEntry.model_validate(record)


class AuditLogger:
    """High-level, asynchronous interface for the audit logging system.

    This class orchestrates the creation, storage, and retrieval of audit
    events. It ensures the integrity of the log by managing the hash chain.

    Attributes:
        storage: The storage backend instance.
        genesis_hash: The seed hash for the very first entry in the log.
    """

    def __init__(
        self,
        storage: AuditStorage,
        genesis_hash: str = "neuralbridge_genesis_block_v1",
    ) -> None:
        self.storage = storage
        self.genesis_hash = hashlib.sha256(
            genesis_hash.encode(),
        ).hexdigest()
        logger.info(
            "AuditLogger initialized.",
            storage=storage.__class__.__name__,
        )

    async def log_event(
        self,
        event_type: str,
        actor: str,
        resource: str,
        action: str,
        result: str,
        ip_address: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Create, hash, and store a new audit event.

        Args:
            event_type: The category of the event.
            actor: The identifier of the user or system.
            resource: The resource being affected.
            action: The specific action performed.
            result: The outcome of the action.
            ip_address: The source IP address of the request.
            details: A dictionary of additional contextual data.

        Returns:
            The newly created and stored ``AuditEntry``.
        """
        last_event = await self.storage.get_last_event()
        previous_hash = (
            last_event.current_hash if last_event else self.genesis_hash
        )

        entry = AuditEntry(
            event_type=event_type,
            actor=actor,
            resource=resource,
            action=action,
            result=result,
            ip_address=ip_address,
            details=details or {},
            previous_hash=previous_hash or self.genesis_hash,
        )
        entry.current_hash = entry.calculate_hash()

        await self.storage.add_event(entry)
        logger.info(
            "Audit event logged successfully.",
            event_id=str(entry.event_id),
            actor=actor,
            action=action,
            resource=resource,
        )
        return entry

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> AsyncGenerator[AuditEntry, None]:
        """Query the audit log using various filters.

        Args:
            actor: Filter by actor ID.
            event_type: Filter by event type.
            start_time: The start of the time window.
            end_time: The end of the time window.

        Yields:
            Matching ``AuditEntry`` objects.
        """
        async for event in self.storage.query_events(
            actor=actor,
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
        ):
            yield event

    async def export_events(
        self,
        file_path: str,
        file_format: str = "json",
        **query_kwargs: Any,
    ) -> None:
        """Export queried audit events to a file in JSON or CSV format.

        Args:
            file_path: The path to the output file.
            file_format: The desired format ('json' or 'csv').
            **query_kwargs: Filtering criteria passed to ``query_events``.

        Raises:
            ValueError: If an unsupported file format is requested.
        """
        events = [
            event async for event in self.query_events(**query_kwargs)
        ]

        if file_format == "json":
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(
                    [e.model_dump(mode="json") for e in events],
                    f,
                    indent=2,
                )
        elif file_format == "csv":
            if not events:
                return
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=AuditEntry.model_fields.keys(),
                )
                writer.writeheader()
                for event in events:
                    writer.writerow(event.model_dump(mode="json"))
        else:
            raise ValueError(
                f"Unsupported export format: {file_format}",
            )

        logger.info(
            "Audit log exported.",
            path=file_path,
            format=file_format,
            count=len(events),
        )

    async def verify_integrity(self) -> bool:
        """Verify the integrity of the entire audit log hash chain.

        Iterates through all log entries and checks that each entry's
        ``previous_hash`` matches the ``current_hash`` of its predecessor.

        Returns:
            ``True`` if the chain is valid, ``False`` otherwise.
        """
        logger.warning(
            "Starting full audit log integrity verification.",
        )
        expected_hash = self.genesis_hash
        event_count = 0
        async for event in self.storage.query_events():
            event_count += 1
            if event.previous_hash != expected_hash:
                logger.error(
                    "Hash chain broken!",
                    event_id=str(event.event_id),
                    expected_hash=expected_hash,
                    found_hash=event.previous_hash,
                )
                return False

            recalculated_hash = event.calculate_hash()
            if recalculated_hash != event.current_hash:
                logger.error(
                    "Entry hash mismatch! Data may have been tampered.",
                    event_id=str(event.event_id),
                    expected_hash=event.current_hash,
                    recalculated_hash=recalculated_hash,
                )
                return False

            expected_hash = event.current_hash

        logger.info(
            "Audit log integrity verification successful.",
            checked_events=event_count,
        )
        return True
