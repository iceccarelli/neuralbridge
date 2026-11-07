"""
NeuralBridge — Durable, Hash-Chained Audit Logging for CRA Compliance.

This module provides the audit trail for the platform: who did what, to which
resource, for which tenant, with what outcome. Each entry is cryptographically
linked to the previous one, so altering a past record breaks the chain
(``AuditLogger.verify_integrity``).

Components:

- ``AuditEntry``: the structure of one audit event.
- ``AuditStorage``: the storage interface.
- ``SQLiteAuditStorage``: **the default**. A durable, append-only SQLite file
  (WAL, busy timeout, atomic chained append) that survives a restart and is safe
  for several worker processes writing at once.
- ``PostgresAuditStorage``: selectable (``NEURALBRIDGE_AUDIT_BACKEND=postgres``) for
  deployments that already run PostgreSQL; the chain is appended under an advisory lock.
- ``InMemoryAuditStorage``: tests and explicit opt-in only
  (``NEURALBRIDGE_AUDIT_BACKEND=memory``); everything is lost on restart.
- ``AuditLogger``: log / query / export / verify, plus ``health()`` and
  ``ensure_writable()`` so an unwritable sink is reported, never silent.

Configuration (environment)::

    NEURALBRIDGE_AUDIT_BACKEND   sqlite (default) | postgres | memory
    NEURALBRIDGE_AUDIT_DB        SQLite file. Default: "neuralbridge-audit.db" in the
                                 directory of NEURALBRIDGE_AI_STORE (or the working directory)
    NEURALBRIDGE_AUDIT_PG_DSN    PostgreSQL DSN when the backend is postgres (a secret)

Append-only semantics: the application only ever INSERTs; both SQL backends carry
triggers that abort UPDATE and DELETE, and the hash chain detects any edit made
around them. Retention: nothing here deletes or rotates records. Keep the file (or
table) for the retention period your obligations require (CRA technical documentation
is typically kept for years); archive by copying the file/table and starting a new
one at a documented cut-over, and keep the archived chain verifiable on its own.

No secret is ever written: ``redact`` masks credential-shaped keys and values in
every field before the entry is hashed and stored.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import os
import re
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger(__name__)

AUDIT_BACKEND_ENV = "NEURALBRIDGE_AUDIT_BACKEND"
AUDIT_DB_ENV = "NEURALBRIDGE_AUDIT_DB"
AUDIT_PG_DSN_ENV = "NEURALBRIDGE_AUDIT_PG_DSN"
DEFAULT_GENESIS = "neuralbridge_genesis_block_v1"
_PAGE = 1000


class AuditUnavailableError(RuntimeError):
    """The audit sink cannot record. Callers must not proceed as if it had."""


# ── Redaction ────────────────────────────────────────────────

_SECRET_KEY = re.compile(
    r"(pass(word|wd)?$|passphrase|secret|token|api[_-]?key|authorization|auth[_-]?header|"
    r"credential|private[_-]?key|dsn|cookie|session[_-]?key)",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"
_TEXT_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"), r"\1" + _REDACTED + "@"),
    (re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE), r"\1 " + _REDACTED),
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)(\"?\s*[=:]\s*\"?)[^\s,;\"'&]+"),
        r"\1\2" + _REDACTED,
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), _REDACTED),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"), _REDACTED),
    (re.compile(r"\bnbk_[A-Za-z0-9_-]{8,}"), _REDACTED),
]
_MAX_TEXT = 4096
_MAX_DEPTH = 8


def redact_text(text: str) -> str:
    """Mask credential-shaped substrings (URL passwords, bearer/basic tokens,
    ``password=...`` pairs, JWTs, Stripe-style keys) and cap the length."""
    for pattern, replacement in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT] + "...[truncated]"
    return text


def redact(value: Any, _depth: int = 0) -> Any:
    """Recursively mask secrets: any value under a credential-looking key, and
    credential-looking substrings of every string. Pure; returns a copy."""
    if _depth > _MAX_DEPTH:
        return _REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            str(k): (_REDACTED if _SECRET_KEY.search(str(k)) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(v, _depth + 1) for v in value]
    return value


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
        if isinstance(v, str):  # reading a stored entry back: keep its time, never "now"
            try:
                v = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(tz=UTC)
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
    """Abstract base class for audit log storage backends."""

    #: True when records survive a process restart.
    durable: bool = False
    backend: str = "abstract"

    @abstractmethod
    async def add_event(self, entry: AuditEntry) -> None:
        """Add an already-chained entry. Prefer :meth:`append_chained`."""
        raise NotImplementedError

    @abstractmethod
    async def get_last_event(self) -> AuditEntry | None:
        """Retrieve the most recent audit entry, or ``None`` for an empty log."""
        raise NotImplementedError

    async def append_chained(
        self, genesis_hash: str, build: Callable[[str], AuditEntry],
    ) -> AuditEntry:
        """Read the chain head, build the next entry from it and store it as one
        atomic step. Backends shared between workers override this so two writers
        can never both extend the same head; this default is read-then-write and
        is only correct for a single writer."""
        last = await self.get_last_event()
        entry = build((last.current_hash if last else None) or genesis_hash)
        await self.add_event(entry)
        return entry

    async def check_writable(self) -> None:
        """Raise :class:`AuditUnavailableError` unless a record could be written now,
        without writing one."""
        return None

    def describe(self) -> dict[str, Any]:
        """Non-secret description for health output."""
        return {"backend": self.backend, "durable": self.durable}

    @abstractmethod
    def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        owner: str | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> AsyncGenerator[AuditEntry, None]:
        """Yield entries matching the filters (oldest first unless ``newest_first``).

        ``owner`` matches ``details["owner"]`` exactly; ``limit`` caps the count."""
        raise NotImplementedError


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _ts_key(value: datetime) -> str:
    """Fixed-width UTC text that sorts and compares lexicographically."""
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _matches(
    e: AuditEntry, actor: str | None, event_type: str | None,
    start_time: datetime | None, end_time: datetime | None, owner: str | None,
) -> bool:
    if actor and e.actor != actor:
        return False
    if event_type and e.event_type != event_type:
        return False
    if start_time and _utc(e.timestamp) < _utc(start_time):
        return False
    if end_time and _utc(e.timestamp) > _utc(end_time):
        return False
    return not (owner is not None and e.details.get("owner") != owner)


class InMemoryAuditStorage(AuditStorage):
    """In-memory storage: tests and explicit opt-in only. **All data is lost on restart.**"""

    backend = "memory"
    durable = False

    def __init__(self) -> None:
        self._log: list[AuditEntry] = []
        self._lock = asyncio.Lock()

    async def add_event(self, entry: AuditEntry) -> None:
        async with self._lock:
            self._log.append(entry)

    async def append_chained(
        self, genesis_hash: str, build: Callable[[str], AuditEntry],
    ) -> AuditEntry:
        async with self._lock:
            last = self._log[-1] if self._log else None
            entry = build((last.current_hash if last else None) or genesis_hash)
            self._log.append(entry)
            return entry

    async def get_last_event(self) -> AuditEntry | None:
        async with self._lock:
            return self._log[-1] if self._log else None

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        owner: str | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> AsyncGenerator[AuditEntry, None]:
        async with self._lock:
            events = self._log.copy()
        if newest_first:
            events.reverse()
        count = 0
        for event in events:
            if not _matches(event, actor, event_type, start_time, end_time, owner):
                continue
            if limit is not None and count >= limit:
                return
            count += 1
            yield event


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL UNIQUE,
    ts            TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    actor         TEXT NOT NULL,
    owner         TEXT,
    resource      TEXT NOT NULL,
    action        TEXT NOT NULL,
    result        TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash  TEXT NOT NULL,
    entry_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_owner ON audit_log (owner, seq);
CREATE INDEX IF NOT EXISTS audit_log_actor ON audit_log (actor, seq);
CREATE INDEX IF NOT EXISTS audit_log_type ON audit_log (event_type, seq);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log (ts);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""
SQLITE_SCHEMA_VERSION = "1"


class SQLiteAuditStorage(AuditStorage):
    """Durable, append-only audit storage in one SQLite file (the default).

    * WAL journal and a 30 s busy timeout; the open-time operations that SQLite
      does not wait for (switching to WAL) go through ``retry_locked``.
    * ``append_chained`` reads the head and inserts inside one ``BEGIN IMMEDIATE``
      transaction, so any number of threads or worker processes extend one linear
      chain: no fork, no duplicate ``previous_hash``.
    * Every call opens its own short-lived connection inside a worker thread, so the
      event loop is never blocked on disk and no connection is shared across threads.
    * UPDATE and DELETE are aborted by triggers.
    """

    backend = "sqlite"
    durable = True

    def __init__(self, path: str | Path) -> None:
        from assurance.core.sqlite import retry_locked

        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            db = self._connect()
            try:
                row = None
                has_meta = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_meta'"
                ).fetchone()
                if has_meta:
                    row = db.execute(
                        "SELECT value FROM audit_meta WHERE key='schema_version'"
                    ).fetchone()
                if row is not None and row[0] != SQLITE_SCHEMA_VERSION:
                    raise AuditUnavailableError(
                        f"{self.path} was written by audit schema {row[0]}; this build speaks "
                        f"{SQLITE_SCHEMA_VERSION}. Refusing rather than guessing."
                    )
                retry_locked(lambda: db.executescript(_SQLITE_SCHEMA), db=db)
                retry_locked(
                    lambda: db.execute(
                        "INSERT OR IGNORE INTO audit_meta (key, value) VALUES ('schema_version', ?)",
                        (SQLITE_SCHEMA_VERSION,),
                    ),
                    db=db,
                )
            finally:
                db.close()
        except AuditUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AuditUnavailableError(
                f"audit sink {self.path} cannot be opened: {type(exc).__name__}: {exc}"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        from assurance.core.sqlite import enable_wal

        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        enable_wal(db)
        return db

    def describe(self) -> dict[str, Any]:
        return {"backend": self.backend, "durable": True, "path": str(self.path)}

    # -- sync primitives (run in a worker thread) -----------------

    def _append_sync(self, genesis: str, build: Callable[[str], AuditEntry]) -> AuditEntry:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT current_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                entry = build(row[0] if row else genesis)
                owner = entry.details.get("owner")
                db.execute(
                    "INSERT INTO audit_log (event_id, ts, event_type, actor, owner, resource, "
                    "action, result, previous_hash, current_hash, entry_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(entry.event_id), _ts_key(entry.timestamp), entry.event_type, entry.actor,
                        str(owner) if owner else None, entry.resource, entry.action, entry.result,
                        entry.previous_hash, entry.current_hash, entry.model_dump_json(),
                    ),
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            return entry
        finally:
            db.close()

    def _last_sync(self) -> AuditEntry | None:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT entry_json FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            return AuditEntry.model_validate_json(row[0]) if row else None
        finally:
            db.close()

    def _page_sync(
        self, where: str, params: list[Any], *, after_seq: int | None, size: int, desc: bool,
    ) -> list[tuple[int, str]]:
        clauses = [where] if where else []
        args = list(params)
        if after_seq is not None:
            clauses.append("seq > ?")
            args.append(after_seq)
        sql = "SELECT seq, entry_json FROM audit_log"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += f" ORDER BY seq {'DESC' if desc else 'ASC'} LIMIT ?"  # nosec B608 - fixed text
        args.append(size)
        db = self._connect()
        try:
            return [(r[0], r[1]) for r in db.execute(sql, args).fetchall()]
        finally:
            db.close()

    def _check_sync(self) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")  # needs the write lock and a writable file
            db.execute("ROLLBACK")
        finally:
            db.close()

    # -- async interface -------------------------------------------

    async def append_chained(
        self, genesis_hash: str, build: Callable[[str], AuditEntry],
    ) -> AuditEntry:
        return await asyncio.to_thread(self._append_sync, genesis_hash, build)

    async def add_event(self, entry: AuditEntry) -> None:
        await self.append_chained(entry.previous_hash, lambda _prev: entry)

    async def get_last_event(self) -> AuditEntry | None:
        return await asyncio.to_thread(self._last_sync)

    async def check_writable(self) -> None:
        try:
            await asyncio.to_thread(self._check_sync)
        except (OSError, sqlite3.Error) as exc:
            raise AuditUnavailableError(
                f"audit sink {self.path} is not writable: {type(exc).__name__}: {exc}"
            ) from exc

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        owner: str | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> AsyncGenerator[AuditEntry, None]:
        conds: list[str] = []
        params: list[Any] = []
        if actor:
            conds.append("actor = ?")
            params.append(actor)
        if event_type:
            conds.append("event_type = ?")
            params.append(event_type)
        if start_time:
            conds.append("ts >= ?")
            params.append(_ts_key(start_time))
        if end_time:
            conds.append("ts <= ?")
            params.append(_ts_key(end_time))
        if owner is not None:
            conds.append("owner = ?")
            params.append(owner)
        where = " AND ".join(conds)
        if newest_first:
            rows = await asyncio.to_thread(
                self._page_sync, where, params, after_seq=None, size=-1 if limit is None else limit, desc=True,
            )
            for _seq, blob in rows:
                yield AuditEntry.model_validate_json(blob)
            return
        after: int | None = None
        remaining = limit
        while remaining is None or remaining > 0:
            size = _PAGE if remaining is None else min(_PAGE, remaining)
            rows = await asyncio.to_thread(
                self._page_sync, where, params, after_seq=after, size=size, desc=False,
            )
            if not rows:
                return
            for seq, blob in rows:
                after = seq
                yield AuditEntry.model_validate_json(blob)
            if remaining is not None:
                remaining -= len(rows)
            if len(rows) < size:
                return


_PG_LOCK_KEY = 7_021_904_113  # advisory-lock id for the audit chain / its DDL
_PG_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS nb_audit_log (
        seq           BIGSERIAL PRIMARY KEY,
        event_id      TEXT NOT NULL UNIQUE,
        ts            TIMESTAMPTZ NOT NULL,
        event_type    TEXT NOT NULL,
        actor         TEXT NOT NULL,
        owner         TEXT,
        resource      TEXT NOT NULL,
        action        TEXT NOT NULL,
        result        TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash  TEXT NOT NULL,
        entry_json    TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS nb_audit_log_owner ON nb_audit_log (owner, seq)",
    "CREATE INDEX IF NOT EXISTS nb_audit_log_ts ON nb_audit_log (ts)",
    """CREATE OR REPLACE FUNCTION nb_audit_log_immutable() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION 'nb_audit_log is append-only'; END; $$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS nb_audit_log_no_change ON nb_audit_log",
    """CREATE TRIGGER nb_audit_log_no_change BEFORE UPDATE OR DELETE ON nb_audit_log
       FOR EACH ROW EXECUTE FUNCTION nb_audit_log_immutable()""",
]


class PostgresAuditStorage(AuditStorage):
    """PostgreSQL audit storage (``NEURALBRIDGE_AUDIT_BACKEND=postgres``).

    Pass an ``asyncpg`` pool, or a ``dsn`` (the pool is then created lazily on the
    running event loop and re-created if the loop changes). The table is
    ``nb_audit_log``; it is created on first use. Appends take a transaction-level
    advisory lock so concurrent writers extend one chain. UPDATE/DELETE are aborted
    by a trigger.
    """

    backend = "postgres"
    durable = True

    def __init__(self, pool: Any = None, *, dsn: str | None = None, max_size: int = 5) -> None:
        if pool is None and not dsn:
            raise AuditUnavailableError(
                f"the postgres audit backend needs {AUDIT_PG_DSN_ENV} (or an asyncpg pool)"
            )
        self.pool = pool
        self._dsn = dsn
        self._owns_pool = pool is None
        self._max_size = max_size
        self._loop: asyncio.AbstractEventLoop | None = None
        self._schema_ready = False

    def describe(self) -> dict[str, Any]:
        return {"backend": self.backend, "durable": True}

    async def _get_pool(self) -> Any:
        loop = asyncio.get_running_loop()
        if self._owns_pool and self.pool is not None and self._loop is not loop:
            try:
                self.pool.terminate()
            except Exception:  # pool of a dead loop; nothing more to do
                logger.warning("audit_pg_pool_discard_failed")
            self.pool = None
            self._schema_ready = False
        if self.pool is None:
            import asyncpg

            try:
                self.pool = await asyncpg.create_pool(
                    self._dsn, min_size=1, max_size=self._max_size, timeout=10, command_timeout=30,
                )
            except (OSError, asyncpg.PostgresError, TimeoutError) as exc:
                raise AuditUnavailableError(
                    f"audit sink (postgres) cannot connect: {type(exc).__name__}"
                ) from exc
            self._loop = loop
        if not self._schema_ready:
            async with self.pool.acquire() as conn, conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock($1)", _PG_LOCK_KEY)
                for statement in _PG_SCHEMA:
                    await conn.execute(statement)
            self._schema_ready = True
        return self.pool

    @staticmethod
    def _row_entry(row: Any) -> AuditEntry:
        return AuditEntry.model_validate_json(row["entry_json"])

    async def append_chained(
        self, genesis_hash: str, build: Callable[[str], AuditEntry],
    ) -> AuditEntry:
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", _PG_LOCK_KEY)
            row = await conn.fetchrow(
                "SELECT current_hash FROM nb_audit_log ORDER BY seq DESC LIMIT 1"
            )
            entry = build(row["current_hash"] if row else genesis_hash)
            owner = entry.details.get("owner")
            await conn.execute(
                "INSERT INTO nb_audit_log (event_id, ts, event_type, actor, owner, resource, "
                "action, result, previous_hash, current_hash, entry_json) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                str(entry.event_id), _utc(entry.timestamp), entry.event_type, entry.actor,
                str(owner) if owner else None, entry.resource, entry.action, entry.result,
                entry.previous_hash, entry.current_hash, entry.model_dump_json(),
            )
            return entry

    async def add_event(self, entry: AuditEntry) -> None:
        await self.append_chained(entry.previous_hash, lambda _prev: entry)

    async def get_last_event(self) -> AuditEntry | None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT entry_json FROM nb_audit_log ORDER BY seq DESC LIMIT 1")
        return self._row_entry(row) if row else None

    async def check_writable(self) -> None:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                ok = await conn.fetchval(
                    "SELECT has_table_privilege(current_user, 'nb_audit_log', 'INSERT') "
                    "AND current_setting('transaction_read_only') = 'off' AND NOT pg_is_in_recovery()"
                )
        except AuditUnavailableError:
            raise
        except Exception as exc:
            raise AuditUnavailableError(
                f"audit sink (postgres) is not writable: {type(exc).__name__}"
            ) from exc
        if not ok:
            raise AuditUnavailableError("audit sink (postgres) is read-only or lacks INSERT privilege")

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        owner: str | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> AsyncGenerator[AuditEntry, None]:
        conds: list[str] = []
        params: list[Any] = []

        def add(clause: str, value: Any) -> None:
            params.append(value)
            conds.append(clause.format(n=len(params)))

        if actor:
            add("actor = ${n}", actor)
        if event_type:
            add("event_type = ${n}", event_type)
        if start_time:
            add("ts >= ${n}", _utc(start_time))
        if end_time:
            add("ts <= ${n}", _utc(end_time))
        if owner is not None:
            add("owner = ${n}", owner)
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        order = "DESC" if newest_first else "ASC"
        tail = f" LIMIT {int(limit)}" if limit is not None else ""
        query = f"SELECT entry_json FROM nb_audit_log {where} ORDER BY seq {order}{tail}"  # nosec B608
        pool = await self._get_pool()
        async with pool.acquire() as conn, conn.transaction():
            async for record in conn.cursor(query, *params):
                yield self._row_entry(record)


class AuditLogger:
    """High-level, asynchronous interface for the audit logging system.

    Orchestrates creation, storage and retrieval of audit events and owns the
    hash chain. A sink that cannot record is **loud**: ``log_event`` raises
    :class:`AuditUnavailableError`, ``health()`` reports ``degraded`` with the
    reason, and ``ensure_writable()`` lets a caller refuse to act first.
    """

    def __init__(self, storage: AuditStorage, genesis_hash: str = DEFAULT_GENESIS) -> None:
        self.storage = storage
        self.genesis_hash = hashlib.sha256(genesis_hash.encode()).hexdigest()
        self._last_error: str | None = None
        self._last_error_at: str | None = None
        if not storage.durable:
            logger.warning(
                "audit_storage_not_durable",
                storage=storage.__class__.__name__,
                note="audit records are lost on restart",
            )

    # -- health ---------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Cheap, synchronous state: the sink description and the last write error."""
        info = self.storage.describe()
        info["status"] = "degraded" if self._last_error else "ok"
        if self._last_error:
            info["last_error"] = self._last_error
            info["last_error_at"] = self._last_error_at
        return info

    def _fail(self, exc: BaseException) -> AuditUnavailableError:
        reason = redact_text(f"{type(exc).__name__}: {exc}")
        self._last_error = reason
        self._last_error_at = datetime.now(UTC).isoformat()
        logger.critical("audit_sink_unwritable", reason=reason, storage=self.storage.__class__.__name__)
        if isinstance(exc, AuditUnavailableError):
            return exc
        return AuditUnavailableError(f"audit sink cannot record: {reason}")

    async def ensure_writable(self) -> None:
        """Probe the sink (no record written). Raises :class:`AuditUnavailableError`
        and marks the logger degraded if it cannot record; clears degradation if it can."""
        try:
            await self.storage.check_writable()
        except Exception as exc:
            raise self._fail(exc) from exc
        self._last_error = None
        self._last_error_at = None

    # -- write ----------------------------------------------------

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
        """Redact, chain, hash and durably store one event.

        Raises:
            AuditUnavailableError: the sink could not record it.
        """
        clean_details = redact(details or {})

        def build(previous_hash: str) -> AuditEntry:
            entry = AuditEntry(
                event_type=redact_text(event_type),
                actor=redact_text(actor),
                resource=redact_text(resource),
                action=redact_text(action),
                result=redact_text(result),
                ip_address=ip_address,
                details=clean_details,
                previous_hash=previous_hash,
            )
            entry.current_hash = entry.calculate_hash()
            return entry

        try:
            entry = await self.storage.append_chained(self.genesis_hash, build)
        except Exception as exc:
            raise self._fail(exc) from exc
        self._last_error = None
        self._last_error_at = None
        logger.info(
            "audit_event_logged",
            event_id=str(entry.event_id), event_type=entry.event_type, actor=entry.actor,
            action=entry.action, resource=entry.resource, result=entry.result,
        )
        return entry

    async def query_events(
        self,
        *,
        actor: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        owner: str | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> AsyncGenerator[AuditEntry, None]:
        """Query the audit log (see :meth:`AuditStorage.query_events`)."""
        async for event in self.storage.query_events(
            actor=actor, event_type=event_type, start_time=start_time, end_time=end_time,
            owner=owner, limit=limit, newest_first=newest_first,
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


# ── Configuration → storage ──────────────────────────────────

def default_audit_path() -> Path:
    """``NEURALBRIDGE_AUDIT_DB``, else ``neuralbridge-audit.db`` next to the /ai store."""
    explicit = os.environ.get(AUDIT_DB_ENV, "").strip()
    if explicit:
        return Path(explicit)
    store = os.environ.get("NEURALBRIDGE_AI_STORE", "neuralbridge-ai.db")
    return Path(store).parent / "neuralbridge-audit.db"


def build_audit_storage() -> AuditStorage:
    """The audit sink selected by the environment. Durable SQLite unless told otherwise.

    Raises:
        AuditUnavailableError: the configured sink cannot be opened, or the
            backend name is not one of ``sqlite``, ``postgres``, ``memory``.
    """
    backend = os.environ.get(AUDIT_BACKEND_ENV, "sqlite").strip().lower() or "sqlite"
    if backend == "sqlite":
        return SQLiteAuditStorage(default_audit_path())
    if backend == "postgres":
        return PostgresAuditStorage(dsn=os.environ.get(AUDIT_PG_DSN_ENV, "").strip() or None)
    if backend == "memory":
        return InMemoryAuditStorage()
    raise AuditUnavailableError(
        f"{AUDIT_BACKEND_ENV}={backend!r} is not one of sqlite, postgres, memory"
    )


def build_audit_logger() -> AuditLogger:
    """An :class:`AuditLogger` over :func:`build_audit_storage`."""
    return AuditLogger(storage=build_audit_storage())
