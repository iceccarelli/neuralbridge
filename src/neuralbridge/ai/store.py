"""Durable storage for /ai — connections and plans survive a restart.

Same pattern as `assurance.billing.accounts.AccountStore`: SQLite,
`BEGIN IMMEDIATE` transactions, a schema-version guard. Not hash-chained —
this is operational state (what's pending approval, what connections
exist), not the evidence ledger; the assurance product's own ledger
(`assurance.evidence.ledger`) is the tamper-evident record and is
untouched by this module. What is stored here: connection metadata
(never the raw credential — see `AiConnectionStore.create`) and plan
records (proposed/approved/denied/executed operations, including their
SQL text, since that *is* the thing an operator needs to review on
restart to see what they're approving).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connections (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    adapter_type  TEXT NOT NULL,
    registry_key  TEXT NOT NULL,
    config_json   TEXT NOT NULL DEFAULT '{}',
    source        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'created',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
    id              TEXT PRIMARY KEY,
    connection_id   TEXT NOT NULL,
    adapter_type    TEXT NOT NULL,
    operation       TEXT NOT NULL,
    operation_class TEXT NOT NULL,
    params_json     TEXT NOT NULL,
    proposed_by     TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    decided_by      TEXT,
    decided_at      TEXT,
    deny_reason     TEXT
);
CREATE INDEX IF NOT EXISTS plans_by_connection ON plans (connection_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class ConnectionRecord:
    id: str
    name: str
    adapter_type: str
    registry_key: str
    source: str
    status: str = "created"
    description: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ConnectionRecord:
        return cls(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            adapter_type=row["adapter_type"],
            registry_key=row["registry_key"],
            config=json.loads(row["config_json"]),
            source=row["source"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass
class PlanRecord:
    id: str
    connection_id: str
    adapter_type: str
    operation: str
    operation_class: str
    params: dict[str, Any]
    proposed_by: str
    status: str = "pending_approval"
    created_at: str = field(default_factory=_now)
    decided_by: str | None = None
    decided_at: str | None = None
    deny_reason: str | None = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> PlanRecord:
        return cls(
            id=row["id"],
            connection_id=row["connection_id"],
            adapter_type=row["adapter_type"],
            operation=row["operation"],
            operation_class=row["operation_class"],
            params=json.loads(row["params_json"]),
            proposed_by=row["proposed_by"],
            status=row["status"],
            created_at=row["created_at"],
            decided_by=row["decided_by"],
            decided_at=row["decided_at"],
            deny_reason=row["deny_reason"],
        )


class AiStore:
    """One SQLite file backing both connections and plans for /ai."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        db = self._connect()
        try:
            db.executescript(_SCHEMA)
            row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                db.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
                db.commit()
            elif int(row[0]) != SCHEMA_VERSION:
                raise RuntimeError(
                    f"{self.path} was written by ai-store schema {row[0]}; this build speaks "
                    f"{SCHEMA_VERSION}. Refusing rather than guessing."
                )
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        if str(self.path) != ":memory:":
            db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
            finally:
                db.close()

    # -- connections --------------------------------------------------

    def create_connection(self, record: ConnectionRecord) -> None:
        with self._txn() as db:
            db.execute(
                "INSERT INTO connections (id, name, description, adapter_type, registry_key, "
                "config_json, source, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id, record.name, record.description, record.adapter_type,
                    record.registry_key, json.dumps(record.config), record.source,
                    record.status, record.created_at, record.updated_at,
                ),
            )

    def list_connections(self) -> list[ConnectionRecord]:
        db = self._connect()
        try:
            rows = db.execute("SELECT * FROM connections ORDER BY created_at").fetchall()
            return [ConnectionRecord.from_row(r) for r in rows]
        finally:
            db.close()

    def get_connection(self, connection_id: str) -> ConnectionRecord | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
            return ConnectionRecord.from_row(row) if row else None
        finally:
            db.close()

    def has_any_connection_of_type(self, adapter_type: str) -> bool:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT 1 FROM connections WHERE adapter_type=? LIMIT 1", (adapter_type,)
            ).fetchone()
            return row is not None
        finally:
            db.close()

    # -- plans ----------------------------------------------------------

    def create_plan(self, record: PlanRecord) -> None:
        with self._txn() as db:
            db.execute(
                "INSERT INTO plans (id, connection_id, adapter_type, operation, operation_class, "
                "params_json, proposed_by, status, created_at, decided_by, decided_at, deny_reason) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id, record.connection_id, record.adapter_type, record.operation,
                    record.operation_class, json.dumps(record.params), record.proposed_by,
                    record.status, record.created_at, record.decided_by, record.decided_at,
                    record.deny_reason,
                ),
            )

    def get_plan(self, plan_id: str) -> PlanRecord | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            return PlanRecord.from_row(row) if row else None
        finally:
            db.close()

    def list_plans(self, *, limit: int = 50) -> list[PlanRecord]:
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT * FROM plans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [PlanRecord.from_row(r) for r in rows]
        finally:
            db.close()

    def update_plan_status(
        self, plan_id: str, *, status: str, decided_by: str | None = None,
        decided_at: str | None = None, deny_reason: str | None = None,
    ) -> PlanRecord:
        with self._txn() as db:
            db.execute(
                "UPDATE plans SET status=?, decided_by=COALESCE(?, decided_by), "
                "decided_at=COALESCE(?, decided_at), deny_reason=COALESCE(?, deny_reason) WHERE id=?",
                (status, decided_by, decided_at, deny_reason, plan_id),
            )
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if row is None:
                raise KeyError(plan_id)
            return PlanRecord.from_row(row)


def new_id() -> str:
    return str(uuid.uuid4())


__all__ = ["AiStore", "ConnectionRecord", "PlanRecord", "new_id", "SCHEMA_VERSION"]
