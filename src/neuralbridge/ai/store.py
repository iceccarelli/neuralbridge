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

from assurance.core.sqlite import enable_wal, retry_locked

#: v2 (tenant isolation): ``owner`` added to ``connections`` and ``plans``.
#: A v1 file is migrated additively in place — existing rows get owner ``''``
#: (legacy: operator-visible only; see ``neuralbridge.ai.tenancy``).
#: v3 (credential custody, four-eyes, shared rate windows): ``custody`` / ``cred_version`` on
#: ``connections``; approval identity, ``four_eyes`` and ``expires_at`` on ``plans``; new tables
#: ``credentials`` (AEAD ciphertext only), ``tenant_policy`` and ``rate_windows``. Additive, so a
#: v1/v2 file is migrated in place and an older build refuses a v3 file rather than guessing.
SCHEMA_VERSION = 3
_READABLE_VERSIONS = (1, 2, 3)

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
    updated_at    TEXT NOT NULL,
    owner         TEXT NOT NULL DEFAULT ''
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
    deny_reason     TEXT,
    owner           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS plans_by_connection ON plans (connection_id);
CREATE TABLE IF NOT EXISTS credentials (
    connection_id TEXT PRIMARY KEY,
    version       INTEGER NOT NULL,
    owner         TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    nonce         BLOB NOT NULL,
    ciphertext    BLOB NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_policy (
    owner      TEXT PRIMARY KEY,
    four_eyes  INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_windows (
    key          TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    hits         INTEGER NOT NULL,
    PRIMARY KEY (key, window_start)
);
"""

#: Additive columns, added in place to a file written by an older build.
_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "connections": {
        "owner": "TEXT NOT NULL DEFAULT ''",
        "custody": "TEXT NOT NULL DEFAULT ''",
        "cred_version": "INTEGER NOT NULL DEFAULT 0",
    },
    "plans": {
        "owner": "TEXT NOT NULL DEFAULT ''",
        "four_eyes": "INTEGER NOT NULL DEFAULT 0",
        "expires_at": "TEXT",
        "proposed_key_ref": "TEXT NOT NULL DEFAULT ''",
        "proposed_operator": "TEXT NOT NULL DEFAULT ''",
        "decided_key_ref": "TEXT",
        "decided_operator": "TEXT",
    },
}

#: Once a plan is decided and finished, WHO decided and WHEN can no longer change (an approval
#: record is evidence). Releasing an in-flight claim (``approved`` -> ``pending_approval``) is the
#: one legitimate rewrite and is allowed because it only happens when nothing ran.
_IMMUTABLE_DECISION_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS plans_decision_immutable
BEFORE UPDATE OF decided_by, decided_at, decided_key_ref, decided_operator, proposed_by,
                 proposed_key_ref, proposed_operator, owner, four_eyes ON plans
WHEN OLD.status IN ('executed', 'failed', 'denied', 'expired')
  OR (OLD.status = 'approved' AND (NEW.decided_by IS NOT OLD.decided_by AND NEW.decided_by IS NOT NULL))
  OR (NEW.proposed_by IS NOT OLD.proposed_by OR NEW.proposed_key_ref IS NOT OLD.proposed_key_ref
      OR NEW.owner IS NOT OLD.owner OR NEW.four_eyes IS NOT OLD.four_eyes)
BEGIN
    SELECT RAISE(ABORT, 'plan identity and decision are immutable');
END;
"""

#: Created after the additive column migration so a v1 file (no ``owner``
#: column yet) does not fail on index creation.
_OWNER_INDEXES = """
CREATE INDEX IF NOT EXISTS connections_by_owner ON connections (owner);
CREATE INDEX IF NOT EXISTS plans_by_owner ON plans (owner);
"""


#: ``ConnectionRecord.status`` of a revoked connection — terminal, refuses every operation.
REVOKED = "revoked"


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
    #: Account id of the creator, from the validated principal. ``''`` is a
    #: legacy row written before owners existed (operator-visible only).
    owner: str = ""
    #: Where this connection's credential lives: ``"vault"`` (AEAD ciphertext in the ``credentials``
    #: table, usable from every worker), ``"process_local"`` (single-worker only, never stored) or
    #: ``""`` (the env-seeded demo, whose credential is ``NEURALBRIDGE_AI_PG_*``).
    custody: str = ""
    #: Monotonic credential version (bumped by every rotation); 0 = no stored credential.
    cred_version: int = 0

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
            owner=row["owner"],
            custody=row["custody"],
            cred_version=int(row["cred_version"]),
        )


@dataclass(frozen=True)
class CredentialRow:
    """One sealed credential: ciphertext only. The key is never in this database."""

    connection_id: str
    version: int
    owner: str
    key_id: str
    nonce: bytes
    ciphertext: bytes
    created_at: str = field(default_factory=_now)


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
    #: Account that proposed the plan — the only account that may approve it.
    owner: str = ""
    #: Four-eyes was in force when this was proposed: a different authenticated principal must approve.
    four_eyes: bool = False
    #: After this instant a four-eyes plan can no longer be approved (it becomes ``expired``).
    expires_at: str | None = None
    #: Fingerprint (SHA-256 prefix, never the key) of the API key that proposed / decided, and the
    #: operator the key is bound to, if any. Set server-side from the validated principal.
    proposed_key_ref: str = ""
    proposed_operator: str = ""
    decided_key_ref: str | None = None
    decided_operator: str | None = None

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
            owner=row["owner"],
            four_eyes=bool(row["four_eyes"]),
            expires_at=row["expires_at"],
            proposed_key_ref=row["proposed_key_ref"],
            proposed_operator=row["proposed_operator"],
            decided_key_ref=row["decided_key_ref"],
            decided_operator=row["decided_operator"],
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
            has_meta = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
            ).fetchone()
            if has_meta:
                row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                if row is not None and int(row[0]) not in _READABLE_VERSIONS:
                    raise RuntimeError(
                        f"{self.path} was written by ai-store schema {row[0]}; this build speaks "
                        f"{SCHEMA_VERSION}. Refusing rather than guessing."
                    )
            retry_locked(lambda: db.executescript(_SCHEMA), db=db)
            retry_locked(lambda: self._migrate(db), db=db)
            retry_locked(lambda: db.executescript(_OWNER_INDEXES), db=db)
            retry_locked(lambda: db.executescript(_IMMUTABLE_DECISION_TRIGGER), db=db)
        finally:
            db.close()

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """Additive v1/v2 -> v3: add the columns in ``_ADDED_COLUMNS`` to a file written by an older
        build, then stamp the version. Idempotent and safe to race (``BEGIN IMMEDIATE``). An
        up-to-date file takes no write lock."""
        def missing() -> bool:
            return any(
                column not in {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
                for table, columns in _ADDED_COLUMNS.items() for column in columns
            )

        current = db.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if current is not None and int(current[0]) == SCHEMA_VERSION and not missing():
            return
        db.execute("BEGIN IMMEDIATE")
        try:
            for table, columns in _ADDED_COLUMNS.items():
                have = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
                for column, ddl in columns.items():
                    if column not in have:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            db.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        if str(self.path) != ":memory:":
            enable_wal(db)
        db.execute("PRAGMA foreign_keys=ON")
        # Freed pages (a revoked or deleted credential's ciphertext) are overwritten with zeros.
        db.execute("PRAGMA secure_delete=ON")
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

    def create_connection(self, record: ConnectionRecord, credential: CredentialRow | None = None) -> None:
        """Insert a connection; with ``credential``, its sealed credential in the SAME transaction
        (a connection is never visible without the credential it claims to have)."""
        with self._txn() as db:
            db.execute(
                "INSERT INTO connections (id, name, description, adapter_type, registry_key, "
                "config_json, source, status, created_at, updated_at, owner, custody, cred_version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id, record.name, record.description, record.adapter_type,
                    record.registry_key, json.dumps(record.config), record.source,
                    record.status, record.created_at, record.updated_at, record.owner,
                    record.custody, record.cred_version,
                ),
            )
            if credential is not None:
                self._put_credential(db, credential)

    @staticmethod
    def _put_credential(db: sqlite3.Connection, c: CredentialRow) -> None:
        db.execute(
            "INSERT INTO credentials (connection_id, version, owner, key_id, nonce, ciphertext, created_at) "
            "VALUES (?,?,?,?,?,?,?) ON CONFLICT(connection_id) DO UPDATE SET version=excluded.version, "
            "owner=excluded.owner, key_id=excluded.key_id, nonce=excluded.nonce, "
            "ciphertext=excluded.ciphertext, created_at=excluded.created_at",
            (c.connection_id, c.version, c.owner, c.key_id, c.nonce, c.ciphertext, c.created_at),
        )

    def get_credential(self, connection_id: str) -> CredentialRow | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM credentials WHERE connection_id=?", (connection_id,)).fetchone()
            return None if row is None else CredentialRow(
                connection_id=row["connection_id"], version=int(row["version"]), owner=row["owner"],
                key_id=row["key_id"], nonce=bytes(row["nonce"]), ciphertext=bytes(row["ciphertext"]),
                created_at=row["created_at"])
        finally:
            db.close()

    def list_credentials(self) -> list[CredentialRow]:
        db = self._connect()
        try:
            return [
                CredentialRow(
                    connection_id=r["connection_id"], version=int(r["version"]), owner=r["owner"],
                    key_id=r["key_id"], nonce=bytes(r["nonce"]), ciphertext=bytes(r["ciphertext"]),
                    created_at=r["created_at"])
                for r in db.execute("SELECT * FROM credentials ORDER BY connection_id")
            ]
        finally:
            db.close()

    def rotate_credential(
        self, connection_id: str, *, expected_version: int, credential: CredentialRow,
        config_updates: dict[str, Any] | None = None,
    ) -> ConnectionRecord | None:
        """Install a new credential version: compare-and-set on the connection's current version, so
        of two concurrent rotations (any worker) exactly one wins and the other gets ``None``.
        The previous ciphertext is overwritten in the same transaction, and a revoked connection is
        never rotated (``None``)."""
        if credential.version <= expected_version:
            raise ValueError("a credential version only ever increases")
        with self._txn() as db:
            row = db.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
            if row is None:
                return None
            record = ConnectionRecord.from_row(row)
            if record.status == REVOKED or record.cred_version != expected_version:
                return None
            config = {**record.config, **(config_updates or {})}
            db.execute(
                "UPDATE connections SET status='rotated', custody='vault', cred_version=?, "
                "config_json=?, updated_at=? WHERE id=? AND cred_version=?",
                (credential.version, json.dumps(config), _now(), connection_id, expected_version),
            )
            self._put_credential(db, credential)
            return ConnectionRecord.from_row(
                db.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone())

    def reseal_credential(self, old: CredentialRow, new: CredentialRow) -> bool:
        """Replace ``old`` by ``new`` (same connection and version, a new key id / nonce / ciphertext)
        only if ``old`` is still what is stored. Used to re-encrypt under a new key."""
        if (old.connection_id, old.version) != (new.connection_id, new.version):
            raise ValueError("re-sealing keeps the connection and the version")
        with self._txn() as db:
            cur = db.execute(
                "UPDATE credentials SET key_id=?, nonce=?, ciphertext=? "
                "WHERE connection_id=? AND version=? AND key_id=? AND nonce=?",
                (new.key_id, new.nonce, new.ciphertext, old.connection_id, old.version, old.key_id, old.nonce),
            )
            return cur.rowcount == 1

    def delete_connection(self, connection_id: str) -> bool:
        """Remove a connection record. Plans still pending against it are
        denied (nothing may execute against an unbound connection); decided
        plans are kept as history. Returns whether a row was removed."""
        with self._txn() as db:
            db.execute(
                "UPDATE plans SET status='denied', decided_by='system:connection-deleted', "
                "decided_at=?, deny_reason='connection deleted' "
                "WHERE connection_id=? AND status='pending_approval'",
                (_now(), connection_id),
            )
            db.execute("DELETE FROM credentials WHERE connection_id=?", (connection_id,))
            cur = db.execute("DELETE FROM connections WHERE id=?", (connection_id,))
            return cur.rowcount > 0

    def update_connection(
        self, connection_id: str, *, status: str | None = None, config_updates: dict[str, Any] | None = None,
    ) -> ConnectionRecord | None:
        """Change a connection's status and/or merge non-secret keys into its config.
        A revoked connection is terminal: it is returned unchanged. ``None`` if missing."""
        with self._txn() as db:
            row = db.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
            if row is None:
                return None
            record = ConnectionRecord.from_row(row)
            if record.status == REVOKED:
                return record
            config = {**record.config, **(config_updates or {})}
            db.execute(
                "UPDATE connections SET status=?, config_json=?, updated_at=? WHERE id=?",
                (status or record.status, json.dumps(config), _now(), connection_id),
            )
            return ConnectionRecord.from_row(
                db.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone())

    def revoke_connection(self, connection_id: str, *, by: str) -> bool | None:
        """Revoke atomically: mark the connection ``revoked`` and deny every plan still
        pending against it, in one transaction. ``True`` = revoked now, ``False`` = it
        already was, ``None`` = no such connection."""
        with self._txn() as db:
            row = db.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
            if row is None:
                return None
            record = ConnectionRecord.from_row(row)
            if record.status == REVOKED:
                return False
            now = _now()
            db.execute(
                "UPDATE plans SET status='denied', decided_by='system:connection-revoked', "
                "decided_at=?, deny_reason='connection revoked' "
                "WHERE connection_id=? AND status='pending_approval'",
                (now, connection_id),
            )
            config = {**record.config, "revoked_at": now, "revoked_by": by}
            db.execute(
                "UPDATE connections SET status=?, config_json=?, updated_at=? WHERE id=?",
                (REVOKED, json.dumps(config), now, connection_id),
            )
            # A revoked connection keeps no credential: the ciphertext row is deleted (and, with
            # secure_delete, its pages zeroed) in the same transaction as the status change.
            db.execute("DELETE FROM credentials WHERE connection_id=?", (connection_id,))
            return True

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

    # -- small key/value facts ----------------------------------------

    def get_meta(self, key: str) -> str | None:
        db = self._connect()
        try:
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return None if row is None else str(row["value"])
        finally:
            db.close()

    def set_meta_if_absent(self, key: str, value: str) -> None:
        with self._txn() as db:
            db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING", (key, value))

    # -- tenant policy and shared rate windows --------------------------

    def get_tenant_policy(self, owner: str) -> bool | None:
        """The tenant's own four-eyes setting; ``None`` = never set (the default, off)."""
        db = self._connect()
        try:
            row = db.execute("SELECT four_eyes FROM tenant_policy WHERE owner=?", (owner,)).fetchone()
            return None if row is None else bool(row["four_eyes"])
        finally:
            db.close()

    def set_tenant_policy(self, owner: str, *, four_eyes: bool, by: str) -> None:
        with self._txn() as db:
            db.execute(
                "INSERT INTO tenant_policy (owner, four_eyes, updated_at, updated_by) VALUES (?,?,?,?) "
                "ON CONFLICT(owner) DO UPDATE SET four_eyes=excluded.four_eyes, "
                "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (owner, int(four_eyes), _now(), by),
            )

    def rate_hit(self, key: str, *, limit: int, window_s: int, now: float) -> tuple[bool, int]:
        """Count one hit for ``key`` in the current fixed window; say whether it is within ``limit``.

        One atomic upsert (``INSERT .. ON CONFLICT DO UPDATE .. RETURNING``) inside a ``BEGIN IMMEDIATE``
        transaction on the file every worker process shares, so the count is exact across processes
        and threads. Returns ``(allowed, hits_in_window)``. Fixed windows admit up to 2x ``limit``
        across a window boundary: the documented price of an exact, cheap counter."""
        start = int(now // window_s) * window_s
        with self._txn() as db:
            hits = int(db.execute(
                "INSERT INTO rate_windows (key, window_start, hits) VALUES (?,?,1) "
                "ON CONFLICT(key, window_start) DO UPDATE SET hits = hits + 1 RETURNING hits",
                (key, start),
            ).fetchone()[0])
            if hits == 1:  # first hit of a window for this key: drop windows nobody can still need
                db.execute("DELETE FROM rate_windows WHERE window_start < ?", (start - 2 * window_s,))
            return hits <= limit, hits

    # -- plans ----------------------------------------------------------

    def create_plan(self, record: PlanRecord) -> None:
        with self._txn() as db:
            db.execute(
                "INSERT INTO plans (id, connection_id, adapter_type, operation, operation_class, "
                "params_json, proposed_by, status, created_at, decided_by, decided_at, deny_reason, owner, "
                "four_eyes, expires_at, proposed_key_ref, proposed_operator) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id, record.connection_id, record.adapter_type, record.operation,
                    record.operation_class, json.dumps(record.params), record.proposed_by,
                    record.status, record.created_at, record.decided_by, record.decided_at,
                    record.deny_reason, record.owner, int(record.four_eyes), record.expires_at,
                    record.proposed_key_ref, record.proposed_operator,
                ),
            )

    def get_plan(self, plan_id: str) -> PlanRecord | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            return PlanRecord.from_row(row) if row else None
        finally:
            db.close()

    def list_plans(self, *, limit: int = 50, owner: str | None = None) -> list[PlanRecord]:
        """``owner=None`` lists every plan (operator); otherwise only that
        account's."""
        db = self._connect()
        try:
            if owner is None:
                rows = db.execute(
                    "SELECT * FROM plans ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM plans WHERE owner=? ORDER BY created_at DESC LIMIT ?",
                    (owner, limit),
                ).fetchall()
            return [PlanRecord.from_row(r) for r in rows]
        finally:
            db.close()

    def transition_plan(
        self, plan_id: str, *, expected: str, status: str, decided_by: str | None = None,
        decided_at: str | None = None, deny_reason: str | None = None, reset_decision: bool = False,
        decided_key_ref: str | None = None, decided_operator: str | None = None,
    ) -> PlanRecord | None:
        """Atomically move a plan from ``expected`` to ``status`` (compare-and-set).

        The precondition is part of the ``UPDATE`` itself (``WHERE id=? AND
        status=?``) inside a ``BEGIN IMMEDIATE`` transaction, so it holds across
        threads *and* across the several worker processes sharing the file: of N
        concurrent callers claiming the same transition exactly one gets the
        record back; the rest get ``None`` and must not act. A read of
        ``record.status`` followed by an unconditional write is not a substitute.
        Raises ``KeyError`` if the plan does not exist."""
        with self._txn() as db:
            if reset_decision:
                # Release a claim that never reached the target: back to undecided.
                cur = db.execute(
                    "UPDATE plans SET status=?, decided_by=NULL, decided_at=NULL, deny_reason=NULL, "
                    "decided_key_ref=NULL, decided_operator=NULL WHERE id=? AND status=?",
                    (status, plan_id, expected),
                )
            else:
                cur = db.execute(
                    "UPDATE plans SET status=?, decided_by=COALESCE(?, decided_by), "
                    "decided_at=COALESCE(?, decided_at), deny_reason=COALESCE(?, deny_reason), "
                    "decided_key_ref=COALESCE(?, decided_key_ref), "
                    "decided_operator=COALESCE(?, decided_operator) "
                    "WHERE id=? AND status=?",
                    (status, decided_by, decided_at, deny_reason, decided_key_ref, decided_operator,
                     plan_id, expected),
                )
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if row is None:
                raise KeyError(plan_id)
            return PlanRecord.from_row(row) if cur.rowcount == 1 else None


def new_id() -> str:
    return str(uuid.uuid4())


__all__ = ["REVOKED", "AiStore", "ConnectionRecord", "CredentialRow", "PlanRecord", "new_id", "SCHEMA_VERSION"]
