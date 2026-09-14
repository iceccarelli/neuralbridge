"""Accounts, API keys and quota.

The rules this store exists to enforce:

* **A key is never stored.** Only ``sha256(key)`` and a short prefix, so a
  stolen database yields no working credential. The key is shown once, at
  issue, and cannot be recovered afterwards.
* **Quota is counted where it is spent**, per account per UTC day, in the same
  transaction that authorises the call. Counting somewhere else and hoping the
  two agree is how a metered product leaks.
* **Paying changes something.** The entitlement on the account is read on every
  request; there is no path where a tier is stored and then never consulted.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.identity import format_utc, utc_now
from .plans import Plan, plan_for

__all__ = ["ACCOUNTS_SCHEMA_VERSION", "Account", "Principal", "QuotaExceededError", "AccountStore"]

ACCOUNTS_SCHEMA_VERSION = 1
KEY_PREFIX = "asr_"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id                     TEXT PRIMARY KEY,
    email                  TEXT NOT NULL,
    company                TEXT NOT NULL DEFAULT '',
    tier                   TEXT NOT NULL,
    stripe_customer_id     TEXT NOT NULL DEFAULT '',
    stripe_subscription_id TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active','past_due','cancelled')),
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_by_customer ON accounts (stripe_customer_id);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash   TEXT PRIMARY KEY,
    prefix     TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    label      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_used  TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS keys_by_account ON api_keys (account_id);
CREATE TABLE IF NOT EXISTS pending_keys (
    session_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    api_key    TEXT NOT NULL,
    tier       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
    subject TEXT NOT NULL,
    scope   TEXT NOT NULL,
    day     TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (subject, scope, day)
);
"""


class QuotaExceededError(RuntimeError):
    """The caller is out of allowance for this scope today."""

    def __init__(self, scope: str, limit: int, used: int, tier: str) -> None:
        self.scope, self.limit, self.used, self.tier = scope, limit, used, tier
        super().__init__(
            f"{scope}: {used} of {limit} used today on the {tier} plan."
        )


@dataclass(frozen=True)
class Account:
    id: str
    email: str
    company: str
    tier: str
    status: str
    stripe_customer_id: str = ""
    stripe_subscription_id: str = ""

    @property
    def plan(self) -> Plan:
        # A lapsed subscription drops to free rather than keeping paid access.
        return plan_for(self.tier if self.status == "active" else "free")


@dataclass(frozen=True)
class Principal:
    """Who is calling, and what they are entitled to."""

    account: Account | None
    key_prefix: str
    #: Set when the caller presented no key (the free, address-limited path).
    anonymous_subject: str = ""

    @property
    def plan(self) -> Plan:
        return self.account.plan if self.account else plan_for("free")

    @property
    def subject(self) -> str:
        return self.account.id if self.account else self.anonymous_subject

    @property
    def tier(self) -> str:
        return self.plan.tier


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class AccountStore:
    """Durable account, key and usage store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # sqlite3's context manager commits; it does not close.
        db = self._connect()
        try:
            db.executescript(_SCHEMA)
            row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(ACCOUNTS_SCHEMA_VERSION),),
                )
            elif int(row[0]) != ACCOUNTS_SCHEMA_VERSION:
                raise RuntimeError(
                    f"{self.path} was written by accounts schema {row[0]}; this build "
                    f"speaks {ACCOUNTS_SCHEMA_VERSION}. Refusing rather than guessing."
                )
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
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

    # -- accounts ---------------------------------------------------------
    def upsert_account(
        self,
        *,
        email: str,
        tier: str,
        company: str = "",
        stripe_customer_id: str = "",
        stripe_subscription_id: str = "",
        status: str = "active",
    ) -> Account:
        """Create or update an account, keyed on the Stripe customer where known.

        Stripe can deliver the same event twice; this is written so that it
        does, harmlessly.
        """
        now = format_utc(utc_now())
        with self._txn() as db:
            existing = None
            if stripe_customer_id:
                existing = db.execute(
                    "SELECT * FROM accounts WHERE stripe_customer_id = ?",
                    (stripe_customer_id,),
                ).fetchone()
            if existing is None:
                existing = db.execute(
                    "SELECT * FROM accounts WHERE email = ?", (email,)
                ).fetchone()

            if existing is None:
                account_id = _new_id("acc")
                db.execute(
                    "INSERT INTO accounts (id, email, company, tier, stripe_customer_id, "
                    "stripe_subscription_id, status, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (account_id, email, company, tier, stripe_customer_id,
                     stripe_subscription_id, status, now, now),
                )
            else:
                account_id = existing["id"]
                db.execute(
                    "UPDATE accounts SET email=?, company=?, tier=?, stripe_customer_id=?, "
                    "stripe_subscription_id=?, status=?, updated_at=? WHERE id=?",
                    (email, company or existing["company"], tier,
                     stripe_customer_id or existing["stripe_customer_id"],
                     stripe_subscription_id or existing["stripe_subscription_id"],
                     status, now, account_id),
                )
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self._row_to_account(row)

    def set_status(self, *, stripe_customer_id: str, status: str, tier: str | None = None) -> None:
        now = format_utc(utc_now())
        with self._txn() as db:
            if tier is None:
                db.execute(
                    "UPDATE accounts SET status=?, updated_at=? WHERE stripe_customer_id=?",
                    (status, now, stripe_customer_id),
                )
            else:
                db.execute(
                    "UPDATE accounts SET status=?, tier=?, updated_at=? "
                    "WHERE stripe_customer_id=?",
                    (status, tier, now, stripe_customer_id),
                )

    @staticmethod
    def _row_to_account(row: sqlite3.Row) -> Account:
        return Account(
            id=row["id"],
            email=row["email"],
            company=row["company"],
            tier=row["tier"],
            status=row["status"],
            stripe_customer_id=row["stripe_customer_id"],
            stripe_subscription_id=row["stripe_subscription_id"],
        )

    def account(self, account_id: str) -> Account | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            return self._row_to_account(row) if row else None
        finally:
            db.close()

    def account_by_customer(self, stripe_customer_id: str) -> Account | None:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT * FROM accounts WHERE stripe_customer_id = ?", (stripe_customer_id,)
            ).fetchone()
            return self._row_to_account(row) if row else None
        finally:
            db.close()

    # -- keys -------------------------------------------------------------
    def issue_key(self, account_id: str, label: str = "") -> str:
        """Mint a key and return it once. Only its hash is kept."""
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        now = format_utc(utc_now())
        with self._txn() as db:
            db.execute(
                "INSERT INTO api_keys (key_hash, prefix, account_id, label, created_at) "
                "VALUES (?,?,?,?,?)",
                (hash_key(key), key[: len(KEY_PREFIX) + 6], account_id, label, now),
            )
        return key

    def revoke_key(self, key_hash: str) -> bool:
        with self._txn() as db:
            cur = db.execute(
                "UPDATE api_keys SET revoked_at=? WHERE key_hash=? AND revoked_at IS NULL",
                (format_utc(utc_now()), key_hash),
            )
            return cur.rowcount > 0

    def resolve_key(self, key: str) -> Principal | None:
        """Look up a presented key. Returns None for unknown or revoked keys."""
        digest = hash_key(key)
        with self._txn() as db:
            row = db.execute(
                "SELECT k.prefix, k.account_id, a.* FROM api_keys k "
                "JOIN accounts a ON a.id = k.account_id "
                "WHERE k.key_hash = ? AND k.revoked_at IS NULL",
                (digest,),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE api_keys SET last_used=? WHERE key_hash=?",
                (format_utc(utc_now()), digest),
            )
        return Principal(account=self._row_to_account(row), key_prefix=row["prefix"])

    def keys_for(self, account_id: str) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            return [
                {
                    "prefix": r["prefix"],
                    "label": r["label"],
                    "created_at": r["created_at"],
                    "last_used": r["last_used"],
                    "revoked": bool(r["revoked_at"]),
                }
                for r in db.execute(
                    "SELECT * FROM api_keys WHERE account_id=? ORDER BY created_at",
                    (account_id,),
                )
            ]
        finally:
            db.close()

    # -- checkout handover ------------------------------------------------
    def stage_pending_key(self, session_id: str, account_id: str, key: str, tier: str) -> None:
        """Hold a freshly minted key for the browser returning from Stripe.

        This is the one place a key exists in plaintext at rest, and it exists
        there for seconds. :meth:`claim_pending_key` deletes it on read, so it
        can be collected exactly once.
        """
        if not session_id:
            return
        with self._txn() as db:
            db.execute(
                "INSERT OR REPLACE INTO pending_keys "
                "(session_id, account_id, api_key, tier, created_at) VALUES (?,?,?,?,?)",
                (session_id, account_id, key, tier, format_utc(utc_now())),
            )

    def claim_pending_key(self, session_id: str) -> dict[str, str] | None:
        """Return the staged key and delete it. Single use, by construction."""
        with self._txn() as db:
            row = db.execute(
                "SELECT * FROM pending_keys WHERE session_id = ?", (session_id,)
            ).fetchone()
            if row is None:
                return None
            db.execute("DELETE FROM pending_keys WHERE session_id = ?", (session_id,))
        return {
            "api_key": row["api_key"],
            "account_id": row["account_id"],
            "tier": row["tier"],
        }

    # -- quota ------------------------------------------------------------
    def consume(
        self, subject: str, scope: str, limit: int | None, tier: str = ""
    ) -> tuple[int, int | None]:
        """Spend one unit of allowance. Raises :class:`QuotaExceededError` at the limit.

        The read and the increment happen inside one transaction, so two
        concurrent requests cannot both see the last remaining unit.
        """
        if limit is None:
            return (0, None)
        # The UTC day, not the server's local day: a quota that rolls over at
        # the operator's midnight behaves differently for a customer in another
        # timezone, and nobody can explain why.
        today = utc_now().date().isoformat()
        with self._txn() as db:
            row = db.execute(
                "SELECT count FROM usage WHERE subject=? AND scope=? AND day=?",
                (subject, scope, today),
            ).fetchone()
            used = row["count"] if row else 0
            if used >= limit:
                raise QuotaExceededError(scope, limit, used, tier or "free")
            db.execute(
                "INSERT INTO usage (subject, scope, day, count) VALUES (?,?,?,1) "
                "ON CONFLICT(subject, scope, day) DO UPDATE SET count = count + 1",
                (subject, scope, today),
            )
        return (used + 1, limit)

    def usage_today(self, subject: str) -> dict[str, int]:
        # The UTC day, not the server's local day: a quota that rolls over at
        # the operator's midnight behaves differently for a customer in another
        # timezone, and nobody can explain why.
        today = utc_now().date().isoformat()
        db = self._connect()
        try:
            return {
                r["scope"]: r["count"]
                for r in db.execute(
                    "SELECT scope, count FROM usage WHERE subject=? AND day=?",
                    (subject, today),
                )
            }
        finally:
            db.close()
