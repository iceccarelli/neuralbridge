"""Accounts, API keys and quota.

The rules this store exists to enforce:

* **A key is never stored.** Only ``sha256(key)`` and a short prefix, so a
  stolen database yields no working credential. The key is shown once, at
  issue, and cannot be recovered afterwards. The single exception is the
  checkout handover: for at most :data:`PENDING_KEY_TTL` after payment, the
  fresh key waits in ``pending_keys`` until the browser returning from Stripe
  collects it, and is deleted on collection or expiry, whichever comes first.
* **Quota is counted where it is spent**, per account per UTC day, in the same
  transaction that authorises the call. Counting somewhere else and hoping the
  two agree is how a metered product leaks.
* **Paying changes something.** The entitlement on the account is read on every
  request; there is no path where a tier is stored and then never consulted.
* **An email address is not an identity.** Accounts are matched by Stripe
  customer id (or an explicit account id) and never by email: the email on a
  Checkout form is typed by the payer, so merging on it would let anyone who
  types a victim's address inherit, or overwrite, the victim's account.
* **A webhook delivery is applied at most once.** Stripe retries and reorders
  events. Every effect is recorded against the event id in the same
  transaction that produces it.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..core.identity import format_utc, utc_now
from .plans import Plan, plan_for

__all__ = [
    "ACCOUNTS_SCHEMA_VERSION",
    "ENTITLED_STATUSES",
    "MAX_ACTIVE_KEYS",
    "PENDING_KEY_TTL",
    "Account",
    "AccountStore",
    "KeyLimitError",
    "Principal",
    "QuotaExceededError",
]

#: Unchanged on purpose. Every change since version 1 is additive and applied
#: idempotently on open (:meth:`AccountStore._migrate`), so an existing database
#: keeps opening and a rollback to the previous build still works. Bump this
#: only for a change an older build could not read.
ACCOUNTS_SCHEMA_VERSION = 1
KEY_PREFIX = "asr_"

#: Account statuses that keep the paid entitlement. ``past_due`` is deliberately
#: among them: a single failed card must not cut a manufacturer off from a
#: register with a 24-hour clock. Stripe's dunning decides when the subscription
#: ends, and says so with ``customer.subscription.updated``/``deleted``.
ENTITLED_STATUSES = frozenset({"active", "past_due"})

#: How long a freshly minted key may wait, in plaintext, for the browser
#: returning from Stripe to collect it.
PENDING_KEY_TTL = timedelta(hours=24)

#: A ceiling on live keys per account, so self-service issuing cannot be used
#: to fill the table.
MAX_ACTIVE_KEYS = 10

#: How long a processed webhook event id is remembered. Stripe retries for at
#: most three days; this is comfortably beyond that.
_EVENT_RETENTION = timedelta(days=35)
#: A subscription state received for a customer we have not seen yet is held
#: this long, waiting for the checkout event that creates the account.
_ORPHAN_RETENTION = timedelta(days=7)

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
    updated_at             TEXT NOT NULL,
    last_event_at          INTEGER NOT NULL DEFAULT 0,
    past_due_since         INTEGER NOT NULL DEFAULT 0
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
CREATE TABLE IF NOT EXISTS processed_events (
    event_id     TEXT PRIMARY KEY,
    kind         TEXT NOT NULL DEFAULT '',
    processed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orphan_states (
    stripe_customer_id TEXT PRIMARY KEY,
    status             TEXT NOT NULL,
    tier               TEXT,
    event_created      INTEGER NOT NULL,
    recorded_at        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entitlement_reconciliations (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                 TEXT NOT NULL,
    account_id             TEXT NOT NULL,
    category               TEXT NOT NULL,
    old_status             TEXT NOT NULL,
    old_tier               TEXT NOT NULL,
    new_status             TEXT NOT NULL,
    new_tier               TEXT NOT NULL,
    stripe_subscription_id TEXT NOT NULL DEFAULT '',
    stripe_status          TEXT NOT NULL DEFAULT '',
    snapshot_at            INTEGER NOT NULL,
    applied_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reconciliations_by_account
    ON entitlement_reconciliations (account_id);
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


class KeyLimitError(RuntimeError):
    """The account already holds the maximum number of live keys."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(f"{limit} active keys is the maximum; revoke one first.")


@dataclass(frozen=True)
class Account:
    id: str
    email: str
    company: str
    tier: str
    status: str
    stripe_customer_id: str = ""
    stripe_subscription_id: str = ""
    #: ``created`` of the newest Stripe event applied to this account (unix
    #: seconds); older subscription events are ignored as stale.
    last_event_at: int = 0
    #: Unix seconds at which the account entered ``past_due`` (the Stripe event
    #: time when known), or 0 if unknown or not past due. Lets reconciliation
    #: end a ``past_due`` that Stripe never resolves.
    past_due_since: int = 0

    @property
    def plan(self) -> Plan:
        # A lapsed subscription drops to free rather than keeping paid access.
        # ``past_due`` still counts as paying: see ENTITLED_STATUSES.
        return plan_for(self.tier if self.status in ENTITLED_STATUSES else "free")

    @property
    def warning(self) -> str:
        """Something the account holder should be told, or the empty string."""
        if self.status == "past_due":
            return (
                "The last payment failed. Access continues while Stripe retries the "
                "charge; update the payment method (POST /v1/billing/portal) before "
                "the subscription is cancelled and the register plan lapses."
            )
        return ""


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
            self._migrate(db)
        finally:
            db.close()

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """Additive, idempotent changes to a database an older build created.

        ``CREATE TABLE IF NOT EXISTS`` in the schema covers new tables; a new
        column on an existing table needs this.
        """
        columns = {r[1] for r in db.execute("PRAGMA table_info(accounts)")}
        if "last_event_at" not in columns:
            db.execute(
                "ALTER TABLE accounts ADD COLUMN last_event_at INTEGER NOT NULL DEFAULT 0"
            )
        if "past_due_since" not in columns:
            db.execute(
                "ALTER TABLE accounts ADD COLUMN past_due_since INTEGER NOT NULL DEFAULT 0"
            )

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
    @staticmethod
    def _upsert_db(
        db: sqlite3.Connection,
        *,
        email: str,
        tier: str,
        company: str,
        stripe_customer_id: str,
        stripe_subscription_id: str,
        status: str,
        account_id: str,
        event_created: int,
    ) -> sqlite3.Row:
        now = format_utc(utc_now())
        existing = None
        if account_id:
            existing = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if existing is None:
                raise LookupError(f"no account {account_id!r}")
        elif stripe_customer_id:
            existing = db.execute(
                "SELECT * FROM accounts WHERE stripe_customer_id = ?",
                (stripe_customer_id,),
            ).fetchone()
        # Never `WHERE email = ?`. See the module docstring.

        if existing is None:
            new_id = _new_id("acc")
            db.execute(
                "INSERT INTO accounts (id, email, company, tier, stripe_customer_id, "
                "stripe_subscription_id, status, created_at, updated_at, last_event_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (new_id, email, company, tier, stripe_customer_id,
                 stripe_subscription_id, status, now, now, max(event_created, 0)),
            )
            return db.execute("SELECT * FROM accounts WHERE id = ?", (new_id,)).fetchone()

        stale = bool(event_created) and existing["last_event_at"] > event_created
        db.execute(
            "UPDATE accounts SET email=?, company=?, tier=?, stripe_customer_id=?, "
            "stripe_subscription_id=?, status=?, updated_at=?, last_event_at=? WHERE id=?",
            (email or existing["email"], company or existing["company"],
             existing["tier"] if stale else tier,
             stripe_customer_id or existing["stripe_customer_id"],
             stripe_subscription_id or existing["stripe_subscription_id"],
             existing["status"] if stale else status, now,
             max(existing["last_event_at"], event_created), existing["id"]),
        )
        return db.execute("SELECT * FROM accounts WHERE id = ?", (existing["id"],)).fetchone()

    def upsert_account(
        self,
        *,
        email: str,
        tier: str,
        company: str = "",
        stripe_customer_id: str = "",
        stripe_subscription_id: str = "",
        status: str = "active",
        account_id: str = "",
        event_created: int = 0,
    ) -> Account:
        """Create or update an account, matched on identity and never on email.

        The match is the Stripe customer id, or an explicit ``account_id``
        (``LookupError`` if it does not exist). With neither, a new account is
        created. Two payers who type the same email are two accounts: an
        address on a form proves nothing about who owns it.
        """
        with self._txn() as db:
            row = self._upsert_db(
                db, email=email, tier=tier, company=company,
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id=stripe_subscription_id,
                status=status, account_id=account_id, event_created=event_created,
            )
        return self._row_to_account(row)

    @staticmethod
    def _apply_state_db(
        db: sqlite3.Connection,
        customer: str,
        status: str,
        tier: str | None,
        event_created: int,
        only_from: frozenset[str] | None = None,
    ) -> str:
        row = db.execute(
            "SELECT id, status, last_event_at, past_due_since FROM accounts "
            "WHERE stripe_customer_id = ?",
            (customer,),
        ).fetchone() if customer else None
        if row is None:
            return "unknown_customer"
        if event_created and row["last_event_at"] > event_created:
            return "stale"
        if (event_created and row["last_event_at"] == event_created
                and row["status"] == "cancelled" and status != "cancelled"):
            # Stripe stamps events to the second. When a cancellation and a
            # "still active" event share one, arrival order is not causal order;
            # of the two mistakes, leaving access on is the worse one.
            return "stale"
        if only_from is not None and row["status"] not in only_from:
            return "not_applicable"
        now = format_utc(utc_now())
        last = max(row["last_event_at"], event_created)
        # When the account entered past_due, so reconciliation can end a
        # past_due that Stripe never resolves. Kept across repeat past_due events.
        if status != "past_due":
            since = 0
        elif row["status"] == "past_due" and row["past_due_since"]:
            since = row["past_due_since"]
        else:
            since = event_created or int(utc_now().timestamp())
        if tier is None:
            db.execute(
                "UPDATE accounts SET status=?, updated_at=?, last_event_at=?, "
                "past_due_since=? WHERE id=?",
                (status, now, last, since, row["id"]),
            )
        else:
            db.execute(
                "UPDATE accounts SET status=?, tier=?, updated_at=?, last_event_at=?, "
                "past_due_since=? WHERE id=?",
                (status, tier, now, last, since, row["id"]),
            )
        return "applied"

    def set_status(
        self,
        *,
        stripe_customer_id: str,
        status: str,
        tier: str | None = None,
        event_created: int = 0,
    ) -> str:
        """Apply a subscription state. Returns ``applied``, ``stale`` or ``unknown_customer``.

        ``stale`` means an event newer than this one was already applied, so
        this one is ignored. The webhook route does not call this directly: it
        uses :meth:`apply_subscription_event`, which also dedupes by event id.
        """
        with self._txn() as db:
            return self._apply_state_db(db, stripe_customer_id, status, tier, event_created)

    @staticmethod
    def _seen_event(db: sqlite3.Connection, event_id: str) -> bool:
        return db.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,)
        ).fetchone() is not None

    @staticmethod
    def _mark_event(db: sqlite3.Connection, event_id: str, kind: str) -> None:
        if event_id:
            db.execute(
                "INSERT OR IGNORE INTO processed_events (event_id, kind, processed_at) "
                "VALUES (?,?,?)",
                (event_id, kind, format_utc(utc_now())),
            )

    @staticmethod
    def _purge_db(db: sqlite3.Connection) -> None:
        now = utc_now()
        db.execute(
            "DELETE FROM processed_events WHERE processed_at < ?",
            (format_utc(now - _EVENT_RETENTION),),
        )
        db.execute(
            "DELETE FROM orphan_states WHERE recorded_at < ?",
            (format_utc(now - _ORPHAN_RETENTION),),
        )
        db.execute(
            "DELETE FROM pending_keys WHERE created_at < ?",
            (format_utc(now - PENDING_KEY_TTL),),
        )

    def apply_subscription_event(
        self,
        *,
        event_id: str,
        kind: str,
        stripe_customer_id: str,
        status: str,
        tier: str | None,
        event_created: int,
        hold_if_unknown: bool,
        only_from: frozenset[str] | None = None,
    ) -> str:
        """Apply one subscription state change, at most once per event id.

        Returns ``duplicate``, ``applied``, ``stale``, ``not_applicable``
        (``only_from`` names the statuses this change may start from, and the
        account is in another), ``held`` or ``unknown_customer``. ``held`` means the customer has no account yet
        (``customer.subscription.updated`` can overtake
        ``checkout.session.completed``), so the state is kept and applied when
        the account is created. It is held rather than answered with an error
        because a Stripe account that sells other products would otherwise
        send this endpoint failures it can never resolve.
        """
        with self._txn() as db:
            if event_id and self._seen_event(db, event_id):
                return "duplicate"
            self._purge_db(db)
            result = self._apply_state_db(
                db, stripe_customer_id, status, tier, event_created, only_from
            )
            if result == "unknown_customer" and hold_if_unknown and stripe_customer_id:
                held = db.execute(
                    "SELECT event_created FROM orphan_states WHERE stripe_customer_id = ?",
                    (stripe_customer_id,),
                ).fetchone()
                if held is None or held["event_created"] <= event_created:
                    db.execute(
                        "INSERT OR REPLACE INTO orphan_states "
                        "(stripe_customer_id, status, tier, event_created, recorded_at) "
                        "VALUES (?,?,?,?,?)",
                        (stripe_customer_id, status, tier, event_created,
                         format_utc(utc_now())),
                    )
                result = "held"
            self._mark_event(db, event_id, kind)
            return result

    def apply_checkout(
        self,
        *,
        event_id: str,
        session_id: str,
        email: str,
        company: str,
        tier: str,
        stripe_customer_id: str,
        stripe_subscription_id: str,
        event_created: int,
    ) -> dict[str, Any]:
        """Grant a paid checkout, at most once per event and once per session.

        Account, key and staged handover are written in one transaction
        together with the processed-event record, so a redelivery (or a second
        event for the same session) can neither mint a second key nor re-arm a
        handover that was already collected. Returns ``{"result": "duplicate"}``
        for a repeat, otherwise ``{"result": "granted", "account_id": ...}``.
        """
        marker = f"session:{session_id}"
        with self._txn() as db:
            if self._seen_event(db, event_id) or self._seen_event(db, marker):
                self._mark_event(db, event_id, "checkout.session.completed")
                return {"result": "duplicate"}
            if db.execute(
                "SELECT 1 FROM pending_keys WHERE session_id = ?", (session_id,)
            ).fetchone():
                self._mark_event(db, event_id, "checkout.session.completed")
                return {"result": "duplicate"}
            self._purge_db(db)

            row = self._upsert_db(
                db, email=email, tier=tier, company=company,
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id=stripe_subscription_id,
                status="active", account_id="", event_created=event_created,
            )
            account_id = row["id"]

            # A subscription change that arrived before this event, and is
            # newer than it, wins. Anything older is already superseded.
            orphan = db.execute(
                "SELECT * FROM orphan_states WHERE stripe_customer_id = ?",
                (stripe_customer_id,),
            ).fetchone() if stripe_customer_id else None
            if orphan is not None:
                self._apply_state_db(
                    db, stripe_customer_id, orphan["status"], orphan["tier"],
                    orphan["event_created"],
                )
                db.execute(
                    "DELETE FROM orphan_states WHERE stripe_customer_id = ?",
                    (stripe_customer_id,),
                )

            key = self._issue_key_db(db, account_id, "issued at checkout")
            db.execute(
                "INSERT INTO pending_keys (session_id, account_id, api_key, tier, created_at) "
                "VALUES (?,?,?,?,?)",
                (session_id, account_id, key, tier, format_utc(utc_now())),
            )
            self._mark_event(db, event_id, "checkout.session.completed")
            self._mark_event(db, marker, "session")
        return {"result": "granted", "account_id": account_id}

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
            last_event_at=row["last_event_at"],
            past_due_since=row["past_due_since"],
        )

    def account(self, account_id: str) -> Account | None:
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            return self._row_to_account(row) if row else None
        finally:
            db.close()

    def list_accounts(self) -> list[Account]:
        """Every account, oldest first. Read-only; the reconciler's input."""
        db = self._connect()
        try:
            return [
                self._row_to_account(r)
                for r in db.execute("SELECT * FROM accounts ORDER BY created_at, id")
            ]
        finally:
            db.close()

    def apply_reconciliation(
        self,
        *,
        run_id: str,
        account_id: str,
        category: str,
        expect_status: str,
        expect_tier: str,
        new_status: str,
        new_tier: str,
        snapshot_at: int,
        skew_seconds: int,
        stripe_subscription_id: str = "",
        stripe_status: str = "",
    ) -> str:
        """Correct one account's status and tier to what Stripe reports, with an audit row.

        The change and its row in ``entitlement_reconciliations`` are one
        transaction: both happen or neither does. Nothing else on the account
        is touched. Refuses (changing nothing) for the operator, an account
        with no Stripe customer, a tier that is not ``free`` or purchasable,
        and:

        ``webhook_newer``
            the account's newest applied webhook is newer than the snapshot the
            caller read Stripe at (minus ``skew_seconds`` for clock difference),
            so the snapshot may predate it.
        ``changed_since_read``
            the account is no longer in the (status, tier) the caller compared.
        ``noop``
            it already is in the target state (a second apply).

        On success ``last_event_at`` moves up to the snapshot (less the skew), so
        a delayed older webhook retry cannot undo the correction. Returns
        ``applied``, one of the refusals above, ``not_found``,
        ``not_stripe_account`` or ``invalid_target``.
        """
        if new_status not in {"active", "past_due", "cancelled"} or new_tier not in {
            "free", "register", "cell"
        }:
            return "invalid_target"
        with self._txn() as db:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                return "not_found"
            if row["id"] == "operator" or not row["stripe_customer_id"]:
                return "not_stripe_account"
            horizon = snapshot_at - skew_seconds
            if row["last_event_at"] > horizon:
                return "webhook_newer"
            if (row["status"], row["tier"]) != (expect_status, expect_tier):
                return "changed_since_read"
            if (row["status"], row["tier"]) == (new_status, new_tier):
                return "noop"
            if new_status != "past_due":
                since = 0
            elif row["status"] == "past_due" and row["past_due_since"]:
                since = row["past_due_since"]
            else:
                since = snapshot_at
            now = format_utc(utc_now())
            db.execute(
                "UPDATE accounts SET status=?, tier=?, updated_at=?, last_event_at=?, "
                "past_due_since=? WHERE id=?",
                (new_status, new_tier, now, max(row["last_event_at"], horizon), since,
                 row["id"]),
            )
            db.execute(
                "INSERT INTO entitlement_reconciliations (run_id, account_id, category, "
                "old_status, old_tier, new_status, new_tier, stripe_subscription_id, "
                "stripe_status, snapshot_at, applied_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, row["id"], category, row["status"], row["tier"], new_status,
                 new_tier, stripe_subscription_id, stripe_status, snapshot_at, now),
            )
            return "applied"

    def last_reconciliation(self, account_id: str) -> dict[str, Any] | None:
        """The newest audit row for an account, or None."""
        db = self._connect()
        try:
            row = db.execute(
                "SELECT * FROM entitlement_reconciliations WHERE account_id=? "
                "ORDER BY id DESC LIMIT 1",
                (account_id,),
            ).fetchone()
            return dict(row) if row else None
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
    @staticmethod
    def _issue_key_db(
        db: sqlite3.Connection, account_id: str, label: str, max_active: int | None = None
    ) -> str:
        if max_active is not None:
            live = db.execute(
                "SELECT COUNT(*) FROM api_keys WHERE account_id=? AND revoked_at IS NULL",
                (account_id,),
            ).fetchone()[0]
            if live >= max_active:
                raise KeyLimitError(max_active)
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO api_keys (key_hash, prefix, account_id, label, created_at) "
            "VALUES (?,?,?,?,?)",
            (hash_key(key), key[: len(KEY_PREFIX) + 6], account_id, label,
             format_utc(utc_now())),
        )
        return key

    def issue_key(
        self, account_id: str, label: str = "", *, max_active: int | None = None
    ) -> str:
        """Mint a key and return it once. Only its hash is kept.

        With ``max_active`` set, raises :class:`KeyLimitError` rather than
        exceeding it; the count and the insert share a transaction.
        """
        with self._txn() as db:
            return self._issue_key_db(db, account_id, label, max_active)

    def revoke_key(self, key_hash: str) -> bool:
        with self._txn() as db:
            cur = db.execute(
                "UPDATE api_keys SET revoked_at=? WHERE key_hash=? AND revoked_at IS NULL",
                (format_utc(utc_now()), key_hash),
            )
            return cur.rowcount > 0

    def revoke_account_key(
        self, account_id: str, *, key_hash: str = "", key_prefix: str = ""
    ) -> str:
        """Revoke one key belonging to ``account_id``.

        Scoped by account in the query itself, so a hash or prefix belonging to
        anyone else is indistinguishable from one that does not exist. Returns
        ``revoked``, ``already_revoked``, ``not_found`` or ``ambiguous`` (a
        prefix shared by more than one live key of the account).
        """
        now = format_utc(utc_now())
        with self._txn() as db:
            if key_hash:
                rows = db.execute(
                    "SELECT key_hash, revoked_at FROM api_keys "
                    "WHERE key_hash=? AND account_id=?",
                    (key_hash, account_id),
                ).fetchall()
            elif key_prefix:
                rows = db.execute(
                    "SELECT key_hash, revoked_at FROM api_keys "
                    "WHERE prefix=? AND account_id=?",
                    (key_prefix, account_id),
                ).fetchall()
            else:
                return "not_found"
            if not rows:
                return "not_found"
            live = [r for r in rows if r["revoked_at"] is None]
            if not live:
                return "already_revoked"
            if len(live) > 1:
                return "ambiguous"
            db.execute(
                "UPDATE api_keys SET revoked_at=? WHERE key_hash=? AND revoked_at IS NULL",
                (now, live[0]["key_hash"]),
            )
            return "revoked"

    def active_key_count(self, account_id: str) -> int:
        db = self._connect()
        try:
            return db.execute(
                "SELECT COUNT(*) FROM api_keys WHERE account_id=? AND revoked_at IS NULL",
                (account_id,),
            ).fetchone()[0]
        finally:
            db.close()

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

    def peek_key(self, key: str) -> Principal | None:
        """Like :meth:`resolve_key` but read-only: no write lock, no ``last_used``.

        For checks that run before authentication proper (the body-size guard),
        where taking the single write lock for every request that carries a
        guessed key would let anyone queue behind, and in front of, real writes.
        """
        db = self._connect()
        try:
            row = db.execute(
                "SELECT k.prefix, k.account_id, a.* FROM api_keys k "
                "JOIN accounts a ON a.id = k.account_id "
                "WHERE k.key_hash = ? AND k.revoked_at IS NULL",
                (hash_key(key),),
            ).fetchone()
        finally:
            db.close()
        if row is None:
            return None
        return Principal(account=self._row_to_account(row), key_prefix=row["prefix"])

    def keys_for(self, account_id: str) -> list[dict[str, Any]]:
        """The account's keys by prefix. Never a hash and never a key."""
        db = self._connect()
        try:
            return [
                {
                    "prefix": r["prefix"],
                    "label": r["label"],
                    "created_at": r["created_at"],
                    "last_used": r["last_used"],
                    "revoked": bool(r["revoked_at"]),
                    "revoked_at": r["revoked_at"],
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

        This is the one place a key exists in plaintext at rest. It stays there
        until :meth:`claim_pending_key` collects it, which deletes the row, or
        until :data:`PENDING_KEY_TTL` (24 hours) passes, after which it is
        purged and the key can no longer be handed over — only its SHA-256
        remains. The checkout webhook stages through :meth:`apply_checkout`
        instead, in the same transaction as the account and the key.
        """
        if not session_id:
            return
        with self._txn() as db:
            self._purge_db(db)
            db.execute(
                "INSERT OR REPLACE INTO pending_keys "
                "(session_id, account_id, api_key, tier, created_at) VALUES (?,?,?,?,?)",
                (session_id, account_id, key, tier, format_utc(utc_now())),
            )

    def claim_pending_key(self, session_id: str) -> dict[str, str] | None:
        """Return the staged key and delete it. Single use, by construction.

        A row older than :data:`PENDING_KEY_TTL` is gone before it is read.
        """
        # An unauthenticated GET lands here with any string. Look first without
        # the write lock, so a flood of guesses cannot queue behind (or in front
        # of) real billing writes; only a row that exists takes the lock.
        probe = self._connect()
        try:
            found = probe.execute(
                "SELECT 1 FROM pending_keys WHERE session_id = ?", (session_id,)
            ).fetchone()
        finally:
            probe.close()
        if found is None:
            return None
        with self._txn() as db:
            self._purge_db(db)
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
            if row is None:
                # First spend of the day for this subject and scope: the cheap
                # moment to drop counters from last week, so the table is
                # bounded by recent activity and not by every address ever seen.
                cutoff = (utc_now().date() - timedelta(days=7)).isoformat()
                db.execute("DELETE FROM usage WHERE day < ?", (cutoff,))
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
