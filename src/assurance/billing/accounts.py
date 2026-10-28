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
import re
import secrets
import sqlite3
import threading
import unicodedata
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from ..core.identity import format_utc, utc_now
from ..core.sqlite import enable_wal, retry_locked
from .metering import (
    MAX_SPEND_LIMIT_UNITS,
    allowance_for,
    month_bounds,
    overage_allowed,
    valid_idempotency_key,
)
from .plans import METERED_SCOPES, Plan, plan_for

__all__ = [
    "ACCOUNTS_SCHEMA_VERSION",
    "ENTITLED_STATUSES",
    "MAX_ACTIVE_KEYS",
    "PENDING_KEY_TTL",
    "USAGE_LEASE",
    "USAGE_MAX_AGE",
    "USAGE_RESEND_WINDOW",
    "Account",
    "AccountStore",
    "IdempotencyConflictError",
    "GRANTABLE_TIERS",
    "KeyLimitError",
    "MANUAL_GRANT",
    "ManualGrantError",
    "Principal",
    "QuotaExceededError",
    "SpendLimitError",
    "UsageRecord",
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

#: ``Account.source`` of an account provisioned by an operator, outside Stripe.
MANUAL_GRANT = "manual_grant"

_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_EMAIL = re.compile(r"[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+")


def valid_day(text: str) -> bool:
    """Whether *text* is exactly a calendar date, ``YYYY-MM-DD``. Nothing looser is a date here."""
    if not _DAY.fullmatch(text):
        return False
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def normal_email(email: str) -> str:
    """The form two spellings of one address share: NFKC, then Unicode case-folded.

    SQLite's ``lower()`` is ASCII-only, so ``MÜLLER@x.de`` and ``müller@x.de`` are different
    strings to it and the same person to everybody else.
    """
    return unicodedata.normalize("NFKC", email.strip()).casefold()


#: The tiers an operator may grant by hand. Never ``free`` (nothing to grant) and never
#: ``payg`` (that is a billing arrangement with Stripe, which a manual grant has none of).
GRANTABLE_TIERS = ("register", "cell")

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

#: Events inside the free allowance are kept this long; billable ones are never
#: dropped by this store.
_INCLUDED_RETENTION = timedelta(days=62)

#: A ``sending`` event may be claimed again after this long without an outcome.
USAGE_LEASE = timedelta(minutes=10)
#: Re-sending the same identifier is safe only while the provider still dedupes
#: on it. Stripe's guarantee is "at least 24 hours"; stay well inside it.
USAGE_RESEND_WINDOW = timedelta(hours=20)
#: The provider refuses usage timestamped more than 35 days back.
USAGE_MAX_AGE = timedelta(days=34)


#: How restrictive a subscription phase is. At the same second Stripe stamps two events
#: with, the more restrictive wins: of the two mistakes, leaving access on is the worse one.
_PHASE_RANK = {"entitled": 0, "past_due": 1, "suspended": 2, "terminal": 3}
#: How much a subscription in this phase counts when choosing the one the account follows.
_CLASS_OF_PHASE = {"entitled": 2, "past_due": 2, "suspended": 1, "terminal": 0}
_STATUS_OF_PHASE = {
    "entitled": "active", "past_due": "past_due", "suspended": "cancelled", "terminal": "cancelled",
}


def _phase_for(status: str, tier: str | None) -> str:
    """The subscription phase an (account status, tier) pair describes."""
    if status == "active":
        return "entitled"
    if status == "past_due":
        return "past_due"
    return "terminal" if tier == "free" else "suspended"


def _effective_phase(sub: sqlite3.Row, failed_at: int) -> str:
    """A payment failure at or after the last state report makes an entitled sub past due.

    Kept as its own timestamp (not a state) so that a late failure can never reinstate
    a subscription that ended, and a failure delivered early is not lost.
    """
    if sub["phase"] == "entitled" and failed_at and failed_at >= sub["state_at"]:
        return "past_due"
    return str(sub["phase"])


def _parse_stamp(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))

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
    past_due_since         INTEGER NOT NULL DEFAULT 0,
    spend_limit_units      INTEGER NOT NULL DEFAULT 0,
    budget_alert_pct       INTEGER NOT NULL DEFAULT 80,
    source                 TEXT NOT NULL DEFAULT '',
    grant_note             TEXT NOT NULL DEFAULT '',
    granted_at             TEXT NOT NULL DEFAULT '',
    grant_expires_on       TEXT NOT NULL DEFAULT '',
    granted_by             TEXT NOT NULL DEFAULT ''
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
-- Individual operators of an account: a named credential holder with a role. A key
-- bound to an operator (api_keys.operator_id) attributes its actions to that operator.
-- This is a credential-to-user binding inside the account; it is not identity proofing.
CREATE TABLE IF NOT EXISTS operators (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts (id),
    name        TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('contributor','decider')),
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL DEFAULT '',
    disabled_at TEXT
);
CREATE INDEX IF NOT EXISTS operators_by_account ON operators (account_id);
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
-- What each of a customer's subscriptions last said, kept apart so that an event about
-- one subscription can never rewrite the state of another, and so that delivery order
-- does not matter: every column is a join (newest wins, ties go to the more restrictive).
-- ``accounts`` stays the row everything reads; it is derived from these on each event.
CREATE TABLE IF NOT EXISTS subscription_states (
    stripe_customer_id     TEXT NOT NULL,
    stripe_subscription_id TEXT NOT NULL,
    born        INTEGER NOT NULL DEFAULT 0,
    state_at    INTEGER NOT NULL DEFAULT 0,
    phase       TEXT NOT NULL CHECK (phase IN ('entitled','past_due','suspended','terminal')),
    tier        TEXT NOT NULL DEFAULT '',
    tier_at     INTEGER NOT NULL DEFAULT 0,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (stripe_customer_id, stripe_subscription_id)
);
-- The newest failed invoice per subscription. Apart from the state above because an
-- invoice can be reported before the subscription it belongs to is known, and because it
-- must never be able to create or reinstate one.
CREATE TABLE IF NOT EXISTS subscription_failures (
    stripe_customer_id     TEXT NOT NULL,
    stripe_subscription_id TEXT NOT NULL,
    failed_at   INTEGER NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (stripe_customer_id, stripe_subscription_id)
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
-- The durable record of metered work, one row per accepted operation. Written in
-- the same transaction as the quota check (see AccountStore.record_usage); it
-- is also the outbox the pay-as-you-go reporter reads (billing/payg.py).
CREATE TABLE IF NOT EXISTS usage_events (
    event_id          TEXT PRIMARY KEY,
    account_id        TEXT NOT NULL REFERENCES accounts (id),
    scope             TEXT NOT NULL,
    quantity          INTEGER NOT NULL CHECK (quantity > 0),
    billable_quantity INTEGER NOT NULL DEFAULT 0
                        CHECK (billable_quantity >= 0 AND billable_quantity <= quantity),
    idempotency_key   TEXT NOT NULL,
    fingerprint       TEXT NOT NULL DEFAULT '',
    occurred_at       TEXT NOT NULL,
    source            TEXT NOT NULL DEFAULT 'api',
    billed_state      TEXT NOT NULL
                        CHECK (billed_state IN
                               ('included','pending','sending','billed','rejected','ambiguous')),
    provider_event_id TEXT NOT NULL DEFAULT '',
    first_attempt_at  TEXT NOT NULL DEFAULT '',
    last_attempt_at   TEXT NOT NULL DEFAULT '',
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT NOT NULL DEFAULT '',
    UNIQUE (account_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS usage_events_by_account ON usage_events (account_id, occurred_at);
CREATE INDEX IF NOT EXISTS usage_events_by_state ON usage_events (billed_state, occurred_at);
"""


class QuotaExceededError(RuntimeError):
    """The caller is out of allowance for this scope today."""

    def __init__(self, scope: str, limit: int, used: int, tier: str) -> None:
        self.scope, self.limit, self.used, self.tier = scope, limit, used, tier
        super().__init__(
            f"{scope}: {used} of {limit} used today on the {tier} plan."
        )


class SpendLimitError(RuntimeError):
    """The allowance is spent and the account's spend limit leaves no room.

    Raised only for an account that *may* be billed past its allowance
    (:func:`~.metering.overage_allowed`) but whose per-month limit, in billable
    units, would be exceeded. Nothing was recorded.
    """

    def __init__(self, scope: str, limit_units: int, used_units: int, requested_units: int) -> None:
        self.scope = scope
        self.limit_units, self.used_units, self.requested_units = (
            limit_units, used_units, requested_units)
        super().__init__(
            f"{scope}: {used_units} of {limit_units} billable units used this month; "
            f"{requested_units} more would exceed the spend limit."
        )


class IdempotencyConflictError(RuntimeError):
    """An idempotency key was reused for different work. Nothing was recorded."""

    def __init__(self, key: str, recorded_scope: str, recorded_quantity: int) -> None:
        self.key = key
        self.recorded_scope, self.recorded_quantity = recorded_scope, recorded_quantity
        super().__init__(
            "this idempotency key was already used for "
            f"{recorded_quantity} x {recorded_scope}; a key identifies one operation."
        )


@dataclass(frozen=True)
class UsageRecord:
    """The outcome of :meth:`AccountStore.record_usage`."""

    event_id: str
    scope: str
    quantity: int
    #: The part of ``quantity`` beyond the daily allowance, to be billed.
    billable_quantity: int
    #: ``included`` (inside the allowance), ``pending`` (billable, not yet reported)
    #: or the reporter's later states; ``""`` when nothing was recorded.
    billed_state: str
    #: True when this key was already recorded: nothing was counted this time.
    duplicate: bool
    #: False when the account's plan does not meter this scope (nothing written).
    recorded: bool = True


class KeyLimitError(RuntimeError):
    """The account already holds the maximum number of live keys."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(f"{limit} active keys is the maximum; revoke one first.")


class ManualGrantError(RuntimeError):
    """A manual grant was refused; the message says why and what to do instead."""

    def __init__(self, message: str, *, account_id: str = "") -> None:
        super().__init__(message)
        self.account_id = account_id


class OperatorsExistError(RuntimeError):
    """A bootstrap was attempted on an account that already has an enabled operator."""


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
    #: The most billable units (operations beyond the daily allowance) this
    #: account allows itself per UTC calendar month. 0 = none: pay-as-you-go
    #: never bills an account that has not set a limit. Enforced in
    #: :meth:`AccountStore.record_usage`, in units because the price lives in
    #: Stripe and this service cannot enforce a currency amount exactly.
    spend_limit_units: int = 0
    #: Percent of the spend limit at which ``GET /v1/usage`` raises
    #: ``budget_alert``. A flag only: this service sends no email.
    budget_alert_pct: int = 80
    #: ``manual_grant`` for an account an operator provisioned by hand
    #: (:meth:`AccountStore.grant_manual`); '' for every other account. A manual grant
    #: has no Stripe customer id, so it is invoiced, if at all, outside Stripe.
    source: str = ""
    grant_note: str = ""
    #: When the operator made the grant (UTC, ISO), and who ('' = not recorded).
    granted_at: str = ""
    granted_by: str = ""
    #: ``YYYY-MM-DD``, the last UTC day the grant is in force, inclusive; '' = no expiry.
    grant_expires_on: str = ""

    @property
    def is_manual_grant(self) -> bool:
        return self.source == MANUAL_GRANT

    @property
    def grant_lapsed(self) -> bool:
        """Whether a manual grant's last day is behind us, read now, on every call.

        There is no job that ends a grant: the entitlement is computed from the date each
        time ``plan`` is read, so it cannot outlive its day by the length of a cron interval,
        and moving the date (:meth:`AccountStore.extend_grant`) takes effect on the next
        request.
        """
        if not (self.is_manual_grant and self.grant_expires_on):
            return False
        # A stored date this build cannot read is not "no expiry": it ends the grant.
        # Fail closed; the store refuses to write such a value, so it can only have
        # arrived by hand.
        return (not valid_day(self.grant_expires_on)
                or utc_now().date().isoformat() > self.grant_expires_on)

    @property
    def plan(self) -> Plan:
        # A lapsed subscription drops to free rather than keeping paid access.
        # ``past_due`` still counts as paying: see ENTITLED_STATUSES. A manual grant
        # past its last day is lapsed the same way.
        entitled = self.status in ENTITLED_STATUSES and not self.grant_lapsed
        return plan_for(self.tier if entitled else "free")

    @property
    def ever_paid(self) -> bool:
        """Whether this account has been a customer: Stripe bound a customer id to it.

        The id is written only by a signed checkout event (or by an operator),
        never by the account holder. It is what separates a customer whose
        subscription ended from a caller who never paid, and so decides who may
        still read out their own evidence (``plans.EVIDENCE_READOUT_AFTER_LAPSE``).
        """
        return bool(self.stripe_customer_id)

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
    #: Set when the key is bound to an individual operator of the account. An
    #: account-level (service) key leaves these empty: it proves the account, not a
    #: person, and cannot make a human decision on a case.
    operator_id: str = ""
    operator_name: str = ""
    operator_role: str = ""

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
            retry_locked(lambda: db.executescript(_SCHEMA), db=db)
            row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                retry_locked(lambda: db.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(ACCOUNTS_SCHEMA_VERSION),),
                ), db=db)
                row = db.execute(
                    "SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if int(row[0]) != ACCOUNTS_SCHEMA_VERSION:
                raise RuntimeError(
                    f"{self.path} was written by accounts schema {row[0]}; this build "
                    f"speaks {ACCOUNTS_SCHEMA_VERSION}. Refusing rather than guessing."
                )
            retry_locked(lambda: self._migrate(db), db=db)
        finally:
            db.close()

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """Additive, idempotent changes to a database an older build created.

        ``CREATE TABLE IF NOT EXISTS`` in the schema covers new tables; a new
        column on an existing table needs this. Safe against a second process
        doing the same at the same moment: the check and the ``ALTER`` share
        one write transaction, and a "duplicate column" from a process that won
        the race anyway is the outcome we wanted, not an error.
        """
        additions = (
            ("accounts", "last_event_at", "INTEGER NOT NULL DEFAULT 0"),
            ("accounts", "past_due_since", "INTEGER NOT NULL DEFAULT 0"),
            ("accounts", "spend_limit_units", "INTEGER NOT NULL DEFAULT 0"),
            ("accounts", "budget_alert_pct", "INTEGER NOT NULL DEFAULT 80"),
            # An account an operator provisioned by hand for a pilot invoiced outside
            # Stripe (``source`` = ``manual_grant``; '' for every other account). See
            # AccountStore.grant_manual.
            ("accounts", "source", "TEXT NOT NULL DEFAULT ''"),
            ("accounts", "grant_note", "TEXT NOT NULL DEFAULT ''"),
            ("accounts", "granted_at", "TEXT NOT NULL DEFAULT ''"),
            ("accounts", "grant_expires_on", "TEXT NOT NULL DEFAULT ''"),
            ("accounts", "granted_by", "TEXT NOT NULL DEFAULT ''"),
            # What request an Idempotency-Key was first used for ('' = unknown,
            # a row an older build wrote: the key alone decides, as it did).
            ("usage_events", "fingerprint", "TEXT NOT NULL DEFAULT ''"),
            # The operator a key belongs to ('' = an account-level service key).
            ("api_keys", "operator_id", "TEXT NOT NULL DEFAULT ''"),
        )

        def present(table: str) -> set[str]:
            return {r[1] for r in db.execute(f"PRAGMA table_info({table})")}

        # Nothing to add (the normal case): no write lock, so opening an
        # up-to-date database never queues behind a writer.
        # A table that does not exist yet is created, whole, by the schema script.
        if all(name in present(table) or not present(table)
               for table, name, _ in additions):
            return
        db.execute("BEGIN IMMEDIATE")
        try:
            for table, name, definition in additions:
                columns = present(table)
                if not columns or name in columns:
                    continue
                try:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc).lower():
                        raise
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    @classmethod
    def open_readonly(cls, path: str | Path) -> AccountStore:
        """Open an existing store without writing a byte: no schema, no migration.

        For a dry run against a production database that may not have been
        migrated yet. Reads tolerate the older shape (``past_due_since`` and
        the audit table may be missing); any write raises.
        """
        self = cls.__new__(cls)
        self.path = Path(path)
        self._lock = threading.Lock()
        self._readonly = True
        db = self._connect()
        try:
            row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        finally:
            db.close()
        if row is None or int(row[0]) != ACCOUNTS_SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} was written by accounts schema "
                f"{row[0] if row else 'unknown'}; this build speaks "
                f"{ACCOUNTS_SCHEMA_VERSION}. Refusing rather than guessing."
            )
        return self

    _readonly = False

    def _connect(self) -> sqlite3.Connection:
        if self._readonly:
            db = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro", uri=True, timeout=30.0,
                isolation_level=None,
            )
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            return db
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        enable_wal(db)
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
             # A stale event describes an older state: it must not replace the
             # subscription the account currently holds (see other_subscription).
             existing["stripe_subscription_id"] if stale
             else (stripe_subscription_id or existing["stripe_subscription_id"]),
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

    # -- manual grants ----------------------------------------------------
    def grant_manual(
        self,
        *,
        email: str,
        tier: str,
        company: str = "",
        note: str = "",
        expires_on: str = "",
        granted_by: str = "",
        label: str = "manual-grant",
    ) -> tuple[Account, str]:
        """Provision an account by hand and mint its first key, returned once.

        For an operator-run pilot invoiced outside Stripe. The account has no Stripe customer
        id and never gets one from here, so :attr:`Account.ever_paid` stays false: whether a
        lapsed pilot keeps reading out its own evidence is the same open decision as for any
        account that never paid (``plans.EVIDENCE_READOUT_AFTER_LAPSE``). Nothing here talks to
        Stripe or any network.

        A second grant for an email that already has a manual grant is refused
        (:class:`ManualGrantError`, naming the account): an address proves nothing about who
        holds it, but two grants for one address is nearly always a repeat of the same command,
        and the way to a second key is explicit (:meth:`issue_key`, on that account).
        ``expires_on`` is the last UTC day in force, ``YYYY-MM-DD``, inclusive; '' = none.
        """
        if tier not in GRANTABLE_TIERS:
            raise ManualGrantError(
                f"tier {tier!r} cannot be granted by hand; one of {', '.join(GRANTABLE_TIERS)}.")
        normalised = email.strip()
        if not _EMAIL.fullmatch(normalised):
            raise ManualGrantError(
                f"{email!r} is not an email address: one '@', something on both sides, and "
                "no whitespace or control characters.")
        if expires_on and not valid_day(expires_on):
            raise ManualGrantError(
                f"expires_on {expires_on!r} is not a date; write it YYYY-MM-DD. A value that "
                "cannot be read would never lapse, so it is refused here, not only in the CLI.")
        with self._txn() as db:
            wanted = normal_email(normalised)
            existing = next((r for r in db.execute(
                "SELECT id, email FROM accounts WHERE source = ? AND status != 'cancelled'",
                (MANUAL_GRANT,)) if normal_email(r["email"]) == wanted), None)
            if existing is not None:
                raise ManualGrantError(
                    f"{normalised} already has a manual grant (account {existing['id']}). "
                    "Nothing was created. To give that account another key use "
                    "`billing issue-key`; to move its last day use `billing extend`.",
                    account_id=existing["id"])
            new_id = _new_id("acc")
            now = format_utc(utc_now())
            db.execute(
                "INSERT INTO accounts (id, email, company, tier, stripe_customer_id, "
                "stripe_subscription_id, status, created_at, updated_at, last_event_at, "
                "source, grant_note, granted_at, grant_expires_on, granted_by) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id, normalised, company, tier, "", "", "active", now, now, 0,
                 MANUAL_GRANT, note, now, expires_on, granted_by),
            )
            key = self._issue_key_db(db, new_id, label)
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (new_id,)).fetchone()
        return self._row_to_account(row), key

    def extend_grant(self, account_id: str, expires_on: str) -> Account:
        """Move a manual grant's last day ('' = remove the expiry). Read on the next request."""
        if expires_on and not valid_day(expires_on):
            raise ManualGrantError(f"expires_on {expires_on!r} is not a date; write it YYYY-MM-DD.")
        with self._txn() as db:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise LookupError(f"no account {account_id!r}")
            if row["source"] != MANUAL_GRANT:
                raise ManualGrantError(
                    f"{account_id} is not a manual grant; its access follows Stripe, and this "
                    "command does not touch it.", account_id=account_id)
            db.execute(
                "UPDATE accounts SET grant_expires_on=?, updated_at=? WHERE id=?",
                (expires_on, format_utc(utc_now()), account_id))
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self._row_to_account(row)

    def end_grant(self, account_id: str, reason: str = "") -> dict[str, Any]:
        """End a manual grant now: revoke every key it has, whoever minted it, and cancel it.

        A customer can mint keys of their own (``POST /v1/keys``), so ending a grant by
        revoking the keys the operator knows about does not end it. This revokes all of them in
        one transaction and sets the account ``cancelled``, which reads as the free plan on the
        next request. Idempotent: ending an ended grant changes nothing.
        """
        with self._txn() as db:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise LookupError(f"no account {account_id!r}")
            if row["source"] != MANUAL_GRANT:
                raise ManualGrantError(
                    f"{account_id} is not a manual grant; its access follows Stripe, and this "
                    "command does not touch it.", account_id=account_id)
            now = format_utc(utc_now())
            revoked = db.execute(
                "UPDATE api_keys SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                (now, account_id)).rowcount
            already = row["status"] == "cancelled"
            if not already:
                note = (row["grant_note"] + " " if row["grant_note"] else "") \
                    + f"[ended {now}" + (f": {reason}" if reason else "") + "]"
                db.execute(
                    "UPDATE accounts SET status='cancelled', grant_note=?, updated_at=? "
                    "WHERE id=?", (note, now, account_id))
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return {"account": self._row_to_account(row), "keys_revoked": revoked,
                "already_ended": already}

    def manual_grants_for_email(self, email: str) -> list[Account]:
        """Manual grants for an address, ended ones included, compared as ``grant_manual`` does."""
        wanted = normal_email(email)
        return [a for a in self.list_accounts()
                if a.is_manual_grant and normal_email(a.email) == wanted]

    # -- per-subscription state ------------------------------------------
    @staticmethod
    def _sub_row(db: sqlite3.Connection, customer: str, sub: str) -> sqlite3.Row | None:
        return db.execute(
            "SELECT * FROM subscription_states "
            "WHERE stripe_customer_id=? AND stripe_subscription_id=?", (customer, sub),
        ).fetchone()

    @classmethod
    def _sync_from_account(cls, db: sqlite3.Connection, row: sqlite3.Row) -> None:
        """Make the account's own subscription agree with the account row.

        The row is what every request reads, and other writers touch it without an
        event: the reconciler, an operator, an older build. Entering an event, a
        subscription whose record is missing (an account that predates this table) or
        disagrees with the row is re-read from the row, so the row stays the truth.
        """
        customer = row["stripe_customer_id"]
        sub = row["stripe_subscription_id"]
        existing = cls._sub_row(db, customer, sub)
        phase = _phase_for(row["status"], row["tier"])
        at = row["last_event_at"]
        now = format_utc(utc_now())
        if existing is None:
            db.execute(
                "INSERT INTO subscription_states (stripe_customer_id, stripe_subscription_id, "
                "born, state_at, phase, tier, tier_at, recorded_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (customer, sub, 0 if phase == "terminal" else at, at, phase, row["tier"], at, now),
            )
            return
        if existing["phase"] == "terminal" and existing["state_at"] > at:
            # The record holds an end newer than anything that wrote the row: the row is
            # the older word here and must not bring the subscription back.
            return
        eff = _effective_phase(existing, cls._failed_at(db, customer, sub))
        tier = "free" if eff == "terminal" else (existing["tier"] or row["tier"])
        if (_STATUS_OF_PHASE[eff], tier) != (row["status"], row["tier"]):
            db.execute(
                "UPDATE subscription_states SET phase=?, tier=?, state_at=?, tier_at=?, "
                "recorded_at=? WHERE stripe_customer_id=? AND stripe_subscription_id=?",
                (phase, row["tier"], at, at, now, customer, sub),
            )
            db.execute(
                "DELETE FROM subscription_failures "
                "WHERE stripe_customer_id=? AND stripe_subscription_id=?", (customer, sub))

    @classmethod
    def _join_state(
        cls, db: sqlite3.Connection, customer: str, sub: str, *,
        status: str, tier: str | None, created: int,
    ) -> str:
        """Join one subscription state report into the record.

        Returns ``new`` (first report of this subscription), ``state`` (its phase or tier
        changed), ``born`` (only the purchase time moved earlier) or ``same``.

        Newest report wins; at the same second the more restrictive phase wins; a
        report with no time (``created == 0``) is taken as the newest. The tier is
        joined on its own clock, so a report that carries none (a payment failure, a
        pause) never erases the tier an older report did.
        """
        phase = _phase_for(status, tier)
        now = format_utc(utc_now())
        cur = cls._sub_row(db, customer, sub)
        if cur is None:
            db.execute(
                "INSERT INTO subscription_states (stripe_customer_id, stripe_subscription_id, "
                "born, state_at, phase, tier, tier_at, recorded_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (customer, sub, 0 if phase == "terminal" else max(created, 0), max(created, 0),
                 phase, tier or "",
                 max(created, 0) if tier is not None else 0, now),
            )
            return "new"
        newer = (
            created == 0 or created > cur["state_at"]
            or (created == cur["state_at"] and _PHASE_RANK[phase] > _PHASE_RANK[cur["phase"]])
        )
        new_phase = phase if newer else cur["phase"]
        new_state_at = max(cur["state_at"], created) if newer else cur["state_at"]
        new_tier, new_tier_at = cur["tier"], cur["tier_at"]
        if tier is not None and (created == 0 or created > cur["tier_at"]
                                 or (created == cur["tier_at"] and newer)):
            new_tier, new_tier_at = tier, max(cur["tier_at"], created)
        # When the subscription was bought: the earliest report that was not its end. A
        # cancellation alone says nothing about when something began.
        born = min((b for b in (cur["born"], created if phase != "terminal" else 0) if b),
                   default=0)
        state_changed = (new_phase, new_state_at, new_tier, new_tier_at) != (
            cur["phase"], cur["state_at"], cur["tier"], cur["tier_at"])
        changed = state_changed or born != cur["born"]
        if changed:
            db.execute(
                "UPDATE subscription_states SET phase=?, state_at=?, tier=?, tier_at=?, born=?, "
                "recorded_at=? WHERE stripe_customer_id=? AND stripe_subscription_id=?",
                (new_phase, new_state_at, new_tier, new_tier_at, born, now, customer, sub),
            )
        return "state" if state_changed else ("born" if changed else "same")

    @staticmethod
    def _failed_at(db: sqlite3.Connection, customer: str, sub: str) -> int:
        found = db.execute(
            "SELECT failed_at FROM subscription_failures "
            "WHERE stripe_customer_id=? AND stripe_subscription_id=?", (customer, sub),
        ).fetchone()
        return int(found["failed_at"]) if found else 0

    @classmethod
    def _join_failure(cls, db: sqlite3.Connection, customer: str, sub: str, created: int) -> bool:
        """Remember the newest failed invoice of a subscription. True if it is newer."""
        if created <= cls._failed_at(db, customer, sub):
            return False
        db.execute(
            "INSERT OR REPLACE INTO subscription_failures "
            "(stripe_customer_id, stripe_subscription_id, failed_at, recorded_at) "
            "VALUES (?,?,?,?)",
            (customer, sub, created, format_utc(utc_now())),
        )
        return True

    @classmethod
    def _adopt_placeholder(cls, db: sqlite3.Connection, customer: str, sub: str) -> None:
        """A state recorded before any subscription id was known belongs to the first id seen."""
        if sub and cls._sub_row(db, customer, sub) is None \
                and cls._sub_row(db, customer, "") is not None:
            db.execute(
                "UPDATE subscription_states SET stripe_subscription_id=? "
                "WHERE stripe_customer_id=? AND stripe_subscription_id=''",
                (sub, customer),
            )
            db.execute(
                "UPDATE OR IGNORE subscription_failures SET stripe_subscription_id=? "
                "WHERE stripe_customer_id=? AND stripe_subscription_id=''",
                (sub, customer),
            )

    @staticmethod
    def _current_state(
        db: sqlite3.Connection, customer: str, fallback_tier: str
    ) -> dict[str, Any] | None:
        """What the customer's subscriptions add up to, or None if none is recorded.

        The current subscription is the newest-bought one that is paying (``active`` or
        ``past_due``); if none is, the newest-bought one that is paused; if none is, the
        newest-bought one that has ended. A purchase supersedes the subscriptions before it
        only among equals: cancelling or pausing the newest plan must not lock out a customer
        who still pays for an older one, which is what Stripe's own state (and the
        reconciler) says. The account is a function of the recorded states alone, so the
        order events arrived in cannot matter.
        """
        subs = db.execute(
            "SELECT * FROM subscription_states WHERE stripe_customer_id=?", (customer,)
        ).fetchall()
        if not subs:
            return None
        failed = {
            r["stripe_subscription_id"]: int(r["failed_at"])
            for r in db.execute(
                "SELECT stripe_subscription_id, failed_at FROM subscription_failures "
                "WHERE stripe_customer_id=?", (customer,))
        }

        def phase_of(r: sqlite3.Row) -> str:
            return _effective_phase(r, failed.get(r["stripe_subscription_id"], 0))

        # Paying (active, past_due) beats paused beats ended; within each, the newest-bought
        # (then the latest report). The same view the reconciler takes of Stripe.
        cur = max(subs, key=lambda r: (
            _CLASS_OF_PHASE[phase_of(r)], r["born"], r["state_at"], r["stripe_subscription_id"]))
        phase = phase_of(cur)
        failure = failed.get(cur["stripe_subscription_id"], 0)
        return {
            "sub": cur["stripe_subscription_id"],
            "status": _STATUS_OF_PHASE[phase],
            "tier": "free" if phase == "terminal" else (cur["tier"] or fallback_tier),
            "since": failure if cur["phase"] == "entitled" and phase == "past_due"
            else cur["state_at"],
            "at": max(cur["state_at"], failure),
        }

    @classmethod
    def _write_current(
        cls, db: sqlite3.Connection, row: sqlite3.Row, event_created: int
    ) -> str:
        """Re-derive the account from its subscriptions. Returns the current subscription id."""
        state = cls._current_state(db, row["stripe_customer_id"], row["tier"])
        assert state is not None
        if state["status"] != "past_due":
            since = 0
        elif row["status"] == "past_due" and row["past_due_since"]:
            since = row["past_due_since"]
        else:
            since = state["since"] or event_created or int(utc_now().timestamp())
        db.execute(
            "UPDATE accounts SET status=?, tier=?, stripe_subscription_id=?, updated_at=?, "
            "last_event_at=?, past_due_since=? WHERE id=?",
            (state["status"], state["tier"], state["sub"] or row["stripe_subscription_id"],
             format_utc(utc_now()), max(row["last_event_at"], event_created), since, row["id"]),
        )
        return str(state["sub"])

    @classmethod
    def _apply_state_db(
        cls,
        db: sqlite3.Connection,
        customer: str,
        status: str,
        tier: str | None,
        event_created: int,
        only_from: frozenset[str] | None = None,
        subscription_id: str = "",
        *,
        ours: bool = True,
        payment_failure: bool = False,
    ) -> str:
        """Apply one report about one subscription to the account that owns the customer.

        Returns ``unknown_customer``, ``not_ours`` (a subscription that is neither one of
        our plans nor one this customer is known to hold), ``not_applicable``,
        ``stale`` (the report is older than what is recorded for that subscription),
        ``other_subscription`` (recorded, but the account's current subscription is a
        different one, so the account did not change) or ``applied``.
        """
        row = db.execute(
            "SELECT * FROM accounts WHERE stripe_customer_id = ?", (customer,)
        ).fetchone() if customer else None
        if row is None:
            if payment_failure and customer and subscription_id:
                # The invoice can overtake the checkout that creates the account.
                cls._join_failure(db, customer, subscription_id, event_created)
            return "unknown_customer"
        cls._sync_from_account(db, row)
        sub = subscription_id or row["stripe_subscription_id"]
        known = cls._sub_row(db, customer, sub) is not None
        if subscription_id and not known and not ours and not payment_failure:
            # Another product's subscription on the same Stripe customer:
            # nothing about our plans.
            return "not_ours"
        if (only_from is not None and sub == row["stripe_subscription_id"]
                and row["status"] not in only_from):
            if payment_failure:
                # The account does not move, but the failure is a fact about the subscription:
                # if it later turns out to have been entitled at that moment (a revival that
                # overtook this invoice), the account must read past_due whatever the order.
                cls._join_failure(db, customer, sub, event_created)
            return "not_applicable"
        if payment_failure:
            if not cls._join_failure(db, customer, sub, event_created):
                return "stale"
            if not known:
                # An invoice for a subscription not seen yet (or for another product's):
                # kept, and it counts only if that subscription turns out to be ours.
                return "other_subscription"
            joined = "state"
        else:
            cls._adopt_placeholder(db, customer, sub)
            joined = cls._join_state(
                db, customer, sub, status=status, tier=tier, created=event_created)
            if joined == "same":
                return "stale"
        current = cls._write_current(
            db, db.execute("SELECT * FROM accounts WHERE id=?", (row["id"],)).fetchone(),
            event_created if joined != "born" else 0)
        after = db.execute("SELECT * FROM accounts WHERE id=?", (row["id"],)).fetchone()
        if joined == "born" and (after["status"], after["tier"], after["stripe_subscription_id"]) \
                == (row["status"], row["tier"], row["stripe_subscription_id"]):
            # Only the purchase time moved: the report itself is older than what is on record.
            return "stale"
        if sub == current:
            return "applied"
        # About a subscription the account does not follow; but if this report is what moved
        # the account (the paying subscription ended and a paused one now stands), it applied.
        moved = (after["status"], after["tier"], after["stripe_subscription_id"]) != (
            row["status"], row["tier"], row["stripe_subscription_id"])
        return "applied" if moved else "other_subscription"

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
            "DELETE FROM subscription_states WHERE recorded_at < ? AND stripe_customer_id "
            "NOT IN (SELECT stripe_customer_id FROM accounts WHERE stripe_customer_id <> '')",
            (format_utc(now - _ORPHAN_RETENTION),),
        )
        db.execute(
            "DELETE FROM subscription_failures WHERE recorded_at < ? AND stripe_customer_id "
            "NOT IN (SELECT stripe_customer_id FROM accounts WHERE stripe_customer_id <> '')",
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
        stripe_subscription_id: str = "",
        ours: bool = True,
        payment_failure: bool = False,
    ) -> str:
        """Apply one subscription state change, at most once per event id.

        Each report is recorded against the subscription it is about; the account is
        derived from the customer's subscriptions, so the order in which Stripe delivers
        events does not change the outcome. An event with no ``stripe_subscription_id``
        is about the account's current subscription. ``ours`` is false for a
        subscription whose price is none of our plans: unless this customer is already
        known to hold it, it is ignored entirely. ``payment_failure`` records an invoice
        failure against the subscription (``status`` and ``tier`` are not used then).

        Returns ``duplicate``, ``applied``, ``stale``, ``other_subscription`` (about a
        subscription that is not the account's current one: recorded, account unchanged),
        ``not_ours``, ``not_applicable``
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
                db, stripe_customer_id, status, tier, event_created, only_from,
                stripe_subscription_id, ours=ours, payment_failure=payment_failure,
            )
            if result == "unknown_customer" and hold_if_unknown and stripe_customer_id:
                self._adopt_placeholder(db, stripe_customer_id, stripe_subscription_id)
                self._join_state(
                    db, stripe_customer_id, stripe_subscription_id,
                    status=status, tier=tier, created=event_created)
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

        The purchased subscription is recorded alongside the customer's others and the
        account derived from all of them, so a checkout that arrives after the
        cancellation of an older subscription still grants what was bought.
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

            if not stripe_customer_id:
                row = self._upsert_db(
                    db, email=email, tier=tier, company=company,
                    stripe_customer_id="", stripe_subscription_id=stripe_subscription_id,
                    status="active", account_id="", event_created=event_created,
                )
            else:
                row = self._grant_subscription(
                    db, email=email, company=company, tier=tier,
                    customer=stripe_customer_id, sub=stripe_subscription_id,
                    created=event_created,
                )
            account_id = row["id"]

            key = self._issue_key_db(db, account_id, "issued at checkout")
            db.execute(
                "INSERT INTO pending_keys (session_id, account_id, api_key, tier, created_at) "
                "VALUES (?,?,?,?,?)",
                (session_id, account_id, key, tier, format_utc(utc_now())),
            )
            self._mark_event(db, event_id, "checkout.session.completed")
            self._mark_event(db, marker, "session")
        return {"result": "granted", "account_id": account_id}

    @classmethod
    def _grant_subscription(
        cls, db: sqlite3.Connection, *, email: str, company: str, tier: str, customer: str,
        sub: str, created: int,
    ) -> sqlite3.Row:
        existing = db.execute(
            "SELECT * FROM accounts WHERE stripe_customer_id = ?", (customer,)
        ).fetchone()
        if existing is not None:
            cls._sync_from_account(db, existing)
        elif cls._sub_row(db, customer, sub) is None:
            # A state held by an older build before this table existed.
            orphan = db.execute(
                "SELECT * FROM orphan_states WHERE stripe_customer_id = ?", (customer,)
            ).fetchone()
            if orphan is not None and not db.execute(
                "SELECT 1 FROM subscription_states WHERE stripe_customer_id=?", (customer,)
            ).fetchone():
                cls._join_state(db, customer, "", status=orphan["status"], tier=orphan["tier"],
                                created=orphan["event_created"])
        cls._adopt_placeholder(db, customer, sub)
        cls._join_state(db, customer, sub, status="active", tier=tier, created=created)
        db.execute("DELETE FROM orphan_states WHERE stripe_customer_id = ?", (customer,))
        if existing is None:
            now = format_utc(utc_now())
            state = cls._current_state(db, customer, tier)
            assert state is not None
            new_id = _new_id("acc")
            db.execute(
                "INSERT INTO accounts (id, email, company, tier, stripe_customer_id, "
                "stripe_subscription_id, status, created_at, updated_at, last_event_at, "
                "past_due_since) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (new_id, email, company, state["tier"], customer, state["sub"],
                 state["status"], now, now, max(created, state["at"], 0),
                 (state["since"] or created) if state["status"] == "past_due" else 0),
            )
            return db.execute("SELECT * FROM accounts WHERE id = ?", (new_id,)).fetchone()
        db.execute(
            "UPDATE accounts SET email=?, company=? WHERE id=?",
            (email or existing["email"], company or existing["company"], existing["id"]),
        )
        cls._write_current(
            db, db.execute("SELECT * FROM accounts WHERE id=?", (existing["id"],)).fetchone(),
            created)
        return db.execute("SELECT * FROM accounts WHERE id = ?", (existing["id"],)).fetchone()

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
            last_event_at=row["last_event_at"] if "last_event_at" in row.keys() else 0,
            past_due_since=row["past_due_since"] if "past_due_since" in row.keys() else 0,
            spend_limit_units=(
                row["spend_limit_units"] if "spend_limit_units" in row.keys() else 0),
            budget_alert_pct=(
                row["budget_alert_pct"] if "budget_alert_pct" in row.keys() else 80),
            source=row["source"] if "source" in row.keys() else "",
            grant_note=row["grant_note"] if "grant_note" in row.keys() else "",
            granted_at=row["granted_at"] if "granted_at" in row.keys() else "",
            granted_by=row["granted_by"] if "granted_by" in row.keys() else "",
            grant_expires_on=(
                row["grant_expires_on"] if "grant_expires_on" in row.keys() else ""),
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
        is touched except the subscription it follows, which becomes the one the finding
        names. Refuses (changing nothing) for the operator, an account
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
            "free", "register", "cell", "payg"
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
            # The account follows the subscription Stripe says it is paying for: left on
            # another one, that one's own end would be ignored as "not the current one".
            db.execute(
                "UPDATE accounts SET status=?, tier=?, stripe_subscription_id=?, updated_at=?, "
                "last_event_at=?, past_due_since=? WHERE id=?",
                (new_status, new_tier, stripe_subscription_id or row["stripe_subscription_id"],
                 now, max(row["last_event_at"], horizon), since, row["id"]),
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
            try:
                row = db.execute(
                    "SELECT * FROM entitlement_reconciliations WHERE account_id=? "
                    "ORDER BY id DESC LIMIT 1",
                    (account_id,),
                ).fetchone()
            except sqlite3.OperationalError as exc:
                if "no such table" not in str(exc):
                    raise
                return None  # a store not yet migrated has no history
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
        ``revoked``, ``already_revoked``, ``not_found``, ``ambiguous`` (a
        prefix shared by more than one live key of the account) or ``operator_key``
        (the key is bound to an operator: it is ended by disabling the operator,
        which carries the last-decider guard, never by this route).
        """
        now = format_utc(utc_now())
        with self._txn() as db:
            if key_hash:
                rows = db.execute(
                    "SELECT key_hash, revoked_at, operator_id FROM api_keys "
                    "WHERE key_hash=? AND account_id=?",
                    (key_hash, account_id),
                ).fetchall()
            elif key_prefix:
                rows = db.execute(
                    "SELECT key_hash, revoked_at, operator_id FROM api_keys "
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
            if live[0]["operator_id"]:
                return "operator_key"
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
        # An unknown or revoked key (a guess, a flood) is answered from a read: the write
        # lock, which every billing event and every metered call queues for, is taken only
        # for a key that exists, to record its use.
        if self.peek_key(key) is None:
            return None
        digest = hash_key(key)
        with self._txn() as db:
            row = db.execute(
                "SELECT k.prefix, k.account_id, k.operator_id AS op_id, "
                "o.name AS op_name, o.role AS op_role, o.disabled_at AS op_off, a.* "
                "FROM api_keys k JOIN accounts a ON a.id = k.account_id "
                "LEFT JOIN operators o ON o.id = k.operator_id "
                "WHERE k.key_hash = ? AND k.revoked_at IS NULL",
                (digest,),
            ).fetchone()
            if row is None or self._operator_off(row):
                return None
            db.execute(
                "UPDATE api_keys SET last_used=? WHERE key_hash=?",
                (format_utc(utc_now()), digest),
            )
        return self._principal(row)

    def peek_key(self, key: str) -> Principal | None:
        """Like :meth:`resolve_key` but read-only: no write lock, no ``last_used``.

        For checks that run before authentication proper (the body-size guard),
        where taking the single write lock for every request that carries a
        guessed key would let anyone queue behind, and in front of, real writes.
        """
        db = self._connect()
        try:
            row = db.execute(
                "SELECT k.prefix, k.account_id, k.operator_id AS op_id, "
                "o.name AS op_name, o.role AS op_role, o.disabled_at AS op_off, a.* "
                "FROM api_keys k JOIN accounts a ON a.id = k.account_id "
                "LEFT JOIN operators o ON o.id = k.operator_id "
                "WHERE k.key_hash = ? AND k.revoked_at IS NULL",
                (hash_key(key),),
            ).fetchone()
        finally:
            db.close()
        if row is None or self._operator_off(row):
            return None
        return self._principal(row)

    @staticmethod
    def _operator_off(row: sqlite3.Row) -> bool:
        """A key bound to an operator who has been disabled authenticates nobody."""
        return bool(row["op_id"]) and (row["op_name"] is None or row["op_off"] is not None)

    def _principal(self, row: sqlite3.Row) -> Principal:
        return Principal(
            account=self._row_to_account(row), key_prefix=row["prefix"],
            operator_id=row["op_id"] or "", operator_name=row["op_name"] or "",
            operator_role=row["op_role"] or "")

    # -- operators --------------------------------------------------------
    def create_operator(
        self, account_id: str, name: str, role: str, *, created_by: str = "",
        only_if_none: bool = False, max_active_keys: int | None = None,
    ) -> tuple[str, str]:
        """A new operator and its first key (returned once). ``(operator_id, key)``.

        ``only_if_none`` makes "the account has no enabled operator" and the insert one
        transaction, so two concurrent bootstraps cannot both succeed. Names are unique
        among an account's enabled operators (case-insensitively). ``max_active_keys``
        applies the plan's live-key cap to the operator's key.
        """
        if role not in ("contributor", "decider"):
            raise ValueError("role must be 'contributor' or 'decider'")
        if not name.strip():
            raise ValueError("an operator needs a name")
        op_id = _new_id("op")
        with self._txn() as db:
            if db.execute("SELECT 1 FROM accounts WHERE id=?", (account_id,)).fetchone() is None:
                raise ValueError("no such account")
            if only_if_none and db.execute(
                    "SELECT 1 FROM operators WHERE account_id=? LIMIT 1",
                    (account_id,)).fetchone() is not None:
                # One-shot: "has ever had an operator", not "has one enabled now".
                # Otherwise offboarding the last decider would hand an account-level
                # key (an agent, the watch, an MCP client) a fresh bootstrap.
                raise OperatorsExistError(
                    "this account already has (or has had) operators; only a decider "
                    "can add more.")
            rows = db.execute(
                "SELECT name FROM operators WHERE account_id=? AND disabled_at IS NULL",
                (account_id,)).fetchall()
            if any(r["name"].lower() == name.strip().lower() for r in rows):
                raise ValueError(f"an operator named {name.strip()!r} already exists")
            db.execute(
                "INSERT INTO operators (id, account_id, name, role, created_at, created_by)"
                " VALUES (?,?,?,?,?,?)",
                (op_id, account_id, name.strip(), role, format_utc(utc_now()), created_by))
            key = self._issue_key_db(db, account_id, f"operator {name.strip()}",
                                     max_active_keys)
            db.execute("UPDATE api_keys SET operator_id=? WHERE key_hash=?",
                       (op_id, hash_key(key)))
        return op_id, key

    def operators_for(self, account_id: str) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            return [
                {"id": r["id"], "name": r["name"], "role": r["role"],
                 "created_at": r["created_at"], "created_by": r["created_by"],
                 "disabled": r["disabled_at"] is not None,
                 "disabled_at": r["disabled_at"]}
                for r in db.execute(
                    "SELECT * FROM operators WHERE account_id=? ORDER BY created_at, id",
                    (account_id,))
            ]
        finally:
            db.close()

    def disable_operator(self, account_id: str, operator_id: str) -> str:
        """Disable an operator of this account and revoke every key bound to it.

        Scoped by account in the query itself. Returns ``disabled``,
        ``already_disabled``, ``not_found`` or ``last_decider`` (the account's only
        enabled decider is not disabled: nobody could then close a case, and the
        account would have no human who can create the next decider).
        """
        now = format_utc(utc_now())
        with self._txn() as db:
            row = db.execute(
                "SELECT disabled_at, role FROM operators WHERE id=? AND account_id=?",
                (operator_id, account_id)).fetchone()
            if row is None:
                return "not_found"
            if row["disabled_at"] is not None:
                return "already_disabled"
            if row["role"] == "decider" and db.execute(
                    "SELECT COUNT(*) FROM operators WHERE account_id=? AND role='decider' "
                    "AND disabled_at IS NULL AND id<>?",
                    (account_id, operator_id)).fetchone()[0] == 0:
                return "last_decider"
            db.execute("UPDATE operators SET disabled_at=? WHERE id=?", (now, operator_id))
            db.execute(
                "UPDATE api_keys SET revoked_at=? WHERE operator_id=? AND revoked_at IS NULL",
                (now, operator_id))
            return "disabled"

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

    # -- durable usage ----------------------------------------------------
    @staticmethod
    def _usage_decision(
        db: sqlite3.Connection, account: Account, scope: str, quantity: int,
        moment: datetime, allowance: int,
    ) -> tuple[int, int]:
        """``(used_today, billable_units)`` for ``quantity`` more, or a refusal.

        The one place the allowance and the spend limit are decided; both the
        write path and the read-only pre-check call it, so they cannot disagree.
        """
        today = moment.date().isoformat()
        row = db.execute(
            "SELECT count FROM usage WHERE subject=? AND scope=? AND day=?",
            (account.id, scope, today),
        ).fetchone()
        used = row["count"] if row else 0
        if used + quantity <= allowance:
            return used, 0
        over = used + quantity - max(allowance, used)
        if not overage_allowed(account):
            raise QuotaExceededError(scope, allowance, used, account.plan.tier)
        start, end = month_bounds(moment)
        so_far = db.execute(
            "SELECT COALESCE(SUM(billable_quantity), 0) FROM usage_events "
            "WHERE account_id=? AND occurred_at >= ? AND occurred_at < ?",
            (account.id, start, end),
        ).fetchone()[0]
        if so_far + over > account.spend_limit_units:
            raise SpendLimitError(scope, account.spend_limit_units, so_far, over)
        return used, over

    @staticmethod
    def _check_request(scope: str, quantity: int, key: str | None) -> None:
        if scope not in METERED_SCOPES:
            raise ValueError(f"{scope!r} is not a metered scope")
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 1:
            raise ValueError("quantity must be a positive integer")
        if key is not None and not valid_idempotency_key(key):
            raise ValueError("idempotency key must be 1-255 characters of A-Z a-z 0-9 . _ : -")

    def record_usage(
        self,
        account_id: str,
        scope: str,
        quantity: int,
        idempotency_key: str,
        *,
        source: str = "api",
        now: datetime | None = None,
        fingerprint: str = "",
    ) -> UsageRecord:
        """Count successful metered work, atomically with the quota check.

        One ``BEGIN IMMEDIATE`` transaction does all of: find a previous record
        under this key (a retry returns it and counts nothing), read the account
        and its plan, read today's counter, decide (inside the allowance;
        beyond it and billable; or refuse), and write the counter and the event.
        There is no moment at which two callers can both take the last unit of
        an allowance or of a spend limit.

        Raises :class:`QuotaExceededError` (allowance spent, billing not on for
        this account), :class:`SpendLimitError` (billing on, limit reached) or
        :class:`IdempotencyConflictError`; in each case nothing is written.
        ``ValueError`` for an unmetered scope, a non-positive quantity or a
        malformed key; ``LookupError`` for an unknown account.

        ``fingerprint`` binds the key to the request it was first used for (the
        API passes a hash of scope, route and canonical body). The same key with
        another fingerprint is an :class:`IdempotencyConflictError`: a key names
        one operation, not a licence to send anything. An empty fingerprint on
        either side (a direct caller, or a row an older build wrote) compares
        on scope and quantity alone, as before.

        A plan that does not meter the scope (Register and Cell have no daily
        cap) records nothing and returns ``recorded=False``.
        """
        self._check_request(scope, quantity, idempotency_key)
        moment = now or utc_now()
        with self._txn() as db:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise LookupError(f"no account {account_id!r}")
            previous = db.execute(
                "SELECT * FROM usage_events WHERE account_id=? AND idempotency_key=?",
                (account_id, idempotency_key),
            ).fetchone()
            if previous is not None:
                if (previous["scope"], previous["quantity"]) != (scope, quantity) \
                        or self._fingerprint_differs(previous, fingerprint):
                    raise IdempotencyConflictError(
                        idempotency_key, previous["scope"], previous["quantity"])
                return UsageRecord(
                    event_id=previous["event_id"], scope=scope, quantity=quantity,
                    billable_quantity=previous["billable_quantity"],
                    billed_state=previous["billed_state"], duplicate=True)
            account = self._row_to_account(row)
            allowance = allowance_for(account.plan, scope)
            if allowance is None:
                return UsageRecord(event_id="", scope=scope, quantity=quantity,
                                   billable_quantity=0, billed_state="", duplicate=False,
                                   recorded=False)
            used, billable = self._usage_decision(db, account, scope, quantity, moment, allowance)
            today = moment.date().isoformat()
            if used == 0:
                # First spend of the day for this account and scope: drop what is
                # old so these tables are bounded by recent activity. Billable
                # events are never dropped here; only those inside the allowance.
                cutoff = (moment.date() - timedelta(days=7)).isoformat()
                db.execute("DELETE FROM usage WHERE day < ?", (cutoff,))
                db.execute(
                    "DELETE FROM usage_events WHERE billed_state='included' AND occurred_at < ?",
                    (format_utc(moment - _INCLUDED_RETENTION),),
                )
            db.execute(
                "INSERT INTO usage (subject, scope, day, count) VALUES (?,?,?,?) "
                "ON CONFLICT(subject, scope, day) DO UPDATE SET count = count + ?",
                (account_id, scope, today, quantity, quantity),
            )
            event_id = "uev_" + secrets.token_hex(12)
            state = "pending" if billable else "included"
            db.execute(
                "INSERT INTO usage_events (event_id, account_id, scope, quantity, "
                "billable_quantity, idempotency_key, fingerprint, occurred_at, source, "
                "billed_state) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (event_id, account_id, scope, quantity, billable, idempotency_key,
                 fingerprint, format_utc(moment), source, state),
            )
            return UsageRecord(event_id=event_id, scope=scope, quantity=quantity,
                               billable_quantity=billable, billed_state=state,
                               duplicate=False)

    @staticmethod
    def _fingerprint_differs(previous: sqlite3.Row, fingerprint: str) -> bool:
        stored = previous["fingerprint"] if "fingerprint" in previous.keys() else ""
        return bool(stored) and bool(fingerprint) and stored != fingerprint

    def check_usage(
        self, account_id: str, scope: str, quantity: int = 1,
        idempotency_key: str | None = None, *, now: datetime | None = None,
        fingerprint: str = "",
    ) -> None:
        """Would :meth:`record_usage` refuse this? Read-only; takes no write lock.

        A cheap early refusal, so a caller who is certainly over their limit
        costs the service no computation. It is advisory: the decision that
        counts is the one :meth:`record_usage` makes inside its transaction. A
        retry of work already recorded under ``idempotency_key`` always passes;
        the same key with a different ``fingerprint`` raises
        :class:`IdempotencyConflictError` before any work is done.
        """
        self._check_request(scope, quantity, idempotency_key)
        moment = now or utc_now()
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise LookupError(f"no account {account_id!r}")
            account = self._row_to_account(row)
            allowance = allowance_for(account.plan, scope)
            if allowance is None:
                return
            previous = None if idempotency_key is None else db.execute(
                "SELECT * FROM usage_events WHERE account_id=? AND idempotency_key=?",
                (account_id, idempotency_key),
            ).fetchone()
            if previous is not None:
                if (previous["scope"], previous["quantity"]) != (scope, quantity) \
                        or self._fingerprint_differs(previous, fingerprint):
                    raise IdempotencyConflictError(
                        idempotency_key or "", previous["scope"], previous["quantity"])
                return
            self._usage_decision(db, account, scope, quantity, moment, allowance)
        finally:
            db.close()

    def check_quota(
        self, subject: str, scope: str, limit: int | None, tier: str = "free"
    ) -> None:
        """Read-only pre-check for a caller with no account (an address bucket)."""
        if limit is None:
            return
        today = utc_now().date().isoformat()
        db = self._connect()
        try:
            row = db.execute(
                "SELECT count FROM usage WHERE subject=? AND scope=? AND day=?",
                (subject, scope, today),
            ).fetchone()
        finally:
            db.close()
        used = row["count"] if row else 0
        if used >= limit:
            raise QuotaExceededError(scope, limit, used, tier)

    def set_spend_limit(
        self, account_id: str, units: int | None = None, budget_alert_pct: int | None = None,
    ) -> Account:
        """Set an account's monthly spend limit (billable units) and/or alert threshold.

        The limit applies from the very next call. Lowering it below what has
        already been used this month stops further billing at once; it never
        un-bills anything. ``ValueError`` outside ``0..MAX_SPEND_LIMIT_UNITS`` or
        ``1..100``; ``LookupError`` for an unknown account.
        """
        if units is not None and (
            isinstance(units, bool) or not isinstance(units, int)
            or not 0 <= units <= MAX_SPEND_LIMIT_UNITS
        ):
            raise ValueError(f"spend limit must be an integer 0..{MAX_SPEND_LIMIT_UNITS}")
        if budget_alert_pct is not None and (
            isinstance(budget_alert_pct, bool) or not isinstance(budget_alert_pct, int)
            or not 1 <= budget_alert_pct <= 100
        ):
            raise ValueError("budget alert percentage must be an integer 1..100")
        with self._txn() as db:
            row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise LookupError(f"no account {account_id!r}")
            db.execute(
                "UPDATE accounts SET spend_limit_units=?, budget_alert_pct=?, updated_at=? "
                "WHERE id=?",
                (row["spend_limit_units"] if units is None else units,
                 row["budget_alert_pct"] if budget_alert_pct is None else budget_alert_pct,
                 format_utc(utc_now()), account_id),
            )
            return self._row_to_account(
                db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())

    def _read_events(self, sql: str, args: tuple[Any, ...]) -> list[sqlite3.Row]:
        db = self._connect()
        try:
            try:
                return db.execute(sql, args).fetchall()
            except sqlite3.OperationalError as exc:
                if "no such table" not in str(exc):
                    raise
                return []  # a store not yet migrated has recorded nothing
        finally:
            db.close()

    def usage_events(
        self, account_id: str, *, start: str = "", end: str = "9999", limit: int = 50,
    ) -> list[dict[str, Any]]:
        """The account's own events in ``[start, end)``, newest first. Never another account's."""
        rows = self._read_events(
            "SELECT event_id, scope, quantity, billable_quantity, idempotency_key, "
            "occurred_at, source, billed_state FROM usage_events "
            "WHERE account_id=? AND occurred_at >= ? AND occurred_at < ? "
            "ORDER BY occurred_at DESC, rowid DESC LIMIT ?",
            (account_id, start, end, max(1, min(int(limit), 500))),
        )
        return [dict(r) for r in rows]

    def usage_totals(
        self, account_id: str, *, start: str = "", end: str = "9999"
    ) -> dict[str, dict[str, int]]:
        """Per scope: units counted and units billable in ``[start, end)``."""
        rows = self._read_events(
            "SELECT scope, SUM(quantity) AS q, SUM(billable_quantity) AS b FROM usage_events "
            "WHERE account_id=? AND occurred_at >= ? AND occurred_at < ? GROUP BY scope",
            (account_id, start, end),
        )
        return {r["scope"]: {"quantity": r["q"], "billable_quantity": r["b"]} for r in rows}

    def billable_by_state(self, account_id: str = "") -> dict[str, int]:
        """Billable units by ``billed_state`` (all accounts if ``account_id`` is empty)."""
        rows = self._read_events(
            "SELECT billed_state, SUM(billable_quantity) AS b FROM usage_events "
            "WHERE billable_quantity > 0 AND (? = '' OR account_id = ?) GROUP BY billed_state",
            (account_id, account_id),
        )
        return {r["billed_state"]: r["b"] for r in rows}

    # -- the outbox: billable events on their way to the provider ----------
    def claim_usage_events(
        self,
        *,
        now: datetime | None = None,
        limit: int = 200,
        lease: timedelta = USAGE_LEASE,
        resend_window: timedelta = USAGE_RESEND_WINDOW,
        max_age: timedelta = USAGE_MAX_AGE,
    ) -> list[dict[str, Any]]:
        """Take billable events that have not been acknowledged, once, for sending.

        One write transaction picks the rows and marks them ``sending`` (with the
        attempt time) before anything touches the network, so two reporters never
        send the same row at the same moment and a crash leaves a visible
        ``sending`` row rather than a lost or double-sent one. A row is claimable
        if it is ``pending``, or ``sending`` with a lease older than ``lease``
        (its sender died or is hopelessly slow). Re-sending is safe only while
        the provider still dedupes on the identifier: past ``resend_window`` from
        the *first* attempt - or, for a never-sent row, past ``max_age`` from when
        the usage happened (the provider refuses timestamps older than that) - the
        row becomes ``ambiguous`` and is **not** sent; reconciliation decides.
        """
        moment = now or utc_now()
        stamp = format_utc(moment)
        with self._txn() as db:
            rows = db.execute(
                "SELECT e.*, a.stripe_customer_id AS customer FROM usage_events e "
                "LEFT JOIN accounts a ON a.id = e.account_id "
                "WHERE e.billable_quantity > 0 AND (e.billed_state = 'pending' OR "
                "(e.billed_state = 'sending' AND e.last_attempt_at <= ?)) "
                "ORDER BY e.rowid LIMIT ?",
                (format_utc(moment - lease), max(1, int(limit))),
            ).fetchall()
            claimed: list[dict[str, Any]] = []
            for row in rows:
                first = row["first_attempt_at"]
                too_old = (
                    _parse_stamp(first) < moment - resend_window if first
                    else _parse_stamp(row["occurred_at"]) < moment - max_age
                )
                if too_old:
                    db.execute(
                        "UPDATE usage_events SET billed_state='ambiguous', last_error=? "
                        "WHERE event_id=? AND billed_state IN ('pending','sending')",
                        ("not re-sent: past the window in which the provider dedupes "
                         "on the identifier" if first else
                         "not sent: older than the provider accepts", row["event_id"]),
                    )
                    continue
                db.execute(
                    "UPDATE usage_events SET billed_state='sending', "
                    "first_attempt_at=CASE WHEN first_attempt_at='' THEN ? ELSE first_attempt_at END, "
                    "last_attempt_at=?, attempts=attempts+1 WHERE event_id=?",
                    (stamp, stamp, row["event_id"]),
                )
                claimed.append({
                    "event_id": row["event_id"], "account_id": row["account_id"],
                    "scope": row["scope"], "billable_quantity": row["billable_quantity"],
                    "occurred_at": row["occurred_at"], "stripe_customer_id": row["customer"] or "",
                    "attempts": row["attempts"] + 1,
                })
            return claimed

    def mark_usage_billed(self, event_id: str, provider_event_id: str) -> bool:
        """Record the provider's acknowledgement. Only a ``sending`` row can become ``billed``."""
        with self._txn() as db:
            return db.execute(
                "UPDATE usage_events SET billed_state='billed', provider_event_id=?, "
                "last_error='' WHERE event_id=? AND billed_state='sending'",
                (provider_event_id, event_id),
            ).rowcount > 0

    def mark_usage_rejected(self, event_id: str, error: str) -> bool:
        """The provider refused the event for good. Never retried automatically."""
        with self._txn() as db:
            return db.execute(
                "UPDATE usage_events SET billed_state='rejected', last_error=? "
                "WHERE event_id=? AND billed_state='sending'",
                (error[:300], event_id),
            ).rowcount > 0

    def release_usage_events(self, event_ids: Sequence[str], error: str) -> int:
        """Give claimed events back after a run-level failure (bad key, wrong meter).

        ``sending`` -> ``pending`` with the claim undone (one attempt fewer; the
        first-attempt stamp cleared if this claim was the only attempt), so the
        dedupe window of a row that really was sent earlier is not extended and
        a row never sent does not start its clock. Returns how many moved.
        """
        moved = 0
        with self._txn() as db:
            for event_id in event_ids:
                moved += db.execute(
                    "UPDATE usage_events SET billed_state='pending', "
                    "attempts=MAX(attempts-1, 0), "
                    "first_attempt_at=CASE WHEN attempts<=1 THEN '' ELSE first_attempt_at END, "
                    "last_attempt_at=CASE WHEN attempts<=1 THEN '' ELSE last_attempt_at END, "
                    "last_error=? WHERE event_id=? AND billed_state='sending'",
                    (error[:300], event_id),
                ).rowcount
        return moved

    def requeue_rejected_usage(self, event_ids: Sequence[str] | None = None) -> list[str]:
        """Operator action: put ``rejected`` events back to ``pending``. Returns their ids.

        Nothing calls this automatically. A rejection was Stripe refusing the
        event itself, or (before configuration errors were told apart) a rotated
        key or wrong meter name; either way a person decides it is worth another
        try. The attempt history is cleared so the dedupe window starts afresh -
        safe because a refused event was never accepted - and the usual age limit
        still applies when the row is next claimed. ``event_ids=None`` means
        every rejected event.
        """
        wanted = None if event_ids is None else set(event_ids)
        moved: list[str] = []
        with self._txn() as db:
            for row in db.execute(
                "SELECT event_id, last_error FROM usage_events "
                "WHERE billed_state='rejected' ORDER BY rowid"
            ).fetchall():
                if wanted is not None and row["event_id"] not in wanted:
                    continue
                db.execute(
                    "UPDATE usage_events SET billed_state='pending', attempts=0, "
                    "first_attempt_at='', last_attempt_at='', last_error=? "
                    "WHERE event_id=? AND billed_state='rejected'",
                    (("requeued by operator; was: " + row["last_error"])[:300], row["event_id"]),
                )
                moved.append(row["event_id"])
        return moved

    def rejected_usage_event_ids(self) -> list[str]:
        """The ids ``requeue_rejected_usage()`` would move. Read-only."""
        return [r["event_id"] for r in self._read_events(
            "SELECT event_id FROM usage_events WHERE billed_state='rejected' ORDER BY rowid", ())]

    def note_usage_error(self, event_id: str, error: str) -> None:
        """A send failed without a verdict (timeout, 5xx). The row stays ``sending``."""
        with self._txn() as db:
            db.execute(
                "UPDATE usage_events SET last_error=? WHERE event_id=? AND billed_state='sending'",
                (error[:300], event_id),
            )

    def resolve_ambiguous_usage(self, event_id: str, *, billed: bool, note: str) -> bool:
        """Settle an ``ambiguous`` event with evidence the caller holds (reconciliation).

        ``billed=True``: the provider's totals prove it was received. ``False``:
        they prove it was not, so it goes back to ``pending`` to be sent once.
        """
        with self._txn() as db:
            if billed:
                cur = db.execute(
                    "UPDATE usage_events SET billed_state='billed', provider_event_id=event_id, "
                    "last_error=? WHERE event_id=? AND billed_state='ambiguous'",
                    (note[:300], event_id),
                )
            else:
                cur = db.execute(
                    "UPDATE usage_events SET billed_state='pending', first_attempt_at='', "
                    "last_attempt_at='', last_error=? WHERE event_id=? AND billed_state='ambiguous'",
                    (note[:300], event_id),
                )
            return cur.rowcount > 0

    def usage_events_all(self, *, start: str = "", end: str = "9999") -> list[dict[str, Any]]:
        """Every billable event in ``[start, end)``, every account. For reconciliation only."""
        rows = self._read_events(
            "SELECT e.*, a.stripe_customer_id AS customer, a.spend_limit_units AS spend_limit "
            "FROM usage_events e LEFT JOIN accounts a ON a.id = e.account_id "
            "WHERE e.billable_quantity > 0 AND e.occurred_at >= ? AND e.occurred_at < ? "
            "ORDER BY e.rowid",
            (start, end),
        )
        return [dict(r) for r in rows]

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
