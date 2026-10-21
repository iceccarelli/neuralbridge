"""Durable usage metering: the foundation pay-as-you-go stands on.

What is pinned here, and why each matters to a customer who might one day be
billed from it:

* usage is recorded in the **same transaction** as the quota check, so there is
  no window in which the cap can be overshot and nothing to reconcile later;
* a retry with the same idempotency key neither double-counts nor double-bills;
* only **successful** work is recorded — a 422 or a 5xx costs nothing;
* when the allowance is gone and pay-as-you-go is off for the account, or its
  spend limit is reached, the API refuses with a 429 that says what to do and
  records nothing;
* ``GET /v1/usage`` shows the caller their own account and nobody else's, and
  no total is ever taken from the client.

Real SQLite files, real FastAPI app, real threads and real processes; the only
thing faked anywhere in billing is Stripe's HTTP (see ``test_assurance_payg.py``).
"""

from __future__ import annotations

import importlib
import json
import sqlite3
import subprocess
import sys
import textwrap
import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing.accounts import (
    AccountStore,
    IdempotencyConflictError,
    QuotaExceededError,
    SpendLimitError,
)
from assurance.billing.plans import PLANS

OPERATOR_KEY = "operator-key-usage"
VALIDATE = {"track": "actively_exploited_vulnerability", "stage": "early_warning",
            "payload": {}}
SEPARATION = {"robot_speed_mm_s": 250, "reaction_time_s": 0.1, "stop_time_s": 0.2,
              "stop_distance_mm": 50, "measured_at_speed_mm_s": 250,
              "intrusion_distance_mm": 100}
ALLOWANCE = PLANS["free"].validations_per_day  # 20


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL",
                 "ASSURANCE_TENANT_LEDGERS", "ASSURANCE_TRUST_FLY_PROXY"):
        monkeypatch.delenv(name, raising=False)
    # Pay-as-you-go is off unless BOTH are set; tests switch it on explicitly.
    monkeypatch.delenv("ASSURANCE_PRICE_PAYG", raising=False)
    monkeypatch.delenv("ASSURANCE_PAYG_METER_EVENT", raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def payg_on(monkeypatch):
    monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_payg_test")
    monkeypatch.setenv("ASSURANCE_PAYG_METER_EVENT", "nb_verification_ops")


@pytest.fixture()
def store(env):
    return AccountStore(env / "accounts.db")


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


def payg_account(store, email="p@example.de", *, limit=10, tier="payg"):
    account = store.upsert_account(email=email, tier=tier, stripe_customer_id=f"cus_{email}")
    if limit is not None:
        store.set_spend_limit(account.id, limit)
    return account


def events(store, account_id):
    db = sqlite3.connect(store.path)
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(
            "SELECT * FROM usage_events WHERE account_id=? ORDER BY rowid", (account_id,))]
    finally:
        db.close()


def counter(store, account_id, scope="validate"):
    return store.usage_today(account_id).get(scope, 0)


# ---------------------------------------------------------------------------
# 1. the store: one transaction, one decision
# ---------------------------------------------------------------------------
class TestRecordUsageInTheQuotaTransaction:
    def test_work_inside_the_allowance_is_recorded_as_included(self, store, payg_on):
        a = payg_account(store)
        rec = store.record_usage(a.id, "validate", 1, "k-1")
        assert (rec.billed_state, rec.billable_quantity, rec.duplicate) == ("included", 0, False)
        assert counter(store, a.id) == 1
        [row] = events(store, a.id)
        assert (row["scope"], row["quantity"], row["idempotency_key"], row["source"]) == (
            "validate", 1, "k-1", "api")
        assert row["occurred_at"].endswith("Z") and row["provider_event_id"] == ""

    def test_the_first_unit_past_the_allowance_is_billable_when_payg_is_on(self, store, payg_on):
        a = payg_account(store, limit=3)
        for i in range(ALLOWANCE):
            assert store.record_usage(a.id, "validate", 1, f"in-{i}").billable_quantity == 0
        rec = store.record_usage(a.id, "validate", 1, "over-1")
        assert (rec.billed_state, rec.billable_quantity) == ("pending", 1)
        assert counter(store, a.id) == ALLOWANCE + 1

    def test_a_free_account_past_the_allowance_is_refused_and_nothing_is_written(self, store):
        a = store.upsert_account(email="f@example.de", tier="free")
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        before = (events(store, a.id), counter(store, a.id))
        with pytest.raises(QuotaExceededError) as caught:
            store.record_usage(a.id, "validate", 1, "one-too-many")
        assert caught.value.limit == ALLOWANCE
        assert (events(store, a.id), counter(store, a.id)) == before

    def test_payg_that_is_not_configured_on_the_deployment_does_not_bill(self, store):
        # tier payg but no ASSURANCE_PRICE_PAYG / meter: off by default.
        a = payg_account(store, limit=100)
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        with pytest.raises(QuotaExceededError):
            store.record_usage(a.id, "validate", 1, "over")
        assert [e for e in events(store, a.id) if e["billed_state"] != "included"] == []

    def test_a_lapsed_payg_account_cannot_run_up_charges(self, store, payg_on):
        a = payg_account(store, limit=100)
        store.set_status(stripe_customer_id=a.stripe_customer_id, status="cancelled",
                         tier="free", event_created=10)
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        with pytest.raises(QuotaExceededError):
            store.record_usage(a.id, "validate", 1, "over")

    def test_the_default_spend_limit_is_zero_so_nothing_is_billed_unasked(self, store, payg_on):
        a = payg_account(store, limit=None)
        assert store.account(a.id).spend_limit_units == 0
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        with pytest.raises(SpendLimitError) as caught:
            store.record_usage(a.id, "validate", 1, "over")
        assert (caught.value.limit_units, caught.value.used_units) == (0, 0)

    def test_the_spend_limit_is_a_hard_stop_in_units(self, store, payg_on):
        a = payg_account(store, limit=4)
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        for i in range(4):
            assert store.record_usage(a.id, "validate", 1, f"over-{i}").billable_quantity == 1
        before = (events(store, a.id), counter(store, a.id))
        with pytest.raises(SpendLimitError) as caught:
            store.record_usage(a.id, "validate", 1, "over-4")
        assert (caught.value.limit_units, caught.value.used_units) == (4, 4)
        assert (events(store, a.id), counter(store, a.id)) == before

    def test_the_limit_spans_every_metered_scope(self, store, payg_on):
        a = payg_account(store, limit=2)
        for scope, allowance in (("validate", 20), ("separation", 20)):
            for i in range(allowance):
                store.record_usage(a.id, scope, 1, f"{scope}-in-{i}")
        store.record_usage(a.id, "validate", 1, "v-over")
        store.record_usage(a.id, "separation", 1, "s-over")
        with pytest.raises(SpendLimitError):
            store.record_usage(a.id, "validate", 1, "v-over-2")

    def test_a_call_that_straddles_the_allowance_splits_exactly(self, store, payg_on):
        a = payg_account(store, limit=10)
        for i in range(ALLOWANCE - 1):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        rec = store.record_usage(a.id, "validate", 3, "straddle")
        assert (rec.quantity, rec.billable_quantity, rec.billed_state) == (3, 2, "pending")

    def test_a_straddling_call_that_would_break_the_limit_is_refused_whole(self, store, payg_on):
        a = payg_account(store, limit=1)
        for i in range(ALLOWANCE - 1):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        with pytest.raises(SpendLimitError):
            store.record_usage(a.id, "validate", 3, "straddle")
        assert counter(store, a.id) == ALLOWANCE - 1

    def test_a_paid_unmetered_plan_records_nothing(self, store):
        a = store.upsert_account(email="r@example.de", tier="register", stripe_customer_id="c")
        rec = store.record_usage(a.id, "validate", 1, "k")
        assert rec.recorded is False
        assert events(store, a.id) == [] and counter(store, a.id) == 0

    def test_unknown_scopes_and_nonsense_quantities_are_refused(self, store):
        a = store.upsert_account(email="f@example.de", tier="free")
        for bad in ((a.id, "cases", 1, "k"), (a.id, "validate", 0, "k"),
                    (a.id, "validate", -1, "k"), (a.id, "validate", 1, ""),
                    (a.id, "validate", 1, "x" * 300)):
            with pytest.raises(ValueError):
                store.record_usage(*bad)
        with pytest.raises(LookupError):
            store.record_usage("acc_does_not_exist", "validate", 1, "k")
        assert events(store, a.id) == []

    def test_cases_and_incident_handling_are_not_metered(self):
        from assurance.billing.plans import METERED_SCOPES

        assert set(METERED_SCOPES) == {
            "validate", "separation", "machinery_diff", "advisory_check"}


# ---------------------------------------------------------------------------
# 2. idempotency
# ---------------------------------------------------------------------------
class TestIdempotency:
    def test_a_retry_with_the_same_key_counts_once(self, store, payg_on):
        a = payg_account(store)
        first = store.record_usage(a.id, "validate", 1, "retry-me")
        again = store.record_usage(a.id, "validate", 1, "retry-me")
        assert again.duplicate is True and again.event_id == first.event_id
        assert len(events(store, a.id)) == 1 and counter(store, a.id) == 1

    def test_a_retried_billable_unit_is_billed_once(self, store, payg_on):
        a = payg_account(store, limit=5)
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"in-{i}")
        for _ in range(5):
            store.record_usage(a.id, "validate", 1, "the-one")
        billable = [e for e in events(store, a.id) if e["billed_state"] == "pending"]
        assert len(billable) == 1 and billable[0]["billable_quantity"] == 1

    def test_a_retry_of_accepted_work_succeeds_even_when_the_allowance_is_now_gone(
            self, store, payg_on):
        a = store.upsert_account(email="f@example.de", tier="free")
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"k-{i}")
        # Key k-3 was accepted; its retry must not turn into a 429.
        assert store.record_usage(a.id, "validate", 1, "k-3").duplicate is True

    def test_the_same_key_for_different_work_is_a_conflict_not_a_free_pass(self, store, payg_on):
        a = payg_account(store)
        store.record_usage(a.id, "validate", 1, "reused")
        with pytest.raises(IdempotencyConflictError):
            store.record_usage(a.id, "separation", 1, "reused")
        with pytest.raises(IdempotencyConflictError):
            store.record_usage(a.id, "validate", 2, "reused")
        assert len(events(store, a.id)) == 1

    def test_keys_are_per_account(self, store, payg_on):
        a, b = payg_account(store, "a@example.de"), payg_account(store, "b@example.de")
        store.record_usage(a.id, "validate", 1, "shared-name")
        rec = store.record_usage(b.id, "validate", 1, "shared-name")
        assert rec.duplicate is False
        assert counter(store, a.id) == 1 and counter(store, b.id) == 1

    def test_the_uniqueness_is_in_the_schema_not_only_in_the_code(self, store, payg_on):
        a = payg_account(store)
        store.record_usage(a.id, "validate", 1, "k")
        db = sqlite3.connect(store.path)
        try:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(
                    "INSERT INTO usage_events (event_id, account_id, scope, quantity, "
                    "idempotency_key, occurred_at, billed_state) "
                    "VALUES ('uev_x', ?, 'validate', 1, 'k', 'now', 'included')", (a.id,))
        finally:
            db.close()

    def test_threads_racing_on_one_key_make_exactly_one_event(self, store, payg_on):
        a = payg_account(store)
        barrier = threading.Barrier(16)
        out: list = []

        def work():
            mine = AccountStore(store.path)  # its own handle, like another worker
            barrier.wait()
            out.append(mine.record_usage(a.id, "validate", 1, "one-key").duplicate)

        threads = [threading.Thread(target=work) for _ in range(16)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert sorted(out) == [False] + [True] * 15
        assert len(events(store, a.id)) == 1 and counter(store, a.id) == 1


# ---------------------------------------------------------------------------
# 3. races: no overshoot, ever
# ---------------------------------------------------------------------------
WORKER = textwrap.dedent("""
    import json, sys
    from assurance.billing.accounts import AccountStore, QuotaExceededError, SpendLimitError
    path, account, prefix, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    store = AccountStore(path)
    out = {"included": 0, "pending": 0, "dup": 0, "quota": 0, "spend": 0}
    for i in range(n):
        try:
            rec = store.record_usage(account, "validate", 1, f"{prefix}-{i}")
            out["dup" if rec.duplicate else rec.billed_state] += 1
        except QuotaExceededError:
            out["quota"] += 1
        except SpendLimitError:
            out["spend"] += 1
    print(json.dumps(out))
""")


def _run_workers(store, account_id, procs, per_proc, *, shared_prefix=False):
    popen = [
        subprocess.Popen(  # noqa: S603 - our own interpreter, our own fixed script
            [sys.executable, "-c", WORKER, str(store.path), account_id,
             "shared" if shared_prefix else f"p{p}", str(per_proc)],
            stdout=subprocess.PIPE, text=True)
        for p in range(procs)
    ]
    totals: dict[str, int] = {}
    for proc in popen:
        stdout, _ = proc.communicate(timeout=120)
        assert proc.returncode == 0
        for key, value in json.loads(stdout.strip().splitlines()[-1]).items():
            totals[key] = totals.get(key, 0) + value
    return totals


class TestNoOvershoot:
    def test_threads_cannot_overshoot_the_allowance_or_the_spend_limit(self, store, payg_on):
        a = payg_account(store, limit=7)
        barrier = threading.Barrier(24)
        results: list[str] = []

        def work(n):
            mine = AccountStore(store.path)
            barrier.wait()
            for i in range(5):
                try:
                    results.append(mine.record_usage(a.id, "validate", 1, f"t{n}-{i}").billed_state)
                except (QuotaExceededError, SpendLimitError):
                    results.append("refused")

        threads = [threading.Thread(target=work, args=(n,)) for n in range(24)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert results.count("included") == ALLOWANCE
        assert results.count("pending") == 7
        assert results.count("refused") == 24 * 5 - ALLOWANCE - 7
        rows = events(store, a.id)
        assert len(rows) == ALLOWANCE + 7
        assert sum(r["billable_quantity"] for r in rows) == 7
        assert counter(store, a.id) == ALLOWANCE + 7  # refusals did not touch it

    def test_separate_processes_cannot_overshoot_either(self, store, payg_on):
        a = payg_account(store, limit=6)
        totals = _run_workers(store, a.id, procs=4, per_proc=15)
        assert totals["included"] == ALLOWANCE
        assert totals["pending"] == 6
        assert totals["spend"] == 4 * 15 - ALLOWANCE - 6
        assert len(events(store, a.id)) == ALLOWANCE + 6

    def test_separate_processes_racing_on_the_same_keys_count_each_once(self, store, payg_on):
        a = payg_account(store, limit=50)
        totals = _run_workers(store, a.id, procs=4, per_proc=10, shared_prefix=True)
        assert totals["included"] + totals["pending"] == 10
        assert totals["dup"] == 30
        assert len(events(store, a.id)) == 10 and counter(store, a.id) == 10

    def test_a_free_account_is_capped_exactly_under_contention(self, store):
        a = store.upsert_account(email="f@example.de", tier="free")
        totals = _run_workers(store, a.id, procs=3, per_proc=20)
        assert totals["included"] == ALLOWANCE and totals["quota"] == 3 * 20 - ALLOWANCE


# ---------------------------------------------------------------------------
# 4. periods: the spend limit is a calendar-month (UTC) budget
# ---------------------------------------------------------------------------
class TestPeriods:
    def test_a_new_month_starts_a_new_budget(self, store, payg_on):
        a = payg_account(store, limit=2)
        last = datetime(2026, 9, 30, 12, tzinfo=UTC)
        first = datetime(2026, 10, 1, 12, tzinfo=UTC)
        for i in range(ALLOWANCE + 2):
            store.record_usage(a.id, "validate", 1, f"sep-{i}", now=last)
        with pytest.raises(SpendLimitError):
            store.record_usage(a.id, "validate", 1, "sep-x", now=last)
        # A new UTC day is a new allowance AND a new month is a new budget.
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"oct-{i}", now=first)
        assert store.record_usage(a.id, "validate", 1, "oct-over", now=first).billable_quantity == 1

    def test_the_allowance_is_per_utc_day(self, store):
        a = store.upsert_account(email="f@example.de", tier="free")
        day1 = datetime(2026, 10, 20, 23, 59, tzinfo=UTC)
        day2 = day1 + timedelta(minutes=2)
        for i in range(ALLOWANCE):
            store.record_usage(a.id, "validate", 1, f"d1-{i}", now=day1)
        with pytest.raises(QuotaExceededError):
            store.record_usage(a.id, "validate", 1, "d1-x", now=day1)
        assert store.record_usage(a.id, "validate", 1, "d2-0", now=day2).billed_state == "included"


# ---------------------------------------------------------------------------
# 5. the old database opens; nothing about it is lost
# ---------------------------------------------------------------------------
OLD_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE accounts (
    id TEXT PRIMARY KEY, email TEXT NOT NULL, company TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL, stripe_customer_id TEXT NOT NULL DEFAULT '',
    stripe_subscription_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','past_due','cancelled')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    last_event_at INTEGER NOT NULL DEFAULT 0, past_due_since INTEGER NOT NULL DEFAULT 0);
CREATE TABLE api_keys (key_hash TEXT PRIMARY KEY, prefix TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id), label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, last_used TEXT, revoked_at TEXT);
CREATE TABLE usage (subject TEXT NOT NULL, scope TEXT NOT NULL, day TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0), PRIMARY KEY (subject, scope, day));
INSERT INTO meta VALUES ('schema_version', '1');
INSERT INTO accounts (id, email, tier, stripe_customer_id, status, created_at, updated_at)
VALUES ('acc_0123456789abcdef', 'old@example.de', 'register', 'cus_old', 'active', 'x', 'x');
INSERT INTO usage VALUES ('acc_0123456789abcdef', 'validate', '2026-10-20', 3);
"""


class TestOldDatabase:
    def _old(self, tmp_path):
        path = tmp_path / "old.db"
        db = sqlite3.connect(path)
        db.executescript(OLD_SCHEMA)
        db.commit()
        db.close()
        return path

    def test_an_older_store_opens_and_gains_the_new_pieces_additively(self, tmp_path):
        path = self._old(tmp_path)
        store = AccountStore(path)
        account = store.account("acc_0123456789abcdef")
        assert (account.email, account.tier, account.spend_limit_units,
                account.budget_alert_pct) == ("old@example.de", "register", 0, 80)
        db = sqlite3.connect(path)
        try:
            assert db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "1"
            assert {r[1] for r in db.execute("PRAGMA table_info(usage_events)")} >= {
                "account_id", "scope", "quantity", "idempotency_key", "occurred_at",
                "source", "billed_state", "provider_event_id"}
            assert db.execute("SELECT count FROM usage").fetchone()[0] == 3
        finally:
            db.close()

    def test_opening_twice_and_concurrently_is_harmless(self, tmp_path):
        path = self._old(tmp_path)
        errors: list[Exception] = []
        barrier = threading.Barrier(8)

        def open_it():
            try:
                barrier.wait()
                AccountStore(path)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=open_it) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert errors == []
        AccountStore(path)

    def test_opening_an_up_to_date_store_never_waits_for_the_write_lock(self, store):
        """Check first, lock only if there is something to change: a writer holding
        the lock (a busy billing webhook) must not make every new process queue."""
        import time

        holder = sqlite3.connect(store.path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            started = time.monotonic()
            AccountStore(store.path)
            assert time.monotonic() - started < 2.0
        finally:
            holder.execute("ROLLBACK")
            holder.close()

    def test_a_read_only_open_of_an_unmigrated_store_still_works_and_writes_nothing(
            self, tmp_path):
        path = self._old(tmp_path)
        before = path.read_bytes()
        store = AccountStore.open_readonly(path)
        assert store.account("acc_0123456789abcdef").spend_limit_units == 0
        assert store.usage_events("acc_0123456789abcdef") == []
        assert path.read_bytes() == before

    def test_the_previous_build_can_still_read_a_migrated_store(self, tmp_path):
        """Rollback safety: only additive changes, schema_version untouched."""
        path = self._old(tmp_path)
        AccountStore(path)
        db = sqlite3.connect(path)
        try:
            row = db.execute("SELECT id, email, tier, status, last_event_at, past_due_since "
                             "FROM accounts").fetchone()
            assert row[:2] == ("acc_0123456789abcdef", "old@example.de")
        finally:
            db.close()

    def test_the_new_account_columns_have_safe_defaults(self, store):
        a = store.upsert_account(email="n@example.de", tier="free")
        assert (store.account(a.id).spend_limit_units, store.account(a.id).budget_alert_pct) \
            == (0, 80)


# ---------------------------------------------------------------------------
# 6. over HTTP: success is counted, failure is not, refusals are loud
# ---------------------------------------------------------------------------
def key_for(store, tier="free", email="h@example.de", *, customer=True, limit=None):
    account = store.upsert_account(
        email=email, tier=tier, stripe_customer_id=f"cus_{email}" if customer else "")
    if limit is not None:
        store.set_spend_limit(account.id, limit)
    return account, {"X-API-Key": store.issue_key(account.id)}


class TestOverHttp:
    def test_a_successful_call_is_recorded_with_its_idempotency_key(self, client, store):
        account, headers = key_for(store)
        r = client.post("/v1/spec/validate", json=VALIDATE,
                        headers={**headers, "Idempotency-Key": "client-key-1"})
        assert r.status_code == 200
        [row] = events(store, account.id)
        assert (row["scope"], row["idempotency_key"], row["billed_state"]) == (
            "validate", "client-key-1", "included")
        assert r.headers["x-assurance-usage-event"] == row["event_id"]

    def test_a_retry_with_the_same_idempotency_key_is_not_counted_twice(self, client, store):
        account, headers = key_for(store)
        h = {**headers, "Idempotency-Key": "retry-1"}
        assert client.post("/v1/spec/validate", json=VALIDATE, headers=h).status_code == 200
        assert client.post("/v1/spec/validate", json=VALIDATE, headers=h).status_code == 200
        assert len(events(store, account.id)) == 1
        assert counter(store, account.id) == 1

    def test_without_a_key_every_call_is_its_own_unit(self, client, store):
        account, headers = key_for(store)
        for _ in range(3):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert len(events(store, account.id)) == 3

    @pytest.mark.parametrize("bad", ["", "has space", "x" * 256, "ünïcode", "a/b"])
    def test_a_malformed_idempotency_key_is_a_400_and_costs_nothing(self, client, store, bad):
        account, headers = key_for(store)
        r = client.post("/v1/spec/validate", json=VALIDATE,
                        headers={**headers, "Idempotency-Key": bad.encode("utf-8")})
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "invalid_idempotency_key"
        assert events(store, account.id) == []

    def test_a_browser_may_send_the_idempotency_key(self, client):
        preflight = client.options("/v1/spec/validate", headers={
            "Origin": "https://neuralbridge.io", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-api-key,idempotency-key"})
        assert preflight.status_code == 200
        assert "idempotency-key" in preflight.headers["access-control-allow-headers"].lower()

    def test_reusing_a_key_for_other_work_is_a_409(self, client, store):
        account, headers = key_for(store)
        h = {**headers, "Idempotency-Key": "same"}
        assert client.post("/v1/spec/validate", json=VALIDATE, headers=h).status_code == 200
        r = client.post("/v1/machine/separation", json=SEPARATION, headers=h)
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "idempotency_key_reused"
        assert len(events(store, account.id)) == 1

    def test_a_422_from_the_domain_costs_nothing(self, client, store):
        # The body is well-formed JSON of the right shape; the DOMAIN refuses the
        # documents inside it. That is the 422 path that is not Pydantic's.
        account, headers = key_for(store)
        r = client.post("/v1/machinery/diff", json={"baseline": {}, "observed": {}},
                        headers=headers)
        assert r.status_code == 422, r.text
        r = client.post("/v1/fleet/advisory/check", json={"advisory": {}, "manifest": {}},
                        headers=headers)
        assert r.status_code == 422, r.text
        assert events(store, account.id) == []
        assert counter(store, account.id, "machinery_diff") == 0
        assert counter(store, account.id, "advisory_check") == 0

    def test_a_request_body_the_schema_rejects_costs_nothing(self, client, store):
        account, headers = key_for(store)
        assert client.post("/v1/spec/validate", json={"nope": 1}, headers=headers).status_code == 422
        assert events(store, account.id) == [] and counter(store, account.id) == 0

    def test_a_5xx_inside_the_operation_costs_nothing(self, client, store, monkeypatch):
        from assurance.api import routes

        account, headers = key_for(store)

        def boom(*a, **k):
            raise RuntimeError("engine fell over")

        monkeypatch.setattr(routes, "validate_payload", boom)
        with TestClient(client.app, raise_server_exceptions=False) as c:
            r = c.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert r.status_code == 500
        assert events(store, account.id) == [] and counter(store, account.id) == 0

    def test_an_anonymous_failure_costs_nothing_either(self, client, store):
        assert client.post("/v1/machinery/diff",
                           json={"baseline": {}, "observed": {}}).status_code == 422
        assert client.post("/v1/spec/validate", json={"nope": 1}).status_code == 422
        assert AccountStore(store.path).usage_today("ip:testclient") == {}

    def test_a_document_that_validates_as_not_submittable_is_still_a_successful_unit(
            self, client, store):
        # The validator's job is to say "not submittable"; that is the product working.
        account, headers = key_for(store)
        r = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert r.status_code == 200 and r.json()["submittable"] is False
        assert len(events(store, account.id)) == 1

    def test_the_cap_for_a_free_account_is_a_429_with_the_remedy_and_records_nothing(
            self, client, store):
        account, headers = key_for(store)
        for _ in range(ALLOWANCE):
            assert client.post("/v1/spec/validate", json=VALIDATE, headers=headers).status_code == 200
        before = events(store, account.id)
        over = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert over.status_code == 429
        assert over.json()["detail"]["error"] == "quota_exceeded"
        assert "retry-after" in over.headers
        assert events(store, account.id) == before

    def test_a_caller_who_is_certainly_over_limit_costs_no_computation(
            self, client, store, monkeypatch):
        from assurance.api import routes

        account, headers = key_for(store)
        for _ in range(ALLOWANCE):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        ran = []
        monkeypatch.setattr(routes, "validate_payload", lambda *a, **k: ran.append(1))
        assert client.post("/v1/spec/validate", json=VALIDATE, headers=headers).status_code == 429
        assert ran == []
        # ... and the same for an address-keyed anonymous caller.
        for _ in range(ALLOWANCE):
            client.post("/v1/machine/separation", json=SEPARATION)
        assert client.post("/v1/machine/separation", json=SEPARATION).status_code == 429

    def test_payg_beyond_the_allowance_is_billable_and_then_hard_stops_at_the_limit(
            self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=2)
        for _ in range(ALLOWANCE + 2):
            assert client.post("/v1/spec/validate", json=VALIDATE, headers=headers).status_code == 200
        billable = [e for e in events(store, account.id) if e["billable_quantity"]]
        assert len(billable) == 2
        before = events(store, account.id)
        over = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert over.status_code == 429
        detail = over.json()["detail"]
        assert detail["error"] == "spend_limit_reached"
        assert (detail["spend_limit_units"], detail["billable_units"]) == (2, 2)
        assert "POST /v1/usage/limits" in detail["remedy"]
        assert events(store, account.id) == before

    def test_payg_with_no_limit_set_says_how_to_set_one(self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=None)
        for _ in range(ALLOWANCE):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        over = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert over.status_code == 429
        assert over.json()["detail"]["error"] == "spend_limit_reached"
        assert over.json()["detail"]["spend_limit_units"] == 0

    def test_every_billable_route_meters_through_the_same_door(self, client, store):
        account, headers = key_for(store)
        manifest = {"manifest": {}}
        client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        client.post("/v1/machine/separation", json=SEPARATION, headers=headers)
        assert {e["scope"] for e in events(store, account.id)} == {"validate", "separation"}
        del manifest

    def test_paid_unmetered_callers_leave_no_usage_rows(self, client, store):
        account, headers = key_for(store, tier="register")
        client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert events(store, account.id) == []


# ---------------------------------------------------------------------------
# 7. GET /v1/usage and /v1/me
# ---------------------------------------------------------------------------
class TestUsageEndpoint:
    def test_it_needs_a_key(self, client):
        assert client.get("/v1/usage").status_code == 401

    def test_it_reports_totals_allowance_and_remaining_per_scope(self, client, store):
        account, headers = key_for(store)
        for _ in range(3):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        client.post("/v1/machine/separation", json=SEPARATION, headers=headers)
        body = client.get("/v1/usage", headers=headers).json()
        scope = body["scopes"]["validate"]
        assert (scope["included_per_day"], scope["used_today"], scope["remaining_today"],
                scope["period_total"], scope["period_billable"]) == (20, 3, 17, 3, 0)
        assert body["scopes"]["separation"]["used_today"] == 1
        assert body["account_id"] == account.id and body["metered"] is True
        assert body["payg"]["enabled"] is False

    def test_it_lists_recent_events_with_their_idempotency_keys(self, client, store):
        _, headers = key_for(store)
        client.post("/v1/spec/validate", json=VALIDATE,
                    headers={**headers, "Idempotency-Key": "mine-1"})
        events_ = client.get("/v1/usage", headers=headers).json()["events"]
        assert [e["idempotency_key"] for e in events_] == ["mine-1"]
        assert set(events_[0]) == {"event_id", "scope", "quantity", "billable_quantity",
                                   "idempotency_key", "occurred_at", "source",
                                   "billed_state"}

    def test_it_shows_only_the_callers_own_account(self, client, store):
        a, ha = key_for(store, email="a@example.de")
        b, hb = key_for(store, email="b@example.de")
        client.post("/v1/spec/validate", json=VALIDATE,
                    headers={**ha, "Idempotency-Key": "a-secret-key"})
        client.post("/v1/spec/validate", json=VALIDATE,
                    headers={**hb, "Idempotency-Key": "b-key"})
        seen = client.get("/v1/usage", headers=hb)
        text = seen.text
        assert "a-secret-key" not in text and a.id not in text
        assert [e["idempotency_key"] for e in seen.json()["events"]] == ["b-key"]

    def test_a_client_cannot_ask_for_another_account(self, client, store):
        a, ha = key_for(store, email="a@example.de")
        b, hb = key_for(store, email="b@example.de")
        client.post("/v1/spec/validate", json=VALIDATE,
                    headers={**ha, "Idempotency-Key": "a-secret-key"})
        for query in (f"?account_id={a.id}", f"?subject={a.id}", f"?account={a.id}"):
            r = client.get(f"/v1/usage{query}", headers=hb)
            assert "a-secret-key" not in r.text and a.id not in r.text

    def test_anonymous_ip_usage_is_not_exposed_to_an_account(self, client, store):
        client.post("/v1/spec/validate", json=VALIDATE)  # anonymous, ip:testclient
        _, headers = key_for(store)
        assert client.get("/v1/usage", headers=headers).json()["events"] == []

    def test_the_period_filter_selects_a_month(self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=5)
        store.record_usage(account.id, "validate", 1, "old",
                           now=datetime(2026, 9, 5, 10, tzinfo=UTC))
        client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        now_month = datetime.now(UTC).strftime("%Y-%m")
        current = client.get("/v1/usage", headers=headers).json()
        assert current["period"]["label"] == now_month
        assert "old" not in [e["idempotency_key"] for e in current["events"]]
        assert len(current["events"]) == 1
        september = client.get("/v1/usage?period=2026-09", headers=headers).json()
        assert [e["idempotency_key"] for e in september["events"]] == ["old"]
        assert september["scopes"]["validate"]["period_total"] == 1
        today = client.get("/v1/usage?period=today", headers=headers).json()
        assert today["period"]["label"] == "today"

    @pytest.mark.parametrize("bad", ["2026-13", "yesterday", "2026-9", "../x", "2026-09-01"])
    def test_a_bad_period_is_a_422(self, client, store, bad):
        _, headers = key_for(store)
        assert client.get("/v1/usage", params={"period": bad}, headers=headers).status_code == 422

    def test_spend_to_date_and_remaining_budget_for_payg(self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=10)
        for _ in range(ALLOWANCE + 3):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        payg = client.get("/v1/usage", headers=headers).json()["payg"]
        assert payg["enabled"] is True
        assert (payg["billable_units"], payg["spend_limit_units"], payg["remaining_units"]) \
            == (3, 10, 7)
        assert payg["unreported_units"] == 3
        assert "amount" in payg["note"].lower() and "stripe" in payg["note"].lower()
        assert "price" not in set(payg)  # this service does not know the price

    def test_the_budget_alert_flag_turns_on_at_the_threshold(self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=10)
        r = client.post("/v1/usage/limits", headers=headers,
                        json={"spend_limit_units": 10, "budget_alert_pct": 50})
        assert r.status_code == 200
        for _ in range(ALLOWANCE + 4):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert client.get("/v1/usage", headers=headers).json()["payg"]["budget_alert"] is False
        client.post("/v1/spec/validate", json=VALIDATE, headers=headers)  # 5 of 10 = 50%
        payg = client.get("/v1/usage", headers=headers).json()["payg"]
        assert payg["budget_alert"] is True and payg["budget_alert_pct"] == 50

    def test_the_operator_has_no_account_usage(self, client):
        body = client.get("/v1/usage", headers={"X-API-Key": OPERATOR_KEY}).json()
        assert body["metered"] is False and body["events"] == []

    def test_me_carries_the_usage_summary(self, client, store):
        _, headers = key_for(store)
        client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        me = client.get("/v1/me", headers=headers).json()
        assert me["usage"]["scopes"]["validate"]["used_today"] == 1
        assert me["usage"]["payg"]["enabled"] is False
        assert "events" not in me["usage"]
        assert me["usage_today"]["validate"] == 1  # unchanged for existing clients


class TestSpendLimitEndpoint:
    def test_a_customer_sets_their_own_limit(self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=None)
        r = client.post("/v1/usage/limits", headers=headers, json={"spend_limit_units": 25})
        assert r.status_code == 200 and r.json()["payg"]["spend_limit_units"] == 25
        assert store.account(account.id).spend_limit_units == 25

    def test_the_browser_cannot_supply_totals_or_ids(self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=None)
        for body in ({"spend_limit_units": 5, "billable_units": 0},
                     {"spend_limit_units": 5, "account_id": "acc_0123456789abcdef"},
                     {"spend_limit_units": 5, "used": 0}):
            assert client.post("/v1/usage/limits", headers=headers, json=body).status_code == 422
        assert store.account(account.id).spend_limit_units == 0

    @pytest.mark.parametrize("body", [
        {"spend_limit_units": -1}, {"spend_limit_units": 10**9}, {"spend_limit_units": 1.5},
        {"spend_limit_units": "ten"}, {"budget_alert_pct": 0}, {"budget_alert_pct": 101}, {},
    ])
    def test_nonsense_is_a_422(self, client, store, payg_on, body):
        _, headers = key_for(store, tier="payg", limit=3)
        assert client.post("/v1/usage/limits", headers=headers, json=body).status_code == 422

    def test_lowering_the_limit_below_what_is_used_stops_billing_at_once(
            self, client, store, payg_on):
        account, headers = key_for(store, tier="payg", limit=10)
        for _ in range(ALLOWANCE + 3):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        client.post("/v1/usage/limits", headers=headers, json={"spend_limit_units": 1})
        assert client.post("/v1/spec/validate", json=VALIDATE,
                           headers=headers).status_code == 429

    def test_anonymous_and_operator_get_a_clear_refusal(self, client):
        assert client.post("/v1/usage/limits", json={"spend_limit_units": 1}).status_code == 401
        r = client.post("/v1/usage/limits", json={"spend_limit_units": 1},
                        headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 400

    def test_a_free_account_cannot_arm_billing_by_setting_a_limit(self, client, store, payg_on):
        account, headers = key_for(store, tier="free", limit=None)
        client.post("/v1/usage/limits", headers=headers, json={"spend_limit_units": 50})
        for _ in range(ALLOWANCE):
            client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        over = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert over.status_code == 429
        assert over.json()["detail"]["error"] == "quota_exceeded"
        assert [e for e in events(store, account.id) if e["billable_quantity"]] == []
