"""Opening a database that several writers may open first must not fail.

A new customer's first requests arrive together (the workspace fires two in
parallel), so a brand-new tenant ledger is created by several threads at once.
SQLite's busy timeout does not cover every step of that — switching to WAL and
running the schema script can fail at once with "database is locked", and the
version row used to be inserted with a plain INSERT (UNIQUE violation for the
loser). Each of those was a 500 on a new tenant's first page load.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest

from assurance.billing.accounts import AccountStore
from assurance.core.sqlite import enable_wal, retry_locked
from assurance.evidence import EvidenceLedger

from . import test_assurance_reconcile as _reconcile_tests


def _race(make, n: int) -> list[BaseException]:
    barrier = threading.Barrier(n)
    errors: list[BaseException] = []

    def go() -> None:
        try:
            barrier.wait()
            make()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


class TestConcurrentFirstOpen:
    @pytest.mark.parametrize("round_", range(10))
    def test_a_brand_new_ledger_opened_by_many_threads(self, tmp_path, round_):
        path = tmp_path / "tenants" / "acc_0123456789abcdef.db"
        assert _race(lambda: EvidenceLedger(path), 24) == []
        assert EvidenceLedger(path).verify_chain() == (True, [])

    @pytest.mark.parametrize("round_", range(10))
    def test_a_brand_new_account_store_opened_by_many_threads(self, tmp_path, round_):
        path = tmp_path / "accounts.db"
        assert _race(lambda: AccountStore(path), 24) == []

    @pytest.mark.parametrize("round_", range(5))
    def test_an_old_account_database_opened_by_many_threads(self, tmp_path, round_):
        path = tmp_path / "old.db"
        db = sqlite3.connect(path)
        db.executescript(_reconcile_tests.TestSchema.OLD)
        db.commit()
        db.close()
        assert _race(lambda: AccountStore(path), 24) == []

    def test_concurrent_appends_to_a_new_ledger_all_land_and_chain(self, tmp_path):
        from assurance.core import Actor, Evidence, Origin

        path = tmp_path / "e.db"

        def append(i: int) -> None:
            ledger = EvidenceLedger(path)
            ledger.append(Evidence(kind="t.r", body={"i": i}, actor=Actor("a.p", "e"),
                                   origin=Origin("unit-test")).seal())

        counter = iter(range(1000))
        lock = threading.Lock()

        def next_one() -> None:
            with lock:
                i = next(counter)
            append(i)

        assert _race(next_one, 16) == []
        ledger = EvidenceLedger(path)
        assert len(ledger.entries()) == 16
        assert ledger.verify_chain() == (True, [])


class TestHelpers:
    def test_retry_waits_through_a_busy_error_then_succeeds(self):
        calls = {"n": 0}

        def flaky() -> str:
            calls["n"] += 1
            if calls["n"] < 4:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        assert retry_locked(flaky, first_delay=0.0001, max_delay=0.0002) == "ok"
        assert calls["n"] == 4

    def test_a_non_busy_error_is_not_retried(self):
        calls = {"n": 0}

        def broken() -> None:
            calls["n"] += 1
            raise sqlite3.OperationalError("no such table: nope")

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            retry_locked(broken, first_delay=0.0001)
        assert calls["n"] == 1

    def test_it_gives_up_eventually_with_the_original_error(self):
        def always() -> None:
            raise sqlite3.OperationalError("database is locked")

        with pytest.raises(sqlite3.OperationalError, match="locked"):
            retry_locked(always, attempts=3, first_delay=0.0001, max_delay=0.0002)

    def test_enable_wal_is_idempotent_and_takes_no_write_when_already_wal(self, tmp_path):
        db = sqlite3.connect(tmp_path / "x.db", isolation_level=None)
        enable_wal(db)
        assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        # A second connection holding a write lock must not block the check.
        holder = sqlite3.connect(tmp_path / "x.db", isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        other = sqlite3.connect(tmp_path / "x.db", timeout=0.2, isolation_level=None)
        enable_wal(other)
        holder.execute("ROLLBACK")
        for c in (db, holder, other):
            c.close()

