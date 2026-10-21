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
            retry_locked(always, deadline=0.05, first_delay=0.0001, max_delay=0.0002)

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



class TestTheWaitIsBounded:
    """A stuck lock must fail in about the deadline, not in hours."""

    def test_the_total_wait_is_the_deadline_not_attempts_times_the_busy_timeout(self, tmp_path):
        import time

        path = tmp_path / "legacy.db"
        # A legacy (delete-mode) database that a reader is holding shared, so
        # the switch to WAL cannot take its lock.
        setup = sqlite3.connect(path, isolation_level=None)
        setup.execute("CREATE TABLE t (x)")
        setup.execute("INSERT INTO t VALUES (1)")
        setup.close()
        reader = sqlite3.connect(path, isolation_level=None)
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM t").fetchall()           # holds SHARED

        db = sqlite3.connect(path, timeout=30.0, isolation_level=None)  # as our stores do
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            retry_locked(lambda: db.execute("PRAGMA journal_mode=WAL").fetchone(),
                         db=db, deadline=1.0)
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, f"waited {elapsed:.1f}s: the 30 s busy timeout leaked into the retry"
        # And the connection's own busy timeout is restored afterwards.
        assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        reader.execute("ROLLBACK")
        reader.close()
        db.close()


class TestOpeningAnExistingFileNeverQueuesBehindAWriter:
    """Constructing a store must not need the write lock when nothing is missing."""

    @staticmethod
    def _hold_the_write_lock(path):
        holder = sqlite3.connect(path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        return holder

    def _assert_fast(self, make, path):
        import time

        make()                                  # create + migrate once
        holder = self._hold_the_write_lock(path)
        try:
            started = time.monotonic()
            make()
            assert time.monotonic() - started < 2.0, "open queued behind a held write lock"
        finally:
            holder.execute("ROLLBACK")
            holder.close()

    def test_ledger(self, tmp_path):
        path = tmp_path / "e.db"
        self._assert_fast(lambda: EvidenceLedger(path), path)

    def test_accounts(self, tmp_path):
        path = tmp_path / "a.db"
        self._assert_fast(lambda: AccountStore(path), path)

    def test_ai_store(self, tmp_path):
        from neuralbridge.ai.store import AiStore

        path = tmp_path / "ai.db"
        self._assert_fast(lambda: AiStore(path), path)


class TestAiStoreFirstOpen:
    @pytest.mark.parametrize("round_", range(6))
    def test_a_brand_new_ai_store_opened_by_many_threads(self, tmp_path, round_):
        from neuralbridge.ai.store import AiStore

        path = tmp_path / "ai.db"
        assert _race(lambda: AiStore(path), 24) == []


# ---------------------------------------------------------------------------
# Independent review of the first-open fix (multi-process, backup, corruption).
# The cases above race threads inside one process; SQLite coordinates those
# through process-wide state that separate processes do not share, so the
# multi-process case is tested separately, below.
# ---------------------------------------------------------------------------
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from assurance.core import Actor, Evidence, Origin  # noqa: E402
from assurance.evidence import restore_check  # noqa: E402
from assurance.evidence.ledger import LedgerIntegrityError  # noqa: E402

SRC = Path(__file__).resolve().parents[1] / "src"


def _ev(n: int, pad: int = 0) -> Evidence:
    return Evidence(kind="t.record", body={"n": n, "pad": "x" * pad},
                    actor=Actor("a.person", "engineer"), origin=Origin("pytest")).seal()


def _child_env() -> dict[str, str]:
    return {"PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}


_OPEN_AND_APPEND = """
import sys
from assurance.core import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
led = EvidenceLedger(sys.argv[1])
led.append(Evidence(kind="t", body={"p": int(sys.argv[2])}, actor=Actor("a"), origin=Origin("x")).seal())
"""


class TestManyProcessesOpeningANewLedger:
    """Separate interpreters, started together, on one brand-new file."""

    @pytest.mark.parametrize("round_", range(3))
    def test_twelve_processes_open_and_append_to_a_new_ledger(self, tmp_path, round_):
        path = tmp_path / "tenants" / "acc_0123456789abcdef.db"
        path.parent.mkdir()
        kids = [subprocess.Popen([sys.executable, "-c", _OPEN_AND_APPEND, str(path), str(i)],  # noqa: S603
                                 env=_child_env(), stderr=subprocess.PIPE, text=True)
                for i in range(12)]
        failures = [k.communicate()[1][-300:] for k in kids if k.wait(timeout=120) != 0]
        assert failures == []
        ledger = EvidenceLedger(path)
        assert len(ledger.entries()) == 12
        assert ledger.verify_chain() == (True, [])


def _seed_data_dir(data: Path, entries: int = 3) -> EvidenceLedger:
    data.mkdir(parents=True)
    AccountStore(data / "accounts.db")
    ledger = EvidenceLedger(data / "art14-register.db")
    for n in range(entries):
        ledger.append(_ev(n))
    return ledger


class TestRestoreCheckBackup:
    @pytest.mark.parametrize("name", ["hash#dir", "q?mark", "pct%41dir", "with space"])
    def test_a_data_directory_with_uri_special_characters_is_really_backed_up(
            self, tmp_path, name):
        """``#`` or ``?`` in the path used to end the SQLite URI early: the 'source' became
        a different, nonexistent file, was created empty, and the backup reported success
        with empty snapshots."""
        base = tmp_path / name
        _seed_data_dir(base / "data")
        out = base / "out"
        taken = restore_check.backup(base / "data", out)
        assert "art14-register.db" in taken
        assert len(EvidenceLedger(out / "art14-register.db").entries()) == 3
        assert restore_check.verify(out)["ok"] is True
        assert {p.name for p in base.iterdir()} == {"data", "out"}, "a stray file was created"
        assert {p.name for p in tmp_path.iterdir()} == {name}, "a stray file was created"

    def test_backup_while_other_processes_append(self, tmp_path):
        data = tmp_path / "data"
        _seed_data_dir(data)
        writer = """
import sys, time
from assurance.core import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
led = EvidenceLedger(sys.argv[1])
end = time.monotonic() + 6
n = 0
while time.monotonic() < end:
    led.append(Evidence(kind="t", body={"w": n}, actor=Actor("a"), origin=Origin("x")).seal())
    n += 1
"""
        kids = [subprocess.Popen([sys.executable, "-c", writer, str(data / "art14-register.db")],  # noqa: S603
                                 env=_child_env(), stderr=subprocess.PIPE, text=True)
                for _ in range(3)]
        try:
            time.sleep(0.5)
            for i in range(4):
                out = tmp_path / f"out{i}"
                restore_check.backup(data, out)
                result = restore_check.verify(out)
                assert result["ok"] is True, result["problems"]
        finally:
            errors = [k.communicate()[1][-300:] for k in kids if k.wait(timeout=60) != 0]
        assert errors == []

    def test_a_backup_does_not_wait_forever_for_a_locked_source(self, tmp_path, monkeypatch):
        """sqlite3's backup() retries a busy source with no limit of its own."""
        src = tmp_path / "rollback.db"
        db = sqlite3.connect(src, isolation_level=None)        # rollback-journal mode
        db.execute("CREATE TABLE t (x)")
        db.execute("INSERT INTO t VALUES (1)")
        db.close()
        holder = sqlite3.connect(src, isolation_level=None)
        holder.execute("BEGIN EXCLUSIVE")
        monkeypatch.setattr(restore_check, "BACKUP_DEADLINE", 1.0, raising=False)
        outcome: list[object] = []

        def attempt() -> None:
            try:
                restore_check._snapshot(src, tmp_path / "snap.db")
                outcome.append("completed")
            except BaseException as exc:  # noqa: BLE001
                outcome.append(exc)

        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        thread.join(15)
        still_running = thread.is_alive()
        holder.execute("ROLLBACK")          # lets a stuck attempt finish either way
        holder.close()
        thread.join(15)
        assert not still_running, "backup is still waiting for a locked source"
        assert isinstance(outcome[0], sqlite3.OperationalError) and "locked" in str(outcome[0])


class TestACorruptButOpenableLedger:
    @staticmethod
    def _damage(path: Path) -> None:
        """Make a table page structurally invalid, past the schema, so the file still opens."""
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        data = bytearray(path.read_bytes())
        marker = data.rindex(b"x" * 100)                    # inside a row's evidence payload
        page = (marker // 4096) * 4096
        assert page > 4096
        data[page] = 0xFF                                   # not a valid b-tree page type
        path.write_bytes(bytes(data))

    def _damaged(self, tmp_path: Path) -> Path:
        path = tmp_path / "damaged.db"
        ledger = EvidenceLedger(path)
        for n in range(40):
            ledger.append(_ev(n, pad=400))
        self._damage(path)
        return path

    def test_verify_chain_reports_damaged_storage_instead_of_raising(self, tmp_path):
        ok, problems = EvidenceLedger(self._damaged(tmp_path)).verify_chain()   # opens fine
        assert ok is False
        assert any("damaged" in p for p in problems), problems

    def test_export_refuses_a_damaged_ledger_with_the_integrity_error(self, tmp_path):
        with pytest.raises(LedgerIntegrityError, match="refusing to export"):
            EvidenceLedger(self._damaged(tmp_path)).export()

    def test_a_busy_database_is_still_an_error_not_a_finding(self, tmp_path, monkeypatch):
        """Busy/locked is transient: it must not be reported as 'the ledger is damaged'."""
        ledger = EvidenceLedger(tmp_path / "ok.db")
        ledger.append(_ev(1))
        holder = sqlite3.connect(ledger.path, isolation_level=None)
        holder.execute("PRAGMA journal_mode=DELETE")
        holder.execute("BEGIN EXCLUSIVE")

        def short(self: EvidenceLedger) -> sqlite3.Connection:
            db = sqlite3.connect(self.path, timeout=0.1, isolation_level=None)
            db.row_factory = sqlite3.Row
            return db

        monkeypatch.setattr(EvidenceLedger, "_connect", short)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                ledger.verify_chain()
        finally:
            holder.execute("ROLLBACK")
            holder.close()


class TestRetryLockedWhenTheCallIsSlow:
    def test_a_slow_attempt_that_ends_busy_after_the_deadline_is_not_retried(self):
        calls = {"n": 0}

        def slow() -> None:
            calls["n"] += 1
            time.sleep(0.3)
            raise sqlite3.OperationalError("database is locked")

        with pytest.raises(sqlite3.OperationalError, match="locked"):
            retry_locked(slow, deadline=0.1, first_delay=0.001)
        assert calls["n"] == 1

    def test_a_slow_attempt_that_succeeds_is_never_cut_short(self):
        def slow() -> str:
            time.sleep(0.3)
            return "done"

        assert retry_locked(slow, deadline=0.05) == "done"

    def test_the_connection_busy_timeout_is_restored_when_the_call_fails_otherwise(self, tmp_path):
        db = sqlite3.connect(tmp_path / "x.db", timeout=30.0, isolation_level=None)
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            retry_locked(lambda: db.execute("SELECT * FROM nope"), db=db)
        assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        db.close()


class TestIngestLock:
    """``watch/ingest.py`` serialises ingest with a thread lock and an advisory file lock."""

    def test_waiting_for_another_process_is_bounded(self, tmp_path, monkeypatch):
        from assurance.watch import ingest

        ledger = EvidenceLedger(tmp_path / "x.db")
        holder_code = (
            "import fcntl, sys, time\n"
            "h = open(sys.argv[1], 'a+'); fcntl.flock(h, fcntl.LOCK_EX)\n"
            "print('locked', flush=True); time.sleep(60)\n"
        )
        holder = subprocess.Popen([sys.executable, "-c", holder_code, ingest.lock_path(ledger)],  # noqa: S603
                                  stdout=subprocess.PIPE, text=True)
        try:
            assert holder.stdout is not None and holder.stdout.readline().strip() == "locked"
            monkeypatch.setattr(ingest, "LOCK_DEADLINE", 1.0, raising=False)
            started = time.monotonic()
            with pytest.raises(ingest.IngestBusyError), ingest._ingest_lock(ledger):
                pass
            assert time.monotonic() - started < 10
        finally:
            holder.kill()
            holder.wait()

    def test_waiting_for_another_thread_on_the_same_ledger_is_bounded(self, tmp_path, monkeypatch):
        from assurance.watch import ingest

        ledger = EvidenceLedger(tmp_path / "x.db")
        monkeypatch.setattr(ingest, "LOCK_DEADLINE", 0.5)
        inside, release = threading.Event(), threading.Event()

        def hold() -> None:
            with ingest._ingest_lock(ledger):
                inside.set()
                release.wait(20)

        holder = threading.Thread(target=hold)
        holder.start()
        assert inside.wait(5)
        started = time.monotonic()
        try:
            with pytest.raises(ingest.IngestBusyError), ingest._ingest_lock(ledger):
                pass
            assert time.monotonic() - started < 10
        finally:
            release.set()
            holder.join(10)

    def test_one_ledgers_ingest_does_not_queue_behind_another_ledgers(self, tmp_path):
        from assurance.watch import ingest

        first = EvidenceLedger(tmp_path / "a.db")
        second = EvidenceLedger(tmp_path / "b.db")
        inside, release = threading.Event(), threading.Event()

        def hold_first() -> None:
            with ingest._ingest_lock(first):
                inside.set()
                release.wait(20)

        holder = threading.Thread(target=hold_first)
        holder.start()
        assert inside.wait(5)
        reached = threading.Event()

        def take_second() -> None:
            with ingest._ingest_lock(second):
                reached.set()

        waiter = threading.Thread(target=take_second, daemon=True)
        waiter.start()
        got_in = reached.wait(3)
        release.set()
        holder.join(10)
        waiter.join(10)
        assert got_in, "ledger B's ingest waited for ledger A's"
