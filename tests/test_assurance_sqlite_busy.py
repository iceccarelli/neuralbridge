"""``_is_busy`` matches SQLite's busy/locked conditions, not any message that
happens to contain the letters; and a ledger write that never began a
transaction does not try to roll one back over the real error."""

from __future__ import annotations

import sqlite3

import pytest

from assurance.core.evidence import Actor, Evidence, Origin
from assurance.core.sqlite import _is_busy, retry_locked
from assurance.evidence.ledger import EvidenceLedger


def _op(message: str, code: int | None = None) -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError(message)
    if code is not None:
        exc.sqlite_errorcode = code  # type: ignore[attr-defined]
    return exc


class TestIsBusy:
    @pytest.mark.parametrize("message", [
        "database is locked", "database table is locked", "database is busy",
        "Database Is Locked",
    ])
    def test_the_real_busy_and_locked_messages_are_busy(self, message):
        assert _is_busy(_op(message))

    @pytest.mark.parametrize("message", [
        "no such table: blocked_items",
        "no such column: busy_since",
        "table clock has no column named locked_at",
        "near \"busy\": syntax error",
    ])
    def test_an_unrelated_message_containing_the_word_is_not_busy(self, message):
        assert not _is_busy(_op(message))

    @pytest.mark.parametrize("code", [5, 6, 261, 517, 262])
    def test_the_error_code_wins_when_python_provides_it(self, code):
        # SQLITE_BUSY / SQLITE_LOCKED and their extended codes.
        assert _is_busy(_op("whatever the message says", code))

    def test_a_non_busy_error_code_is_not_busy_whatever_the_message(self):
        assert not _is_busy(_op("database is locked", 1))

    def test_a_real_missing_table_is_not_retried_until_the_deadline(self, tmp_path):
        db = sqlite3.connect(tmp_path / "x.db")
        calls = []

        def go():
            calls.append(1)
            db.execute("SELECT * FROM blocked_items")

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            retry_locked(go, db=db, deadline=5.0)
        assert len(calls) == 1
        db.close()


class TestFailedBeginIsNotMaskedByRollback:
    def test_a_locked_begin_reports_locked_not_no_transaction(self, tmp_path, monkeypatch):
        ledger = EvidenceLedger(tmp_path / "l.db")
        holder = sqlite3.connect(ledger.path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        original = ledger._connect

        def impatient():
            db = original()
            db.execute("PRAGMA busy_timeout=0")
            return db

        monkeypatch.setattr(ledger, "_connect", impatient)
        ev = Evidence(kind="x.y", body={"a": 1}, actor=Actor("a", "r"),
                      origin=Origin(system="t", reference="r")).seal()
        try:
            with pytest.raises(sqlite3.OperationalError) as info:
                ledger.append(ev, subject="s")
        finally:
            holder.execute("ROLLBACK")
            holder.close()
        assert "database is locked" in str(info.value)
        assert "no transaction is active" not in str(info.value)

    def test_a_failure_inside_the_transaction_still_rolls_back(self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "l.db")
        with pytest.raises(RuntimeError, match="boom"), ledger._write_txn() as db:
            db.execute("INSERT INTO meta (key, value) VALUES ('probe', '1')")
            raise RuntimeError("boom")
        check = sqlite3.connect(ledger.path)
        assert check.execute("SELECT COUNT(*) FROM meta WHERE key='probe'").fetchone()[0] == 0
        check.close()
