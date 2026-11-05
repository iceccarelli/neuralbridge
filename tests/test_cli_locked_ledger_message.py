"""A locked ledger is said to be locked, not blamed on the shape of the input."""
import sqlite3

from assurance.cli import _operator_message


def test_a_locked_database_is_reported_as_locked():
    msg = _operator_message(sqlite3.OperationalError("database is locked"))
    assert "locked" in msg and "wrong shape" not in msg and "Nothing was written" in msg


def test_other_operational_errors_keep_the_generic_message():
    assert "could not complete" in _operator_message(sqlite3.OperationalError("no such table: chain"))
