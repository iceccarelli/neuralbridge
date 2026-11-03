"""``EvidenceLedger(path)`` must not create ledger tables inside somebody else's database."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from assurance.core import LedgerIntegrityError
from assurance.evidence import EvidenceLedger


def _snapshot(path: Path):
    st = path.stat()
    return (hashlib.sha256(path.read_bytes()).hexdigest(), st.st_size, st.st_mtime_ns,
            sorted(p.name for p in path.parent.iterdir()))


def test_a_foreign_sqlite_database_is_refused_and_left_unchanged(tmp_path):
    p = tmp_path / "foreign.db"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)")
    db.execute("INSERT INTO customers (name) VALUES ('x')")
    db.commit()
    db.close()
    before = _snapshot(p)
    with pytest.raises(LedgerIntegrityError, match="another application|not a ledger"):
        EvidenceLedger(p)
    with pytest.raises(LedgerIntegrityError):
        EvidenceLedger(p, mint_id=False)
    assert _snapshot(p) == before
    db = sqlite3.connect(p)
    assert [r[0] for r in db.execute("SELECT name FROM sqlite_master")] == ["customers"]
    db.close()


def test_a_non_sqlite_file_is_refused_and_left_unchanged(tmp_path):
    p = tmp_path / "notes.db"
    p.write_bytes(b"this is not a database\n" * 20)
    before = _snapshot(p)
    with pytest.raises(LedgerIntegrityError, match="not a SQLite database"):
        EvidenceLedger(p)
    assert _snapshot(p) == before


def test_a_short_garbage_file_is_refused(tmp_path):
    p = tmp_path / "short.db"
    p.write_bytes(b"x")
    with pytest.raises(LedgerIntegrityError):
        EvidenceLedger(p)
    assert p.read_bytes() == b"x"


def test_a_wal_mode_foreign_database_with_live_sidecars_is_refused(tmp_path):
    p = tmp_path / "foreign.db"
    db = sqlite3.connect(p)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE t (x)")
    db.commit()
    try:        # the table lives only in the -wal until a checkpoint
        with pytest.raises(LedgerIntegrityError, match="another application|not a ledger"):
            EvidenceLedger(p)
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master")}
        assert names == {"t"}
    finally:
        db.close()


def test_a_missing_or_empty_file_becomes_a_ledger_as_before(tmp_path):
    assert len(EvidenceLedger(tmp_path / "a" / "new.db")) == 0
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    assert len(EvidenceLedger(empty)) == 0


def test_an_existing_ledger_in_either_journal_mode_opens(tmp_path):
    p = tmp_path / "l.db"
    EvidenceLedger(p)
    db = sqlite3.connect(p)
    db.execute("PRAGMA journal_mode=DELETE").fetchone()
    db.close()
    assert len(EvidenceLedger(p)) == 0
