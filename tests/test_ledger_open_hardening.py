"""Ledger opens (workstream L, red team): foreign files, read-only opens, ``mint_id=False``.

* a foreign DB with only a differently shaped ``chain`` table is refused BEFORE any write;
* the read-only opens refuse a file that holds another application's tables, as the write path
  does;
* ``EvidenceLedger(path, mint_id=False)`` on an existing ledger changes no byte (no WAL switch);
* ``_already_assessed`` (watch) trusts nothing from a chain that does not verify.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3

import pytest

from assurance.core import Actor
from assurance.core.errors import LedgerIntegrityError
from assurance.core.identity import parse_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import Art14Register, Awareness, Signal, SignalChannel, Track


def snapshot(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir())}


def foreign(path, *statements):
    db = sqlite3.connect(path)
    for statement in statements:
        db.execute(statement)
    db.commit()
    db.close()


CHAIN_WRONG = "CREATE TABLE chain (id INTEGER PRIMARY KEY, note TEXT)"
META = "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
CHAIN_OK = (
    "CREATE TABLE chain (seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, kind TEXT, subject TEXT,"
    " content_hash TEXT, prev_hash TEXT, link_hash TEXT, actor TEXT, payload TEXT)")


def test_a_foreign_chain_table_is_refused_before_any_write(tmp_path):
    path = tmp_path / "f.db"
    foreign(path, CHAIN_WRONG)
    before = snapshot(tmp_path)
    with pytest.raises(LedgerIntegrityError, match="another application"):
        EvidenceLedger(path)
    assert snapshot(tmp_path) == before
    db = sqlite3.connect(path)
    assert [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")] == [
        "chain"]  # in particular: no meta table was created
    db.close()


def test_a_foreign_chain_table_is_refused_by_the_read_only_opens_too(tmp_path):
    path = tmp_path / "f.db"
    foreign(path, META, CHAIN_WRONG)
    before = snapshot(tmp_path)
    for opener in (EvidenceLedger.open_readonly, EvidenceLedger.open_existing):
        with pytest.raises(LedgerIntegrityError):
            opener(path)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("extra", [
    "CREATE TABLE secrets (k TEXT, v TEXT)",
    "CREATE TABLE users (id INTEGER PRIMARY KEY)",
])
def test_a_lookalike_with_application_tables_is_refused_for_reading(tmp_path, extra):
    path = tmp_path / "app.db"
    foreign(path, META, CHAIN_OK, extra)
    before = snapshot(tmp_path)
    for opener in (EvidenceLedger.open_readonly, EvidenceLedger.open_existing):
        with pytest.raises(LedgerIntegrityError, match="another application"):
            opener(path)
    with pytest.raises(LedgerIntegrityError):
        EvidenceLedger(path)  # the write path already refused it
    assert snapshot(tmp_path) == before


def test_a_genuine_ledger_still_opens_everywhere(tmp_path):
    path = tmp_path / "ok.db"
    EvidenceLedger(path)
    assert len(EvidenceLedger.open_readonly(path)) == 0
    assert len(EvidenceLedger.open_existing(path)) == 0


def idless_delete_journal_ledger(tmp_path):
    path = tmp_path / "old.db"
    ledger = EvidenceLedger(path)
    reg = Art14Register(ledger)
    reg.record_signal("C1", Signal(received_at=parse_utc("2026-09-19T05:00:00Z"),
                                   channel=SignalChannel.OTHER, received_by="a",
                                   description="d"), Actor("a", "r"))
    db = sqlite3.connect(path)
    db.execute("DELETE FROM meta WHERE key = 'ledger_id'")
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.execute("PRAGMA journal_mode=DELETE")
    db.close()
    return path


def test_mint_id_false_changes_no_byte_of_an_existing_ledger(tmp_path):
    path = idless_delete_journal_ledger(tmp_path)
    before = snapshot(tmp_path)
    assert set(before) == {"old.db"}
    ledger = EvidenceLedger(path, mint_id=False)
    assert len(ledger) == 1
    ok, problems = ledger.verify_chain()
    assert ok, problems
    assert ledger.entries()[0].kind == "art14.signal"
    assert ledger.ledger_id() is None
    assert snapshot(tmp_path) == before  # no WAL switch, no id, no -wal / -shm


def test_mint_id_false_can_still_be_appended_to_and_then_mints_nothing(tmp_path):
    path = idless_delete_journal_ledger(tmp_path)
    ledger = EvidenceLedger(path, mint_id=False)
    Art14Register(ledger).record_signal(
        "C2", Signal(received_at=parse_utc("2026-09-19T05:00:00Z"), channel=SignalChannel.OTHER,
                     received_by="a", description="d"), Actor("a", "r"))
    assert len(EvidenceLedger.open_readonly(path)) == 2
    assert EvidenceLedger.open_readonly(path).ledger_id() is None


def test_mint_id_false_on_a_new_path_still_creates_the_ledger(tmp_path):
    path = tmp_path / "new.db"
    ledger = EvidenceLedger(path, mint_id=False)
    assert path.is_file() and len(ledger) == 0 and ledger.ledger_id() is None


def test_a_wal_crash_copy_without_shm_is_read_correctly(tmp_path):
    """The documented limit: the data and -wal bytes are untouched; SQLite adds a -shm."""
    src = tmp_path / "src"
    src.mkdir()
    path = src / "l.db"
    ledger = EvidenceLedger(path)
    keep = sqlite3.connect(path)
    keep.execute("PRAGMA wal_autocheckpoint=0")
    keep.execute("SELECT COUNT(*) FROM chain").fetchone()
    reg = Art14Register(ledger)
    for i in range(3):
        reg.record_signal(f"C{i}", Signal(received_at=parse_utc("2026-09-19T05:00:00Z"),
                                          channel=SignalChannel.OTHER, received_by="a",
                                          description="d"), Actor("a", "r"))
    copy = tmp_path / "copy"
    copy.mkdir()
    shutil.copy(path, copy / "l.db")
    shutil.copy(str(path) + "-wal", copy / "l.db-wal")
    before = snapshot(copy)
    opened = EvidenceLedger.open_existing(copy / "l.db")
    assert len(opened) == 3 and opened.verify_chain()[0]
    after = snapshot(copy)
    assert {k: after[k] for k in before} == before
    keep.close()


def test_already_assessed_ignores_a_chain_that_does_not_verify(tmp_path):
    from assurance.watch.runner import _already_assessed

    path = tmp_path / "w.db"
    ledger = EvidenceLedger(path)
    reg = Art14Register(ledger)
    reg.record_signal("CASE-ADV-1", Signal(received_at=parse_utc("2026-09-19T05:00:00Z"),
                                           channel=SignalChannel.OTHER, received_by="a",
                                           description="d"), Actor("a", "r"))
    reg.record_awareness(
        "CASE-ADV-1", Awareness(established_at=parse_utc("2026-09-19T06:00:00Z"),
                                assessment_started_at=parse_utc("2026-09-19T05:30:00Z"),
                                assessment_completed_at=parse_utc("2026-09-19T06:00:00Z"),
                                determined_by="a", reasoning="r"),
        Track.VULNERABILITY, Actor("a", "r"), now=parse_utc("2026-10-01T00:00:00Z"))
    assert _already_assessed(EvidenceLedger.open_readonly(path)) == frozenset({"ADV-1"})
    # tamper: edit a row in place (the record itself is still internally consistent, the link is not)
    db = sqlite3.connect(path)
    db.execute("UPDATE chain SET at = '2026-09-19T00:00:00Z' WHERE kind = 'art14.signal'")
    db.commit()
    db.close()
    assert _already_assessed(EvidenceLedger.open_readonly(path)) == frozenset()
