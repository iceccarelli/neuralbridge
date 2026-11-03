"""Read verbs must not mutate the ledger they read.

``EvidenceLedger.open_existing`` used to build a full read-write ledger: on a DELETE-journal
file it switched to WAL, ran the schema script and minted a ledger id, so the file's bytes
changed on a READ. These tests pin byte-for-byte equality (sha256, size, mtime, directory
listing) across every read verb, for a DELETE-mode ledger and a WAL one, and pin that a verb
that really writes still works.
"""

from __future__ import annotations

import hashlib
import io
import sqlite3
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from assurance.attest.cli import main as attest_main
from assurance.core import Actor, Evidence, LedgerIntegrityError, Origin
from assurance.evidence import EvidenceLedger
from assurance.fleet.cli import main as fleet_main


def _make(n: int) -> Evidence:
    return Evidence(kind="test.record", body={"value": n}, actor=Actor("t", "engineer"),
                    origin=Origin("unit-test")).seal()


def _legacy_ledger(path: Path, *, journal: str, records: int = 3) -> Path:
    """A ledger as an older build left it: no ledger id, in the given journal mode."""
    ledger = EvidenceLedger(path)
    for i in range(records):
        ledger.append(_make(i))
    db = sqlite3.connect(path)
    try:
        db.execute("DELETE FROM meta WHERE key = 'ledger_id'")
        db.commit()
        db.execute(f"PRAGMA journal_mode={journal}").fetchone()
    finally:
        db.close()
    return path


def _state(path: Path) -> dict[str, object]:
    out: dict[str, object] = {"listing": sorted(p.name for p in path.parent.iterdir())}
    for p in sorted(path.parent.iterdir()):
        st = p.stat()
        out[p.name] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_size, st.st_mtime_ns)
    return out


@pytest.fixture(params=["delete", "wal"])
def ledger_file(request, tmp_path) -> Path:
    return _legacy_ledger(tmp_path / "ledger" / "l.db", journal=request.param)


class TestReadVerbsDoNotWrite:
    def test_open_existing_changes_nothing(self, ledger_file):
        before = _state(ledger_file)
        EvidenceLedger.open_existing(ledger_file)
        assert _state(ledger_file) == before

    def test_every_read_method_changes_nothing(self, ledger_file, tmp_path):
        before = _state(ledger_file)
        ledger = EvidenceLedger.open_existing(ledger_file)
        assert len(ledger) == 3
        assert len(ledger.entries()) == 3
        assert ledger.get(ledger.entries()[0].content_hash) is not None
        assert ledger.ledger_id() is None             # no id is minted by a read
        assert ledger.verify_chain() == (True, [])
        assert ledger.verify_report()["verified"] is True
        assert ledger.verify_cached()[0] is True
        ledger.require_intact(full=True)
        ledger.head_attestation()
        ledger.export()
        ledger.read_subject("", "test.record")
        assert _state(ledger_file) == before
        # snapshot_to reads this file and writes elsewhere
        copy = ledger.snapshot_to(tmp_path / "copy" / "c.db")
        assert EvidenceLedger.open_readonly(copy).verify_chain()[0] is True
        assert _state(ledger_file) == before

    def test_open_readonly_refuses_to_write(self, ledger_file):
        ledger = EvidenceLedger.open_readonly(ledger_file)
        before = _state(ledger_file)
        with pytest.raises(LedgerIntegrityError, match="read-only"):
            ledger.append(_make(99))
        assert _state(ledger_file) == before

    def test_fleet_list_changes_nothing(self, ledger_file):
        before = _state(ledger_file)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            fleet_main(["list", "--ledger", str(ledger_file), "--json"])
        assert _state(ledger_file) == before

    def test_attest_sign_and_verify_leave_the_ledger_alone(self, ledger_file, tmp_path):
        keys = tmp_path / "keys"
        keys.mkdir()
        private, public, log = keys / "k", keys / "k.pub", tmp_path / "log.jsonl"
        with redirect_stdout(io.StringIO()):
            assert attest_main(["keygen", "--out", str(private), "--public-out",
                                str(public)]) == 0
        before = _state(ledger_file)
        with redirect_stdout(io.StringIO()):
            assert attest_main(["sign", "--ledger", str(ledger_file), "--key", str(private),
                                "--log", str(log)]) == 0
            assert attest_main(["verify", "--log", str(log), "--public-key", str(public),
                                "--ledger", str(ledger_file)]) == 0
        assert _state(ledger_file) == before

    def test_a_ledger_with_live_sidecars_is_read_without_creating_any(self, tmp_path):
        path = tmp_path / "l.db"
        ledger = EvidenceLedger(path)
        ledger.append(_make(1))
        holder = sqlite3.connect(path)              # keeps -wal / -shm alive while we read
        try:
            holder.execute("SELECT count(*) FROM chain").fetchone()
            before = sorted(p.name for p in tmp_path.iterdir())
            reader = EvidenceLedger.open_existing(path)
            assert len(reader) == 1 and reader.verify_chain()[0] is True
            assert sorted(p.name for p in tmp_path.iterdir()) == before
        finally:
            holder.close()


class TestMissingOrNotALedger:
    def test_a_missing_ledger_is_an_error_and_is_not_created(self, tmp_path):
        missing = tmp_path / "typo.db"
        for opener in (EvidenceLedger.open_existing, EvidenceLedger.open_readonly):
            with pytest.raises(FileNotFoundError):
                opener(missing)
        assert list(tmp_path.iterdir()) == []

    def test_an_empty_file_is_not_a_ledger_and_stays_empty(self, tmp_path):
        p = tmp_path / "empty.db"
        p.write_bytes(b"")
        with pytest.raises(LedgerIntegrityError, match="not a ledger"):
            EvidenceLedger.open_existing(p)
        assert p.read_bytes() == b"" and [q.name for q in tmp_path.iterdir()] == ["empty.db"]

    def test_a_foreign_sqlite_and_a_text_file_are_refused_unchanged(self, tmp_path):
        foreign = tmp_path / "other.db"
        db = sqlite3.connect(foreign)
        db.execute("CREATE TABLE users (id INTEGER)")
        db.commit()
        db.close()
        text = tmp_path / "notes.txt"
        text.write_text("hello")
        before = _state(foreign)
        before_text = _state(text)
        for p in (foreign, text):
            with pytest.raises(LedgerIntegrityError, match="not a ledger"):
                EvidenceLedger.open_existing(p)
        assert _state(foreign) == before and _state(text) == before_text


class TestWritersStillWork:
    def test_open_existing_then_append_prepares_the_file_at_the_write(self, tmp_path):
        path = _legacy_ledger(tmp_path / "l.db", journal="delete")
        ledger = EvidenceLedger.open_existing(path)
        assert ledger.ledger_id() is None
        ledger.append(_make(10))
        assert len(ledger) == 4 and ledger.ledger_id() is not None
        assert EvidenceLedger.open_readonly(path).verify_chain()[0] is True

    def test_writable_true_prepares_the_file_immediately(self, tmp_path):
        path = _legacy_ledger(tmp_path / "l.db", journal="delete")
        ledger = EvidenceLedger.open_existing(path, writable=True)
        assert ledger.ledger_id() is not None
        ledger.append(_make(11))
        assert len(ledger) == 4

    def test_the_plain_constructor_still_creates(self, tmp_path):
        p = tmp_path / "new" / "l.db"
        ledger = EvidenceLedger(p)
        ledger.append(_make(1))
        assert p.is_file() and len(ledger) == 1
