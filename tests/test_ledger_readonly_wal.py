"""A read-only / check open of a WAL ledger can never write or alter a file.

PR #106 left two holes: ``EvidenceLedger(path, mint_id=False)`` on a WAL-mode ledger took the
ordinary read-WRITE open (so a crash copy with a ``-wal`` was checkpointed into the main file and
the ``-wal`` deleted), and ``immutable=1`` could misread a file a writer touched between the
sidecar check and the read. Everything here uses synthetic ledgers in ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from assurance.core import Actor, Evidence, LedgerIntegrityError, Origin
from assurance.evidence import EvidenceLedger


def _ev(n: int) -> Evidence:
    return Evidence(kind="test.record", body={"value": n}, actor=Actor("t", "engineer"),
                    origin=Origin("unit-test")).seal()


def _state(directory: Path, *, skip_suffixes: tuple[str, ...] = ()) -> dict[str, tuple]:
    out = {}
    for p in sorted(directory.iterdir()):
        if p.name.endswith(skip_suffixes):
            continue
        st = p.stat()
        out[p.name] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_size, st.st_mtime_ns)
    return out


@pytest.fixture
def crash_copy(tmp_path) -> Path:
    """A WAL ledger as a crash leaves it: ``.db`` + ``-wal`` with committed frames, no ``-shm``."""
    live = tmp_path / "live" / "l.db"
    ledger = EvidenceLedger(live)
    holder = sqlite3.connect(live)          # keeps the WAL from being checkpointed away
    holder.execute("PRAGMA wal_autocheckpoint=0")
    assert holder.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    for i in range(3):
        ledger.append(_ev(i))
    copy = tmp_path / "copy" / "l.db"
    copy.parent.mkdir()
    shutil.copy(live, copy)
    shutil.copy(str(live) + "-wal", str(copy) + "-wal")
    holder.close()
    assert sorted(p.name for p in copy.parent.iterdir()) == ["l.db", "l.db-wal"]
    return copy


class TestMintIdFalseOnAWalLedgerNeverWrites:
    def test_a_crash_copy_is_read_without_touching_any_file(self, crash_copy):
        before = _state(crash_copy.parent)
        ledger = EvidenceLedger(crash_copy, mint_id=False)
        assert len(ledger.entries()) == 3          # the committed WAL frames are used
        assert ledger.verify_chain() == (True, [])
        assert _state(crash_copy.parent) == before  # same files, same bytes, same mtime

    def test_open_readonly_on_a_crash_copy_creates_no_sidecar_either(self, crash_copy):
        before = _state(crash_copy.parent)
        ledger = EvidenceLedger.open_readonly(crash_copy)
        assert len(ledger.entries()) == 3
        assert _state(crash_copy.parent) == before

    def test_a_clean_wal_ledger_gains_no_sidecar_and_no_byte(self, tmp_path):
        path = tmp_path / "l.db"
        EvidenceLedger(path).append(_ev(1))
        before = _state(tmp_path)
        ledger = EvidenceLedger(path, mint_id=False)
        assert len(ledger.entries()) == 1 and ledger.verify_chain()[0]
        assert _state(tmp_path) == before

    def test_with_a_live_writer_the_database_and_wal_bytes_do_not_move(self, tmp_path):
        path = tmp_path / "l.db"
        writer = EvidenceLedger(path)
        writer.append(_ev(1))
        holder = sqlite3.connect(path)
        holder.execute("PRAGMA wal_autocheckpoint=0")
        holder.execute("PRAGMA journal_mode").fetchone()
        writer.append(_ev(2))
        try:
            # -shm is the shared-memory index every WAL reader updates; it is rebuildable and
            # not evidence. The database and the log are.
            before = _state(tmp_path, skip_suffixes=("-shm",))
            ledger = EvidenceLedger(path, mint_id=False)
            assert len(ledger.entries()) == 2
            assert _state(tmp_path, skip_suffixes=("-shm",)) == before
        finally:
            holder.close()

    def test_a_write_through_the_readonly_handle_is_refused(self, tmp_path):
        path = tmp_path / "l.db"
        EvidenceLedger(path).append(_ev(1))
        ledger = EvidenceLedger.open_readonly(path)
        with pytest.raises(LedgerIntegrityError):
            ledger.append(_ev(2))


class TestTheImmutableReadRaceIsDetectedNotServed:
    def test_a_writer_that_lands_during_an_immutable_read_voids_the_read(self, tmp_path):
        path = tmp_path / "l.db"
        EvidenceLedger(path).append(_ev(1))
        ledger = EvidenceLedger.open_readonly(path)
        db = ledger._connect()                      # quiescent: an immutable=1 read
        try:
            db.execute("SELECT COUNT(*) FROM chain").fetchone()
            EvidenceLedger(path).append(_ev(2))     # a writer starts after the sidecar check
        finally:
            with pytest.raises(LedgerIntegrityError, match="changed while"):
                db.close()                          # fail closed: the read is discarded

    def test_an_undisturbed_immutable_read_closes_cleanly(self, tmp_path):
        path = tmp_path / "l.db"
        EvidenceLedger(path).append(_ev(1))
        ledger = EvidenceLedger.open_readonly(path)
        assert len(ledger.entries()) == 1 and ledger.verify_chain()[0]
