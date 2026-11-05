"""A ledger object opened on an existing ledger must not recreate it after its files are gone.

``EvidenceLedger(path, mint_id=False)`` opens an existing ledger read-only and prepares it for writing
at its first append. If the tenant's files were deleted in between (``tenant delete``), that first
append used to create a brand-new, schema-bearing ledger at the old path and acknowledge the write:
a deleted tenant's ledger resurrected by a stale handle, with the record missing from the export the
deletion was bound to.
"""

import pytest

from assurance.core import Actor, Evidence, Origin
from assurance.core.errors import LedgerIntegrityError
from assurance.evidence.ledger import EvidenceLedger


def _ev(n: int) -> Evidence:
    return Evidence(kind="signal", body={"n": n}, actor=Actor("t.a", "a", "person"), origin=Origin("t")).seal()


def _remove_with_sidecars(path):
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = path.with_name(path.name + suffix)
        if p.exists():
            p.unlink()


def test_a_write_through_a_stale_read_only_handle_does_not_recreate_a_deleted_ledger(tmp_path):
    path = tmp_path / "tenant.db"
    seed = EvidenceLedger(path)
    seed.append(_ev(1), subject="s")
    stale = EvidenceLedger(path, mint_id=False)          # opened read-only, not yet prepared for writing
    _remove_with_sidecars(path)                           # the tenant is deleted
    with pytest.raises((LedgerIntegrityError, FileNotFoundError)):
        stale.append(_ev(2), subject="race")
    assert not path.exists(), "the write recreated the deleted ledger"


def test_a_prepared_handle_whose_file_was_deleted_also_refuses_and_creates_nothing(tmp_path):
    path = tmp_path / "tenant.db"
    EvidenceLedger(path).append(_ev(1), subject="s")
    handle = EvidenceLedger(path, mint_id=False)
    handle.append(_ev(2), subject="ok")                   # upgraded while the file exists
    _remove_with_sidecars(path)
    with pytest.raises(Exception):  # noqa: B017 - any refusal is fine; what matters is nothing acknowledged
        handle.append(_ev(3), subject="race")
    assert not path.exists() or not _has_chain(path)


def _has_chain(path):
    import sqlite3

    db = sqlite3.connect(path)
    try:
        return db.execute("SELECT 1 FROM sqlite_master WHERE name='chain'").fetchone() is not None
    finally:
        db.close()


def test_the_ordinary_flow_still_works(tmp_path):
    path = tmp_path / "tenant.db"
    EvidenceLedger(path).append(_ev(1), subject="s")
    handle = EvidenceLedger(path, mint_id=False)
    assert handle.append(_ev(2), subject="s").seq == 2


def test_a_handle_that_waits_on_a_lock_across_a_deletion_cannot_resurrect_the_ledger(tmp_path):
    """The window the first guard cannot close: the upgrade began while the file existed, then the files were
    removed before its connection opened. A writing connection must be unable to create a file at all."""
    path = tmp_path / "tenant.db"
    EvidenceLedger(path).append(_ev(1), subject="s")
    handle = EvidenceLedger(path, mint_id=False)
    _remove_with_sidecars(path)
    with pytest.raises(LedgerIntegrityError):
        handle._connect_rw()                  # what _init_for_writing / _write_txn call after the wait
    assert not path.exists()
