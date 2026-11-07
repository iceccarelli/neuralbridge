"""No plain file descriptor may be opened on a ledger (or intel store) database in a live process.

POSIX advisory locks belong to the process, not to the descriptor: closing *any* descriptor on a
file releases every lock the process holds on it, including the ones SQLite holds for another
thread's open transaction (https://www.sqlite.org/howtocorrupt.html, "Posix advisory locks").
The ledger used to read the database header with ``Path.open("rb")`` whenever a ledger object was
built for a file that already existed, and to ``shutil.copy2`` the file for a crash-copy read.
With four workers a new tenant's first requests build ledger objects in several threads while
another thread is mid-write: the lock vanished, a second process believed it was the last user,
and a commit that had been acknowledged (HTTP 201) was lost. Main CI saw it as a tenant with six
acknowledged first writes and five durable records, and before that as
``sqlite3.OperationalError: disk I/O error``.

The mechanism is demonstrated, not just argued: ``test_closing_any_descriptor_releases_the_lock``
shows the platform behaviour this depends on; the remaining tests pin the product to never doing it.
"""

from __future__ import annotations

import builtins
import fcntl
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.intel.store import IntelStore

_PROBE = (
    "import fcntl,os,sys\n"
    "fd=os.open(sys.argv[1],os.O_RDWR)\n"
    "try:\n fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print('granted')\n"
    "except OSError:\n print('refused')\n"
)


def _can_lock_exclusively(path: Path) -> bool:
    out = subprocess.run([sys.executable, "-c", _PROBE, str(path)],  # noqa: S603 - fixed argv
                         capture_output=True, text=True, check=True)
    return out.stdout.strip() == "granted"


def test_closing_any_descriptor_releases_the_lock(tmp_path: Path) -> None:
    """The platform fact the whole invariant rests on (fails loudly if a platform changes it)."""
    target = tmp_path / "f"
    target.write_bytes(b"x" * 200)
    held = os.open(target, os.O_RDWR)
    try:
        fcntl.lockf(held, fcntl.LOCK_SH)
        assert not _can_lock_exclusively(target), "setup: the lock should be held"
        os.close(os.open(target, os.O_RDONLY))           # an unrelated read of the same file
        assert _can_lock_exclusively(target), "this platform kept the lock; the hazard is absent"
    finally:
        os.close(held)


class _OpenRecorder:
    """Records every plain open of a file under ``root`` made through Python's own APIs."""

    def __init__(self, root: Path) -> None:
        self.root, self.opened = str(root), []

    def _note(self, file: object) -> None:
        if isinstance(file, (str, bytes, os.PathLike)) and self.root in os.fsdecode(file):
            self.opened.append(os.fsdecode(file))

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_open, real_io_open, real_os_open = builtins.open, io.open, os.open

        def wrap(real):
            def inner(file, *a, **kw):
                self._note(file)
                return real(file, *a, **kw)
            return inner

        monkeypatch.setattr(builtins, "open", wrap(real_open))
        monkeypatch.setattr(io, "open", wrap(real_io_open))
        monkeypatch.setattr(os, "open", wrap(real_os_open))


def _existing_ledger(tmp_path: Path) -> Path:
    path = tmp_path / "tenant.db"
    EvidenceLedger(path)
    return path


@pytest.mark.parametrize("how", ["construct", "construct_readonly_handle", "open_readonly"])
def test_building_a_ledger_for_an_existing_file_opens_no_plain_descriptor(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    path = _existing_ledger(tmp_path)
    rec = _OpenRecorder(tmp_path)
    rec.install(monkeypatch)
    if how == "construct":
        EvidenceLedger(path)
    elif how == "construct_readonly_handle":
        EvidenceLedger(path, mint_id=False)
    else:
        EvidenceLedger.open_readonly(path)
    assert rec.opened == [], f"plain descriptors opened on the ledger: {rec.opened}"


def test_the_private_copy_is_refused_while_this_process_holds_a_connection(tmp_path: Path) -> None:
    """The private copy uses ordinary descriptors, so it must prove no SQLite connection to the
    file is open in this process; otherwise it voids the read (the caller retries)."""
    from assurance.evidence import ledger as ledger_mod

    path = _existing_ledger(tmp_path)
    ledger = EvidenceLedger(path)
    key = str(path.resolve())
    dst = tmp_path / "copy.db"
    live = ledger._connect_rw()                           # a transaction in flight, in this process
    try:
        assert ledger_mod._LIVE.get(key, 0) >= 1
        with pytest.raises(ledger_mod.LedgerChangedWhileReadError):
            ledger_mod._copy_when_no_live_connection(key, [(path, dst)])
        assert not dst.exists(), "nothing may be copied while a connection is open"
    finally:
        live.close()
    ledger_mod._copy_when_no_live_connection(key, [(path, dst)])   # idle process: allowed
    assert dst.read_bytes() == path.read_bytes()


def test_the_registry_counts_every_connection_and_forgets_closed_and_dropped_ones(tmp_path: Path) -> None:
    from assurance.evidence import ledger as ledger_mod

    ledger = EvidenceLedger(tmp_path / "t.db")
    key = str(Path(tmp_path / "t.db").resolve())
    before = ledger_mod._LIVE.get(key, 0)
    a, b = ledger._connect_rw(), ledger._connect_rw()
    assert ledger_mod._LIVE[key] == before + 2
    a.close()
    a.close()                                             # closing twice must not double-release
    assert ledger_mod._LIVE[key] == before + 1
    del b                                                 # dropped unclosed: __del__ releases it
    import gc
    gc.collect()
    assert ledger_mod._LIVE.get(key, 0) == before


def test_the_intel_store_header_check_opens_no_plain_descriptor(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "intel.db"
    IntelStore(path)
    rec = _OpenRecorder(tmp_path)
    rec.install(monkeypatch)
    IntelStore(path)
    assert rec.opened == [], f"plain descriptors opened on the intel store: {rec.opened}"


def test_a_file_that_is_not_a_database_is_still_refused_untouched(tmp_path: Path) -> None:
    from assurance.core.errors import LedgerIntegrityError

    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not sqlite" * 40)
    before = junk.read_bytes()
    with pytest.raises(LedgerIntegrityError, match="not a SQLite database"):
        EvidenceLedger(junk)
    assert junk.read_bytes() == before and not Path(str(junk) + "-wal").exists()
