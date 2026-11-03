"""A file the intel store refuses is left byte for byte as it was.

Issue #92: ``assurance intel ingest --store FILE``, FILE being somebody else's SQLite database,
refused it (correct) but only after switching it to WAL journal mode (header bytes 18-19 from
``01 01`` to ``02 02``; ``-wal``/``-shm`` may appear). A command that decides a file is not its
own must not have modified it: the application-id check runs before any pragma that writes.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from assurance.cli import main as top
from assurance.intel.store import IntelStore, IntelStoreError

from .intel_support import FIXTURES


def tree(root: Path) -> dict[str, tuple]:
    out = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        out[p.relative_to(root).as_posix()] = (
            st.st_size, st.st_mtime_ns, st.st_mode,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "")
    return out


def foreign(path: Path, *, application_id: int = 0, wal: bool = False) -> None:
    db = sqlite3.connect(path)
    if wal:
        db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE precious (x)")
    db.execute("INSERT INTO precious VALUES (42)")
    if application_id:
        db.execute(f"PRAGMA application_id={application_id}")
    db.commit()
    db.close()


def not_sqlite(path: Path, *, application_id: int = 0, wal: bool = False) -> None:
    path.write_bytes(b"this is somebody's notes, not a database\n" * 20)


CASES = {
    "other app id": lambda p: foreign(p, application_id=0x0BADCAFE),
    "no app id but tables": foreign,
    "other app id, already WAL": lambda p: foreign(p, application_id=0x0BADCAFE, wal=True),
    "tables, already WAL": lambda p: foreign(p, wal=True),
    "not a database": not_sqlite,
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_constructor_refuses_a_foreign_file_without_touching_it(tmp_path, case):
    path = tmp_path / "other.db"
    CASES[case](path)
    before = tree(tmp_path)
    with pytest.raises(IntelStoreError, match="not an intel observation store"):
        IntelStore(path)
    assert tree(tmp_path) == before          # sizes, mtimes, modes, sha256, and no new files
    if "WAL" not in case:
        assert path.read_bytes()[18:20] != b"\x02\x02" or case == "not a database"


@pytest.mark.parametrize("case", sorted(CASES))
def test_cli_ingest_refuses_a_foreign_file_exit_2_and_leaves_it_alone(tmp_path, capsys, case):
    path = tmp_path / "other.db"
    CASES[case](path)
    before = tree(tmp_path)
    code = top(["intel", "ingest", "--store", str(path), "--kev", str(FIXTURES / "kev_min.json")])
    err = capsys.readouterr().err
    assert code == 2 and "not an intel observation store" in err and "Traceback" not in err
    assert tree(tmp_path) == before


def test_the_header_bytes_are_the_ones_the_lab_watches(tmp_path):
    """Pin the specific symptom: journal-mode bytes 18-19 stay 01 01."""
    path = tmp_path / "other.db"
    foreign(path, application_id=0x0BADCAFE)
    assert path.read_bytes()[18:20] == b"\x01\x01"
    with pytest.raises(IntelStoreError):
        IntelStore(path)
    assert path.read_bytes()[18:20] == b"\x01\x01"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["other.db"]


def test_a_foreign_file_that_cannot_be_written_is_refused_not_failed_differently(tmp_path):
    path = tmp_path / "other.db"
    foreign(path, application_id=0x0BADCAFE)
    os.chmod(path, 0o444)
    os.chmod(tmp_path, 0o555)  # noqa: S103 - a read-only dir is the point
    try:
        before = tree(tmp_path)
        with pytest.raises(IntelStoreError, match="not an intel observation store"):
            IntelStore(path)
        assert tree(tmp_path) == before
    finally:
        os.chmod(tmp_path, 0o755)  # noqa: S103


# ---------------------------------------------------------------------------
# its own stores, empty files and new paths still work
# ---------------------------------------------------------------------------
def test_a_new_path_becomes_a_store_and_reopens(tmp_path):
    path = tmp_path / "s.db"
    IntelStore(path)
    assert path.read_bytes()[18:20] == b"\x02\x02"
    IntelStore(path)                       # its own store: accepted again


def test_an_empty_file_becomes_a_store(tmp_path):
    path = tmp_path / "s.db"
    path.write_bytes(b"")
    IntelStore(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA application_id").fetchone()[0] == 0x494E544C


def test_cli_ingest_into_a_fresh_store_and_again_still_works(tmp_path, capsys):
    path = tmp_path / "s.db"
    args = ["intel", "ingest", "--store", str(path), "--kev", str(FIXTURES / "kev_min.json")]
    assert top(args) == 0
    assert top(args) == 0
    capsys.readouterr()


# ---------------------------------------------------------------------------
# the read verbs: opening a store for reading creates nothing beside it
# ---------------------------------------------------------------------------
def test_reading_a_quiescent_wal_store_creates_no_sidecars(tmp_path, capsys):
    path = tmp_path / "s.db"
    assert top(["intel", "ingest", "--store", str(path),
                "--kev", str(FIXTURES / "kev_min.json")]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s.db"]      # WAL mode, no sidecars
    assert path.read_bytes()[18:20] == b"\x02\x02"
    before = tree(tmp_path)
    for verb in (["history"], ["history", "--json"], ["candidates"], ["show", "1"]):
        top(["intel", *verb, "--store", str(path)])
        assert tree(tmp_path) == before, verb
    store = IntelStore.open_existing(path)
    assert store.observations()
    assert tree(tmp_path) == before
    capsys.readouterr()


def test_reading_a_store_a_writer_still_holds_open_sees_the_wal_and_adds_nothing(tmp_path):
    path = tmp_path / "s.db"
    IntelStore(path)
    writer = sqlite3.connect(path, isolation_level=None)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("SELECT count(*) FROM observations").fetchone()
        names = sorted(p.name for p in tmp_path.iterdir())
        assert "s.db-wal" in names and "s.db-shm" in names
        before = tree(tmp_path)
        assert IntelStore.open_existing(path).observations() == []
        assert tree(tmp_path) == before
    finally:
        writer.close()


def test_open_existing_still_refuses_what_is_not_a_store_and_what_is_missing(tmp_path):
    other = tmp_path / "other.db"
    foreign(other, application_id=0x0BADCAFE)
    before = tree(tmp_path)
    for target in (other, tmp_path / "missing.db"):
        with pytest.raises(IntelStoreError):
            IntelStore.open_existing(target)
    assert tree(tmp_path) == before
