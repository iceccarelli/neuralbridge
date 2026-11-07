"""Small SQLite helpers for opening a database that several writers may open first.

SQLite's busy timeout covers ordinary lock waits, but not every call: switching
a database into WAL mode, or writing the schema-version row, can fail at once
with "database is locked" when other connections are doing the same thing. That
is exactly the situation of a brand-new tenant ledger whose first two requests
arrive together (the workspace fires them in parallel), or of two processes
opening an older database after an upgrade. Those must wait their turn, not
fail with a 500 — and must never wait unboundedly, or one stuck writer would
hang every request that merely opens the file.
"""

from __future__ import annotations

import random
import sqlite3
import subprocess  # noqa: S404 - fixed argv, no shell; see copy_files_apart
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypeVar

__all__ = ["copy_files_apart", "enable_wal", "is_not_a_database", "retry_locked"]

T = TypeVar("T")

#: Longest a single open-time operation may wait for a busy database, in seconds.
DEFAULT_DEADLINE = 30.0


#: SQLite's own busy/locked messages (``SQLITE_BUSY`` / ``SQLITE_LOCKED``).
_BUSY_MESSAGES = frozenset({
    "database is locked", "database table is locked", "database is busy",
})
#: Primary result codes; extended codes carry them in the low byte.
_BUSY_CODES = frozenset({5, 6})  # SQLITE_BUSY, SQLITE_LOCKED


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    """Is this SQLite's "someone else holds the lock", and nothing else?

    The error code decides when Python provides it (3.11+); otherwise the
    message must be one of SQLite's own busy/locked messages **exactly**. A
    substring test would retry ``no such table: blocked_items`` until the
    deadline: a permanent error dressed as a transient one.
    """
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return (code & 0xFF) in _BUSY_CODES
    return str(exc).strip().lower() in _BUSY_MESSAGES


def retry_locked(
    fn: Callable[[], T], *, db: sqlite3.Connection | None = None,
    deadline: float = DEFAULT_DEADLINE, first_delay: float = 0.005,
    max_delay: float = 0.1,
) -> T:
    """Call ``fn`` and retry, with jittered backoff, while SQLite says it is busy.

    The wait is bounded by ``deadline`` seconds of wall-clock time **in total**.
    That only holds if ``db`` — the connection ``fn`` uses — is passed: its own
    busy timeout (30 s on our stores) would otherwise be spent inside every
    single attempt, multiplying the bound by the number of attempts. With ``db``
    given, its busy timeout is set to zero for the duration so that this loop is
    the only thing waiting, and restored afterwards.

    Only a busy/locked ``OperationalError`` is retried; any other error, and the
    last busy one once the deadline has passed, propagates unchanged.
    """
    start = time.monotonic()
    delay = first_delay
    previous: int | None = None
    if db is not None:
        previous = int(db.execute("PRAGMA busy_timeout").fetchone()[0])
        db.execute("PRAGMA busy_timeout=0")
    try:
        while True:
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                if not _is_busy(exc) or time.monotonic() - start >= deadline:
                    raise
                time.sleep(delay * (0.5 + random.random()))  # noqa: S311 - jitter, not security
                delay = min(delay * 2, max_delay)
    finally:
        if db is not None and previous is not None:
            db.execute(f"PRAGMA busy_timeout={previous}")


def enable_wal(db: sqlite3.Connection) -> None:
    """Put ``db`` in WAL mode, waiting (boundedly) for a concurrent switch.

    Reads the current mode first: once any connection has switched the file, the
    others have nothing to change and take no exclusive lock.
    """
    def go() -> None:
        mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        if str(mode).lower() != "wal":
            db.execute("PRAGMA journal_mode=WAL")

    retry_locked(go, db=db)


def is_not_a_database(exc: sqlite3.Error) -> bool:
    """SQLite's own verdict that a file is not a SQLite database at all."""
    return "not a database" in str(exc).lower()


_COPY_SNIPPET = (
    "import shutil, sys\n"
    "a = sys.argv[1:]\n"
    "for src, dst in zip(a[0::2], a[1::2], strict=True):\n"
    "    shutil.copy2(src, dst)\n"
)


def copy_files_apart(pairs: Sequence[tuple[Path, Path]], *, timeout: float = 30.0) -> None:
    """Copy files in a CHILD process.

    POSIX advisory locks belong to the process, not to the descriptor: closing *any* descriptor
    on a file releases every lock this process holds on it, including the ones SQLite holds for
    another thread's open transaction. A plain ``open()`` (or ``shutil.copy``) of a database file
    in a process that also uses it through SQLite can therefore silently drop the write lock, and
    a commit that has already been acknowledged is then lost to a second process that believes it
    is the last user (https://www.sqlite.org/howtocorrupt.html, "Posix advisory locks").
    The child's descriptors affect only the child. Raises ``OSError`` if the copy fails.
    """
    argv: list[str] = [sys.executable, "-I", "-c", _COPY_SNIPPET]
    for src, dst in pairs:
        argv += [str(src), str(dst)]
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)  # noqa: S603
    except subprocess.TimeoutExpired as exc:
        raise OSError("copying the database files timed out") from exc
    if done.returncode != 0:
        raise OSError(done.stderr.decode("utf-8", "replace").strip()[-300:] or "copy failed")
