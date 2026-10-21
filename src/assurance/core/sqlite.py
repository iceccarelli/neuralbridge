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
import time
from collections.abc import Callable
from typing import TypeVar

__all__ = ["enable_wal", "retry_locked"]

T = TypeVar("T")

#: Longest a single open-time operation may wait for a busy database, in seconds.
DEFAULT_DEADLINE = 30.0


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


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
