"""Small SQLite helpers for opening a database that several writers may open first.

SQLite's busy timeout covers ordinary lock waits, but not every call: switching
a database into WAL mode, or running the schema script, can fail at once with
"database is locked" when other connections are doing the same thing. That is
exactly the situation of a brand-new tenant ledger whose first two requests
arrive together (the workspace fires them in parallel), or of two processes
opening an older database after an upgrade. Those must wait their turn, not
fail with a 500.
"""

from __future__ import annotations

import random
import sqlite3
import time
from collections.abc import Callable
from typing import TypeVar

__all__ = ["enable_wal", "retry_locked"]

T = TypeVar("T")


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def retry_locked(
    fn: Callable[[], T], *, attempts: int = 400, first_delay: float = 0.005,
    max_delay: float = 0.1,
) -> T:
    """Call ``fn`` and retry, with jittered backoff, while SQLite says it is busy.

    Only a busy/locked ``OperationalError`` is retried; every other error, and the
    last busy one after ``attempts`` tries (about half a minute), propagates.
    """
    delay = first_delay
    for attempt in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if not _is_busy(exc) or attempt == attempts - 1:
                raise
            time.sleep(delay * (0.5 + random.random()))  # noqa: S311 - jitter, not security
            delay = min(delay * 2, max_delay)
    raise AssertionError("unreachable")  # pragma: no cover


def enable_wal(db: sqlite3.Connection) -> None:
    """Put ``db`` in WAL mode, waiting for a concurrent switch instead of failing.

    Reads the current mode first: once any connection has switched the file, the
    others have nothing to change and take no exclusive lock.
    """
    def go() -> None:
        mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        if str(mode).lower() != "wal":
            db.execute("PRAGMA journal_mode=WAL")

    retry_locked(go)
