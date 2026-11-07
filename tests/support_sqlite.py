"""SQLite helpers for tests that open a database file directly.

``with sqlite3.connect(path) as db:`` commits or rolls back when the block ends but does **not**
close the connection, so every use leaks one connection that CPython reports as a
``ResourceWarning`` when it is collected (``unclosed database``). A one-liner such as
``sqlite3.connect(p).execute(...).fetchall()`` leaks the same way. These helpers keep the
transaction semantics of the ``with`` form and always close.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from os import PathLike
from typing import Any


@contextmanager
def connect(database: str | PathLike[str], /, **kwargs: Any) -> Iterator[sqlite3.Connection]:
    """``sqlite3.connect`` as a context manager that commits/rolls back like ``with conn:`` and
    then closes the connection (which ``with conn:`` alone never does)."""
    conn = sqlite3.connect(database, **kwargs)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def rows(database: str | PathLike[str], sql: str, params: tuple[Any, ...] = (), /,
         **kwargs: Any) -> list[Any]:
    """Run one statement on a fresh connection, return every row, close the connection."""
    with connect(database, **kwargs) as conn:
        return conn.execute(sql, params).fetchall()


def scalar(database: str | PathLike[str], sql: str, params: tuple[Any, ...] = (), /,
           **kwargs: Any) -> Any:
    """Like :func:`rows` but the first column of the first row."""
    with connect(database, **kwargs) as conn:
        return conn.execute(sql, params).fetchone()[0]


class ConnectionTracker:
    """Records every ``sqlite3.connect`` made while installed, to prove each one was closed.

    ``ResourceWarning: unclosed database`` is only emitted by CPython 3.13 and later, so a leak
    cannot be seen as a warning on 3.11/3.12; asking each recorded connection whether it still
    works is version independent.
    """

    def __init__(self) -> None:
        self.connections: list[sqlite3.Connection] = []

    def open_ones(self) -> list[sqlite3.Connection]:
        still_open = []
        for conn in self.connections:
            try:
                conn.execute("SELECT 1")
            except sqlite3.ProgrammingError:   # "Cannot operate on a closed database."
                continue
            still_open.append(conn)
        return still_open


@contextmanager
def tracked_connections() -> Iterator[ConnectionTracker]:
    """Patch ``sqlite3.connect`` to record what it returns (the real connection is returned)."""
    tracker = ConnectionTracker()
    real = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn = real(*args, **kwargs)
        tracker.connections.append(conn)
        return conn

    sqlite3.connect = connect  # type: ignore[assignment]
    try:
        yield tracker
    finally:
        sqlite3.connect = real  # type: ignore[assignment]
