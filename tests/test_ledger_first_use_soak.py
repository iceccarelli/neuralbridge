"""Bounded soak: many brand-new ledgers, each raced at first use by several processes and threads.

This is the data-integrity gate for the first-use window (four workers, a new tenant's first
requests arriving together). Every append that returned is acknowledged; every acknowledged
append must be in the file afterwards, and no operation may fail. It uses only product code
(``EvidenceLedger`` construction and ``_write_txn``), several processes times several threads,
for a bounded number of ledgers (a few seconds).

It is a soak, not a proof: on a quiet local filesystem the pre-fix code passes it too, which is
why the invariant itself is pinned separately in ``test_ledger_foreign_fd_lock_loss.py``.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger

PROCESSES, THREADS, LEDGERS = 4, 3, 60


def _worker(directory: str, start: float, queue: mp.Queue) -> None:
    acked: list[tuple[int, str]] = []
    errors: list[str] = []

    def one(k: int, t: int) -> None:
        path = os.path.join(directory, f"t{k}.db")
        time.sleep(max(0.0, start + k * 0.04 - time.time()))   # every worker hits ledger k together
        try:
            led = EvidenceLedger(path)                          # first use in this process
            key = f"{k}:{os.getpid()}:{t}"
            with led._write_txn() as db:
                db.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (key, "1"))
            acked.append((k, key))
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            errors.append(repr(exc)[:120])

    for k in range(LEDGERS):
        threads = [threading.Thread(target=one, args=(k, t)) for t in range(THREADS)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
    queue.put((acked, errors))


@pytest.mark.skipif(os.name != "posix", reason="POSIX advisory-lock semantics are what this guards")
def test_first_use_of_new_ledgers_by_several_processes_loses_and_fails_nothing(tmp_path: Path) -> None:
    # "spawn", not "fork": the pytest process is multi-threaded (Python 3.12+ warns that forking
    # it can deadlock the child), and a spawned worker is also a truly *first* use of the ledger.
    ctx = mp.get_context("spawn")
    queue: mp.Queue = ctx.Queue()
    start = time.time() + 1.0
    procs = [ctx.Process(target=_worker, args=(str(tmp_path), start, queue)) for _ in range(PROCESSES)]
    for p in procs:
        p.start()
    results = [queue.get(timeout=120) for _ in procs]
    for p in procs:
        p.join(timeout=30)

    errors = [e for _, errs in results for e in errs]
    acked = {a for got, _ in results for a in got}
    assert not errors, sorted(set(errors))[:3]
    assert len(acked) == PROCESSES * THREADS * LEDGERS

    lost = []
    for k in range(LEDGERS):
        db = sqlite3.connect(tmp_path / f"t{k}.db")
        try:
            have = {r[0] for r in db.execute("SELECT key FROM meta")}
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            db.close()
        lost += sorted({key for kk, key in acked if kk == k} - have)
    assert not lost, f"acknowledged but not durable: {lost[:5]}"
