"""What this process last verified about a ledger, so a check can be incremental.

``EvidenceLedger.verify_chain`` walks every record: about 55 microseconds each,
so 1 s at 20 000 records. Anything that has to know "does this chain still
verify" on every request (the case store does, before it shows or extends a case)
cannot afford that. This module remembers, per ledger *file*, the head a full
walk last verified and when, and :meth:`EvidenceLedger.verify_cached` then checks
only what a full walk could not have seen:

* the record at the remembered head is still there with the same link hash and
  still chains from its own content (catches truncation, a rewind and a
  replacement at the head), and
* every record appended since is verified completely, including its link to the
  one before it and its evidence hash (catches garbage appended after the head).

**The trade-off, stated plainly.** An in-place edit of an *old* record by
someone with write access to the database file is **not** seen by an incremental
pass. It is seen by the next full pass, which happens at the first check in a
process, whenever the last full pass is older than ``ASSURANCE_CHAIN_RECHECK_SECONDS``
(default 60; ``0`` means every check is a full walk), and always on export,
replay, ``GET /v1/ledger/verify`` and any other call to ``verify_chain``. So the
worst case is "detected within the recheck interval", not "detected on every
read". Nothing here defends against someone who rebuilds a consistent chain: that
needs a signed head attestation (``assurance attest``), exactly as for
``verify_chain`` itself.

Invariants: a failure is never recorded as a pass (it drops the entry, and the
next check is a full walk); an incremental pass never refreshes the age of the
full pass it builds on, so the interval is a hard bound; the identity of a ledger
is its resolved path *and* inode/device, so replacing the file invalidates it.
Per-process and lock-protected; another process keeps its own cache.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

__all__ = ["DEFAULT_RECHECK_SECONDS", "Verified", "drop", "identity", "lookup",
           "recheck_seconds", "remember", "reset"]

DEFAULT_RECHECK_SECONDS = 60.0
_ENV = "ASSURANCE_CHAIN_RECHECK_SECONDS"
#: Enough for a busy multi-tenant process; beyond it the oldest entry is dropped
#: (and that ledger's next check is simply a full walk).
_MAX_ENTRIES = 1024


@dataclass(frozen=True)
class Verified:
    """The head a full walk verified, and the monotonic time that walk finished."""

    seq: int
    link_hash: str
    full_pass_at: float


_lock = threading.Lock()
_cache: dict[tuple[str, int, int], Verified] = {}


def identity(path: Path) -> tuple[str, int, int] | None:
    """Resolved path + inode + device, or ``None`` if the file cannot be stat'ed."""
    try:
        st = os.stat(path)
        return (str(path.resolve()), st.st_ino, st.st_dev)
    except OSError:
        return None


def recheck_seconds() -> float:
    """The bound on how old the last full pass may be. ``0`` disables the cache."""
    raw = os.environ.get(_ENV, "").strip()
    if not raw:
        return DEFAULT_RECHECK_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_RECHECK_SECONDS
    return max(0.0, value)


def now() -> float:
    return time.monotonic()


def lookup(key: tuple[str, int, int] | None) -> Verified | None:
    if key is None:
        return None
    with _lock:
        return _cache.get(key)


def remember(key: tuple[str, int, int] | None, seq: int, link_hash: str,
             full_pass_at: float) -> None:
    if key is None:
        return
    with _lock:
        _cache.pop(key, None)
        _cache[key] = Verified(seq, link_hash, full_pass_at)
        while len(_cache) > _MAX_ENTRIES:
            _cache.pop(next(iter(_cache)))


def drop(key: tuple[str, int, int] | None) -> None:
    if key is None:
        return
    with _lock:
        _cache.pop(key, None)


def reset() -> None:
    """Forget everything (tests; an operator who wants the next check to be full)."""
    with _lock:
        _cache.clear()
