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
pass *that sees an append as well*. (A write that is not an append is: the file's
mtime/size signature changed while the head did not move, so that pass becomes a full
walk. See :func:`file_signature`. An edit made while records are being appended cannot
be told from the append by a stat, and stays inside the window.) Every answer says which
it was: :meth:`EvidenceLedger.verify_cached_detail` returns the depth (``full`` or
``incremental``) and the age of the full pass it rests on. It is seen by the next full pass, which happens at the first check in a
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

__all__ = ["DEFAULT_RECHECK_SECONDS", "Verified", "drop", "file_signature", "identity",
           "lookup", "recheck_seconds", "remember", "reset"]

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
    #: :func:`file_signature` taken BEFORE the walk that produced this entry, so a write
    #: that lands during or after the walk shows up as a difference, never as a match.
    #: ``None`` (signature unreadable) never matches anything.
    stat_sig: tuple[tuple[int, int] | None, ...] | None = None


_lock = threading.Lock()
_cache: dict[tuple[str, int, int], Verified] = {}


def identity(path: Path) -> tuple[str, int, int] | None:
    """Resolved path + inode + device, or ``None`` if the file cannot be stat'ed."""
    try:
        st = os.stat(path)
        return (str(path.resolve()), st.st_ino, st.st_dev)
    except OSError:
        return None


def file_signature(path: Path) -> tuple[tuple[int, int] | None, ...] | None:
    """``(mtime_ns, size)`` of the database file and of its ``-wal``, or ``None``.

    Cheap (two stats). It cannot say *what* changed, only that the bytes were written:
    an append and an in-place edit both change it. What it buys is that an incremental
    pass whose head did NOT advance, over a file that WAS written, has seen a write
    that was not an append, and must become a full walk. A missing sidecar is recorded
    as ``None`` in its slot (so its appearance or disappearance is a difference too).
    """
    out: list[tuple[int, int] | None] = []
    try:
        base = path.resolve()
        for name in (base.name, base.name + "-wal"):
            try:
                st = os.stat(base.with_name(name))
            except FileNotFoundError:
                if name == base.name:
                    return None
                out.append(None)
            else:
                out.append((st.st_mtime_ns, st.st_size))
    except OSError:
        return None
    return tuple(out)


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
             full_pass_at: float,
             stat_sig: tuple[tuple[int, int] | None, ...] | None = None) -> None:
    if key is None:
        return
    with _lock:
        _cache.pop(key, None)
        _cache[key] = Verified(seq, link_hash, full_pass_at, stat_sig)
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
