"""A small, bounded, in-process rate limiter.

What it is: a sliding window per ``(route, client)`` and one process-wide budget, held in
memory, with an injectable clock so a test never sleeps.

What it is not: a defence for a deployment with more than one process or machine. Each process
counts for itself, so N workers allow N times the limit, and a restart forgets everything.
A real limit for the public internet belongs at the edge (Fly proxy, Cloudflare, Vercel
firewall); this exists so that an unauthenticated route that costs a Stripe API call, or CPU,
is not completely open when that edge limit has not been configured yet. The operator still
owns the edge limit.

Memory is bounded two ways: a client's record is dropped once its window has emptied, and the
table never holds more than ``max_clients`` records (the least recently seen is evicted, so an
attacker with a great many addresses can make the limiter forget a quiet client, but cannot
make the process grow).
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["Limit", "RateLimiter", "RateLimitedError", "env_limit"]


@dataclass(frozen=True)
class Limit:
    """At most ``count`` events per ``window`` seconds. ``count`` of 0 means "no limit"."""

    count: int
    window: float = 60.0


class RateLimitedError(Exception):
    """The caller is over its limit; ``retry_after`` is whole seconds, at least 1."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"rate limited; retry in {retry_after}s")
        self.retry_after = retry_after


def env_limit(name: str, default: Limit) -> Limit:
    """``name`` as ``<count>`` (per minute) or ``<count>/<seconds>``; 0 disables. Bad = default."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    count_text, _, window_text = raw.partition("/")
    try:
        count = int(count_text)
        window = float(window_text) if window_text else default.window
    except ValueError:
        return default
    if count < 0 or window <= 0:
        return default
    return Limit(count, window)


class RateLimiter:
    """Sliding-window counters keyed by an arbitrary string."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 max_clients: int = 10_000) -> None:
        self._clock = clock
        self._max = max(1, max_clients)
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def set_clock(self, clock: Callable[[], float]) -> None:
        self._clock = clock

    def __len__(self) -> int:
        return len(self._hits)

    def check(self, key: str, limit: Limit) -> None:
        """Count one event for ``key``; raise :class:`RateLimitedError` if it is over ``limit``.

        A refused event is not counted, so a client that keeps hammering does not extend its
        own ban: it is let back in exactly when its oldest counted event leaves the window.
        """
        if limit.count <= 0:
            return
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                hits = deque()
            while hits and now - hits[0] >= limit.window:
                hits.popleft()
            if len(hits) >= limit.count:
                self._hits[key] = hits
                self._hits.move_to_end(key)
                raise RateLimitedError(max(1, math.ceil(limit.window - (now - hits[0]))))
            hits.append(now)
            self._hits[key] = hits
            self._hits.move_to_end(key)
            while len(self._hits) > self._max:
                self._hits.popitem(last=False)
            if len(self._hits) > 64 and len(self._hits) % 64 == 0:
                self._sweep(now, limit.window)

    def _sweep(self, now: float, window: float) -> None:
        """Drop records whose events have all left the window (called with the lock held)."""
        for key in [k for k, h in self._hits.items() if not h or now - h[-1] >= window]:
            del self._hits[key]
