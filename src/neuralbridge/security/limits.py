"""Resource controls for the adapter, /ai and MCP paths.

What exists, where, and what it is *not*:

* **Request body size** — :class:`BodySizeLimitMiddleware` (ASGI) refuses a request whose
  ``Content-Length`` exceeds the cap with 413, and counts streamed bytes for chunked
  bodies so a missing/lying header cannot get around it. Default 1 MiB
  (``NEURALBRIDGE_MAX_BODY_BYTES``). The MCP gateway applies the same cap to the raw
  JSON-RPC message (``core.gateway``).
* **Rate limit** — :class:`SlidingWindowLimiter`, per tenant (``owner``, else actor), applied
  inside ``RequestRouter.route`` so the raw adapters route, ``/ai`` and the MCP gateway
  share one limit. Default 120 calls/minute (``NEURALBRIDGE_RATE_LIMIT_PER_MINUTE``,
  ``0`` disables). 429 with ``Retry-After``.
* **Concurrency** — :class:`ConcurrencyGate`: at most N calls in flight globally
  (``NEURALBRIDGE_MAX_CONCURRENT_CALLS``, default 32) and M per adapter instance
  (``NEURALBRIDGE_MAX_CONCURRENT_PER_ADAPTER``, default 8). Over the cap is refused at once
  (503 ``Retry-After``), never queued without bound.
* **Call timeout** — one wall-clock bound around every adapter ``execute``
  (``NEURALBRIDGE_ADAPTER_CALL_TIMEOUT`` seconds, default 60) -> 504.

What is shared across worker processes and what is not
-------------------------------------------------------
* **Shared (exact across processes on one host):** the per-tenant adapter-call rate limit, when a
  window store is supplied (``SharedWindowLimiter`` over the ``/ai`` store's ``rate_windows`` table,
  one atomic ``INSERT .. ON CONFLICT DO UPDATE .. RETURNING`` per call; the wiring in
  ``api/dependencies.py`` does this). It is a sliding-window counter over two fixed windows (the previous window is
  weighted by its remaining share, so a boundary burst is not admitted twice; an estimate, not an exact
  log), a refused call is not counted, and it needs every worker to share the store's filesystem. If the
  store errors the limiter falls back to the process-local one (stricter per process, N times looser
  in total) and says so (``fallbacks``; ``/health/ready``). The free ``/ai/read`` daily quota and the
  other metered scopes are separate, exact and account-wide (``assurance.billing``).
* **Process-local, by construction:** :class:`ConcurrencyGate` (calls in flight; a count of live
  work cannot be shared without leases and heartbeats, which are not built), the refusal-event
  limiter in ``ai/audit_events.py`` (a log-volume guard, not a customer limit) and the
  assurance-side throttles (``assurance.billing.rate_limit``). With ``WEB_CONCURRENCY`` = N each
  admits N times its configured value in total; ``/health/ready`` warns when N > 1.
* Not wired: ``security/rate_limit.py`` (a Redis token bucket and middleware nothing mounts).
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

import structlog

logger = structlog.get_logger(__name__)

MAX_BODY_ENV = "NEURALBRIDGE_MAX_BODY_BYTES"
RATE_ENV = "NEURALBRIDGE_RATE_LIMIT_PER_MINUTE"
GLOBAL_CONCURRENCY_ENV = "NEURALBRIDGE_MAX_CONCURRENT_CALLS"
ADAPTER_CONCURRENCY_ENV = "NEURALBRIDGE_MAX_CONCURRENT_PER_ADAPTER"
CALL_TIMEOUT_ENV = "NEURALBRIDGE_ADAPTER_CALL_TIMEOUT"


class NotDispatchedError(Exception):
    """Raised *before* an adapter was invoked: nothing ran on the target, so the
    caller may safely retry and a claimed plan may be returned to pending."""


class ResourceLimitError(NotDispatchedError):
    """A resource control refused the call. ``status_code``/``retry_after`` map to HTTP."""

    status_code = 429
    code = "resource_limit"

    def __init__(self, message: str, retry_after: float = 1.0) -> None:
        super().__init__(message)
        self.retry_after = max(1, int(retry_after + 0.999))


class RateLimitedError(ResourceLimitError):
    status_code = 429
    code = "rate_limited"


class BusyError(ResourceLimitError):
    status_code = 503
    code = "busy"


def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        logger.warning("limits_env_ignored", name=name)
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("limits_env_ignored", name=name)
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Limits:
    max_body_bytes: int = 1024 * 1024
    rate_per_minute: int = 120
    max_concurrent: int = 32
    max_concurrent_per_adapter: int = 8
    call_timeout: float = 60.0

    @classmethod
    def from_env(cls) -> Limits:
        return cls(
            max_body_bytes=_int_env(MAX_BODY_ENV, cls.max_body_bytes, minimum=1),
            rate_per_minute=_int_env(RATE_ENV, cls.rate_per_minute),
            max_concurrent=_int_env(GLOBAL_CONCURRENCY_ENV, cls.max_concurrent, minimum=1),
            max_concurrent_per_adapter=_int_env(
                ADAPTER_CONCURRENCY_ENV, cls.max_concurrent_per_adapter, minimum=1
            ),
            call_timeout=_float_env(CALL_TIMEOUT_ENV, cls.call_timeout),
        )


class SlidingWindowLimiter:
    """At most ``limit`` hits per ``window`` seconds per key. Thread-safe; ``limit<=0`` disables."""

    def __init__(self, limit: int, window: float = 60.0, *, clock: Any = time.monotonic) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        if self.limit <= 0:
            return
        now = self._clock()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                raise RateLimitedError(
                    f"rate limit of {self.limit} calls per {self.window:g}s exceeded",
                    retry_after=self.window - (now - q[0]),
                )
            q.append(now)
            if len(self._hits) > 10_000:  # bound memory: drop idle keys
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window]:
                    self._hits.pop(k, None)


class SharedWindowStore(Protocol):
    """What :class:`SharedWindowLimiter` needs: ``AiStore.rate_hit``."""

    def rate_hit(self, key: str, *, limit: int, window_s: int, now: float) -> tuple[bool, int, float]: ...


class SharedWindowLimiter:
    """At most about ``limit`` hits per ``window`` seconds per ``scope`` + key, counted in a store that every
    worker process shares. Same ``check`` contract as :class:`SlidingWindowLimiter`.

    ``fallback`` is used (and ``fallbacks`` incremented) only when the store itself raises; a
    refusal from the shared counter is never overridden by the local one."""

    def __init__(self, store: SharedWindowStore, limit: int, window: float = 60.0, *, scope: str,
                 fallback: SlidingWindowLimiter | None = None, clock: Any = time.time) -> None:
        self.store = store
        self.limit = limit
        self.window = max(1, int(window))
        self.scope = scope
        self._clock = clock
        self._fallback = fallback or SlidingWindowLimiter(limit, window)
        self.fallbacks = 0

    @property
    def mode(self) -> str:
        return "shared_with_local_fallback" if self.fallbacks else "shared"

    def check(self, key: str) -> None:
        if self.limit <= 0:
            return
        now = self._clock()
        try:
            allowed, _, retry = self.store.rate_hit(
                f"{self.scope}|{key}", limit=self.limit, window_s=self.window, now=now)
        except Exception:  # noqa: BLE001 - a broken limiter store must not take the platform down
            self.fallbacks += 1
            logger.error("shared_rate_limiter_unavailable_using_process_local", scope=self.scope)
            self._fallback.check(key)
            return
        if not allowed:
            raise RateLimitedError(
                f"rate limit of {self.limit} calls per {self.window:g}s exceeded",
                retry_after=retry,
            )


class ConcurrencyGate:
    """Fail-fast in-flight caps: ``total`` overall and ``per_key`` for each key."""

    def __init__(self, total: int, per_key: int) -> None:
        self.total = total
        self.per_key = per_key
        self._in_flight = 0
        self._by_key: dict[str, int] = {}
        self._lock = threading.Lock()

    @contextmanager
    def slot(self, key: str):  # type: ignore[no-untyped-def]
        with self._lock:
            if self._in_flight >= self.total:
                raise BusyError(f"more than {self.total} calls already in flight", retry_after=1)
            if self._by_key.get(key, 0) >= self.per_key:
                raise BusyError(f"more than {self.per_key} calls already in flight for '{key}'", retry_after=1)
            self._in_flight += 1
            self._by_key[key] = self._by_key.get(key, 0) + 1
        try:
            yield
        finally:
            with self._lock:
                self._in_flight -= 1
                left = self._by_key.get(key, 1) - 1
                if left <= 0:
                    self._by_key.pop(key, None)
                else:
                    self._by_key[key] = left

    @property
    def in_flight(self) -> int:
        return self._in_flight


class BodySizeLimitMiddleware:
    """Pure-ASGI request body cap: 413 over ``max_bytes`` (header or streamed)."""

    def __init__(self, app: Any, max_bytes: int | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes

    def _cap(self) -> int:
        return self.max_bytes if self.max_bytes is not None else Limits.from_env().max_body_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        cap = self._cap()
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > cap:
            await self._reject(send, cap)
            return

        seen = 0
        exceeded = False
        answered = False

        async def counting_receive() -> Any:
            nonlocal seen, exceeded
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > cap:
                    exceeded = True
                    raise _TooLargeError
            return message

        async def tracking_send(message: Any) -> None:
            # Once the cap is blown, whatever the app answers (FastAPI turns a body
            # read failure into a 400) is replaced by one 413.
            nonlocal answered
            if exceeded:
                if not answered:
                    answered = True
                    await self._reject(send, cap)
                return
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLargeError:
            pass
        if exceeded and not answered:
            await self._reject(send, cap)

    @staticmethod
    async def _reject(send: Any, cap: int) -> None:
        body = (
            b'{"detail":{"error":"request_too_large","message":"Request body exceeds the '
            + str(cap).encode()
            + b' byte limit."}}'
        )
        await send({
            "type": "http.response.start", "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})


class _TooLargeError(Exception):
    pass
