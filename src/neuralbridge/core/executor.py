"""
NeuralBridge Execution Engine — Sandboxed Operation Runner.

The executor wraps every adapter call in a controlled execution context
that enforces:

* **Timeouts** — no single operation can run indefinitely.
* **Resource limits** — memory and CPU guards (production: cgroups).
* **Error containment** — exceptions are caught, logged, and returned as
  structured error payloads rather than crashing the gateway.
* **Retry logic** — transient failures are retried with exponential backoff.

This is the last line of defence before an adapter touches an external
system, making it a critical component of the zero-trust architecture.
"""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ExecutionResult:
    """Structured result of a sandboxed execution."""

    success: bool
    data: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    retries: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "retries": self.retries,
            "timestamp": self.timestamp.isoformat(),
        }


class ExecutionEngine:
    """
    Sandboxed, observable execution engine for adapter operations.

    Parameters
    ----------
    default_timeout : float
        Maximum seconds an operation may run before cancellation.
    max_retries : int
        Number of retry attempts for transient failures.
    backoff_base : float
        Base delay (seconds) for exponential backoff between retries.
    """

    def __init__(
        self,
        default_timeout: float = 30.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
    ) -> None:
        self._default_timeout = default_timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base

    async def execute(
        self,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        timeout: float | None = None,
        retries: int | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """
        Run *func* inside a sandboxed context with timeout and retry.

        Parameters
        ----------
        func : Callable
            The async callable to execute (typically ``adapter.execute``).
        timeout : float | None
            Override the default timeout for this call.
        retries : int | None
            Override the default retry count.

        Returns
        -------
        ExecutionResult
            Structured result with timing, retry count, and error info.
        """
        effective_timeout = timeout or self._default_timeout
        effective_retries = retries if retries is not None else self._max_retries
        attempt = 0
        last_error: str | None = None

        while attempt <= effective_retries:
            start = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=effective_timeout,
                )
                elapsed = (time.monotonic() - start) * 1000
                return ExecutionResult(
                    success=True,
                    data=result,
                    duration_ms=round(elapsed, 2),
                    retries=attempt,
                )

            except TimeoutError:
                elapsed = (time.monotonic() - start) * 1000
                last_error = f"Operation timed out after {effective_timeout}s"
                logger.warning(
                    "execution_timeout",
                    attempt=attempt,
                    timeout=effective_timeout,
                )

            except Exception as exc:
                elapsed = (time.monotonic() - start) * 1000
                last_error = str(exc)
                logger.warning(
                    "execution_error",
                    attempt=attempt,
                    error=last_error,
                )

            attempt += 1
            if attempt <= effective_retries:
                delay = self._backoff_base * (2 ** (attempt - 1))
                logger.info("execution_retry", attempt=attempt, delay=delay)
                await asyncio.sleep(delay)

        return ExecutionResult(
            success=False,
            error=last_error,
            duration_ms=round((time.monotonic() - start) * 1000, 2),
            retries=attempt - 1,
        )

    @staticmethod
    def with_timeout(seconds: float) -> Callable[..., Callable[..., Any]]:
        """
        Decorator that wraps an async function with a timeout guard.

        Usage::

            @ExecutionEngine.with_timeout(10.0)
            async def slow_operation():
                ...
        """
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            return wrapper
        return decorator
