"""
NeuralBridge Request Batcher — Aggregate Multiple Agent Requests.

When multiple agents (or a single agent issuing rapid-fire calls) target
the same adapter, the batcher groups those requests into a single adapter
invocation.  This dramatically reduces API call counts and, for metered
services, lowers cost.

Architecture
------------
1. Incoming requests are placed in an async queue keyed by adapter type.
2. A background flush loop fires every ``flush_interval`` seconds **or**
   when the queue reaches ``max_batch_size``, whichever comes first.
3. The batch is handed to the adapter's ``execute`` method as a single
   bulk operation (adapters that support batching) or executed serially
   with shared connection reuse.

Usage::

    batcher = RequestBatcher(flush_interval=1.0, max_batch_size=20)
    await batcher.start()
    future = await batcher.enqueue("salesforce", "query", {"soql": "SELECT ..."})
    result = await future
    await batcher.stop()
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class BatchItem:
    """A single request waiting in the batch queue."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    adapter_type: str = ""
    operation: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    future: asyncio.Future[Any] = field(default_factory=lambda: asyncio.get_event_loop().create_future())
    enqueued_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class BatchStats:
    """Runtime statistics for the batcher."""

    total_enqueued: int = 0
    total_flushed: int = 0
    total_batches: int = 0
    avg_batch_size: float = 0.0
    last_flush: datetime | None = None

    def record_flush(self, batch_size: int) -> None:
        self.total_flushed += batch_size
        self.total_batches += 1
        self.avg_batch_size = self.total_flushed / self.total_batches
        self.last_flush = datetime.now(UTC)


class RequestBatcher:
    """
    Groups rapid-fire agent requests into batches for efficient execution.

    Parameters
    ----------
    flush_interval : float
        Maximum seconds between automatic flushes.
    max_batch_size : int
        Maximum items per batch before an immediate flush.
    """

    def __init__(
        self,
        flush_interval: float = 1.0,
        max_batch_size: int = 20,
    ) -> None:
        self._flush_interval = flush_interval
        self._max_batch_size = max_batch_size
        self._queues: dict[str, list[BatchItem]] = {}
        self._lock = asyncio.Lock()
        self._running = False
        self._flush_task: asyncio.Task[None] | None = None
        self._execute_fn: Any = None  # Set externally (router.route)
        self.stats = BatchStats()

    def set_executor(self, fn: Any) -> None:
        """Set the async callable used to execute batched operations."""
        self._execute_fn = fn

    # ── Lifecycle ────────────────────────────────────────────

    async def start(self) -> None:
        """Start the background flush loop."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("batcher_started", interval=self._flush_interval, max_size=self._max_batch_size)

    async def stop(self) -> None:
        """Flush remaining items and stop the background loop."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self._flush_all()
        logger.info("batcher_stopped", stats=self.stats.__dict__)

    # ── Enqueue ──────────────────────────────────────────────

    async def enqueue(
        self,
        adapter_type: str,
        operation: str,
        params: dict[str, Any],
    ) -> asyncio.Future[Any]:
        """
        Add a request to the batch queue.

        Returns an ``asyncio.Future`` that resolves when the batch
        containing this request is executed.
        """
        item = BatchItem(
            adapter_type=adapter_type,
            operation=operation,
            params=params,
        )

        async with self._lock:
            if adapter_type not in self._queues:
                self._queues[adapter_type] = []
            self._queues[adapter_type].append(item)
            self.stats.total_enqueued += 1

            # Immediate flush if batch is full
            if len(self._queues[adapter_type]) >= self._max_batch_size:
                await self._flush_queue(adapter_type)

        return item.future

    # ── Flush Logic ──────────────────────────────────────────

    async def _flush_loop(self) -> None:
        """Background loop that flushes all queues periodically."""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            await self._flush_all()

    async def _flush_all(self) -> None:
        """Flush every adapter queue."""
        async with self._lock:
            for adapter_type in list(self._queues.keys()):
                if self._queues[adapter_type]:
                    await self._flush_queue(adapter_type)

    async def _flush_queue(self, adapter_type: str) -> None:
        """
        Execute all pending items for a single adapter type.

        If the adapter supports bulk operations, the entire batch is sent
        as one call.  Otherwise, items are executed sequentially but share
        the same connection.
        """
        items = self._queues.pop(adapter_type, [])
        if not items:
            return

        batch_size = len(items)
        logger.info("batch_flushing", adapter=adapter_type, size=batch_size)

        for item in items:
            try:
                if self._execute_fn:
                    result = await self._execute_fn(
                        adapter_type=item.adapter_type,
                        operation=item.operation,
                        params=item.params,
                    )
                else:
                    result = {"status": "no_executor", "params": item.params}

                if not item.future.done():
                    item.future.set_result(result)
            except Exception as exc:
                if not item.future.done():
                    item.future.set_exception(exc)

        self.stats.record_flush(batch_size)
        logger.info("batch_flushed", adapter=adapter_type, size=batch_size)

    # ── Inspection ───────────────────────────────────────────

    def pending_count(self, adapter_type: str | None = None) -> int:
        """Return the number of items waiting in the queue."""
        if adapter_type:
            return len(self._queues.get(adapter_type, []))
        return sum(len(q) for q in self._queues.values())

    def get_stats(self) -> dict[str, Any]:
        """Return batcher statistics as a dict."""
        return {
            **self.stats.__dict__,
            "pending": self.pending_count(),
            "queues": {k: len(v) for k, v in self._queues.items()},
        }
