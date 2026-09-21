"""
NeuralBridge Request Router — Adapter Dispatch.

The router sits between callers (the REST API, the MCP gateway, the AI
orchestrator) and the adapter layer.  ``route()`` does exactly three things:

1. Resolves the target adapter from the registry.
2. Delegates execution to the adapter's ``execute()`` method.
3. Returns a normalised JSON response and logs an audit event.

It does **not** validate permissions or apply rate limits — despite an
earlier version of this docstring claiming otherwise, no such check ever
ran here (see ``reports/NEURALBRIDGE-AI-CAPABILITY-MATRIX.md``). Callers
that need authorization must decide it *before* calling ``route()`` and
pass the resulting ``actor`` through so the audit trail records who
actually asked, not a hardcoded placeholder — see
``src/neuralbridge/ai/policy.py`` for the minimal gate the ``/ai`` surface
applies this way.

All operations are logged to the audit trail via ``AuditLogger``.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from neuralbridge.adapters.base import BaseAdapter
from neuralbridge.security.audit import AuditLogger

logger = structlog.get_logger(__name__)


class AdapterRegistry:
    """
    Thread-safe registry of adapter instances keyed by adapter type name.

    Adapters register themselves at startup (or when hot-loaded via the
    management API).  The router looks up adapters here.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, BaseAdapter] = {}

    def register(self, adapter: BaseAdapter, key: str | None = None) -> None:
        """Register an adapter instance.

        Keyed by its declared type name by default — the original,
        one-instance-per-type behaviour every existing caller relies on.
        Pass an explicit ``key`` (e.g. ``f"postgres:{connection_id}"``) to
        register a second, independent instance of the same adapter type
        for a different connection — see ``neuralbridge.ai.connections``,
        which is the one caller that needs more than one Postgres
        connection live at once.
        """
        self._adapters[key or adapter.adapter_type] = adapter
        logger.info("adapter_registered", adapter_type=adapter.adapter_type, key=key or adapter.adapter_type)

    def unregister(self, adapter_type: str) -> None:
        self._adapters.pop(adapter_type, None)

    def get(self, adapter_type: str) -> BaseAdapter | None:
        return self._adapters.get(adapter_type)

    def list_all(self) -> list[str]:
        return list(self._adapters.keys())

    def __contains__(self, adapter_type: str) -> bool:
        return adapter_type in self._adapters


class RequestRouter:
    """
    Routes agent requests to the correct adapter with full observability.

    Parameters
    ----------
    registry : AdapterRegistry
        The live adapter registry.
    audit_logger : AuditLogger
        Immutable audit logger (CRA requirement).
    """

    def __init__(self, registry: AdapterRegistry, audit_logger: AuditLogger) -> None:
        self._registry = registry
        self._audit = audit_logger

    async def route(
        self,
        adapter_type: str,
        operation: str,
        params: dict[str, Any],
        request_id: str | None = None,
        actor: str = "system",
    ) -> dict[str, Any]:
        """
        Dispatch a request to the named adapter.

        Parameters
        ----------
        adapter_type : str
            Registered adapter type (e.g. ``"salesforce"``, ``"slack"``).
        operation : str
            Adapter-specific operation name (e.g. ``"query"``, ``"send_message"``).
        params : dict
            Operation parameters forwarded to the adapter.
        request_id : str | None
            Correlation ID for tracing.
        actor : str
            Who is asking, recorded verbatim on the audit event. Defaults to
            the literal string ``"system"`` for callers that have not been
            updated to pass a real identity — that default is itself a gap,
            not a design choice; see
            ``reports/NEURALBRIDGE-AI-DATA-MAP.md``. Callers that know who
            is calling (e.g. ``src/neuralbridge/ai``) must pass it.

        Returns
        -------
        dict
            Normalised JSON response from the adapter.

        Raises
        ------
        ValueError
            If the adapter type is not registered.
        """
        adapter = self._registry.get(adapter_type)
        if adapter is None:
            raise ValueError(
                f"Adapter '{adapter_type}' is not registered. "
                f"Available: {self._registry.list_all()}"
            )

        start = time.monotonic()
        logger.info(
            "routing_request",
            adapter_type=adapter_type,
            operation=operation,
            request_id=request_id,
        )

        try:
            result = await adapter.execute(operation, params)
            elapsed = time.monotonic() - start

            # Audit trail (immutable, CRA-compliant)
            await self._audit.log_event(
                event_type="adapter_call",
                actor=actor,
                resource=adapter_type,
                action=operation,
                result="success",
                details={
                    "request_id": request_id,
                    "duration_ms": round(elapsed * 1000, 2),
                },
            )

            logger.info(
                "request_routed",
                adapter_type=adapter_type,
                operation=operation,
                duration_ms=round(elapsed * 1000, 2),
            )
            return {
                "status": "success",
                "adapter": adapter_type,
                "operation": operation,
                "data": result,
                "duration_ms": round(elapsed * 1000, 2),
            }

        except Exception as exc:
            elapsed = time.monotonic() - start
            await self._audit.log_event(
                event_type="adapter_error",
                actor=actor,
                resource=adapter_type,
                action=operation,
                result="error",
                details={
                    "request_id": request_id,
                    "error": str(exc),
                    "duration_ms": round(elapsed * 1000, 2),
                },
            )
            logger.exception("request_routing_failed", adapter_type=adapter_type)
            raise
