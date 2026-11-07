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

import asyncio
import time
from typing import Any

import structlog

from neuralbridge.adapters.base import BaseAdapter
from neuralbridge.security.audit import AuditLogger, AuditUnavailableError
from neuralbridge.security.limits import (
    ConcurrencyGate,
    Limits,
    NotDispatchedError,
    SlidingWindowLimiter,
)

logger = structlog.get_logger(__name__)


class AuditPreflightError(AuditUnavailableError, NotDispatchedError):
    """The audit sink could not record, so the call was refused *before* the adapter ran."""


class AdapterTimeoutError(TimeoutError):
    """The adapter did not finish within the configured call timeout (the target's
    state is unknown — the call was dispatched)."""


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

    def __init__(
        self, registry: AdapterRegistry, audit_logger: AuditLogger, limits: Limits | None = None,
    ) -> None:
        self._registry = registry
        self._audit = audit_logger
        self.limits = limits or Limits.from_env()
        self._rate = SlidingWindowLimiter(self.limits.rate_per_minute)
        self._gate = ConcurrencyGate(self.limits.max_concurrent, self.limits.max_concurrent_per_adapter)

    async def route(
        self,
        adapter_type: str,
        operation: str,
        params: dict[str, Any],
        request_id: str | None = None,
        actor: str = "system",
        owner: str | None = None,
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
        owner : str | None
            Tenant (account id) the call is made on behalf of, recorded as
            ``details["owner"]`` on the audit event so a tenant's audit
            trail can be filtered to its own entries. Derived by the caller
            from the validated principal, never from client input. ``None``
            (callers that predate tenancy) leaves the entry operator-visible
            only.

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
            # Only plain adapter types are listed: per-connection keys (``postgres:<id>``) are
            # tenants' bound connections and this text becomes a 400 body for any caller. The
            # operator sees them through GET /adapters.
            shared = [k for k in self._registry.list_all() if ":" not in k]
            raise ValueError(
                f"Adapter '{adapter_type}' is not registered. "
                f"Available: {shared}"
            )

        owner_detail = {"owner": owner} if owner else {}

        # Refusals that happen before the adapter runs (NotDispatchedError): nothing
        # reached the target, the caller may retry, and a claimed plan goes back to pending.
        self._rate.check(owner or actor)
        try:
            await self._audit.ensure_writable()
        except AuditUnavailableError as exc:
            raise AuditPreflightError(str(exc)) from exc

        with self._gate.slot(adapter_type):
            return await self._dispatch(adapter, adapter_type, operation, params, request_id, actor, owner_detail)

    async def validate(self, adapter_type: str, *, actor: str, owner: str | None = None) -> Any:
        """``adapter.validate_credentials()`` under the same limits and audit as ``route``.

        It can make a credentialed outbound call, so it takes the owner's rate-limit slot, the
        adapter's concurrency slot and the call timeout, and always leaves an ``adapter_validate``
        audit row (``success`` / ``failure``) with actor and tenant. Entitlement is the caller's
        job (``neuralbridge.ai.guard.enforce_validate_gate``).
        """
        adapter = self._registry.get(adapter_type)
        if adapter is None:
            raise ValueError(f"Adapter '{adapter_type}' is not registered.")
        self._rate.check(owner or actor)
        try:
            await self._audit.ensure_writable()
        except AuditUnavailableError as exc:
            raise AuditPreflightError(str(exc)) from exc
        owner_detail = {"owner": owner} if owner else {}
        with self._gate.slot(adapter_type):
            try:
                async with asyncio.timeout(self.limits.call_timeout) as deadline:
                    result = await adapter.validate_credentials()
            except TimeoutError as exc:
                await self._audit.log_event(
                    event_type="adapter_validate", actor=actor, resource=adapter_type, action="validate",
                    result="timeout", details=owner_detail)
                if deadline.expired():
                    raise AdapterTimeoutError(
                        f"adapter '{adapter_type}' did not finish within {self.limits.call_timeout:g}s") from exc
                raise
        await self._audit.log_event(
            event_type="adapter_validate", actor=actor, resource=adapter_type, action="validate",
            result="success" if result.success else "failure", details=owner_detail)
        return result

    async def _dispatch(
        self, adapter: BaseAdapter, adapter_type: str, operation: str, params: dict[str, Any],
        request_id: str | None, actor: str, owner_detail: dict[str, Any],
    ) -> dict[str, Any]:
        start = time.monotonic()
        logger.info(
            "routing_request",
            adapter_type=adapter_type,
            operation=operation,
            request_id=request_id,
        )

        try:
            async with asyncio.timeout(self.limits.call_timeout) as deadline:
                result = await adapter.execute(operation, params)
        except TimeoutError as exc:
            failure: Exception = exc
            if deadline.expired():
                failure = AdapterTimeoutError(
                    f"adapter '{adapter_type}' did not finish within {self.limits.call_timeout:g}s"
                )
                failure.__cause__ = exc
            await self._audit_error(failure, adapter_type, operation, request_id, actor, owner_detail, start)
            raise failure from exc
        except Exception as exc:
            await self._audit_error(exc, adapter_type, operation, request_id, actor, owner_detail, start)
            raise
        elapsed = time.monotonic() - start

        # Audit trail (immutable, CRA-compliant). The adapter has already run; if the
        # sink fails here the AuditUnavailableError propagates (outcome recorded as
        # unknown by callers) rather than being reported as an adapter error.
        await self._audit.log_event(
            event_type="adapter_call",
            actor=actor,
            resource=adapter_type,
            action=operation,
            result="success",
            details={
                "request_id": request_id,
                "duration_ms": round(elapsed * 1000, 2),
                **owner_detail,
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

    async def _audit_error(
        self, exc: Exception, adapter_type: str, operation: str, request_id: str | None,
        actor: str, owner_detail: dict[str, Any], start: float,
    ) -> None:
        elapsed = time.monotonic() - start
        await self._audit.log_event(
            event_type="adapter_error",
            actor=actor,
            resource=adapter_type,
            action=operation,
            result="error",
            details={
                "request_id": request_id,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "duration_ms": round(elapsed * 1000, 2),
                **owner_detail,
            },
        )
        logger.exception("request_routing_failed", adapter_type=adapter_type, error_type=type(exc).__name__)
