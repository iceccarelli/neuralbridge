"""
NeuralBridge Health Check Routes.

Provides ``/health``, ``/health/ready``, and ``/health/live`` endpoints
for Kubernetes probes and monitoring systems.  Also exposes a Prometheus
metrics endpoint at ``/metrics``.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from neuralbridge import __version__
from neuralbridge.ai.audit_events import refusals_suppressed_total
from neuralbridge.api.dependencies import get_adapter_registry, get_audit_logger, get_settings
from neuralbridge.config import Settings
from neuralbridge.core.router import AdapterRegistry
from neuralbridge.security.audit import AuditLogger, AuditUnavailableError

router = APIRouter()


@router.get("/health", summary="Basic health check")
async def health_check() -> dict[str, Any]:
    """Return basic health status and version information."""
    return {
        "status": "healthy",
        "version": __version__,
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "NeuralBridge",
    }


@router.get("/health/ready", summary="Readiness probe")
async def readiness_check(
    settings: Settings = Depends(get_settings),
    registry: AdapterRegistry = Depends(get_adapter_registry),
) -> Any:
    """
    Readiness probe for Kubernetes.

    200 only when the configuration loaded and the **audit sink can record** (a
    write lock is taken and released; nothing is written). If the sink is
    unwritable the answer is **503** with ``status: "degraded"`` and
    ``checks.audit: "unwritable"``: security-relevant operations are refused
    with 503 in that state, so traffic should stop. Failure details are in the
    server log, not in this response.
    """
    audit: AuditLogger | None = None
    audit_state = "ok"
    try:
        audit = get_audit_logger()
        await audit.ensure_writable()
    except AuditUnavailableError:
        audit_state = "unwritable"
    checks: dict[str, str] = {"config": "ok", "adapters": "ok", "audit": audit_state}
    all_ok = all(v == "ok" for v in checks.values())
    body: dict[str, Any] = {
        "status": "ready" if all_ok else "degraded",
        "checks": checks,
        "environment": settings.env.value,
        "audit_backend": audit.storage.backend if audit else "unavailable",
        "audit_durable": bool(audit and audit.storage.durable),
        # Refusal events (402/403 at a gate) are rate limited before the write; this counts the
        # ones not written since the process started, so the suppression is visible.
        "audit_refusals_suppressed": refusals_suppressed_total(),
    }
    # Warning only (never flips readiness): the free /ai demo connection logs in as a role that
    # can reach server files or programs. Absent when no demo DSN is configured.
    from neuralbridge.ai.connections import check_seeded_role

    role = await check_seeded_role()
    warnings: list[str] = []
    notices: list[str] = []
    if role is not None:
        body["ai_demo_role"] = role
        if role.get("privileged"):
            warnings.append(
                "ai_demo_role_privileged: the seeded /ai demo database role is a superuser or a "
                "server-file/program role; use a plain read-only role (docs/ai-local-setup.md)"
            )
    # Credential custody and rate limits: what is shared across workers and what is not. Warnings
    # only (they never flip readiness): a deployment without custody still serves reads, it just
    # refuses to bind a connection (503), and says why here.
    from neuralbridge.ai.credentials import declared_workers, vault_for
    from neuralbridge.api.dependencies import get_ai_store

    workers = declared_workers()
    try:
        custody = vault_for(get_ai_store()).status()
    except Exception as exc:  # noqa: BLE001 - readiness must answer even if the store is broken
        custody = {"mode": "unknown", "reason": f"could not inspect ({type(exc).__name__})"}
    body["credential_custody"] = custody
    if custody.get("mode") == "unavailable":
        warnings.append(f"credential_custody_unavailable: {custody.get('reason', '')}")
    elif custody.get("mode") == "process_local":
        warnings.append("credential_custody_process_local: bound connections are live in ONE worker only")
    journal = custody.get("journal")
    if isinstance(journal, dict) and journal.get("same_device"):
        # A documented limit, not a fault: reported as a notice so a deployment that cannot do better
        # is not told it is broken, and one that can sees what to change.
        notices.append(
            "credential_journal_same_device: the anti-rollback journal shares a device with the /ai store, so "
            "a whole-volume snapshot restore would rewind both; keep it on separate storage")
    if isinstance(journal, dict) and journal.get("intact") is False:
        warnings.append(f"credential_journal_unreadable: {journal.get('error')}")
    # Do not build the router here (it needs the audit sink, which may be the thing that is down).
    from neuralbridge.api import dependencies as deps
    from neuralbridge.security.limits import Limits

    limiter = getattr(deps._request_router, "_rate", None)
    if limiter is not None:
        shared, per_minute = getattr(limiter, "mode", "process_local"), getattr(limiter, "limit", None)
    else:  # no request has needed it yet: report how it will be built
        shared = "shared" if os.environ.get("NEURALBRIDGE_RATE_LIMIT_SHARED", "1") != "0" else "process_local"
        per_minute = Limits.from_env().rate_per_minute
    body["rate_limits"] = {
        "declared_workers": workers,
        "adapter_calls": {"mode": shared, "per_minute": per_minute},
        "process_local": ["concurrency_gate", "audit_refusal_limiter", "assurance_billing_throttles"],
    }
    if shared == "shared_with_local_fallback":
        warnings.append("rate_limit_fallback: the shared rate counter failed; limits are per-process until it recovers")
    if workers > 1:
        warnings.append(
            f"process_local_limiters: WEB_CONCURRENCY={workers}, so the concurrency gate, the audit refusal "
            f"limiter and the assurance throttles admit {workers}x their configured values in total")
    if warnings:
        body["warnings"] = warnings
    if notices:
        body["notices"] = notices
    return JSONResponse(status_code=200 if all_ok else 503, content=body)


@router.get("/health/live", summary="Liveness probe")
async def liveness_check() -> dict[str, str]:
    """Liveness probe — returns 200 if the process is alive."""
    return {"status": "alive"}


@router.get("/metrics", summary="Prometheus metrics")
async def prometheus_metrics() -> dict[str, Any]:
    """
    Expose key metrics in a Prometheus-compatible format.

    In production this would use ``prometheus_client`` to generate
    the standard exposition format.  Here we return a JSON summary.
    """
    return {
        "neuralbridge_info": {"version": __version__},
        "neuralbridge_uptime_seconds": 0,  # Placeholder
        "neuralbridge_requests_total": 0,
        "neuralbridge_errors_total": 0,
        "neuralbridge_adapter_calls_total": 0,
    }
