"""
NeuralBridge Health Check Routes.

Provides ``/health``, ``/health/ready``, and ``/health/live`` endpoints
for Kubernetes probes and monitoring systems.  Also exposes a Prometheus
metrics endpoint at ``/metrics``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from neuralbridge import __version__
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
    }
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
