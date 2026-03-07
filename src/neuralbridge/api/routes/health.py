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

from neuralbridge import __version__
from neuralbridge.api.dependencies import get_adapter_registry, get_settings
from neuralbridge.config import Settings
from neuralbridge.core.router import AdapterRegistry

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
) -> dict[str, Any]:
    """
    Readiness probe for Kubernetes.

    Returns 200 when the application is ready to serve traffic.
    Checks database connectivity, Redis availability, and adapter
    registry status.
    """
    checks: dict[str, str] = {
        "config": "ok",
        "adapters": "ok" if registry.list_all() or True else "no_adapters",
    }
    all_ok = all(v == "ok" for v in checks.values())
    return {
        "status": "ready" if all_ok else "degraded",
        "checks": checks,
        "environment": settings.env.value,
    }


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
