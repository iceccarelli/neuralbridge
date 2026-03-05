"""
NeuralBridge API Dependencies — FastAPI Dependency Injection.

Provides shared dependencies that are injected into route handlers:
* ``get_settings`` — application configuration
* ``get_audit_logger`` — immutable audit logger
* ``get_adapter_registry`` — live adapter registry
* ``get_router`` — request router
* ``get_current_user`` — authenticated user (from JWT/API key)
"""

from __future__ import annotations

from fastapi import Depends

from neuralbridge.config import Settings
from neuralbridge.config import get_settings as _get_settings
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

# ── Singletons ───────────────────────────────────────────────

_audit_logger: AuditLogger | None = None
_adapter_registry: AdapterRegistry | None = None
_request_router: RequestRouter | None = None


def get_settings() -> Settings:
    """Return the validated application settings."""
    return _get_settings()


def get_audit_logger() -> AuditLogger:
    """Return the global audit logger singleton."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(storage=InMemoryAuditStorage())
    return _audit_logger


def get_adapter_registry() -> AdapterRegistry:
    """Return the global adapter registry singleton."""
    global _adapter_registry
    if _adapter_registry is None:
        _adapter_registry = AdapterRegistry()
    return _adapter_registry


def get_request_router(
    registry: AdapterRegistry = Depends(get_adapter_registry),
    audit: AuditLogger = Depends(get_audit_logger),
) -> RequestRouter:
    """Return the global request router singleton."""
    global _request_router
    if _request_router is None:
        _request_router = RequestRouter(registry=registry, audit_logger=audit)
    return _request_router
