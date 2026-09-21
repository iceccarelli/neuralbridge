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

import os

from fastapi import Depends

from neuralbridge.ai.store import AiStore
from neuralbridge.config import Settings
from neuralbridge.config import get_settings as _get_settings
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

# ── Singletons ───────────────────────────────────────────────

_audit_logger: AuditLogger | None = None
_adapter_registry: AdapterRegistry | None = None
_request_router: RequestRouter | None = None
_ai_store: AiStore | None = None


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


def get_ai_store() -> AiStore:
    """Return the global /ai store singleton — durable connection + plan
    state, see ``neuralbridge.ai.store``. Path from ``NEURALBRIDGE_AI_STORE``,
    defaulting to ``neuralbridge-ai.db`` in the working directory (same
    convention as ``ASSURANCE_LEDGER``/``ASSURANCE_ACCOUNTS``)."""
    global _ai_store
    if _ai_store is None:
        _ai_store = AiStore(os.environ.get("NEURALBRIDGE_AI_STORE", "neuralbridge-ai.db"))
    return _ai_store
