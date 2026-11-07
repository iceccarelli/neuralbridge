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
import threading

from fastapi import Depends

from neuralbridge.ai.credentials import CredentialVault, make_connection_guard, vault_for
from neuralbridge.ai.store import AiStore
from neuralbridge.config import Settings
from neuralbridge.config import get_settings as _get_settings
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger, build_audit_logger
from neuralbridge.security.limits import Limits, SharedWindowLimiter

# ── Singletons ───────────────────────────────────────────────

_audit_logger: AuditLogger | None = None
_adapter_registry: AdapterRegistry | None = None
_request_router: RequestRouter | None = None
_ai_store: AiStore | None = None
_router_lock = threading.Lock()
_store_lock = threading.Lock()


def get_settings() -> Settings:
    """Return the validated application settings."""
    return _get_settings()


def get_audit_logger() -> AuditLogger:
    """Return the global audit logger singleton — durable by default.

    SQLite file ``neuralbridge-audit.db`` next to the /ai store
    (``NEURALBRIDGE_AUDIT_DB`` overrides; ``NEURALBRIDGE_AUDIT_BACKEND`` selects
    ``postgres`` or, explicitly, ``memory``). Raises ``AuditUnavailableError``
    (mapped to 503 by the app) when the sink cannot be opened — never a silent
    fall-back to memory."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = build_audit_logger()
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
    """Return the global request router singleton.

    Its per-tenant rate limit is counted in the shared ``/ai`` store (exact across worker
    processes) unless ``NEURALBRIDGE_RATE_LIMIT_SHARED=0``; its per-connection guard re-checks
    the shared record before a bound connection is used."""
    global _request_router
    if _request_router is None:
        # This runs in a worker thread (a plain ``def`` dependency), and building the router opens
        # the store: without the lock, requests arriving together each built their own router, and
        # with it their own concurrency gate, so the in-flight cap was not enforced.
        with _router_lock:
            if _request_router is None:
                limits = Limits.from_env()
                store = get_ai_store()
                limiter: SharedWindowLimiter | None = None
                if os.environ.get("NEURALBRIDGE_RATE_LIMIT_SHARED", "1") != "0":
                    limiter = SharedWindowLimiter(store, limits.rate_per_minute, 60.0, scope="adapter_call")
                _request_router = RequestRouter(
                    registry=registry, audit_logger=audit, limits=limits, rate_limiter=limiter,
                    connection_guard=make_connection_guard(registry, store),
                )
    return _request_router


def get_ai_store() -> AiStore:
    """Return the global /ai store singleton — durable connection + plan
    state, see ``neuralbridge.ai.store``. Path from ``NEURALBRIDGE_AI_STORE``,
    defaulting to ``neuralbridge-ai.db`` in the working directory (same
    convention as ``ASSURANCE_LEDGER``/``ASSURANCE_ACCOUNTS``)."""
    global _ai_store
    if _ai_store is None:
        with _store_lock:
            if _ai_store is None:
                _ai_store = AiStore(os.environ.get("NEURALBRIDGE_AI_STORE", "neuralbridge-ai.db"))
    return _ai_store


def get_credential_vault(store: AiStore = Depends(get_ai_store)) -> CredentialVault:
    """The credential vault for the /ai store (see ``neuralbridge.ai.credentials``): custody mode
    and keys come from the environment, never from the store."""
    return vault_for(store)
