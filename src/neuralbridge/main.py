"""
NeuralBridge — Application Entry Point.

This module bootstraps the FastAPI application, registers all routers,
configures middleware (CORS, OpenTelemetry, Prometheus), and exposes a
CLI helper so the server can be started with ``neuralbridge`` or
``python -m neuralbridge.main``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from neuralbridge import __version__
from neuralbridge.api.dependencies import get_audit_logger
from neuralbridge.api.routes import adapters, ai, compliance, connections, health, logs
from neuralbridge.config import Settings, get_settings
from neuralbridge.security.audit import AuditUnavailableError
from neuralbridge.security.limits import BodySizeLimitMiddleware
from neuralbridge.utils.logger import setup_logging

_log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage startup and shutdown events.

    On startup we:
    * Initialise structured logging
    * Validate configuration
    * Warm the adapter registry

    On shutdown we gracefully close database pools and Redis connections.
    """
    settings: Settings = get_settings()
    setup_logging(settings.log_level, settings.log_format)

    # Store settings in app state for dependency injection
    app.state.settings = settings

    # Fail loudly: a platform that cannot record its audit trail must not start
    # serving. (A sink that breaks later turns /health/ready red and refuses
    # security-relevant operations with 503; see AuditLogger.ensure_writable.)
    try:
        await get_audit_logger().ensure_writable()
    except AuditUnavailableError:
        _log.critical("audit_sink_unavailable_at_startup")
        raise

    # Loud, not fatal (CI's own Postgres service user is a superuser): a privileged demo role is
    # an arbitrary-file/command primitive if any policy gap appears. Also shown on /health/ready.
    from neuralbridge.ai.connections import check_seeded_role

    await check_seeded_role(force=True)

    # Loud, not fatal: what bound /ai connections can and cannot do on this deployment, and which
    # limiters stay per-process when more than one worker is declared (also on /health/ready).
    from neuralbridge.ai.credentials import declared_workers, vault_for
    from neuralbridge.api.dependencies import get_ai_store

    custody = vault_for(get_ai_store())
    if custody.mode != "shared_encrypted":
        _log.warning("ai_credential_custody", mode=custody.mode, reason=custody.config.reason)
    if declared_workers() > 1:
        _log.warning("process_local_limiters", workers=declared_workers(),
                     detail="concurrency gate, audit refusal limiter and assurance throttles are per worker")

    yield  # ← application runs here

    # Shutdown: close every registered adapter (database pools, HTTP clients). Each gets a bounded
    # wait and a failure in one never stops the others; a leaked pool is a real resource leak
    # (asyncpg connections and sockets were left to the garbage collector before this).
    import asyncio

    from neuralbridge.api.dependencies import get_adapter_registry

    registry = get_adapter_registry()
    for adapter_type in registry.list_all():
        adapter = registry.get(adapter_type)
        if adapter is None:
            continue
        try:
            await asyncio.wait_for(adapter.disconnect(), timeout=10.0)
        except Exception as exc:  # noqa: BLE001 - logged, shutdown continues
            _log.warning("adapter_disconnect_failed_at_shutdown", adapter=adapter_type,
                         error=type(exc).__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Application factory.

    Parameters
    ----------
    settings:
        Optional override; when *None* the default ``get_settings()``
        factory is used (reads env / .env).

    Returns
    -------
    FastAPI
        Fully configured application instance.
    """
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="NeuralBridge",
        description=(
            "A lightweight integration hub connecting AI agents to a small set of "
            "supported systems (PostgreSQL, REST) via a common backend, MCP gateway, "
            "and audit trail. See /ai for the agent control-plane slice."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    @app.exception_handler(AuditUnavailableError)
    async def _audit_unavailable(_request: Request, _exc: AuditUnavailableError) -> JSONResponse:
        # Nothing about the sink (path, DSN, driver text) goes to the client.
        return JSONResponse(
            status_code=503,
            content={"detail": {"error": "audit_unavailable",
                                "message": "The audit trail cannot record; the operation was refused."}},
            headers={"Retry-After": "30"},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the submitted value (``input``) of every bad
        # field, which would send a rejected request's password straight back to
        # the caller (and into any proxy log). Keep location/message/type only.
        errors = [{k: v for k, v in e.items() if k in ("loc", "msg", "type")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})

    # Request bodies are capped (NEURALBRIDGE_MAX_BODY_BYTES, default 1 MiB): 413 beyond it.
    app.add_middleware(BodySizeLimitMiddleware)

    # ── CORS ─────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ──────────────────────────────────────────────
    api_prefix = "/api/v1"
    app.include_router(health.router, prefix=api_prefix, tags=["Health"])
    app.include_router(adapters.router, prefix=api_prefix, tags=["Adapters"])
    app.include_router(connections.router, prefix=api_prefix, tags=["Connections"])
    app.include_router(logs.router, prefix=api_prefix, tags=["Audit Logs"])
    app.include_router(compliance.router, prefix=api_prefix, tags=["Compliance"])
    app.include_router(ai.router, prefix=api_prefix, tags=["AI"])

    return app


# ── CLI entry point ──────────────────────────────────────────
def cli() -> None:
    """Start NeuralBridge from the command line."""
    settings = get_settings()
    uvicorn.run(
        "neuralbridge.main:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


# Module-level app instance for test clients and uvicorn CLI
app = create_app()


if __name__ == "__main__":
    cli()
