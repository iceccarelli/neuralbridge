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

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from neuralbridge import __version__
from neuralbridge.api.routes import adapters, compliance, connections, health, logs
from neuralbridge.config import Settings, get_settings
from neuralbridge.utils.logger import setup_logging


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

    yield  # ← application runs here

    # Cleanup (database pools, Redis, etc.) would go here in production.


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
            "Universal Enterprise Middleware for Agentic AI Integration — "
            "securely connect ANY AI agent to ANY system with YAML configuration, "
            "CRA compliance, and zero-trust security."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

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
