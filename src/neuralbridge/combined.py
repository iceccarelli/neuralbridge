"""Single-origin ASGI composition for the Assurance and NeuralBridge platform APIs.

The two APIs deliberately share the ASSURANCE_ACCOUNTS file. A customer key issued by
Stripe checkout must resolve to the same account on both /v1 and /api/v1.
Deploying the APIs as independent services with separate local SQLite volumes
silently breaks that identity boundary. This dispatcher keeps both applications
in one process and sends each request to the original FastAPI app without
rewriting its path or headers.
"""
from __future__ import annotations

from contextlib import AsyncExitStack

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class CombinedService:
    """Dispatch one ASGI origin to two FastAPI applications and both lifespans."""

    def __init__(self, assurance_app: ASGIApp, platform_app: ASGIApp) -> None:
        self.assurance_app = assurance_app
        self.platform_app = platform_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            await self._lifespan(scope, receive, send)
            return

        path = str(scope.get("path", "/"))
        if path == "/api" or path.startswith("/api/") or path.startswith("/platform/"):
            target = self.platform_app
        else:
            target = self.assurance_app

        # Keep the original scope intact: platform routes are already mounted at
        # /api/v1, and Assurance routes are mounted at /v1.
        await target(scope, receive, send)

    async def _lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Start both services before accepting traffic; shut both down together."""
        del scope
        async with AsyncExitStack() as stack:
            try:
                # Assurance currently has the default no-op lifespan. Enter it
                # explicitly so future startup/shutdown hooks are not skipped.
                await stack.enter_async_context(
                    self.assurance_app.router.lifespan_context(self.assurance_app)  # type: ignore[attr-defined]
                )
                await stack.enter_async_context(
                    self.platform_app.router.lifespan_context(self.platform_app)  # type: ignore[attr-defined]
                )
            except Exception as exc:
                await send({"type": "lifespan.startup.failed", "message": str(exc)})
                return

            await send({"type": "lifespan.startup.complete"})
            while True:
                message: Message = await receive()
                if message["type"] == "lifespan.shutdown":
                    try:
                        await stack.aclose()
                    except Exception as exc:
                        await send({"type": "lifespan.shutdown.failed", "message": str(exc)})
                    else:
                        await send({"type": "lifespan.shutdown.complete"})
                    return


def create_app(
    assurance_app: ASGIApp | None = None,
    platform_app: ASGIApp | None = None,
) -> CombinedService:
    """Create the combined ASGI app, with injectable applications for tests."""
    if assurance_app is None:
        from assurance.api.service import app as default_assurance_app

        assurance_app = default_assurance_app

    if platform_app is None:
        from neuralbridge.main import app as default_platform_app

        platform_app = default_platform_app

    return CombinedService(assurance_app=assurance_app, platform_app=platform_app)


# Uvicorn entry point used by the combined Fly deployment.
app = create_app()
