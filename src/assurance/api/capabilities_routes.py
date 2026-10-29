"""``GET /v1/capabilities``: the service catalogue, generated from the live surfaces.

Free and stateless, like ``/v1/plans``: it reads nothing of an account and writes nothing. It
lists every capability, which of the command line, the HTTP API and the MCP server offer it, which
plan flags gate each API route, and every surface that is absent together with whether that is by
design or a known gap (``assurance/capabilities.py``).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from ..capabilities import catalogue

__all__ = ["capabilities_router"]

capabilities_router = APIRouter(prefix="/v1", tags=["free"])


@capabilities_router.get(
    "/capabilities",
    summary="Everything this service can do, and on which surface",
)
def capabilities(request: Request) -> dict[str, Any]:
    """The catalogue, computed from the running service and cached for its lifetime.

    ``present`` means the command, route or tool exists in this build; it does not prove they
    behave identically. ``planned`` marks a known gap and ``by_design`` a deliberate absence,
    each with its reason.
    """
    cached = getattr(request.app.state, "capabilities_catalogue", None)
    if cached is None:
        cached = catalogue(request.app)
        request.app.state.capabilities_catalogue = cached
    return cached
