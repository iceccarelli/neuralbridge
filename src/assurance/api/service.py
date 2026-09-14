"""The service.

    uvicorn assurance.api.service:app --host 0.0.0.0 --port 8000

An HTTP register for the EU Cyber Resilience Act Article 14 reporting duty.
Every write lands in an append-only hash-chained ledger; every read can be
exported as a bundle that refuses to emit if the chain does not verify.

Configuration is in :mod:`assurance.api.deps`. The short version: set
``ASSURANCE_API_KEYS`` before this holds anything real, or the register routes
return 503 and say so.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .. import __version__
from .billing_routes import billing_router
from .deps import auth_mode
from .routes import free_router, public_router, router

__all__ = ["create_app", "app"]

_DESCRIPTION = """
Register for **Regulation (EU) 2024/2847, Article 14** — reporting of actively
exploited vulnerabilities and severe incidents.

Article 14 has applied since **11 September 2026**, and by Article 69(3) it
applies to every in-scope product placed on the market **before 11 December
2027**. There is no grandfathering for reporting, and the Commission's guidance
confirms the duty outlives a product's support period.

**What this service does that a spreadsheet cannot**

* Records the awareness timestamp independently. The reporting platform does
  not yet capture it for vulnerabilities and records *detection* for incidents,
  and awareness is the fact every deadline runs from.
* Computes both final-report clocks correctly: 14 days from a corrective **or
  mitigating** measure for a vulnerability, one calendar month from
  **submission** of the 72-hour notification for an incident.
* Validates a draft submission against the platform's 39-field specification
  before anyone opens the platform.
* Keeps every record in a hash-chained ledger, and refuses to export one that
  does not verify.

It does not give legal advice, and it does not decide a judgement for you:
triage returns *undetermined* until a human answers.
"""


def create_app(**kwargs: Any) -> FastAPI:
    application = FastAPI(
        title="Industrial Assurance — CRA Article 14 register",
        version=__version__,
        description=_DESCRIPTION,
        openapi_tags=[
            {"name": "free", "description": "The field specification and the dry-run "
                                            "validator. No account needed."},
            {"name": "article 14", "description": "The register. Needs a plan that "
                                                  "includes it."},
            {"name": "billing", "description": "Plans, checkout, and your own account."},
            {"name": "service", "description": "Liveness and configuration."},
        ],
        **kwargs,
    )

    @application.exception_handler(ValueError)
    async def _value_error(_: Request, exc: ValueError) -> JSONResponse:
        # A ValueError reaching here is a malformed enum or timestamp from the
        # caller, not a server fault. Say which, rather than returning a 500.
        return JSONResponse(
            status_code=422, content={"error": "invalid_value", "detail": str(exc)}
        )

    application.include_router(public_router)
    application.include_router(billing_router)
    application.include_router(free_router)
    application.include_router(router)
    return application


app = create_app()


def main() -> int:
    """``assurance-api`` console entry point."""
    import os

    import uvicorn

    if auth_mode() == "unconfigured":
        print(
            "warning: no API keys configured. Register routes will return 503.\n"
            "         set ASSURANCE_API_KEYS=key1,key2  (or ASSURANCE_ALLOW_UNAUTHENTICATED=1\n"
            "         for a local evaluation only)."
        )
    uvicorn.run(
        "assurance.api.service:app",
        host=os.environ.get("ASSURANCE_HOST", "127.0.0.1"),
        port=int(os.environ.get("ASSURANCE_PORT", "8000")),
        reload=os.environ.get("ASSURANCE_RELOAD") == "1",
    )
    return 0
