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

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import __version__
from .attest_routes import attest_router
from .billing_routes import billing_router
from .cache_headers import NoStoreMiddleware
from .capabilities_routes import capabilities_router
from .change_routes import change_router
from .check_routes import check_router
from .deps import (
    BodySizeLimitMiddleware,
    accounts_path,
    allowed_origins,
    auth_mode,
    get_accounts,
    ledger_path,
    tenant_ledgers_dir,
    too_deep_body,
    validation_error_body,
)
from .evidence_routes import evidence_router as evidence_verify_router
from .fleet_routes import fleet_router
from .intel_routes import intel_router
from .logging_filters import install as install_log_filters
from .machine_routes import machine_router
from .machinery_routes import machinery_router
from .operator_routes import operator_router
from .routes import evidence_router, free_router, public_router, router
from .supplier_routes import supplier_router
from .value_routes import value_router
from .watch_routes import watch_router

__all__ = ["create_app", "app", "attestation_key_state", "readiness"]

_log = logging.getLogger("assurance.api.service")

_DESCRIPTION = """
Register for **Regulation (EU) 2024/2847, Article 14** — reporting of actively
exploited vulnerabilities and severe incidents.

Article 14 has applied since **11 September 2026**, and by Article 69(3) it
applies to every in-scope product placed on the market **before 11 December
2027**. There is no grandfathering for reporting. Reports go from the manufacturer
to the CSIRT designated as coordinator and to ENISA, through ENISA's single reporting
platform (Art. 14(1), (3), (7); Art. 16); this service files nothing.

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


# =====================================================================
# readiness
# =====================================================================
def _scrub(text: str) -> str:
    """Remove the server's configured paths from an error text before it is shown."""
    for raw in (ledger_path(), accounts_path(), str(tenant_ledgers_dir()),
                os.environ.get("ASSURANCE_ATTEST_LOGS", ""),
                os.environ.get("ASSURANCE_ATTEST_KEY", "")):
        if not raw:
            continue
        for variant in {raw, str(Path(raw).resolve()), str(Path(raw).resolve().parent)}:
            if variant and variant not in ("/", "."):
                text = text.replace(variant, "<path>")
    return text


def _reason(exc: BaseException) -> str:
    return _scrub(f"{type(exc).__name__}: {exc}")[:200]


def _directory_problem(configured: str, what: str, *, must_exist: bool) -> str | None:
    """Why files could not be created under ``configured`` (or beside it), else ``None``.

    ``must_exist`` is for the directory itself; otherwise the path is a file and its parent
    is checked. A missing directory is fine when some ancestor exists, is a directory and is
    writable (it is created on first use); an ancestor that is a file, or that the service
    cannot write, is not. Only ``stat`` and ``access`` are used: nothing is created.
    """
    target = Path(configured).absolute()
    folder = target if must_exist else target.parent
    probe = folder
    try:
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        if not probe.is_dir():
            return f"{what}: a path component is not a directory"
        if not os.access(probe, os.W_OK | os.X_OK):
            return f"{what}: the directory is not writable by the service account"
    except OSError as exc:
        return f"{what}: {type(exc).__name__}"
    return None


def attestation_key_state() -> str:
    """``configured`` / ``not_configured`` / ``unsafe`` / ``unusable`` (never the key).

    Informational. An unconfigured key is an honest, supported state (the attest routes
    answer 503 and say so); it must be visible, not fatal.
    """
    from fastapi import HTTPException

    from .attest_routes import _service_key
    try:
        _service_key()
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return {"no_attestation_key_configured": "not_configured",
                "attestation_key_unsafe": "unsafe"}.get(
                    str(detail.get("error")), "unusable")
    except Exception:  # noqa: BLE001 - reported as a state, never echoed
        return "unusable"
    return "configured"


def _environment() -> tuple[dict[str, Any], list[str], list[str]]:
    """Checks that touch no database: data directories and the attestation key.

    Safe to run at import time (opens and creates nothing). ``(fields, problems, warnings)``.
    """
    out: dict[str, Any] = {}
    problems: list[str] = []
    warnings: list[str] = []
    storage = [
        _directory_problem(accounts_path(), "ASSURANCE_ACCOUNTS", must_exist=False),
        _directory_problem(ledger_path(), "ASSURANCE_LEDGER", must_exist=False),
        _directory_problem(str(tenant_ledgers_dir()), "ASSURANCE_TENANT_LEDGERS",
                           must_exist=True),
    ]
    storage = [x for x in storage if x]
    out["storage_ok"] = not storage
    if storage:
        out["storage_problems"] = [_scrub(x) for x in storage]
        problems.append("a data directory is not usable")
    key = attestation_key_state()
    out["attestation_key"] = key
    if key in ("unsafe", "unusable"):
        warnings.append(
            f"The attestation key is {key}: the attestation routes answer 503 until it is "
            "fixed. `assurance attest preflight` names the problem.")
    elif key == "configured":
        logs = _directory_problem(os.environ.get("ASSURANCE_ATTEST_LOGS", "attestations"),
                                  "ASSURANCE_ATTEST_LOGS", must_exist=True)
        if logs:
            out["attestation_logs_ok"] = False
            warnings.append(_scrub(logs) + "; attestations cannot be recorded")
    return out, problems, warnings


def readiness(operator_ledger_records: Any = None) -> dict[str, Any]:
    """What the service can actually do right now. ``ready`` is False -> answer 503.

    Never raises. Cheap (no chain walk). Reasons name an error class and a scrubbed message,
    never a configured path. ``operator_ledger_records`` is a callable returning the operator
    ledger's entry count (the unauthenticated ``/healthz`` hands it in; the architecture test
    allows only ``routes.py`` to reach the shared register). A startup environment the service cannot work in (an accounts
    database or tenant-ledger directory it cannot write) makes it not ready; a broken
    attestation key only degrades (the attest routes 503), and a missing one is reported
    without changing the status.
    """
    out: dict[str, Any] = {"auth_mode": auth_mode()}
    problems: list[str] = []
    warnings: list[str] = []
    try:
        if operator_ledger_records is not None:
            out["ledger_records"] = operator_ledger_records()
        out["ledger_ok"] = True
    except Exception as exc:  # noqa: BLE001
        out["ledger_ok"] = False
        out["ledger_error"] = _reason(exc)
        problems.append("the operator ledger cannot be opened")
    try:
        get_accounts().usage_today("healthz")
        out["accounts_ok"] = True
    except Exception as exc:  # noqa: BLE001 - building the store is inside the guard
        out["accounts_ok"] = False
        out["accounts_error"] = _reason(exc)
        problems.append("the accounts database cannot be opened")
    env_out, env_problems, env_warnings = _environment()
    out |= env_out
    problems += env_problems
    warnings += env_warnings
    out["ready"] = not problems
    out["problems"] = problems
    out["warnings"] = warnings
    return out


def create_app(**kwargs: Any) -> FastAPI:
    application = FastAPI(
        title="Industrial Autonomous Assurance API",
        version=__version__,
        description=_DESCRIPTION,
        openapi_tags=[
            {"name": "free", "description": "The field specification and the dry-run "
                                            "validator. No account needed."},
            {"name": "article 14", "description": "The register. Needs a plan that "
                                                  "includes it."},
            {"name": "machine safety", "description": "Verify a recorded machine run "
                                                     "against its declared safety "
                                                     "envelope. The separation "
                                                     "calculator and the bundle "
                                                     "re-checker need no account."},
            {"name": "machinery", "description": "Machinery Regulation Annex III "
                                                 "1.1.9: safety software identity, "
                                                 "evidence of intervention, and which "
                                                 "safety functions a recorded "
                                                 "verification still stands for, "
                                                 "at what tier."},
            {"name": "fleet", "description": "Every enrolled machine at once: "
                                             "component advisories fanned out to "
                                             "serial numbers, and Declarations of "
                                             "Conformity bound to a configuration."},
            {"name": "supplier", "description": "Publish a signed component advisory "
                                                "to a hosted feed (Supplier tier, "
                                                "sales-assigned). Reading any feed "
                                                "needs no account."},
            {"name": "billing", "description": "Plans, checkout, and your own account."},
            {"name": "service", "description": "Liveness and configuration."},
        ],
        **kwargs,
    )

    # Added before CORS so it sits inside it: a 413 still carries CORS headers
    # and a browser caller sees "too large", not a CORS failure.
    application.add_middleware(BodySizeLimitMiddleware)
    application.add_middleware(NoStoreMiddleware)
    install_log_filters()

    # Bearer-token auth, never cookies — allow_credentials stays False so a
    # wide origin list can never be combined with credentialed requests.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins()),
        allow_methods=["GET", "POST"],
        # x-api-key is how every paid write in this API is authenticated —
        # Console and /ai both send it as a plain header from the browser
        # (see app/lib/apiKey.ts). Omitting it here does not show up in any
        # curl/pytest test (a browser is the only caller that enforces CORS
        # preflight at all), but it silently breaks every real cross-origin
        # deployment: the browser never even sends the key, so the API sees
        # an anonymous caller and returns 401/402 for a request that should
        # have succeeded. Found while building the Console guided flow.
        # idempotency-key: a browser client that retries a metered call must be
        # allowed to send it, or the preflight refuses the request outright.
        allow_headers=["content-type", "authorization", "x-api-key", "idempotency-key",
                       "x-issuer-public-key"],
        # A browser can read only the CORS-safelisted response headers unless the
        # server lists the rest. app/lib/assuranceApi.ts reads retry-after, and the
        # quota/usage headers are for the browser client too. Named, no wildcard;
        # tests/test_assurance_cors_expose.py fails if a route emits an
        # X-Assurance-* header that is not listed here.
        expose_headers=[
            "Retry-After", "WWW-Authenticate",
            "X-Assurance-Tier", "X-Assurance-Quota-Limit", "X-Assurance-Quota-Remaining",
            "X-Assurance-Usage-Event", "X-Assurance-Billable-Units",
            "X-Assurance-Access", "X-Assurance-Submittable",
        ],
        allow_credentials=False,
    )

    @application.exception_handler(ValueError)
    async def _value_error(_: Request, exc: ValueError) -> JSONResponse:
        # A ValueError reaching here is a malformed enum or timestamp from the
        # caller, not a server fault. Say which, rather than returning a 500.
        return JSONResponse(
            status_code=422, content={"error": "invalid_value", "detail": str(exc)}
        )

    @application.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default echoes each error's `input`: a large body comes back larger.
        return JSONResponse(status_code=422, content=validation_error_body(exc.errors()))

    @application.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> Any:
        # FastAPI answers a body its parser cannot read with 400 "error parsing the body",
        # chaining the cause. When the cause is the interpreter's recursion limit the body is
        # nested too deeply to be data: say that (422), the same on every Python version.
        if isinstance(exc.__cause__, RecursionError):
            return JSONResponse(status_code=422, content=too_deep_body())
        return await http_exception_handler(request, exc)

    application.include_router(public_router)
    application.include_router(billing_router)
    application.include_router(free_router)
    application.include_router(capabilities_router)
    application.include_router(machine_router)
    application.include_router(machinery_router)
    application.include_router(change_router)
    application.include_router(operator_router)
    application.include_router(value_router)
    application.include_router(watch_router)
    application.include_router(fleet_router)
    application.include_router(check_router)
    application.include_router(evidence_verify_router)
    application.include_router(attest_router)
    application.include_router(supplier_router)
    application.include_router(intel_router)
    application.include_router(router)
    application.include_router(evidence_router)
    _log_startup_problems()
    return application


def _log_startup_problems() -> None:
    """Say at start-up what /healthz will say, so the first line of the log is not silence.

    The service still starts: ``/livez`` must answer so the platform restarts nothing that
    a readiness failure alone explains, and ``/healthz`` carries the detail. Best effort;
    a failure here must not stop the app being created (import time).
    """
    try:
        _, problems, warnings = _environment()
    except Exception:  # noqa: BLE001
        return
    for item in [*problems, *warnings]:
        _log.warning("startup: %s", item)


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
