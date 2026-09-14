"""NeuralBridge compliance routes — withdrawn.

Every endpoint that previously lived here returned a hardcoded literal. The
readiness score was computed from its own dict of the word "compliant"; the CRA
report asserted "All known vulnerabilities have been assessed and mitigated"
without consulting any vulnerability; the SBOM endpoint returned eight invented
package names and never called the generator.

They are withdrawn rather than deleted so that anything still calling them
receives an explicit answer instead of a 404 it might read as a routing fault.

The real thing is ``assurance.security.art14`` — a register that records what
actually happened, keeps it in a hash-chained ledger, and refuses to export a
chain that does not verify.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/compliance")

_WITHDRAWN = {
    "error": "withdrawn",
    "reason": (
        "This endpoint returned hardcoded values rather than measurements. It has been "
        "withdrawn rather than left in place, because a fabricated compliance assertion is "
        "worse than none."
    ),
    "use_instead": {
        "service": "assurance.security.art14 — CRA Article 14 register",
        "http": "/v1/register and /v1/cases/{case_id}",
        "cli": "assurance art14 register",
        "validate_a_draft_filing": "POST /v1/spec/validate",
    },
    "note": (
        "CRA Article 14 has applied since 11 September 2026 and, by Art. 69(3), covers "
        "products placed on the market before 11 December 2027. The remaining CRA "
        "obligations apply from 11 December 2027."
    ),
}


def _withdrawn(path: str) -> None:
    raise HTTPException(status_code=410, detail={**_WITHDRAWN, "withdrawn_path": path})


@router.get("/status", summary="Withdrawn — see assurance.security.art14")
async def compliance_status() -> dict[str, Any]:
    """Withdrawn: returned a readiness score computed from its own literals."""
    _withdrawn("/compliance/status")
    return {}


@router.get("/cra-report", summary="Withdrawn — see assurance.security.art14")
async def generate_cra_report() -> dict[str, Any]:
    """Withdrawn: asserted that vulnerabilities had been assessed and mitigated."""
    _withdrawn("/compliance/cra-report")
    return {}


@router.get("/sbom", summary="Withdrawn — see assurance.security.art14")
async def generate_sbom() -> dict[str, Any]:
    """Withdrawn: returned invented package names, never calling the generator."""
    _withdrawn("/compliance/sbom")
    return {}


@router.get("/gdpr", summary="Withdrawn — see assurance.security.art14")
async def gdpr_register() -> dict[str, Any]:
    """Withdrawn: listed security measures the service does not implement."""
    _withdrawn("/compliance/gdpr")
    return {}


@router.get("/incidents", summary="Withdrawn — see assurance.security.art14")
async def incidents() -> dict[str, Any]:
    """Withdrawn: returned an empty incident list unconditionally."""
    _withdrawn("/compliance/incidents")
    return {}
