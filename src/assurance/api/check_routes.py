"""The Machine Assurance Check over HTTP: one transaction, two entry points.

Free, no account: ``POST /v1/check/machine`` takes one manifest and one
advisory and says whether the change matches this machine — the same
demonstration as ``/v1/fleet/advisory/check``, reshaped into the explicit
verdict states the rest of this module works in.

Paid: ``POST /v1/check/fleet-machine`` takes the key of a machine already
enrolled in the ledger. That is where the paid product actually lives: this
machine's own intervention history and verification bundles decide whether
its safety evidence is still valid, and — when a change is given — the same
change is fanned out across every other enrolled machine in one call.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Anyone, get_register, require_machine
from assurance.billing.accounts import Principal
from assurance.billing.plans import PLANS
from assurance.check import AssuranceVerdict, CheckError, run_ad_hoc_check, run_enrolled_check
from assurance.core.errors import AssuranceError
from assurance.fleet.advisory import ComponentAdvisory
from assurance.machinery.manifest import SafetyManifest

__all__ = ["check_router"]

check_router = APIRouter(prefix="/v1/check", tags=["check"])


async def _entitled_for_fleet_machine(
    principal: Annotated[Principal, Anyone],
) -> Principal:
    """The real Cell gate, with a structured, agent-parseable refusal.

    ``require_machine`` decides entitlement; nothing here duplicates that
    decision or re-implements billing. This only reshapes the 401/402 it
    raises so a calling agent — not just a human reading the page — can act
    on it without special-casing this one route's error body.
    """
    try:
        return await require_machine(principal)
    except HTTPException as exc:
        if exc.status_code == 402 and isinstance(exc.detail, dict):
            detail = {
                "status": "payment_required",
                "service": "fleet_machine_assurance",
                "required_plan": "cell",
                "human_action": "purchase_or_upgrade",
                "next_step": "checkout",
                **exc.detail,
            }
            raise HTTPException(status_code=402, detail=detail) from exc
        if exc.status_code == 401:
            detail = exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
            raise HTTPException(
                status_code=401,
                detail={
                    "status": "authentication_required",
                    "service": "fleet_machine_assurance",
                    "human_action": "sign_in_or_get_a_key",
                    "next_step": "GET /v1/plans",
                    **detail,
                },
                headers=exc.headers,
            ) from exc
        raise


EntitledForFleetMachine = Depends(_entitled_for_fleet_machine)


class MachineCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    advisory: dict[str, Any]


class FleetMachineCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    machine_key: str = Field(min_length=1, max_length=300)
    advisory: dict[str, Any] | None = None


def _bad(exc: Exception, what: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={"error": f"invalid_{what}", "detail": str(exc)},
    )


def _manifest(raw: dict[str, Any]) -> SafetyManifest:
    try:
        return SafetyManifest.from_dict(raw)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "manifest") from exc


def _advisory(raw: dict[str, Any]) -> ComponentAdvisory:
    try:
        return ComponentAdvisory.from_dict(raw)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "advisory") from exc


# Kept in sync with assurance.check.pipeline.MachineAssuranceCheck.to_dict()
# by hand, not generated: it is a dataclass, not a Pydantic model, so there is
# nothing to introspect automatically without inventing a second schema
# layer. The input schemas below *are* introspected, straight from the
# Pydantic models the routes already validate against — no drift possible.
_CHECK_OUTPUT_SCHEMA: dict[str, Any] = {
    "machine": "string", "verdict": "string (see AssuranceVerdict)",
    "enrolled": "boolean", "advisory_evaluated": "boolean", "affected": "boolean",
    "matches": "array", "functions": "array",
    "evidence": {"valid": "integer", "stale": "integer",
                 "insufficient": "integer", "cannot_determine": "integer"},
    "required_actions": "array of function_id",
    "human_review_required": "boolean",
    "interventions": "array", "latest_intervention": "object | null",
    "fleet": {"machines_analyzed": "integer | null",
              "machines_affected": "integer | null"},
    "commercial_next_action": {"action": "string", "endpoint": "string | null"},
    "assessed_at": "string (UTC timestamp)", "checks_skipped": "array of string",
}

_VERDICTS = [v.value for v in AssuranceVerdict]


@check_router.get(
    "/services",
    summary="What NeuralBridge can execute for a machine right now",
)
async def services() -> dict[str, Any]:
    """A machine-readable catalogue an agent can discover before calling anything.

    Generated from the same models and the same ``PLANS`` table every other
    route enforces — nothing here is a price or a capability this deployment
    cannot actually execute. See ``GET /v1/plans`` for the full pricing table
    this catalogue's ``required_plan``/``price`` fields are drawn from.
    """
    cell = PLANS["cell"]
    return {
        "verdicts": _VERDICTS,
        "services": [
            {
                "service_id": "machine_assurance_check",
                "human_name": "Machine Assurance Check",
                "description": (
                    "Does this change or advisory match this machine? Free, "
                    "no account, no ledger read — cannot assess whether "
                    "standing safety evidence is still valid."
                ),
                "endpoint": "POST /v1/check/machine",
                "input_schema": MachineCheckIn.model_json_schema(),
                "output_schema": _CHECK_OUTPUT_SCHEMA,
                "free_or_paid": "free",
                "required_plan": None,
                "price": "free",
                "human_review_may_be_required": True,
                "estimated_execution_class": "synchronous, sub-second",
                "evidence_output": "none — no ledger entry is made",
                "commercial_action": None,
            },
            {
                "service_id": "fleet_machine_assurance",
                "human_name": "Fleet Machine Assurance Check",
                "description": (
                    "The same check against a machine already enrolled in "
                    "the ledger: its own intervention history and "
                    "verification bundles, plus the fleet-wide fan-out when "
                    "a change is given."
                ),
                "endpoint": "POST /v1/check/fleet-machine",
                "input_schema": FleetMachineCheckIn.model_json_schema(),
                "output_schema": _CHECK_OUTPUT_SCHEMA,
                "free_or_paid": "paid",
                "required_plan": "cell",
                "price": cell.price_label or "unpublished",
                "human_review_may_be_required": True,
                "estimated_execution_class": "synchronous, sub-second",
                "evidence_output": (
                    "the machine's manifest, interventions and verification "
                    "bundles already sealed in the hash-chained ledger — "
                    "this call reads them, it does not seal anything new"
                ),
                "commercial_action": {
                    "status_if_not_entitled": "payment_required",
                    "how_to_check_entitlement": "GET /v1/plans with X-API-Key",
                    "how_to_purchase": "POST /v1/checkout",
                },
            },
        ],
    }


@check_router.post(
    "/machine",
    summary="Machine Assurance Check — one manifest, one advisory, no account",
)
async def check_machine(
    body: MachineCheckIn,
    principal: Annotated[Principal, Anyone],
) -> dict[str, Any]:
    """What changed, does it match this machine, what should happen next.

    This is the free entry point: no ledger is read, so the result cannot say
    whether standing safety evidence is still valid — only whether the change
    matches what you told it is on the machine. ``checks_skipped`` says so.
    """
    del principal  # free and unmetered: the same reasoning as the advisory-check route
    manifest = _manifest(body.manifest)
    advisory = _advisory(body.advisory)
    try:
        result = run_ad_hoc_check(manifest, advisory)
    except CheckError as exc:
        raise _bad(exc, "request") from exc
    return result.to_dict()


@check_router.post(
    "/fleet-machine",
    summary="Machine Assurance Check — an enrolled machine, its ledger history",
)
async def check_fleet_machine(
    body: FleetMachineCheckIn,
    principal: Annotated[Principal, EntitledForFleetMachine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The paid product: this machine's own evidence, and the fleet fan-out.

    Requires the Cell plan (the same gate as machine safety verification and
    the machinery passport) because it reads the ledger: the machine must
    already be enrolled via ``POST /v1/machinery/manifest``.
    """
    del principal
    advisory = _advisory(body.advisory) if body.advisory is not None else None
    try:
        result = run_enrolled_check(register.ledger, body.machine_key, advisory)
    except CheckError as exc:
        raise HTTPException(
            status_code=404,
            detail={"error": "machine_not_enrolled", "detail": str(exc)},
        ) from exc
    return result.to_dict()
