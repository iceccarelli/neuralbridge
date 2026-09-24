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

from assurance.api.deps import Anyone, Machine, get_register
from assurance.billing.accounts import Principal
from assurance.check import CheckError, run_ad_hoc_check, run_enrolled_check
from assurance.core.errors import AssuranceError
from assurance.fleet.advisory import ComponentAdvisory
from assurance.machinery.manifest import SafetyManifest

__all__ = ["check_router"]

check_router = APIRouter(prefix="/v1/check", tags=["check"])


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
    principal: Annotated[Principal, Machine],
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
