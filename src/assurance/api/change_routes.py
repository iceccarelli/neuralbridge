"""Continuous Machine Change Assurance over HTTP.

Cell-tier only, the same boundary as ``/v1/machine`` and the coverage half of
``/v1/machinery`` — a case is the join of machine verification and Annex III
coverage into a workflow, so it does not make sense to sell it at a tier that
does not include either. No new plan, no new price: see
``deploy/assurance/ADR-0002-change-assurance.md``.

Every route here calls :mod:`assurance.change.service` with objects built from
the request body by the exact same constructors ``/v1/machinery`` already
uses (:class:`~assurance.machinery.manifest.SafetyManifest`,
:class:`~assurance.fleet.advisory.ComponentAdvisory`) — there is no second,
looser parser for the same JSON shape.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Machine, get_register
from assurance.billing.accounts import Principal
from assurance.change.model import CaseStatus
from assurance.change.service import (
    CaseTransitionError,
    advance,
    assess_advisory,
    assess_drift,
    claim,
    decide,
    reverify,
)
from assurance.change.store import CaseStore
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.fleet.advisory import ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord

__all__ = ["change_router"]

change_router = APIRouter(prefix="/v1/change", tags=["change"])


def _bad(exc: Exception, what: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"error": f"invalid_{what}", "detail": str(exc)})


def _actor(name: str, role: str) -> Actor:
    return Actor(identifier=name or "operator", role=role,
                kind="person" if name else "automation")


class DriftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline: dict[str, Any]
    observed: dict[str, Any]
    actor: str = Field(default="", max_length=200)


class AdvisoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisory: dict[str, Any]
    actor: str = Field(default="", max_length=200)


class ClaimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner: str = Field(min_length=1, max_length=200)
    actor: str = Field(default="", max_length=200)


class AdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(default="", max_length=200)


class ReverificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    verification_content_hash: str = Field(min_length=1, max_length=128)
    actor: str = Field(default="", max_length=200)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: str = Field(pattern="^(closed|rejected|deferred)$")
    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(default="", max_length=200)


def _not_found(case_id: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "case_not_found", "case_id": case_id})


@change_router.post("/assess/drift", summary="Turn a manifest divergence into a case")
async def assess_drift_route(
    body: DriftIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        baseline = SafetyManifest.from_dict(body.baseline)
        observed = SafetyManifest.from_dict(body.observed)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "manifest") from exc
    try:
        divergence = compare(baseline, observed)
    except ValueError as exc:
        raise _bad(exc, "comparison") from exc

    key = observed.machine.key
    verifications = VerificationRecord.from_ledger(register.ledger, subject=key)
    interventions = interventions_from_ledger(register.ledger, key)
    store = CaseStore(register.ledger)
    case = assess_drift(store, divergence, observed, verifications, interventions,
                        actor=_actor(body.actor, "watch"))
    return {"opened": case is not None, "case": case.to_dict() if case else None,
           "verdict": divergence.verdict}


@change_router.post("/assess/advisory", summary="Turn a fleet impact report into a case")
async def assess_advisory_route(
    body: AdvisoryIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        advisory = ComponentAdvisory.from_dict(body.advisory)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "advisory") from exc
    fleet = Fleet.from_ledger(register.ledger)
    report = assess_impact(advisory, fleet)
    store = CaseStore(register.ledger)
    case = assess_advisory(store, report, actor=_actor(body.actor, "fleet"))
    return {"opened": case is not None, "case": case.to_dict() if case else None,
           "verdict": report.verdict}


@change_router.get("/cases", summary="The Active Assurance Cases queue")
async def list_cases(
    principal: Annotated[Principal, Machine], status: str = "",
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = CaseStore(register.ledger)
    try:
        parsed = CaseStatus(status) if status else None
    except ValueError as exc:
        raise _bad(exc, "status") from exc
    cases = store.list(status=parsed)
    open_cases = [c for c in cases if c.is_open]
    return {
        "cases": [c.row() for c in cases],
        "summary": {
            "open": len(open_cases),
            "safety_relevant": sum(1 for c in open_cases if c.change_severity == "safety_relevant"),
            "awaiting_reverification": sum(
                1 for c in open_cases if c.status is CaseStatus.AWAITING_REVERIFICATION),
            "ready_to_close": sum(1 for c in open_cases if c.status is CaseStatus.READY_TO_CLOSE),
        },
    }


@change_router.get("/cases/{case_id}", summary="One case in full")
async def get_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    case = CaseStore(register.ledger).get(case_id)
    if case is None:
        raise _not_found(case_id)
    return case.to_dict()


@change_router.post("/cases/{case_id}/claim", summary="OPEN -> IN_REVIEW")
async def claim_case_route(
    case_id: str, body: ClaimIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = claim(CaseStore(register.ledger), case_id, owner=body.owner,
                    actor=_actor(body.actor, "reviewer"))
    except CaseTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/advance", summary="Move to the next required stop")
async def advance_case_route(
    case_id: str, body: AdvanceIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = advance(CaseStore(register.ledger), case_id, actor=_actor(body.actor, "reviewer"))
    except CaseTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/reverification", summary="Supply fresh verification evidence")
async def reverify_case_route(
    case_id: str, body: ReverificationIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        manifest = SafetyManifest.from_dict(body.manifest)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "manifest") from exc
    key = manifest.machine.key
    verifications = VerificationRecord.from_ledger(register.ledger, subject=key)
    interventions = interventions_from_ledger(register.ledger, key)
    try:
        case = reverify(CaseStore(register.ledger), case_id, manifest, verifications,
                        interventions, verification_content_hash=body.verification_content_hash,
                        actor=_actor(body.actor, "verification engineer"))
    except CaseTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/decision", summary="Close, reject or defer — a human decision")
async def decide_case_route(
    case_id: str, body: DecisionIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = decide(CaseStore(register.ledger), case_id, disposition=body.disposition,
                     reason=body.reason, actor=_actor(body.actor, "reviewer"))
    except CaseTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return case.to_dict()
