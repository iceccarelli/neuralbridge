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
from assurance.change.model import CaseStatus, queue_summary
from assurance.change.replay import reconstruct_case
from assurance.change.service import (
    CaseNotFoundError,
    CaseTransitionError,
    UnknownInterventionError,
    advance,
    assess_advisory,
    assess_drift,
    assess_recorded_intervention,
    claim,
    decide,
    resolve_decision,
    resume,
    reverify,
    waive_reverification,
)
from assurance.change.store import CASE_KINDS, CaseStore, CaseStoreError
from assurance.core.errors import AssuranceError, LedgerIntegrityError
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


def _actor(name: str, role: str, principal: Principal) -> Actor:
    """The recorded actor: the declared person, bound to the authenticated account.

    ``identifier`` is the name the caller says acted. ``role`` carries the
    authenticated account that asserted it, taken from the principal and never
    from the request body, so the ledger shows both who the account says acted
    and which account vouched for it. An empty name (allowed only on the
    ``assess/*`` routes) is recorded as automation, not as a person.
    """
    account = principal.account.id if principal.account else "open-mode"
    return Actor(identifier=name or "operator", role=f"{role} via account {account}",
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
    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class AdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class ReverificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    verification_content_hash: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: str = Field(pattern="^(closed|rejected|deferred)$")
    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class ResumeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class ResolveDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The question exactly as the case lists it in ``human_decisions_required``.
    #: The text, not a position: another person may have answered a question
    #: since the caller last read the case, and a position would then answer the
    #: wrong one.
    decision: str = Field(min_length=1, max_length=2000)
    resolution: str = Field(min_length=1, max_length=2000)
    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class WaiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The entry as the case lists it in ``required_reverifications``
    #: (``machine/function`` on an advisory case).
    entry: str = Field(min_length=1, max_length=400)
    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(min_length=1, max_length=200, pattern=r"\S",
                       description="the named person taking this step")


class InterventionAssessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    #: An intervention already sealed in the account's ledger
    #: (``POST /v1/machinery/intervention``).
    intervention_id: str = Field(min_length=1, max_length=200)
    actor: str = Field(default="", max_length=200)


def _not_found(case_id: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"error": "case_not_found", "case_id": case_id})


def _refused(exc: AssuranceError) -> HTTPException:
    """One mapping for every refusal the case domain can raise.

    No case by that id is a 404 on every verb, the same answer ``GET`` gives;
    any other refusal of a transition is a 409 carrying the domain's own words.
    The rules live in :mod:`assurance.change.service`; this only maps them.
    """
    if isinstance(exc, CaseNotFoundError):
        return _not_found(exc.case_id)
    if isinstance(exc, LedgerIntegrityError):
        # The account's chain does not verify: nothing is shown or extended.
        return HTTPException(status_code=500, detail={
            "error": "ledger_integrity", "detail": str(exc)})
    return HTTPException(status_code=409, detail=str(exc))


#: What a case operation may refuse with. ``LedgerIntegrityError`` is the chain
#: guard in :class:`~assurance.change.store.CaseStore`.
_REFUSALS = (CaseTransitionError, CaseStoreError, LedgerIntegrityError)


def _intact(store: CaseStore) -> CaseStore:
    """``store``, after checking the chain: a read that skipped this could show a
    case as it was before someone edited its newest entry."""
    try:
        store.require_intact()
    except LedgerIntegrityError as exc:
        raise _refused(exc) from exc
    return store


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
    try:
        case = assess_drift(store, divergence, observed, verifications, interventions,
                            actor=_actor(body.actor, "watch", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
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
    try:
        case = assess_advisory(store, report, actor=_actor(body.actor, "fleet", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return {"opened": case is not None, "case": case.to_dict() if case else None,
           "verdict": report.verdict}


@change_router.post("/assess/intervention", summary="Did a recorded intervention invalidate evidence?")
async def assess_intervention_route(
    body: InterventionAssessIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The same call ``assurance change assess-intervention`` makes.

    The intervention is looked up in the caller's own ledger by id; its
    verifications and interventions come from that ledger and not from the body.
    """
    try:
        manifest = SafetyManifest.from_dict(body.manifest)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "manifest") from exc
    try:
        chosen, case = assess_recorded_intervention(
            CaseStore(register.ledger), manifest, body.intervention_id,
            actor=_actor(body.actor, "watch", principal))
    except UnknownInterventionError as exc:
        raise HTTPException(status_code=422, detail={
            "error": "unknown_intervention", "detail": str(exc)}) from exc
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return {"opened": case is not None, "case": case.to_dict() if case else None,
            "intervention_id": chosen.intervention_id}


@change_router.get("/cases", summary="The Active Assurance Cases queue")
async def list_cases(
    principal: Annotated[Principal, Machine], status: str = "",
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = _intact(CaseStore(register.ledger))
    try:
        parsed = CaseStatus(status) if status else None
    except ValueError as exc:
        raise _bad(exc, "status") from exc
    cases = store.list(status=parsed)
    return {"cases": [c.row() for c in cases], "summary": queue_summary(cases)}


@change_router.get("/cases/{case_id}", summary="One case in full")
async def get_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    case = _intact(CaseStore(register.ledger)).get(case_id)
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
                    actor=_actor(body.actor, "reviewer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/advance", summary="Move to the next required stop")
async def advance_case_route(
    case_id: str, body: AdvanceIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = advance(CaseStore(register.ledger), case_id,
                       actor=_actor(body.actor, "reviewer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
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
                        actor=_actor(body.actor, "verification engineer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/decision", summary="Close, reject or defer — a human decision")
async def decide_case_route(
    case_id: str, body: DecisionIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = decide(CaseStore(register.ledger), case_id, disposition=body.disposition,
                     reason=body.reason, actor=_actor(body.actor, "reviewer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/resume", summary="DEFERRED -> IN_REVIEW — a human decision")
async def resume_case_route(
    case_id: str, body: ResumeIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = resume(CaseStore(register.ledger), case_id, reason=body.reason,
                      actor=_actor(body.actor, "reviewer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/resolve-decision",
                    summary="Answer one of the case's open human questions — a human decision")
async def resolve_decision_route(
    case_id: str, body: ResolveDecisionIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = resolve_decision(CaseStore(register.ledger), case_id, decision=body.decision,
                                resolution=body.resolution,
                                actor=_actor(body.actor, "reviewer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/waive-reverification",
                    summary="Close one re-verification entry WITHOUT evidence — a human decision")
async def waive_reverification_route(
    case_id: str, body: WaiveIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The only way to close an entry nothing verified. It reads ``waived``,
    never ``current``, in the case and in every export."""
    try:
        case = waive_reverification(CaseStore(register.ledger), case_id, entry=body.entry,
                                    reason=body.reason,
                                    actor=_actor(body.actor, "reviewer", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.get("/cases/{case_id}/export",
                   summary="A verifiable evidence bundle for one case")
async def export_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The case's ledger entries as ``assurance evidence verify`` expects them.

    Refuses (500 ``ledger_integrity``) if the account's chain does not verify,
    and says no such case (404) when the ledger holds no entry of a case kind
    under this id, so an export is never an empty bundle that reads as clean.
    """
    try:
        bundle = register.ledger.export(subject=case_id)
    except LedgerIntegrityError as exc:
        raise _refused(exc) from exc
    if not any(e["kind"] in CASE_KINDS for e in bundle["entries"]):
        raise _not_found(case_id)
    return bundle


@change_router.get("/cases/{case_id}/replay",
                   summary="Rebuild the case from the ledger alone and check every step")
async def replay_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    replay = reconstruct_case(register.ledger, case_id)
    if replay.entries == 0:
        raise _not_found(case_id)
    return replay.to_dict()
