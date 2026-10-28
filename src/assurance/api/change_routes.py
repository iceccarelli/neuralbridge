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

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.attest_routes import EXPORT_RESPONSES, anchor_contradiction, latest_anchor
from assurance.api.declared_actor import sanitise_declared_role
from assurance.api.deps import Machine, get_register
from assurance.api.recorder_trust import reader_recorder_trust
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
    blocked_reason,
    claim,
    decide,
    resolve_decision,
    resume,
    reverify,
    waive_reverification,
)
from assurance.change.store import CASE_KINDS, CaseConflictError, CaseStore, CaseStoreError
from assurance.core.errors import AssuranceError, LedgerIntegrityError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import AnchorContradictsLedgerError
from assurance.fleet.advisory import ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.provenance import bare_provenance
from assurance.fleet.registry import Fleet
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger, manifests_from_ledger
from assurance.machinery.staleness import VerificationRecord

__all__ = ["change_router"]

change_router = APIRouter(prefix="/v1/change", tags=["change"])


def _bad(exc: Exception, what: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"error": f"invalid_{what}", "detail": str(exc)})


def _actor(name: str, role: str, principal: Principal, *, human: bool = False,
           named: bool = False) -> Actor:
    """The recorded actor, and how far it is established.

    * An **operator key** (a credential bound to an individual operator of the
      account) attributes the action to that operator: the identifier is the
      operator's name from the account store, never from the request. A different
      ``actor`` in the body is refused, so a client cannot act as someone else by
      changing a string.
    * An **account-level key** proves only the account. Its caller may *declare* a
      name, which is recorded as declared, with the key prefix. It cannot make a
      human decision (``human=True``): that needs an operator whose role is
      ``decider``. An agent, MCP client or watch holding such a key therefore
      cannot close, reject, defer, resume, resolve or waive.
    * Open mode (no account store configured) keeps declared names, and says so.

    ``attribution=authenticated_operator`` means a credential bound to a named
    operator was presented; it is not identity-proofing of a real-world person.
    ``named`` demands a name from a caller that has no operator (the human-workflow
    steps); the ``assess/*`` routes leave it off and record automation.
    """
    # Whatever role is handed in, the sealed text has the server's grammar (`;`, `=`, and
    # so `operator=`/`key=`/`attribution=`) only where this function wrote it.
    role = sanitise_declared_role(role)
    account = principal.account.id if principal.account else "open-mode"
    if principal.operator_id:
        if name and name.strip() != principal.operator_name:
            raise HTTPException(status_code=403, detail={
                "error": "actor_mismatch",
                "detail": "this key belongs to operator "
                          f"{principal.operator_name!r}; the request names {name!r}. "
                          "An action is attributed to the credential that made it."})
        if human and principal.operator_role != "decider":
            raise HTTPException(status_code=403, detail={
                "error": "decider_role_required",
                "detail": f"operator {principal.operator_name!r} has role "
                          f"{principal.operator_role!r}; a decision needs 'decider'."})
        return Actor(
            identifier=principal.operator_name,
            role=f"{role} via account {account}; operator={principal.operator_id} "
                 f"({principal.operator_role}); key={principal.key_prefix}; "
                 "attribution=authenticated_operator",
            kind="person")
    open_mode = principal.key_prefix == "open-mode"
    if human and not open_mode:
        raise HTTPException(status_code=403, detail={
            "error": "operator_required",
            "detail": "closing, rejecting, deferring, resuming, resolving a question or "
                      "waiving re-verification is a human decision. It needs a key "
                      "issued to an individual operator with the 'decider' role "
                      "(POST /v1/operators); an account-level key cannot make it."})
    if (human or named) and not name.strip():
        raise HTTPException(status_code=422, detail={
            "error": "actor_required", "detail": "name the person taking this step."})
    basis = "declared_open_mode" if open_mode else "declared_by_account_key"
    return Actor(
        identifier=name or "operator",
        role=f"{role} via account {account}; key={principal.key_prefix}; "
             f"attribution={basis}",
        kind="person" if name else "automation")


class DriftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline: dict[str, Any]
    observed: dict[str, Any]
    actor: str = Field(default="", max_length=200)


class AdvisoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisory: dict[str, Any]
    #: Opening a case from an UNSIGNED import is refused unless a named person says so.
    accept_unsigned: bool = False
    reason: str = Field(default="", max_length=500)
    actor: str = Field(default="", max_length=200)


class ClaimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner: str = Field(min_length=1, max_length=200)
    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


class AdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


class ReverificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    verification_content_hash: str = Field(min_length=1, max_length=128)
    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: str = Field(pattern="^(closed|rejected|deferred)$")
    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


class ResumeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


class ResolveDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The question exactly as the case lists it in ``human_decisions_required``.
    #: The text, not a position: another person may have answered a question
    #: since the caller last read the case, and a position would then answer the
    #: wrong one.
    decision: str = Field(min_length=1, max_length=2000)
    resolution: str = Field(min_length=1, max_length=2000)
    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


class WaiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The entry as the case lists it in ``required_reverifications``
    #: (``machine/function`` on an advisory case).
    entry: str = Field(min_length=1, max_length=400)
    reason: str = Field(min_length=1, max_length=2000)
    actor: str = Field(default="", max_length=200,
                       description="optional with an operator key (then it must match the operator); required with an account-level key on non-decision steps")


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
    if isinstance(exc, CaseConflictError):
        # Someone else recorded on this case after it was read. Not a refusal of
        # the step on its merits: re-read (GET the case) and send it again.
        return HTTPException(status_code=409, detail={
            "error": "case_conflict", "case_id": exc.case_id, "detail": str(exc)})
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
    key = observed.machine.key
    # The baseline is what this account's ledger says the machine was, not what
    # the request says: a caller who names the observed state as the baseline
    # would suppress the case, and one who names an invented state would shape
    # what the case says changed. The request's baseline is used only when the
    # ledger has none, and the response says which it was.
    sealed = _sealed_baseline(register.ledger, observed)
    source = "ledger" if sealed is not None else "request"
    used = sealed if sealed is not None else baseline
    try:
        divergence = compare(used, observed)
    except ValueError as exc:
        raise _bad(exc, "comparison") from exc


    verifications = VerificationRecord.from_ledger(
        register.ledger, subject=key, recorder_trust=reader_recorder_trust())
    interventions = interventions_from_ledger(register.ledger, key)
    store = CaseStore(register.ledger)
    try:
        case = assess_drift(store, divergence, observed, verifications, interventions,
                            actor=_actor(body.actor, "watch", principal))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return {"opened": case is not None, "case": case.to_dict() if case else None,
            "verdict": divergence.verdict,
            "baseline_source": source,
            "baseline_configuration": used.configuration_hash(),
            "request_baseline_ignored": sealed is not None
            and baseline.configuration_hash() != sealed.configuration_hash()}


def _sealed_baseline(ledger: Any, observed: SafetyManifest) -> SafetyManifest | None:
    """The newest manifest sealed for this machine in a *different* configuration.

    The same rule the watch ingest applies (compare against what the ledger last
    held), except that a manifest equal to the observed configuration is not a
    baseline for it: a watch may already have sealed what it saw, and the change
    is from the configuration before that.
    """
    observed_hash = observed.configuration_hash()
    for sealed in reversed(manifests_from_ledger(ledger, observed.machine.key)):
        if sealed.configuration_hash() != observed_hash:
            return sealed
    return None


@change_router.post("/assess/advisory", summary="Turn a fleet impact report into a case")
async def assess_advisory_route(
    body: AdvisoryIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        advisory = ComponentAdvisory.from_dict(body.advisory)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "advisory") from exc
    fleet = Fleet.from_ledger(register.ledger, recorder_trust=reader_recorder_trust())
    report = assess_impact(advisory, fleet, provenance=bare_provenance("body"))
    store = CaseStore(register.ledger)
    try:
        case = assess_advisory(store, report, actor=_actor(body.actor, "fleet", principal),
                               accept_unsigned=body.accept_unsigned, reason=body.reason)
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return {"opened": case is not None, "case": case.to_dict() if case else None,
            "verdict": report.verdict, "incomplete": report.incomplete,
            "advisory_trust": report.provenance,
            "advisory_import": report.advisory_import}


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
            actor=_actor(body.actor, "watch", principal),
            recorder_trust=reader_recorder_trust())
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
                    actor=_actor(body.actor, "reviewer", principal, named=True))
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
                       actor=_actor(body.actor, "reviewer", principal, named=True))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.post("/cases/{case_id}/reverification", summary="Supply fresh verification evidence; blocked_reason says why a case still waits")
async def reverify_case_route(
    case_id: str, body: ReverificationIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Submit fresh verification evidence for the entries a case is waiting on.

    ``200`` means the submission was accepted and recorded, **not** that it cleared
    anything. When the case is still waiting the response carries ``blocked_reason``
    (absent when nothing is outstanding): ``code`` is ``below_validated_tier`` when a
    required entry was read current on evidence under the floor, or
    ``evidence_not_current`` when coverage did not read the entry current at all;
    ``entries`` maps each outstanding entry to its recorded reason and ``message``
    says what would clear it. A decider may waive an entry
    (``waive-reverification``); a waiver is recorded as one and never reads as
    current.
    """
    try:
        manifest = SafetyManifest.from_dict(body.manifest)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "manifest") from exc
    key = manifest.machine.key
    verifications = VerificationRecord.from_ledger(
        register.ledger, subject=key, recorder_trust=reader_recorder_trust())
    interventions = interventions_from_ledger(register.ledger, key)
    try:
        case = reverify(CaseStore(register.ledger), case_id, manifest, verifications,
                        interventions, verification_content_hash=body.verification_content_hash,
                        actor=_actor(body.actor, "verification engineer", principal,
                                     named=True))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    out = case.to_dict()
    # 200 means the submission was accepted and recorded, not that it cleared
    # anything. Say why when the case is still waiting (absent when nothing is).
    reason = blocked_reason(case)
    if reason is not None:
        out["blocked_reason"] = reason
    return out


@change_router.post("/cases/{case_id}/decision", summary="Close, reject or defer — a human decision")
async def decide_case_route(
    case_id: str, body: DecisionIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        case = decide(CaseStore(register.ledger), case_id, disposition=body.disposition,
                     reason=body.reason,
                     actor=_actor(body.actor, "reviewer", principal, human=True))
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
                      actor=_actor(body.actor, "reviewer", principal, human=True))
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
                                actor=_actor(body.actor, "reviewer", principal, human=True))
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
                                    actor=_actor(body.actor, "reviewer", principal,
                                                 human=True))
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return case.to_dict()


@change_router.get("/cases/{case_id}/export",
                   summary="A verifiable evidence bundle for one case",
                   responses=EXPORT_RESPONSES)
async def export_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
    anchor: Annotated[bool, Query(
        description="embed the newest signed attestation from this account's own "
                    "attestation log as the bundle's `anchor`, so a verifier holding "
                    "the signer's public key can check the bundle is complete up to "
                    "it. Set false to export without one.")] = True,
    skeleton: Annotated[bool, Query(
        description="true to also carry `skeleton`: the position, kind, subject, time and hashes of every OTHER entry of this account's ledger (no evidence), so a verifier can see a removed entry and check completeness. Off by default because it discloses the id, kind and time of this account's other cases and incidents to whoever receives the file.")] = False,
) -> dict[str, Any]:
    """The case's ledger entries as ``assurance evidence verify`` expects them.

    Refuses (500 ``ledger_integrity``) if the account's chain does not verify,
    and says no such case (404) when the ledger holds no entry of a case kind
    under this id, so an export is never an empty bundle that reads as clean.
    ``?skeleton=true`` adds a ``skeleton`` of the account's other entries (ids,
    kinds, times and hashes; no evidence) so removed entries are visible; it is off
    by default because it names every other case and incident of the account.

    **Completeness.** Without ``skeleton`` a bundle is internally consistent but a
    removed entry of the case cannot be seen, and a verifier reports completeness as
    *not checked*. With ``skeleton`` and a signed ``anchor``, a verifier holding the
    signer's public key can show nothing was removed up to the anchor; records after
    it are covered by no signature.

    **Anchor.** ``anchor`` is the newest attestation the service *read from this
    account's own ledger* (``read_from_ledger``). No customer route creates one: the
    operator runs ``assurance attest sign`` against the hosted ledger
    (``deploy/assurance/ATTEST.md``). Until then the export carries no ``anchor`` and
    its completeness is not checked. Counter-signed heads you declared about your own
    ledger (``POST /v1/ledger/attest``) are never embedded. If the embedded
    attestation does not match this ledger the answer is 409
    ``anchor_contradicts_ledger``, a rewind signal, and nothing is exported. A damaged
    attestation log is 500 ``attestation_log_damaged``, never a silently unanchored
    export; ``?anchor=false`` is the explicit way to export without one.
    """
    signed_anchor = latest_anchor(principal) if anchor else None
    try:
        bundle = register.ledger.export(
            subject=case_id, anchor=signed_anchor, skeleton=skeleton)
    except AnchorContradictsLedgerError as exc:
        raise anchor_contradiction(exc) from exc
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
