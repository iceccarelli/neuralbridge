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

import sqlite3
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.attest_routes import EXPORT_RESPONSES, anchor_contradiction, latest_anchor
from assurance.api.declared_actor import sanitise_declared_role
from assurance.api.deps import Machine, get_register
from assurance.api.fleet_routes import SignedFeedIn, evaluate_signed_feed
from assurance.api.intel_routes import _open_store, _read_failed
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
from assurance.watch.config import INTEL_SOURCES
from assurance.watch.intel_source import impact_and_candidate_from_store
from assurance.watch.open_case import (
    NOT_ESTABLISHED as INTEL_CASE_NOT_ESTABLISHED,
)
from assurance.watch.open_case import (
    OpenCaseRefusedError,
    open_case_from_report,
    role_problem,
)

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
def assess_drift_route(
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
def assess_advisory_route(
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
        # Overriding the refusal to act on an unsigned import is a human decision, like closing
        # a case: an account-level key (which anyone or any agent can hold) cannot make it
        # with a name it typed; it takes an operator key with the decider role.
        case = assess_advisory(
            store, report,
            actor=_actor(body.actor, "fleet", principal, human=body.accept_unsigned),
            accept_unsigned=body.accept_unsigned, reason=body.reason)
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return {"opened": case is not None, "case": case.to_dict() if case else None,
            "verdict": report.verdict, "incomplete": report.incomplete,
            "clear_is_complete": report.clear_is_complete,
            "advisory_trust": report.provenance,
            "advisory_import": report.advisory_import}


class SignedAssessIn(SignedFeedIn):
    """A signed supplier feed, and the one advisory in it to open a case from."""

    advisory_id: str = Field(min_length=1, max_length=200)
    accept_unsigned: bool = False
    reason: str = Field(default="", max_length=500)
    actor: str = Field(default="", max_length=200)


@change_router.post("/assess/advisory/signed",
                    summary="Turn one advisory of a signed supplier feed into a case, with its trust")
def assess_advisory_signed_route(
    body: SignedAssessIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Same case as ``/assess/advisory``, but the advisory arrives with its signature.

    The feed is judged by the same function as ``/v1/fleet/advisory/signed``, under the
    account's own pinned keys. Only an advisory whose policy is satisfied by a *pinned*
    key and valid signatures opens without a named person, and the case records that
    basis. Anything else (unknown key, bad signature, unreadable, a translation) is
    handled exactly as the bare route handles it: a named person is required. Nothing
    here closes a case; closing stays a named decider's act.
    """
    records, trust, error = evaluate_signed_feed(body, principal, register)
    if error or trust is None:
        raise _bad(AssuranceError(f"the feed cannot be read: {error}"), "feed")
    first = {r.advisory_id: r for r in records if not r.is_withdrawal}
    stands = any(a["advisory_id"] == body.advisory_id for a in trust.advisories)
    if body.advisory_id not in first or not stands:
        raise HTTPException(status_code=404, detail={
            "error": "advisory_not_in_feed",
            "detail": f"advisory {body.advisory_id!r} is not a standing advisory in this feed."})
    try:
        advisory = first[body.advisory_id].component()
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "advisory") from exc
    provenance = trust.provenance_for(body.advisory_id)
    if provenance.get("trust_basis") != "pinned_key_policy":
        # Only a pinned key vouches for an advisory without a person. Any other basis
        # (a manual override, nothing) is handled as an unauthenticated input.
        provenance = {**provenance, "automated_consequences_permitted": False,
                      "inspect_only": True}
    fleet = Fleet.from_ledger(register.ledger, recorder_trust=reader_recorder_trust())
    report = assess_impact(advisory, fleet, provenance=provenance)
    store = CaseStore(register.ledger)
    try:
        case = assess_advisory(
            store, report,
            actor=_actor(body.actor, "fleet", principal, human=body.accept_unsigned),
            accept_unsigned=body.accept_unsigned, reason=body.reason)
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    return {"opened": case is not None, "case": case.to_dict() if case else None,
            "verdict": report.verdict, "incomplete": report.incomplete,
            "advisory_trust": report.provenance,
            "advisory_import": report.advisory_import,
            "feed_trust": trust.to_dict()}


class IntelAssessIn(BaseModel):
    """A named person asks to open a case from one public-intel candidate."""

    model_config = ConfigDict(extra="forbid")

    advisory_id: str = Field(min_length=1, max_length=200)
    actor: str = Field(default="", max_length=200)
    role: str = Field(min_length=1, max_length=200)
    #: The override for a CSAF-derived (unsigned import) candidate; needs a reason too.
    accept_unsigned: bool = False
    reason: str = Field(default="", max_length=500)
    #: Which recorded candidate sources to look in (never KEV/EPSS: they carry no versions).
    sources: list[Literal["nvd", "csaf"]] = Field(default_factory=lambda: ["nvd", "csaf"],
                                                  min_length=1, max_length=2)


@change_router.post(
    "/assess/advisory/intel",
    summary="A named person opens a case from a public-intel (unauthenticated) finding")
def assess_advisory_intel_route(
    body: IntelAssessIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The hosted twin of ``assurance watch open-case``: same domain function, same rules.

    Reads the operator's intel store read-only (503 ``no_intel_store_configured`` /
    ``intel_store_unreadable``), re-derives the candidate for the CALLER'S fleet with the
    watch's own matcher, and opens the case through
    :func:`~assurance.change.service.assess_advisory` as an unauthenticated public-source,
    inspect-only advisory: a named person is required, a CSAF-derived candidate needs
    ``accept_unsigned`` with a reason and an operator key with the ``decider`` role, an
    existing open case is returned untouched (never re-attributed), a settled case is never
    reopened. Nothing is closed, decided, waived or advanced here, and no MCP tool calls it.
    """
    problem = role_problem(body.role)
    if problem:
        raise HTTPException(status_code=422, detail={"error": "invalid_role",
                                                     "detail": problem + ". Nothing was opened."})
    store = _open_store()
    fleet = Fleet.from_ledger(register.ledger, recorder_trust=reader_recorder_trust())
    source_ids = tuple(INTEL_SOURCES[s] for s in body.sources)
    try:
        report, candidate = impact_and_candidate_from_store(
            store, body.advisory_id, fleet, source_ids)
    except AssuranceError as exc:
        if str(exc).startswith("no intel candidate"):
            raise HTTPException(status_code=404, detail={
                "error": "advisory_not_found",
                "detail": f"{body.advisory_id!r} is not an advisory candidate in the recorded "
                          "intel observations. Nothing was opened."}) from exc
        raise _read_failed(exc) from exc
    except (sqlite3.Error, OSError) as exc:
        raise _read_failed(exc) from exc
    if report.machines_in_fleet == 0:
        raise HTTPException(status_code=409, detail={
            "error": "nothing_assessed",
            "detail": "this account's fleet has no machine with a sealed manifest, so nothing "
                      "was assessed and nothing was cleared. Nothing was opened."})
    try:
        result = open_case_from_report(
            register.ledger, report,
            _actor(body.actor, "fleet", principal, human=body.accept_unsigned),
            accept_unsigned=body.accept_unsigned, reason=body.reason)
    except OpenCaseRefusedError as exc:
        raise HTTPException(status_code=409, detail={
            "error": "open_case_refused", "detail": str(exc)}) from exc
    except _REFUSALS as exc:
        raise _refused(exc) from exc
    case = CaseStore(register.ledger).get(result.case_id)
    return {"opened": result.outcome == "opened", "outcome": result.outcome,
            "case": case.to_dict() if case else None,
            "verdict": report.verdict, "incomplete": report.incomplete,
            "clear_is_complete": report.clear_is_complete,
            "advisory_trust": report.provenance,
            "advisory_import": report.advisory_import,
            "intel": {"source": candidate.source, "citation": candidate.citation,
                      "notes": list(candidate.notes),
                      "not_representable": list(candidate.not_representable)},
            "not_established": list(INTEL_CASE_NOT_ESTABLISHED)}


@change_router.post("/assess/intervention", summary="Did a recorded intervention invalidate evidence?")
def assess_intervention_route(
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
def list_cases(
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
def get_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    case = _intact(CaseStore(register.ledger)).get(case_id)
    if case is None:
        raise _not_found(case_id)
    return case.to_dict()


@change_router.post("/cases/{case_id}/claim", summary="OPEN -> IN_REVIEW")
def claim_case_route(
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
def advance_case_route(
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
def reverify_case_route(
    case_id: str, body: ReverificationIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Submit fresh verification evidence for the entries a case is waiting on.

    ``200`` means the submission was accepted and recorded, **not** that it cleared
    anything. When the case is still waiting the response carries ``blocked_reason``
    (absent when nothing is outstanding): ``code`` is ``below_validated_tier`` when a
    required entry was read current on evidence under the floor (no accepted recorder
    attestation), ``below_validated_unit_binding`` when the evidence is held down by its
    unit key (sealed for another key or none: re-seal it under the exact key, an attestation
    is not what is missing), or ``evidence_not_current`` when coverage did not read the
    entry current at all;
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
def decide_case_route(
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
def resume_case_route(
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
def resolve_decision_route(
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
def waive_reverification_route(
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
def export_case(
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
def replay_case(
    case_id: str, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    replay = reconstruct_case(register.ledger, case_id)
    if replay.entries == 0:
        raise _not_found(case_id)
    return replay.to_dict()
