"""Turn an existing engine's output into a case, and move a case forward.

Every ``assess_*`` function here takes the exact object an existing engine
already produces — a :class:`~assurance.machinery.divergence.Divergence`, an
:class:`~assurance.fleet.impact.ImpactReport`, an
:class:`~assurance.machinery.intervention.Intervention` joined against
:class:`~assurance.machinery.staleness.CoverageReport` — and turns it into a
:class:`~assurance.change.model.ChangeAssuranceCase`. None of them re-derive a
fact an engine already computed; they read a verdict and write down what the
existing product's own doctrine says that verdict means for a human's queue.

The rest of the module moves an already-open case through its lifecycle.
Nothing here invents ``compliant``, ``safe`` or ``certified`` — the strongest
thing any function in this file says is ``ready_to_close``, and only
:func:`decide` can turn that into ``closed``, and only with a named actor and
a reason that actor wrote.
"""

from __future__ import annotations

from dataclasses import replace

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of, format_utc, utc_now
from assurance.fleet.impact import Exposure, ImpactReport
from assurance.machinery.divergence import Divergence, Severity
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.staleness import (
    Coverage,
    VerificationRecord,
    assess_coverage,
)

from .model import CaseStatus, ChangeAssuranceCase, TriggerType
from .store import CaseStore

__all__ = [
    "CaseTransitionError",
    "assess_advisory",
    "assess_drift",
    "assess_intervention",
    "claim",
    "decide",
    "advance",
    "reverify",
]


class CaseTransitionError(AssuranceError):
    """A case was asked to move somewhere its own state does not permit."""


def _case_id(trigger_type: TriggerType, trigger_id: str) -> str:
    """Deterministic, so the same trigger folds into the same case.

    A distinct ``trigger_id`` — a different observed configuration hash, a
    different advisory id, a different intervention id — is a distinct change
    event and gets its own case. The same trigger seen again is not.
    """
    return "case-" + content_hash_of({"trigger_type": trigger_type.value,
                                      "trigger_id": trigger_id})[:16]


def _open_or_update(
    store: CaseStore, new: ChangeAssuranceCase, *, actor: Actor, detail: str,
) -> ChangeAssuranceCase:
    """One persistent case per trigger, never a duplicate per observation.

    A settled case (closed, rejected or deferred) seeing the exact same
    trigger again is left alone — the watch is not wrong to look again, and
    this is not wrong to say nothing changed about the decision already made.
    """
    existing = store.get(new.case_id)
    if existing is None:
        now = format_utc(utc_now())
        opened = replace(new, opened_at=now, created_at=now, updated_at=now)
        return store.open(opened, actor=actor, detail=detail)
    if existing.status.is_settled:
        return existing
    merged = replace(
        new,
        status=existing.status, owner=existing.owner, reviewer=existing.reviewer,
        opened_at=existing.opened_at, created_at=existing.created_at,
        review_started_at=existing.review_started_at,
        reverification_requested_at=existing.reverification_requested_at,
        reverified_at=existing.reverified_at,
        history=existing.history,
    )
    return store.update(merged, actor=actor, detail=detail)


# ---------------------------------------------------------------------------
# Trigger A — machine drift
# ---------------------------------------------------------------------------

def assess_drift(
    store: CaseStore,
    divergence: Divergence,
    manifest: SafetyManifest,
    verifications: list[VerificationRecord],
    interventions: list[Intervention],
    *,
    actor: Actor,
) -> ChangeAssuranceCase | None:
    """A watch (or a direct ``compare()``) found a configuration change.

    Opens a case only when :attr:`Divergence.verdict` is
    ``safety_relevant_drift`` — a relabelling or an administrative change is
    not a change this product asks a human to act on. Current evidence state
    comes from :func:`assess_coverage` over the *observed* manifest, joined
    against whatever interventions are on record; when a safety-relevant item
    changed with **no** intervention on record for it, that absence is itself
    the finding this case leads with, because Annex III 1.1.9 is exactly the
    duty an undocumented change violates.
    """
    if divergence.verdict != "safety_relevant_drift":
        return None

    coverage = assess_coverage(manifest, verifications, interventions)
    affected = divergence.affected_functions
    evidence_current = {f.function_id: f.coverage.value
                        for f in coverage.functions if f.function_id in affected}

    required_actions: list[str] = []
    required_reverifications: list[str] = []
    invalidation_reason = ""
    for fid in affected:
        fc = next((f for f in coverage.functions if f.function_id == fid), None)
        if fc is None:
            continue
        if fc.coverage is Coverage.STALE:
            invalidation_reason = invalidation_reason or fc.detail
            required_actions.append(
                f"Re-run {', '.join(fc.checks) or 'the declared checks'} "
                f"for {fid} ({fc.description}); last valid evidence "
                f"{fc.last_verified_hash[:12] or 'none'} was invalidated by "
                f"{fc.invalidated_by or 'this change'}.")
            required_reverifications.append(fid)
        elif fc.coverage in (Coverage.CURRENT,):
            required_actions.append(
                f"File an Annex III 1.1.9 intervention record for the change to "
                f"{divergence.machine_key}, then re-run coverage for {fid} — "
                "a safety-relevant configuration change was observed with no "
                "intervention record naming it, so evidence still reads "
                "'current' for a reason that will not survive an audit.")
            required_reverifications.append(fid)
        else:
            required_actions.append(
                f"Establish verification evidence for {fid} ({fc.coverage.value}): "
                f"{fc.detail}")
            required_reverifications.append(fid)

    case = ChangeAssuranceCase(
        case_id=_case_id(TriggerType.MACHINE_DRIFT, divergence.observed_configuration),
        trigger_type=TriggerType.MACHINE_DRIFT,
        trigger_id=divergence.observed_configuration,
        status=CaseStatus.OPEN,
        machines=(divergence.machine_key,),
        sites=(manifest.machine.site,) if manifest.machine.site else (),
        changed_items=tuple(c.to_dict() for c in divergence.safety_relevant),
        change_severity=Severity.SAFETY_RELEVANT.value,
        affected_functions=affected,
        before_hash=divergence.baseline_configuration,
        after_hash=divergence.observed_configuration,
        evidence_before={},
        evidence_current=evidence_current,
        invalidation_reason=invalidation_reason,
        required_actions=tuple(dict.fromkeys(required_actions)),
        required_reverifications=tuple(dict.fromkeys(required_reverifications)),
        linked_evidence=(
            {"relation": "concerns", "content_hash": divergence.baseline_hash,
             "note": "baseline manifest"},
            {"relation": "derived_from", "content_hash": divergence.observed_hash,
             "note": "observed manifest"},
        ),
        checks_skipped=divergence.checks_skipped + coverage.checks_skipped,
        confidence="high" if divergence.tier.may_claim_physical_behaviour else "medium",
        provenance={
            "changed_items": "assurance.machinery.divergence.compare",
            "evidence_current": "assurance.machinery.staleness.assess_coverage",
        },
    )
    return _open_or_update(
        store, case, actor=actor,
        detail=f"drift on {divergence.machine_key}: "
              f"{len(divergence.safety_relevant)} safety-relevant change(s)")


# ---------------------------------------------------------------------------
# Trigger B — supplier advisory
# ---------------------------------------------------------------------------

def assess_advisory(store: CaseStore, impact: ImpactReport, *, actor: Actor) -> ChangeAssuranceCase | None:
    """A supplier advisory now touches this fleet.

    One case per advisory, naming every machine :func:`assess_impact` found —
    not one case per machine, because the decision this drives ("does this
    advisory's remedy apply here") is the same decision across every exposed
    machine, and forty copies of it would not be forty findings.

    Opens a case only when the report is not ``clear``: an advisory that
    matches nothing in the fleet is not a change to anyone's evidence.
    """
    if impact.verdict == "clear":
        return None

    def _row(e: Exposure) -> dict[str, object]:
        return {
            "item_id": f"{e.machine_key}/{e.item_id}",
            "detail": f"{e.machine_key} ({e.site or 'unknown site'}): {e.detail}",
            "confidence": e.confidence,
            "functions": [f.function_id for f in e.functions],
        }

    affected: list[str] = []
    evidence_before: dict[str, str] = {}
    for exposure in impact.exposures:
        for f in exposure.functions:
            if f.function_id not in affected:
                affected.append(f.function_id)
            evidence_before[f.function_id] = f.coverage_before.value

    human_decisions: list[str] = []
    required_actions: list[str] = []
    for exposure in impact.contradictory:
        human_decisions.append(
            f"{exposure.machine_key}/{exposure.item_id}: label and artefact hash "
            f"disagree with the supplier's own published figures — neither "
            "affected nor clear. A human has to look.")
    for exposure in impact.needing_a_human:
        if exposure not in impact.contradictory:
            human_decisions.append(
                f"{exposure.machine_key}/{exposure.item_id}: matched by "
                f"{exposure.confidence} confidence only ({exposure.basis.value}).")
    for exposure in impact.exposures:
        for f in exposure.newly_in_question:
            required_actions.append(
                f"Re-verify {f.function_id} on {exposure.machine_key} "
                f"per the supplier's remedy: nothing declared beyond the "
                "advisory itself.")

    case = ChangeAssuranceCase(
        case_id=_case_id(TriggerType.SUPPLIER_ADVISORY, impact.advisory_id),
        trigger_type=TriggerType.SUPPLIER_ADVISORY,
        trigger_id=impact.advisory_id,
        status=CaseStatus.OPEN,
        machines=impact.machines_affected,
        sites=tuple(dict.fromkeys(e.site for e in impact.exposures if e.site)),
        changed_items=tuple(_row(e) for e in impact.exposures),
        change_severity="safety_relevant",
        affected_functions=tuple(affected),
        evidence_before=evidence_before,
        evidence_current=dict(evidence_before),
        required_actions=tuple(dict.fromkeys(required_actions)),
        required_reverifications=tuple(dict.fromkeys(
            f.function_id for e in impact.exposures for f in e.newly_in_question)),
        human_decisions_required=tuple(dict.fromkeys(human_decisions)),
        linked_evidence=({"relation": "concerns", "content_hash": impact.advisory_hash,
                          "note": f"advisory {impact.advisory_id} from {impact.issued_by}"},),
        checks_skipped=impact.checks_skipped,
        confidence="high" if impact.confirmed else "medium",
        provenance={"changed_items": "assurance.fleet.impact.assess_impact"},
    )
    return _open_or_update(
        store, case, actor=actor,
        detail=f"advisory {impact.advisory_id}: {len(impact.machines_affected)} "
              f"machine(s) affected")


# ---------------------------------------------------------------------------
# Trigger C — intervention
# ---------------------------------------------------------------------------

def assess_intervention(
    store: CaseStore,
    intervention: Intervention,
    manifest: SafetyManifest,
    verifications: list[VerificationRecord],
    interventions: list[Intervention],
    *,
    actor: Actor,
) -> ChangeAssuranceCase | None:
    """A recorded intervention, joined against coverage: did it invalidate anything?

    Opens a case only for the functions this specific intervention broke —
    :func:`assess_coverage` already computed which function each intervention
    invalidates; this reads that join rather than re-deriving it, and ignores
    every function this intervention did not touch.
    """
    coverage = assess_coverage(manifest, verifications, interventions)
    mine = [f for f in coverage.functions
           if f.coverage is Coverage.STALE and f.invalidated_by == intervention.intervention_id]
    if not mine:
        return None

    required_actions = [
        f"Re-run {', '.join(f.checks) or 'the declared checks'} for {f.function_id} "
        f"({f.description}); {f.detail}"
        for f in mine
    ]
    case = ChangeAssuranceCase(
        case_id=_case_id(TriggerType.INTERVENTION, intervention.intervention_id),
        trigger_type=TriggerType.INTERVENTION,
        trigger_id=intervention.intervention_id,
        status=CaseStatus.OPEN,
        machines=(intervention.machine_key,),
        sites=(manifest.machine.site,) if manifest.machine.site else (),
        changed_items=({
            "item_id": intervention.item_id, "kind": intervention.kind.value,
            "detail": f"{intervention.kind.value} on {intervention.item_id}: "
                     f"{intervention.reason}",
        },),
        change_severity="safety_relevant",
        affected_functions=tuple(f.function_id for f in mine),
        evidence_before={f.function_id: "current" for f in mine},
        evidence_current={f.function_id: f.coverage.value for f in mine},
        invalidation_reason=mine[0].detail,
        required_actions=tuple(dict.fromkeys(required_actions)),
        required_reverifications=tuple(f.function_id for f in mine),
        linked_evidence=({"relation": "concerns", "content_hash": intervention.to_hash,
                          "note": f"intervention {intervention.intervention_id}"},)
        if intervention.to_hash else (),
        checks_skipped=coverage.checks_skipped,
        confidence="high",
        provenance={"changed_items": "assurance.machinery.intervention",
                   "evidence_current": "assurance.machinery.staleness.assess_coverage"},
    )
    return _open_or_update(
        store, case, actor=actor,
        detail=f"intervention {intervention.intervention_id} invalidated "
              f"{len(mine)} function(s)")


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def claim(store: CaseStore, case_id: str, *, owner: str, actor: Actor) -> ChangeAssuranceCase:
    """OPEN -> IN_REVIEW. A named person is now responsible for this case."""
    case = _require(store, case_id)
    if case.status is not CaseStatus.OPEN:
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}, not open. claim() is only valid "
            "from open.")
    now = format_utc(utc_now())
    updated = replace(case, status=CaseStatus.IN_REVIEW, owner=owner,
                      review_started_at=now)
    return store.transition(updated, actor=actor, detail=f"claimed by {owner}")


def advance(store: CaseStore, case_id: str, *, actor: Actor) -> ChangeAssuranceCase:
    """Move a case to the next stop its own required work says it needs.

    IN_REVIEW moves to AWAITING_ACTION when actions are outstanding, else
    AWAITING_REVERIFICATION when only re-verification is outstanding, else
    READY_TO_CLOSE. AWAITING_ACTION moves on the same rule once its actions
    are confirmed done (the caller's job — this never marks an action done
    itself, since only the reviewer knows whether it actually happened).
    """
    case = _require(store, case_id)
    if case.status not in (CaseStatus.IN_REVIEW, CaseStatus.AWAITING_ACTION):
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}. advance() is only valid from "
            "in_review or awaiting_action.")
    if case.status is CaseStatus.IN_REVIEW and case.required_actions:
        nxt = CaseStatus.AWAITING_ACTION
    elif case.required_reverifications:
        nxt = CaseStatus.AWAITING_REVERIFICATION
    else:
        nxt = CaseStatus.READY_TO_CLOSE
    if nxt is CaseStatus.AWAITING_REVERIFICATION:
        updated = replace(case, status=nxt, reverification_requested_at=format_utc(utc_now()))
    else:
        updated = replace(case, status=nxt)
    return store.transition(updated, actor=actor, detail=f"advanced to {nxt.value}")


def reverify(
    store: CaseStore, case_id: str,
    manifest: SafetyManifest, verifications: list[VerificationRecord],
    interventions: list[Intervention],
    *, verification_content_hash: str, actor: Actor,
) -> ChangeAssuranceCase:
    """Re-run coverage with a fresh verification bundle on record, and see.

    This never marks a function covered by assertion — it calls
    :func:`assess_coverage` again with ``verifications`` that must already
    include the new bundle, and reads what that engine says now.
    """
    case = _require(store, case_id)
    if case.status is not CaseStatus.AWAITING_REVERIFICATION:
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}. reverify() is only valid from "
            "awaiting_reverification.")
    coverage = assess_coverage(manifest, verifications, interventions)
    still_required = []
    evidence_current = dict(case.evidence_current)
    for fid in case.required_reverifications:
        fc = next((f for f in coverage.functions if f.function_id == fid), None)
        if fc is None:
            continue
        evidence_current[fid] = fc.coverage.value
        if fc.coverage is not Coverage.CURRENT:
            still_required.append(fid)

    nxt = CaseStatus.AWAITING_REVERIFICATION if still_required else CaseStatus.READY_TO_CLOSE
    linked = (*case.linked_evidence,
             {"relation": "supports", "content_hash": verification_content_hash,
              "note": "re-verification evidence"})
    updated = replace(
        case, status=nxt, evidence_current=evidence_current,
        required_reverifications=tuple(still_required),
        required_actions=() if not still_required else case.required_actions,
        reverified_at=format_utc(utc_now()), linked_evidence=linked,
    )
    return store.reverify(
        updated, actor=actor,
        detail=f"re-verified against {verification_content_hash[:12]}; "
              f"{len(still_required)} function(s) still not current")


def decide(
    store: CaseStore, case_id: str, *, disposition: str, reason: str, actor: Actor,
) -> ChangeAssuranceCase:
    """The one human decision this whole product exists to lead up to.

    ``closed`` is only accepted from ``READY_TO_CLOSE`` — this function will
    not close a case that still has an outstanding action or re-verification,
    no matter who asks. ``rejected`` and ``deferred`` are accepted from any
    open status, because a human is always allowed to say "this is not a real
    problem" or "not now" without the deterministic engines' agreement.
    """
    if disposition not in ("closed", "rejected", "deferred"):
        raise CaseTransitionError(
            f"disposition must be closed, rejected or deferred, not {disposition!r}.")
    if not reason.strip():
        raise CaseTransitionError(
            "a decision needs a reason. This is the sentence a reviewer reads "
            "when they ask why a case ended the way it did.")
    case = _require(store, case_id)
    if case.status.is_settled:
        raise CaseTransitionError(f"{case_id} is already {case.status.value}.")
    if disposition == "closed" and case.status is not CaseStatus.READY_TO_CLOSE:
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}, not ready_to_close. This system "
            "does not close a case with outstanding actions or re-verifications, "
            "and it never infers 'safe' or 'compliant' from anything short of that.")

    now = format_utc(utc_now())
    status = {"closed": CaseStatus.CLOSED, "rejected": CaseStatus.REJECTED,
             "deferred": CaseStatus.DEFERRED}[disposition]
    updated = replace(
        case, status=status, decision=disposition, decision_reason=reason,
        decision_by=actor.identifier,
        closed_at=now if disposition == "closed" else case.closed_at,
    )
    return store.decide(updated, actor=actor, detail=f"{disposition}: {reason}")


def _require(store: CaseStore, case_id: str) -> ChangeAssuranceCase:
    case = store.get(case_id)
    if case is None:
        raise CaseTransitionError(f"no case {case_id!r}.")
    return case
