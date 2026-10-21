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
:func:`decide` can turn that into ``closed``, and only with a named *person*
and a reason that person wrote. Detecting and reporting may be automated;
deciding may not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of, format_utc, utc_now
from assurance.fleet.impact import Exposure, ImpactReport
from assurance.machinery.divergence import Divergence, Severity
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import MANIFEST_KIND
from assurance.machinery.staleness import (
    Coverage,
    VerificationRecord,
    assess_coverage,
)

from .model import CaseStatus, ChangeAssuranceCase, TriggerType
from .store import CaseStore

__all__ = [
    "CaseTransitionError",
    "advance",
    "assess_advisory",
    "assess_drift",
    "assess_intervention",
    "case_id_for",
    "claim",
    "decide",
    "note_advisory_withdrawn",
    "resolve_decision",
    "resume",
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


def case_id_for(trigger_type: TriggerType, trigger_id: str) -> str:
    """The id a trigger's case has (or would have), without building the case."""
    return _case_id(trigger_type, trigger_id)


def _require_human(actor: Actor, what: str) -> None:
    """Only a named person may make a decision on a case.

    ``Actor.kind`` is ``person | service | automation``. A watch runs as
    ``automation``; so does anything an HTTP or CLI caller did not put a name
    to. None of those can close, reject, defer, resume or resolve — those are
    the human decisions the whole workflow exists to lead up to. This refuses
    the *kind* of actor, and it is only as strong as the layer that sets
    ``kind``: a hosted API that accepts a self-asserted actor string cannot
    prove the string is a person (see CHANGE.md).
    """
    if actor.kind.strip().lower() != "person" or not actor.identifier.strip():
        raise CaseTransitionError(
            f"{what} is a human decision and needs a named person. Actor "
            f"{actor.identifier!r} is kind {actor.kind!r}; an automated, service "
            "or anonymous actor can detect and report, but it cannot decide.")


# ---------------------------------------------------------------------------
# Folding a repeat observation into the case that already exists
# ---------------------------------------------------------------------------

def _content(case: ChangeAssuranceCase) -> dict[str, object]:
    """A case minus the bookkeeping a repeat observation always changes."""
    d = case.to_dict()
    d.pop("updated_at", None)
    d.pop("history", None)
    return d


def _key(item: Mapping[str, object]) -> object:
    return item.get("item_id") or item.get("detail") or repr(sorted(item.items()))


def _union(a: Sequence[str], b: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys([*a, *b]))


def _links_union(
    existing: Sequence[dict[str, str]], new: Sequence[dict[str, str]],
) -> tuple[dict[str, str], ...]:
    """Existing links first. A new link is added only when no existing link has
    the same relation and note, so re-observing the same drift with a
    re-collected manifest does not pile up near-identical links."""
    seen = {(r.get("relation"), r.get("note")) for r in existing if r.get("note")}
    out = list(existing)
    for r in new:
        if r.get("note") and (r.get("relation"), r.get("note")) in seen:
            continue
        if r not in out:
            out.append(r)
    return tuple(out)


def _carry_workflow(existing: ChangeAssuranceCase, new: ChangeAssuranceCase,
                    ) -> ChangeAssuranceCase:
    """``new`` with everything that is the human workflow taken from ``existing``."""
    return replace(
        new,
        status=existing.status, owner=existing.owner, reviewer=existing.reviewer,
        opened_at=existing.opened_at, created_at=existing.created_at,
        review_started_at=existing.review_started_at,
        reverification_requested_at=existing.reverification_requested_at,
        reverified_at=existing.reverified_at, closed_at=existing.closed_at,
        decision=existing.decision, decision_reason=existing.decision_reason,
        decision_by=existing.decision_by,
        resolved_decisions=existing.resolved_decisions,
        prior_closures=existing.prior_closures,
        history=existing.history, updated_at=existing.updated_at,
    )


def _merge(
    existing: ChangeAssuranceCase, new: ChangeAssuranceCase,
    actions_by_fid: Mapping[str, Sequence[str]],
) -> ChangeAssuranceCase:
    """Fold a repeat observation of an open trigger into its case.

    Before any work has started — ``OPEN`` or ``IN_REVIEW`` with nothing yet
    re-verified — the freshest reading of the engines simply replaces the facts
    and the work list, because there is no progress to protect. Once work is
    under way the case is **additive only**: new machines, new functions and
    new questions are added; nothing already recorded is rewritten, and a
    function the case already tracks never has its work list re-inflated by a
    later look. If an addition makes ``READY_TO_CLOSE`` untrue, the case steps
    back to the stop that has work.
    """
    resolved = {r.get("decision") for r in existing.resolved_decisions}
    fresh_decisions = tuple(d for d in new.human_decisions_required if d not in resolved)
    base = _carry_workflow(existing, new)

    pre_work = existing.status in (CaseStatus.OPEN, CaseStatus.IN_REVIEW) \
        and not existing.reverified_at
    if pre_work:
        # Links the case earned itself (a prior closure it follows) survive.
        kept = tuple(r for r in existing.linked_evidence
                     if r.get("note", "").startswith("prior closure by"))
        return replace(base, human_decisions_required=fresh_decisions,
                       linked_evidence=_links_union(new.linked_evidence, kept))

    new_fids = [f for f in new.affected_functions if f not in existing.affected_functions]
    items = list(existing.changed_items)
    known = {_key(i) for i in items}
    for i in new.changed_items:
        if _key(i) not in known:
            items.append(i)
            known.add(_key(i))
    # A machine the case did not name before is new work even when its function
    # ids coincide with ones already tracked: function ids are per-machine
    # namespaces, so SF-01 on machine B has not been re-verified because SF-01
    # on machine A was.
    new_machines = [m for m in new.machines if m not in existing.machines]
    fids_from_new_machines = [
        f for i in new.changed_items
        if any(str(i.get("item_id", "")).startswith(m + "/") for m in new_machines)
        for f in i.get("functions", ())]
    work_fids = list(dict.fromkeys([*new_fids, *fids_from_new_machines]))
    added_actions = [
        a for f in work_fids for a in actions_by_fid.get(f, ())
        if f in new_fids or any(m in a for m in new_machines)]
    added_reverifs = [f for f in work_fids if f in new.required_reverifications]
    decisions = _union(existing.human_decisions_required, fresh_decisions)
    reverifs = _union(existing.required_reverifications, added_reverifs)

    status = existing.status
    requested = existing.reverification_requested_at
    if status is CaseStatus.READY_TO_CLOSE:
        if reverifs:
            status, requested = CaseStatus.AWAITING_REVERIFICATION, format_utc(utc_now())
        elif decisions:
            status = CaseStatus.AWAITING_ACTION

    return replace(
        existing,
        status=status, reverification_requested_at=requested,
        machines=_union(existing.machines, new.machines),
        sites=_union(existing.sites, new.sites),
        changed_items=tuple(items),
        affected_functions=_union(existing.affected_functions, new.affected_functions),
        evidence_before={**{f: new.evidence_before[f] for f in new_fids
                            if f in new.evidence_before}, **existing.evidence_before},
        evidence_current={**{f: new.evidence_current[f] for f in new_fids
                             if f in new.evidence_current}, **existing.evidence_current},
        required_actions=_union(existing.required_actions, added_actions),
        required_reverifications=reverifs,
        human_decisions_required=decisions,
        linked_evidence=_links_union(existing.linked_evidence, new.linked_evidence),
        checks_skipped=_union(existing.checks_skipped, new.checks_skipped),
    )


def _recurrence(
    store: CaseStore, closed: ChangeAssuranceCase, new: ChangeAssuranceCase,
) -> str:
    """Why a *closed* case's trigger counts as having happened again, or ``""``.

    Seeing the same trigger again is not a recurrence. A recurrence is the
    trigger happening a second time:

    * drift: the machine was recorded in some *other* configuration after the
      closure and has now come back to the closed one (A -> B closed, B -> A,
      A -> B again). The evidence is the ledger's own manifests ordered by
      chain position, not by anybody's clock.
    * advisory: the advisory now reaches a machine the closed case did not name.
    * intervention: never. An intervention is one event; a new one is a new
      trigger and gets its own case.
    """
    closure = store.closure_entry(closed.case_id)
    if closure is None:
        return ""
    if closed.trigger_type is TriggerType.MACHINE_DRIFT:
        key = closed.machines[0] if closed.machines else ""
        for entry in store.ledger.entries(kind=MANIFEST_KIND, subject=key):
            if entry.seq <= closure.seq:
                continue
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            other = str(evidence.body.get("configuration_hash", ""))
            if other and other != closed.trigger_id:
                return (f"{key} was recorded at configuration {other[:12]} after "
                        f"this case was closed and has returned to "
                        f"{closed.trigger_id[:12]}")
        return ""
    if closed.trigger_type is TriggerType.SUPPLIER_ADVISORY:
        extra = [m for m in new.machines if m not in closed.machines]
        if extra:
            return ("the advisory now reaches machine(s) the closed case did not "
                    "name: " + ", ".join(extra))
    return ""


def _reopen(
    store: CaseStore, closed: ChangeAssuranceCase, new: ChangeAssuranceCase,
    because: str, *, actor: Actor, detail: str,
) -> ChangeAssuranceCase:
    """Append a ``reopened`` entry that points at the closure it follows.

    Nothing about the earlier cycle is deleted: the closure entry stays in the
    chain exactly as sealed, the old history is carried forward, and
    ``prior_closures`` plus a ``concerns`` link carry its hash into the new
    cycle. Owner, reviewer and decision are cleared — a new cycle needs a new
    claim and a new decision.
    """
    closure = store.closure_entry(closed.case_id)
    now = format_utc(utc_now())
    chash = closure.content_hash if closure else ""
    prior = {
        "closed_at": closed.closed_at, "closed_by": closed.decision_by,
        "reason": closed.decision_reason, "closure_hash": chash,
        "reopened_at": now, "reopened_because": because,
    }
    reopened = replace(
        new, status=CaseStatus.OPEN, opened_at=now, created_at=closed.created_at,
        history=closed.history,
        prior_closures=(*closed.prior_closures, prior),
        linked_evidence=(*new.linked_evidence,
                         {"relation": "concerns", "content_hash": chash,
                          "note": f"prior closure by {closed.decision_by}: "
                                  f"{closed.decision_reason}"}),
    )
    return store.reopen(
        reopened, actor=actor,
        detail=f"reopened ({because}); follows closure {chash[:12]} by "
               f"{closed.decision_by}. {detail}")


def _open_or_update(
    store: CaseStore, new: ChangeAssuranceCase, *, actor: Actor, detail: str,
    actions_by_fid: Mapping[str, Sequence[str]] | None = None,
) -> ChangeAssuranceCase:
    """One persistent case per trigger; seeing it again writes nothing unless it matters.

    ========== ==============================================================
    existing   a repeat observation of the same trigger
    ========== ==============================================================
    none       open it
    open ..    merge (:func:`_merge`); **no ledger entry if nothing differs**
    closed     reopen only on a genuine recurrence (:func:`_recurrence`),
               else leave alone
    rejected   leave alone (a different trigger id is a different case)
    deferred   leave alone until a person calls :func:`resume`
    ========== ==============================================================
    """
    existing = store.get(new.case_id)
    if existing is None:
        now = format_utc(utc_now())
        opened = replace(new, opened_at=now, created_at=now, updated_at=now)
        return store.open(opened, actor=actor, detail=detail)
    if existing.status is CaseStatus.CLOSED:
        because = _recurrence(store, existing, new)
        if not because:
            return existing
        return _reopen(store, existing, new, because, actor=actor, detail=detail)
    if existing.status.is_settled:
        return existing
    merged = _merge(existing, new, actions_by_fid or {})
    if _content(merged) == _content(existing):
        return existing
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
    actions_by_fid: dict[str, list[str]] = {}
    invalidation_reason = ""
    for fid in affected:
        fc = next((f for f in coverage.functions if f.function_id == fid), None)
        if fc is None:
            continue
        if fc.coverage is Coverage.STALE:
            invalidation_reason = invalidation_reason or fc.detail
            action = (
                f"Re-run {', '.join(fc.checks) or 'the declared checks'} "
                f"for {fid} ({fc.description}); last valid evidence "
                f"{fc.last_verified_hash[:12] or 'none'} was invalidated by "
                f"{fc.invalidated_by or 'this change'}.")
        elif fc.coverage in (Coverage.CURRENT,):
            action = (
                f"File an Annex III 1.1.9 intervention record for the change to "
                f"{divergence.machine_key}, then re-run coverage for {fid} — "
                "a safety-relevant configuration change was observed with no "
                "intervention record naming it, so evidence still reads "
                "'current' for a reason that will not survive an audit.")
        else:
            action = (
                f"Establish verification evidence for {fid} ({fc.coverage.value}): "
                f"{fc.detail}")
        required_actions.append(action)
        required_reverifications.append(fid)
        actions_by_fid.setdefault(fid, []).append(action)

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
        store, case, actor=actor, actions_by_fid=actions_by_fid,
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
    actions_by_fid: dict[str, list[str]] = {}
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
            action = (
                f"Re-verify {f.function_id} on {exposure.machine_key} "
                f"per the supplier's remedy: nothing declared beyond the "
                "advisory itself.")
            required_actions.append(action)
            actions_by_fid.setdefault(f.function_id, []).append(action)

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
        store, case, actor=actor, actions_by_fid=actions_by_fid,
        detail=f"advisory {impact.advisory_id}: {len(impact.machines_affected)} "
              f"machine(s) affected")


def note_advisory_withdrawn(
    store: CaseStore, advisory_id: str, reason: str, *, actor: Actor,
) -> ChangeAssuranceCase | None:
    """The supplier retracted an advisory this fleet had a case for.

    Whatever was done because of it now rests on a retracted advisory, and only
    a person can say whether that matters. So the withdrawal becomes a human
    decision on the open case — it does not close, reject or advance anything.
    A case already settled is left alone; no case at all returns ``None``.
    """
    case = store.get(_case_id(TriggerType.SUPPLIER_ADVISORY, advisory_id))
    if case is None or case.status.is_settled:
        return case
    question = (f"The supplier withdrew {advisory_id}: {reason or 'no reason given'}. "
                "Decide whether the work this case drove still stands, or reject "
                "the case as raised on a retracted advisory.")
    if question in case.human_decisions_required or any(
            r.get("decision") == question for r in case.resolved_decisions):
        return case
    status = CaseStatus.AWAITING_ACTION if case.status is CaseStatus.READY_TO_CLOSE \
        else case.status
    return store.update(
        replace(case, status=status,
                human_decisions_required=(*case.human_decisions_required, question)),
        actor=actor, detail=f"advisory {advisory_id} withdrawn by the supplier")


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

    actions_by_fid = {
        f.function_id: [
            f"Re-run {', '.join(f.checks) or 'the declared checks'} for {f.function_id} "
            f"({f.description}); {f.detail}"]
        for f in mine
    }
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
        required_actions=tuple(dict.fromkeys(
            a for acts in actions_by_fid.values() for a in acts)),
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
        store, case, actor=actor, actions_by_fid=actions_by_fid,
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
    AWAITING_REVERIFICATION when only re-verification is outstanding, else —
    when only human decisions remain — AWAITING_ACTION, else READY_TO_CLOSE.
    AWAITING_ACTION moves on the same rule once its actions are confirmed done
    (the caller's job — this never marks an action done itself, since only the
    reviewer knows whether it actually happened). It will not reach
    READY_TO_CLOSE while a re-verification or a human decision is outstanding.
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
    elif case.human_decisions_required:
        if case.status is CaseStatus.AWAITING_ACTION:
            raise CaseTransitionError(
                f"{case_id} still has {len(case.human_decisions_required)} human "
                "decision(s) unresolved, so it cannot be ready to close. A person "
                "answers each with resolve_decision(), or rejects/defers the case.")
        nxt = CaseStatus.AWAITING_ACTION
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
    include the new bundle, and reads what that engine says now. A function
    the manifest no longer declares cannot be shown current, so it stays
    required rather than quietly dropping off the list.
    """
    case = _require(store, case_id)
    if case.status is not CaseStatus.AWAITING_REVERIFICATION:
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}. reverify() is only valid from "
            "awaiting_reverification.")
    if not any(v.content_hash == verification_content_hash for v in verifications):
        raise CaseTransitionError(
            f"verification {verification_content_hash[:12]!r} is not among the "
            "sealed verifications this re-check was run against, so it cannot "
            "be recorded as the evidence behind it.")
    coverage = assess_coverage(manifest, verifications, interventions)
    still_required = []
    evidence_current = dict(case.evidence_current)
    for fid in case.required_reverifications:
        fc = next((f for f in coverage.functions if f.function_id == fid), None)
        if fc is None:
            evidence_current[fid] = "unknown"
            still_required.append(fid)
            continue
        evidence_current[fid] = fc.coverage.value
        if fc.coverage is not Coverage.CURRENT:
            still_required.append(fid)

    if still_required:
        nxt = CaseStatus.AWAITING_REVERIFICATION
    elif case.human_decisions_required:
        nxt = CaseStatus.AWAITING_ACTION
    else:
        nxt = CaseStatus.READY_TO_CLOSE
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


def resolve_decision(
    store: CaseStore, case_id: str, *, decision: str, resolution: str, actor: Actor,
) -> ChangeAssuranceCase:
    """A named person answers one of the case's open human decisions.

    The question moves from ``human_decisions_required`` to
    ``resolved_decisions`` with the answer and who gave it, so a later look at
    the same advisory never asks it again. Without this, a case that names a
    human decision could only ever be rejected or deferred.
    """
    _require_human(actor, "resolving a human decision")
    if not resolution.strip():
        raise CaseTransitionError("a resolution needs the answer the person gave.")
    case = _require(store, case_id)
    if case.status.is_settled:
        raise CaseTransitionError(f"{case_id} is already {case.status.value}.")
    if decision not in case.human_decisions_required:
        raise CaseTransitionError(
            f"{case_id} has no open human decision {decision!r}.")
    updated = replace(
        case,
        human_decisions_required=tuple(
            d for d in case.human_decisions_required if d != decision),
        resolved_decisions=(*case.resolved_decisions, {
            "decision": decision, "resolution": resolution,
            "by": actor.identifier, "at": format_utc(utc_now())}),
    )
    return store.update(updated, actor=actor,
                        detail=f"decision resolved by {actor.identifier}: {resolution}")


def resume(store: CaseStore, case_id: str, *, reason: str, actor: Actor) -> ChangeAssuranceCase:
    """DEFERRED -> IN_REVIEW. A named person takes the review back up.

    The way out of the one dead end the lifecycle used to have. The deferral
    stays in the history; the decision fields are cleared so the next
    ``decide`` is a fresh one. The resumed case is ``IN_REVIEW`` and must be
    advanced again, so nobody inherits a stop they did not confirm.
    """
    _require_human(actor, "resuming a deferred case")
    if not reason.strip():
        raise CaseTransitionError("resuming a case needs a reason.")
    case = _require(store, case_id)
    if case.status is not CaseStatus.DEFERRED:
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}, not deferred. resume() is only "
            "valid from deferred.")
    now = format_utc(utc_now())
    updated = replace(
        case, status=CaseStatus.IN_REVIEW, owner=case.owner or actor.identifier,
        review_started_at=case.review_started_at or now,
        decision="", decision_reason="", decision_by="",
    )
    return store.transition(
        updated, actor=actor,
        detail=f"resumed by {actor.identifier}: {reason} "
               f"(deferred by {case.decision_by}: {case.decision_reason})")


def decide(
    store: CaseStore, case_id: str, *, disposition: str, reason: str, actor: Actor,
) -> ChangeAssuranceCase:
    """The one human decision this whole product exists to lead up to.

    ``closed`` is only accepted from ``READY_TO_CLOSE`` — this function will
    not close a case that still has an outstanding action, re-verification or
    human decision, no matter who asks. ``rejected`` and ``deferred`` are
    accepted from any open status, because a human is always allowed to say
    "this is not a real problem" or "not now" without the deterministic
    engines' agreement. Every disposition needs a named *person*: an
    automated, service or anonymous actor is refused.
    """
    if disposition not in ("closed", "rejected", "deferred"):
        raise CaseTransitionError(
            f"disposition must be closed, rejected or deferred, not {disposition!r}.")
    _require_human(actor, f"{disposition} a case")
    if not reason.strip():
        raise CaseTransitionError(
            "a decision needs a reason. This is the sentence a reviewer reads "
            "when they ask why a case ended the way it did.")
    case = _require(store, case_id)
    if case.status.is_settled:
        raise CaseTransitionError(f"{case_id} is already {case.status.value}.")
    if disposition == "closed":
        if case.status is not CaseStatus.READY_TO_CLOSE:
            raise CaseTransitionError(
                f"{case_id} is {case.status.value}, not ready_to_close. This system "
                "does not close a case with outstanding actions or re-verifications, "
                "and it never infers 'safe' or 'compliant' from anything short of that.")
        if case.required_reverifications or case.human_decisions_required:
            raise CaseTransitionError(
                f"{case_id} names outstanding work "
                f"({', '.join((*case.required_reverifications, *case.human_decisions_required))}"
                ") and cannot be closed.")

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
