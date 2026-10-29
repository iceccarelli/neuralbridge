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

import random
import re
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import TypeVar

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of, format_utc, parse_utc, utc_now
from assurance.core.text import neutralise
from assurance.core.tiers import AssuranceTier
from assurance.fleet.impact import Exposure, ImpactReport
from assurance.machine.recorder_attestation import RecorderTrust
from assurance.machinery.divergence import Divergence, Severity
from assurance.machinery.intervention import IMPLIED_PREFIX, Intervention
from assurance.machinery.manifest import SafetyManifest, not_a_look
from assurance.machinery.record import (
    MANIFEST_KIND,
    interventions_from_ledger,
    manifests_from_ledger,
)
from assurance.machinery.staleness import (
    Coverage,
    VerificationRecord,
    assess_coverage,
    tier_reaches_validated,
)

from .model import CaseStatus, ChangeAssuranceCase, TriggerType
from .store import CaseConflictError, CaseStore

T = TypeVar("T")

__all__ = [
    "INCOMPLETE_COLLECTION_MARK",
    "CaseNotFoundError",
    "CaseTransitionError",
    "UnknownInterventionError",
    "UntrustedAdvisoryError",
    "advance",
    "advisory_case_id",
    "assess_advisory",
    "assess_drift",
    "assess_intervention",
    "assess_recorded_intervention",
    "blocked_reason",
    "case_id_for",
    "claim",
    "decide",
    "named_person_problem",
    "note_advisory_withdrawn",
    "resolve_decision",
    "resume",
    "reverify",
    "waive_reverification",
]


class CaseTransitionError(AssuranceError):
    """A case was asked to move somewhere its own state does not permit."""


class CaseNotFoundError(CaseTransitionError):
    """The case id names no case in this ledger.

    A subclass, so a caller that only knows :class:`CaseTransitionError` still
    refuses. The interfaces tell it apart: HTTP answers 404 (the same as a read
    of that id), the command line exits 2 (it could not run, as ``show`` does)
    instead of the 409 / exit 1 that a refused *transition* gets.
    """

    def __init__(self, case_id: str) -> None:
        super().__init__(f"no case {case_id!r}.")
        self.case_id = case_id


class UnknownInterventionError(AssuranceError):
    """The intervention id names no intervention sealed for that machine."""


class UntrustedAdvisoryError(CaseTransitionError):
    """A case was asked for on an advisory nobody has authenticated, without the override.

    A subclass of :class:`CaseTransitionError`, so every interface that already maps that to
    a refusal (HTTP 409, the command line's ``finding:``) refuses this one the same way.
    """


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


def _advisory_trigger(impact: ImpactReport) -> str:
    """The trigger id of an advisory case.

    An advisory that is not an import keeps the id it always had: the advisory id, so the
    cases already in a ledger do not move. An import's trigger names its trust class and its
    publisher too, so an unsigned document that happens to reuse a tracking id can never fold
    into (or rewrite) the case of a different advisory, and two publishers who number their
    advisories alike do not share one.
    """
    record = impact.advisory_import
    if record is None:
        return impact.advisory_id
    return (f"{impact.advisory_id} [{record.get('trust')} {record.get('origin')} from "
            f"{neutralise(impact.issued_by)}]")


def advisory_case_id(impact: ImpactReport) -> str:
    """The id the case for this advisory report has (or would have)."""
    return _case_id(TriggerType.SUPPLIER_ADVISORY, _advisory_trigger(impact))


#: Names no person is called. A caller that labels itself one of these is saying
#: what it is, not who it is.
_RESERVED_NAMES = frozenset({
    "automation", "watch", "agent", "service", "system", "bot", "assistant",
    "operator", "ai",
})
#: Code points that render as nothing (or as a blank) but are not control or
#: format characters, so a category test alone lets them through.
_FILLERS = frozenset("\u115f\u1160\u3164\uffa0\u2800")
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Cc", "Zl", "Zp"})
#: Letters from other scripts that read as Latin ones, mapped to the Latin
#: letter. A short list of the common ones, not Unicode's full confusables
#: table: it closes the obvious disguises of a reserved word, no more.
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u04bb": "h", "\u0501": "d", "\u0475": "v", "\u043a": "k", "\u043c": "m",
    "\u0442": "t", "\u043d": "h",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03b9": "i",
    "\u03ba": "k", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u03b5": "e",
    "\u03b7": "n", "\u03c2": "s",
    "\u0261": "g", "\u0131": "i", "\u0237": "j",
})


def _skeleton(name: str) -> str:
    """The name as it would read in Latin letters: NFKC, accents dropped,
    lookalike letters mapped, case folded."""
    norm = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", name))
    stripped = "".join(c for c in norm if not unicodedata.combining(c))
    return stripped.casefold().translate(_CONFUSABLES)


def _name_problem(name: str) -> str:
    """Why ``name`` cannot be the name of a person, or ``""`` if it can."""
    norm = unicodedata.normalize("NFKC", name)
    for ch in norm:
        if ch in _FILLERS or unicodedata.category(ch) in _INVISIBLE_CATEGORIES:
            return f"it contains an invisible or control character (U+{ord(ch):04X})"
    if not any(ch.isalnum() for ch in norm):
        return "it has no letter or digit in it"
    # Reserved if every word in it that is not a number is a reserved word:
    # "agent.", "system:", "bot-7", "automation bot", and the same in lookalike
    # letters. "Agent Smith" and "Botticelli" are somebody's name and pass.
    words = [w for w in re.findall(r"[^\W_]+", _skeleton(name)) if not w.isdigit()]
    if words and all(w in _RESERVED_NAMES for w in words):
        return f"{name.strip()!r} is what an automated actor is called, not who it is"
    return ""


def _require_human(actor: Actor, what: str) -> None:
    """Only a named person may make a decision on a case.

    ``Actor.kind`` must be exactly ``person`` (the alternatives are ``service``
    and ``automation``; a watch runs as ``automation``, and so does anything an
    HTTP or CLI caller did not put a name to), and the name must be one a
    person could have: visible, with a letter or digit in it, and not one of
    the labels automation goes by. Neither can close, reject, defer, resume,
    resolve or waive — those are the human decisions the whole workflow exists
    to lead up to.

    This refuses the *kind* and the *shape* of an actor. A name is declared by
    whoever holds the account or the shell; nothing here proves the person
    behind it is who they say, so "named person" means a name declared by an
    authenticated account holder, not an identity-proofed human (see CHANGE.md).
    """
    problem = _name_problem(actor.identifier) if actor.kind == "person" else ""
    if actor.kind != "person" or problem or not actor.identifier.strip():
        why = f" ({problem})" if problem else ""
        raise CaseTransitionError(
            f"{what} is a human decision and needs a named person. Actor "
            f"{actor.identifier!r} is kind {actor.kind!r}{why}; an automated, "
            "service or anonymous actor can detect and report, but it cannot decide.")


#: Written into a manifest's ``notes`` by the watch when a collection did not
#: find or read every item its plan names. Such a manifest is a partial look,
#: not a configuration the machine was in, so it cannot count as "left that
#: configuration" when judging whether a closed case recurred.
INCOMPLETE_COLLECTION_MARK = "[collection incomplete"


def _entry_machine(case: ChangeAssuranceCase, entry: str) -> str | None:
    """The machine an entry of ``required_reverifications`` concerns.

    Advisory cases span machines, so their entries are ``machine/function``.
    Every other case concerns one machine and keeps bare function ids.
    """
    if case.trigger_type is TriggerType.SUPPLIER_ADVISORY and "/" in entry:
        return entry.rpartition("/")[0]
    if case.trigger_type is TriggerType.SUPPLIER_ADVISORY:
        return None
    return case.machines[0] if case.machines else None


def _entry_function(case: ChangeAssuranceCase, entry: str) -> str:
    if case.trigger_type is TriggerType.SUPPLIER_ADVISORY and "/" in entry:
        return entry.rpartition("/")[2]
    return entry


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


def _append_links(
    existing: Sequence[dict[str, str]], new: Sequence[dict[str, str]],
) -> tuple[dict[str, str], ...]:
    """Every existing link, then each new link that is not already there.

    Unlike :func:`_links_union` this does not fold a new link into an old one because they
    share a note: two advisories can both be "advisory X from Y" and are different evidence.
    """
    out = list(existing)
    out.extend(r for r in new if r not in out)
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
        trigger_at=existing.trigger_at or new.trigger_at,
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
        if existing.trigger_type is not TriggerType.SUPPLIER_ADVISORY:
            # Drift and intervention cases are keyed by what happened (the observed
            # configuration, the intervention id), so a repeat look at the same trigger is
            # the same fact read again: the freshest reading replaces the facts and the
            # pointers to the evidence it rests on (a re-collected manifest is the one
            # that was actually sealed). Links the case earned itself survive.
            kept = tuple(r for r in existing.linked_evidence
                         if r.get("note", "").startswith("prior closure by"))
            # The facts are replaced; the work is not. A later look may name more, but
            # it never names less than what is already outstanding: dropping a
            # re-verification, an action or a question takes a re-verification or a
            # person's recorded waiver or answer, not a repeat observation.
            return replace(
                base,
                required_reverifications=_union(existing.required_reverifications,
                                                new.required_reverifications),
                required_actions=_union(existing.required_actions, new.required_actions),
                human_decisions_required=_union(existing.human_decisions_required,
                                                fresh_decisions),
                linked_evidence=_links_union(new.linked_evidence, kept))
        # An advisory id does not determine an advisory's content: the same id re-issued
        # narrower, or by another document, is a different reading. So here a later look
        # only ever adds. It refreshes a row it re-reads, but it never drops a machine the
        # case names, never overwrites the link to the advisory the case was opened on
        # (the new advisory's link is appended), and never narrows the work.
        fresh_keys = {_key(i) for i in new.changed_items}
        rows = (*new.changed_items,
                *(i for i in existing.changed_items if _key(i) not in fresh_keys))
        return replace(
            base,
            machines=_union(existing.machines, new.machines),
            sites=_union(existing.sites, new.sites),
            changed_items=tuple(rows),
            affected_functions=_union(existing.affected_functions, new.affected_functions),
            evidence_before={**existing.evidence_before, **new.evidence_before},
            evidence_current={**existing.evidence_current, **new.evidence_current},
            required_reverifications=_union(existing.required_reverifications,
                                            new.required_reverifications),
            required_actions=_union(existing.required_actions, new.required_actions),
            human_decisions_required=_union(existing.human_decisions_required,
                                            fresh_decisions),
            linked_evidence=_append_links(existing.linked_evidence, new.linked_evidence),
            checks_skipped=_union(existing.checks_skipped, new.checks_skipped),
            provenance={**new.provenance, **existing.provenance})

    items = list(existing.changed_items)
    known = {_key(i) for i in items}
    for i in new.changed_items:
        if _key(i) not in known:
            items.append(i)
            known.add(_key(i))
    # Work is new only if the case has never tracked that entry: a machine the
    # case did not name, or a function it did not list. An entry the case has
    # already handled (it is in evidence_current) is never re-added, which is
    # what stops a later look re-inflating a case that has been worked.
    tracked = (set(existing.evidence_before) | set(existing.evidence_current)
               | set(existing.required_reverifications))
    added_reverifs = [e for e in new.required_reverifications if e not in tracked]
    added_actions = [a for e in added_reverifs for a in actions_by_fid.get(e, ())]
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
        evidence_before={**new.evidence_before, **existing.evidence_before},
        evidence_current={**new.evidence_current, **existing.evidence_current},
        required_actions=_union(existing.required_actions, added_actions),
        required_reverifications=reverifs,
        human_decisions_required=decisions,
        linked_evidence=(
            _append_links(existing.linked_evidence, new.linked_evidence)
            if existing.trigger_type is TriggerType.SUPPLIER_ADVISORY
            else _links_union(existing.linked_evidence, new.linked_evidence)),
        checks_skipped=_union(existing.checks_skipped, new.checks_skipped),
        provenance={**new.provenance, **existing.provenance},
    )


def _recurrence(
    store: CaseStore, settled: ChangeAssuranceCase, new: ChangeAssuranceCase,
) -> str:
    """Why a *closed or rejected* case's trigger counts as having happened again, or ``""``.

    Seeing the same trigger again is not a recurrence. A recurrence is the
    trigger happening a second time:

    * drift, closed only: the machine was recorded in some *other* complete
      configuration after the closure and has now come back to the closed one
      (A -> B closed, B -> A, A -> B again). The evidence is the ledger's own
      manifests ordered by chain position, not by anybody's clock. A partial
      collection (a missing export) is not another configuration and does not
      count. A rejected drift stays rejected.
    * advisory, closed or rejected: the advisory now reaches a machine the
      settled case did not name.
    * intervention: never. An intervention is one event; a new one is a new
      trigger and gets its own case.
    """
    settling = store.settling_entry(settled.case_id, settled.decision)
    if settling is None:
        return ""
    if settled.trigger_type is TriggerType.MACHINE_DRIFT \
            and settled.status is CaseStatus.CLOSED:
        key = settled.machines[0] if settled.machines else ""
        for entry in store.ledger.entries(kind=MANIFEST_KIND, subject=key):
            if entry.seq <= settling.seq:
                continue
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            if INCOMPLETE_COLLECTION_MARK in str(
                    evidence.body.get("manifest", {}).get("notes", "")):
                continue
            other = str(evidence.body.get("configuration_hash", ""))
            if other and other != settled.trigger_id:
                return (f"{key} was recorded at configuration {other[:12]} after "
                        f"this case was closed and has returned to "
                        f"{settled.trigger_id[:12]}")
        return ""
    if settled.trigger_type is TriggerType.SUPPLIER_ADVISORY:
        extra = [m for m in new.machines if m not in settled.machines]
        if extra:
            return ("the advisory now reaches machine(s) the "
                    f"{settled.status.value} case did not name: " + ", ".join(extra))
    return ""


def _reopen(
    store: CaseStore, settled: ChangeAssuranceCase, new: ChangeAssuranceCase,
    because: str, *, actor: Actor, detail: str,
) -> ChangeAssuranceCase:
    """Append a ``reopened`` entry that points at the decision it follows.

    Nothing about the earlier cycle is deleted: the closing (or rejecting)
    entry stays in the chain exactly as sealed, the old history is carried
    forward and extended, and ``prior_closures`` plus a ``concerns`` link carry
    its hash into the new cycle. Owner, reviewer and decision are cleared — a
    new cycle needs a new claim and a new decision.
    """
    settling = store.settling_entry(settled.case_id, settled.decision)
    now = format_utc(utc_now())
    chash = settling.content_hash if settling else ""
    prior = {
        "disposition": settled.decision,
        "closed_at": settled.closed_at or settled.updated_at,
        "closed_by": settled.decision_by,
        "reason": settled.decision_reason, "closure_hash": chash,
        "reopened_at": now, "reopened_because": because,
    }
    reopened = replace(
        new, status=CaseStatus.OPEN, opened_at=now, created_at=settled.created_at,
        trigger_at=new.trigger_at or now,
        history=settled.history,
        prior_closures=(*settled.prior_closures, prior),
        linked_evidence=(*new.linked_evidence,
                         {"relation": "concerns", "content_hash": chash,
                          "note": f"prior {settled.decision} by {settled.decision_by}: "
                                  f"{settled.decision_reason}"}),
    )
    return store.reopen(
        reopened, actor=actor,
        detail=f"reopened ({because}); follows {settled.decision} {chash[:12]} by "
               f"{settled.decision_by}. {detail}")


def _grow_deferred(
    store: CaseStore, deferred: ChangeAssuranceCase, new: ChangeAssuranceCase,
    *, actor: Actor,
) -> ChangeAssuranceCase:
    """A deferred advisory case whose exposure has grown.

    Deferral is "not today", not "never look again". The machine is added to
    the case and a question is put to its owner — recorded, once — but the case
    stays deferred: only a person resumes it.
    """
    extra = [m for m in new.machines if m not in deferred.machines]
    if not extra or deferred.trigger_type is not TriggerType.SUPPLIER_ADVISORY:
        return deferred
    known = {_key(i) for i in deferred.changed_items}
    rows = [i for i in new.changed_items
            if any(str(i.get("item_id", "")).startswith(m + "/") for m in extra)
            and _key(i) not in known]
    questions = [
        f"{m}: this deferred advisory case now also exposes this machine. Resume the "
        "case to work it, or decide it needs nothing." for m in extra]
    resolved = {r.get("decision") for r in deferred.resolved_decisions}
    grown = replace(
        deferred,
        machines=_union(deferred.machines, extra),
        sites=_union(deferred.sites, new.sites),
        changed_items=(*deferred.changed_items, *rows),
        human_decisions_required=_union(
            deferred.human_decisions_required, [q for q in questions if q not in resolved]),
    )
    return store.update(grown, actor=actor,
                        detail="deferred case's exposure grew: " + ", ".join(extra))


#: How many times a machine-driven step re-reads and recomputes after losing a
#: race to another writer before it gives up and reports the conflict.
_CONFLICT_RETRIES = 8


def _retrying(step: Callable[[], T]) -> T:
    """Run a machine-driven read-decide-append, redoing all of it when it lost a race.

    ``step`` re-reads the case on every call, so a retry judges the new state: a
    second observer of a recurrence finds the case already reopened and writes
    nothing; a repeat look finds the human's decision and leaves it alone. Human
    steps are *not* retried here — a person's decision was made on what they
    saw, so they are told (409) and decide again.
    """
    for attempt in range(_CONFLICT_RETRIES):
        try:
            return step()
        except CaseConflictError:
            if attempt == _CONFLICT_RETRIES - 1:
                raise
            time.sleep(random.random() * 0.01 * (attempt + 1))  # noqa: S311 - jitter
    raise AssertionError("unreachable")  # pragma: no cover


def _open_or_update(
    store: CaseStore, new: ChangeAssuranceCase, *, actor: Actor, detail: str,
    actions_by_fid: Mapping[str, Sequence[str]] | None = None,
) -> ChangeAssuranceCase:
    """:func:`_open_or_update_once`, redone from a fresh read if another writer won."""
    return _retrying(lambda: _open_or_update_once(
        store, new, actor=actor, detail=detail, actions_by_fid=actions_by_fid))


def _open_or_update_once(
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
    rejected   reopen only if an advisory now exposes a machine the rejection
               did not name; an identical trigger stays rejected
    deferred   leave alone until a person calls :func:`resume` — but a growing
               advisory exposure is added and put to the owner as a question
    ========== ==============================================================
    """
    existing = store.get(new.case_id)
    if existing is None:
        now = format_utc(utc_now())
        # The case stamps its own opening time as the trigger when the engine
        # gave none (an advisory has no observation time): the floor for
        # re-verification evidence is the case's, never the caller's.
        opened = replace(new, opened_at=now, created_at=now, updated_at=now,
                         trigger_at=new.trigger_at or now)
        return store.open(opened, actor=actor, detail=detail)
    if existing.status in (CaseStatus.CLOSED, CaseStatus.REJECTED):
        because = _recurrence(store, existing, new)
        if not because:
            return existing
        return _reopen(store, existing, new, because, actor=actor, detail=detail)
    if existing.status is CaseStatus.DEFERRED:
        return _grow_deferred(store, existing, new, actor=actor)
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

    # The drift under assessment is this case's finding, not evidence for it. Once the
    # observed manifest is sealed the ledger derives an implied change from it; leaving
    # that in would make a re-assessment after sealing read differently from the first,
    # which ran before the manifest was sealed (so a crash between the two is a no-op).
    own = f"{IMPLIED_PREFIX}{manifest.content_hash()[:12]}@"
    interventions = [i for i in interventions if not i.intervention_id.startswith(own)]
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
        trigger_at=format_utc(manifest.taken_at),
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

def _attribution_basis(actor: Actor) -> str:
    """How the actor's name was established, as the surface that built the actor recorded it.

    ``authenticated_operator`` is a credential bound to a named operator; ``declared_*`` is a
    name an account-level key or an open-mode caller typed; ``declared_locally`` is the
    command line, where whoever owns the shell and the ledger file declares it.
    """
    found = re.search(r"attribution=([a-z_]+)", actor.role or "")
    return found.group(1) if found else "declared_locally"


def named_person_problem(identifier: str) -> str:
    """Why ``identifier`` cannot be the name of a person, or ``""`` if it can."""
    return _name_problem(identifier) if identifier.strip() else "no name was given"


def _untrusted_marker(
    impact: ImpactReport, actor: Actor, accept_unsigned: bool, reason: str,
) -> dict[str, str]:
    """Refuse, or say plainly, that a case rests on an advisory nobody has authenticated.

    ``{}`` for an advisory that is not an import and was not handed over as a bare file or
    body (a signed, pinned supplier feed, or a caller that states no provenance). Otherwise
    only a named person may open the case, and an unsigned import additionally needs that
    person's explicit override. The result is written into the case's provenance, so the
    case, its export and every later reader can see it.
    """
    record = impact.advisory_import
    given = impact.provenance or {}
    if record is None and not given.get("inspect_only"):
        return {}
    shown = neutralise(impact.advisory_id)
    _require_human(actor, f"opening a case from advisory {shown}, which nobody has "
                          "authenticated,")
    if record is not None and not accept_unsigned:
        raise UntrustedAdvisoryError(
            f"advisory {shown} is an unsigned, inspect-only import "
            f"({record.get('origin')}). A case is a record people must work, and nothing "
            "has checked that this advisory is genuine. If a named person has read it "
            "against the publisher's own page and wants the case anyway, pass the "
            "override explicitly (`--accept-unsigned` with `--actor NAME`; the API's "
            "`accept_unsigned` with `actor`). Nothing was opened.")
    if record is not None and not reason.strip():
        raise UntrustedAdvisoryError(
            f"advisory {shown} is an unsigned import and the override needs a reason in the "
            "person's own words (`--reason`; the API's `reason`): what was checked, against "
            "what. Nothing was opened.")
    marker: dict[str, str] = {
        "advisory_trust": str(record["trust"] if record else
                              given.get("trust_state") or "unauthenticated"),
        "advisory_origin": str(record["origin"] if record else
                               given.get("source") or "unknown"),
        "advisory_issuer": neutralise(impact.issued_by),
        "advisory_accepted_by": actor.identifier.strip(),
        "advisory_accepted_basis": _attribution_basis(actor),
        "advisory_accept_reason": " ".join(neutralise(reason).split())[:500],
    }
    if record is not None:
        marker.update({
            "advisory_partial": "true" if record.get("partial") else "false",
            "advisory_dropped_products": ", ".join(
                neutralise(i) for i in impact.dropped_products),
            "advisory_severity_source": neutralise(record.get("severity_source")),
            "advisory_tlp": neutralise(record.get("tlp")),
            "advisory_tracking_status": neutralise(record.get("tracking_status")),
            "advisory_document_category": neutralise(record.get("document_category")),
            "advisory_document_date": neutralise(record.get("document_date")),
        })
    return marker


def assess_advisory(
    store: CaseStore, impact: ImpactReport, *, actor: Actor,
    accept_unsigned: bool = False, reason: str = "",
) -> ChangeAssuranceCase | None:
    """A supplier advisory now touches this fleet.

    An advisory nobody has authenticated (an unsigned import, or a bare file or body: see
    :func:`_untrusted_marker`) opens a case only for a named person, an unsigned import only
    with ``accept_unsigned`` as well, and the case says so in its provenance.

    One case per advisory, naming every machine :func:`assess_impact` found —
    not one case per machine, because the decision this drives ("does this
    advisory's remedy apply here") is the same decision across every exposed
    machine, and forty copies of it would not be forty findings.

    Opens a case only when the report is not ``clear``: an advisory that
    matches nothing in the fleet is not a change to anyone's evidence.
    """
    if impact.verdict == "clear":
        return None
    marker = _untrusted_marker(impact, actor, accept_unsigned, reason)
    imported = impact.advisory_import is not None

    def _row(e: Exposure) -> dict[str, object]:
        return {
            "item_id": f"{e.machine_key}/{e.item_id}",
            "detail": f"{e.machine_key} ({e.site or 'unknown site'}): {e.detail}",
            "confidence": e.confidence,
            "functions": [f.function_id for f in e.functions],
        }

    # Every function an exposed item implements needs evidence that postdates
    # the advisory — not only the ones that were current until now. A function
    # that was never verified, or already stale, is not supported by anything
    # either; leaving it off the list let a case close on no evidence at all.
    # Entries are machine-qualified (``machine/function``) because SF-01 on one
    # machine is not SF-01 on another.
    affected: list[str] = []
    evidence_before: dict[str, str] = {}
    required_reverifications: list[str] = []
    for exposure in impact.exposures:
        for f in exposure.functions:
            if f.function_id not in affected:
                affected.append(f.function_id)
            key = f"{exposure.machine_key}/{f.function_id}"
            evidence_before[key] = f.coverage_before.value
            required_reverifications.append(key)

    human_decisions: list[str] = []
    required_actions: list[str] = []
    actions_by_fid: dict[str, list[str]] = {}
    if imported:
        human_decisions.append(
            f"The advisory behind this case is an unsigned, inspect-only CSAF import "
            f"(accepted by {marker['advisory_accepted_by']}). Confirm it against the "
            "publisher's own page and key before any change is made to a safety system "
            "on its authority.")
        if impact.incomplete:
            gone = ", ".join(repr(i) for i in impact.dropped_products)
            why = "; ".join(neutralise(r) for r in impact.incomplete_reasons)
            human_decisions.append(
                "The advisory is an incomplete translation of its source"
                + (f": affected product(s) {gone} were not imported, so machines running "
                   "them are NOT in this case" if gone else "")
                + f". Check the source document against the fleet by hand ({why}).")
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
        for f in exposure.functions:
            key = f"{exposure.machine_key}/{f.function_id}"
            if f.newly_in_question:
                action = (
                    f"Re-verify {f.function_id} on {exposure.machine_key} "
                    f"per the supplier's remedy: nothing declared beyond the "
                    "advisory itself.")
            else:
                action = (
                    f"Establish verification evidence for {f.function_id} on "
                    f"{exposure.machine_key} ({f.coverage_before.value}): the "
                    "advisory reaches an item that implements it, and nothing "
                    "currently supports it.")
            required_actions.append(action)
            actions_by_fid.setdefault(key, []).append(action)

    case = ChangeAssuranceCase(
        case_id=advisory_case_id(impact),
        trigger_type=TriggerType.SUPPLIER_ADVISORY,
        trigger_id=_advisory_trigger(impact),
        status=CaseStatus.OPEN,
        machines=impact.machines_affected,
        sites=tuple(dict.fromkeys(e.site for e in impact.exposures if e.site)),
        changed_items=tuple(_row(e) for e in impact.exposures),
        change_severity="safety_relevant",
        affected_functions=tuple(affected),
        evidence_before=evidence_before,
        evidence_current=dict(evidence_before),
        required_actions=tuple(dict.fromkeys(required_actions)),
        required_reverifications=tuple(dict.fromkeys(required_reverifications)),
        human_decisions_required=tuple(dict.fromkeys(human_decisions)),
        linked_evidence=({"relation": "concerns", "content_hash": impact.advisory_hash,
                          "note": f"advisory {neutralise(impact.advisory_id)} from "
                                  f"{neutralise(impact.issued_by)}"
                                  + (" (unsigned CSAF import)" if imported else "")},),
        checks_skipped=(
            impact.checks_skipped if not marker else (
                f"this case rests on an advisory nobody has authenticated "
                f"({marker['advisory_trust']}), opened on the authority of "
                f"{marker['advisory_accepted_by']}; no signature was checked.",
                *impact.checks_skipped)),
        confidence=("high" if impact.confirmed and not marker else "medium"),
        provenance={"changed_items": "assurance.fleet.impact.assess_impact", **marker},
    )
    if marker and not imported:
        # A bare file or body shares its case id with a case opened from a signed or
        # pinned feed (ids of existing cases must not move). It must not alter that case:
        # an unauthenticated reading never rewrites one that carries no such marker.
        current = store.get(case.case_id)
        if current is not None and not current.provenance.get("advisory_trust"):
            raise UntrustedAdvisoryError(
                f"case {current.case_id} for advisory {neutralise(impact.advisory_id)} was "
                "opened from a source that carries no unauthenticated marker (a signed feed "
                "or the watch), and an unauthenticated file does not update it. The case is "
                "not updated; this reading was not applied.")
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
    def step() -> ChangeAssuranceCase | None:
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

    return _retrying(step)


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
        trigger_at=format_utc(intervention.occurred_at),
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


def assess_recorded_intervention(
    store: CaseStore, manifest: SafetyManifest, intervention_id: str, *, actor: Actor,
    recorder_trust: RecorderTrust | None = None,
) -> tuple[Intervention, ChangeAssuranceCase | None]:
    """:func:`assess_intervention` for an intervention already sealed in the ledger.

    The one place that looks the intervention up, so the command line and the
    HTTP route cannot disagree about which record they assessed. The
    verifications and interventions come from the ledger, never the caller.
    ``recorder_trust`` is the reader's own recorder trust list, applied to those
    verifications (a hosted reader always passes one).
    """
    key = manifest.machine.key
    interventions = interventions_from_ledger(store.ledger, key)
    chosen = next((i for i in interventions if i.intervention_id == intervention_id), None)
    if chosen is None:
        raise UnknownInterventionError(
            f"no intervention {intervention_id!r} is sealed for {key}. "
            "Record it first with `assurance machinery record-change`.")
    verifications = VerificationRecord.from_ledger(
        store.ledger, subject=key, recorder_trust=recorder_trust)
    return chosen, assess_intervention(
        store, chosen, manifest, verifications, interventions, actor=actor)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def claim(store: CaseStore, case_id: str, *, owner: str, actor: Actor) -> ChangeAssuranceCase:
    """OPEN -> IN_REVIEW. A named person is now responsible for this case."""
    case = _require(store, case_id)
    problem = _name_problem(owner)
    if problem:
        raise CaseTransitionError(
            f"{owner!r} cannot own a case: {problem}. An owner is the person "
            "who answers for it.")
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
    reviewer knows whether it actually happened). AWAITING_REVERIFICATION
    moves only once nothing is left to re-verify (each entry cleared by
    evidence, or waived by a person). It will not reach READY_TO_CLOSE while a
    re-verification or a human decision is outstanding.
    """
    case = _require(store, case_id)
    if case.status not in (CaseStatus.IN_REVIEW, CaseStatus.AWAITING_ACTION,
                           CaseStatus.AWAITING_REVERIFICATION):
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}. advance() is only valid from "
            "in_review, awaiting_action or (once nothing is left to re-verify) "
            "awaiting_reverification.")
    if case.status is CaseStatus.AWAITING_REVERIFICATION and case.required_reverifications:
        raise CaseTransitionError(
            f"{case_id} is awaiting re-verification of "
            f"{', '.join(case.required_reverifications)}. advance() will not move it "
            "until each is cleared by re-verification evidence or waived by a person.")
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


def _validated_or_better(tier: str) -> bool:
    """Is a verification's tier at least ``validated``?

    One ladder with the staleness engine that reads the tier out of the ledger
    (:func:`assurance.machinery.staleness.tier_reaches_validated`): a name it does
    not contain (empty, misspelt, from a newer build) is not known to be enough.
    The tier itself is already capped there to what its sealed provenance basis
    supports, so a legacy ``validated`` body arrives as ``community``.
    """
    return tier_reaches_validated(tier)


def _trace_filed_elsewhere(ledger: object, verification_hash: str, key: str) -> str:
    """The other subject the same trace is filed under, or "" if there is none."""
    from assurance.machine.bundle import BUNDLE_KIND

    entries = list(ledger.entries(kind=BUNDLE_KIND))  # type: ignore[attr-defined]
    trace_hash = next(
        (str(e.payload.get("body", {}).get("trace_hash", "")) for e in entries
         if e.content_hash == verification_hash), "")
    if not trace_hash:
        return ""
    for e in entries:
        if (e.subject != key
                and str(e.payload.get("body", {}).get("trace_hash", "")) == trace_hash):
            return e.subject
    return ""


def reverify(
    store: CaseStore, case_id: str,
    manifest: SafetyManifest, verifications: list[VerificationRecord],
    interventions: list[Intervention],
    *, verification_content_hash: str, actor: Actor,
) -> ChangeAssuranceCase:
    """Record a fresh verification against one machine, and see what it clears.

    This never marks a function covered by assertion. It clears an entry only
    when **all** of these hold, each read from the record and never from the
    caller's say-so:

    * the manifest is for a machine this case concerns, and the entry is that
      machine's (advisory entries are ``machine/function``; one machine's
      bundle never clears another's);
    * the cited verification is one the coverage check actually ran against,
      was sealed *after this case's current cycle began*, and describes a state
      at or after both the change that triggered the case and the manifest it
      is checked against — a bundle that already existed when the change was
      found cannot be evidence about it;
    * that bundle passed every check the function declares (a newer bundle for one
      check plus an older one for another is not enough);
    * that bundle's tier is at least ``validated``. A trace's declared provenance is
      capped at ``community``; a ``validated`` verification needs a signed recorder
      attestation accepted under the verifier's own recorder trust list (a trusted
      key signed these exact trace bytes; not proof the recording is physically
      true). Without one a re-verification clears nothing by itself and only a
      person's waiver (a ``decider`` operator) closes an entry, and a waiver is
      still a waiver; and
    * :func:`assess_coverage` reads the function ``current``.

    An entry that fails any of them stays required, with the reason in
    ``evidence_current`` (``below_validated:<tier>`` for evidence under the floor, which the
    case also records in ``checks_skipped``); :func:`blocked_reason` turns that into
    the machine-readable answer the interfaces return beside the case. A function the
    manifest no longer declares cannot be shown current and stays required too.
    """
    case = _require(store, case_id)
    if case.status is not CaseStatus.AWAITING_REVERIFICATION:
        raise CaseTransitionError(
            f"{case_id} is {case.status.value}. reverify() is only valid from "
            "awaiting_reverification.")
    key = manifest.machine.key
    if key not in case.machines:
        raise CaseTransitionError(
            f"the manifest is for {key}, which does not concern {case_id} "
            f"(it concerns {', '.join(case.machines) or 'no machine'}). "
            "A re-verification of another machine is not evidence about this one.")
    record = next((v for v in verifications if v.content_hash == verification_content_hash),
                  None)
    if record is None:
        raise CaseTransitionError(
            f"verification {verification_content_hash[:12]!r} is not among the "
            "sealed verifications this re-check was run against, so it cannot "
            "be recorded as the evidence behind it.")
    start = store.cycle_start_seq(case_id)
    if record.ledger_seq <= start:
        raise CaseTransitionError(
            f"verification {record.content_hash[:12]} was sealed before this case "
            f"was opened (ledger position {record.ledger_seq}, case at {start}). "
            "Evidence that already existed when the change was found cannot be "
            "evidence about it; run the checks again.")
    # Ledger truth: the machine's declared functions and checks, and its current
    # configuration, are read from the newest manifest sealed for it, never from
    # the manifest in the caller's hands (which only has to agree with it).
    sealed_manifests = manifests_from_ledger(store.ledger, key)
    if not sealed_manifests:
        raise CaseTransitionError(
            f"the ledger holds no manifest sealed for {key}, so there is nothing to "
            "check a re-verification against. Record the machine's manifest first.")
    sealed = sealed_manifests[-1]
    not_looked = not_a_look(sealed)
    if not_looked:
        raise CaseTransitionError(
            f"the newest manifest sealed for {key} cannot show the machine after the "
            f"change: {not_looked} Collect it from the machine and seal it, then "
            "re-verify.")
    if record.date_suspect:
        raise CaseTransitionError(
            f"verification {record.content_hash[:12]} cannot be dated: its trace start "
            "is unreadable or later than the moment it was filed, so it cannot be shown "
            "to postdate the change.")
    other = _trace_filed_elsewhere(store.ledger, record.content_hash, key)
    if other:
        raise CaseTransitionError(
            f"verification {record.content_hash[:12]} rests on a trace that is also "
            f"filed as evidence for {other}. One recording is not evidence about two "
            "machines; run the verification on this machine's own trace.")
    allowed = {sealed.configuration_hash()}
    if case.trigger_type is TriggerType.MACHINE_DRIFT:
        allowed.add(case.after_hash)
    if manifest.configuration_hash() not in allowed:
        raise CaseTransitionError(
            f"the manifest's configuration {manifest.configuration_hash()[:12]} is "
            f"neither the one this case concerns nor the newest sealed for {key} "
            f"({sealed.configuration_hash()[:12]}); a re-verification of some other "
            "configuration is not evidence about this one.")
    floor = parse_utc(case.trigger_at or case.opened_at)
    if sealed.taken_at < floor:
        raise CaseTransitionError(
            f"the newest manifest sealed for {key} was taken {format_utc(sealed.taken_at)}, "
            f"which predates this case's trigger ({format_utc(floor)}). Collect and seal "
            "the machine's manifest again after the change, then re-verify.")
    if record.effective_at < floor:
        raise CaseTransitionError(
            f"verification {record.content_hash[:12]} describes a state before "
            f"{format_utc(floor)} (the run started {format_utc(record.effective_at)}). "
            "It cannot show the machine as it is after the change.")
    mine = [e for e in case.required_reverifications
            if _entry_machine(case, e) in (key, None)]
    if not mine:
        raise CaseTransitionError(
            f"{case_id} has nothing outstanding for {key}; it awaits "
            f"{', '.join(case.required_reverifications) or 'nothing'}.")

    coverage = assess_coverage(sealed, verifications, interventions)
    cleared: set[str] = set()
    weak: list[str] = []
    bound: list[str] = []
    evidence_current = dict(case.evidence_current)
    for entry in mine:
        fid = _entry_function(case, entry)
        fn = sealed.function(fid)
        fc = next((f for f in coverage.functions if f.function_id == fid), None)
        if fn is None or fc is None:
            evidence_current[entry] = "unknown"
        elif fc.coverage is not Coverage.CURRENT:
            evidence_current[entry] = fc.coverage.value
        elif not fn.verified_by or not set(fn.verified_by) <= set(record.checks_verified):
            evidence_current[entry] = "no_new_evidence"
        elif not _validated_or_better(record.tier):
            # Current on evidence under the 'validated' floor is a statement about
            # a recorded file, not a demonstration on the machine. It does not
            # clear the entry; only a person can accept it, by waiving it.
            if record.tier_note:
                # Held down by the UNIT BINDING (sealed for another unit key or none, or the
                # same recording is another unit's): re-attesting would not help, re-sealing
                # under the exact key would. Say that, not "a recorder attestation is needed".
                evidence_current[entry] = (
                    f"{_BOUND}{record.tier or 'unknown'}")
                bound.append(entry)
            else:
                evidence_current[entry] = f"below_validated:{record.tier or 'unknown'}"
                weak.append(entry)
        else:
            evidence_current[entry] = Coverage.CURRENT.value
            cleared.add(entry)
    still_required = tuple(e for e in case.required_reverifications if e not in cleared)
    skipped = case.checks_skipped
    if bound:
        skipped = _union(skipped, [
            f"{', '.join(bound)}: the re-verification evidence {record.content_hash[:12]} is "
            f"held at tier {record.tier or 'unknown'!r} by its unit binding, not by a missing "
            f"attestation: {record.tier_note}. Re-seal the run with the exact unit key as the "
            f"subject ({key}); the recorder's attestation is unchanged. A decider operator may "
            "waive the entry; a waiver is still a waiver."])
    if weak:
        skipped = _union(skipped, [
            f"{', '.join(weak)}: the re-verification evidence "
            f"{record.content_hash[:12]} is at tier {record.tier or 'unknown'!r}, below "
            "'validated', so it did not clear the entry. A declared provenance is "
            "capped at 'community'; a 'validated' verification needs a recorder "
            "attestation accepted under the verifier's own recorder trust list. A "
            "decider operator may waive the entry; a waiver is still a waiver."])

    if still_required:
        nxt = CaseStatus.AWAITING_REVERIFICATION
    elif case.human_decisions_required:
        nxt = CaseStatus.AWAITING_ACTION
    else:
        nxt = CaseStatus.READY_TO_CLOSE
    linked = (*case.linked_evidence,
             {"relation": "supports", "content_hash": verification_content_hash,
              "note": f"re-verification evidence ({key})"})
    updated = replace(
        case, status=nxt, evidence_current=evidence_current,
        required_reverifications=still_required,
        required_actions=() if not still_required else case.required_actions,
        reverified_at=format_utc(utc_now()), linked_evidence=linked,
        checks_skipped=skipped,
    )
    return store.reverify(
        updated, actor=actor,
        detail=f"re-verified {key} against {verification_content_hash[:12]}; "
              f"{len(still_required)} entr{'y' if len(still_required) == 1 else 'ies'} "
              "still not current"
              + (f" ({len(weak) + len(bound)} on evidence below 'validated': tier "
                 f"{record.tier or 'unknown'!r}"
                 + (", held by its unit binding" if bound else "") + ")"
                 if weak or bound else ""))


#: The tier a verification must reach to clear a required re-verification.
REVERIFICATION_TIER_FLOOR = AssuranceTier.VALIDATED.value

_BELOW = "below_validated:"
_BOUND = "below_validated_unit_binding:"


def blocked_reason(case: ChangeAssuranceCase) -> dict[str, object] | None:
    """Why a case is still waiting on re-verification, or ``None`` when nothing is.

    Read from the case's own sealed ``evidence_current``, so the HTTP API, the CLI
    and the MCP tool give the same answer for the same case. ``reverify`` answers
    "ok" whenever the submission was *accepted*; this says whether it *cleared*
    anything. ``code`` is ``below_validated_tier`` when a required entry was read
    current on evidence under the floor (every verification whose trace has no
    accepted recorder attestation) and ``evidence_not_current`` when coverage did
    not read the entry current at all. ``entries`` maps each outstanding entry to
    the reason recorded for it.
    """
    if not case.required_reverifications:
        return None
    entries = {e: case.evidence_current.get(e, "not_yet_re_verified")
               for e in case.required_reverifications}
    tiers = sorted({r[len(_BELOW):] or "unknown" for r in entries.values()
                    if r.startswith(_BELOW)})
    bound_tiers = sorted({r[len(_BOUND):] or "unknown" for r in entries.values()
                          if r.startswith(_BOUND)})
    waive = ("A decider operator may waive an entry (waive-reverification); that is "
             "recorded as a waiver and never reads as current.")
    if bound_tiers and not tiers:
        return {
            "code": "below_validated_unit_binding",
            "tier_floor": REVERIFICATION_TIER_FLOOR,
            "tiers": bound_tiers,
            "entries": entries,
            "message": (
                f"Not cleared: the evidence is at tier "
                f"{', '.join(repr(t) for t in bound_tiers)} because of its UNIT BINDING, "
                "not because an attestation is missing: it was sealed for another unit key, "
                "or for none (a bundle sealed before bundles recorded one), or the same "
                "recording is already the validated evidence of another unit. Re-seal the "
                "run with the exact unit key as the subject "
                f"({', '.join(case.machines) or 'maker/model#serial'}; "
                "`assurance machine verify --subject <that key>`); the recorder's "
                "attestation is unchanged. The case's checks_skipped names the specific "
                "reason. " + waive),
        }
    if tiers:
        return {
            "code": "below_validated_tier",
            "tier_floor": REVERIFICATION_TIER_FLOOR,
            "tiers": tiers,
            "entries": entries,
            "message": (
                f"Not cleared: the evidence is at tier {', '.join(repr(t) for t in tiers)}, "
                f"below the {REVERIFICATION_TIER_FLOOR!r} floor a re-verification must "
                "reach to clear an entry. A trace's declared provenance is capped at "
                "'community'; a 'validated' verification requires a recorder "
                "attestation accepted under the verifier's own recorder trust list "
                "(a signed statement by a key the verifier trusts over these exact "
                "trace bytes; not proof the recording is physically true), so one is "
                "needed to clear this by evidence. "
                + ("Some of these entries are held down by a unit binding instead: "
                   "re-seal those with the exact unit key as the subject. "
                   if bound_tiers else "") + waive),
        }
    return {
        "code": "evidence_not_current",
        "tier_floor": REVERIFICATION_TIER_FLOOR,
        "tiers": [],
        "entries": entries,
        "message": (
            "Not cleared: the cited verification does not show these entries current "
            "after the change (see the reason per entry). Submit a verification, "
            "sealed after the case opened, that ran every check each function "
            f"declares; even then it must reach {REVERIFICATION_TIER_FLOOR!r}, which "
            "needs a recorder attestation accepted under the verifier's own recorder "
            "trust list. " + waive),
    }


def waive_reverification(
    store: CaseStore, case_id: str, *, entry: str, reason: str, actor: Actor,
) -> ChangeAssuranceCase:
    """A named person closes one re-verification entry *without* evidence.

    The only way a case can reach ready-to-close with an entry that no
    verification cleared, and it is a decision, not a default: it needs a
    person and a reason, it is kept in ``resolved_decisions`` under the entry's
    name, and the entry's ``evidence_current`` reads ``waived`` rather than
    ``current``.
    """
    case = _require(store, case_id, human=True)
    _require_human(actor, "waiving a re-verification")
    if not reason.strip():
        raise CaseTransitionError(
            "a waiver needs a reason: why closing without evidence is acceptable.")
    if case.status.is_settled:
        raise CaseTransitionError(f"{case_id} is already {case.status.value}.")
    if entry not in case.required_reverifications:
        raise CaseTransitionError(f"{case_id} has no outstanding re-verification {entry!r}.")
    updated = replace(
        case,
        required_reverifications=tuple(e for e in case.required_reverifications if e != entry),
        evidence_current={**case.evidence_current, entry: "waived"},
        resolved_decisions=(*case.resolved_decisions, {
            "decision": f"close without re-verification evidence: {entry}",
            "resolution": reason, "by": actor.identifier, "at": format_utc(utc_now()),
            "kind": "waiver"}),
    )
    return store.update(updated, actor=actor,
                        detail=f"re-verification of {entry} waived by {actor.identifier}: {reason}")


def resolve_decision(
    store: CaseStore, case_id: str, *, decision: str, resolution: str, actor: Actor,
) -> ChangeAssuranceCase:
    """A named person answers one of the case's open human decisions.

    The question moves from ``human_decisions_required`` to
    ``resolved_decisions`` with the answer and who gave it, so a later look at
    the same advisory never asks it again. Without this, a case that names a
    human decision could only ever be rejected or deferred.
    """
    case = _require(store, case_id, human=True)
    _require_human(actor, "resolving a human decision")
    if not resolution.strip():
        raise CaseTransitionError("a resolution needs the answer the person gave.")
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
    case = _require(store, case_id, human=True)
    _require_human(actor, "resuming a deferred case")
    if not reason.strip():
        raise CaseTransitionError("resuming a case needs a reason.")
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
    case = _require(store, case_id, human=True)
    _require_human(actor, f"{disposition} a case")
    if not reason.strip():
        raise CaseTransitionError(
            "a decision needs a reason. This is the sentence a reviewer reads "
            "when they ask why a case ended the way it did.")
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


def _require(store: CaseStore, case_id: str, *, human: bool = False) -> ChangeAssuranceCase:
    # First: on a ledger that does not verify a case whose only entry was edited
    # reads as "no such case", which is the wrong thing to say about it.
    # ``human``: a person is about to decide something about this case, so the
    # whole chain is walked rather than trusting the cached check (see
    # CaseStore.require_intact).
    store.require_intact(full=human)
    case = store.get(case_id)
    if case is None:
        raise CaseNotFoundError(case_id)
    return case
