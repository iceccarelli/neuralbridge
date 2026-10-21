"""Rebuild a case from the ledger alone, and check it kept the rules on the way.

"A case's state is reconstructable from the authoritative record" is a claim
that is easy to make and rarely tested. :func:`reconstruct_case` makes it
checkable: it reads only the case's own ledger entries, verifies each one's
sealed evidence, folds them oldest-first into the case a reader would see, and
replays every step against the state machine — reporting any entry that the
lifecycle would not have allowed, that does not verify, that rewrote history,
or that records a decision by something other than a named person.

It deliberately shares no code path with :class:`~assurance.change.store.CaseStore`
beyond reading the same ledger, so agreement between the two is evidence and
not tautology. The result is a report, not a repair: a case with violations is
exactly as it was sealed, and the report says which entry to look at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from assurance.change.model import CaseStatus, ChangeAssuranceCase
from assurance.change.store import (
    CASE_KINDS,
    DECISION_KIND,
    OPENED_KIND,
    REOPENED_KIND,
    REVERIFICATION_KIND,
    TRANSITION_KIND,
    UPDATED_KIND,
)
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import BUNDLE_KIND

__all__ = ["CaseReplay", "reconstruct_case"]

S = CaseStatus
_OPEN_STATES = (S.OPEN, S.IN_REVIEW, S.AWAITING_ACTION, S.AWAITING_REVERIFICATION,
                S.READY_TO_CLOSE)

#: Every (previous status, next status) pair each kind of entry may record.
_LEGAL: dict[str, set[tuple[CaseStatus, CaseStatus]]] = {
    TRANSITION_KIND: {
        (S.OPEN, S.IN_REVIEW),
        (S.IN_REVIEW, S.AWAITING_ACTION),
        (S.IN_REVIEW, S.AWAITING_REVERIFICATION),
        (S.IN_REVIEW, S.READY_TO_CLOSE),
        (S.AWAITING_ACTION, S.AWAITING_REVERIFICATION),
        (S.AWAITING_ACTION, S.READY_TO_CLOSE),
        (S.DEFERRED, S.IN_REVIEW),
        # Only once nothing is left to re-verify: the work lists must already
        # be empty, which the work-list rules enforce by forbidding a shrink here.
        (S.AWAITING_REVERIFICATION, S.READY_TO_CLOSE),
        (S.AWAITING_REVERIFICATION, S.AWAITING_ACTION),
    },
    REVERIFICATION_KIND: {
        (S.AWAITING_REVERIFICATION, S.AWAITING_REVERIFICATION),
        (S.AWAITING_REVERIFICATION, S.READY_TO_CLOSE),
        (S.AWAITING_REVERIFICATION, S.AWAITING_ACTION),
    },
    DECISION_KIND: {
        *((s, S.REJECTED) for s in _OPEN_STATES),
        *((s, S.DEFERRED) for s in _OPEN_STATES),
        (S.READY_TO_CLOSE, S.CLOSED),
    },
    REOPENED_KIND: {(S.CLOSED, S.OPEN), (S.REJECTED, S.OPEN)},
    UPDATED_KIND: {
        *((s, s) for s in _OPEN_STATES),
        (S.DEFERRED, S.DEFERRED),            # a growing advisory exposure, recorded
        (S.READY_TO_CLOSE, S.AWAITING_REVERIFICATION),
        (S.READY_TO_CLOSE, S.AWAITING_ACTION),
    },
}


@dataclass(frozen=True)
class CaseReplay:
    """What the ledger alone says about one case, and whether it can be trusted."""

    case_id: str
    #: The last entry that verified, as a case. ``None`` if none did.
    case: ChangeAssuranceCase | None
    entries: int
    #: One sentence per problem, each naming the ledger sequence number.
    violations: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.case is not None and not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "ok": self.ok, "entries": self.entries,
                "violations": list(self.violations),
                "case": self.case.to_dict() if self.case else None}

    def summary(self) -> str:
        head = (f"{self.case_id}: {self.entries} ledger entr"
                f"{'y' if self.entries == 1 else 'ies'}, "
                f"{self.case.status.value if self.case else 'no usable state'}")
        if self.ok:
            return head + " — every entry verifies and every step was legal."
        return "\n".join([head + " — DOES NOT REPLAY CLEANLY:",
                          *(f"  - {v}" for v in self.violations)])


def reconstruct_case(
    ledger: EvidenceLedger, case_id: str, *, check_chain: bool = True,
) -> CaseReplay:
    """Fold a case's ledger entries into its state and replay each step."""
    violations: list[str] = []
    if check_chain:
        ok, problems = ledger.verify_chain()
        if not ok:
            violations.extend(f"ledger chain: {p}" for p in problems)

    state: ChangeAssuranceCase | None = None
    count = 0
    cycle_start = 0
    for entry in ledger.entries(subject=case_id):
        if entry.kind not in CASE_KINDS:
            continue
        count += 1
        where = f"seq {entry.seq} ({entry.kind})"
        evidence = entry.evidence()
        if not evidence.verify():
            violations.append(f"{where}: sealed evidence does not verify; "
                              "excluded from the reconstructed state.")
            continue
        if evidence.content_hash != entry.content_hash:
            violations.append(f"{where}: the ledger link names content "
                              f"{entry.content_hash[:12]} but the payload hashes to "
                              f"{evidence.content_hash[:12]}; excluded.")
            continue
        try:
            snap = ChangeAssuranceCase.from_dict(evidence.body["case"])
        except (KeyError, ValueError, TypeError) as exc:
            violations.append(f"{where}: payload is not a case ({exc}); excluded.")
            continue

        if evidence.kind != entry.kind:
            violations.append(f"{where}: the ledger files this as {entry.kind} but the "
                              f"evidence was sealed as {evidence.kind}; excluded.")
            continue

        violations.extend(_check_step(where, entry.kind, state, snap, evidence.actor.kind,
                                      evidence.actor.identifier, case_id))
        if entry.kind == REVERIFICATION_KIND and state is not None:
            violations.extend(_check_reverification(ledger, where, state, snap, cycle_start))
        if entry.kind in (OPENED_KIND, REOPENED_KIND):
            cycle_start = entry.seq
        state = snap

    if count == 0:
        violations.append(f"no ledger entries for {case_id!r}.")
    return CaseReplay(case_id=case_id, case=state, entries=count,
                      violations=tuple(violations))


def _check_step(
    where: str, kind: str, prev: ChangeAssuranceCase | None, snap: ChangeAssuranceCase,
    actor_kind: str, actor_id: str, subject: str,
) -> list[str]:
    out: list[str] = []
    if snap.case_id != subject:
        out.append(f"{where}: filed under {subject} but the case inside says "
                   f"{snap.case_id}.")

    # -- the state machine -------------------------------------------------
    if prev is None:
        if kind != OPENED_KIND:
            out.append(f"{where}: the first entry for a case must be an opening, "
                       f"not {kind}.")
        elif snap.status is not S.OPEN:
            out.append(f"{where}: a case is opened as open, not {snap.status.value}.")
    else:
        if kind == OPENED_KIND:
            out.append(f"{where}: a second opening for a case that already exists.")
        elif (prev.status, snap.status) not in _LEGAL.get(kind, set()):
            out.append(f"{where}: {prev.status.value} -> {snap.status.value} is not "
                       f"a move a {kind.rsplit('.', 1)[-1]} entry can make.")
        if (snap.trigger_type, snap.trigger_id) != (prev.trigger_type, prev.trigger_id):
            out.append(f"{where}: the trigger changed from "
                       f"{prev.trigger_type.value}/{prev.trigger_id} to "
                       f"{snap.trigger_type.value}/{snap.trigger_id}.")
        # -- history is append-only, and a closure is never erased ----------
        if snap.history[:len(prev.history)] != prev.history:
            out.append(f"{where}: the case's history was rewritten, not appended to.")
        if len(snap.history) != len(prev.history) + 1:
            out.append(f"{where}: history grew by {len(snap.history) - len(prev.history)}"
                       " entries, expected exactly 1.")
        if snap.prior_closures[:len(prev.prior_closures)] != prev.prior_closures:
            out.append(f"{where}: a recorded prior closure was altered or dropped.")
    if snap.history and snap.history[-1].get("kind") != kind:
        out.append(f"{where}: its own history says the last event was "
                   f"{snap.history[-1].get('kind')}.")

    # -- work only goes away through the entries that are allowed to remove it --
    if prev is not None:
        out.extend(_check_work_lists(where, kind, prev, snap))

    # -- the guards a snapshot must satisfy wherever it sits ----------------
    if snap.status in (S.READY_TO_CLOSE, S.CLOSED):
        if snap.required_reverifications:
            out.append(f"{where}: {snap.status.value} while re-verification of "
                       f"{', '.join(snap.required_reverifications)} is outstanding.")
        if snap.human_decisions_required:
            out.append(f"{where}: {snap.status.value} with "
                       f"{len(snap.human_decisions_required)} human decision(s) open.")
    if snap.status is S.CLOSED:
        if snap.decision != "closed" or not snap.decision_by or not snap.decision_reason \
                or not snap.closed_at:
            out.append(f"{where}: closed without a recorded decision, decider, "
                       "reason and time.")
        if snap.decision_by and snap.decision_by != actor_id:
            out.append(f"{where}: closed by {snap.decision_by!r} but sealed by "
                       f"{actor_id!r}.")

    # -- only a person decides ----------------------------------------------
    decided = kind == DECISION_KIND or (
        prev is not None and prev.status is S.DEFERRED and snap.status is S.IN_REVIEW) or (
        prev is not None and len(snap.resolved_decisions) > len(prev.resolved_decisions))
    if decided and actor_kind.strip().lower() != "person":
        out.append(f"{where}: a decision recorded by {actor_id!r}, kind "
                   f"{actor_kind!r}, which is not a named person.")
    return out


def _pre_work(case: ChangeAssuranceCase) -> bool:
    """Nothing re-verified yet, so a fresh reading may replace the work lists."""
    return case.status in (S.OPEN, S.IN_REVIEW) and not case.reverified_at


def _check_work_lists(
    where: str, kind: str, prev: ChangeAssuranceCase, snap: ChangeAssuranceCase,
) -> list[str]:
    """Required work may leave a case only on an entry that has the standing to
    remove it: a ``reverification`` (re-verifications and actions), a person's
    resolution or waiver (named in ``resolved_decisions``), a fresh reading
    before any work started, or a reopening. A plain transition that quietly
    empties the lists is how a case would be walked to ``ready_to_close``
    without anyone doing anything."""
    out: list[str] = []
    if kind == REOPENED_KIND:
        return out
    short = kind.rsplit(".", 1)[-1]
    resolved_now = {r.get("decision") for r in snap.resolved_decisions}
    grew = len(snap.resolved_decisions) > len(prev.resolved_decisions)
    free = kind == UPDATED_KIND and _pre_work(prev)

    gone_rev = set(prev.required_reverifications) - set(snap.required_reverifications)
    if gone_rev and not free and kind != REVERIFICATION_KIND:
        unwaived = [e for e in gone_rev
                    if not (grew and f"close without re-verification evidence: {e}"
                            in resolved_now)]
        if unwaived:
            out.append(f"{where}: re-verification of {', '.join(sorted(unwaived))} was "
                       f"removed by a {short} entry, which cannot remove it (only a "
                       "re-verification, or a person's recorded waiver, can).")
    gone_act = set(prev.required_actions) - set(snap.required_actions)
    if gone_act and not free and kind != REVERIFICATION_KIND:
        out.append(f"{where}: {len(gone_act)} required action(s) were removed by a "
                   f"{short} entry, which cannot remove them.")
    gone_dec = set(prev.human_decisions_required) - set(snap.human_decisions_required)
    if gone_dec and not free:
        unresolved = [d for d in gone_dec if d not in resolved_now]
        if unresolved:
            out.append(f"{where}: {len(unresolved)} human decision(s) were removed "
                       "without a recorded resolution.")
    if kind in (TRANSITION_KIND, DECISION_KIND) and snap.evidence_current != prev.evidence_current:
        out.append(f"{where}: a {short} entry changed the recorded evidence state, "
                   "which only a re-verification can do.")
    return out


def _check_reverification(
    ledger: EvidenceLedger, where: str, prev: ChangeAssuranceCase,
    snap: ChangeAssuranceCase, cycle_start: int,
) -> list[str]:
    """A re-verification entry must cite real, post-trigger evidence."""
    out: list[str] = []
    new_links = [r for r in snap.linked_evidence
                 if r not in prev.linked_evidence and r.get("relation") == "supports"]
    if not snap.reverified_at:
        out.append(f"{where}: a re-verification entry that does not record when it "
                   "was re-verified (reverified_at).")
    if not new_links:
        out.append(f"{where}: a re-verification entry that cites no 'supports' evidence.")
    for link in new_links:
        h = link.get("content_hash", "")
        found = [e for e in ledger.entries(kind=BUNDLE_KIND) if e.content_hash == h]
        if not found:
            out.append(f"{where}: it cites {h[:12]!r}, which is not a sealed verification "
                       "in this ledger.")
        elif not any(e.seq > cycle_start and e.subject in snap.machines for e in found):
            out.append(f"{where}: it cites verification {h[:12]}, which was sealed before "
                       "the case's current cycle began or for a machine the case does "
                       "not concern.")
    return out
