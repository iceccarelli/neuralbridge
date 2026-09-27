"""Case state, kept the way everything else here is kept: append-only.

There is no case table. Every transition — opened, updated by a repeat
observation, reviewed, re-verified, decided — is sealed as its own
:class:`~assurance.core.evidence.Evidence` object in the same
:class:`~assurance.evidence.ledger.EvidenceLedger` the rest of the product
writes to, under ``subject=case_id``. The *current* case is not stored
anywhere; it is the last event's own snapshot, which means a case's whole
history is exactly as reconstructable, exportable and tamper-evident as a
machine passport already is — because it is written by the same ledger, with
the same single-writer guarantee.

Storing the full snapshot on every event rather than a diff is a deliberate
trade of a few kilobytes of duplication for a case that is never at risk of an
un-replayable event: reading is "take the last event for this subject", not
"fold forty years of deltas correctly."
"""

from __future__ import annotations

from dataclasses import replace

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger

from .model import CaseStatus, ChangeAssuranceCase

__all__ = [
    "CASE_KINDS",
    "DECISION_KIND",
    "OPENED_KIND",
    "REVERIFICATION_KIND",
    "TRANSITION_KIND",
    "UPDATED_KIND",
    "CaseStore",
    "CaseStoreError",
]

OPENED_KIND = "assurance.change.opened"
UPDATED_KIND = "assurance.change.updated"
TRANSITION_KIND = "assurance.change.transition"
REVERIFICATION_KIND = "assurance.change.reverification"
DECISION_KIND = "assurance.change.decision"

#: Every kind a case's history can be assembled from. A ledger `entries()`
#: filter that used only ``OPENED_KIND`` would silently drop every case's
#: later chapters.
CASE_KINDS = (OPENED_KIND, UPDATED_KIND, TRANSITION_KIND, REVERIFICATION_KIND, DECISION_KIND)


class CaseStoreError(AssuranceError):
    """A case transition was asked for that the ledger's own history refuses."""


class CaseStore:
    """Read and write ``ChangeAssuranceCase`` state through one ledger."""

    def __init__(self, ledger: EvidenceLedger) -> None:
        self.ledger = ledger

    # -- reading ------------------------------------------------------
    def get(self, case_id: str) -> ChangeAssuranceCase | None:
        """The case as of its most recent sealed, verifying event.

        ``entries()`` already returns oldest-first, so the last matching,
        verifying entry is the current snapshot — no timestamp comparison
        needed, and none trusted from inside a payload that could be forged.
        """
        latest: ChangeAssuranceCase | None = None
        for entry in self.ledger.entries(subject=case_id):
            if entry.kind not in CASE_KINDS:
                continue
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            latest = ChangeAssuranceCase.from_dict(evidence.body["case"])
        return latest

    def list(self, *, status: CaseStatus | None = None) -> list[ChangeAssuranceCase]:
        """The latest snapshot of every case this ledger has ever opened."""
        subjects: dict[str, None] = {}
        for entry in self.ledger.entries():
            if entry.kind in CASE_KINDS:
                subjects[entry.subject] = None
        out = []
        for case_id in subjects:
            case = self.get(case_id)
            if case is not None and (status is None or case.status is status):
                out.append(case)
        return sorted(out, key=lambda c: c.opened_at)

    # -- writing --------------------------------------------------------
    def _seal_and_append(
        self, case: ChangeAssuranceCase, kind: str, *, actor: Actor, detail: str,
    ) -> ChangeAssuranceCase:
        now = format_utc(utc_now())
        history = (*case.history, {"kind": kind, "at": now, "detail": detail})
        stamped = replace(case, updated_at=now, history=history)

        evidence = Evidence(
            kind=kind,
            body={"case": stamped.to_dict()},
            actor=actor,
            origin=Origin(
                system="assurance.change",
                reference=stamped.case_id,
                method=f"{stamped.trigger_type.value}:{stamped.trigger_id}",
            ),
            validation_state=(
                ValidationState.VERIFIED if kind == DECISION_KIND
                else ValidationState.UNVERIFIED
            ),
            confidence=Confidence.HIGH if stamped.confidence == "high"
            else Confidence.MEDIUM if stamped.confidence == "medium"
            else Confidence.LOW if stamped.confidence == "low" else Confidence.NONE,
            checks_skipped=stamped.checks_skipped,
        ).seal()
        self.ledger.append(evidence, subject=stamped.case_id)
        return stamped

    def open(self, case: ChangeAssuranceCase, *, actor: Actor, detail: str) -> ChangeAssuranceCase:
        if case.status is not CaseStatus.OPEN:
            raise CaseStoreError(
                f"a case is opened as OPEN, not {case.status.value}. "
                "Build it with the status service.assess_* already computed, "
                "then open() it once."
            )
        return self._seal_and_append(case, OPENED_KIND, actor=actor, detail=detail)

    def update(self, case: ChangeAssuranceCase, *, actor: Actor, detail: str) -> ChangeAssuranceCase:
        """A repeat observation of the same open trigger. Not a new case."""
        return self._seal_and_append(case, UPDATED_KIND, actor=actor, detail=detail)

    def transition(self, case: ChangeAssuranceCase, *, actor: Actor, detail: str) -> ChangeAssuranceCase:
        return self._seal_and_append(case, TRANSITION_KIND, actor=actor, detail=detail)

    def reverify(self, case: ChangeAssuranceCase, *, actor: Actor, detail: str) -> ChangeAssuranceCase:
        return self._seal_and_append(case, REVERIFICATION_KIND, actor=actor, detail=detail)

    def decide(self, case: ChangeAssuranceCase, *, actor: Actor, detail: str) -> ChangeAssuranceCase:
        return self._seal_and_append(case, DECISION_KIND, actor=actor, detail=detail)
