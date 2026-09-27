"""``ChangeAssuranceCase`` — the orchestration layer, not a new source of truth.

Three things already tell a customer that a machine changed:
:func:`assurance.machinery.divergence.compare` (a manifest no longer matches
its baseline), :func:`assurance.fleet.impact.assess_impact` (a supplier
advisory now touches this fleet), and an
:class:`assurance.machinery.intervention.Intervention` record (somebody
changed something and said so). Each answers its own question and stops.
Nobody was ever shown the sentence that actually matters:

    this changed, here is what it means for the machine, here is what has to
    happen before anyone can say it is covered again, and here is who has to
    decide that.

A ``ChangeAssuranceCase`` is that sentence, kept alive from the moment the
change is detected until a named person closes it. It duplicates none of the
three engines above — every field on it is either copied verbatim from their
output or is bookkeeping about the human workflow around it (owner, status,
timestamps, a decision). See :mod:`assurance.change.service` for how a case is
built, and :mod:`assurance.change.store` for how it is kept — one entry per
state transition in the same hash-chained ledger everything else here uses,
never a table that can be edited in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from assurance.core.identity import parse_utc, utc_now

__all__ = [
    "CaseStatus",
    "ChangeAssuranceCase",
    "TriggerType",
]


class TriggerType(StrEnum):
    """The three ways a case comes to exist. Nothing here is user-created."""

    #: A watch or a direct ``compare()`` found a safety-relevant configuration
    #: change on one machine.
    MACHINE_DRIFT = "machine_drift"
    #: A supplier advisory now exposes standing evidence on one or more
    #: machines in the fleet.
    SUPPLIER_ADVISORY = "supplier_advisory"
    #: A recorded intervention invalidated evidence for a safety function.
    INTERVENTION = "intervention"


class CaseStatus(StrEnum):
    """The lifecycle. Six ordinary stops and two ways a human ends it early.

    ``OPEN -> IN_REVIEW -> AWAITING_ACTION -> AWAITING_REVERIFICATION ->
    READY_TO_CLOSE -> CLOSED`` is the path a case takes when everything the
    deterministic engines found needs real work. Nothing here skips a stop
    that has work outstanding: :mod:`assurance.change.service` computes which
    stops apply from the same evidence the case carries, never from a guess.
    """

    OPEN = "open"
    IN_REVIEW = "in_review"
    AWAITING_ACTION = "awaiting_action"
    AWAITING_REVERIFICATION = "awaiting_reverification"
    READY_TO_CLOSE = "ready_to_close"
    CLOSED = "closed"
    #: A human looked and decided this case does not describe a real problem.
    REJECTED = "rejected"
    #: A human looked and is deliberately not acting yet. Not closed: the
    #: case still needs the same eventual decision, just not today.
    DEFERRED = "deferred"

    @property
    def is_closed(self) -> bool:
        """True only for the one disposition that says the matter is settled.

        ``REJECTED`` and ``DEFERRED`` are both human dispositions, and neither
        is a claim that the underlying evidence question was answered — the
        rule the whole product exists to enforce: only ``CLOSED``, reached
        from ``READY_TO_CLOSE``, means the required evidence actually stands.
        """
        return self is CaseStatus.CLOSED

    @property
    def is_settled(self) -> bool:
        """``CLOSED``, ``REJECTED`` or ``DEFERRED`` — nothing left to detect twice.

        Used only to decide whether a *recurring* observation of the same
        trigger should update this case or leave it alone; a settled case is
        not reopened by a watch run seeing the same thing again.
        """
        return self in (CaseStatus.CLOSED, CaseStatus.REJECTED, CaseStatus.DEFERRED)


@dataclass(frozen=True)
class ChangeAssuranceCase:
    """One machine change, its consequence, and where the case for it stands.

    Every field naming a fact about the machine or its evidence is produced by
    an existing engine and copied in — see the docstrings on
    :mod:`assurance.change.service`. Every field naming a person, a status or a
    timestamp belongs to the workflow this module adds.
    """

    case_id: str
    trigger_type: TriggerType
    trigger_id: str
    status: CaseStatus

    #: One or more machines this case concerns. A drift case names one; a
    #: supplier-advisory case may name every machine the advisory reaches.
    machines: tuple[str, ...] = ()
    sites: tuple[str, ...] = ()

    #: What changed, each item a dict shaped like
    #: :meth:`assurance.machinery.divergence.Change.to_dict`, or the fleet
    #: exposure a supplier advisory produced.
    changed_items: tuple[dict[str, Any], ...] = ()
    #: The worst severity among ``changed_items`` — ``safety_relevant`` is the
    #: only one this module ever opens a case for.
    change_severity: str = ""
    affected_functions: tuple[str, ...] = ()

    before_hash: str = ""
    after_hash: str = ""
    #: function_id -> coverage state (``current`` | ``stale`` | ... ), before
    #: and after this change, straight from
    #: :func:`assurance.machinery.staleness.assess_coverage`.
    evidence_before: dict[str, str] = field(default_factory=dict)
    evidence_current: dict[str, str] = field(default_factory=dict)
    last_valid_verification: str = ""
    invalidation_reason: str = ""

    #: Deterministic, engine-justified next steps. Never free text invented
    #: by an LLM — see :mod:`assurance.change.service` for how each line here
    #: is derived from a specific coverage or impact finding.
    required_actions: tuple[str, ...] = ()
    #: Safety function ids that still need a fresh verification bundle before
    #: this case can reach ``READY_TO_CLOSE``.
    required_reverifications: tuple[str, ...] = ()
    human_decisions_required: tuple[str, ...] = ()

    owner: str = ""
    reviewer: str = ""

    opened_at: str = ""
    review_started_at: str = ""
    reverification_requested_at: str = ""
    reverified_at: str = ""
    closed_at: str = ""

    #: "" | "closed" | "rejected" | "deferred" — set only by
    #: :func:`assurance.change.service.decide`, never inferred.
    decision: str = ""
    decision_reason: str = ""
    decision_by: str = ""

    #: Typed edges to other evidence in the ledger: the divergence report, the
    #: impact report, the reverification bundle. ``{relation, content_hash,
    #: note}``, the same shape as :class:`assurance.core.evidence.EvidenceRef`.
    linked_evidence: tuple[dict[str, str], ...] = ()

    checks_skipped: tuple[str, ...] = ()
    confidence: str = ""
    #: Which engine produced which fact, so a reviewer can tell "the change
    #: detection" from "the coverage join" from "the advisory fan-out" without
    #: reading source.
    provenance: dict[str, str] = field(default_factory=dict)

    created_at: str = ""
    updated_at: str = ""
    #: One entry per ledger event this case has been through, oldest first —
    #: the timeline a case detail page renders. ``{"kind", "at", "detail"}``.
    history: tuple[dict[str, str], ...] = ()

    @property
    def is_open(self) -> bool:
        return not self.status.is_settled

    @property
    def age_days(self) -> int:
        if not self.opened_at:
            return 0
        try:
            return max(0, (utc_now() - parse_utc(self.opened_at)).days)
        except (ValueError, TypeError):
            return 0

    def next_action(self) -> str:
        """The single line that answers "what do I need to deal with right now".

        This is the primary UI this product exists to produce — see
        ``deploy/assurance/CHANGE.md`` — and it is never invented text: each
        branch names the concrete field a reviewer would otherwise have to
        find themselves.
        """
        if self.status is CaseStatus.OPEN:
            return "Assign an owner and start the review."
        if self.status is CaseStatus.IN_REVIEW:
            return "Confirm the action plan below to move this case forward."
        if self.status is CaseStatus.AWAITING_ACTION:
            first = self.required_actions[0] if self.required_actions else \
                "Complete the required action."
            return first
        if self.status is CaseStatus.AWAITING_REVERIFICATION:
            if self.required_reverifications:
                return ("Re-verify " + ", ".join(self.required_reverifications)
                        + " and submit the result.")
            return "Submit the pending re-verification result."
        if self.status is CaseStatus.READY_TO_CLOSE:
            return "Evidence is current. A human decision is required to close this case."
        if self.status is CaseStatus.DEFERRED:
            return "Deferred. Resume the review when ready."
        if self.status is CaseStatus.REJECTED:
            return f"Rejected: {self.decision_reason or 'no reason recorded'}."
        return f"Closed by {self.decision_by or 'unknown'}: {self.decision_reason}."

    def row(self) -> dict[str, Any]:
        """One line of the Active Assurance Cases queue."""
        return {
            "case_id": self.case_id,
            "machines": list(self.machines),
            "trigger": self.trigger_type.value,
            "opened_at": self.opened_at,
            "changed": [c.get("detail", c.get("item_id", "")) for c in self.changed_items][:3],
            "affected_functions": list(self.affected_functions),
            "evidence_state": sorted(set(self.evidence_current.values())) or ["n/a"],
            "status": self.status.value,
            "owner": self.owner,
            "next_action": self.next_action(),
            "age_days": self.age_days,
        }

    def summary(self) -> str:
        """The case detail page, as text — the terminal-first shape every
        other report in this product already takes (``assurance report``,
        ``assurance machinery coverage``)."""
        lines = [
            f"case {self.case_id}  [{self.status.value.upper()}]",
            f"  trigger    {self.trigger_type.value} / {self.trigger_id}",
            f"  machine(s) {', '.join(self.machines) or '(none named)'}",
        ]
        if self.before_hash or self.after_hash:
            lines.append(f"  config     {self.before_hash[:12] or '—'} -> "
                         f"{self.after_hash[:12] or '—'}")
        lines.append("")
        lines.append("  what changed:")
        for c in self.changed_items:
            lines.append(f"    - {c.get('detail', c)}")
        if not self.changed_items:
            lines.append("    (nothing recorded)")
        lines.append("")
        lines.append(f"  affected safety functions: "
                     f"{', '.join(self.affected_functions) or '(none)'}")
        lines.append("  evidence state:")
        for fid in self.affected_functions:
            before = self.evidence_before.get(fid, "?")
            current = self.evidence_current.get(fid, "?")
            lines.append(f"    {fid}: {before} -> {current}")
        if self.invalidation_reason:
            lines.append(f"  invalidated because: {self.invalidation_reason}")
        lines.append("")
        lines.append("  required actions:")
        for a in self.required_actions:
            lines.append(f"    [ ] {a}")
        if not self.required_actions:
            lines.append("    (none outstanding)")
        if self.human_decisions_required:
            lines.append("  human decisions required:")
            for d in self.human_decisions_required:
                lines.append(f"    ? {d}")
        lines.append("")
        lines.append(f"  owner: {self.owner or '(unassigned)'}   "
                     f"reviewer: {self.reviewer or '—'}")
        lines.append(f"  next action: {self.next_action()}")
        if self.checks_skipped:
            lines.append("")
            lines.append("  not established by this case:")
            for gap in self.checks_skipped:
                lines.append(f"    - {gap}")
        lines.append("")
        lines.append("  timeline:")
        for h in self.history:
            lines.append(f"    {h.get('at', '')}  {h.get('kind', '')}  {h.get('detail', '')}")
        if self.linked_evidence:
            lines.append("")
            lines.append("  linked evidence:")
            for ref in self.linked_evidence:
                lines.append(f"    {ref.get('relation', '')}: "
                             f"{ref.get('content_hash', '')[:16]}  {ref.get('note', '')}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "trigger_type": self.trigger_type.value,
            "trigger_id": self.trigger_id,
            "status": self.status.value,
            "machines": list(self.machines),
            "sites": list(self.sites),
            "changed_items": list(self.changed_items),
            "change_severity": self.change_severity,
            "affected_functions": list(self.affected_functions),
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "evidence_before": dict(self.evidence_before),
            "evidence_current": dict(self.evidence_current),
            "last_valid_verification": self.last_valid_verification,
            "invalidation_reason": self.invalidation_reason,
            "required_actions": list(self.required_actions),
            "required_reverifications": list(self.required_reverifications),
            "human_decisions_required": list(self.human_decisions_required),
            "owner": self.owner,
            "reviewer": self.reviewer,
            "opened_at": self.opened_at,
            "review_started_at": self.review_started_at,
            "reverification_requested_at": self.reverification_requested_at,
            "reverified_at": self.reverified_at,
            "closed_at": self.closed_at,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "decision_by": self.decision_by,
            "linked_evidence": [dict(r) for r in self.linked_evidence],
            "checks_skipped": list(self.checks_skipped),
            "confidence": self.confidence,
            "provenance": dict(self.provenance),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "history": [dict(h) for h in self.history],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChangeAssuranceCase:
        return cls(
            case_id=str(d["case_id"]),
            trigger_type=TriggerType(d["trigger_type"]),
            trigger_id=str(d["trigger_id"]),
            status=CaseStatus(d["status"]),
            machines=tuple(d.get("machines", ())),
            sites=tuple(d.get("sites", ())),
            changed_items=tuple(d.get("changed_items", ())),
            change_severity=str(d.get("change_severity", "")),
            affected_functions=tuple(d.get("affected_functions", ())),
            before_hash=str(d.get("before_hash", "")),
            after_hash=str(d.get("after_hash", "")),
            evidence_before=dict(d.get("evidence_before", {})),
            evidence_current=dict(d.get("evidence_current", {})),
            last_valid_verification=str(d.get("last_valid_verification", "")),
            invalidation_reason=str(d.get("invalidation_reason", "")),
            required_actions=tuple(d.get("required_actions", ())),
            required_reverifications=tuple(d.get("required_reverifications", ())),
            human_decisions_required=tuple(d.get("human_decisions_required", ())),
            owner=str(d.get("owner", "")),
            reviewer=str(d.get("reviewer", "")),
            opened_at=str(d.get("opened_at", "")),
            review_started_at=str(d.get("review_started_at", "")),
            reverification_requested_at=str(d.get("reverification_requested_at", "")),
            reverified_at=str(d.get("reverified_at", "")),
            closed_at=str(d.get("closed_at", "")),
            decision=str(d.get("decision", "")),
            decision_reason=str(d.get("decision_reason", "")),
            decision_by=str(d.get("decision_by", "")),
            linked_evidence=tuple(dict(r) for r in d.get("linked_evidence", ())),
            checks_skipped=tuple(d.get("checks_skipped", ())),
            confidence=str(d.get("confidence", "")),
            provenance=dict(d.get("provenance", {})),
            created_at=str(d.get("created_at", "")),
            updated_at=str(d.get("updated_at", "")),
            history=tuple(dict(h) for h in d.get("history", ())),
        )
