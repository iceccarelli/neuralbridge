"""One customer question — *what does this change mean for this machine* —
answered by composing engines that already exist and are already tested.

This module invents no evidence model, no machine model, and no matching or
staleness algorithm. It reads :mod:`assurance.fleet.advisory` (does the change
match this machine's items), :mod:`assurance.machinery.staleness` (does
standing evidence still cover each safety function) and
:mod:`assurance.fleet.impact` (the same question fanned across every enrolled
machine), and turns their three separate answers into one verdict a customer
who has never heard of a ledger can act on.

Two shapes of the same question:

``run_ad_hoc_check`` — no ledger. The advisory and the manifest given are all
there is. It can say whether the change matches this manifest today. It
cannot say whether standing safety evidence for this machine is still valid,
because that needs interventions and verification bundles, and those live in
a ledger this call was not given. This is the free, no-account path, and the
narrower answer is said explicitly rather than guessed past.

``run_enrolled_check`` — a ledger, and a machine already enrolled in it. The
match is combined with :func:`assurance.machinery.staleness.assess_coverage`
(this machine's own interventions and verification bundles) and, when a
change is given, :func:`assurance.fleet.impact.assess_impact` across every
other enrolled machine. This is the paid path: what makes it worth more than
the free one is exactly the ledger history it reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory, match_item
from assurance.fleet.impact import ImpactReport, assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.staleness import Coverage, CoverageReport

__all__ = [
    "AssuranceVerdict",
    "CheckError",
    "MachineAssuranceCheck",
    "run_ad_hoc_check",
    "run_enrolled_check",
]


class CheckError(AssuranceError):
    """The check was asked a question it has nothing to answer with."""


class AssuranceVerdict(StrEnum):
    """The customer-facing answer. Never collapsed to safe/affected.

    Ranked worst-first, so a reader scanning many checks can sort on it.
    """

    REQUIRES_HUMAN_REVIEW = "requires_human_review"
    REQUIRES_REVERIFICATION = "requires_reverification"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    POTENTIALLY_AFFECTED = "potentially_affected"
    CANNOT_DETERMINE = "cannot_determine"
    NO_IMPACT_FOUND = "no_impact_found"
    VERIFIED = "verified"

    @property
    def rank(self) -> int:
        return {
            "requires_human_review": 0, "requires_reverification": 1,
            "insufficient_evidence": 2, "potentially_affected": 3,
            "cannot_determine": 4, "no_impact_found": 5, "verified": 6,
        }[self.value]


@dataclass(frozen=True)
class MachineAssuranceCheck:
    """The canonical result: what changed, what it affects, what to do next."""

    machine_key: str
    verdict: AssuranceVerdict
    enrolled: bool
    advisory_evaluated: bool
    matches: tuple[dict[str, Any], ...]
    functions: tuple[dict[str, Any], ...]
    evidence_valid: int
    evidence_stale: int
    evidence_insufficient: int
    evidence_cannot_determine: int
    required_actions: tuple[str, ...]
    human_review_required: bool
    interventions: tuple[dict[str, Any], ...]
    latest_intervention: dict[str, Any] | None
    fleet_machines_analyzed: int | None
    fleet_machines_affected: int | None
    assessed_at: str
    checks_skipped: tuple[str, ...] = field(default_factory=tuple)

    @property
    def affected(self) -> bool:
        return self.verdict not in (
            AssuranceVerdict.NO_IMPACT_FOUND, AssuranceVerdict.VERIFIED,
        )

    @property
    def next_action(self) -> str:
        return _next_action(self.verdict, self.enrolled)[0]

    @property
    def next_action_endpoint(self) -> str | None:
        return _next_action(self.verdict, self.enrolled)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "verdict": self.verdict.value,
            "enrolled": self.enrolled,
            "advisory_evaluated": self.advisory_evaluated,
            "affected": self.affected,
            "matches": list(self.matches),
            "functions": list(self.functions),
            "evidence": {
                "valid": self.evidence_valid,
                "stale": self.evidence_stale,
                "insufficient": self.evidence_insufficient,
                "cannot_determine": self.evidence_cannot_determine,
            },
            "commercial_next_action": {
                "action": self.next_action,
                "endpoint": self.next_action_endpoint,
            },
            "required_actions": list(self.required_actions),
            "human_review_required": self.human_review_required,
            "interventions": list(self.interventions),
            "latest_intervention": self.latest_intervention,
            "fleet": {
                "machines_analyzed": self.fleet_machines_analyzed,
                "machines_affected": self.fleet_machines_affected,
            } if self.fleet_machines_analyzed is not None else None,
            "assessed_at": self.assessed_at,
            "checks_skipped": list(self.checks_skipped),
        }


# Every action here names an endpoint (or site page) that exists and does
# what the action says today — never a purchase or capability this codebase
# cannot execute. "none" means the check already answered the question this
# result can answer; there is nothing further to buy for it.
_DEFAULT_NEXT_ACTION: dict[AssuranceVerdict, tuple[str, str | None]] = {
    AssuranceVerdict.NO_IMPACT_FOUND: ("enroll_machine", "POST /v1/machinery/manifest"),
    AssuranceVerdict.POTENTIALLY_AFFECTED: ("enroll_machine", "POST /v1/machinery/manifest"),
    AssuranceVerdict.REQUIRES_REVERIFICATION: ("verify_machine", "POST /v1/machine/verify"),
    AssuranceVerdict.INSUFFICIENT_EVIDENCE: ("verify_machine", "POST /v1/machine/verify"),
    # No purchasable human-review service exists in this codebase yet — the
    # honest next step is the real sales channel, not a fabricated checkout.
    AssuranceVerdict.REQUIRES_HUMAN_REVIEW: ("contact_sales", "/contact"),
    AssuranceVerdict.CANNOT_DETERMINE: ("provide_more_evidence", None),
    AssuranceVerdict.VERIFIED: ("none", None),
}

# Overrides for a machine that is already enrolled: the free "go enrol it"
# action makes no sense once the ledger already has this machine.
_ENROLLED_OVERRIDES: dict[AssuranceVerdict, tuple[str, str | None]] = {
    AssuranceVerdict.NO_IMPACT_FOUND: ("none", None),
    AssuranceVerdict.POTENTIALLY_AFFECTED: (
        "generate_report", "GET /v1/fleet/report",
    ),
}


def _next_action(verdict: AssuranceVerdict, enrolled: bool) -> tuple[str, str | None]:
    if enrolled and verdict in _ENROLLED_OVERRIDES:
        return _ENROLLED_OVERRIDES[verdict]
    return _DEFAULT_NEXT_ACTION[verdict]


def _intervention_summary(intervention: Intervention) -> dict[str, Any]:
    return {
        "intervention_id": intervention.intervention_id,
        "occurred_at": format_utc(intervention.occurred_at),
        "performed_by": intervention.performed_by.identifier,
        "kind": intervention.kind.value,
        "item_id": intervention.item_id,
        "affects_functions": list(intervention.affects_functions),
        "revalidated": intervention.is_revalidated,
    }


def _match_manifest(manifest: SafetyManifest, advisory: ComponentAdvisory) -> tuple[
    list[dict[str, Any]], bool,
]:
    """The item-level match, exactly as the free advisory-check route computes it."""
    matches: list[dict[str, Any]] = []
    needs_a_human = False
    for item in manifest.items:
        matched = match_item(advisory, item)
        if matched is None:
            continue
        basis, detail = matched
        if basis.needs_a_human:
            needs_a_human = True
        matches.append({
            "item_id": item.item_id,
            "item_name": item.name,
            "item_version": item.version,
            "basis": basis.value,
            "confidence": basis.confidence,
            "needs_a_human": basis.needs_a_human,
            "detail": detail,
            "implements": list(item.implements),
        })
    return matches, needs_a_human


def _tally(coverage: CoverageReport | None) -> tuple[
    list[dict[str, Any]], int, int, int, int, list[str],
]:
    """Fold a coverage report into the four evidence buckets a customer reads.

    ``stale``/``failing`` are both work to do, so both land in
    ``required_actions``; ``never_verified`` has no prior evidence to lose, so
    it is reported as insufficient rather than as work a change caused.
    """
    functions: list[dict[str, Any]] = []
    valid = stale = insufficient = cannot_determine = 0
    required: list[str] = []
    if coverage is None:
        return functions, valid, stale, insufficient, cannot_determine, required
    for f in coverage.functions:
        functions.append(f.to_dict())
        if f.coverage is Coverage.CURRENT:
            valid += 1
        elif f.coverage is Coverage.STALE:
            stale += 1
            required.append(f.function_id)
        elif f.coverage is Coverage.FAILING:
            insufficient += 1
            required.append(f.function_id)
        elif f.coverage is Coverage.NEVER_VERIFIED:
            insufficient += 1
        elif f.coverage is Coverage.NOT_DEMONSTRABLE:
            cannot_determine += 1
    return functions, valid, stale, insufficient, cannot_determine, required


def _decide_verdict(
    *, advisory_evaluated: bool, matches: list[dict[str, Any]],
    human_review_required: bool, coverage: CoverageReport | None,
    required_actions: list[str], valid: int, insufficient: int,
    cannot_determine: int,
) -> AssuranceVerdict:
    if advisory_evaluated:
        if not matches:
            return AssuranceVerdict.NO_IMPACT_FOUND
        if required_actions:
            return AssuranceVerdict.REQUIRES_REVERIFICATION
        if human_review_required:
            return AssuranceVerdict.REQUIRES_HUMAN_REVIEW
        return AssuranceVerdict.POTENTIALLY_AFFECTED
    # No change was given: this is a standing-evidence read of the machine
    # as it is today, which only means something with a ledger behind it.
    if coverage is None:
        return AssuranceVerdict.CANNOT_DETERMINE
    if required_actions:
        return AssuranceVerdict.REQUIRES_REVERIFICATION
    if cannot_determine and not valid and not insufficient:
        # every declared function is NOT_DEMONSTRABLE: there is no check that
        # could ever cover it, which is a structural gap, not a missing
        # verification — "insufficient evidence" would imply one is owed.
        return AssuranceVerdict.CANNOT_DETERMINE
    if insufficient or cannot_determine:
        return AssuranceVerdict.INSUFFICIENT_EVIDENCE
    return AssuranceVerdict.VERIFIED


def run_ad_hoc_check(
    manifest: SafetyManifest, advisory: ComponentAdvisory | None = None,
) -> MachineAssuranceCheck:
    """The free path: one manifest, one optional advisory, no ledger."""
    if advisory is None:
        raise CheckError(
            "an ad-hoc check with no ledger and no advisory has nothing to "
            "assess: nothing to match, and no history to read standing "
            "evidence from. Provide an advisory, or enrol this machine."
        )
    matches, human_review_required = _match_manifest(manifest, advisory)
    checks_skipped = [
        "no ledger was supplied, so this compares the change only against the "
        "manifest you provided. It cannot say whether standing safety evidence "
        "for this machine is still valid — that needs the machine enrolled, "
        "with its interventions and verifications sealed in the ledger.",
    ]
    verdict = _decide_verdict(
        advisory_evaluated=True, matches=matches,
        human_review_required=human_review_required, coverage=None,
        required_actions=[], valid=0, insufficient=0, cannot_determine=0,
    )
    return MachineAssuranceCheck(
        machine_key=manifest.machine.key, verdict=verdict, enrolled=False,
        advisory_evaluated=True, matches=tuple(matches), functions=(),
        evidence_valid=0, evidence_stale=0, evidence_insufficient=0,
        evidence_cannot_determine=0, required_actions=(),
        human_review_required=human_review_required, interventions=(),
        latest_intervention=None, fleet_machines_analyzed=None,
        fleet_machines_affected=None, assessed_at=format_utc(utc_now()),
        checks_skipped=tuple(checks_skipped),
    )


def run_enrolled_check(
    ledger: EvidenceLedger, machine_key: str,
    advisory: ComponentAdvisory | None = None,
) -> MachineAssuranceCheck:
    """The paid path: a machine already enrolled in the ledger.

    Reads :class:`assurance.fleet.registry.Fleet`, which already computes
    coverage, interventions and verifications per machine — this composes
    those, it does not recompute them.
    """
    fleet = Fleet.from_ledger(ledger)
    record = fleet.record(machine_key)
    if record is None:
        raise CheckError(
            f"{machine_key!r} is not enrolled: no sealed manifest for it was "
            "found in this ledger. Seal a manifest first "
            "(POST /v1/machinery/manifest), or run the free check instead."
        )

    checks_skipped: list[str] = list(record.coverage.checks_skipped)
    if not fleet.chain_verified:
        checks_skipped.insert(
            0, "THE LEDGER CHAIN DOES NOT VERIFY. Every statement here is drawn "
               "from a store whose integrity is in question.")

    matches: list[dict[str, Any]] = []
    human_review_required = False
    fleet_report: ImpactReport | None = None
    if advisory is not None:
        matches, human_review_required = _match_manifest(record.manifest, advisory)
        fleet_report = assess_impact(advisory, fleet)
        checks_skipped.extend(
            c for c in fleet_report.checks_skipped if c not in checks_skipped
        )

    functions, valid, stale, insufficient, cannot_determine, required = _tally(
        record.coverage
    )
    verdict = _decide_verdict(
        advisory_evaluated=advisory is not None, matches=matches,
        human_review_required=human_review_required, coverage=record.coverage,
        required_actions=required, valid=valid, insufficient=insufficient,
        cannot_determine=cannot_determine,
    )
    interventions = sorted(record.interventions, key=lambda i: i.occurred_at)
    latest = _intervention_summary(interventions[-1]) if interventions else None

    return MachineAssuranceCheck(
        machine_key=machine_key, verdict=verdict, enrolled=True,
        advisory_evaluated=advisory is not None, matches=tuple(matches),
        functions=tuple(functions), evidence_valid=valid, evidence_stale=stale,
        evidence_insufficient=insufficient,
        evidence_cannot_determine=cannot_determine,
        required_actions=tuple(dict.fromkeys(required)),
        human_review_required=human_review_required,
        interventions=tuple(_intervention_summary(i) for i in interventions),
        latest_intervention=latest,
        fleet_machines_analyzed=(fleet_report.machines_in_fleet
                                  if fleet_report is not None else None),
        fleet_machines_affected=(len(fleet_report.machines_affected)
                                  if fleet_report is not None else None),
        assessed_at=format_utc(utc_now()),
        checks_skipped=tuple(dict.fromkeys(checks_skipped)),
    )
