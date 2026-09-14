"""Watching the suppliers, not just the machines.

The machine watch answers "did anything on my floor change". This answers the
other half, and it is the half that wakes somebody up: **did the world change
underneath machines that did not**.

A supplier publishes a signed advisory at 09:00. Nothing on the plant floor
moved. Every manifest still matches. The machine watch reports QUIET, correctly,
and the integrator learns on the day their insurer asks. That gap is the reason
a tool becomes a subscription: a thing that tells you about a problem you did
not know to look for is worth paying for every month, and a thing you have to
remember to run is not.

Four judgements, and each is a place this could have been built wrong:

**New is not the same as outstanding.** An advisory reported last week is not
reported again as new, but it does not disappear either — it stays outstanding
until the fleet stops matching it or the supplier withdraws it. A watch that
re-reports everything trains the reader to skim, and a watch that reports
something once and forgets lets it rot.

**A feed that cannot be verified is DEGRADED, never silence.** "I could not
check" and "nothing new" must not share an exit code, for the same reason
"I could not look at the machine" and "the machine did not change" must not.
This is where a signed-advisory mechanism most easily becomes decoration: fetch
fails, verification is skipped, the run reports quiet, and the absence of alarms
is read as the absence of danger.

**A withdrawal is a finding.** If an advisory that affected this fleet is
withdrawn, somebody here very likely changed a machine because of it. Nothing
else in this industry tells them. "The advisory you acted on in March has been
withdrawn, and here is the reason the supplier gave" is a first-class finding,
not a footnote.

**A severity that means stop is said first.** An advisory the supplier marked
``stop_use`` against a machine that matched is not one line among forty; it is
the reason this ran.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..attest.keys import SigningKeyError, VerifyingKey
from ..core.errors import AssuranceError
from ..fleet.advisory import ComponentAdvisory
from ..fleet.impact import ImpactReport, assess_impact
from ..fleet.registry import Fleet
from ..supplier.publish import (
    AdvisoryFeed,
    PublishError,
    SignedAdvisory,
    verify_feed,
)
from .config import FeedSubscription

__all__ = [
    "ADVISORY_KIND",
    "AdvisoryFinding",
    "AdvisoryPass",
    "FeedOutcome",
    "check_feeds",
]

ADVISORY_KIND = "watch.advisory"


@dataclass(frozen=True)
class FeedOutcome:
    """What happened when this watch looked at one supplier's feed."""

    supplier_id: str
    #: ``verified`` | ``unverifiable`` | ``unreadable`` | ``absent``
    status: str
    records: int = 0
    new: tuple[str, ...] = ()
    newly_withdrawn: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()
    detail: str = ""

    @property
    def is_degraded(self) -> bool:
        """A feed that could not be checked degrades the whole run.

        Not a finding — a finding means something was found. This means the
        watch was blind to one supplier, and the reader has to know the
        difference.
        """
        return self.status != "verified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "supplier_id": self.supplier_id, "status": self.status,
            "records": self.records, "new": list(self.new),
            "newly_withdrawn": list(self.newly_withdrawn),
            "problems": list(self.problems), "detail": self.detail,
        }


@dataclass(frozen=True)
class AdvisoryFinding:
    """One advisory, and what it means for this fleet today."""

    advisory_id: str
    supplier_id: str
    severity: str
    title: str
    remedy: str
    reference: str
    #: ``new`` on the first run that saw it, ``outstanding`` afterwards,
    #: ``withdrawn`` when the supplier has retracted it.
    state: str
    #: The impact engine's own verdict: ``clear`` | ``needs_review`` | ``affected``.
    impact: str
    machines: tuple[str, ...] = ()
    functions_in_question: tuple[str, ...] = ()
    withdrawal_reason: str = ""

    @property
    def stops_use(self) -> bool:
        return self.severity == "stop_use" and bool(self.machines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id, "supplier_id": self.supplier_id,
            "severity": self.severity, "title": self.title,
            "remedy": self.remedy, "reference": self.reference,
            "state": self.state, "impact": self.impact,
            "machines": list(self.machines),
            "functions_in_question": list(self.functions_in_question),
            "withdrawal_reason": self.withdrawal_reason,
        }


@dataclass(frozen=True)
class AdvisoryPass:
    """Everything one look at the subscribed feeds established."""

    feeds: tuple[FeedOutcome, ...] = ()
    findings: tuple[AdvisoryFinding, ...] = ()
    checks_skipped: tuple[str, ...] = field(default_factory=tuple)

    @property
    def degraded(self) -> tuple[FeedOutcome, ...]:
        return tuple(f for f in self.feeds if f.is_degraded)

    @property
    def new(self) -> tuple[AdvisoryFinding, ...]:
        return tuple(f for f in self.findings if f.state == "new")

    @property
    def withdrawn(self) -> tuple[AdvisoryFinding, ...]:
        return tuple(f for f in self.findings if f.state == "withdrawn")

    @property
    def stop_use(self) -> tuple[AdvisoryFinding, ...]:
        return tuple(f for f in self.findings if f.stops_use)

    @property
    def is_finding(self) -> bool:
        """Anything that has not been reported before, or a retraction."""
        return bool(self.new or self.withdrawn)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feeds": [f.to_dict() for f in self.feeds],
            "findings": [f.to_dict() for f in self.findings],
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        if not self.feeds:
            return "no supplier feeds subscribed"
        parts = []
        if self.stop_use:
            parts.append(
                f"{len(self.stop_use)} STOP-USE advisory(ies) match this fleet")
        if self.new:
            parts.append(f"{len(self.new)} new")
        if self.withdrawn:
            parts.append(f"{len(self.withdrawn)} withdrawn")
        if self.degraded:
            parts.append(
                f"{len(self.degraded)} feed(s) could not be checked")
        return "; ".join(parts) if parts else (
            f"{len(self.feeds)} feed(s) checked, nothing new")


def _read_feed(
    supplier_id: str, feed_path: str, key_path: str,
) -> tuple[list[SignedAdvisory], FeedOutcome | None, list[str]]:
    """Read and verify one feed, or explain why it could not be."""
    path = Path(feed_path)
    if not path.exists():
        return [], FeedOutcome(
            supplier_id=supplier_id, status="absent",
            detail=f"{path} does not exist. The watch is blind to this supplier; "
                   "that is not the same as this supplier having nothing to say."
        ), []

    try:
        records = AdvisoryFeed(path).read()
    except (PublishError, OSError) as exc:
        return [], FeedOutcome(
            supplier_id=supplier_id, status="unreadable",
            detail=f"{path} could not be read: {exc}"), []

    try:
        key = VerifyingKey.from_file(key_path)
    except (SigningKeyError, OSError) as exc:
        return [], FeedOutcome(
            supplier_id=supplier_id, status="unreadable", records=len(records),
            detail=f"the public key for {supplier_id} could not be read: {exc}"), []

    verdict = verify_feed(records, key, expect_supplier=supplier_id)
    if not verdict.ok:
        return [], FeedOutcome(
            supplier_id=supplier_id, status="unverifiable", records=len(records),
            problems=tuple(verdict.problems),
            detail="this feed does not verify, so nothing in it was acted on. "
                   "An advisory that cannot be authenticated must not drive a "
                   "change to a safety system."), list(verdict.checks_skipped)

    return list(records), None, list(verdict.checks_skipped)


def check_feeds(
    subscriptions: Sequence[FeedSubscription],
    fleet: Fleet,
    *,
    previously_seen: dict[str, str] | None = None,
    now: datetime | None = None,
) -> AdvisoryPass:
    """Look at every subscribed feed and say what is new for *this* fleet.

    ``previously_seen`` maps advisory id to the state it was last reported in,
    so that an advisory already known is carried as ``outstanding`` rather than
    announced twice — and so that a withdrawal of something this fleet was told
    about is announced exactly once.
    """
    seen = dict(previously_seen or {})
    outcomes: list[FeedOutcome] = []
    findings: list[AdvisoryFinding] = []
    caveats: list[str] = []

    for sub in subscriptions:
        records, failure, notes = _read_feed(
            sub.supplier_id, sub.feed, sub.public_key)
        caveats.extend(notes)
        if failure is not None:
            outcomes.append(failure)
            continue

        standing: dict[str, SignedAdvisory] = {}
        withdrawals: dict[str, str] = {}
        for record in records:
            if record.is_withdrawal:
                standing.pop(record.withdraws, None)
                withdrawals[record.withdraws] = record.withdrawal_reason
            else:
                standing[record.advisory_id] = record

        new_ids: list[str] = []
        withdrawn_ids: list[str] = []

        for advisory_id, record in standing.items():
            try:
                advisory = record.component()
            except AssuranceError as exc:
                caveats.append(
                    f"{sub.supplier_id} {advisory_id} could not be read as an "
                    f"advisory ({exc}); it was skipped, and skipping is not "
                    "clearing.")
                continue
            report = assess_impact(advisory, fleet)
            if report.verdict == "clear":
                # Not carried as a finding, and deliberately not silent either:
                # the feed outcome still counts it, so "we checked and it does
                # not touch you" is recorded rather than merely implied.
                continue
            state = "outstanding" if advisory_id in seen else "new"
            if state == "new":
                new_ids.append(advisory_id)
            findings.append(_finding(
                advisory, sub.supplier_id, state, report))

        for advisory_id, reason in withdrawals.items():
            if advisory_id not in seen:
                # Withdrawn before this fleet was ever told. Nothing was acted
                # on here, so announcing it would be noise.
                continue
            if seen.get(advisory_id) == "withdrawn":
                continue
            withdrawn_ids.append(advisory_id)
            original = next((r for r in records
                             if r.advisory_id == advisory_id
                             and not r.is_withdrawal), None)
            title = str(original.advisory.get("title", "")) if original else ""
            findings.append(AdvisoryFinding(
                advisory_id=advisory_id, supplier_id=sub.supplier_id,
                severity=str(original.advisory.get("severity", "")) if original else "",
                title=title, remedy="", reference="",
                state="withdrawn", impact="withdrawn",
                withdrawal_reason=reason,
            ))

        outcomes.append(FeedOutcome(
            supplier_id=sub.supplier_id, status="verified", records=len(records),
            new=tuple(new_ids), newly_withdrawn=tuple(withdrawn_ids),
            detail=f"{len(standing)} advisory(ies) stand in this feed"))

    if outcomes:
        caveats.append(
            "an advisory affects what is in the latest sealed manifest for each "
            "machine. A machine that has changed since its last observation, or "
            "was never enrolled, is absent from these findings — and absence "
            "here is not evidence of safety."
        )
        caveats.append(
            "this watch learns of an advisory when the subscribed feed file "
            "changes. Whatever puts the supplier's feed in that file is outside "
            "this system, and a sync that silently stopped looks exactly like a "
            "supplier with nothing to report."
        )

    return AdvisoryPass(
        feeds=tuple(outcomes),
        findings=tuple(findings),
        checks_skipped=tuple(dict.fromkeys(caveats)),
    )


def _finding(
    advisory: ComponentAdvisory, supplier_id: str, state: str,
    report: ImpactReport,
) -> AdvisoryFinding:
    machines = list(report.machines_affected)
    functions: list[str] = []
    for exposure in report.exposures:
        for function in exposure.newly_in_question:
            if function.function_id not in functions:
                functions.append(function.function_id)
    return AdvisoryFinding(
        advisory_id=advisory.advisory_id,
        supplier_id=supplier_id,
        severity=advisory.severity.value,
        title=advisory.title,
        remedy=advisory.remedy,
        reference=advisory.reference,
        state=state,
        impact=report.verdict,
        machines=tuple(machines),
        functions_in_question=tuple(functions),
    )
