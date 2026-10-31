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

**An empty fleet cannot clear anything.** An advisory whose impact verdict is
``clear`` against a fleet with machines is counted (``FeedOutcome.cleared``) and
carried no further. Against a fleet with ZERO machines the same verdict is
vacuous: nothing was assessed, so nothing was cleared. Such an advisory is
carried as a finding in the explicit state ``not_assessed`` (impact
``not_assessed``), counted apart from ``clear``, shown in the summary and the
JSON, and it makes the run **DEGRADED** (exit 2). DEGRADED is the most
conservative existing verdict ("the watch could not see"): it adds no new exit
code, it can never read as QUIET (0), and it does not claim a finding (1) that
nobody has evidence for. A ``not_assessed`` finding has no machines and no
report, so it opens no case, stops no use and drafts no intake, and it is not
remembered as "seen": when the fleet is later enrolled the advisory is assessed
as ``new``.
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
from ..supplier.trust import FeedTrust, SupplierTrustStore, evaluate_feed
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
    #: Advisories assessed against a non-empty fleet and found to touch nothing.
    cleared: int = 0
    #: Advisories that could not be assessed because the fleet has no machines.
    #: Deliberately NOT part of ``cleared``.
    not_assessed: tuple[str, ...] = ()
    #: ``config_key`` — verified under the key file named in the watch config
    #: (an operator decision made out of band, not an auditable pin);
    #: ``pinned_key_policy`` — under a key pinned in the account's trust store.
    trust_basis: str = ""
    #: The trust store's evaluation of this feed (see ``supplier.trust``), when
    #: one was consulted. Empty otherwise.
    trust: dict[str, Any] = field(default_factory=dict)

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
            "cleared": self.cleared, "not_assessed": list(self.not_assessed),
            "trust_basis": self.trust_basis, "trust": dict(self.trust),
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
    #: The change-assurance case the runner opened or updated for this finding.
    #: Empty until the runner has done so (and always empty in a dry run).
    case_id: str = ""
    #: ``config_key`` | ``pinned_key_policy`` | ``manual_override`` | ``none``.
    trust_basis: str = "config_key"
    #: True for an advisory that did not meet the trust policy. It is shown so an
    #: operator can inspect it, and it carries NO consequence: ``machines`` is
    #: empty (so no stop-use and no regulatory intake is drafted), ``report`` is
    #: ``None`` (so no case is opened) and ``state`` is ``untrusted``.
    inspect_only: bool = False
    #: Machines the advisory would touch if it were trusted. For inspection only.
    inspect_machines: tuple[str, ...] = ()
    #: Whether a person has reviewed the implications. Software never sets it.
    implications_reviewed: bool = False
    trust_state: str = ""
    #: Hash of the advisory content behind an intel-store finding, so a changed
    #: observation can be told from a re-seen one. Empty for supplier-feed findings.
    content_hash: str = ""
    #: Provenance, enrichment and caveats of an intel-store finding (see
    #: ``watch.intel_source``). Context only: it never changes ``impact``. Empty otherwise.
    intel: dict[str, Any] = field(default_factory=dict, compare=False)
    #: The impact engine's own report, kept in memory so the runner can hand it
    #: to :func:`assurance.change.service.assess_advisory` without asking the
    #: engine twice. Never serialised: the sealed run carries the finding, and
    #: the case carries the report's consequences.
    report: ImpactReport | None = field(default=None, compare=False, repr=False)

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
            "case_id": self.case_id,
            "trust_basis": self.trust_basis,
            "trust_state": self.trust_state,
            "inspect_only": self.inspect_only,
            "inspect_machines": list(self.inspect_machines),
            "implications_reviewed": self.implications_reviewed,
            **({"content_hash": self.content_hash, "intel": self.intel}
               if self.intel else {}),
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
    def updated(self) -> tuple[AdvisoryFinding, ...]:
        """Intel-store advisories already reported whose recorded content has changed."""
        return tuple(f for f in self.findings if f.state == "updated")

    @property
    def withdrawn(self) -> tuple[AdvisoryFinding, ...]:
        return tuple(f for f in self.findings if f.state == "withdrawn")

    @property
    def not_assessed(self) -> tuple[AdvisoryFinding, ...]:
        """Advisories received while the fleet had no machines to assess them on."""
        return tuple(f for f in self.findings if f.state == "not_assessed")

    @property
    def untrusted(self) -> tuple[AdvisoryFinding, ...]:
        """Advisories shown for inspection that carry no consequence."""
        return tuple(f for f in self.findings if f.inspect_only)

    @property
    def stop_use(self) -> tuple[AdvisoryFinding, ...]:
        return tuple(f for f in self.findings if f.stops_use)

    @property
    def is_finding(self) -> bool:
        """Anything that has not been reported before, or a retraction."""
        return bool(self.new or self.updated or self.withdrawn)

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
        if self.updated:
            parts.append(f"{len(self.updated)} updated")
        if self.withdrawn:
            parts.append(f"{len(self.withdrawn)} withdrawn")
        if self.untrusted:
            parts.append(
                f"{len(self.untrusted)} advisory(ies) NOT TRUSTED (inspect only, "
                "no consequence)")
        if self.not_assessed:
            parts.append(
                f"{len(self.not_assessed)} advisory(ies) NOT ASSESSED (the fleet "
                "has no machines, so nothing was cleared)")
        if self.degraded:
            parts.append(
                f"{len(self.degraded)} feed(s) could not be checked or are untrusted")
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


def _read_feed_pinned(
    supplier_id: str, feed_path: str, store: SupplierTrustStore,
) -> tuple[list[SignedAdvisory], FeedOutcome | None, list[str], FeedTrust | None]:
    """Read one feed and judge it under the account's pinned keys."""
    path = Path(feed_path)
    if not path.exists():
        return [], FeedOutcome(
            supplier_id=supplier_id, status="absent",
            detail=f"{path} does not exist. The watch is blind to this supplier; "
                   "that is not the same as this supplier having nothing to say."
        ), [], None
    try:
        records = AdvisoryFeed(path).read()
    except (PublishError, OSError) as exc:
        return [], FeedOutcome(
            supplier_id=supplier_id, status="unreadable",
            detail=f"{path} could not be read: {exc}"), [], None
    seen = store.feed_head(supplier_id)
    trust = evaluate_feed(
        records, store, expect_supplier=supplier_id,
        min_sequence=seen[0] if seen else 0, expect_head=seen[1] if seen else "")
    if trust.policy_satisfied and records:
        # Only a feed that was trusted moves the remembered head; one that is not
        # trusted must not become the baseline a later feed is compared with.
        store.record_feed_head(supplier_id, records[-1].sequence, records[-1].content_hash())
    notes = [trust.trust_statement]
    if not seen:
        notes.append(
            "No earlier head of this feed was on record, so whether it has been cut "
            "back could not be checked on this pass; later passes compare against it.")
    return records, None, notes, trust


def check_feeds(
    subscriptions: Sequence[FeedSubscription],
    fleet: Fleet,
    *,
    previously_seen: dict[str, str] | None = None,
    now: datetime | None = None,
    trust_store: SupplierTrustStore | None = None,
) -> AdvisoryPass:
    """Look at every subscribed feed and say what is new for *this* fleet.

    ``previously_seen`` maps advisory id to the state it was last reported in,
    so that an advisory already known is carried as ``outstanding`` rather than
    announced twice — and so that a withdrawal of something this fleet was told
    about is announced exactly once.

    ``trust_store`` is the account's pinned-key store. For a supplier with a pin
    in it the feed is judged by :func:`assurance.supplier.trust.evaluate_feed`:
    only a feed that meets the policy (or an advisory with a recorded manual
    override) drives cases, stop-use and intakes; anything else is listed as
    ``untrusted`` for inspection and does nothing. A supplier with no pin falls
    back to the key file in the watch configuration, as before, and is labelled
    ``config_key`` so the two are never confused.
    """
    # An advisory that was only ever "not assessed" was never told to anyone.
    seen = {k: v for k, v in (previously_seen or {}).items() if v != "not_assessed"}
    outcomes: list[FeedOutcome] = []
    findings: list[AdvisoryFinding] = []
    caveats: list[str] = []

    for sub in subscriptions:
        pinned = (trust_store is not None
                  and bool(trust_store.pins(sub.supplier_id)))
        trust: FeedTrust | None = None
        if pinned:
            assert trust_store is not None
            records, failure, notes, trust = _read_feed_pinned(
                sub.supplier_id, sub.feed, trust_store)
        else:
            records, failure, notes = _read_feed(
                sub.supplier_id, sub.feed, sub.public_key)
        caveats.extend(notes)
        if failure is not None:
            outcomes.append(failure)
            continue

        standing: dict[str, SignedAdvisory] = {}
        withdrawals: dict[str, str] = {}
        if trust is not None:
            first = {r.advisory_id: r for r in records if not r.is_withdrawal}
            standing = {a["advisory_id"]: first[a["advisory_id"]]
                        for a in trust.advisories}
            if trust.policy_satisfied:
                withdrawals = {r.withdraws: r.withdrawal_reason for r in records
                               if r.is_withdrawal and r.withdraws in trust.withdrawn}
        else:
            for record in records:
                if record.is_withdrawal:
                    standing.pop(record.withdraws, None)
                    withdrawals[record.withdraws] = record.withdrawal_reason
                else:
                    standing[record.advisory_id] = record

        new_ids: list[str] = []
        withdrawn_ids: list[str] = []
        cleared = 0
        unassessed_ids: list[str] = []

        for advisory_id, record in standing.items():
            try:
                advisory = record.component()
            except AssuranceError as exc:
                caveats.append(
                    f"{sub.supplier_id} {advisory_id} could not be read as an "
                    f"advisory ({exc}); it was skipped, and skipping is not "
                    "clearing.")
                continue
            provenance = (trust.provenance_for(advisory_id) if trust is not None
                          else {"source": "supplier_feed", "trust_basis": "config_key",
                                "trust_state": "config_key_verified"})
            report = assess_impact(advisory, fleet, provenance=provenance)
            if advisory.import_record is not None or (
                    trust is not None and not trust.permitted(advisory_id)):
                # Inspectable, consequence-free: no machines (so no stop-use and
                # no intake), no report (so no case), not counted as new.
                # An unsigned import is untrusted wherever it was found, even in a feed
                # whose signature verifies: the signature is over the supplier's file,
                # and the file says it is not the supplier's own statement.
                findings.append(_finding(
                    advisory, sub.supplier_id, "untrusted", report,
                    trust_basis="none",
                    trust_state=(trust.trust_state if trust is not None
                                 and advisory.import_record is None else "unsigned_import"),
                    inspect_only=True))
                continue
            if report.verdict == "clear":
                if report.machines_in_fleet == 0:
                    # Vacuous: nothing was assessed, so nothing was cleared.
                    # Surfaced explicitly (DEGRADED), never silently dropped.
                    unassessed_ids.append(advisory_id)
                    findings.append(AdvisoryFinding(
                        advisory_id=advisory.advisory_id,
                        supplier_id=sub.supplier_id,
                        severity=advisory.severity.value, title=advisory.title,
                        remedy=advisory.remedy, reference=advisory.reference,
                        state="not_assessed", impact="not_assessed",
                        trust_basis=str(provenance.get("trust_basis", "config_key")),
                        trust_state=str(provenance.get("trust_state", ""))))
                    continue
                # Not carried as a finding, and deliberately not silent either:
                # the feed outcome counts it, so "we checked and it does not
                # touch you" is recorded rather than merely implied.
                cleared += 1
                continue
            state = "outstanding" if advisory_id in seen else "new"
            if state == "new":
                new_ids.append(advisory_id)
            findings.append(_finding(
                advisory, sub.supplier_id, state, report,
                trust_basis=str(provenance.get("trust_basis", "config_key")),
                trust_state=str(provenance.get("trust_state", ""))))

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

        if trust is not None and not trust.policy_satisfied:
            outcomes.append(FeedOutcome(
                supplier_id=sub.supplier_id, status="untrusted", records=len(records),
                problems=tuple(trust.problems), trust_basis="none",
                trust=trust.to_dict(), new=tuple(new_ids),
                cleared=cleared, not_assessed=tuple(unassessed_ids),
                detail="this feed does not meet the trust policy for the pinned key(s). "
                       "Its advisories are listed for inspection only; nothing in it "
                       "opened a case, stopped use or drafted an intake except an "
                       "advisory carrying a recorded manual override."))
            continue
        outcomes.append(FeedOutcome(
            supplier_id=sub.supplier_id, status="verified", records=len(records),
            new=tuple(new_ids), newly_withdrawn=tuple(withdrawn_ids),
            cleared=cleared, not_assessed=tuple(unassessed_ids),
            trust_basis="pinned_key_policy" if trust is not None else "config_key",
            trust=trust.to_dict() if trust is not None else {},
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
    report: ImpactReport, *, trust_basis: str = "config_key", trust_state: str = "",
    inspect_only: bool = False,
) -> AdvisoryFinding:
    if inspect_only:
        return AdvisoryFinding(
            advisory_id=advisory.advisory_id, supplier_id=supplier_id,
            severity=advisory.severity.value, title=advisory.title,
            remedy=advisory.remedy, reference=advisory.reference, state=state,
            impact=report.verdict, machines=(), functions_in_question=(),
            trust_basis=trust_basis, trust_state=trust_state, inspect_only=True,
            inspect_machines=tuple(report.machines_affected), report=None,
        )
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
        trust_basis=trust_basis,
        trust_state=trust_state,
        report=report,
    )
