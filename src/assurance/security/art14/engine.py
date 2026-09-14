"""The case: one event, from first signal to final filing.

Every step writes a sealed evidence object into the hash-chained ledger, so the
question a market surveillance authority actually asks — *when did you know,
and can you show me* — has an answer that does not depend on anyone's memory
or on a spreadsheet that could have been edited last week.

The order is enforced. Awareness cannot be recorded without a signal; a filing
cannot be recorded before awareness; a final report cannot be recorded before
the fact that starts its clock. Each refusal names the provision, because an
error message that says "invalid state" teaches nobody anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ...core.errors import AssuranceError, EvidenceIncompleteError
from ...core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from ...core.identity import format_utc, parse_utc, utc_now
from ...evidence.ledger import EvidenceLedger
from .clock import Deadlines
from .model import CASE_KIND, Awareness, NonReportGround, ProductVersion, Signal, Stage, Track
from .srp import PayloadValidation, validate_payload
from .triage import Answer, Question, TriageResult, triage

__all__ = ["Art14Register", "Case", "CaseError"]

_ORIGIN = Origin(system="assurance.security.art14", method="recorded via Art14Register")


class CaseError(AssuranceError):
    """A step was attempted out of order, or without the fact it depends on."""


@dataclass
class Case:
    """The live view of one Article 14 case, rebuilt from the ledger.

    Not a cache. Every field here was read back out of the chain, so a case view
    and an audit export cannot drift apart.
    """

    case_id: str
    signal: Signal | None = None
    awareness: Awareness | None = None
    track: Track | None = None
    triage_result: TriageResult | None = None
    product: ProductVersion | None = None
    ground: NonReportGround | None = None
    reopen_trigger: str = ""
    measure_available_at: datetime | None = None
    filings: dict[str, datetime] = None  # type: ignore[assignment]
    users_informed_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.filings is None:
            self.filings = {}

    @property
    def deadlines(self) -> Deadlines | None:
        """None until a track and an awareness moment both exist."""
        if self.awareness is None or self.track is None:
            return None
        return Deadlines(
            track=self.track,
            awareness_at=self.awareness.established_at,
            measure_available_at=self.measure_available_at,
            early_warning_submitted_at=self.filings.get(Stage.EARLY_WARNING.value),
            notification_submitted_at=self.filings.get(Stage.NOTIFICATION.value),
            final_submitted_at=self.filings.get(Stage.FINAL.value),
        )

    @property
    def state(self) -> str:
        if self.ground is not None:
            return "closed_not_reportable"
        if self.awareness is None:
            return "signal_received"
        if self.triage_result is None or self.triage_result.reportable is None:
            return "awaiting_triage"
        if Stage.FINAL.value in self.filings:
            return "closed_filed"
        return "reportable_open"

    def outstanding(self, now: datetime | None = None) -> list[str]:
        """What still has to happen, worst first.

        Deliberately blunt. A case view whose most prominent element is a green
        tick is a case view that gets someone fined.
        """
        out: list[str] = []
        if self.ground is not None:
            if self.ground.requires_reopen_trigger and not self.reopen_trigger:
                out.append(
                    f"CLOSED on a ground that can stop being true ({self.ground.value}) with no "
                    f"reopen trigger recorded — {self.ground.authority}"
                )
            if self.ground.leaves_upstream_duty:
                out.append(
                    "Art. 13(6): the vulnerability must still be reported to the maintainer of "
                    "the third-party component"
                )
            return out
        if self.awareness is None:
            out.append("awareness has not been established; no deadline is running yet")
            return out
        if self.triage_result is None:
            out.append("triage has not been recorded")
        deadlines = self.deadlines
        if deadlines is not None:
            for d in deadlines.all():
                if d.submitted_at is None:
                    hours = d.hours_remaining(now)
                    if hours < 0:
                        out.append(
                            f"OVERDUE by {abs(hours):.1f} h: {d.stage.label} ({d.provision}), "
                            f"due {format_utc(d.due_at)}"
                        )
                    else:
                        out.append(
                            f"{d.stage.label} ({d.provision}) due in {hours:.1f} h at "
                            f"{format_utc(d.due_at)}"
                        )
                elif d.met is False:
                    out.append(f"FILED LATE: {d.stage.label} ({d.provision})")
            out.extend(deadlines.pending_facts())
        if self.users_informed_at is None:
            out.append(
                "Art. 14(8): impacted users have not been recorded as informed. The trigger is "
                "becoming aware, not the availability of a fix."
            )
        if self.product is not None:
            out.extend(f"availability record: {g}" for g in self.product.gaps())
        return out

    def to_dict(self, now: datetime | None = None) -> dict[str, Any]:
        deadlines = self.deadlines
        return {
            "case_id": self.case_id,
            "state": self.state,
            "track": self.track.value if self.track else None,
            "signal": self.signal.to_dict() if self.signal else None,
            "awareness": self.awareness.to_dict() if self.awareness else None,
            "assessment_lag_hours": (
                self.awareness.lag_hours_from(self.signal)
                if self.awareness and self.signal
                else None
            ),
            "triage": self.triage_result.to_dict() if self.triage_result else None,
            "product": self.product.to_dict() if self.product else None,
            "ground": self.ground.value if self.ground else None,
            "reopen_trigger": self.reopen_trigger,
            "deadlines": deadlines.to_dict(now) if deadlines else None,
            "users_informed_at": format_utc(self.users_informed_at) if self.users_informed_at else None,
            "outstanding": self.outstanding(now),
        }


class Art14Register:
    """The register. One ledger, many cases.

    All state lives in the ledger; this class is the vocabulary for putting
    things into it and the logic for reading them back.
    """

    def __init__(self, ledger: EvidenceLedger) -> None:
        self.ledger = ledger

    # -- writing ----------------------------------------------------------
    def _append(
        self,
        case_id: str,
        kind: str,
        body: dict[str, Any],
        actor: Actor,
        *,
        state: ValidationState = ValidationState.UNVERIFIED,
        confidence: Confidence = Confidence.NONE,
        checks_skipped: tuple[str, ...] = (),
        origin: Origin | None = None,
    ) -> Evidence:
        evidence = Evidence(
            kind=kind,
            body={"case_id": case_id, **body},
            actor=actor,
            origin=origin or _ORIGIN,
            validation_state=state,
            confidence=confidence,
            checks_skipped=checks_skipped,
        ).seal()
        self.ledger.append(evidence, subject=case_id)
        return evidence

    def record_signal(self, case_id: str, signal: Signal, actor: Actor) -> Evidence:
        """Open a case with the first thing anyone heard.

        Recorded before anyone knows whether it matters, because the interval
        from here to awareness is the number that gets asked about and it cannot
        be reconstructed later.
        """
        if self._load(case_id).signal is not None:
            raise CaseError(f"case {case_id} already has a signal; open a new case")
        return self._append(
            case_id,
            CASE_KIND["signal"],
            {"signal": signal.to_dict()},
            actor,
            origin=Origin(
                system="assurance.security.art14",
                reference=signal.reference,
                method=f"intake via {signal.channel.value}",
            ),
            checks_skipped=("nothing has been assessed at intake; this records receipt only",),
        )

    def record_awareness(
        self, case_id: str, awareness: Awareness, track: Track, actor: Actor
    ) -> Evidence:
        """Fix the moment every deadline runs from."""
        case = self._load(case_id)
        if case.signal is None:
            raise CaseError(
                f"case {case_id} has no signal. Record what was received before recording when "
                "it was understood — the interval between the two is the evidence."
            )
        if case.awareness is not None:
            raise CaseError(
                f"case {case_id} already has an awareness record at "
                f"{format_utc(case.awareness.established_at)}. Moving it would move a legal "
                "deadline; supersede it explicitly if it was wrong."
            )
        if awareness.established_at < case.signal.received_at:
            raise CaseError(
                "awareness cannot precede the signal that produced it "
                f"({format_utc(awareness.established_at)} < "
                f"{format_utc(case.signal.received_at)})"
            )
        if not awareness.reasoning.strip():
            raise EvidenceIncompleteError(
                "an awareness record without reasoning is not evidence. Guidance §213 "
                "makes this a judgement about reasonable certainty; record the judgement."
            )
        return self._append(
            case_id,
            CASE_KIND["awareness"],
            {"track": track.value, "awareness": awareness.to_dict()},
            actor,
            state=ValidationState.VERIFIED,
            confidence=Confidence.ESTABLISHED,
            checks_skipped=(
                (
                    "the reporting platform does not currently capture this fact for "
                    "vulnerabilities, and records detection rather than awareness for incidents; "
                    "this record is the compensating control"
                ),
            ),
        )

    def record_triage(
        self,
        case_id: str,
        answers: dict[Question | str, Answer | str],
        actor: Actor,
        reasoning: str = "",
        *,
        reopen_trigger: str = "",
    ) -> tuple[Evidence, TriageResult]:
        """Work the decision path and record the outcome, whichever way it goes."""
        case = self._load(case_id)
        if case.track is None:
            raise CaseError(
                f"case {case_id} has no track. Record awareness with a track first; the tests "
                "for a vulnerability and for an incident are different provisions."
            )
        result = triage(case.track, answers, reasoning)

        if result.reportable is False and result.reopen_trigger_required and not reopen_trigger:
            raise EvidenceIncompleteError(
                f"ground '{result.ground.value if result.ground else ''}' can stop being true "
                f"without any action by us ({result.authority}). A reopen trigger is required "
                "— name the circumstance that would make this reportable."
            )

        kind = CASE_KIND["non_report"] if result.reportable is False else CASE_KIND["triage"]
        body: dict[str, Any] = {"triage": result.to_dict()}
        if reopen_trigger:
            body["reopen_trigger"] = reopen_trigger

        skipped: list[str] = list((result.unanswered and
            [f"question left undetermined: {q}" for q in result.unanswered]) or [])
        if result.track is Track.INCIDENT and result.reportable is not None:
            skipped.append(
                "'sensitive or important data or functions' (Art. 14(5)(a)) is undefined in the "
                "Regulation and unelaborated in the Commission FAQ and guidance; this judgement "
                "has no official interpretive support"
            )

        evidence = self._append(
            case_id,
            kind,
            body,
            actor,
            state=(
                ValidationState.INDETERMINATE
                if result.reportable is None
                else ValidationState.VERIFIED
            ),
            checks_skipped=tuple(skipped),
        )
        return evidence, result

    def record_availability(self, case_id: str, product: ProductVersion, actor: Actor) -> Evidence:
        """Attach the product and Member State record the filing needs."""
        gaps = product.gaps()
        return self._append(
            case_id,
            "art14.availability",
            {"product": product.to_dict()},
            actor,
            state=ValidationState.VERIFIED if not gaps else ValidationState.INDETERMINATE,
            checks_skipped=tuple(gaps),
        )

    def record_measure_available(
        self, case_id: str, at: datetime, description: str, actor: Actor
    ) -> Evidence:
        """Record the moment a corrective OR mitigating measure became available.

        This starts the 14-day vulnerability final-report clock (Art. 14(2)(c)).
        A documented workaround starts it exactly as a patch does, which is why
        this is a separate act from shipping a release.
        """
        case = self._load(case_id)
        if case.awareness is None:
            raise CaseError(f"case {case_id} has no awareness record")
        return self._append(
            case_id,
            "art14.measure",
            {"available_at": format_utc(at), "description": description},
            actor,
            state=ValidationState.VERIFIED,
            checks_skipped=(
                (
                    "a mitigating measure starts the Art. 14(2)(c) clock as surely as a corrective "
                    "one; confirm this is the earliest measure that became available"
                ),
            ),
        )

    def record_filing(
        self,
        case_id: str,
        stage: Stage,
        submitted_at: datetime,
        payload: dict[str, Any],
        actor: Actor,
        platform_reference: str = "",
    ) -> tuple[Evidence, PayloadValidation]:
        """Record a submission, with the payload validated against the field spec."""
        case = self._load(case_id)
        if case.awareness is None or case.track is None:
            raise CaseError(
                f"case {case_id} has no awareness record, so no deadline is running and no "
                "filing is due yet"
            )
        if case.triage_result is not None and case.triage_result.reportable is False:
            raise CaseError(
                f"case {case_id} was closed as not reportable on ground "
                f"'{case.ground.value if case.ground else ''}'. Supersede that decision before "
                "filing."
            )
        if stage is Stage.FINAL:
            deadlines = case.deadlines
            assert deadlines is not None
            deadlines.require_final()  # raises ClockError with the reason

        validation = validate_payload(payload, case.track, stage)
        evidence = self._append(
            case_id,
            CASE_KIND["filing"],
            {
                "stage": stage.value,
                "submitted_at": format_utc(submitted_at),
                "platform_reference": platform_reference,
                "payload": payload,
                "validation": validation.to_dict(),
            },
            actor,
            state=ValidationState.VERIFIED if validation.submittable else ValidationState.INDETERMINATE,
            checks_skipped=validation.checks_skipped,
        )
        return evidence, validation

    def record_user_notification(
        self,
        case_id: str,
        at: datetime,
        scope: str,
        content: str,
        actor: Actor,
        *,
        public: bool = False,
    ) -> Evidence:
        """Record the Article 14(8) notification to users.

        The trigger is becoming aware, not the availability of a fix. And the
        guidance is explicit that this is not an obligation to publish: it may
        be limited to the users concerned, particularly where publishing
        technical detail would itself increase risk.
        """
        return self._append(
            case_id,
            CASE_KIND["user_notice"],
            {
                "at": format_utc(at),
                "scope": scope,
                "content": content,
                "public_disclosure": public,
            },
            actor,
            state=ValidationState.VERIFIED,
            checks_skipped=(
                (
                    "Art. 14(8) requires impacted users to be informed, and where appropriate all "
                    "users; 'where appropriate' is a judgement this record does not make for you "
                    "(guidance §§219-221)"
                ),
            ),
        )

    # -- reading ----------------------------------------------------------
    def _load(self, case_id: str) -> Case:
        case = Case(case_id=case_id)
        for entry in self.ledger.entries(subject=case_id):
            body = entry.payload.get("body", {})
            kind = entry.kind
            if kind == CASE_KIND["signal"]:
                case.signal = Signal.from_dict(body["signal"])
            elif kind == CASE_KIND["awareness"]:
                case.awareness = Awareness.from_dict(body["awareness"])
                case.track = Track(body["track"])
            elif kind in (CASE_KIND["triage"], CASE_KIND["non_report"]):
                t = body["triage"]
                case.triage_result = TriageResult(
                    track=Track(t["track"]),
                    reportable=t["reportable"],
                    answered=dict(t.get("answered", {})),
                    ground=NonReportGround(t["ground"]) if t.get("ground") else None,
                    authority=t.get("authority", ""),
                    unanswered=tuple(t.get("unanswered", ())),
                    reasoning=t.get("reasoning", ""),
                    reopen_trigger_required=bool(t.get("reopen_trigger_required", False)),
                    upstream_duty_remains=bool(t.get("upstream_duty_remains", False)),
                    notes=tuple(t.get("notes", ())),
                )
                case.ground = case.triage_result.ground
                case.reopen_trigger = body.get("reopen_trigger", case.reopen_trigger)
            elif kind == "art14.availability":
                case.product = ProductVersion.from_dict(body["product"])
            elif kind == "art14.measure":
                case.measure_available_at = parse_utc(body["available_at"])
            elif kind == CASE_KIND["filing"]:
                case.filings[body["stage"]] = parse_utc(body["submitted_at"])
            elif kind == CASE_KIND["user_notice"]:
                case.users_informed_at = parse_utc(body["at"])
        return case

    def case(self, case_id: str) -> Case:
        return self._load(case_id)

    def case_ids(self) -> list[str]:
        seen: list[str] = []
        for entry in self.ledger.entries():
            if entry.subject and entry.subject not in seen:
                seen.append(entry.subject)
        return seen

    def cases(self) -> list[Case]:
        return [self._load(cid) for cid in self.case_ids()]

    def breaches(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Every deadline missed or currently overdue, across all cases."""
        found: list[dict[str, Any]] = []
        reference = now or utc_now()
        for case in self.cases():
            deadlines = case.deadlines
            if deadlines is None:
                continue
            for d in deadlines.all():
                overdue = d.submitted_at is None and d.due_at < reference
                if d.met is False or overdue:
                    found.append(
                        {
                            "case_id": case.case_id,
                            "stage": d.stage.value,
                            "provision": d.provision,
                            "due_at": format_utc(d.due_at),
                            "submitted_at": format_utc(d.submitted_at) if d.submitted_at else None,
                            "status": "filed_late" if d.met is False else "overdue_unfiled",
                        }
                    )
        return found
