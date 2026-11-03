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
from datetime import datetime, timedelta
from typing import Any

from ...core.errors import (
    AssuranceError,
    EvidenceIncompleteError,
    LedgerConflictError,
    LedgerIntegrityError,
)
from ...core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from ...core.identity import format_utc, parse_utc, utc_now
from ...evidence.ledger import EvidenceLedger
from .clock import Deadlines
from .model import CASE_KIND, Awareness, NonReportGround, ProductVersion, Signal, Stage, Track
from .srp import PayloadValidation, validate_payload
from .timestamps import require_deadline_arithmetic
from .triage import Answer, Question, TriageResult, triage

__all__ = ["Art14Register", "Case", "CaseError"]

_ORIGIN = Origin(system="assurance.security.art14", method="recorded via Art14Register")

#: How far ahead of "now" a declared submission time may be before it is refused. A
#: filing cannot have happened in the future; this allowance covers clock skew between
#: the person's machine and this one, not planned submissions.
CLOCK_SKEW_SECONDS = 300


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
    #: Stages whose only counted filing failed the blocking field checks.
    incomplete_stages: frozenset[str] = frozenset()
    #: Stages whose counted filing carries a (declared, unchecked) platform reference.
    referenced_stages: frozenset[str] = frozenset()
    #: Filings kept in the ledger but NOT counted: their submission time is later than
    #: the ledger's own time of recording them (plus the skew allowance).
    uncounted_filings: list[dict[str, str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.filings is None:
            self.filings = {}
        if self.uncounted_filings is None:
            self.uncounted_filings = []

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
            incomplete_stages=self.incomplete_stages,
            referenced_stages=self.referenced_stages,
        )

    @property
    def state(self) -> str:
        if self.ground is not None:
            return "closed_not_reportable"
        if self.awareness is None:
            return "signal_received"
        if self.triage_result is None or self.triage_result.reportable is None:
            return "awaiting_triage"
        if Stage.FINAL.value in self.filings and Stage.FINAL.value not in self.incomplete_stages:
            # An incomplete final filing is evidence that something was submitted, not that the
            # case is finished: it stays open until a complete one is recorded.
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
                elif d.status == "recorded_incomplete":
                    out.append(
                        f"RECORDED WITH INCOMPLETE CONTENT: {d.stage.label} ({d.provision}) was "
                        f"recorded as submitted at {format_utc(d.submitted_at)} but its content "
                        "fails the blocking checks of the field specification. It is not counted "
                        f"as a met deadline (due {format_utc(d.due_at)}); record a complete "
                        "submission."
                    )
                elif d.met is False:
                    gap = "; its content is also incomplete" if not d.content_complete else ""
                    out.append(f"FILED LATE: {d.stage.label} ({d.provision}){gap}")
            out.extend(deadlines.pending_facts())
        for f in self.uncounted_filings:
            out.append(
                f"NOT COUNTED AS FILED: a {f['stage']} filing is recorded with submission time "
                f"{f['submitted_at']}, later than the time it was recorded in the ledger "
                f"({f['recorded_at']}). A submission cannot precede its own record; the "
                "deadline stays open."
            )
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
            "uncounted_filings": list(self.uncounted_filings),
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
        expect_head: int | None = None,
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
        try:
            # Compare-and-swap against the case entry the caller's decision was read
            # from, checked inside the write transaction: two writers cannot both
            # pass a "once" guard, and a clock-moving write cannot land on a case
            # that changed under it.
            self.ledger.append(evidence, subject=case_id, expect_subject_head=expect_head)
        except LedgerConflictError as exc:
            raise CaseError(
                f"case {case_id} changed while this record was being prepared; re-read the "
                f"case and decide again. Nothing was written. ({exc})"
            ) from exc
        return evidence

    def record_signal(self, case_id: str, signal: Signal, actor: Actor) -> Evidence:
        """Open a case with the first thing anyone heard.

        Recorded before anyone knows whether it matters, because the interval
        from here to awareness is the number that gets asked about and it cannot
        be reconstructed later.
        """
        case, head = self._load_for_write(case_id)
        if case.signal is not None:
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
            expect_head=head,
        )

    def record_awareness(
        self, case_id: str, awareness: Awareness, track: Track, actor: Actor
    ) -> Evidence:
        """Fix the moment every deadline runs from."""
        case, head = self._load_for_write(case_id)
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
        if case.users_informed_at is not None and case.users_informed_at < awareness.established_at:
            raise CaseError(
                "users were recorded as informed at "
                f"{format_utc(case.users_informed_at)}, before this awareness "
                f"({format_utc(awareness.established_at)}). Users cannot be informed before "
                "the manufacturer became aware; correct one of the two records."
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
        # Before the append: a record whose deadlines cannot be computed must not be written,
        # because the case would then fail on every later read and could not be corrected.
        require_deadline_arithmetic(
            awareness.established_at, case.measure_available_at, field="established_at"
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
            expect_head=head,
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
        case, head = self._load_for_write(case_id)
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
            expect_head=head,
        )
        return evidence, result

    def record_availability(self, case_id: str, product: ProductVersion, actor: Actor) -> Evidence:
        """Attach the product and Member State record the filing needs."""
        self._guard(write=True)  # the only write that does not read the case first
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
        case, head = self._load_for_write(case_id)
        if case.awareness is None:
            raise CaseError(f"case {case_id} has no awareness record")
        require_deadline_arithmetic(at, field="available_at")
        return self._append(
            case_id,
            "art14.measure",
            {"available_at": format_utc(at), "description": description},
            actor,
            state=ValidationState.VERIFIED,
            checks_skipped=(
                (
                    "a mitigating measure starts the Art. 14(2)(c) clock as surely as a corrective "
                    "one; the case clock runs from the earliest measure recorded"
                ),
            ),
            expect_head=head,
        )

    def record_filing(
        self,
        case_id: str,
        stage: Stage,
        submitted_at: datetime,
        payload: dict[str, Any],
        actor: Actor,
        platform_reference: str = "",
        *,
        now: datetime | None = None,
    ) -> tuple[Evidence, PayloadValidation]:
        """Record a submission, with the payload validated against the field spec.

        What is recorded is the caller's own declaration that a submission happened at
        ``submitted_at``; nothing here can check it against the reporting platform. A time
        later than ``now`` plus :data:`CLOCK_SKEW_SECONDS` is refused (``now`` is injectable
        for tests): a submission that has not happened cannot meet a deadline.

        A payload that fails the blocking field checks is still recorded, as evidence that
        something was submitted, but it is never counted as a met deadline (status
        ``recorded_incomplete``).
        """
        case, head = self._load_for_write(case_id)
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

        reference = now or utc_now()
        if submitted_at > reference + timedelta(seconds=CLOCK_SKEW_SECONDS):
            raise CaseError(
                f"a filing cannot be dated in the future ({format_utc(submitted_at)} is after "
                f"{format_utc(reference)} plus the {CLOCK_SKEW_SECONDS} s clock-skew allowance). "
                "A submission that has not happened cannot meet a deadline; record it when it "
                "has been made. Nothing was recorded."
            )
        require_deadline_arithmetic(submitted_at, field="submitted_at")
        if submitted_at < case.awareness.established_at:
            raise CaseError(
                "a filing cannot precede the awareness it answers "
                f"({format_utc(submitted_at)} < {format_utc(case.awareness.established_at)}); "
                "a submission time before awareness would make a late filing read as on time"
            )
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
            expect_head=head,
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
        case, head = self._load_for_write(case_id)
        if case.awareness is not None and at < case.awareness.established_at:
            raise CaseError(
                "users cannot be informed before the manufacturer became aware "
                f"({format_utc(at)} < {format_utc(case.awareness.established_at)})"
            )
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
            expect_head=head,
        )

    # -- reading ----------------------------------------------------------
    def _load(self, case_id: str) -> Case:
        return self._load_at_head(case_id)[0]

    def _guard(self, *, write: bool = False) -> None:
        """Refuse to read or extend a chain that does not verify (``ChainBrokenError``).

        Reads pay the incremental check; a write pays a full walk. A case folded from an edited
        ledger would show a moved deadline as fact.
        """
        self.ledger.require_intact(full=write)

    def _load_for_write(self, case_id: str) -> tuple[Case, int]:
        """:meth:`_load_at_head` for a decision that will be written: full chain walk first."""
        self._guard(write=True)
        return self._load_at_head(case_id)

    def _load_at_head(self, case_id: str) -> tuple[Case, int]:
        """The case and the seq of its newest entry (0 for none), read together."""
        self._guard()
        case = Case(case_id=case_id)
        head = 0
        filings_valid: dict[str, tuple[datetime, bool]] = {}
        filings_any: dict[str, tuple[datetime, bool]] = {}
        for entry in self.ledger.entries(subject=case_id):
            head = entry.seq
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
                # Earliest wins: a later record can never move a legal clock out.
                at = parse_utc(body["available_at"])
                if case.measure_available_at is None or at < case.measure_available_at:
                    case.measure_available_at = at
            elif kind == CASE_KIND["filing"]:
                at = parse_utc(body["submitted_at"])
                stage = body["stage"]
                # Earliest wins, but a payload that failed validation must not shadow a
                # later complete filing of the same stage. It still counts when nothing
                # valid exists: it was recorded as submitted, and dropping it could hide
                # a deadline that runs from it (the incident final report).
                #
                # A filing whose declared time is later than the moment the ledger recorded it
                # (plus the skew allowance) is not counted as filed at all: it claims to have
                # happened after it was written down. It stays in the ledger and is listed on
                # the case as not counted.
                try:
                    recorded = parse_utc(entry.at)
                except ValueError:
                    recorded = None
                if recorded is not None and at > recorded + timedelta(seconds=CLOCK_SKEW_SECONDS):
                    case.uncounted_filings.append(
                        {
                            "stage": stage,
                            "submitted_at": format_utc(at),
                            "recorded_at": format_utc(recorded),
                            "ledger_seq": str(entry.seq),
                        }
                    )
                    continue
                valid = (body.get("validation") or {}).get("submittable", True)
                has_ref = bool(str(body.get("platform_reference") or "").strip())
                bucket = filings_valid if valid else filings_any
                if stage not in bucket or at < bucket[stage][0]:
                    bucket[stage] = (at, has_ref)
            elif kind == CASE_KIND["user_notice"]:
                at = parse_utc(body["at"])
                if case.users_informed_at is None or at < case.users_informed_at:
                    case.users_informed_at = at
        counted = {**filings_any, **filings_valid}
        case.filings = {stage: at for stage, (at, _) in counted.items()}
        case.referenced_stages = frozenset(stage for stage, (_, ref) in counted.items() if ref)
        case.incomplete_stages = frozenset(s for s in counted if s not in filings_valid)
        return case, head

    def case(self, case_id: str) -> Case:
        return self._load(case_id)

    def case_ids(self) -> list[str]:
        self._guard()
        seen: dict[str, None] = {}
        for entry in self.ledger.entries():
            if entry.subject:
                seen.setdefault(entry.subject, None)
        return list(seen)

    def cases(self) -> list[Case]:
        """Every case that can be read. See :meth:`survey` for the ones that cannot."""
        return self.survey()[0]

    def survey(self, now: datetime | None = None) -> tuple[list[Case], list[dict[str, str]]]:
        """``(readable cases, unreadable cases)``: one bad case does not blind the register.

        A case is unreadable when its own records cannot be turned into a view (for example a
        legacy awareness record whose deadlines cannot be computed). It is never dropped
        silently: it comes back as ``{"case_id", "error"}`` and every consumer shows it.
        A broken chain is different: that refuses the whole read (``ChainBrokenError``).
        """
        reference = now or utc_now()
        readable: list[Case] = []
        unreadable: list[dict[str, str]] = []
        for cid in self.case_ids():
            try:
                case = self._load(cid)
                case.to_dict(reference)  # exercises every deadline computation
            except LedgerIntegrityError:
                raise
            except Exception as exc:  # noqa: BLE001 - flagged below, never swallowed
                unreadable.append({"case_id": cid, "error": f"{type(exc).__name__}: {exc}"})
                continue
            readable.append(case)
        return readable, unreadable

    def breaches(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Every deadline missed, overdue or recorded incomplete, across all cases.

        An unreadable case appears with status ``case_unreadable`` rather than vanishing.
        """
        found: list[dict[str, Any]] = []
        reference = now or utc_now()
        cases, unreadable = self.survey(reference)
        for case in cases:
            deadlines = case.deadlines
            if deadlines is None:
                continue
            for d in deadlines.all():
                overdue = d.submitted_at is None and d.due_at < reference
                incomplete_late = d.status == "recorded_incomplete" and d.due_at < reference
                if d.met is False or overdue or incomplete_late:
                    if d.met is False:
                        status = "filed_late"
                    elif incomplete_late:
                        status = "recorded_incomplete_past_due"
                    else:
                        status = "overdue_unfiled"
                    found.append(
                        {
                            "case_id": case.case_id,
                            "stage": d.stage.value,
                            "provision": d.provision,
                            "due_at": format_utc(d.due_at),
                            "submitted_at": format_utc(d.submitted_at) if d.submitted_at else None,
                            "status": status,
                            "submission_evidence": d.submission_evidence,
                            "verified_by_platform": False,
                        }
                    )
        for bad in unreadable:
            found.append(
                {
                    "case_id": bad["case_id"],
                    "stage": None,
                    "provision": None,
                    "due_at": None,
                    "submitted_at": None,
                    "status": "case_unreadable",
                    "detail": bad["error"],
                }
            )
        return found
