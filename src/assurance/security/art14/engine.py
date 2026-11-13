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

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from ...core.actor_names import actor_name_problem
from ...core.errors import (
    AssuranceError,
    EvidenceIncompleteError,
    LedgerConflictError,
    LedgerIntegrityError,
)
from ...core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from ...core.identity import format_utc, parse_utc, utc_now
from ...evidence.ledger import EvidenceLedger, LedgerEntry
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


def _require_person(actor: Actor, what: str) -> None:
    """Awareness, triage, filing and closure are human decisions; software drafts.

    A signal may be raised by monitoring (the bridge opens cases from advisories), but the
    legal moment of awareness, the reportability call, a submission and the closing of a case
    each need a person who can be asked about it, and so do the two records that start or
    answer a duty (the availability of a measure, which starts the 14-day final-report clock,
    and the notice to users). An ``automation`` or ``service`` actor is refused; nothing is
    recorded.
    """
    if actor.kind != "person":
        raise CaseError(
            f"{what} is a human decision and cannot be recorded by an actor of kind "
            f"'{actor.kind}' ({actor.identifier}). Software may draft it; a named person "
            "records it. Nothing was recorded."
        )
    # ``kind`` is declared by the caller (the HTTP body defaults it to ``person``), so it is
    # not enough on its own: software that labels itself a person under the name automation
    # goes by is still software. The same rule the change workflow applies to its decisions.
    problem = actor_name_problem(actor.identifier)
    if problem:
        raise CaseError(
            f"{what} is a human decision and needs a named person. Actor "
            f"{actor.identifier[:60]!r} is not a name a person could have ({problem}). "
            "Software may draft it; a named person records it. Nothing was recorded."
        )


def _not_in_future(at: datetime, field: str, reference: datetime) -> None:
    if at - reference > timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise CaseError(
            f"{field} {format_utc(at)} is in the future (after {format_utc(reference)} plus "
            f"the {CLOCK_SKEW_SECONDS} s clock-skew allowance). A fact that has not happened "
            "cannot start or satisfy a legal clock; record it when it has. Nothing was recorded."
        )


def _require_open_case(case: Case, case_id: str, what: str) -> None:
    """A record belongs to a case that exists: one opened by a signal.

    Without this a mistyped case id silently opens a phantom case with no signal and no
    deadlines, which the register would list beside the real ones.
    """
    if case.signal is None:
        raise CaseError(
            f"case {case_id} has no signal, so {what} has nothing to attach to. Record the "
            "signal first (or check the case id). Nothing was recorded."
        )


def _who(entry: Any) -> str:
    actor = entry.payload.get("actor") or {}
    ident = str(actor.get("identifier", "")) or "(unnamed)"
    role = str(actor.get("role", ""))
    return f"{ident} ({role})" if role else ident


def _awareness_item(entry: Any, awareness: Awareness, *, status: str) -> dict[str, Any]:
    return {
        "ledger_seq": entry.seq,
        "content_hash": entry.content_hash,
        "recorded_at": entry.at,
        "recorded_by": _who(entry),
        "established_at": format_utc(awareness.established_at),
        "reasoning": awareness.reasoning,
        "status": status,
        "supersedes": None,
        "supersession_reason": None,
        "superseded_by": None,
    }


def _history_item(entry: Any, body: dict[str, Any]) -> dict[str, Any]:
    """One ledger record of a case in words. Never carries a filing payload or free text bodies."""
    kind = entry.kind
    try:
        if kind == CASE_KIND["signal"]:
            s = body["signal"]
            text = f"signal received {s['received_at']} via {s.get('channel', '')}"
        elif kind == CASE_KIND["awareness"]:
            text = (
                f"awareness established at {body['awareness']['established_at']} "
                f"(track {body.get('track', '')})"
            )
        elif kind == CASE_KIND["awareness_supersession"]:
            text = (
                f"awareness SUPERSEDED: {body['previous_awareness']['established_at']} -> "
                f"{body['awareness']['established_at']}; reason: {body.get('reason', '')}; "
                f"supersedes record {str(body.get('supersedes', ''))[:16]}"
            )
        elif kind in (CASE_KIND["triage"], CASE_KIND["non_report"]):
            t = body["triage"]
            text = f"triage: {t.get('status', '')}" + (
                f" (ground {t['ground']})" if t.get("ground") else ""
            )
        elif kind == "art14.availability":
            text = f"product and Member States recorded for {body['product'].get('product_name', '')}"
        elif kind == "art14.measure":
            text = f"measure available at {body['available_at']}"
        elif kind == CASE_KIND["filing"]:
            text = (
                f"{body['stage']} filing DECLARED by the manufacturer as submitted "
                f"{body['submitted_at']}; not verified by the reporting platform; content "
                + ("complete" if (body.get("validation") or {}).get("submittable", True)
                   else "INCOMPLETE")
            )
        elif kind == CASE_KIND["user_notice"]:
            text = f"users notified at {body['at']} (scope: {body.get('scope', '')})"
        else:
            text = kind
    except (KeyError, TypeError):
        text = f"{kind} (body could not be summarised)"
    return {
        "ledger_seq": entry.seq,
        "recorded_at": entry.at,
        "kind": kind,
        "recorded_by": _who(entry),
        "actor_kind": str((entry.payload.get("actor") or {}).get("kind", "")),
        "content_hash": entry.content_hash,
        "summary": text,
    }


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
    #: Every counted filing time per stage, ascending (complete and incomplete alike).
    filing_times: dict[str, list[datetime]] = None  # type: ignore[assignment]
    #: Decisions recorded (in a ledger written before this was enforced) by a non-person actor.
    non_person_records: list[str] = None  # type: ignore[assignment]
    #: Ledger position of the measure record the 14-day clock runs from (the earliest one).
    measure_source: dict[str, Any] | None = None
    #: Content hash of the awareness record that is currently in force.
    awareness_hash: str = ""
    #: Every awareness record in order (the original and each supersession), with which one is
    #: in force. The earlier ones are never removed or edited: they are what was recorded.
    awareness_history: list[dict[str, Any]] = None  # type: ignore[assignment]
    #: Each awareness-derived deadline a supersession moved, who moved it and why.
    deadline_shifts: list[dict[str, Any]] = None  # type: ignore[assignment]
    #: Records whose references do not fit the case they sit in; shown, never dropped.
    anomalies: list[str] = None  # type: ignore[assignment]
    #: The audit history: every ledger record of this case, oldest first, in words.
    history: list[dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.awareness_history is None:
            self.awareness_history = []
        if self.deadline_shifts is None:
            self.deadline_shifts = []
        if self.anomalies is None:
            self.anomalies = []
        if self.history is None:
            self.history = []
        if self.filings is None:
            self.filings = {}
        if self.filing_times is None:
            self.filing_times = {}
        if self.non_person_records is None:
            self.non_person_records = []
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
            notification_first_recorded_at=(
                self.filing_times[Stage.NOTIFICATION.value][0]
                if self.filing_times.get(Stage.NOTIFICATION.value)
                else None
            ),
            conflicting_filing_times={
                stage: tuple(times)
                for stage, times in self.filing_times.items()
                if len(set(times)) > 1
            },
            sources=self._fact_sources(),
        )

    def _fact_sources(self) -> dict[str, dict[str, Any]]:
        """Where in the ledger the facts the deadlines run from were recorded, when known."""
        sources: dict[str, dict[str, Any]] = {}
        if self.awareness_history:
            current = self.awareness_history[-1]   # the record in force is always the last one
            kinds = {h["ledger_seq"]: h["actor_kind"] for h in self.history}
            sources["awareness"] = {
                "ledger_seq": current["ledger_seq"],
                "content_hash": current["content_hash"],
                "recorded_by": current["recorded_by"],
                "actor_kind": kinds.get(current["ledger_seq"], ""),
            }
        if self.measure_source is not None:
            sources["measure"] = dict(self.measure_source)
        return sources

    @property
    def state(self) -> str:
        if self.ground is not None:
            return "closed_not_reportable"
        if self.awareness is None:
            return "signal_received"
        if self.triage_result is None or self.triage_result.reportable is None:
            return "awaiting_triage"
        if self._closable():
            return "closed_filed"
        return "reportable_open"

    def _closable(self) -> bool:
        """All three stages filed and complete. There is no waiver record in this version.

        An incomplete filing is evidence that something was submitted, not that the case is
        finished. A final report alone does not finish a case whose early warning and
        notification were never recorded: those stay outstanding, and the case stays open.
        """
        return all(
            stage.value in self.filings and stage.value not in self.incomplete_stages
            for stage in (Stage.EARLY_WARNING, Stage.NOTIFICATION, Stage.FINAL)
        )

    def _supersession_notes(self) -> list[str]:
        """What a correction of the awareness moment did to the deadlines, in plain words.

        Always listed, for as long as the case exists: a deadline that moved is a fact a
        reader of the case must meet, not one they have to dig for in the history.
        """
        notes: list[str] = []
        for shift in self.deadline_shifts:
            late_move = shift["original_already_passed"] and shift["moved_later"]
            lead = (
                "DEADLINE MOVED LATER AFTER THE ORIGINAL HAD ALREADY PASSED"
                if late_move
                else "DEADLINE RECOMPUTED"
            )
            tail = (
                " The original deadline had passed when this was recorded, so the case still "
                "reports it as a breach until a person confirms the correction."
                if late_move
                else ""
            )
            notes.append(
                f"{lead}: {shift['stage_label']} from {shift['from_due_at']} to "
                f"{shift['to_due_at']} by {shift['by']}, reason: {shift['reason']} "
                f"(superseding record {shift['record'][:16]}; the original awareness record "
                f"{shift['supersedes'][:16]} stays in the ledger).{tail}"
            )
        superseded = [h for h in self.awareness_history if h.get("supersedes")]
        if superseded and not self.deadline_shifts:
            last = superseded[-1]
            notes.append(
                f"AWARENESS SUPERSEDED by {last['recorded_by']}, reason: "
                f"{last['supersession_reason']}; no awareness-derived deadline moved."
            )
        if superseded:
            notes.append(
                "Art. 14 and guidance C(2026) 5252 do not provide for correcting a recorded "
                "awareness moment. This register keeps the original, treats the latest "
                "superseding record as the awareness in force, and does not decide whether an "
                "authority accepts the correction."
            )
        notes.extend(f"ANOMALY: {a}" for a in self.anomalies)
        return notes

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
        out.extend(self._supersession_notes())
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
            for stage, times in sorted(deadlines.conflicting_filing_times.items()):
                shown = ", ".join(format_utc(t) for t in times)
                out.append(
                    f"CONFLICTING FILING TIMES for {stage}: {shown}. The deadline view uses the "
                    "earliest of the complete filings (earliest of any, if none is complete); "
                    "these are declarations nothing here can check against the platform. A "
                    "person must confirm which is right."
                )
        if (
            Stage.FINAL.value in self.filings
            and self.triage_result is not None
            and not self._closable()
        ):
            missing = [
                s.label
                for s in (Stage.EARLY_WARNING, Stage.NOTIFICATION, Stage.FINAL)
                if s.value not in self.filings or s.value in self.incomplete_stages
            ]
            out.append(
                "NOT CLOSED: a final filing is recorded, but "
                + ", ".join(missing)
                + " is not filed with complete content. A case closes only when the early "
                "warning, the notification and the final report are each filed; there is no "
                "waiver record."
            )
        for note in self.non_person_records:
            out.append(
                f"{note} Awareness, triage, filing, closure, the measure that starts the "
                "final-report clock and the user notice are recorded by a person; a person "
                "must confirm this record."
            )
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
            "awareness_record": self.awareness_hash or None,
            "awareness_history": [dict(h) for h in self.awareness_history],
            "deadline_shifts": [dict(x) for x in self.deadline_shifts],
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
        # The entry the LAST append on this thread produced. A register is shared by every
        # request thread of a worker, so it is thread-local: an HTTP answer must name the
        # sequence number its own write received, not one a concurrent request or an identical
        # earlier record happens to have (the ledger does not make content hashes unique).
        self._written = threading.local()

    def last_entry(self) -> LedgerEntry | None:
        """The ledger entry this thread's most recent append produced, or ``None``."""
        return getattr(self._written, "entry", None)

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
            self._written.entry = self.ledger.append(
                evidence, subject=case_id, expect_subject_head=expect_head)
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
        self,
        case_id: str,
        awareness: Awareness,
        track: Track,
        actor: Actor,
        *,
        now: datetime | None = None,
    ) -> Evidence:
        """Fix the moment every deadline runs from. A person records it; software drafts.

        None of the assessment times may be later than ``now`` plus :data:`CLOCK_SKEW_SECONDS`.
        """
        _require_person(actor, "recording awareness (the legal moment every deadline runs from)")
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
                "deadline, so this call never replaces it. A wrongly recorded awareness is "
                "corrected by an explicit, reasoned supersession (art14 supersede-awareness; "
                "POST /v1/cases/{case_id}/awareness/supersede): it appends a new record, keeps "
                "this one in the ledger, and shows every deadline it moves. Nothing was recorded."
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
        reference = now or utc_now()
        _not_in_future(awareness.established_at, "awareness established_at", reference)
        _not_in_future(awareness.assessment_started_at, "assessment_started_at", reference)
        _not_in_future(awareness.assessment_completed_at, "assessment_completed_at", reference)
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
                    "the pinned platform field specification (Glossary v1.3) is older than the "
                    "live glossary (v1.6, 21 October 2026), which lists an awareness field for "
                    "both tracks; the field table has not been re-pinned and the platform has "
                    "not been observed. This record is the evidence of the moment and of the "
                    "reasoning either way"
                ),
            ),
            expect_head=head,
        )

    def supersede_awareness(
        self,
        case_id: str,
        awareness: Awareness,
        reason: str,
        supersedes: str,
        actor: Actor,
        *,
        now: datetime | None = None,
    ) -> Evidence:
        """Correct a wrongly recorded awareness by APPENDING a record that supersedes it.

        Nothing is edited or deleted: the earlier awareness stays in the ledger and in the case
        history, and the deadlines are computed from the newest awareness in force. What this
        guards, because a deadline is a legal fact:

        * a named person records it (``actor.kind == "person"``) and gives a reason;
        * ``supersedes`` must be the content hash (or a prefix of at least 12 characters) of the
          awareness record currently in force, so a stale view cannot supersede the wrong record;
        * a closed case is refused, and so is a case with ANY filing recorded: a declared
          submission was made against the deadlines as they stood, and moving them under it
          would rewrite what that filing answered. Art. 14 does not say how a filed awareness is
          corrected, and this register does not invent a rule; that is for a person outside it;
        * the track is not changed (a different track is a different set of provisions);
        * a deadline that moves is listed on the case with the person and the reason, and one
          that was already past when the correction was recorded, and is moved later, keeps
          appearing as a breach.
        """
        _require_person(actor, "superseding a recorded awareness")
        case, head = self._load_for_write(case_id)
        if case.awareness is None or case.track is None:
            raise CaseError(
                f"case {case_id} has no awareness record to supersede. Record the awareness "
                "first. Nothing was recorded."
            )
        if case.state.startswith("closed"):
            raise CaseError(
                f"case {case_id} is closed ({case.state}). An awareness is not superseded on a "
                "closed case: a person reopens the question outside this register. Nothing was "
                "recorded."
            )
        filed = sorted(
            set(case.filing_times) | {f["stage"] for f in case.uncounted_filings}
        )
        if filed:
            raise CaseError(
                f"case {case_id} already has a filing recorded ({', '.join(filed)}). A filing is "
                "the manufacturer's declaration that it answered the deadlines as they stood; "
                "superseding the awareness would move the deadlines under it. Art. 14 does not "
                "provide a correction after filing and this register does not invent one. The "
                "filing and the awareness stay as recorded. Nothing was recorded."
            )
        if not str(reason).strip():
            raise EvidenceIncompleteError(
                "a supersession needs a reason: why the awareness recorded earlier was wrong. "
                "Nothing was recorded."
            )
        ref = str(supersedes).strip().lower()
        if len(ref) < 12 or not case.awareness_hash.startswith(ref):
            raise CaseError(
                "supersedes must name the awareness record currently in force "
                f"({case.awareness_hash[:16]}…) by its content hash, at least 12 characters; got "
                f"{str(supersedes).strip()[:20]!r}. Nothing was recorded."
            )
        if not awareness.reasoning.strip():
            raise EvidenceIncompleteError(
                "an awareness record without reasoning is not evidence. Guidance §213 "
                "makes this a judgement about reasonable certainty; record the judgement."
            )
        if case.signal is not None and awareness.established_at < case.signal.received_at:
            raise CaseError(
                "awareness cannot precede the signal that produced it "
                f"({format_utc(awareness.established_at)} < "
                f"{format_utc(case.signal.received_at)}). Nothing was recorded."
            )
        if case.users_informed_at is not None and case.users_informed_at < awareness.established_at:
            raise CaseError(
                f"users were recorded as informed at {format_utc(case.users_informed_at)}, before "
                f"this awareness ({format_utc(awareness.established_at)}). Users cannot be "
                "informed before the manufacturer became aware. Nothing was recorded."
            )
        if (
            case.measure_available_at is not None
            and case.measure_available_at < awareness.established_at
        ):
            raise CaseError(
                f"a measure was recorded as available at {format_utc(case.measure_available_at)}, "
                f"before this awareness ({format_utc(awareness.established_at)}). Nothing was "
                "recorded."
            )
        reference = now or utc_now()
        _not_in_future(awareness.established_at, "awareness established_at", reference)
        _not_in_future(awareness.assessment_started_at, "assessment_started_at", reference)
        _not_in_future(awareness.assessment_completed_at, "assessment_completed_at", reference)
        require_deadline_arithmetic(
            awareness.established_at, case.measure_available_at, field="established_at"
        )
        return self._append(
            case_id,
            CASE_KIND["awareness_supersession"],
            {
                "track": case.track.value,
                "supersedes": case.awareness_hash,
                "reason": str(reason).strip(),
                "awareness": awareness.to_dict(),
                "previous_awareness": case.awareness.to_dict(),
            },
            actor,
            state=ValidationState.UNVERIFIED,
            confidence=Confidence.NONE,
            checks_skipped=(
                (
                    "Art. 14 and guidance C(2026) 5252 do not provide for correcting a recorded "
                    "awareness moment; this is the manufacturer's own correction, kept beside "
                    "the original, and no authority has accepted or checked it"
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
        """Work the decision path and record the outcome, whichever way it goes.

        Reportability (and so closing a case as not reportable) is a human decision: only a
        ``person`` actor may record it.
        """
        _require_person(actor, "the reportability decision (triage)")
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
        case, head = self._load_for_write(case_id)
        _require_open_case(case, case_id, "a product and Member State record")
        gaps = product.gaps()
        return self._append(
            case_id,
            "art14.availability",
            {"product": product.to_dict()},
            actor,
            state=ValidationState.VERIFIED if not gaps else ValidationState.INDETERMINATE,
            checks_skipped=tuple(gaps),
            expect_head=head,
        )

    def record_measure_available(
        self,
        case_id: str,
        at: datetime,
        description: str,
        actor: Actor,
        *,
        now: datetime | None = None,
    ) -> Evidence:
        """Record the moment a corrective OR mitigating measure became available.

        This starts the 14-day vulnerability final-report clock (Art. 14(2)(c)).
        A documented workaround starts it exactly as a patch does, which is why
        this is a separate act from shipping a release.

        A named person records it (the same rule as awareness and a filing): this record starts
        a legal clock, and the CRA does not define when a measure "is available", so someone
        must be able to be asked what was judged to be available. Software may draft it.
        """
        _require_person(
            actor,
            "recording that a corrective or mitigating measure is available "
            "(it starts the Art. 14(2)(c) final-report clock)",
        )
        case, head = self._load_for_write(case_id)
        if case.awareness is None:
            raise CaseError(f"case {case_id} has no awareness record")
        _not_in_future(at, "measure available_at", now or utc_now())
        if at < case.awareness.established_at:
            raise CaseError(
                f"a measure cannot have become available before awareness ({format_utc(at)} < "
                f"{format_utc(case.awareness.established_at)}); a measure dated before awareness "
                "would start the final-report clock before the case existed. Nothing was recorded."
            )
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
        _require_person(actor, "a filing (the submission to the reporting platform)")
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
        earlier = min(case.filing_times.get(stage.value, ()), default=None)
        if earlier is not None and submitted_at < earlier:
            raise CaseError(
                f"a {stage.value} filing is already recorded for case {case_id} with submission "
                f"time {format_utc(earlier)}; a later record cannot declare an EARLIER time "
                f"({format_utc(submitted_at)}) for the same stage, because that would move the "
                "stage's lateness after the fact. The original stays. This version has no "
                "supersede record: a genuine correction is an operator action outside the "
                "register. Recording the same time again, or a later one, is accepted. "
                "Nothing was recorded."
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
        now: datetime | None = None,
    ) -> Evidence:
        """Record the Article 14(8) notification to users.

        The trigger is becoming aware, not the availability of a fix. And the
        guidance is explicit that this is not an obligation to publish: it may
        be limited to the users concerned, particularly where publishing
        technical detail would itself increase risk.

        A named person records it: that users were informed, to what scope and when, is a
        statement the manufacturer answers for. Software may draft it.
        """
        _require_person(actor, "recording that users were informed (Art. 14(8))")
        case, head = self._load_for_write(case_id)
        _require_open_case(case, case_id, "a user notification")
        _not_in_future(at, "user notification time", now or utc_now())
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
            actor_kind = str((entry.payload.get("actor") or {}).get("kind", "person"))
            if actor_kind != "person" and kind in (
                CASE_KIND["awareness"],
                CASE_KIND["awareness_supersession"],
                CASE_KIND["triage"],
                CASE_KIND["non_report"],
                CASE_KIND["filing"],
                # The measure record starts the 14-day clock and the user notice answers
                # Art. 14(8); both are person-gated now, so a non-person one is a legacy or
                # hand-written record and is shown, not trusted.
                "art14.measure",
                CASE_KIND["user_notice"],
            ):
                case.non_person_records.append(
                    f"ledger seq {entry.seq} ({kind}) was recorded by an actor of kind "
                    f"'{actor_kind}'."
                )
            case.history.append(_history_item(entry, body))
            if kind == CASE_KIND["signal"]:
                case.signal = Signal.from_dict(body["signal"])
            elif kind == CASE_KIND["awareness"]:
                case.awareness = Awareness.from_dict(body["awareness"])
                case.track = Track(body["track"])
                case.awareness_hash = entry.content_hash
                case.awareness_history.append(
                    _awareness_item(entry, case.awareness, status="in_force")
                )
            elif kind == CASE_KIND["awareness_supersession"]:
                self._apply_supersession(case, entry, body)
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
                    case.measure_source = {
                        "ledger_seq": entry.seq,
                        "content_hash": entry.content_hash,
                        "recorded_by": _who(entry),
                        "actor_kind": actor_kind,
                    }
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
                case.filing_times.setdefault(stage, []).append(at)
                bucket = filings_valid if valid else filings_any
                if stage not in bucket or at < bucket[stage][0]:
                    bucket[stage] = (at, has_ref)
            elif kind == CASE_KIND["user_notice"]:
                at = parse_utc(body["at"])
                if case.users_informed_at is None or at < case.users_informed_at:
                    case.users_informed_at = at
        for times in case.filing_times.values():
            times.sort()
        counted = {**filings_any, **filings_valid}
        case.filings = {stage: at for stage, (at, _) in counted.items()}
        case.referenced_stages = frozenset(stage for stage, (_, ref) in counted.items() if ref)
        case.incomplete_stages = frozenset(s for s in counted if s not in filings_valid)
        return case, head

    @staticmethod
    def _apply_supersession(case: Case, entry: Any, body: dict[str, Any]) -> None:
        """Fold one supersession into the case view: new awareness in force, shifts listed."""
        new = Awareness.from_dict(body["awareness"])
        ref = str(body.get("supersedes", ""))
        prior, prior_hash = case.awareness, case.awareness_hash
        by = _who(entry)
        reason = str(body.get("reason", ""))
        if prior is None or ref != prior_hash:
            case.anomalies.append(
                f"ledger seq {entry.seq} supersedes {ref[:16] or '(nothing named)'}, which is not "
                f"the awareness in force at that point ({prior_hash[:16] or 'none'}). It is "
                "applied as recorded; a person must confirm it."
            )
        if prior is not None:
            try:
                recorded = parse_utc(entry.at)
            except ValueError:
                recorded = None
            for stage, hours, label in (
                (Stage.EARLY_WARNING, 24, Stage.EARLY_WARNING.label),
                (Stage.NOTIFICATION, 72, Stage.NOTIFICATION.label),
            ):
                old_due = prior.established_at + timedelta(hours=hours)
                new_due = new.established_at + timedelta(hours=hours)
                if old_due == new_due:
                    continue
                case.deadline_shifts.append(
                    {
                        "stage": stage.value,
                        "stage_label": label,
                        "from_due_at": format_utc(old_due),
                        "to_due_at": format_utc(new_due),
                        "moved_later": new_due > old_due,
                        "original_already_passed": recorded is None or old_due < recorded,
                        "by": by,
                        "reason": reason,
                        "record": entry.content_hash,
                        "supersedes": ref,
                        "recorded_at": entry.at,
                    }
                )
        for item in case.awareness_history:
            if item["content_hash"] == ref:
                item["status"] = "superseded"
                item["superseded_by"] = entry.content_hash
        case.awareness = new
        case.awareness_hash = entry.content_hash
        item = _awareness_item(entry, new, status="in_force")
        item["supersedes"] = ref
        item["supersession_reason"] = reason
        case.awareness_history.append(item)

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
            for shift in case.deadline_shifts:
                if shift["moved_later"] and shift["original_already_passed"]:
                    found.append(
                        {
                            "case_id": case.case_id,
                            "stage": shift["stage"],
                            "provision": None,
                            "due_at": shift["to_due_at"],
                            "original_due_at": shift["from_due_at"],
                            "submitted_at": None,
                            "status": "deadline_moved_later_after_original_passed",
                            "moved_by": shift["by"],
                            "reason": shift["reason"],
                            "superseding_record": shift["record"],
                            "verified_by_platform": False,
                        }
                    )
            deadlines = case.deadlines
            if deadlines is None:
                continue
            closed_not_reportable = case.state == "closed_not_reportable"
            for d in deadlines.all():
                if closed_not_reportable and d.submitted_at is None:
                    # A person closed this case as not reportable: no submission is owed, and the
                    # case view already lists no deadline. An unfiled stage is not a breach.
                    continue
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
