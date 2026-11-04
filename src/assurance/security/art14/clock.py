"""Deadlines.

Article 14 has six deadlines across two tracks, and three different facts start
them. Getting this wrong is the most common way a manufacturer files late while
believing it filed early, so the arithmetic lives here, in one place, with the
provision that justifies each rule written next to it.

    Vulnerability   early warning   24 h  from awareness
                    notification    72 h  from awareness
                    final report    14 d  from the date a corrective OR
                                          MITIGATING measure became available

    Incident        early warning   24 h  from awareness
                    notification    72 h  from awareness
                    final report     1 month from SUBMISSION of the 72 h
                                          notification

Two traps are encoded rather than commented:

* The vulnerability final-report clock is started by a *mitigating* measure as
  much as by a patch. A documented workaround starts it. Waiting for a release
  is how a 14-day deadline is missed by a month.
* The incident final-report clock runs from the submission of the 72-hour
  notification, not from awareness and not from remediation. Filing the 72-hour
  notification early therefore brings the final report forward.

There is also a defect in the reporting platform itself worth surfacing to a
user rather than silently disagreeing with: in the current release the 72-hour
counter is displayed as 48 hours after submission of the early warning, so the
platform can show a notification as overdue while it is still in time.
:func:`platform_displayed_notification_due` computes what the platform will
show, so a case view can display both and explain the difference.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ...core.errors import ClockError
from ...core.identity import format_utc, utc_now
from .model import Stage, Track

__all__ = [
    "EARLY_WARNING_HOURS",
    "NOTIFICATION_HOURS",
    "VULNERABILITY_FINAL_DAYS",
    "Deadline",
    "Deadlines",
    "add_one_month",
    "platform_displayed_notification_due",
]

EARLY_WARNING_HOURS = 24          # Art. 14(2)(a), 14(4)(a)
NOTIFICATION_HOURS = 72           # Art. 14(2)(b), 14(4)(b)
VULNERABILITY_FINAL_DAYS = 14     # Art. 14(2)(c)

#: ENISA CRA SRP FAQ 26: the displayed 72-hour counter is computed as this many
#: hours after submission of the early warning, not from awareness.
_PLATFORM_COUNTER_OFFSET_HOURS = 48


def add_one_month(moment: datetime) -> datetime:
    """Add one calendar month, clamping to the last valid day.

    Article 14(4)(c) says "within one month", which is a calendar month, not 30
    days. 31 January plus one month is the last day of February, not 3 March.
    Time of day is preserved.

    The arithmetic is done on the UTC instant, not in the submitter's own UTC offset. A
    submission near local midnight can therefore have a due time up to one calendar day earlier
    than the same wall-clock rule applied in the submitter's zone would give. That is the
    conservative direction (the deadline is never later than it should be); it is not corrected.
    """
    year = moment.year + (1 if moment.month == 12 else 0)
    month = 1 if moment.month == 12 else moment.month + 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def platform_displayed_notification_due(early_warning_submitted_at: datetime) -> datetime:
    """What the reporting platform's 72-hour counter currently displays.

    Not the legal deadline. Provided so a case view can show the discrepancy
    explicitly instead of appearing to contradict the platform.
    """
    return early_warning_submitted_at + timedelta(hours=_PLATFORM_COUNTER_OFFSET_HOURS)


@dataclass(frozen=True)
class Deadline:
    """One deadline, what starts it, and where it stands."""

    stage: Stage
    due_at: datetime
    runs_from: datetime
    runs_from_fact: str
    provision: str
    submitted_at: datetime | None = None
    #: False when the only filing counted for this stage failed the field
    #: specification's blocking checks (see ``srp.validate_payload``).
    content_complete: bool = True
    #: True when the counted filing carries a platform reference. It is the
    #: caller's own declaration; nothing here checks it against the platform.
    has_platform_reference: bool = False

    @property
    def met(self) -> bool | None:
        """True/False once the outcome is knowable; None while open or unprovable.

        A submission recorded after the due time is late whatever it contained (False). One
        recorded in time whose content failed the blocking field checks is neither met nor
        missed (None): the product cannot say a submission with blocking gaps satisfied the
        duty, and will not say it did not. Its recorded time is kept (``submitted_at``).
        """
        if self.submitted_at is None:
            return None
        if self.submitted_at > self.due_at:
            return False
        return True if self.content_complete else None

    @property
    def status(self) -> str:
        if self.submitted_at is None:
            return "open"
        if self.submitted_at > self.due_at:
            return "filed_late"
        return "filed_on_time" if self.content_complete else "recorded_incomplete"

    @property
    def recorded_after_due(self) -> bool | None:
        """Whether the recorded submission time is later than the due time (None if open)."""
        if self.submitted_at is None:
            return None
        return self.submitted_at > self.due_at

    @property
    def submission_evidence(self) -> str | None:
        """What stands behind the recorded submission. Always a declaration, never a check."""
        if self.submitted_at is None:
            return None
        return "declared_with_platform_reference" if self.has_platform_reference else "declared"

    def hours_remaining(self, now: datetime | None = None) -> float:
        """Negative once the deadline has passed."""
        reference = now or utc_now()
        return round((self.due_at - reference).total_seconds() / 3600.0, 2)

    def to_dict(self, now: datetime | None = None) -> dict[str, Any]:
        d = {
            "stage": self.stage.value,
            "stage_label": self.stage.label,
            "due_at": format_utc(self.due_at),
            "runs_from": format_utc(self.runs_from),
            "runs_from_fact": self.runs_from_fact,
            "provision": self.provision,
            "status": self.status,
            "submitted_at": format_utc(self.submitted_at) if self.submitted_at else None,
            "content_complete": self.content_complete if self.submitted_at else None,
            "recorded_after_due": self.recorded_after_due,
            # What was recorded is the manufacturer's own statement that it submitted. This
            # product has no channel to the reporting platform and verifies nothing about it.
            "submission_evidence": self.submission_evidence,
            "verified_by_platform": False,
        }
        if self.submitted_at is None:
            d["hours_remaining"] = self.hours_remaining(now)
        return d


@dataclass(frozen=True)
class Deadlines:
    """Every deadline that is currently computable for one case.

    Deadlines appear as the facts that start them are established. Asking for
    the vulnerability final report before a measure exists raises rather than
    guessing, because a guessed regulatory deadline is worse than an absent one.
    """

    track: Track
    awareness_at: datetime
    measure_available_at: datetime | None = None
    notification_submitted_at: datetime | None = None
    early_warning_submitted_at: datetime | None = None
    final_submitted_at: datetime | None = None
    #: Stage values whose counted filing is content-incomplete.
    incomplete_stages: frozenset[str] = frozenset()
    #: Stage values whose counted filing carries a declared platform reference.
    referenced_stages: frozenset[str] = frozenset()
    #: The earliest notification recorded of any kind, complete or not. The one-month incident
    #: final-report clock runs from it, so a complete notification recorded later than an
    #: incomplete one cannot move the deadline later.
    notification_first_recorded_at: datetime | None = None
    #: Stages recorded with more than one distinct filing time -> those times, ascending.
    conflicting_filing_times: dict[str, tuple[datetime, ...]] = field(default_factory=dict)

    def _flags(self, stage: Stage) -> dict[str, bool]:
        return {
            "content_complete": stage.value not in self.incomplete_stages,
            "has_platform_reference": stage.value in self.referenced_stages,
        }

    # -- individual stages -------------------------------------------------
    @property
    def early_warning(self) -> Deadline:
        return Deadline(
            stage=Stage.EARLY_WARNING,
            due_at=self.awareness_at + timedelta(hours=EARLY_WARNING_HOURS),
            runs_from=self.awareness_at,
            runs_from_fact="becoming aware",
            provision="Art. 14(2)(a)" if self.track is Track.VULNERABILITY else "Art. 14(4)(a)",
            submitted_at=self.early_warning_submitted_at,
            **self._flags(Stage.EARLY_WARNING),
        )

    @property
    def notification(self) -> Deadline:
        return Deadline(
            stage=Stage.NOTIFICATION,
            due_at=self.awareness_at + timedelta(hours=NOTIFICATION_HOURS),
            runs_from=self.awareness_at,
            runs_from_fact="becoming aware",
            provision="Art. 14(2)(b)" if self.track is Track.VULNERABILITY else "Art. 14(4)(b)",
            submitted_at=self.notification_submitted_at,
            **self._flags(Stage.NOTIFICATION),
        )

    @property
    def final(self) -> Deadline | None:
        """The final report deadline, or None while its trigger has not happened.

        None is a real state, not an error: for a vulnerability with no measure
        yet available, the clock has not started.
        """
        if self.track is Track.VULNERABILITY:
            if self.measure_available_at is None:
                return None
            return Deadline(
                stage=Stage.FINAL,
                due_at=self.measure_available_at + timedelta(days=VULNERABILITY_FINAL_DAYS),
                runs_from=self.measure_available_at,
                runs_from_fact="a corrective or mitigating measure became available",
                provision="Art. 14(2)(c)",
                submitted_at=self.final_submitted_at,
                **self._flags(Stage.FINAL),
            )
        if self.notification_submitted_at is None:
            return None
        run_from = self.notification_submitted_at
        if self.notification_first_recorded_at is not None:
            run_from = min(run_from, self.notification_first_recorded_at)
        return Deadline(
            stage=Stage.FINAL,
            due_at=add_one_month(run_from),
            runs_from=run_from,
            runs_from_fact="submission of the 72-hour incident notification",
            provision="Art. 14(4)(c)",
            submitted_at=self.final_submitted_at,
            **self._flags(Stage.FINAL),
        )

    def require_final(self) -> Deadline:
        """The final deadline, raising a clear error when it has not started."""
        deadline = self.final
        if deadline is None:
            if self.track is Track.VULNERABILITY:
                raise ClockError(
                    "the 14-day final-report clock has not started: no corrective or "
                    "mitigating measure has been recorded as available. A documented "
                    "workaround counts — record it when it exists (Art. 14(2)(c))."
                )
            raise ClockError(
                "the one-month final-report clock has not started: the 72-hour incident "
                "notification has not been recorded as submitted (Art. 14(4)(c))."
            )
        return deadline

    # -- aggregate ---------------------------------------------------------
    def all(self) -> list[Deadline]:
        out = [self.early_warning, self.notification]
        if self.final is not None:
            out.append(self.final)
        return out

    def open_deadlines(self) -> list[Deadline]:
        return [d for d in self.all() if d.submitted_at is None]

    def breaches(self) -> list[Deadline]:
        """Complete filings that were late. Does not include deadlines still open."""
        return [d for d in self.all() if d.met is False]

    def incomplete(self) -> list[Deadline]:
        """Stages recorded as submitted whose content failed the blocking checks."""
        return [d for d in self.all() if d.status == "recorded_incomplete"]

    def next_due(self, now: datetime | None = None) -> Deadline | None:
        pending = self.open_deadlines()
        return min(pending, key=lambda d: d.due_at) if pending else None

    def pending_facts(self) -> list[str]:
        """Deadlines that cannot be computed, and what would make them computable.

        This is the ``checks_skipped`` discipline applied to time: say what you
        could not calculate and why, instead of presenting a partial schedule
        as if it were the whole one.
        """
        gaps: list[str] = []
        if self.final is None:
            if self.track is Track.VULNERABILITY:
                gaps.append(
                    "final report (Art. 14(2)(c)): not computable until the date a corrective "
                    "or mitigating measure became available is recorded"
                )
            else:
                gaps.append(
                    "final report (Art. 14(4)(c)): not computable until the 72-hour "
                    "notification is recorded as submitted"
                )
        return gaps

    def to_dict(self, now: datetime | None = None) -> dict[str, Any]:
        d: dict[str, Any] = {
            "track": self.track.value,
            "awareness_at": format_utc(self.awareness_at),
            "deadlines": [x.to_dict(now) for x in self.all()],
            "pending_facts": self.pending_facts(),
            "breaches": [x.stage.value for x in self.breaches()],
            "recorded_incomplete": [x.stage.value for x in self.incomplete()],
            "conflicting_filing_times": {
                stage: [format_utc(t) for t in times]
                for stage, times in sorted(self.conflicting_filing_times.items())
            },
        }
        if self.early_warning_submitted_at is not None:
            shown = platform_displayed_notification_due(self.early_warning_submitted_at)
            legal = self.notification.due_at
            d["platform_counter"] = {
                "displayed_notification_due": format_utc(shown),
                "legal_notification_due": format_utc(legal),
                "agrees": shown == legal,
                "note": (
                    "ENISA CRA SRP FAQ 26: in the current release the 72-hour counter is "
                    "displayed as 48 hours after submission of the early warning rather than "
                    "72 hours after awareness. Where these differ, the legal deadline governs."
                ),
            }
        return d
