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
from dataclasses import dataclass
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

    @property
    def met(self) -> bool | None:
        """True/False once submitted; None while still open."""
        if self.submitted_at is None:
            return None
        return self.submitted_at <= self.due_at

    @property
    def status(self) -> str:
        if self.submitted_at is not None:
            return "filed_on_time" if self.met else "filed_late"
        return "open"

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
            )
        if self.notification_submitted_at is None:
            return None
        return Deadline(
            stage=Stage.FINAL,
            due_at=add_one_month(self.notification_submitted_at),
            runs_from=self.notification_submitted_at,
            runs_from_fact="submission of the 72-hour incident notification",
            provision="Art. 14(4)(c)",
            submitted_at=self.final_submitted_at,
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
        """Filings that were late. Does not include deadlines still open."""
        return [d for d in self.all() if d.met is False]

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
