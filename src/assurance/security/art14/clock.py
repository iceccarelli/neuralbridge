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
import functools
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from ...core.errors import ClockError
from ...core.identity import format_utc, utc_now
from .model import Stage, Track

__all__ = [
    "EARLY_WARNING_HOURS",
    "NOTIFICATION_HOURS",
    "VULNERABILITY_FINAL_DAYS",
    "OPEN_LEGAL_QUESTIONS",
    "RULE_HISTORY",
    "RULE_VERSION",
    "Deadline",
    "Deadlines",
    "MonthReadings",
    "add_one_month",
    "incident_final_due_at",
    "platform_displayed_notification_due",
]

EARLY_WARNING_HOURS = 24          # Art. 14(2)(a), 14(4)(a)
NOTIFICATION_HOURS = 72           # Art. 14(2)(b), 14(4)(b)
VULNERABILITY_FINAL_DAYS = 14     # Art. 14(2)(c)

#: ENISA CRA SRP FAQ 26: the displayed 72-hour counter is computed as this many
#: hours after submission of the early warning, not from awareness.
_PLATFORM_COUNTER_OFFSET_HOURS = 48

#: Version of the counting rules in this module. Bump it, and add a line to :data:`RULE_HISTORY`,
#: whenever a change here can alter the due time of ANY deadline for ANY input. It is printed in
#: every deadline's ``basis`` and in the register report, so a deadline that moved because the
#: rule changed (and not because a fact changed) is visible when two exports are compared.
RULE_VERSION = "2"

RULE_HISTORY: tuple[tuple[str, str], ...] = (
    ("1", "one-month incident final report = add_one_month() of the UTC instant (before 2026-11-12)."),
    ("2", "one-month incident final report = the earlier of that and the end of the same date one "
          "month later in the calendar of every fixed UTC offset -12:00..+14:00 (15-minute grid); "
          "24 h, 72 h and 14 d unchanged."),
)

#: Questions the arithmetic cannot settle. They are shown with the deadlines, never answered by
#: this software: a qualified lawyer must decide each. The ``id`` is what a deadline's ``basis``
#: points at.
OPEN_LEGAL_QUESTIONS: tuple[dict[str, str], ...] = (
    {
        "id": "reg_1182_71_applies",
        "question": (
            "Does Regulation (EEC, Euratom) No 1182/71 (rules for periods, dates and time limits) "
            "apply to the periods in Article 14 of Regulation (EU) 2024/2847? Its Art. 1 reads "
            "'acts of the Council or Commission'; the CRA is an act of the European Parliament and "
            "of the Council. Case 139/73 (para. 4) and Case C-171/03 (Toeters) applied it to "
            "Commission regulations and do not decide this."
        ),
    },
    {
        "id": "art3_or_art5",
        "question": (
            "If it applies, is 'within N days' a period (Art. 3) or an action to be effected "
            "within a number of days following an event (Art. 5, which applies Art. 3 'with the "
            "exception of paragraphs 4 and 5')? The answer decides whether a last day on a "
            "Saturday, Sunday or public holiday moves the end to the next working day (Art. 3(4))."
        ),
    },
    {
        "id": "calendar_of_the_day",
        "question": (
            "In which calendar and time zone is 'the day' or 'the same date' read: the "
            "submitter's, the manufacturer's main establishment, the coordinating CSIRT's, "
            "ENISA's, or UTC?"
        ),
    },
    {
        "id": "meaning_of_submission",
        "question": (
            "What is the 'submission' that starts the one-month period of Art. 14(4)(c): the "
            "manufacturer's act of submitting, or the reporting platform's receipt?"
        ),
    },
    {
        "id": "art14_4c_trigger_when_waived",
        "question": (
            "If the 72-hour incident notification is not submitted because 'the relevant "
            "information has already been provided' (Art. 14(4)(b)), what starts the one-month "
            "period of Art. 14(4)(c)?"
        ),
    },
)


def add_one_month(moment: datetime) -> datetime:
    """Add one calendar month, clamping to the last valid day.

    Article 14(4)(c) says "within one month", which is a calendar month, not 30
    days. 31 January plus one month is the last day of February, not 3 March.
    Time of day is preserved.

    The arithmetic is done on the instant in the datetime's own offset (UTC for every instant
    this package produces), not in the submitter's calendar. That is NOT always the earlier
    reading: a submission late on the last evening of a month in a zone west of UTC is already
    "the next day" in UTC, and a month counted from that date ends days after a month counted
    in the submitter's own calendar. The public function is unchanged (callers rely on it); the
    incident final-report deadline does not use it alone, it uses
    :func:`incident_final_due_at`, which also takes the earliest end of "the same date one month
    later" over every fixed UTC offset (see there).
    """
    year = moment.year + (1 if moment.month == 12 else 0)
    month = 1 if moment.month == 12 else moment.month + 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


#: Every fixed UTC offset a clock can show, -12:00 .. +14:00, on a 15-minute grid (the same range
#: ``timestamps.legal_timestamp`` accepts; no inhabited zone uses a finer step).
_FIXED_OFFSETS: tuple[timedelta, ...] = tuple(
    timedelta(minutes=m) for m in range(-12 * 60, 14 * 60 + 1, 15)
)


def _end_of_same_date_one_month_on(moment_utc: datetime, offset: timedelta) -> datetime:
    """The expiry of the last hour of "the same date one month later", as a UTC instant.

    Reg. (EEC, Euratom) No 1182/71 Art. 3(2)(c): a period in months ends with the expiry of the
    last hour of the day that falls on the same date in the last month, or of the last day of that
    month where it has no such date. The date is the one a clock at fixed UTC offset ``offset``
    shows for ``moment_utc``. ``moment_utc`` must be timezone-aware.
    """
    local_date = (moment_utc + offset).date()
    year = local_date.year + (1 if local_date.month == 12 else 0)
    month = 1 if local_date.month == 12 else local_date.month + 1
    day = min(local_date.day, calendar.monthrange(year, month)[1])
    following = date(year, month, day) + timedelta(days=1)
    return datetime(following.year, following.month, following.day, tzinfo=UTC) - offset


@dataclass(frozen=True)
class MonthReadings:
    """The readings the one-month incident deadline is chosen from."""

    #: ``add_one_month`` of the instant: same time of day, UTC calendar (the rule before
    #: rule version 2).
    utc_wall_clock: datetime
    #: The earliest end of "the same date one month later" over every fixed UTC offset, or
    #: ``None`` if none could be represented.
    earliest_fixed_offset: datetime | None
    #: The offset that gave ``earliest_fixed_offset``.
    at_offset: timedelta | None

    @property
    def due_at(self) -> datetime:
        if self.earliest_fixed_offset is not None and self.earliest_fixed_offset < self.utc_wall_clock:
            return self.earliest_fixed_offset
        return self.utc_wall_clock


@functools.lru_cache(maxsize=4096)
def _month_readings(moment: datetime) -> MonthReadings:
    baseline = add_one_month(moment)   # raises where the old rule raised: unchanged behaviour
    naive = moment.tzinfo is None
    as_utc = moment.replace(tzinfo=UTC) if naive else moment.astimezone(UTC)
    best: datetime | None = None
    best_offset: timedelta | None = None
    for offset in _FIXED_OFFSETS:
        try:
            candidate = _end_of_same_date_one_month_on(as_utc, offset)
        except (OverflowError, ValueError):
            continue   # beyond the representable calendar: that reading cannot be earlier
        if naive:
            candidate = candidate.replace(tzinfo=None)
        if best is None or candidate < best:
            best, best_offset = candidate, offset
    return MonthReadings(utc_wall_clock=baseline, earliest_fixed_offset=best,
                         at_offset=best_offset)


def incident_final_due_at(notification_submitted_at: datetime) -> datetime:
    """The one-month incident final-report deadline, Art. 14(4)(c).

    "Within one month after the submission of the incident notification." The product records
    the submission as a UTC instant and does not know the submitter's calendar, so it takes the
    EARLIEST of

    * ``add_one_month`` of the instant (same time of day, UTC calendar), and
    * the end of "the same date one month later" (clamped to the month's last day) in the
      calendar of EVERY fixed UTC offset from -12:00 to +14:00 on a 15-minute grid, per
      Reg. (EEC, Euratom) No 1182/71 Art. 3(2)(c) (the period ends with the expiry of the last
      hour of that day).

    so that for a submission counted in any fixed-offset calendar the deadline shown is never
    later than the end of the legal period. It can be up to 2 days 23 h 58 min earlier than
    ``add_one_month``, and does so for about 1.7 % of instants (the evening before a month's end
    in the west, the morning after it in the east).

    Two things this does NOT do, stated because the rule is a legal reading and not a fact:

    * Whether Reg. 1182/71 applies to a Regulation (EU) 2024/2847 filing period at all, and
      which calendar "the date" is read in, are open legal questions (see
      :data:`OPEN_LEGAL_QUESTIONS`). The guard is the conservative direction under any of them.
    * Residual: in a zone that changes its UTC offset during the month (daylight saving) the
      result can still be later than the end of the local date by up to one hour (the size of
      the step), because a fixed offset is used for the month.

    Art. 3(4) (a last day on a public holiday, Saturday or Sunday moves the end to the next
    working day) can only make a legal date later; it is not applied, so the product's date is
    never later because of it.
    """
    return _month_readings(notification_submitted_at).due_at


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
            due_at=incident_final_due_at(run_from),
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
