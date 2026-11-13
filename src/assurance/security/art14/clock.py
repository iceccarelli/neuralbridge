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

ENISA documents a behaviour of the reporting platform that a user should be shown
rather than silently disagreed with: in the release described by its FAQ 26 the
72-hour counter displays a due time 48 hours after submission of the early warning,
so the platform can show a notification as overdue while it is still in time
(source below). :func:`platform_displayed_notification_due` computes what the platform
is documented to show, so a case view can display both and explain the difference.
That is ENISA's description of one release as retrieved on the date below; this
software has not observed the platform and does not know whether it has changed.
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
    "PLATFORM_FAQ_URL",
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

#: ENISA CRA SRP FAQ 26 ("How are the 72-hour and Final Report counters calculated?"), as
#: documented by ENISA: "In the current release, the 72-hour counter displays a due date/time
#: 48hrs after submission of the 24-hour Early Warning", to be changed "in a future release".
#: Source: PLATFORM_FAQ_URL below, page "Updated: 15 October 2026", retrieved 2026-11-12.
#: The displayed 72-hour counter is computed as this many hours after submission of the early
#: warning, not from awareness.
_PLATFORM_COUNTER_OFFSET_HOURS = 48
PLATFORM_FAQ_URL = (
    "https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp/frequently-asked-questions"
)

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


_CITATION = "Regulation (EU) 2024/2847, OJ L, 20.11.2024, "
_WITHOUT_UNDUE_DELAY = (
    "without undue delay: the outer limit is not the standard. The provision requires the "
    "filing without undue delay and in any event within the limit."
)
_ALREADY_PROVIDED = (
    "'unless the relevant information has already been provided' is not modelled: the deadline "
    "is shown as running. Whether the stage can be satisfied by earlier information is for a "
    "person (and, for Art. 14(4)(c), a lawyer) to decide; nothing here records that decision."
)

#: provision -> (stage kind, period, verbatim wording from the OJ text, qualifiers, counting id)
_PROVISIONS: dict[str, dict[str, Any]] = {
    "Art. 14(2)(a)": {
        "kind": "hours", "n": 24, "counting": "hours_from_awareness_instant",
        "wording": "without undue delay and in any event within 24 hours of the manufacturer becoming aware of it",
        "also_required": _WITHOUT_UNDUE_DELAY, "not_modelled": [],
    },
    "Art. 14(2)(b)": {
        "kind": "hours", "n": 72, "counting": "hours_from_awareness_instant",
        "wording": "without undue delay and in any event within 72 hours of the manufacturer becoming aware of the actively exploited vulnerability",
        "also_required": _WITHOUT_UNDUE_DELAY, "not_modelled": [_ALREADY_PROVIDED],
    },
    "Art. 14(2)(c)": {
        "kind": "days", "n": 14, "counting": "days_from_measure_available_instant",
        "wording": "no later than 14 days after a corrective or mitigating measure is available",
        "also_required": None, "not_modelled": [_ALREADY_PROVIDED],
    },
    "Art. 14(4)(a)": {
        "kind": "hours", "n": 24, "counting": "hours_from_awareness_instant",
        "wording": "without undue delay and in any event within 24 hours of the manufacturer becoming aware of it",
        "also_required": _WITHOUT_UNDUE_DELAY, "not_modelled": [],
    },
    "Art. 14(4)(b)": {
        "kind": "hours", "n": 72, "counting": "hours_from_awareness_instant",
        "wording": "without undue delay and in any event within 72 hours of the manufacturer becoming aware of the incident",
        "also_required": _WITHOUT_UNDUE_DELAY, "not_modelled": [_ALREADY_PROVIDED],
    },
    "Art. 14(4)(c)": {
        "kind": "month", "n": 1, "counting": "calendar_month_earliest_over_fixed_utc_offsets",
        "wording": "within one month after the submission of the incident notification under point (b)",
        "also_required": None, "not_modelled": [_ALREADY_PROVIDED],
    },
}

_WEEKEND_HOLIDAY = {
    "id": "reg_1182_71_art3_4_next_working_day",
    "status": "UNRESOLVED_LEGAL_QUESTION",
    "applied": False,
    "informational_only": True,
    "would_end_at": None,
    "note": (
        "Reg. 1182/71 Art. 3(4) moves a last day that is a public holiday, Saturday or Sunday to "
        "the next working day, for periods 'expressed otherwise than in hours'. It can only make "
        "the legal date LATER, public holidays depend on the place and are not known here, and "
        "whether it applies to an Art. 14 filing period at all is an open legal question "
        "(see open_legal_question_ids). The product does not apply it: its due_at is never "
        "later because of it."
    ),
}

_RESIDUAL = {
    "hours": None,
    "days": (
        "In a zone that changes its UTC offset inside the 14 days (daylight saving) the 14 x 24 h "
        "instant can be later than the end of the local 14th day by less than one hour."
    ),
    "month": (
        "In a zone that changes its UTC offset inside the month (daylight saving) the due time can "
        "still be later than the end of the same local date one month on by up to one hour: a "
        "fixed offset is used for the month."
    ),
}


def _offset_label(offset: timedelta | None) -> str:
    if offset is None:
        return "none"
    minutes = int(offset.total_seconds() // 60)
    sign = "-" if minutes < 0 else "+"
    return f"{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def _utc(moment: datetime) -> datetime:
    return moment.astimezone(UTC) if moment.tzinfo else moment.replace(tzinfo=UTC)


def _reading_end(kind: str, n: int, start: datetime) -> datetime:
    """The end of the period in the UTC calendar under Reg. 1182/71 Art. 3(1)-(2)."""
    start = _utc(start)
    if kind == "hours":      # the hour of the event is not counted; the last hour expires
        return start.replace(minute=0, second=0, microsecond=0) + timedelta(hours=n + 1)
    midnight = start.replace(hour=0, minute=0, second=0, microsecond=0)
    if kind == "days":       # the day of the event is not counted; the last day expires
        return midnight + timedelta(days=n + 1)
    return _end_of_same_date_one_month_on(start, timedelta(0))


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
    #: Where the fact this deadline runs from sits in the ledger, when the case loader has it:
    #: ``{"ledger_seq", "content_hash", "recorded_by", "actor_kind"}``.
    source: dict[str, Any] | None = None

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

    def basis(self) -> dict[str, Any]:
        """Why this deadline is what it is. Provenance only: nothing here changes ``due_at``.

        Other legal readings are listed for information with their own end time; none of them
        replaces ``due_at``, ``status`` or ``met``. Which reading governs is for a qualified
        lawyer to decide, and no legal conclusion is stated.
        """
        spec = _PROVISIONS.get(self.provision)
        src = self.source or {}
        starts_from = {
            "fact": self.runs_from_fact,
            "at": format_utc(self.runs_from),
            "ledger_seq": src.get("ledger_seq"),
            "ledger_hash": src.get("content_hash"),
            "recorded_by": src.get("recorded_by"),
            "actor_kind": src.get("actor_kind"),
            "source_note": None if src else (
                "the ledger position of this fact is not carried for this deadline; find the "
                "record with this time in the case's audit history"
            ),
        }
        basis: dict[str, Any] = {
            "instrument": "Regulation (EU) 2024/2847",
            "citation": _CITATION + self.provision,
            "provision": self.provision,
            "wording": spec["wording"] if spec else None,
            "counting": spec["counting"] if spec else None,
            "rule_version": RULE_VERSION,
            "also_required": spec["also_required"] if spec else None,
            "not_modelled": list(spec["not_modelled"]) if spec else [],
            "starts_from": starts_from,
            "residual": _RESIDUAL[spec["kind"]] if spec else None,
            "other_readings": [],
            "weekend_holiday_rule": dict(_WEEKEND_HOLIDAY),
            "open_legal_question_ids": [q["id"] for q in OPEN_LEGAL_QUESTIONS],
            "status_note": None,
        }
        if spec is None:
            return basis
        readings: list[dict[str, Any]] = []
        end = _reading_end(spec["kind"], spec["n"], self.runs_from)
        readings.append({
            "id": "reg_1182_71_end_of_period_utc_calendar",
            "status": "UNRESOLVED_LEGAL_QUESTION",
            "informational_only": True,
            "would_end_at": format_utc(end),
            "note": (
                "Reg. 1182/71 Art. 3(1)-(2) counted in the UTC calendar: the hour or day of the "
                "event is not counted and the period ends with the expiry of its last hour or day."
            ),
        })
        ends = [end]
        if spec["kind"] == "month":
            readings_m = _month_readings(self.runs_from)
            if readings_m.utc_wall_clock != self.due_at:
                readings.append({
                    "id": "utc_wall_clock_month_rule_v1",
                    "status": "SUPERSEDED_PRODUCT_RULE",
                    "informational_only": True,
                    "would_end_at": format_utc(readings_m.utc_wall_clock),
                    "note": (
                        "Same time of day one month later in the UTC calendar: the rule of "
                        "rule_version 1. The due_at above is earlier because the month ends "
                        "earlier in the calendar of a fixed UTC offset "
                        f"({_offset_label(readings_m.at_offset)}), and the product shows the "
                        "earliest."
                    ),
                })
                ends.append(readings_m.utc_wall_clock)
        basis["other_readings"] = readings
        if self.submitted_at is not None and self.submitted_at > self.due_at:
            fits = [r for r, e in zip(readings, ends, strict=True) if self.submitted_at <= e]
            if fits:
                names = ", ".join(f"{r['id']} (ends {r['would_end_at']})" for r in fits)
                basis["status_note"] = (
                    f"Recorded as filed late on this product's due_at ({format_utc(self.due_at)}); "
                    f"the recorded submission time {format_utc(self.submitted_at)} is not later "
                    f"than the end of the period under: {names}. Whether such a reading applies "
                    "is an UNRESOLVED_LEGAL_QUESTION that a qualified lawyer must decide. This "
                    "note does not change due_at, status or met."
                )
        return basis

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
            "basis": self.basis(),
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
    #: Ledger provenance of the facts the deadlines run from, keyed ``awareness`` / ``measure`` /
    #: ``notification``; each ``{"ledger_seq", "content_hash", "recorded_by", "actor_kind"}``.
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)

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
            source=self.sources.get("awareness"),
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
            source=self.sources.get("awareness"),
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
                source=self.sources.get("measure"),
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
            source=self.sources.get("notification"),
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
            "rule_version": RULE_VERSION,
            "open_legal_questions": [dict(q) for q in OPEN_LEGAL_QUESTIONS],
        }
        if self.early_warning_submitted_at is not None:
            shown = platform_displayed_notification_due(self.early_warning_submitted_at)
            legal = self.notification.due_at
            d["platform_counter"] = {
                "displayed_notification_due": format_utc(shown),
                "legal_notification_due": format_utc(legal),
                "agrees": shown == legal,
                "note": (
                    "ENISA CRA SRP FAQ 26, as documented by ENISA (page updated 15 October "
                    "2026, retrieved 2026-11-12, " + PLATFORM_FAQ_URL + "): in the release it "
                    "describes, the 72-hour counter is displayed as 48 hours after submission of "
                    "the early warning rather than 72 hours after awareness. This software has "
                    "not observed the platform. Where the two differ, the legal deadline "
                    "(Art. 14) governs, not the platform's counter."
                ),
            }
        return d
