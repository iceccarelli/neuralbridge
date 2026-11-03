"""Legal timestamps: the one place a caller-supplied instant becomes a UTC datetime.

A timestamp here starts or satisfies a statutory clock, so the parser is stricter
than ``datetime.fromisoformat``: it accepts only a full ISO-8601 date-time that
carries its own UTC offset, in a plausible range, and never guesses. It refuses
(with a ``ValueError`` that names the field and the reason):

* a non-string (a JSON integer would otherwise be read as an epoch in a unit
  nobody stated);
* a date with no time of day, or a time with no offset;
* an offset no inhabited zone uses (valid zones run -12:00 .. +14:00, minutes 00-59);
* a year outside 2000..2099, where deadline arithmetic is not meaningful.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from ...core.identity import parse_utc

__all__ = ["MAX_LEGAL_YEAR", "MIN_LEGAL_YEAR", "legal_timestamp", "require_deadline_arithmetic"]

MIN_LEGAL_YEAR = 2000
MAX_LEGAL_YEAR = 2099

_FULL = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?"
    r"(?P<zone>[Zz]|[+-]\d{2}(:?\d{2})?)$"
)
_MIN_OFFSET = timedelta(hours=-12)
_MAX_OFFSET = timedelta(hours=14)


def legal_timestamp(value: object, field: str = "timestamp") -> datetime:
    """Parse ``value`` as a legal instant and return it in UTC, or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError(
            f"{field}: expected an ISO-8601 string with a UTC offset such as "
            f"'2026-09-19T06:30:00Z', got {type(value).__name__}. A number is not accepted "
            "because its unit and epoch would be guessed."
        )
    raw = value.strip()
    match = _FULL.match(raw)
    if match is None:
        raise ValueError(
            f"{field}: {value!r} is not a full ISO-8601 date-time with a UTC offset "
            "(for example '2026-09-19T06:30:00Z' or '2026-09-19T08:30:00+02:00'). A date "
            "alone, or a time without an offset, is refused rather than guessed: guessing "
            "moves a legal deadline."
        )
    try:
        parsed = parse_utc(raw.replace(" ", "T", 1))
    except ValueError as exc:
        raise ValueError(f"{field}: {exc}") from exc
    zone = match.group("zone")
    if zone not in ("Z", "z"):
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        offset_minutes = int(digits[2:] or 0)
        if offset_minutes >= 60:
            raise ValueError(
                f"{field}: UTC offset {zone} has {offset_minutes} minutes; the minutes of an "
                "offset must be 00-59 (+00:99 is not +01:39). Nothing was guessed."
            )
        offset = sign * timedelta(hours=int(digits[:2]), minutes=offset_minutes)
        if not _MIN_OFFSET <= offset <= _MAX_OFFSET:
            raise ValueError(
                f"{field}: UTC offset {zone} is outside the range any time zone uses "
                "(-12:00 to +14:00)."
            )
        if abs(offset.total_seconds()) % 60:
            raise ValueError(f"{field}: UTC offset {zone} is not a whole number of minutes.")
    if not MIN_LEGAL_YEAR <= parsed.year <= MAX_LEGAL_YEAR:
        raise ValueError(
            f"{field}: year {parsed.year} is outside {MIN_LEGAL_YEAR}..{MAX_LEGAL_YEAR}; a "
            "deadline computed from it would not be meaningful."
        )
    return parsed.astimezone(UTC)


def require_deadline_arithmetic(*moments: datetime | None, field: str = "timestamp") -> None:
    """Raise ValueError if the legal periods cannot be added to these instants.

    Called BEFORE anything is appended: a record whose deadlines cannot be
    computed must not be written, because the case would then fail on every read.
    """
    from .clock import NOTIFICATION_HOURS, VULNERABILITY_FINAL_DAYS, add_one_month

    for moment in moments:
        if moment is None:
            continue
        try:
            moment + timedelta(hours=NOTIFICATION_HOURS)
            moment + timedelta(days=VULNERABILITY_FINAL_DAYS)
            add_one_month(moment)
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                f"{field}: deadlines cannot be computed from {moment.isoformat()} "
                f"({exc}); nothing was recorded."
            ) from exc
