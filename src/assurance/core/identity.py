"""Content addressing.

Two runs that produced the same facts must produce the same identifier, on any
machine, in any language runtime, on any CPU. That property is what lets an
auditor ask "is this the artifact you filed?" and get an answer that does not
depend on trusting the person who kept the file.

The canonicalisation rules are deliberately identical to the ones the planning
engine already uses, so a plan hash computed there and an evidence hash
computed here are comparable without a translation layer.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "HASH_PRECISION",
    "canonical_json",
    "content_hash_of",
    "format_utc",
    "parse_utc",
    "utc_now",
]

#: Decimal places retained when hashing a float. Beyond this, two machines
#: disagree about the last bits of a value that means the same thing.
HASH_PRECISION = 6


def _round(value: Any) -> Any:
    """Normalise a value for hashing: fixed precision, no negative zero."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        r = round(float(value), HASH_PRECISION)
        return 0.0 if r == 0 else r
    if isinstance(value, dict):
        return {k: _round(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_round(v) for v in value]
    if isinstance(value, datetime):
        return format_utc(value)
    return value


def canonical_json(payload: Any) -> str:
    """Deterministic JSON: sorted keys, fixed float precision, no whitespace."""
    return json.dumps(_round(payload), sort_keys=True, separators=(",", ":"), default=str)


def content_hash_of(payload: Any) -> str:
    """SHA-256 of the canonical JSON encoding of *payload*.

    This is the hash of the *content*, which is the only kind worth recording.
    A hash of a name and a version number looks identical in a document and
    proves nothing.
    """
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    """Timezone-aware UTC. Never ``datetime.now()``.

    Every deadline in this package is wall-clock and cross-border. A naive
    local timestamp in an awareness record is an unforced error that surfaces
    as a missed 24-hour deadline in a different Member State.
    """
    return datetime.now(UTC)


def parse_utc(text: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalise it to UTC.

    Accepts a trailing ``Z``. Refuses a naive timestamp rather than assuming a
    zone, because guessing here silently moves a legal deadline.
    """
    raw = text.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise ValueError(
            f"{text!r} has no timezone. Deadlines are computed in UTC; supply an "
            "offset (e.g. '2026-09-19T06:30:00Z') rather than letting this be guessed."
        )
    return parsed.astimezone(UTC)


def format_utc(moment: datetime) -> str:
    """Render a timestamp as ``YYYY-MM-DDTHH:MM:SSZ``, to the second.

    Sub-second precision is dropped on purpose: it is never load-bearing for a
    24-hour obligation and its presence invites false precision in a filing.
    """
    if moment.tzinfo is None:
        raise ValueError("refusing to format a naive datetime as UTC")
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
