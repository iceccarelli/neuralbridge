"""What a ledger knows about whether anybody has been looking.

The hosted workspace is a subscription for *continuous* assurance, so the first
question a customer asks of it is not "what is the configuration" but "when was
this machine last actually looked at, and did the last attempt work". The answer
lives in the ``watch.observation`` records the Watch runner has always sealed
(``assurance.watch.runner``); a hosted ledger holds the same records, written by
``assurance.watch.ingest`` from a report the customer chose to send.

This module only reads. It derives nothing about safety: it reports dates,
statuses and a staleness comparison against the cadence the customer declared,
and it names the cases that are open. A failed look is never a positive one:
:func:`observation_succeeded` is the single definition of "a look that
counts", shared with the runner's own staleness test.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from assurance.change.store import CaseStore
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import MANIFEST_KIND

__all__ = [
    "DEFAULT_CADENCE_HOURS",
    "MAX_CADENCE_HOURS",
    "MIN_CADENCE_HOURS",
    "OBSERVATION_KIND",
    "REPORT_KIND",
    "FAILED_STATUSES",
    "MANIFEST_STALE",
    "NOT_A_LOOK_STATUSES",
    "fleet_observations",
    "observation_succeeded",
    "observed_at_of",
]

OBSERVATION_KIND = "watch.observation"
#: One record per accepted report: the run summary and the declared cadence.
REPORT_KIND = "watch.report"
#: Used when no report has declared a cadence. The same default the Watch
#: configuration uses (``WatchConfig.max_age_hours``).
DEFAULT_CADENCE_HOURS = 168.0
#: The range a report may declare. A cadence is how long a machine may go
#: unobserved before it reads stale, so a large one is a way to hide staleness:
#: it is capped at 30 days, and floored at an hour.
MIN_CADENCE_HOURS = 1.0
MAX_CADENCE_HOURS = 720.0
#: Statuses that mean the look did not happen, or did not finish.
FAILED_STATUSES = frozenset({"uncollectable", "incomplete"})
#: Recorded (never accepted as a reported status) when a positive look rests on a
#: manifest older than the cadence window at the moment it claims to have been
#: observed: a replay of old data is not a look at the machine.
MANIFEST_STALE = "manifest_stale"
#: Every recorded status that is not a successful look of the machine.
NOT_A_LOOK_STATUSES = FAILED_STATUSES | {MANIFEST_STALE}


def observation_succeeded(body: dict[str, Any]) -> bool:
    """Whether an observation record is a look that counts as having seen the machine.

    ``uncollectable`` is an attempt, not an observation, and so is
    ``manifest_stale`` (a manifest too old to describe the machine today). ``incomplete`` (or any
    record that says ``complete: false``) saw only part of what the plan names:
    it can describe a drift, but it cannot say the machine is current.
    """
    if str(body.get("status", "")) in NOT_A_LOOK_STATUSES:
        return False
    return body.get("complete", True) is not False


def observed_at_of(body: dict[str, Any], fallback: str) -> datetime | None:
    """When the look happened: the run's own clock, never later than the ledger's.

    ``fallback`` is the ledger's append time. A record stamped later than the
    moment it was written (a reporter's fast clock, or a lie) is read as written:
    otherwise a success dated a minute ahead would outrank a real failure that
    follows it.
    """
    try:
        stated = parse_utc(str(body.get("observed_at") or fallback))
        written = parse_utc(str(fallback))
    except (ValueError, TypeError):  # pragma: no cover - ledger writes UTC
        return None
    return min(stated, written)


def _cadence_of(body: dict[str, Any]) -> float | None:
    value = body.get("cadence_hours")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if MIN_CADENCE_HOURS <= value <= MAX_CADENCE_HOURS else None


def _manifest_age_of(body: dict[str, Any]) -> float | None:
    value = body.get("manifest_age_hours")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _machine_cadence(seen: list[_Seen]) -> tuple[float, bool]:
    """The cadence that judges one machine, and whether any watch declared one.

    Each watch's cadence is the one it declared with its own latest successful
    look of this machine; when several watches have reported the machine the
    shortest wins. A failed look declares nothing, so a report can never
    lengthen the cadence of a machine it did not successfully observe.
    """
    latest: dict[str, _Seen] = {}
    for s in seen:                       # oldest first
        if s.succeeded:
            latest[s.watch_id] = s
    if not latest:
        return DEFAULT_CADENCE_HOURS, False
    declared = [s.cadence for s in latest.values() if s.cadence is not None]
    values = [s.cadence if s.cadence is not None else DEFAULT_CADENCE_HOURS
              for s in latest.values()]
    return min(values), bool(declared)


@dataclass(frozen=True)
class _Seen:
    at: datetime
    status: str
    complete: bool
    detail: str
    succeeded: bool
    watch_id: str = ""
    #: The cadence the reporting watch declared with this look, or None.
    cadence: float | None = None
    #: Hours between the manifest's ``taken_at`` and the look's ``observed_at``
    #: (hosted reports only; None where the record does not carry it).
    manifest_age_hours: float | None = None
    manifest_relayed: bool = False


def fleet_observations(
    ledger: EvidenceLedger, *, now: datetime | None = None,
) -> dict[str, Any]:
    """Per machine: last successful look, last attempt, staleness, open cases."""
    as_of = now or utc_now()

    by_machine: dict[str, list[_Seen]] = {}
    for entry in ledger.entries(kind=OBSERVATION_KIND):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        body = evidence.body
        key = str(body.get("machine") or entry.subject or body.get("serial") or "")
        at = observed_at_of(body, entry.at)
        if not key or at is None:
            continue
        by_machine.setdefault(key, []).append(_Seen(
            at=at, status=str(body.get("status", "")),
            complete=body.get("complete", True) is not False,
            detail=str(body.get("detail", "")),
            succeeded=observation_succeeded(body),
            watch_id=str(body.get("watch_id", "")),
            cadence=_cadence_of(body) if observation_succeeded(body) else None,
            manifest_age_hours=_manifest_age_of(body),
            manifest_relayed=body.get("manifest_relayed") is True,
        ))

    enrolled = {e.subject for e in ledger.entries(kind=MANIFEST_KIND) if e.subject}
    store = CaseStore(ledger)
    open_cases: dict[str, list[str]] = {}
    for case in store.list():
        if case.is_open:
            for machine in case.machines:
                open_cases.setdefault(machine, []).append(case.case_id)

    machines: list[dict[str, Any]] = []
    for key in sorted(set(by_machine) | enrolled):
        # Ordered by when the look happened; ledger order breaks ties (sorted is
        # stable), so the last element is the latest attempt.
        seen = sorted(by_machine.get(key, []), key=lambda s: s.at)
        last_attempt = seen[-1] if seen else None
        last_ok = next((s for s in reversed(seen) if s.succeeded), None)
        failed_run = 0
        for s in reversed(seen):
            if s.succeeded:
                break
            failed_run += 1

        cadence, declared = _machine_cadence(seen)
        age_hours = None
        if last_ok is not None:
            age_hours = round(max(0.0, (as_of - last_ok.at).total_seconds() / 3600), 2)
        if not seen:
            stale, reason = True, "never_reported"
        elif last_ok is None:
            stale, reason = True, "never_successfully_observed"
        elif age_hours is not None and age_hours > cadence:
            stale, reason = True, "older_than_cadence"
        else:
            stale, reason = False, ""

        machines.append({
            "machine": key,
            "reported": bool(seen),
            "last_successful_observation_at":
                format_utc(last_ok.at) if last_ok else None,
            "last_attempt_at": format_utc(last_attempt.at) if last_attempt else None,
            "last_attempt_status": last_attempt.status if last_attempt else None,
            "last_attempt_succeeded": last_attempt.succeeded if last_attempt else None,
            "last_attempt_detail": last_attempt.detail if last_attempt else "",
            # How old the manifest behind a look was at the moment of the look, as
            # reported. A successful look is one inside the cadence window; the
            # attempt's age is what shows a stale manifest was offered.
            "last_successful_manifest_age_hours":
                last_ok.manifest_age_hours if last_ok else None,
            "last_successful_manifest_relayed":
                last_ok.manifest_relayed if last_ok else None,
            "last_attempt_manifest_age_hours":
                last_attempt.manifest_age_hours if last_attempt else None,
            "age_hours": age_hours,
            "stale": stale,
            "stale_reason": reason,
            "cadence_hours": cadence,
            "cadence_declared": declared,
            "consecutive_failed_attempts": failed_run,
            "open_case_ids": sorted(open_cases.get(key, [])),
        })

    return {
        "as_of": format_utc(as_of),
        "default_cadence_hours": DEFAULT_CADENCE_HOURS,
        "reporting": bool(by_machine),
        "machines": machines,
        "summary": {
            "machines": len(machines),
            "never_reported": sum(1 for m in machines if not m["reported"]),
            "latest_attempt_failed": sum(
                1 for m in machines if m["last_attempt_succeeded"] is False),
            "stale": sum(1 for m in machines if m["stale"]),
        },
        "limitations": [
            "Reported by the customer, not independently observed: the hosted "
            "service cannot collect from a machine and did not watch any of them. "
            "Both the dates and the cadence are declared by the reporting client, "
            "which could replay an old manifest as if it were looked at now.",
            "A date here is when the customer's own Watch says it looked, as "
            "reported. It is not independently verified.",
            "A machine is stale when its last successful observation is older than "
            "the cadence declared with it (the shortest, when more than one watch "
            "reported it; 168 h when none declared one). A cadence is taken only "
            "from a successful look of that machine. A machine never reported is "
            "stale by definition.",
            "A look whose manifest was taken longer before the look than that same "
            "cadence window is recorded as manifest_stale and does not count, unless "
            "the reporter marks the manifest as one it sealed earlier and relayed "
            "(its age is then shown, not judged). The manifest's own date and that "
            "mark are both declared by the reporting client, so this catches an old "
            "export sent as new by mistake, not a forged date.",
        ],
    }
