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
    "OBSERVATION_KIND",
    "REPORT_KIND",
    "FAILED_STATUSES",
    "fleet_observations",
    "observation_succeeded",
    "observed_at_of",
    "declared_cadence",
]

OBSERVATION_KIND = "watch.observation"
#: One record per accepted report: the run summary and the declared cadence.
REPORT_KIND = "watch.report"
#: Used when no report has declared a cadence. The same default the Watch
#: configuration uses (``WatchConfig.max_age_hours``).
DEFAULT_CADENCE_HOURS = 168.0
#: Statuses that mean the look did not happen, or did not finish.
FAILED_STATUSES = frozenset({"uncollectable", "incomplete"})


def observation_succeeded(body: dict[str, Any]) -> bool:
    """Whether an observation record is a look that counts as having seen the machine.

    ``uncollectable`` is an attempt, not an observation. ``incomplete`` (or any
    record that says ``complete: false``) saw only part of what the plan names:
    it can describe a drift, but it cannot say the machine is current.
    """
    if str(body.get("status", "")) in FAILED_STATUSES:
        return False
    return body.get("complete", True) is not False


def observed_at_of(body: dict[str, Any], fallback: str) -> datetime | None:
    """When the look happened: the run's own clock, else the ledger append time."""
    try:
        return parse_utc(str(body.get("observed_at") or fallback))
    except (ValueError, TypeError):  # pragma: no cover - ledger writes UTC
        return None


def declared_cadence(ledger: EvidenceLedger) -> tuple[float, bool, str]:
    """``(hours, declared, run_started_at)`` for this ledger's account.

    Taken from the report with the latest ``run_started_at`` that declared one,
    so a delayed or replayed older report cannot move it. ``declared`` is False
    when nothing was ever declared and the default is being applied.
    """
    best: tuple[datetime, int, float, str] | None = None
    for entry in ledger.entries(kind=REPORT_KIND):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        hours = evidence.body.get("max_age_hours")
        if not isinstance(hours, (int, float)) or isinstance(hours, bool) or hours <= 0:
            continue
        try:
            started = parse_utc(str(evidence.body.get("run_started_at", "")))
        except (ValueError, TypeError):
            continue
        candidate = (started, entry.seq, float(hours), format_utc(started))
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    if best is None:
        return DEFAULT_CADENCE_HOURS, False, ""
    return best[2], True, best[3]


@dataclass(frozen=True)
class _Seen:
    at: datetime
    status: str
    complete: bool
    detail: str
    succeeded: bool


def fleet_observations(
    ledger: EvidenceLedger, *, now: datetime | None = None,
) -> dict[str, Any]:
    """Per machine: last successful look, last attempt, staleness, open cases."""
    as_of = now or utc_now()
    cadence, declared, declared_at = declared_cadence(ledger)

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
            "age_hours": age_hours,
            "stale": stale,
            "stale_reason": reason,
            "consecutive_failed_attempts": failed_run,
            "open_case_ids": sorted(open_cases.get(key, [])),
        })

    return {
        "as_of": format_utc(as_of),
        "cadence_hours": cadence,
        "cadence_declared": declared,
        "cadence_declared_by_run": declared_at,
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
            "These are observations the account holder chose to report; the hosted "
            "service cannot collect from a machine and did not watch any of them.",
            "A date here is when the customer's own Watch says it looked, as "
            "reported. It is not independently verified.",
            "A machine is stale when its last successful observation is older than "
            "the cadence the customer declared in a report"
            + ("" if declared else " (none declared yet: the default is applied)")
            + ". A machine that was never reported is stale by definition.",
        ],
    }
