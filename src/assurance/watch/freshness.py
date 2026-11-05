"""How old is the last run, judged against the clock rather than replayed.

``watch status`` reads the last sealed run and used to repeat its stored verdict.
A watch that stopped running never runs again, so a verdict that was ``quiet`` weeks
ago kept reading ``quiet``. Staleness is therefore judged here, at read time, against
a clock the caller can inject:

* a last run older than the config's ``max_age_hours`` is ``stale``;
* a last run dated later than the clock (beyond a small tolerance for clock drift)
  is ``future``: a run from the future is not a fresh one, and the skew is reported;
* a last run whose time cannot be read is ``unreadable``;
* a machine whose last successful look is older than ``max_age_hours`` is stale too,
  whatever the last run's own record said.

Any of these makes the status ``degraded``; none of them can improve a stored verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from assurance.core.identity import format_utc, parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.config import WatchConfig

__all__ = ["CLOCK_SKEW_TOLERANCE", "StatusFreshness", "assess_status_freshness",
           "interrupted_work"]

#: A run may be dated this much after the assessing clock (two machines, one drifting)
#: before it is called a run from the future.
CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)


@dataclass(frozen=True)
class StatusFreshness:
    #: ``fresh`` | ``stale`` | ``future`` | ``unreadable``
    state: str
    assessed_at: str
    last_run_at: str
    age_hours: float | None
    max_age_hours: float
    stale_machines: tuple[str, ...] = field(default_factory=tuple)
    #: Records this watch sealed AFTER its last run record: a run that began and did not finish.
    interrupted: tuple[str, ...] = field(default_factory=tuple)

    @property
    def degraded(self) -> bool:
        return self.state != "fresh" or bool(self.stale_machines) or bool(self.interrupted)

    @property
    def reasons(self) -> tuple[str, ...]:
        out: list[str] = []
        if self.state == "stale":
            out.append(f"the last run is {self.age_hours:.2f} h old, older than the "
                       f"declared max_age_hours of {self.max_age_hours:g}: a watch that "
                       "stopped running is not a fleet that stopped changing")
        elif self.state == "future":
            out.append(f"the last run is dated {self.last_run_at}, after the assessing "
                       f"clock ({self.assessed_at}): a clock is wrong, and a run from the "
                       "future is not a fresh one")
        elif self.state == "unreadable":
            out.append("the last run carries no readable time, so its age is unknown")
        if self.stale_machines:
            out.append("not looked at successfully within max_age_hours: "
                       + ", ".join(self.stale_machines))
        if self.interrupted:
            out.append("a run began and did not finish: it sealed " + "; ".join(self.interrupted)
                       + " after the last run record. What it found was never reported, so the "
                       "last run's verdict does not describe the ledger")
        return tuple(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state, "assessed_at": self.assessed_at,
            "last_run_at": self.last_run_at, "age_hours": self.age_hours,
            "max_age_hours": self.max_age_hours, "degraded": self.degraded,
            "stale_machines": list(self.stale_machines),
            "interrupted": list(self.interrupted), "reasons": list(self.reasons),
        }


def interrupted_work(ledger: EvidenceLedger, config: WatchConfig) -> tuple[str, ...]:
    """What this watch sealed after its last run record (empty when every run finished).

    The run record is the last thing a run writes. A run killed before it leaves sealed
    observations, manifests, divergences or cases that no run record ever reported, and the
    next run compares against the manifest the dead run already sealed: the change would be
    reported nowhere. Only records written by the watch's own actor count.
    """
    from assurance.change import store as cases
    from assurance.machinery.record import DIVERGENCE_KIND, MANIFEST_KIND
    from assurance.watch.runner import OBSERVATION_KIND, RUN_KIND

    kinds = {OBSERVATION_KIND, MANIFEST_KIND, DIVERGENCE_KIND, cases.OPENED_KIND,
             cases.UPDATED_KIND}
    entries = ledger.entries()
    last_seq = 0
    for entry in reversed(entries):
        if entry.kind == RUN_KIND and _run_is_ours(entry, config):
            last_seq = entry.seq
            break
    return tuple(f"{e.kind} {e.subject} (seq {e.seq})" for e in entries
                 if e.seq > last_seq and e.kind in kinds and e.actor == config.operator)


def _run_is_ours(entry: Any, config: WatchConfig) -> bool:
    evidence = entry.evidence()
    return bool(evidence.verify()) and evidence.body.get("watch_id") == config.watch_id


def assess_status_freshness(
    body: dict[str, Any], config: WatchConfig, ledger: EvidenceLedger, *, now: datetime,
) -> StatusFreshness:
    """Judge the last run ``body`` and each target's last successful look against ``now``."""
    raw = str(body.get("finished_at") or body.get("started_at") or "")
    try:
        at = parse_utc(raw)
    except (ValueError, TypeError):
        at = None
    if at is None:
        state, age = "unreadable", None
    elif at > now + CLOCK_SKEW_TOLERANCE:
        state, age = "future", None
    else:
        age = round(max(0.0, (now - at).total_seconds() / 3600), 2)
        state = "stale" if (now - at) > timedelta(hours=config.max_age_hours) else "fresh"

    from assurance.watch.runner import _last_observation_at

    cutoff = now - timedelta(hours=config.max_age_hours)
    stale: list[str] = []
    for target in config.targets:
        seen = _last_observation_at(ledger, target.serial)
        if seen is None or seen < cutoff:
            stale.append(target.serial)
    return StatusFreshness(
        state=state, assessed_at=format_utc(now), last_run_at=raw, age_hours=age,
        max_age_hours=config.max_age_hours, stale_machines=tuple(sorted(stale)),
        interrupted=interrupted_work(ledger, config))
