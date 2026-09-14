"""What a watch looks at, and how often somebody expects it to.

A watch is a standing declaration: these machines, these plans, these export
folders, checked on this cadence. It is written once and then nobody touches it
again, which is exactly why it has to carry the things that are easy to get
wrong at three in the morning eighteen months later — which plan, which
territory, and how stale an observation is allowed to get before its silence
becomes a finding in itself.

``max_age_hours`` is the field that makes a watch worth paying for. A watch that
stopped running is indistinguishable from a fleet that stopped changing, and the
second is the comfortable interpretation. Declaring the expected cadence turns
that ambiguity into an alarm.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import content_hash_of

__all__ = ["WatchConfig", "WatchError", "WatchTarget"]


class WatchError(AssuranceError):
    """A watch is malformed, or would watch nothing."""


@dataclass(frozen=True)
class WatchTarget:
    """One machine, and where this run should look for it."""

    serial: str
    #: Path to the collection plan for this machine's type.
    plan: str
    #: Folder the machine's exports are dropped into.
    root: str
    site: str = ""
    #: ISO 3166-1 alpha-2. Absent here means a filing under CRA Article 14
    #: cannot name this unit's territory, so the watch reports it as a gap.
    country: str = ""
    year: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.serial or not self.plan or not self.root:
            raise WatchError(
                "a watch target needs a serial, a plan and a root. A target "
                "missing any of them would be silently skipped every run, which "
                "reads exactly like a machine that never changes."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial, "plan": self.plan, "root": self.root,
            "site": self.site, "country": self.country, "year": self.year,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WatchTarget:
        return cls(
            serial=str(d["serial"]), plan=str(d["plan"]), root=str(d["root"]),
            site=str(d.get("site", "")), country=str(d.get("country", "")).upper(),
            year=str(d.get("year", "")), notes=str(d.get("notes", "")),
        )


@dataclass(frozen=True)
class WatchConfig:
    """A standing instruction to keep looking."""

    watch_id: str
    targets: tuple[WatchTarget, ...]
    #: Who the watch runs as. Every record it seals is attributed here, and an
    #: automated actor is marked as automation rather than dressed as a person.
    operator: str = "assurance-watch"
    organisation: str = ""
    #: How old an observation may be before the watch itself is a finding.
    #: A watch nobody notices has stopped is worse than no watch, because the
    #: absence of alarms gets read as the absence of change.
    max_age_hours: float = 168.0
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.watch_id:
            raise WatchError("a watch needs an id.")
        if not self.targets:
            raise WatchError(
                f"watch {self.watch_id!r} has no targets: it would report "
                "'nothing changed' forever, about nothing."
            )
        if self.max_age_hours <= 0:
            raise WatchError("max_age_hours must be positive.")
        seen: set[str] = set()
        for t in self.targets:
            if t.serial in seen:
                raise WatchError(
                    f"watch {self.watch_id!r} lists serial {t.serial!r} twice.")
            seen.add(t.serial)

    @property
    def targets_without_country(self) -> tuple[WatchTarget, ...]:
        return tuple(t for t in self.targets if not t.country)

    def target(self, serial: str) -> WatchTarget | None:
        return next((t for t in self.targets if t.serial == serial), None)

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "watch_id": self.watch_id,
            "operator": self.operator,
            "organisation": self.organisation,
            "max_age_hours": self.max_age_hours,
            "notes": self.notes,
            "targets": [t.to_dict() for t in
                        sorted(self.targets, key=lambda t: t.serial)],
        }

    def content_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WatchConfig:
        return cls(
            watch_id=str(d["watch_id"]),
            targets=tuple(WatchTarget.from_dict(t) for t in d["targets"]),
            operator=str(d.get("operator", "assurance-watch")),
            organisation=str(d.get("organisation", "")),
            max_age_hours=float(d.get("max_age_hours", 168.0)),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> WatchConfig:
        p = Path(path)
        config = cls.from_dict(json.loads(p.read_text(encoding="utf-8")))
        # Plan and root paths are written relative to the config, because a
        # watch outlives whatever directory it was first run from.
        base = p.parent
        return WatchConfig(
            watch_id=config.watch_id,
            operator=config.operator,
            organisation=config.organisation,
            max_age_hours=config.max_age_hours,
            notes=config.notes,
            targets=tuple(
                WatchTarget(
                    serial=t.serial,
                    plan=str((base / t.plan).resolve()) if not Path(t.plan).is_absolute()
                    else t.plan,
                    root=str((base / t.root).resolve()) if not Path(t.root).is_absolute()
                    else t.root,
                    site=t.site, country=t.country, year=t.year, notes=t.notes,
                )
                for t in config.targets
            ),
        )
