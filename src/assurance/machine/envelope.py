"""The safety envelope a machine is sold as staying inside.

This is the declaration half of the product. A manufacturer states, in a form
a machine can check, what the cell is claimed to do: where the tool may go, how
fast it may go there in each mode, how long it takes to notice a person and how
far it travels before it stops, and how much the sensing system might be wrong
by.

Every figure carries its source. A stopping distance copied off a datasheet and
a stopping distance measured at commissioning are both usable, and they are not
worth the same, so the envelope records which it is and the verification result
inherits that. This is the difference between an assurance case and a form.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of
from assurance.core.tiers import AssuranceTier
from assurance.machine.trace import OperatingMode

__all__ = [
    "DEFAULT_HUMAN_APPROACH_SPEED_MM_S",
    "EnvelopeError",
    "FigureBasis",
    "SafetyEnvelope",
    "SensingUncertainty",
    "StopPerformance",
    "Workspace",
]


class EnvelopeError(AssuranceError):
    """An envelope is incomplete, inconsistent, or claims more than it evidences."""


#: ISO 13855 walking speed, used where the sensing system does not report a
#: closing speed. 1600 mm/s is the figure for a person approaching the detection
#: zone; 2000 mm/s is used for a directed approach at short range. Declaring the
#: slower figure where the faster applies shortens every computed distance, so
#: the envelope records which was declared and the verifier says so in the
#: bundle rather than silently adopting a default.
DEFAULT_HUMAN_APPROACH_SPEED_MM_S = 1600.0


@dataclass(frozen=True)
class FigureBasis:
    """Where a safety-relevant number came from, and how much it is worth.

    ``measured`` means somebody put an instrument on this machine and recorded
    the result. ``datasheet`` means a vendor asserted it. ``estimated`` means
    somebody worked it out. The tier a bundle can reach is capped by the weakest
    basis among the figures the verdict actually depended on.
    """

    kind: str          # measured | datasheet | estimated
    reference: str     # report number, datasheet revision, calculation note
    date: str = ""     # ISO date the figure was established

    _RANK = {"measured": AssuranceTier.VALIDATED, "datasheet": AssuranceTier.PROFILE,
             "estimated": AssuranceTier.PROFILE}

    def __post_init__(self) -> None:
        if self.kind not in ("measured", "datasheet", "estimated"):
            raise EnvelopeError(
                f"figure basis {self.kind!r} is not one of measured, datasheet, estimated."
            )
        if not self.reference:
            raise EnvelopeError(
                f"a {self.kind} figure with no reference cannot be checked by anyone. "
                "Give the report number, datasheet revision, or calculation note."
            )

    @property
    def tier_ceiling(self) -> AssuranceTier:
        return self._RANK[self.kind]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "reference": self.reference, "date": self.date}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FigureBasis:
        return cls(kind=str(d["kind"]), reference=str(d.get("reference", "")),
                   date=str(d.get("date", "")))


@dataclass(frozen=True)
class StopPerformance:
    """How long the machine takes to notice, and how far it goes before standstill.

    ``reaction_time_s`` is Tr in ISO/TS 15066: detection to the stop command
    taking effect. ``stop_time_s`` is Ts: command to standstill.
    ``stop_distance_mm`` is the travel over Ts, and it is only valid at the
    speed it was measured at — which is why that speed is a required field.
    Extrapolating a stopping distance past its measured point is the single
    most common way a separation calculation comes out short.
    """

    reaction_time_s: float
    stop_time_s: float
    stop_distance_mm: float
    measured_at_speed_mm_s: float
    basis: FigureBasis

    def __post_init__(self) -> None:
        for name in ("reaction_time_s", "stop_time_s", "stop_distance_mm",
                     "measured_at_speed_mm_s"):
            if getattr(self, name) < 0:
                raise EnvelopeError(f"StopPerformance.{name} is negative.")
        if self.measured_at_speed_mm_s <= 0:
            raise EnvelopeError(
                "StopPerformance.measured_at_speed_mm_s must be positive: a stopping "
                "distance with no speed attached cannot be used for anything."
            )

    @property
    def total_delay_s(self) -> float:
        """Tr + Ts: the whole window in which a person keeps moving toward the tool."""
        return self.reaction_time_s + self.stop_time_s

    def stop_distance_at(self, speed_mm_s: float) -> tuple[float, str]:
        """Stopping distance at ``speed_mm_s``, and the basis for it.

        Returns ``(distance_mm, basis)`` where basis is:

        ``measured``
            The requested speed is at or below the speed the figure was measured
            at, so the measured distance is used unchanged. That is conservative.

        ``extrapolated_quadratic``
            The requested speed exceeds the measured point. Stopping distance is
            scaled by the square of the speed ratio, which is what constant
            deceleration gives. It is a model, not a measurement, and the caller
            is expected to degrade the bundle's tier accordingly.
        """
        if speed_mm_s <= self.measured_at_speed_mm_s:
            return self.stop_distance_mm, "measured"
        ratio = speed_mm_s / self.measured_at_speed_mm_s
        return self.stop_distance_mm * ratio * ratio, "extrapolated_quadratic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "reaction_time_s": self.reaction_time_s,
            "stop_time_s": self.stop_time_s,
            "stop_distance_mm": self.stop_distance_mm,
            "measured_at_speed_mm_s": self.measured_at_speed_mm_s,
            "basis": self.basis.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StopPerformance:
        return cls(
            reaction_time_s=float(d["reaction_time_s"]),
            stop_time_s=float(d["stop_time_s"]),
            stop_distance_mm=float(d["stop_distance_mm"]),
            measured_at_speed_mm_s=float(d["measured_at_speed_mm_s"]),
            basis=FigureBasis.from_dict(d["basis"]),
        )


@dataclass(frozen=True)
class SensingUncertainty:
    """Zd and Zr: how wrong the position measurements may be.

    These come from the safety sensing system's own specification and from the
    robot's position accuracy. They are added to the required separation, so
    understating them shortens the distance the cell will keep.
    """

    human_position_mm: float          # Zd
    robot_position_mm: float          # Zr
    basis: FigureBasis

    def __post_init__(self) -> None:
        if self.human_position_mm < 0 or self.robot_position_mm < 0:
            raise EnvelopeError("SensingUncertainty values are negative.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "human_position_mm": self.human_position_mm,
            "robot_position_mm": self.robot_position_mm,
            "basis": self.basis.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SensingUncertainty:
        return cls(
            human_position_mm=float(d["human_position_mm"]),
            robot_position_mm=float(d["robot_position_mm"]),
            basis=FigureBasis.from_dict(d["basis"]),
        )


@dataclass(frozen=True)
class Workspace:
    """An axis-aligned box the tool centre point is claimed to stay inside, mm."""

    minimum: tuple[float, float, float]
    maximum: tuple[float, float, float]
    frame: str = "cell"

    def __post_init__(self) -> None:
        if any(b <= a for a, b in zip(self.minimum, self.maximum, strict=True)):
            raise EnvelopeError(
                f"workspace maximum {self.maximum} is not strictly greater than "
                f"minimum {self.minimum} on every axis."
            )

    def contains(self, point: tuple[float, float, float]) -> bool:
        return all(lo <= v <= hi for lo, v, hi in
                   zip(self.minimum, point, self.maximum, strict=True))

    def excursion_mm(self, point: tuple[float, float, float]) -> float:
        """How far outside the box the point is, on its worst axis. 0 if inside."""
        worst = 0.0
        for lo, v, hi in zip(self.minimum, point, self.maximum, strict=True):
            worst = max(worst, lo - v, v - hi)
        return worst

    def to_dict(self) -> dict[str, Any]:
        return {"minimum": list(self.minimum), "maximum": list(self.maximum),
                "frame": self.frame}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Workspace:
        return cls(
            minimum=tuple(float(v) for v in d["minimum"]),  # type: ignore[arg-type]
            maximum=tuple(float(v) for v in d["maximum"]),  # type: ignore[arg-type]
            frame=str(d.get("frame", "cell")),
        )


@dataclass(frozen=True)
class SafetyEnvelope:
    """The manufacturer's machine-checkable claim about one product version."""

    envelope_id: str
    product: str
    product_version: str
    workspace: Workspace
    #: Maximum permitted TCP speed per operating mode, mm/s. A mode absent from
    #: this mapping is a mode the envelope makes no claim about, and the
    #: verifier reports it as unchecked rather than passing it.
    max_tcp_speed_mm_s: dict[OperatingMode, float]
    stop: StopPerformance
    uncertainty: SensingUncertainty
    #: C in ISO/TS 15066: intrusion distance, from ISO 13855, for the body part
    #: the sensing system can resolve. 850 mm is the usual figure where a hand
    #: or arm can reach through undetected; it is not a default here because
    #: getting it wrong is worth about a metre of separation.
    intrusion_distance_mm: float
    #: vh where the sensing system does not report a closing speed.
    human_approach_speed_mm_s: float = DEFAULT_HUMAN_APPROACH_SPEED_MM_S
    #: Content hash of the power-and-force limits table this envelope is
    #: declared against. Empty means the product makes no PFL claim.
    pfl_limits_hash: str = ""
    declared_by: Actor = field(default_factory=lambda: Actor(identifier="", role=""))
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.envelope_id or not self.product or not self.product_version:
            raise EnvelopeError(
                "an envelope needs envelope_id, product and product_version: "
                "evidence that is not tied to a specific version proves nothing "
                "about the unit in front of the auditor."
            )
        if self.intrusion_distance_mm < 0:
            raise EnvelopeError("intrusion_distance_mm is negative.")
        if self.human_approach_speed_mm_s <= 0:
            raise EnvelopeError("human_approach_speed_mm_s must be positive.")
        for mode, speed in self.max_tcp_speed_mm_s.items():
            if speed < 0:
                raise EnvelopeError(f"max_tcp_speed_mm_s[{mode}] is negative.")

    @property
    def claims_pfl(self) -> bool:
        return bool(self.pfl_limits_hash)

    @property
    def tier_ceiling(self) -> AssuranceTier:
        """The best a verification against this envelope could ever be worth.

        An envelope whose stopping distance is a datasheet figure cannot produce
        VALIDATED evidence however good the trace is, because the number the
        verdict rests on was never measured on this machine.
        """
        return min(self.stop.basis.tier_ceiling, self.uncertainty.basis.tier_ceiling)

    def speed_limit_for(self, mode: OperatingMode) -> float | None:
        return self.max_tcp_speed_mm_s.get(mode)

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "product": self.product,
            "product_version": self.product_version,
            "workspace": self.workspace.to_dict(),
            "max_tcp_speed_mm_s": {k.value: v for k, v in
                                   sorted(self.max_tcp_speed_mm_s.items())},
            "stop": self.stop.to_dict(),
            "uncertainty": self.uncertainty.to_dict(),
            "intrusion_distance_mm": self.intrusion_distance_mm,
            "human_approach_speed_mm_s": self.human_approach_speed_mm_s,
            "pfl_limits_hash": self.pfl_limits_hash,
            "declared_by": self.declared_by.to_dict(),
            "notes": self.notes,
        }

    def content_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SafetyEnvelope:
        return cls(
            envelope_id=str(d["envelope_id"]),
            product=str(d["product"]),
            product_version=str(d["product_version"]),
            workspace=Workspace.from_dict(d["workspace"]),
            max_tcp_speed_mm_s={OperatingMode(k): float(v)
                                for k, v in (d.get("max_tcp_speed_mm_s") or {}).items()},
            stop=StopPerformance.from_dict(d["stop"]),
            uncertainty=SensingUncertainty.from_dict(d["uncertainty"]),
            intrusion_distance_mm=float(d["intrusion_distance_mm"]),
            human_approach_speed_mm_s=float(
                d.get("human_approach_speed_mm_s", DEFAULT_HUMAN_APPROACH_SPEED_MM_S)),
            pfl_limits_hash=str(d.get("pfl_limits_hash", "")),
            declared_by=Actor.from_dict(d["declared_by"]) if d.get("declared_by")
            else Actor(identifier="", role=""),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> SafetyEnvelope:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
