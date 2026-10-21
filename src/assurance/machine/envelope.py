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

Every figure is a finite number in the package's fixed units (millimetres,
millimetres per second, seconds). Nothing is converted and nothing is repaired:
a string, a boolean, NaN, an infinity, a negative magnitude, or a value past
the plausibility rails in :mod:`assurance.machine.quantities` is refused with
an :class:`EnvelopeError` naming the field. An envelope field the schema does
not define is refused too, because the alternative — ignoring
``human_approach_speed_m_s`` and quietly using the 1600 mm/s default — is a
unit error that nobody sees.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of
from assurance.core.tiers import AssuranceTier
from assurance.machine.quantities import (
    DISTANCE_MAX_MM,
    DURATION_MAX_S,
    SPEED_MAX_MM_S,
    number,
)
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


def _num(value: Any, name: str, **kw: Any) -> float:
    """A physical figure, or an :class:`EnvelopeError` naming it."""
    return number(value, name, exc=EnvelopeError, **kw)


def _object(value: Any, name: str, allowed: set[str]) -> dict[str, Any]:
    """A JSON object whose every key is one this schema defines.

    An unknown key is refused rather than ignored. The failure it prevents is
    quiet: ``human_approach_speed_m_s`` ignored means the 1600 mm/s default is
    used, and a misspelt ``pfl_limit_hash`` means the product makes no force
    claim at all.
    """
    if not isinstance(value, dict):
        raise EnvelopeError(f"{name} must be an object, got {type(value).__name__}.")
    unknown = sorted(str(k) for k in set(value) - allowed)
    if unknown:
        raise EnvelopeError(
            f"{name} has unrecognised field(s) {', '.join(unknown)}. Units are part of "
            "the field name (…_mm, …_mm_s, …_s) and nothing here converts them, so a "
            "field in other units is refused rather than ignored. Expected: "
            + ", ".join(sorted(allowed)) + "."
        )
    return value


def _require(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d:
        raise EnvelopeError(f"{where} is missing required field {key!r}.")
    return d[key]


#: ISO 13855 walking speed, used where the sensing system does not report a
#: closing speed. 1600 mm/s is the figure for a person approaching the detection
#: zone; 2000 mm/s is used for a directed approach at short range. Declaring the
#: slower figure where the faster applies shortens every computed distance, so
#: the envelope records which was declared and the verifier says so in the
#: bundle rather than silently adopting a default.
#:
#: UNVERIFIED: both figures, and which applies at what separation, are quoted
#: from memory of the standards, not from a licensed copy in this repository.
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
        if not isinstance(self.reference, str) or not self.reference.strip():
            raise EnvelopeError(
                f"a {self.kind} figure with no reference cannot be checked by anyone. "
                "Give the report number, datasheet revision, or calculation note."
            )
        if self.date:
            try:
                if "T" in self.date or " " in self.date:
                    datetime.fromisoformat(self.date.replace("Z", "+00:00"))
                else:
                    date.fromisoformat(self.date)
            except (ValueError, TypeError) as exc:
                raise EnvelopeError(
                    f"figure date {self.date!r} is not an ISO date (YYYY-MM-DD). A date "
                    "nobody can parse cannot show how old the figure is."
                ) from exc

    @property
    def tier_ceiling(self) -> AssuranceTier:
        return self._RANK[self.kind]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "reference": self.reference, "date": self.date}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FigureBasis:
        d = _object(d, "basis", {"kind", "reference", "date"})
        return cls(kind=str(_require(d, "kind", "basis")),
                   reference=str(d.get("reference", "")), date=str(d.get("date", "")))


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
        # Strictly positive: no real machine reacts in zero time or stops in zero
        # distance, and a zero here shortens the computed separation toward zero
        # while reading as a perfect measurement. Refuse it rather than believe it.
        _num(self.reaction_time_s, "StopPerformance.reaction_time_s",
             maximum=DURATION_MAX_S, positive=True)
        _num(self.stop_time_s, "StopPerformance.stop_time_s", maximum=DURATION_MAX_S,
             positive=True)
        _num(self.stop_distance_mm, "StopPerformance.stop_distance_mm",
             maximum=DISTANCE_MAX_MM, positive=True)
        if _num(self.measured_at_speed_mm_s, "StopPerformance.measured_at_speed_mm_s",
                maximum=SPEED_MAX_MM_S) <= 0:
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
        d = _object(d, "stop", {"reaction_time_s", "stop_time_s", "stop_distance_mm",
                                "measured_at_speed_mm_s", "basis"})
        return cls(
            reaction_time_s=_num(_require(d, "reaction_time_s", "stop"),
                                 "reaction_time_s", maximum=DURATION_MAX_S,
                                 positive=True),
            stop_time_s=_num(_require(d, "stop_time_s", "stop"), "stop_time_s",
                             maximum=DURATION_MAX_S, positive=True),
            stop_distance_mm=_num(_require(d, "stop_distance_mm", "stop"),
                                  "stop_distance_mm", maximum=DISTANCE_MAX_MM,
                                  positive=True),
            measured_at_speed_mm_s=_num(
                _require(d, "measured_at_speed_mm_s", "stop"),
                "measured_at_speed_mm_s", maximum=SPEED_MAX_MM_S),
            basis=FigureBasis.from_dict(_require(d, "basis", "stop")),
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
        _num(self.human_position_mm, "SensingUncertainty.human_position_mm",
             maximum=DISTANCE_MAX_MM)
        _num(self.robot_position_mm, "SensingUncertainty.robot_position_mm",
             maximum=DISTANCE_MAX_MM)

    @property
    def has_zero_figure(self) -> bool:
        return self.human_position_mm == 0 or self.robot_position_mm == 0

    @property
    def tier_ceiling(self) -> AssuranceTier:
        """The basis's ceiling, except that a zero figure is never a measurement.

        Zd and Zr are accepted at zero (a caller may genuinely fold the
        uncertainty into another term), but an instrument always has a nonzero
        error, so a ``measured`` basis over a zero cannot be what it says. The
        figure is capped at the weakest tier instead of refused, because refusing
        would stop an honest datasheet-level declaration from being verified at all.
        """
        if self.has_zero_figure:
            return AssuranceTier.PROFILE
        return self.basis.tier_ceiling

    def to_dict(self) -> dict[str, Any]:
        return {
            "human_position_mm": self.human_position_mm,
            "robot_position_mm": self.robot_position_mm,
            "basis": self.basis.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SensingUncertainty:
        d = _object(d, "uncertainty",
                    {"human_position_mm", "robot_position_mm", "basis"})
        return cls(
            human_position_mm=_num(_require(d, "human_position_mm", "uncertainty"),
                                   "human_position_mm", maximum=DISTANCE_MAX_MM),
            robot_position_mm=_num(_require(d, "robot_position_mm", "uncertainty"),
                                   "robot_position_mm", maximum=DISTANCE_MAX_MM),
            basis=FigureBasis.from_dict(_require(d, "basis", "uncertainty")),
        )


@dataclass(frozen=True)
class Workspace:
    """An axis-aligned box the tool centre point is claimed to stay inside, mm."""

    minimum: tuple[float, float, float]
    maximum: tuple[float, float, float]
    frame: str = "cell"

    def __post_init__(self) -> None:
        for label, corner in (("minimum", self.minimum), ("maximum", self.maximum)):
            if not isinstance(corner, (tuple, list)) or len(corner) != 3:
                raise EnvelopeError(
                    f"workspace {label} needs three coordinates (x, y, z), got {corner!r}."
                )
            for axis, v in zip("xyz", corner, strict=True):
                _num(v, f"workspace {label} {axis}", maximum=DISTANCE_MAX_MM, signed=True)
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
        d = _object(d, "workspace", {"minimum", "maximum", "frame"})
        corners: dict[str, tuple[float, float, float]] = {}
        for label in ("minimum", "maximum"):
            raw = _require(d, label, "workspace")
            if not isinstance(raw, (list, tuple)) or len(raw) != 3:
                raise EnvelopeError(
                    f"workspace {label} needs three coordinates (x, y, z), got {raw!r}."
                )
            x, y, z = (
                _num(v, f"workspace {label} {axis}", maximum=DISTANCE_MAX_MM,
                     signed=True)
                for axis, v in zip("xyz", raw, strict=True)
            )
            corners[label] = (x, y, z)
        return cls(minimum=corners["minimum"], maximum=corners["maximum"],
                   frame=str(d.get("frame", "cell")))


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
    #:
    #: UNVERIFIED: 850 mm and the reach it stands for are quoted from memory of
    #: ISO 13855, not from a licensed copy in this repository. The package does
    #: not compute C; it takes the figure the manufacturer declares, and it
    #: carries no ``FigureBasis`` for it, so a weak C does not lower the tier.
    intrusion_distance_mm: float
    #: vh where the sensing system does not report a closing speed. ``None`` means
    #: the envelope declared none and :data:`DEFAULT_HUMAN_APPROACH_SPEED_MM_S` is
    #: adopted; the verifier reports that as ``default``, never as ``declared``.
    #: Read the figure used through :attr:`approach_speed_mm_s`.
    human_approach_speed_mm_s: float | None = None
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
        _num(self.intrusion_distance_mm, "intrusion_distance_mm",
             maximum=DISTANCE_MAX_MM, positive=True)
        if self.human_approach_speed_mm_s is not None:
            _num(self.human_approach_speed_mm_s, "human_approach_speed_mm_s",
                 maximum=SPEED_MAX_MM_S, positive=True)
        for mode, speed in self.max_tcp_speed_mm_s.items():
            _num(speed, f"max_tcp_speed_mm_s[{mode}]", maximum=SPEED_MAX_MM_S)

    @property
    def approach_speed_mm_s(self) -> float:
        """The closing speed the separation sum uses when the trace records none."""
        if self.human_approach_speed_mm_s is None:
            return DEFAULT_HUMAN_APPROACH_SPEED_MM_S
        return self.human_approach_speed_mm_s

    @property
    def approach_speed_declared(self) -> bool:
        """Whether the manufacturer stated the approach speed, or it is the default."""
        return self.human_approach_speed_mm_s is not None

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
        return min(self.stop.basis.tier_ceiling, self.uncertainty.tier_ceiling)

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
        d = _object(d, "envelope", {
            "envelope_id", "product", "product_version", "workspace",
            "max_tcp_speed_mm_s", "stop", "uncertainty", "intrusion_distance_mm",
            "human_approach_speed_mm_s", "pfl_limits_hash", "declared_by", "notes",
        })
        limits_raw = d.get("max_tcp_speed_mm_s") or {}
        if not isinstance(limits_raw, dict):
            raise EnvelopeError("max_tcp_speed_mm_s must be an object keyed by mode.")
        limits: dict[OperatingMode, float] = {}
        for k, v in limits_raw.items():
            try:
                mode = OperatingMode(str(k))
            except ValueError as exc:
                raise EnvelopeError(
                    f"max_tcp_speed_mm_s names operating mode {k!r}, which is not one "
                    f"of {', '.join(m.value for m in OperatingMode)}."
                ) from exc
            limits[mode] = _num(v, f"max_tcp_speed_mm_s[{k}]", maximum=SPEED_MAX_MM_S)
        try:
            declared = (Actor.from_dict(d["declared_by"]) if d.get("declared_by")
                        else Actor(identifier="", role=""))
        except (KeyError, TypeError, AttributeError) as exc:
            raise EnvelopeError(f"declared_by is not a valid actor: {exc!r}.") from exc
        return cls(
            envelope_id=str(_require(d, "envelope_id", "envelope")),
            product=str(_require(d, "product", "envelope")),
            product_version=str(_require(d, "product_version", "envelope")),
            workspace=Workspace.from_dict(_require(d, "workspace", "envelope")),
            max_tcp_speed_mm_s=limits,
            stop=StopPerformance.from_dict(_require(d, "stop", "envelope")),
            uncertainty=SensingUncertainty.from_dict(
                _require(d, "uncertainty", "envelope")),
            intrusion_distance_mm=_num(
                _require(d, "intrusion_distance_mm", "envelope"),
                "intrusion_distance_mm", maximum=DISTANCE_MAX_MM, positive=True),
            # Absent or null means "not declared": the default is adopted and
            # reported as a default, not mistaken for the manufacturer's figure.
            human_approach_speed_mm_s=(
                None if d.get("human_approach_speed_mm_s") is None
                else _num(d["human_approach_speed_mm_s"], "human_approach_speed_mm_s",
                          maximum=SPEED_MAX_MM_S, positive=True)),
            pfl_limits_hash=str(d.get("pfl_limits_hash", "")),
            declared_by=declared,
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> SafetyEnvelope:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise EnvelopeError(f"{path} is not valid JSON: {exc}") from exc
        return cls.from_dict(raw)
