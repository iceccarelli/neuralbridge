"""Protective separation distance, ISO/TS 15066 speed and separation monitoring.

The formula is public and short. What it costs to get right is the inputs, and
what nobody sells today is the arithmetic done against a machine's own recorded
run rather than against a number somebody typed into a risk assessment.

    S(t0) = Sh + Sr + Ss + C + Zd + Zr

Sh  the distance the person covers while the machine notices and stops
Sr  the distance the machine covers while it is still noticing
Ss  the distance the machine covers while stopping
C   intrusion distance: how far a body part reaches before it is detected
Zd  position uncertainty of the sensing system
Zr  position uncertainty of the machine

Two details decide whether a separation calculation is honest.

The first is that Sh runs over Tr + Ts, not over Ts. The person keeps walking
during the reaction time, and a calculation that omits it is short by roughly a
metre at walking pace.

The second is that Ss is only valid at the speed it was measured at. Scaling a
measured stopping distance up to a higher speed is a model of constant
deceleration, and it is where a compliant-looking number quietly stops being
evidence. :func:`separation_required` reports which of the two it used, and the
caller is expected to carry that into the tier the bundle can claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from assurance.machine.envelope import SafetyEnvelope

__all__ = ["SeparationBreakdown", "separation_required"]


@dataclass(frozen=True)
class SeparationBreakdown:
    """Every term of S(t0), kept separately so a reviewer can argue with one.

    A single number is not reviewable. A safety engineer who disagrees with the
    result almost always disagrees with one term — usually C, occasionally vh —
    and an assurance case that cannot show which term is which forces them to
    reject the whole thing.
    """

    human_travel_mm: float          # Sh
    robot_reaction_travel_mm: float  # Sr
    robot_stopping_travel_mm: float  # Ss
    intrusion_mm: float             # C
    human_uncertainty_mm: float     # Zd
    robot_uncertainty_mm: float     # Zr
    #: "measured" or "extrapolated_quadratic" — how Ss was arrived at.
    stopping_basis: str
    #: The closing speed used, and whether it was measured or declared.
    human_speed_mm_s: float
    human_speed_source: str         # "sensed" | "declared"
    robot_speed_mm_s: float

    @property
    def total_mm(self) -> float:
        return (
            self.human_travel_mm
            + self.robot_reaction_travel_mm
            + self.robot_stopping_travel_mm
            + self.intrusion_mm
            + self.human_uncertainty_mm
            + self.robot_uncertainty_mm
        )

    @property
    def rests_on_extrapolation(self) -> bool:
        """Whether the verdict depends on a stopping distance nobody measured."""
        return self.stopping_basis != "measured"

    def to_dict(self) -> dict[str, Any]:
        return {
            "Sh_human_travel_mm": self.human_travel_mm,
            "Sr_robot_reaction_travel_mm": self.robot_reaction_travel_mm,
            "Ss_robot_stopping_travel_mm": self.robot_stopping_travel_mm,
            "C_intrusion_mm": self.intrusion_mm,
            "Zd_human_uncertainty_mm": self.human_uncertainty_mm,
            "Zr_robot_uncertainty_mm": self.robot_uncertainty_mm,
            "total_mm": self.total_mm,
            "stopping_basis": self.stopping_basis,
            "human_speed_mm_s": self.human_speed_mm_s,
            "human_speed_source": self.human_speed_source,
            "robot_speed_mm_s": self.robot_speed_mm_s,
        }

    def explain(self) -> str:
        return (
            f"S = {self.human_travel_mm:.0f} (Sh) "
            f"+ {self.robot_reaction_travel_mm:.0f} (Sr) "
            f"+ {self.robot_stopping_travel_mm:.0f} (Ss, {self.stopping_basis}) "
            f"+ {self.intrusion_mm:.0f} (C) "
            f"+ {self.human_uncertainty_mm:.0f} (Zd) "
            f"+ {self.robot_uncertainty_mm:.0f} (Zr) "
            f"= {self.total_mm:.0f} mm"
        )


def separation_required(
    envelope: SafetyEnvelope,
    *,
    robot_speed_mm_s: float,
    human_speed_mm_s: float | None = None,
) -> SeparationBreakdown:
    """Compute S(t0) for one instant.

    ``human_speed_mm_s`` is the closing speed the sensing system reported. When
    it is ``None`` the envelope's declared approach speed is used and the
    breakdown says so, because a declared 1600 mm/s standing in for a sensed
    closing speed is an assumption a reviewer is entitled to see.
    """
    if robot_speed_mm_s < 0:
        raise ValueError("robot_speed_mm_s is negative.")

    if human_speed_mm_s is None:
        vh = envelope.human_approach_speed_mm_s
        vh_source = "declared"
    else:
        if human_speed_mm_s < 0:
            raise ValueError("human_speed_mm_s is negative.")
        vh = human_speed_mm_s
        vh_source = "sensed"

    stop = envelope.stop
    ss, basis = stop.stop_distance_at(robot_speed_mm_s)

    return SeparationBreakdown(
        human_travel_mm=vh * stop.total_delay_s,
        robot_reaction_travel_mm=robot_speed_mm_s * stop.reaction_time_s,
        robot_stopping_travel_mm=ss,
        intrusion_mm=envelope.intrusion_distance_mm,
        human_uncertainty_mm=envelope.uncertainty.human_position_mm,
        robot_uncertainty_mm=envelope.uncertainty.robot_position_mm,
        stopping_basis=basis,
        human_speed_mm_s=vh,
        human_speed_source=vh_source,
        robot_speed_mm_s=robot_speed_mm_s,
    )
