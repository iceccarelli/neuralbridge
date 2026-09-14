"""Verify a recorded run against a declared safety envelope.

This is the engine. It takes what the manufacturer claimed and what the machine
actually did, and produces a result that states, per check, what was verified,
what was violated, by how much, and what was not looked at.

Three design decisions carry the product.

**A check that could not run is not a pass.** Every check reports one of
verified / violated / not_applicable / unchecked, and ``unchecked`` appears in
the bundle as prominently as a violation. A tool that silently skips the check
it could not perform is worse than no tool, because it produces a clean report.

**The verdict inherits the weakest input.** The tier a result may claim is the
minimum of the trace's provenance ceiling, the envelope's figure bases, and the
limits table's verification state. A perfect run against a datasheet stopping
distance is not validated evidence, and the result says so without being asked.

**Margins, not booleans.** A separation that passed by 3 mm and one that passed
by 800 mm are different facts about a cell. The worst margin per check is
recorded, because that is the number an integrator actually needs before
shipping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from assurance.core.identity import utc_now
from assurance.core.tiers import AssuranceTier
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.ssm import separation_required
from assurance.machine.trace import OperatingMode, Trace

__all__ = [
    "CheckOutcome",
    "CheckResult",
    "Verdict",
    "VerificationResult",
    "Violation",
    "verify",
]

#: Bumped when the meaning of a check changes. Recorded in every result so an
#: old bundle is never silently reinterpreted under new rules.
ENGINE_VERSION = "1"


class CheckOutcome(StrEnum):
    VERIFIED = "verified"
    VIOLATED = "violated"
    #: The envelope makes no claim here, or the trace never entered this regime.
    NOT_APPLICABLE = "not_applicable"
    #: The check applies and could not be run. Never treat as a pass.
    UNCHECKED = "unchecked"


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    #: Nothing was violated, but something that should have been checked was not.
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class Violation:
    """One sample that failed one check, with the arithmetic that condemned it.

    ``measured`` is always what the machine did and ``bound`` is always the
    limit it was held to. ``direction`` says which side of the bound is safe, so
    a reader never has to infer whether a number was too big or too small.
    """

    check: str
    sample_index: int
    t: float
    measured: float
    bound: float
    unit: str
    #: "at_least" — measured must not fall below bound (separation).
    #: "at_most"  — measured must not rise above bound (speed, force).
    direction: str = "at_least"
    detail: str = ""
    breakdown: dict[str, Any] = field(default_factory=dict)

    @property
    def exceedance(self) -> float:
        """How far the wrong side of the bound the machine was. Always positive."""
        if self.direction == "at_least":
            return self.bound - self.measured
        return self.measured - self.bound

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "sample_index": self.sample_index,
            "t": self.t,
            "measured": self.measured,
            "bound": self.bound,
            "direction": self.direction,
            "unit": self.unit,
            "exceedance": self.exceedance,
            "detail": self.detail,
            "breakdown": self.breakdown,
        }


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one named check across the whole trace."""

    name: str
    outcome: CheckOutcome
    #: What the check is for, in the words a safety engineer would use.
    statement: str
    samples_examined: int = 0
    violations: tuple[Violation, ...] = ()
    #: Smallest margin seen among the samples that passed. None if none passed.
    worst_margin: float | None = None
    unit: str = ""
    #: Why the check could not run, when outcome is UNCHECKED.
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome.value,
            "statement": self.statement,
            "samples_examined": self.samples_examined,
            "violation_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "worst_margin": self.worst_margin,
            "unit": self.unit,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class VerificationResult:
    """What this run proves about this product version, and what it does not."""

    envelope_hash: str
    trace_hash: str
    product: str
    product_version: str
    trace_id: str
    provenance: str
    engine_version: str
    checks: tuple[CheckResult, ...]
    checks_skipped: tuple[str, ...]
    tier: AssuranceTier
    verified_at: str

    @property
    def violations(self) -> list[Violation]:
        return [v for c in self.checks for v in c.violations]

    @property
    def unchecked(self) -> list[CheckResult]:
        return [c for c in self.checks if c.outcome is CheckOutcome.UNCHECKED]

    @property
    def verdict(self) -> Verdict:
        if self.violations:
            return Verdict.FAIL
        if self.unchecked:
            return Verdict.INCOMPLETE
        return Verdict.PASS

    @property
    def may_claim_physical_behaviour(self) -> bool:
        return self.tier.may_claim_physical_behaviour

    def check(self, name: str) -> CheckResult | None:
        return next((c for c in self.checks if c.name == name), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_version": self.engine_version,
            "envelope_hash": self.envelope_hash,
            "trace_hash": self.trace_hash,
            "product": self.product,
            "product_version": self.product_version,
            "trace_id": self.trace_id,
            "provenance": self.provenance,
            "verdict": self.verdict.value,
            "tier": self.tier.value,
            "may_claim_physical_behaviour": self.may_claim_physical_behaviour,
            "checks": [c.to_dict() for c in self.checks],
            "checks_skipped": list(self.checks_skipped),
            "verified_at": self.verified_at,
        }

    def summary(self) -> str:
        lines = [
            f"{self.product} {self.product_version} — {self.verdict.value.upper()} "
            f"at tier {self.tier.value}",
            f"  trace {self.trace_id} ({self.provenance}) {self.trace_hash[:12]}",
            f"  envelope {self.envelope_hash[:12]}",
        ]
        for c in self.checks:
            mark = {"verified": "ok  ", "violated": "FAIL", "not_applicable": "n/a ",
                    "unchecked": "??  "}[c.outcome.value]
            margin = (f"  worst margin {c.worst_margin:.1f} {c.unit}"
                      if c.worst_margin is not None else "")
            lines.append(f"  [{mark}] {c.name} ({c.samples_examined} samples)"
                         f"{margin}")
            if c.reason:
                lines.append(f"           {c.reason}")
            for v in c.violations[:3]:
                lines.append(
                    f"           t={v.t:.3f}s measured {v.measured:.1f} "
                    f"{'<' if v.direction == 'at_least' else '>'} "
                    f"{v.bound:.1f} {v.unit} (by {v.exceedance:.1f})"
                )
            if len(c.violations) > 3:
                lines.append(f"           ... and {len(c.violations) - 3} more")
        if not self.may_claim_physical_behaviour:
            lines.append(
                "  This result may NOT be used to claim how the hardware behaves."
            )
        return "\n".join(lines)


# -- the checks -----------------------------------------------------------


def _workspace_containment(envelope: SafetyEnvelope, trace: Trace) -> CheckResult:
    violations: list[Violation] = []
    worst: float | None = None
    for i, s in enumerate(trace.samples):
        excursion = envelope.workspace.excursion_mm(s.tcp)
        if excursion > 0:
            violations.append(Violation(
                check="workspace_containment", sample_index=i, t=s.t,
                measured=excursion, bound=0.0, unit="mm", direction="at_most",
                detail=f"TCP at {s.tcp} is outside the declared workspace.",
            ))
        else:
            margin = min(
                min(v - lo, hi - v)
                for lo, v, hi in zip(envelope.workspace.minimum, s.tcp,
                                     envelope.workspace.maximum, strict=True)
            )
            worst = margin if worst is None else min(worst, margin)
    return CheckResult(
        name="workspace_containment",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="The tool centre point stayed inside the declared workspace.",
        samples_examined=len(trace.samples),
        violations=tuple(violations),
        worst_margin=worst,
        unit="mm",
    )


def _speed_limit(envelope: SafetyEnvelope, trace: Trace) -> CheckResult:
    violations: list[Violation] = []
    worst: float | None = None
    examined = 0
    modes_without_limit: list[str] = []
    for i, s in enumerate(trace.samples):
        limit = envelope.speed_limit_for(s.mode)
        if limit is None:
            if s.mode.value not in modes_without_limit:
                modes_without_limit.append(s.mode.value)
            continue
        examined += 1
        if s.tcp_speed > limit:
            violations.append(Violation(
                check="speed_limit", sample_index=i, t=s.t,
                measured=s.tcp_speed, bound=limit, unit="mm/s", direction="at_most",
                detail=f"TCP speed {s.tcp_speed:.1f} exceeds the {s.mode.value} "
                       f"limit of {limit:.1f} mm/s.",
            ))
        else:
            margin = limit - s.tcp_speed
            worst = margin if worst is None else min(worst, margin)

    if examined == 0:
        return CheckResult(
            name="speed_limit", outcome=CheckOutcome.UNCHECKED,
            statement="TCP speed stayed within the declared limit for the mode in force.",
            samples_examined=0, unit="mm/s",
            reason=f"the envelope declares no speed limit for any mode present in the "
                   f"trace ({', '.join(m.value for m in trace.modes_present())}).",
        )
    result = CheckResult(
        name="speed_limit",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="TCP speed stayed within the declared limit for the mode in force.",
        samples_examined=examined, violations=tuple(violations),
        worst_margin=worst, unit="mm/s",
        reason=("no declared limit for mode(s) " + ", ".join(modes_without_limit)
                + "; those samples were not checked." if modes_without_limit else ""),
    )
    return result


def _ssm_separation(envelope: SafetyEnvelope, trace: Trace) -> tuple[CheckResult, list[str]]:
    """The check that is the whole reason this package exists."""
    caveats: list[str] = []
    violations: list[Violation] = []
    worst: float | None = None
    examined = 0
    no_separation_reported = 0
    extrapolated = 0

    relevant = [(i, s) for i, s in enumerate(trace.samples)
                if s.mode.separation_is_the_control]
    if not relevant:
        return CheckResult(
            name="ssm_separation", outcome=CheckOutcome.NOT_APPLICABLE,
            statement="Measured separation met the ISO/TS 15066 protective "
                      "separation distance at every instant.",
            samples_examined=0, unit="mm",
            reason="the trace contains no samples in a mode where separation is "
                   "the protective measure.",
        ), caveats

    for i, s in relevant:
        if s.separation is None:
            no_separation_reported += 1
            continue
        examined += 1
        breakdown = separation_required(
            envelope, robot_speed_mm_s=s.tcp_speed, human_speed_mm_s=s.human_speed,
        )
        if breakdown.rests_on_extrapolation:
            extrapolated += 1
        required = breakdown.total_mm
        if s.separation < required:
            violations.append(Violation(
                check="ssm_separation", sample_index=i, t=s.t,
                measured=s.separation, bound=required, unit="mm",
                direction="at_least",
                detail=breakdown.explain(), breakdown=breakdown.to_dict(),
            ))
        else:
            margin = s.separation - required
            worst = margin if worst is None else min(worst, margin)

    if no_separation_reported:
        caveats.append(
            f"{no_separation_reported} of {len(relevant)} samples in a "
            "separation-controlled mode reported no detected person. Those samples "
            "were not checked: this verifies the separation the sensing system "
            "measured, and cannot confirm the sensing system saw everyone."
        )
    if extrapolated:
        caveats.append(
            f"{extrapolated} samples ran at a speed above the one the stopping "
            f"distance was measured at ({envelope.stop.measured_at_speed_mm_s:.0f} "
            "mm/s). Ss for those samples is a constant-deceleration model, not a "
            "measurement."
        )

    if examined == 0:
        return CheckResult(
            name="ssm_separation", outcome=CheckOutcome.UNCHECKED,
            statement="Measured separation met the ISO/TS 15066 protective "
                      "separation distance at every instant.",
            samples_examined=0, unit="mm",
            reason="every sample in a separation-controlled mode reported no "
                   "detected person, so no separation was ever compared.",
        ), caveats

    return CheckResult(
        name="ssm_separation",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="Measured separation met the ISO/TS 15066 protective separation "
                  "distance at every instant.",
        samples_examined=examined, violations=tuple(violations),
        worst_margin=worst, unit="mm",
    ), caveats


def _stop_characterisation(envelope: SafetyEnvelope, trace: Trace) -> CheckResult:
    """Whether the machine ever ran faster than its stopping distance was measured at.

    This is not a safety limit in itself. It is the check that says whether the
    separation result above is a measurement or a model, and it is separate so
    that it cannot be lost inside a pass.
    """
    ceiling = envelope.stop.measured_at_speed_mm_s
    relevant = [(i, s) for i, s in enumerate(trace.samples)
                if s.mode.separation_is_the_control]
    violations = [
        Violation(
            check="stop_characterisation", sample_index=i, t=s.t,
            measured=s.tcp_speed, bound=ceiling, unit="mm/s", direction="at_most",
            detail=f"TCP ran at {s.tcp_speed:.1f} mm/s; the stopping distance was "
                   f"only ever measured at {ceiling:.1f} mm/s "
                   f"({envelope.stop.basis.kind}, {envelope.stop.basis.reference}).",
        )
        for i, s in relevant if s.tcp_speed > ceiling
    ]
    if not relevant:
        return CheckResult(
            name="stop_characterisation", outcome=CheckOutcome.NOT_APPLICABLE,
            statement="The machine never relied on a stopping distance outside the "
                      "speed range it was measured over.",
            unit="mm/s",
            reason="no separation-controlled samples in the trace.",
        )
    margins = [ceiling - s.tcp_speed for _, s in relevant if s.tcp_speed <= ceiling]
    return CheckResult(
        name="stop_characterisation",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="The machine never relied on a stopping distance outside the speed "
                  "range it was measured over.",
        samples_examined=len(relevant), violations=tuple(violations),
        worst_margin=min(margins) if margins else None, unit="mm/s",
    )


def _pfl_contact(
    envelope: SafetyEnvelope, trace: Trace, limits: LimitsTable | None,
) -> tuple[CheckResult, list[str]]:
    caveats: list[str] = []
    statement = ("Contact force and pressure stayed within the declared body-region "
                 "limits wherever contact was permitted.")
    contacts = [(i, s) for i, s in enumerate(trace.samples)
                if s.mode.contact_is_permitted and s.contact_force is not None]

    if not envelope.claims_pfl and not contacts:
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.NOT_APPLICABLE,
            statement=statement,
            reason="the envelope makes no power-and-force-limiting claim and the "
                   "trace records no contact.",
        ), caveats

    if limits is None:
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=0, unit="N",
            reason=f"{len(contacts)} contact samples were recorded and no body-region "
                   "limits table was supplied. Contact forces were NOT checked.",
        ), caveats

    if limits.content_hash() != envelope.pfl_limits_hash and envelope.pfl_limits_hash:
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=0, unit="N",
            reason=f"the supplied limits table ({limits.content_hash()[:12]}) is not "
                   f"the one the envelope was declared against "
                   f"({envelope.pfl_limits_hash[:12]}). Checking against a different "
                   "table would prove nothing about the declared product.",
        ), caveats

    caveats.append(limits.provenance_caveat)

    violations: list[Violation] = []
    worst: float | None = None
    examined = 0
    unknown_regions: list[str] = []
    without_area = 0

    for i, s in contacts:
        region = s.body_region
        if not region or region not in limits.regions:
            if region not in unknown_regions:
                unknown_regions.append(region or "<unnamed>")
            continue
        examined += 1
        force = float(s.contact_force or 0.0)
        allowed = limits.permitted_force_n(region, transient=False)
        if force > allowed:
            violations.append(Violation(
                check="pfl_contact", sample_index=i, t=s.t,
                measured=force, bound=allowed, unit="N", direction="at_most",
                detail=f"contact force {force:.1f} N on {region} exceeds the "
                       f"quasi-static limit of {allowed:.1f} N.",
            ))
        else:
            margin = allowed - force
            worst = margin if worst is None else min(worst, margin)

        if s.contact_area is None:
            without_area += 1
        else:
            pressure = force / float(s.contact_area)
            allowed_p = limits.permitted_pressure_n_cm2(region, transient=False)
            if pressure > allowed_p:
                violations.append(Violation(
                    check="pfl_contact", sample_index=i, t=s.t,
                    measured=pressure, bound=allowed_p, unit="N/cm2",
                    direction="at_most",
                    detail=f"contact pressure {pressure:.1f} N/cm² on {region} "
                           f"exceeds the quasi-static limit of {allowed_p:.1f} N/cm².",
                ))

    if unknown_regions:
        caveats.append(
            "contact samples credited to body region(s) "
            + ", ".join(sorted(unknown_regions))
            + " were not checked: the limits table does not cover them."
        )
    if without_area:
        caveats.append(
            f"{without_area} contact samples recorded a force but no contact area, so "
            "pressure was not checked for them. Force alone does not establish a PFL "
            "claim: a compliant force through a small area is not a compliant contact."
        )

    if examined == 0:
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=0, unit="N",
            reason="no contact sample could be matched to a region in the limits table.",
        ), caveats

    return CheckResult(
        name="pfl_contact",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement=statement, samples_examined=examined,
        violations=tuple(violations), worst_margin=worst, unit="N",
    ), caveats


def _mode_consistency(envelope: SafetyEnvelope, trace: Trace) -> CheckResult:
    """A person detected while the cell is in unrestricted automatic mode.

    This is not an ISO clause, it is the failure an integrator is actually
    frightened of: the safeguarding said the space was clear and it was not.
    """
    del envelope
    violations: list[Violation] = []
    for i, s in enumerate(trace.samples):
        if s.mode is OperatingMode.AUTOMATIC and s.separation is not None:
            violations.append(Violation(
                check="mode_consistency", sample_index=i, t=s.t,
                measured=1.0, bound=0.0, unit="detections", direction="at_most",
                detail="a person was detected while the cell was in unrestricted "
                       "automatic mode. Either the safeguarding did not transition, "
                       "or the mode signal is wrong. Both are findings.",
            ))
    return CheckResult(
        name="mode_consistency",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="No person was detected while the cell was in unrestricted "
                  "automatic mode.",
        samples_examined=len(trace.samples), violations=tuple(violations), unit="mm",
    )


# -- the entry point ------------------------------------------------------


def verify(
    envelope: SafetyEnvelope,
    trace: Trace,
    *,
    limits: LimitsTable | None = None,
) -> VerificationResult:
    """Check one run against one envelope.

    The returned tier is the weakest of everything the verdict rests on. It is
    computed, never passed in, because a tier a caller can assert is a tier that
    will be asserted.
    """
    checks: list[CheckResult] = []
    caveats: list[str] = []

    checks.append(_workspace_containment(envelope, trace))
    checks.append(_speed_limit(envelope, trace))
    ssm, ssm_caveats = _ssm_separation(envelope, trace)
    checks.append(ssm)
    caveats.extend(ssm_caveats)
    checks.append(_stop_characterisation(envelope, trace))
    pfl, pfl_caveats = _pfl_contact(envelope, trace, limits)
    checks.append(pfl)
    caveats.extend(pfl_caveats)
    checks.append(_mode_consistency(envelope, trace))

    # The tier is the floor of every input the verdict depends on.
    tier = min(trace.provenance.tier_ceiling, envelope.tier_ceiling)
    if limits is not None and pfl.outcome is CheckOutcome.VERIFIED:
        tier = min(tier, limits.tier_ceiling)

    stop_basis = envelope.stop.basis
    caveats.append(
        f"stopping performance is a {stop_basis.kind} figure "
        f"({stop_basis.reference}); reaction time "
        f"{envelope.stop.reaction_time_s:.3f} s and stop time "
        f"{envelope.stop.stop_time_s:.3f} s were taken from the envelope and not "
        "re-measured from this trace."
    )
    if trace.provenance.value == "simulation":
        caveats.append(
            "the trace is simulated. Nothing here is evidence about the physical "
            "machine, only about the model that produced these samples."
        )
    if trace.gaps:
        caveats.append(
            f"the trace has {len(trace.gaps)} gap(s) longer than two sample periods, "
            f"the first at t={trace.gaps[0][0]:.3f}s. Nothing is known about what the "
            "machine did inside a gap."
        )
    caveats.append(
        "this compares a recorded trace against a declared envelope. It does not "
        "establish that the trace came from the machine it names, that the sensing "
        "system detected every person present, or that the envelope is the right "
        "envelope for this application."
    )

    return VerificationResult(
        envelope_hash=envelope.content_hash(),
        trace_hash=trace.content_hash(),
        product=envelope.product,
        product_version=envelope.product_version,
        trace_id=trace.trace_id,
        provenance=trace.provenance.value,
        engine_version=ENGINE_VERSION,
        checks=tuple(checks),
        checks_skipped=tuple(caveats),
        tier=tier,
        verified_at=utc_now().isoformat().replace("+00:00", "Z"),
    )

