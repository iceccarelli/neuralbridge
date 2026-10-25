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
minimum of the trace's provenance ceiling (which a *declared* provenance cannot lift
above community; only a recorder attestation accepted under the verifier's own trust
list does), the envelope's figure bases, and the
limits table's verification state. A perfect run against a datasheet stopping
distance is not validated evidence, and the result says so without being asked.

**Margins, not booleans.** A separation that passed by 3 mm and one that passed
by 800 mm are different facts about a cell. The worst margin per check is
recorded, because that is the number an integrator actually needs before
shipping.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from typing import Any

from assurance.core.identity import utc_now
from assurance.core.tiers import AssuranceTier
from assurance.machine import provenance_trust
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.limits_review import LimitsReviewAssessment, ReviewTrust, assess_reviews
from assurance.machine.recorder_attestation import MachineRef, RecorderTrust
from assurance.machine.ssm import separation_required
from assurance.machine.trace import OperatingMode, Trace

__all__ = [
    "FORMULA_LIMITATION",
    "MIN_TRACE_DURATION_S",
    "MIN_TRACE_SAMPLES",
    "CheckOutcome",
    "CheckResult",
    "Verdict",
    "VerificationResult",
    "Violation",
    "is_known_engine",
    "parse_engine_version",
    "verify",
]

#: Bumped when the meaning of a check changes. Recorded in every result so an
#: old bundle is never silently reinterpreted under new rules.
#:
#: 2: a recording gap beside a separation-controlled sample makes
#:    ``ssm_separation`` unchecked, a contact force recorded where contact is not
#:    permitted makes ``pfl_contact`` unchecked, ``pfl_contact`` is unchecked
#:    while any contact sample went unevaluated (no area, or a region the table
#:    lacks), and inputs must be finite numbers (earlier engines passed NaN).
#: 3: coverage-incomplete data can no longer pass. A speed limit missing for a mode
#:    that was exercised, a separation or contact force missing on a sample in its
#:    regime, a recording gap anywhere, an unpinned PFL table, a trace below the
#:    sanity floor or that exercised no safety regime, and a future-dated trace or
#:    figure each make the check unchecked. Zero stop figures are refused. The
#:    separation statement names the computation, not the standard, and the
#:    formula limitation is always listed.
#: 4: a limits table reaches a validated tier only through an accepted signed
#:    review by a key in the verifier's own trust list. The table's free-text
#:    verified_by / verified_on claim no longer lifts the tier, and the review
#:    assessment is sealed into the bundle.
#: 5: a trace's declared provenance (bench / field) no longer lifts the tier. It is
#:    written by whoever files the trace and nothing signs a recording, so the tier is
#:    capped at community (``provenance_basis: declared_by_filer``, sealed and
#:    reported) until a recorder attestation can be verified
#:    (``machine/provenance_trust.py``). Earlier engines let ``field`` reach
#:    ``validated``; a bundle that carries that is rejected by the checker.
#: 6: a declared provenance can be lifted by a signed recorder attestation accepted
#:    under the verifier's own recorder trust list
#:    (``machine/recorder_attestation.py``, ``provenance_basis: recorder_attested``).
#:    The sealed body gains ``recorder_attestation`` (the assessment and the
#:    attestations as supplied) and ``machine_serial``. A bundle is believed to carry
#:    ``recorder_attested`` only if the checker's own re-assessment reproduces it;
#:    engine 5 and earlier bundles can never be read as recorder-attested.
ENGINE_VERSION = "6"

_ENGINE_SPELLING = re.compile(r"[1-9][0-9]{0,3}", re.ASCII)


def parse_engine_version(value: object) -> int | None:
    """The engine number a sealed body names, or ``None`` if it is not a real one.

    Only the canonical spelling counts: ASCII digits, no sign, no leading zero, no
    surrounding space, at most four digits. ``int()`` alone accepts ``"٦"`` (an Arabic-
    Indic six), ``" 6"`` and ``"+6"``, so a body could name an engine that this checker
    reads as 6 while every string comparison against ``ENGINE_VERSION`` says it is
    another one.
    """
    if type(value) is not str or not _ENGINE_SPELLING.fullmatch(value):
        return None
    return int(value)


def is_known_engine(value: object) -> bool:
    """Is ``value`` the spelling of an engine that exists (1 up to :data:`ENGINE_VERSION`)?"""
    n = parse_engine_version(value)
    return n is not None and n <= int(ENGINE_VERSION)

#: A sanity floor on how much trace is worth calling a verification, NOT a standard
#: and not taken from one. A single sample, or a handful spanning a few
#: milliseconds, cannot show a machine staying inside anything, and a result built
#: on one reads exactly like a result built on an hour of production. The numbers
#: are deliberately low so that no honest recording is refused; they only separate
#: "a run" from "a data point". The floor is stated in the ``trace_coverage``
#: check's statement and in ``checks_skipped`` of every result.
MIN_TRACE_SAMPLES = 10
MIN_TRACE_DURATION_S = 0.1

#: How far past the moment of verification an input may be dated before it is not
#: believed. A day absorbs clock skew and time zones (as in machinery/staleness and
#: limits.py); it does not absorb a run that "started" in 2099.
_FUTURE_TOLERANCE = timedelta(days=1)

#: Always listed in ``checks_skipped``. The separation arithmetic and its constants
#: are written from memory of the standards (see ssm.py and envelope.py), and no
#: result from this engine may be read as having been checked against the text.
FORMULA_LIMITATION = (
    "the separation formula and constants (Sh/Sr/Ss/C/Zd/Zr, the 1600 mm/s default "
    "approach speed, the quadratic extrapolation of the stopping distance) are "
    "unverified: formula and constants not verified against a licensed copy of the "
    "standard. A separation check passes against that computation, not against the "
    "standard itself."
)

_SSM_STATEMENT = (
    "Measured separation was at least the separation distance computed from the "
    "envelope's figures using the formula in ssm.py, at every compared sample."
)


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
    #: How the limits table's review evidence was assessed; None when no table.
    limits_review: dict[str, Any] | None = None
    #: Why the trace's provenance is believed as far as it is: ``declared_by_filer``
    #: (never lifts the tier) or ``recorder_attested`` (a signed recorder attestation
    #: was accepted under the verifier's own trust list; see provenance_trust.py).
    provenance_basis: str = "declared_by_filer"
    provenance_assessment: dict[str, Any] | None = None
    #: How the supplied recorder attestations were assessed, with the attestations
    #: themselves, so a later verifier can re-assess them under its own trust list.
    recorder_attestation: dict[str, Any] | None = None
    #: The machine unit the verification is about, if known (checked against the
    #: attestation's machine reference). Empty: the product line.
    machine_serial: str = ""

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
            "provenance_basis": self.provenance_basis,
            "provenance_assessment": self.provenance_assessment,
            "recorder_attestation": self.recorder_attestation,
            "machine_serial": self.machine_serial,
            "verdict": self.verdict.value,
            "tier": self.tier.value,
            "may_claim_physical_behaviour": self.may_claim_physical_behaviour,
            "checks": [c.to_dict() for c in self.checks],
            "checks_skipped": list(self.checks_skipped),
            "verified_at": self.verified_at,
            "limits_review": self.limits_review,
        }

    def summary(self) -> str:
        lines = [
            f"{self.product} {self.product_version} — {self.verdict.value.upper()} "
            f"at tier {self.tier.value}",
            f"  trace {self.trace_id} ({self.provenance}, {self.provenance_basis}) "
            f"{self.trace_hash[:12]}",
            f"  envelope {self.envelope_hash[:12]}",
        ]
        for c in self.checks:
            mark = {"verified": "ok  ", "violated": "FAIL", "not_applicable": "n/a ",
                    "unchecked": "??  "}[c.outcome.value]
            if c.violations:
                # The margin of the samples that passed says nothing about how
                # badly the others failed; the figure that matters is the shortfall.
                margin = (f"  worst shortfall "
                          f"{max(v.exceedance for v in c.violations):.1f} {c.unit}")
            else:
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
        if self.provenance_basis == "declared_by_filer" and self.provenance != "simulation":
            lines.append(
                f"  The trace's provenance ({self.provenance!r}) is the filer's own "
                "declaration; no recorder attestation was accepted under a trust list "
                "this verifier holds, so it does not lift the tier above community."
            )
        elif self.provenance_basis == "recorder_attested":
            lines.append(
                "  A recorder attestation was accepted under this verifier's own trust "
                "list: a trusted key signed these exact trace bytes. That is not proof "
                "the recording is physically true, that the recorder was calibrated or "
                "uncompromised, or that the machine is safe."
            )
        return "\n".join(lines)


# -- the checks -----------------------------------------------------------


def _gap_reason(trace: Trace) -> str:
    first = trace.gaps[0]
    return (f"the recording has a gap (t={first[0]:.3f}s to t={first[1]:.3f}s, the "
            "first of several if more) beside a sample this check covers. 'Stayed "
            "within' cannot be established across an interval nobody recorded, so "
            "the samples that were compared are not enough for a verified result.")


def _across_gaps(
    result: CheckResult, trace: Trace, applies: Callable[[Any], bool],
) -> CheckResult:
    """A 'stayed within' result is not verified across a recording gap.

    The same rule for every such check: a gap beside a sample the check covers
    makes a would-be pass unchecked. A violation stands regardless (a shortfall
    seen is a shortfall), and is annotated rather than softened.
    """
    if result.outcome not in (CheckOutcome.VERIFIED, CheckOutcome.VIOLATED):
        return result
    if not trace.gap_touches(applies):
        return result
    note = _gap_reason(trace)
    if result.outcome is CheckOutcome.VIOLATED:
        return replace(result, reason=(result.reason + " " + note).strip())
    return replace(result, outcome=CheckOutcome.UNCHECKED, reason=note)


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
    return _across_gaps(CheckResult(
        name="workspace_containment",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="The tool centre point stayed inside the declared workspace.",
        samples_examined=len(trace.samples),
        violations=tuple(violations),
        worst_margin=worst,
        unit="mm",
    ), trace, lambda _s: True)


def _speed_limit(envelope: SafetyEnvelope, trace: Trace) -> CheckResult:
    violations: list[Violation] = []
    worst: float | None = None
    examined = 0
    skipped_by_mode: dict[str, int] = {}
    for i, s in enumerate(trace.samples):
        limit = envelope.speed_limit_for(s.mode)
        if limit is None:
            skipped_by_mode[s.mode.value] = skipped_by_mode.get(s.mode.value, 0) + 1
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
    skipped = sum(skipped_by_mode.values())
    not_evaluated = ""
    if skipped:
        not_evaluated = (
            f"{skipped} of {len(trace.samples)} samples were not evaluated because "
            "the envelope declares no speed limit for their mode: "
            + ", ".join(f"{m} ({n})" for m, n in skipped_by_mode.items()) + "."
        )
    if violations:
        outcome = CheckOutcome.VIOLATED
    elif skipped:
        # A limit the envelope does not declare for a mode that ran is a mode that
        # was never held to anything. "Verified" over the remainder would be a pass
        # from the samples that happened to have a limit.
        outcome = CheckOutcome.UNCHECKED
    else:
        outcome = CheckOutcome.VERIFIED
    result = CheckResult(
        name="speed_limit", outcome=outcome,
        statement="TCP speed stayed within the declared limit for the mode in force.",
        samples_examined=examined, violations=tuple(violations),
        worst_margin=worst, unit="mm/s", reason=not_evaluated,
    )
    return _across_gaps(result, trace, lambda _s: True)


def _ssm_separation(envelope: SafetyEnvelope, trace: Trace) -> tuple[CheckResult, list[str]]:
    """The check that is the whole reason this package exists."""
    caveats: list[str] = []
    violations: list[Violation] = []
    worst: float | None = None
    examined = 0
    no_separation_reported = 0
    extrapolated = 0
    declared_speed_used = 0
    default_speed_used = 0

    relevant = [(i, s) for i, s in enumerate(trace.samples)
                if s.mode.separation_is_the_control]
    if not relevant:
        return CheckResult(
            name="ssm_separation", outcome=CheckOutcome.NOT_APPLICABLE,
            statement=_SSM_STATEMENT, samples_examined=0, unit="mm",
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
        if breakdown.human_speed_source == "declared":
            declared_speed_used += 1
        elif breakdown.human_speed_source == "default":
            default_speed_used += 1
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

    missing = ""
    if no_separation_reported:
        missing = (
            f"{no_separation_reported} of {len(relevant)} samples in a "
            "separation-controlled mode have no separation measurement. A missing "
            "measurement is not 'nobody there': it is equally a dead or occluded "
            "sensor or a column that was not recorded, and this trace schema has no "
            "explicit 'no person present' value. Those samples were not compared."
        )
        caveats.append(missing)
    if extrapolated:
        caveats.append(
            f"{extrapolated} samples ran at a speed above the one the stopping "
            f"distance was measured at ({envelope.stop.measured_at_speed_mm_s:.0f} "
            "mm/s). Ss for those samples is a constant-deceleration model, not a "
            "measurement."
        )
    if declared_speed_used:
        caveats.append(
            f"{declared_speed_used} of {examined} compared samples used the envelope's "
            f"declared approach speed ({envelope.approach_speed_mm_s:.0f} mm/s) "
            "as the person's closing speed, because the trace recorded none. That is "
            "an assumption, not a measurement, and the envelope carries no evidence "
            "basis for it."
        )
    if default_speed_used:
        caveats.append(
            f"{default_speed_used} of {examined} compared samples used the package "
            f"DEFAULT approach speed ({envelope.approach_speed_mm_s:.0f} mm/s) as the "
            "person's closing speed: the envelope declares none and the trace "
            "recorded none. The default was adopted, not declared by anyone, and is "
            "quoted from memory of the standard (see ssm.py)."
        )

    if violations:
        # A shortfall stands whatever else was missing.
        return CheckResult(
            name="ssm_separation", outcome=CheckOutcome.VIOLATED,
            statement=_SSM_STATEMENT, samples_examined=examined,
            violations=tuple(violations), worst_margin=worst, unit="mm",
            reason=missing,
        ), caveats

    if no_separation_reported:
        return CheckResult(
            name="ssm_separation", outcome=CheckOutcome.UNCHECKED,
            statement=_SSM_STATEMENT, samples_examined=examined, worst_margin=worst,
            unit="mm", reason=missing,
        ), caveats

    result = CheckResult(
        name="ssm_separation", outcome=CheckOutcome.VERIFIED,
        statement=_SSM_STATEMENT, samples_examined=examined, worst_margin=worst,
        unit="mm",
    )
    return _across_gaps(
        result, trace, lambda s: s.mode.separation_is_the_control), caveats


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
    return _across_gaps(CheckResult(
        name="stop_characterisation",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="The machine never relied on a stopping distance outside the speed "
                  "range it was measured over.",
        samples_examined=len(relevant), violations=tuple(violations),
        worst_margin=min(margins) if margins else None, unit="mm/s",
    ), trace, lambda s: s.mode.separation_is_the_control)


def _pfl_contact(
    envelope: SafetyEnvelope, trace: Trace, limits: LimitsTable | None,
) -> tuple[CheckResult, list[str]]:
    """Contact within limits where permitted — and contact where it is not.

    A nonzero force recorded in a mode that does not permit contact is not
    evaluated against any limit (the table is about permitted contact), and it is
    not nothing: the check cannot read as verified or not applicable beside it.
    """
    result, caveats = _pfl_contact_permitted(envelope, trace, limits)
    stray = [(i, s) for i, s in enumerate(trace.samples)
             if not s.mode.contact_is_permitted
             and s.contact_force is not None and s.contact_force > 0]
    if not stray:
        return result, caveats
    i0, s0 = stray[0]
    note = (f"{len(stray)} sample(s) recorded a nonzero contact force in a mode that "
            f"does not permit contact (first: t={s0.t:.3f}s, {s0.contact_force:.1f} N, "
            f"{s0.mode.value}). Those samples were not evaluated against any limit.")
    caveats.append(note)
    if result.outcome in (CheckOutcome.VERIFIED, CheckOutcome.NOT_APPLICABLE):
        result = CheckResult(
            name=result.name, outcome=CheckOutcome.UNCHECKED,
            statement=result.statement, samples_examined=result.samples_examined,
            violations=result.violations, worst_margin=result.worst_margin,
            unit=result.unit, reason=note,
        )
    return result, caveats


def _pfl_contact_permitted(
    envelope: SafetyEnvelope, trace: Trace, limits: LimitsTable | None,
) -> tuple[CheckResult, list[str]]:
    caveats: list[str] = []
    statement = ("Contact force and pressure stayed within the declared body-region "
                 "limits wherever contact was permitted.")
    in_mode = [(i, s) for i, s in enumerate(trace.samples)
               if s.mode.contact_is_permitted]
    contacts = [(i, s) for i, s in in_mode if s.contact_force is not None]
    # A force that was not recorded in a mode where contact is permitted is not
    # "no force". It is a sensor that is absent, off or unlogged, and a sample
    # dropped here would let 99 unmeasured samples ride on one measured one.
    no_force = len(in_mode) - len(contacts)
    missing = (f"{no_force} of {len(in_mode)} samples in a contact-permitting mode "
               "recorded no contact force, so they were not checked. A missing force "
               "is not a zero force." if no_force else "")

    if not envelope.claims_pfl and not in_mode:
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
                   "limits table was supplied. Contact forces were NOT checked. "
                   + missing,
        ), caveats

    if not envelope.pfl_limits_hash:
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=0, unit="N",
            reason=f"the envelope pins no limits table (pfl_limits_hash is empty), so "
                   f"the supplied table ({limits.content_hash()[:12]}) is whatever the "
                   "caller chose. Contact checked against an unpinned table proves "
                   "nothing about the declared product; the envelope must pin the "
                   "table's hash. " + missing,
        ), caveats

    if limits.content_hash() != envelope.pfl_limits_hash:
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=0, unit="N",
            reason=f"the supplied limits table ({limits.content_hash()[:12]}) is not "
                   f"the one the envelope was declared against "
                   f"({envelope.pfl_limits_hash[:12]}). Checking against a different "
                   "table would prove nothing about the declared product.",
        ), caveats

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
            reason=("no contact sample could be matched to a region in the limits "
                    "table. " + missing).strip(),
        ), caveats

    # A violation stands whatever else went unevaluated. Without one, a pass needs
    # every contact sample evaluated against both force and pressure: a sample with
    # no area, or in a region the table lacks, was not checked, and "verified"
    # beside a caveat saying so is a pass from missing data.
    if not violations and (unknown_regions or without_area or no_force):
        gaps = []
        if no_force:
            gaps.append(missing.rstrip("."))
        if without_area:
            gaps.append(f"{without_area} contact sample(s) recorded a force with no "
                        "contact area, so their pressure was not checked")
        if unknown_regions:
            gaps.append("contact credited to body region(s) "
                        + ", ".join(sorted(unknown_regions))
                        + " was not checked: the limits table does not cover them")
        return CheckResult(
            name="pfl_contact", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=examined, worst_margin=worst,
            unit="N", reason="; ".join(gaps) + ". Every contact sample must be "
                             "evaluated for this check to be verified.",
        ), caveats

    return _across_gaps(CheckResult(
        name="pfl_contact",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement=statement, samples_examined=examined,
        violations=tuple(violations), worst_margin=worst, unit="N",
        reason=missing,
    ), trace, lambda s: s.mode.contact_is_permitted), caveats


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
    return _across_gaps(CheckResult(
        name="mode_consistency",
        outcome=CheckOutcome.VIOLATED if violations else CheckOutcome.VERIFIED,
        statement="No person was detected while the cell was in unrestricted "
                  "automatic mode.",
        samples_examined=len(trace.samples), violations=tuple(violations), unit="mm",
    ), trace, lambda _s: True)


def _figure_instant(figure_date: str) -> datetime | None:
    """A figure's date as a UTC instant, or None if undated or unreadable."""
    if not figure_date:
        return None
    try:
        if "T" in figure_date or " " in figure_date:
            when = datetime.fromisoformat(figure_date.replace("Z", "+00:00"))
            return when if when.tzinfo else when.replace(tzinfo=UTC)
        d = date.fromisoformat(figure_date)
    except ValueError:
        return None
    return datetime(d.year, d.month, d.day, tzinfo=UTC)


def _trace_coverage(envelope: SafetyEnvelope, trace: Trace) -> CheckResult:
    """Is this a run, and did it exercise anything the envelope is about?

    "Not applicable" on every safety regime is the absence of a test, not a
    passed one. A trace that only ever ran in automatic mode, or that is one
    sample long, has proved the workspace and speed checks over a moment and
    nothing about separation or contact. That reads as UNCHECKED, with the reason.
    """
    statement = (
        f"The trace meets a sanity floor of {MIN_TRACE_SAMPLES} samples spanning at "
        f"least {MIN_TRACE_DURATION_S:g} s (a sanity floor, not a standard) and "
        "exercised at least one safety regime: speed and separation monitoring, power "
        "and force limiting, or an envelope that claims power and force limiting."
    )
    problems: list[str] = []
    n = len(trace.samples)
    if n < MIN_TRACE_SAMPLES:
        problems.append(f"the trace has {n} sample(s), below the floor of "
                        f"{MIN_TRACE_SAMPLES}")
    if trace.duration_s < MIN_TRACE_DURATION_S:
        problems.append(f"the trace spans {trace.duration_s:.4g} s, below the floor of "
                        f"{MIN_TRACE_DURATION_S:g} s")
    exercised = envelope.claims_pfl or any(
        s.mode.separation_is_the_control
        or s.mode is OperatingMode.PFL
        or (s.mode.contact_is_permitted and s.contact_force is not None)
        for s in trace.samples
    )
    if not exercised:
        problems.append(
            "no safety regime was exercised: the trace contains no speed-and-"
            "separation-monitoring or power-and-force-limiting samples and the "
            "envelope claims none, so ssm_separation, stop_characterisation and "
            "pfl_contact are all not applicable and a run of only automatic, "
            "stopped or reduced-speed samples establishes nothing about them"
        )
    if problems:
        return CheckResult(
            name="trace_coverage", outcome=CheckOutcome.UNCHECKED,
            statement=statement, samples_examined=n,
            reason="; ".join(problems) + ".",
        )
    return CheckResult(
        name="trace_coverage", outcome=CheckOutcome.VERIFIED,
        statement=statement, samples_examined=n,
    )


def _input_dates(
    envelope: SafetyEnvelope, trace: Trace, moment: datetime,
) -> CheckResult:
    """No input may be dated after the day it is being verified.

    A run that "started" in 2099 or a stopping distance "measured" in 2099 was
    not measured: the date is wrong, and so is whatever else the file says. The
    same rule the lifecycle code applies (``machinery/staleness``) to a trace
    that claims to start after its own filing. Depends on the clock, by design:
    "the future" has no meaning without one.
    """
    horizon = moment + _FUTURE_TOLERANCE
    future: list[str] = []
    if trace.started_at > horizon:
        future.append(f"the trace's started_at ({trace.started_at.isoformat()})")
    for label, figure in (("stopping", envelope.stop.basis),
                          ("sensing", envelope.uncertainty.basis)):
        when = _figure_instant(figure.date)
        if when is not None and when > horizon:
            future.append(f"the {label} figure's date ({figure.date})")
    statement = ("No input is dated after the moment of verification (a one-day "
                 "clock tolerance is allowed).")
    if future:
        return CheckResult(
            name="input_dates", outcome=CheckOutcome.UNCHECKED, statement=statement,
            reason=f"{'; '.join(future)} is in the future relative to "
                   f"{moment.isoformat()}. A date that has not happened cannot be the "
                   "date anything was recorded or measured, so this result is "
                   "suspect and may not be validated.",
        )
    return CheckResult(name="input_dates", outcome=CheckOutcome.VERIFIED,
                       statement=statement)


def _age_of(figure_date: str, trace: Trace) -> str:
    """How old a figure was on the day the trace began, in words. Deterministic."""
    if not figure_date:
        return "is undated"
    when = _figure_instant(figure_date)
    if when is None:
        return f"has an unreadable date {figure_date!r}"
    d = when.date()
    days = (trace.started_at.date() - d).days
    if days < 0:
        return (f"is dated {figure_date}, {-days} day(s) AFTER the trace began")
    return f"is dated {figure_date}, {days} day(s) before the trace began"


# -- the entry point ------------------------------------------------------


def verify(
    envelope: SafetyEnvelope,
    trace: Trace,
    *,
    limits: LimitsTable | None = None,
    limits_reviews: Sequence[Any] = (),
    review_trust: ReviewTrust | None = None,
    recorder_attestations: Sequence[Any] = (),
    recorder_trust: RecorderTrust | None = None,
    machine_serial: str = "",
    now: datetime | None = None,
) -> VerificationResult:
    """Check one run against one envelope.

    ``limits_reviews`` are signed reviews of the limits table and ``review_trust``
    the verifier's own list of reviewer keys. Only an accepted review can lift the
    limits tier to validated; the table's own verified_by text never does.

    ``recorder_attestations`` are signed attestations of the trace and ``recorder_trust``
    the verifier's own list of recorder keys. Only an accepted attestation lets the
    trace's declared provenance reach its own ceiling; with no trust list nothing can
    be accepted. ``machine_serial`` names the unit this verification is about, if known.

    ``now`` is the moment of verification, used only to judge whether an input is
    dated in the future; it defaults to the clock.

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
    review: LimitsReviewAssessment | None = None
    if limits is not None:
        review = assess_reviews(limits, limits_reviews, review_trust, now=now)
        if envelope.pfl_limits_hash == limits.content_hash():
            caveats.append(limits.provenance_caveat(review))
    checks.append(_mode_consistency(envelope, trace))
    checks.append(_trace_coverage(envelope, trace))
    dates = _input_dates(envelope, trace, now if now is not None else utc_now())
    checks.append(dates)

    # The tier is the floor of every input the verdict depends on.
    prov = provenance_trust.assess_provenance(
        trace, recorder_attestations, recorder_trust,
        machine_ref=MachineRef(envelope.product, envelope.product_version, machine_serial),
        now=now)
    tier = min(prov.ceiling, envelope.tier_ceiling)
    caveats.append(f"provenance_basis {prov.basis.value}: {prov.explanation}")
    if limits is not None and pfl.outcome is CheckOutcome.VERIFIED:
        limits_tier, limits_reason = limits.tier_for(envelope.pfl_limits_hash, review)
        tier = min(tier, limits_tier)
        caveats.append(limits_reason)
    if dates.outcome is CheckOutcome.UNCHECKED:
        tier = min(tier, AssuranceTier.COMMUNITY)

    stop_basis = envelope.stop.basis
    caveats.append(
        f"stopping performance is a {stop_basis.kind} figure "
        f"({stop_basis.reference}); reaction time "
        f"{envelope.stop.reaction_time_s:.3f} s and stop time "
        f"{envelope.stop.stop_time_s:.3f} s were taken from the envelope and not "
        "re-measured from this trace."
    )
    caveats.append(
        "age of the figures this verdict rests on, against the day the trace began: "
        f"stopping {_age_of(stop_basis.date, trace)}; sensing "
        f"{_age_of(envelope.uncertainty.basis.date, trace)}. No maximum age is applied: "
        "a stopping distance measured years ago on a machine since modified passes "
        "exactly as a fresh one does, and whether it still describes the machine is "
        "the manufacturer's call."
    )
    if envelope.uncertainty.has_zero_figure:
        caveats.append(
            "the envelope declares a zero position uncertainty (Zd or Zr). A zero is "
            "a claim of perfect sensing, not a measurement, so the sensing figure is "
            "capped at the profile tier whatever basis it names."
        )
    if trace.provenance.value == "simulation":
        caveats.append(
            "the trace is simulated. Nothing here is evidence about the physical "
            "machine, only about the model that produced these samples."
        )
    if trace.rate_disagrees_with_data:
        observed = trace.observed_period_s or 0.0
        caveats.append(
            f"the trace declares a sample rate of {trace.sample_rate_hz:g} Hz but its "
            f"samples are a median {observed:.4g} s apart "
            f"(about {1.0 / observed if observed else float('inf'):.4g} Hz). The "
            "declared rate decides what counts as a gap, so gaps were measured against "
            "the shorter of the two periods; correct the declaration."
        )
    if trace.gaps:
        caveats.append(
            f"the trace has {len(trace.gaps)} gap(s) longer than two sample periods, "
            f"the first at t={trace.gaps[0][0]:.3f}s. Nothing is known about what the "
            "machine did inside a gap."
        )
    caveats.append(
        f"trace_coverage: a trace shorter than {MIN_TRACE_SAMPLES} samples or "
        f"{MIN_TRACE_DURATION_S:g} s is not accepted as a verification. That is a "
        "sanity floor chosen by this package, not a figure from any standard; a run "
        "above it is not thereby long enough for any particular claim."
    )
    caveats.append(FORMULA_LIMITATION)
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
        limits_review=review.to_dict() if review is not None else None,
        provenance_basis=prov.basis.value,
        provenance_assessment=prov.to_dict(),
        recorder_attestation=prov.attestation.to_dict() if prov.attestation else None,
        machine_serial=machine_serial,
    )

