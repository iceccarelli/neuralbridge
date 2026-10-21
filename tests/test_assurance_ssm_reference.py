"""The protective separation distance, checked against an independent calculation.

The reference below is written from the *published structure* of the formula
(ISO/TS 15066 speed and separation monitoring):

    Sp = Sh + Sr + Ss + C + Zd + Zr
    Sh = v_h * (T_r + T_s)        the person keeps moving through reaction AND stop
    Sr = v_r * T_r                the machine keeps moving while it is still noticing
    Ss = stopping travel          valid at, and only at, the speed it was measured

It deliberately works in SI (metres, seconds) and converts at the end, which is
a different path through the arithmetic from the implementation's millimetres.
It never imports the implementation's formula.

What the standard text says is NOT verifiable from this repository (the standard
is licensed and not present). These tests therefore establish that the code is
internally consistent with the formula structure its own docstrings state; they
do not establish that the structure is the standard's. That remains UNVERIFIED.
"""

from __future__ import annotations

import itertools
import math
import random
from datetime import UTC, datetime

import pytest

from assurance.core.tiers import AssuranceTier
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.ssm import separation_required
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import CheckOutcome, Verdict, verify

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
DATASHEET = FigureBasis(kind="datasheet", reference="scanner rev D")
ESTIMATED = FigureBasis(kind="estimated", reference="calc note 7")


def env(*, tr=0.1, ts=0.25, ss=120.0, vm=500.0, c=850.0, zd=100.0, zr=50.0,
        vh=1600.0, stop_basis=MEASURED, unc_basis=MEASURED):
    return SafetyEnvelope(
        envelope_id="E", product="Cell", product_version="1",
        workspace=Workspace(minimum=(-1000.0, -1000.0, 0.0),
                            maximum=(1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 5000.0},
        stop=StopPerformance(reaction_time_s=tr, stop_time_s=ts, stop_distance_mm=ss,
                             measured_at_speed_mm_s=vm, basis=stop_basis),
        uncertainty=SensingUncertainty(human_position_mm=zd, robot_position_mm=zr,
                                       basis=unc_basis),
        intrusion_distance_mm=c, human_approach_speed_mm_s=vh,
    )


def reference_mm(*, vh_mm_s, vr_mm_s, tr_s, ts_s, ss_mm, vm_mm_s, c_mm, zd_mm, zr_mm):
    """Sp in millimetres, computed in SI from the formula's published structure."""
    vh, vr, vm = vh_mm_s / 1000.0, vr_mm_s / 1000.0, vm_mm_s / 1000.0   # m/s
    sh = vh * (tr_s + ts_s)                                            # m
    sr = vr * tr_s                                                     # m
    ss_m = ss_mm / 1000.0
    ss = ss_m if vr <= vm else ss_m * (vr / vm) ** 2                   # m
    return (sh + sr + ss + c_mm / 1000.0 + zd_mm / 1000.0 + zr_mm / 1000.0) * 1000.0


# -- agreement with the independent calculation ----------------------------

GRID = list(itertools.product(
    (0.0, 0.05, 0.1, 0.5),           # Tr
    (0.0, 0.25, 1.0),                # Ts
    (0.0, 120.0, 900.0),             # Ss at vm
    (250.0, 500.0, 1500.0),          # vm
    (0.0, 300.0, 750.0, 2500.0),     # vr
    (800.0, 1600.0, 2000.0),         # vh
))


class TestAgreesWithTheReference:
    @pytest.mark.parametrize("tr,ts,ss,vm,vr,vh", GRID)
    def test_the_total_matches_an_independent_si_calculation(self, tr, ts, ss, vm, vr, vh):
        e = env(tr=tr, ts=ts, ss=ss, vm=vm, vh=vh)
        got = separation_required(e, robot_speed_mm_s=vr).total_mm
        want = reference_mm(vh_mm_s=vh, vr_mm_s=vr, tr_s=tr, ts_s=ts, ss_mm=ss,
                            vm_mm_s=vm, c_mm=850.0, zd_mm=100.0, zr_mm=50.0)
        assert got == pytest.approx(want, rel=1e-12, abs=1e-9)

    def test_the_documented_example_is_1905_mm(self):
        """deploy/assurance/MACHINE.md prints this breakdown for ``--speed 750``."""
        b = separation_required(env(), robot_speed_mm_s=750.0)
        assert round(b.human_travel_mm) == 560
        assert round(b.robot_reaction_travel_mm) == 75
        assert round(b.robot_stopping_travel_mm) == 270
        assert round(b.total_mm) == 1905
        assert b.total_mm == pytest.approx(reference_mm(
            vh_mm_s=1600.0, vr_mm_s=750.0, tr_s=0.1, ts_s=0.25, ss_mm=120.0,
            vm_mm_s=500.0, c_mm=850.0, zd_mm=100.0, zr_mm=50.0), rel=1e-12)

    def test_each_term_is_the_one_the_formula_names(self):
        e = env(tr=0.2, ts=0.3, ss=77.0, vm=400.0, c=611.0, zd=13.0, zr=7.0, vh=1234.0)
        b = separation_required(e, robot_speed_mm_s=300.0)
        assert b.human_travel_mm == pytest.approx(1234.0 * (0.2 + 0.3))
        assert b.robot_reaction_travel_mm == pytest.approx(300.0 * 0.2)
        assert b.robot_stopping_travel_mm == pytest.approx(77.0)
        assert (b.intrusion_mm, b.human_uncertainty_mm, b.robot_uncertainty_mm) == (
            611.0, 13.0, 7.0)

    @pytest.mark.parametrize("tr", [0.05, 0.1, 0.5, 1.0])
    @pytest.mark.parametrize("vh", [1000.0, 1600.0, 2000.0])
    def test_leaving_out_the_reaction_time_is_short_by_exactly_vh_times_tr(self, tr, vh):
        """The 'classic' error: Sh over Ts alone. The shortfall is v_h * T_r — 160 mm
        at 0.1 s and 1600 mm/s, not 'roughly a metre' unless T_r is near 0.6 s."""
        e = env(tr=tr, ts=0.25, vh=vh)
        full = separation_required(e, robot_speed_mm_s=300.0).human_travel_mm
        ts_only = vh * 0.25
        assert full - ts_only == pytest.approx(vh * tr)

    def test_ss_below_the_measured_speed_is_the_measured_distance_unchanged(self):
        e = env(ss=120.0, vm=500.0)
        for v in (0.0, 1.0, 250.0, 499.999, 500.0):
            d, basis = e.stop.stop_distance_at(v)
            assert (d, basis) == (120.0, "measured")

    @pytest.mark.parametrize("ratio", [1.0001, 1.5, 2.0, 4.0])
    def test_ss_above_the_measured_speed_is_flagged_and_quadratic(self, ratio):
        e = env(ss=120.0, vm=500.0)
        b = separation_required(e, robot_speed_mm_s=500.0 * ratio)
        assert b.stopping_basis == "extrapolated_quadratic"
        assert b.rests_on_extrapolation
        assert b.robot_stopping_travel_mm == pytest.approx(120.0 * ratio ** 2)

    def test_ss_is_continuous_at_the_measured_speed(self):
        e = env(ss=120.0, vm=500.0)
        below = e.stop.stop_distance_at(500.0)[0]
        above = e.stop.stop_distance_at(math.nextafter(500.0, math.inf))[0]
        assert above == pytest.approx(below, rel=1e-12)


# -- invariances -----------------------------------------------------------

class TestUnitRescaling:
    """The package has no unit conversion. What must hold is that its arithmetic
    is dimensionally consistent: rescaling a unit rescales the answer exactly."""

    @pytest.mark.parametrize("k", [0.001, 0.1, 25.4, 100.0])
    def test_changing_the_length_unit_scales_the_total_by_the_same_factor(self, k):
        base = env()
        scaled = env(ss=120.0 * k, vm=500.0 * k, c=850.0 * k, zd=100.0 * k,
                     zr=50.0 * k, vh=1600.0 * k)
        a = separation_required(base, robot_speed_mm_s=750.0)
        b = separation_required(scaled, robot_speed_mm_s=750.0 * k)
        assert b.total_mm == pytest.approx(a.total_mm * k, rel=1e-12)

    @pytest.mark.parametrize("mu", [0.01, 0.5, 2.0, 60.0])
    def test_changing_the_time_unit_leaves_the_total_unchanged(self, mu):
        """Times in a unit mu times as large, speeds mu times smaller."""
        base = env()
        rescaled = env(tr=0.1 * mu, ts=0.25 * mu, vm=500.0 / mu, vh=1600.0 / mu)
        a = separation_required(base, robot_speed_mm_s=750.0)
        b = separation_required(rescaled, robot_speed_mm_s=750.0 / mu)
        assert b.total_mm == pytest.approx(a.total_mm, rel=1e-12)

    def test_a_millimetre_figure_given_in_metres_is_not_equivalent(self):
        """A metre value in a millimetre field is a different (and short) number."""
        right = separation_required(env(c=850.0), robot_speed_mm_s=300.0).total_mm
        wrong = separation_required(env(c=0.85), robot_speed_mm_s=300.0).total_mm
        assert right - wrong == pytest.approx(850.0 - 0.85)


# -- monotonicity ----------------------------------------------------------

BASE = {"tr": 0.1, "ts": 0.25, "ss": 120.0, "vm": 500.0, "c": 850.0, "zd": 100.0,
        "zr": 50.0, "vh": 1600.0}


def total(vr=300.0, hs=None, **over):
    kw = {**BASE, **over}
    return separation_required(env(**kw), robot_speed_mm_s=vr,
                               human_speed_mm_s=hs).total_mm


class TestMonotonicity:
    @pytest.mark.parametrize("field,values", [
        ("tr", [0.0, 0.05, 0.1, 0.3, 1.0]),
        ("ts", [0.0, 0.1, 0.25, 0.5, 2.0]),
        ("ss", [0.0, 50.0, 120.0, 500.0]),
        ("c", [0.0, 100.0, 850.0, 2000.0]),
        ("zd", [0.0, 10.0, 100.0, 400.0]),
        ("zr", [0.0, 10.0, 50.0, 400.0]),
        ("vh", [100.0, 800.0, 1600.0, 2000.0]),
    ])
    def test_a_larger_figure_never_shortens_the_required_separation(self, field, values):
        for speed in (0.0, 300.0, 500.0, 900.0):
            seq = [total(vr=speed, **{field: v}) for v in values]
            assert seq == sorted(seq), (field, speed, seq)

    def test_a_faster_robot_never_shortens_it(self):
        speeds = [0.0, 100.0, 250.0, 499.0, 500.0, 501.0, 750.0, 2000.0]
        seq = [total(vr=v) for v in speeds]
        assert seq == sorted(seq)

    def test_a_faster_sensed_human_never_shortens_it(self):
        seq = [total(hs=v) for v in (0.0, 500.0, 1600.0, 2500.0)]
        assert seq == sorted(seq)

    def test_a_less_capable_stop_characterisation_never_shortens_it(self):
        """Lowering the speed the stop distance was measured at can only raise Ss."""
        for speed in (200.0, 500.0, 900.0):
            seq = [total(vr=speed, vm=vm) for vm in (2000.0, 1000.0, 500.0, 250.0, 100.0)]
            assert seq == sorted(seq), (speed, seq)

    def test_randomised_perturbations_never_decrease_it(self):
        rng = random.Random(15066)      # fixed seed: the same cases every run
        names = ["tr", "ts", "ss", "c", "zd", "zr", "vh"]
        for _ in range(500):
            kw = {"tr": rng.uniform(0, 1), "ts": rng.uniform(0, 2),
                  "ss": rng.uniform(0, 800), "vm": rng.uniform(50, 2000),
                  "c": rng.uniform(0, 1500), "zd": rng.uniform(0, 300),
                  "zr": rng.uniform(0, 300), "vh": rng.uniform(100, 2500)}
            vr = rng.uniform(0, 3000)
            before = separation_required(env(**kw), robot_speed_mm_s=vr).total_mm
            name = rng.choice(names)
            bumped = {**kw, name: kw[name] * rng.uniform(1.0, 3.0) + rng.uniform(0, 1)}
            after = separation_required(env(**bumped), robot_speed_mm_s=vr).total_mm
            assert after >= before, (name, kw, vr)
            faster = separation_required(env(**kw), robot_speed_mm_s=vr * 1.5 + 1).total_mm
            assert faster >= before

    def test_randomised_agreement_with_the_reference(self):
        rng = random.Random(1305)
        for _ in range(500):
            kw = {"tr": rng.uniform(0, 1), "ts": rng.uniform(0, 2),
                  "ss": rng.uniform(0, 800), "vm": rng.uniform(50, 2000),
                  "c": rng.uniform(0, 1500), "zd": rng.uniform(0, 300),
                  "zr": rng.uniform(0, 300), "vh": rng.uniform(100, 2500)}
            vr = rng.uniform(0, 3000)
            got = separation_required(env(**kw), robot_speed_mm_s=vr).total_mm
            want = reference_mm(vh_mm_s=kw["vh"], vr_mm_s=vr, tr_s=kw["tr"],
                                ts_s=kw["ts"], ss_mm=kw["ss"], vm_mm_s=kw["vm"],
                                c_mm=kw["c"], zd_mm=kw["zd"], zr_mm=kw["zr"])
            assert got == pytest.approx(want, rel=1e-10, abs=1e-8)


# -- the boundary ----------------------------------------------------------

def one_sample_run(envelope, separation, speed=300.0, n=3):
    samples = tuple(
        Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=speed,
               mode=OperatingMode.SSM, separation=separation)
        for i in range(n)
    )
    return Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                 started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=50.0,
                 samples=samples)


class TestTheBoundary:
    def test_separation_exactly_equal_to_required_is_verified_with_zero_margin(self):
        e = env()
        required = separation_required(e, robot_speed_mm_s=300.0).total_mm
        r = verify(e, one_sample_run(e, required))
        c = r.check("ssm_separation")
        assert c.outcome is CheckOutcome.VERIFIED
        assert c.worst_margin == 0.0

    def test_one_ulp_below_required_is_a_violation(self):
        e = env()
        required = separation_required(e, robot_speed_mm_s=300.0).total_mm
        r = verify(e, one_sample_run(e, math.nextafter(required, 0.0)))
        c = r.check("ssm_separation")
        assert c.outcome is CheckOutcome.VIOLATED
        assert r.verdict is Verdict.FAIL
        assert c.violations[0].bound == required

    def test_one_ulp_above_required_is_verified(self):
        e = env()
        required = separation_required(e, robot_speed_mm_s=300.0).total_mm
        r = verify(e, one_sample_run(e, math.nextafter(required, math.inf)))
        assert r.check("ssm_separation").outcome is CheckOutcome.VERIFIED

    def test_the_speed_limit_boundary_is_inclusive_on_both_sides(self):
        e = env()
        e = SafetyEnvelope.from_dict({**e.to_dict(),
                                      "max_tcp_speed_mm_s": {"ssm": 300.0}})
        sep = 1.0e5
        at = verify(e, one_sample_run(e, sep, speed=300.0))
        over = verify(e, one_sample_run(e, sep, speed=math.nextafter(300.0, math.inf)))
        assert at.check("speed_limit").outcome is CheckOutcome.VERIFIED
        assert over.check("speed_limit").outcome is CheckOutcome.VIOLATED

    def test_running_above_the_stop_characterisation_speed_fails_even_with_ample_room(self):
        e = env()
        r = verify(e, one_sample_run(e, 1.0e6, speed=math.nextafter(500.0, math.inf)))
        assert r.check("stop_characterisation").outcome is CheckOutcome.VIOLATED
        assert r.verdict is Verdict.FAIL
        assert any("constant-deceleration" in c for c in r.checks_skipped)

    def test_at_the_stop_characterisation_speed_it_is_verified(self):
        e = env()
        r = verify(e, one_sample_run(e, 1.0e6, speed=500.0))
        assert r.check("stop_characterisation").outcome is CheckOutcome.VERIFIED


# -- the tier is the floor of every input ----------------------------------

CEILING = {"measured": AssuranceTier.VALIDATED, "datasheet": AssuranceTier.PROFILE,
           "estimated": AssuranceTier.PROFILE}
BASIS = {"measured": MEASURED, "datasheet": DATASHEET, "estimated": ESTIMATED}
PROV_CEILING = {Provenance.SIMULATION: AssuranceTier.COMMUNITY,
                Provenance.BENCH: AssuranceTier.VALIDATED,
                Provenance.FIELD: AssuranceTier.VALIDATED}


def weakest(*tiers):
    order = [AssuranceTier.PROFILE, AssuranceTier.COMMUNITY, AssuranceTier.VALIDATED,
             AssuranceTier.CERTIFIED]
    return min(tiers, key=order.index)


class TestWeakestInputDecidesTheTier:
    @pytest.mark.parametrize("stop_kind", sorted(CEILING))
    @pytest.mark.parametrize("unc_kind", sorted(CEILING))
    @pytest.mark.parametrize("prov", list(Provenance))
    def test_tier_is_the_minimum_of_stop_basis_sensing_basis_and_provenance(
            self, stop_kind, unc_kind, prov):
        e = env(stop_basis=BASIS[stop_kind], unc_basis=BASIS[unc_kind])
        run = one_sample_run(e, 1.0e5)
        run = Trace(trace_id="R", provenance=prov, source_system="s",
                    started_at=run.started_at, sample_rate_hz=50.0, samples=run.samples)
        want = weakest(CEILING[stop_kind], CEILING[unc_kind], PROV_CEILING[prov])
        assert verify(e, run).tier is want

    @pytest.mark.parametrize("stop_kind", sorted(CEILING))
    @pytest.mark.parametrize("unc_kind", sorted(CEILING))
    def test_only_measured_inputs_on_a_physical_trace_reach_validated(
            self, stop_kind, unc_kind):
        e = env(stop_basis=BASIS[stop_kind], unc_basis=BASIS[unc_kind])
        r = verify(e, one_sample_run(e, 1.0e5))
        reaches = r.tier is AssuranceTier.VALIDATED
        assert reaches == (stop_kind == "measured" and unc_kind == "measured")
        assert r.may_claim_physical_behaviour == reaches

    def test_certified_is_never_reachable_from_files(self):
        for stop_kind, unc_kind, prov in itertools.product(CEILING, CEILING, Provenance):
            e = env(stop_basis=BASIS[stop_kind], unc_basis=BASIS[unc_kind])
            run = one_sample_run(e, 1.0e5)
            run = Trace(trace_id="R", provenance=prov, source_system="s",
                        started_at=run.started_at, sample_rate_hz=50.0,
                        samples=run.samples)
            assert verify(e, run).tier is not AssuranceTier.CERTIFIED

    def test_nothing_in_the_trace_can_raise_the_tier(self):
        """A simulated trace whose free-form fields claim to be a certified field
        run is still a simulation."""
        e = env()
        run = one_sample_run(e, 1.0e5)
        liar = Trace(
            trace_id="CERTIFIED-FIELD-VALIDATED", provenance=Provenance.SIMULATION,
            source_system="field controller, validated, tier=certified",
            started_at=run.started_at, sample_rate_hz=50.0, samples=run.samples,
            conditions={"tier": "certified", "provenance": "field",
                        "may_claim_physical_behaviour": True, "validated": True},
        )
        r = verify(e, liar)
        assert r.tier is AssuranceTier.COMMUNITY
        assert not r.may_claim_physical_behaviour

    def test_nothing_in_the_envelope_notes_can_raise_the_tier(self):
        e = SafetyEnvelope.from_dict({**env(stop_basis=DATASHEET).to_dict(),
                                      "notes": "tier=validated; measured on site"})
        assert verify(e, one_sample_run(e, 1.0e5)).tier is AssuranceTier.PROFILE

    def _pfl_case(self, verified):
        table = LimitsTable(
            edition="Example 2016", transcribed_by="a",
            verified_by="b" if verified else "", verified_on="2026-04-01" if verified else "",
            transient_multiplier=2.0,
            regions={"hand": BodyRegionLimit("hand", "Hand", 260.0, 140.0)})
        e = SafetyEnvelope.from_dict({**env().to_dict(),
                                      "max_tcp_speed_mm_s": {"ssm": 5000.0, "pfl": 250.0},
                                      "pfl_limits_hash": table.content_hash()})
        samples = (
            Sample(t=0.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=100.0, mode=OperatingMode.PFL,
                   contact_force=50.0, contact_area=2.0, body_region="hand"),
            Sample(t=0.02, tcp=(0.0, 0.0, 1000.0), tcp_speed=100.0,
                   mode=OperatingMode.PFL, contact_force=50.0, contact_area=2.0,
                   body_region="hand"),
        )
        run = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                    started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=50.0,
                    samples=samples)
        return e, run, table

    def test_a_verified_limits_table_does_not_lower_the_tier(self):
        e, run, table = self._pfl_case(verified=True)
        r = verify(e, run, limits=table)
        assert r.check("pfl_contact").outcome is CheckOutcome.VERIFIED
        assert r.tier is AssuranceTier.VALIDATED

    def test_an_unverified_limits_table_caps_a_pfl_pass_at_community(self):
        e, run, table = self._pfl_case(verified=False)
        r = verify(e, run, limits=table)
        assert r.check("pfl_contact").outcome is CheckOutcome.VERIFIED
        assert r.tier is AssuranceTier.COMMUNITY
        assert not r.may_claim_physical_behaviour


# -- verdict semantics -----------------------------------------------------

class TestPassIsEarned:
    def test_a_clean_complete_run_passes(self):
        e = env()
        run = one_sample_run(e, 1.0e5)
        r = verify(e, run)
        assert r.verdict is Verdict.PASS
        assert not r.unchecked and not r.violations

    def test_unchecked_propagates_to_incomplete(self):
        e = env()
        samples = tuple(
            Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                   mode=OperatingMode.SSM, separation=None) for i in range(3))
        run = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                    started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=50.0,
                    samples=samples)
        r = verify(e, run)
        assert r.check("ssm_separation").outcome is CheckOutcome.UNCHECKED
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_violation_outranks_an_unchecked_check(self):
        e = env()
        samples = (
            Sample(t=0.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=6000.0,
                   mode=OperatingMode.SSM, separation=None),
            Sample(t=0.02, tcp=(0.0, 0.0, 1000.0), tcp_speed=6000.0,
                   mode=OperatingMode.SSM, separation=None),
        )
        run = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                    started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=50.0,
                    samples=samples)
        r = verify(e, run)
        assert r.check("ssm_separation").outcome is CheckOutcome.UNCHECKED
        assert r.check("speed_limit").outcome is CheckOutcome.VIOLATED
        assert r.verdict is Verdict.FAIL

    def test_a_pass_is_possible_only_when_every_check_is_verified_or_not_applicable(self):
        e = env()
        r = verify(e, one_sample_run(e, 1.0e5))
        assert r.verdict is Verdict.PASS
        assert all(c.outcome in (CheckOutcome.VERIFIED, CheckOutcome.NOT_APPLICABLE)
                   for c in r.checks)
