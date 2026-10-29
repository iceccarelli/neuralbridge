"""A pass must never come from coverage-incomplete data.

Each class reproduces one way an earlier engine (version 2) turned missing,
skipped, future-dated or zero data into PASS / validated. The shape of every test
is the same: build a trace that is honest in all but one respect, and require the
engine to say so rather than agree.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from assurance.core.tiers import AssuranceTier
from assurance.machine.envelope import (
    EnvelopeError,
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.ssm import separation_required
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import (
    ENGINE_VERSION,
    MIN_TRACE_DURATION_S,
    MIN_TRACE_SAMPLES,
    CheckOutcome,
    Verdict,
    verify,
)

from .support_recorder import verify_attested

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
FORMULA_LIMITATION = "formula and constants not verified against a licensed copy"


def limits(**over):
    kw = {
        "edition": "Example 2016", "transcribed_by": "a",
        "verified_by": "b", "verified_on": "2026-04-01", "transient_multiplier": 2.0,
        "regions": {"hand": BodyRegionLimit("hand", "Hand", 140.0, 140.0)},
    }
    kw.update(over)
    return LimitsTable(**kw)


def envelope(**over):
    kw = {
        "envelope_id": "ENV-1", "product": "Cell", "product_version": "1.0.0",
        "workspace": Workspace((-1000.0, -1000.0, 0.0), (1000.0, 1000.0, 2000.0)),
        "max_tcp_speed_mm_s": {OperatingMode.SSM: 500.0, OperatingMode.AUTOMATIC: 2000.0,
                               OperatingMode.PFL: 250.0},
        "stop": StopPerformance(0.1, 0.25, 120.0, 500.0, MEASURED),
        "uncertainty": SensingUncertainty(100.0, 50.0, MEASURED),
        "intrusion_distance_mm": 850.0,
        "human_approach_speed_mm_s": 1600.0,
    }
    kw.update(over)
    return SafetyEnvelope(**kw)


def sample(i, **over):
    kw = {"t": i / 50.0, "tcp": (0.0, 0.0, 1000.0), "tcp_speed": 300.0,
          "mode": OperatingMode.SSM, "separation": 3000.0}
    kw.update(over)
    return Sample(**kw)


def trace(samples, **over):
    kw = {"trace_id": "RUN-1", "provenance": Provenance.FIELD, "source_system": "fw",
          "started_at": datetime(2026, 9, 12, 4, 31, tzinfo=UTC), "sample_rate_hz": 50.0}
    kw.update(over)
    return Trace(samples=tuple(samples), **kw)


def good(n=40, **per_sample):
    return trace([sample(i, **per_sample) for i in range(n)])


def run(env, tr, **kw):
    return verify(env, tr, now=NOW, **kw)


def test_the_positive_control_an_honest_covered_trace_still_passes_at_validated():
    """With a recorder attestation the verifier accepts (a real signature and trust list)."""
    r = verify_attested(envelope(), good(), now=NOW)
    assert r.verdict is Verdict.PASS
    assert r.tier is AssuranceTier.VALIDATED
    assert all(c.outcome in (CheckOutcome.VERIFIED, CheckOutcome.NOT_APPLICABLE)
               for c in r.checks)


def test_the_engine_version_was_bumped_because_the_semantics_changed():
    assert ENGINE_VERSION == "6"
    assert run(envelope(), good()).engine_version == "6"


# -- (a) speed limit ------------------------------------------------------

class TestSpeedLimitCoverage:
    def test_samples_in_a_mode_with_no_declared_limit_make_the_check_unchecked(self):
        samples = [sample(0, mode=OperatingMode.AUTOMATIC, tcp_speed=100.0, separation=None)]
        samples += [sample(i, mode=OperatingMode.REDUCED_SPEED, tcp_speed=5000.0)
                    for i in range(1, 40)]
        r = run(envelope(), trace(samples))
        c = r.check("speed_limit")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "reduced_speed" in c.reason and "39" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_real_violation_still_reads_as_violated_and_names_the_unevaluated_modes(self):
        samples = [sample(i, mode=OperatingMode.SSM, tcp_speed=600.0) for i in range(20)]
        samples += [sample(i, mode=OperatingMode.REDUCED_SPEED) for i in range(20, 40)]
        c = run(envelope(), trace(samples)).check("speed_limit")
        assert c.outcome is CheckOutcome.VIOLATED
        assert "reduced_speed" in c.reason

    def test_every_mode_covered_is_verified(self):
        assert run(envelope(), good()).check("speed_limit").outcome is CheckOutcome.VERIFIED


# -- (b) ssm separation ---------------------------------------------------

class TestSeparationCoverage:
    def test_ninety_nine_missing_separations_are_not_a_pass(self):
        samples = [sample(0)] + [sample(i, separation=None) for i in range(1, 100)]
        r = run(envelope(), trace(samples))
        c = r.check("ssm_separation")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "99" in c.reason and "100" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_one_missing_separation_is_enough(self):
        samples = [sample(i) for i in range(39)] + [sample(39, separation=None)]
        c = run(envelope(), trace(samples)).check("ssm_separation")
        assert c.outcome is CheckOutcome.UNCHECKED

    def test_a_shortfall_elsewhere_still_reads_as_violated(self):
        samples = [sample(i) for i in range(38)] + [
            sample(38, separation=10.0), sample(39, separation=None)]
        c = run(envelope(), trace(samples)).check("ssm_separation")
        assert c.outcome is CheckOutcome.VIOLATED


# -- (c) pfl contact ------------------------------------------------------

def pfl_envelope(table, **over):
    return envelope(pfl_limits_hash=table.content_hash(), **over)


def pfl_samples(forces):
    out = []
    for i, f in enumerate(forces):
        out.append(sample(i, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=f, contact_area=20.0 if f is not None else None,
                          body_region="hand" if f is not None else ""))
    return out


class TestContactCoverage:
    def test_the_positive_control_complete_contact_data_verifies(self):
        table = limits()
        c = run(pfl_envelope(table), trace(pfl_samples([10.0] * 40)),
                limits=table).check("pfl_contact")
        assert c.outcome is CheckOutcome.VERIFIED

    def test_ninety_nine_missing_forces_are_not_a_pass(self):
        table = limits()
        forces = [10.0] + [None] * 99
        r = run(pfl_envelope(table), trace(pfl_samples(forces)), limits=table)
        c = r.check("pfl_contact")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "99" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_force_over_the_limit_still_reads_as_violated(self):
        table = limits()
        forces = [500.0] + [None] * 39
        c = run(pfl_envelope(table), trace(pfl_samples(forces)),
                limits=table).check("pfl_contact")
        assert c.outcome is CheckOutcome.VIOLATED


# -- (d) a pass needs a regime exercised and a meaningful trace -----------

class TestMinimumMeaningfulTrace:
    def test_one_automatic_sample_is_not_a_validated_pass(self):
        r = run(envelope(), trace([sample(0, mode=OperatingMode.AUTOMATIC,
                                          separation=None)], provenance=Provenance.BENCH))
        assert r.verdict is Verdict.INCOMPLETE
        c = r.check("trace_coverage")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert str(MIN_TRACE_SAMPLES) in c.reason

    def test_a_long_trace_that_only_ever_ran_automatic_is_not_a_pass(self):
        samples = [sample(i, mode=OperatingMode.AUTOMATIC, separation=None)
                   for i in range(200)]
        r = run(envelope(), trace(samples))
        c = r.check("trace_coverage")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "regime" in c.reason
        assert r.verdict is Verdict.INCOMPLETE
        assert r.check("ssm_separation").outcome is CheckOutcome.NOT_APPLICABLE

    def test_a_trace_just_under_the_sample_floor_is_unchecked(self):
        r = run(envelope(), good(n=MIN_TRACE_SAMPLES - 1))
        assert r.check("trace_coverage").outcome is CheckOutcome.UNCHECKED

    def test_a_trace_at_the_sample_floor_with_enough_duration_is_covered(self):
        step = 1.01 * MIN_TRACE_DURATION_S / (MIN_TRACE_SAMPLES - 1)
        samples = [sample(i, t=i * step) for i in range(MIN_TRACE_SAMPLES)]
        r = run(envelope(), trace(samples, sample_rate_hz=1.0 / step))
        assert r.check("trace_coverage").outcome is CheckOutcome.VERIFIED

    def test_many_samples_over_no_time_worth_mentioning_is_unchecked(self):
        step = MIN_TRACE_DURATION_S / (4 * MIN_TRACE_SAMPLES)
        samples = [sample(i, t=i * step) for i in range(MIN_TRACE_SAMPLES + 5)]
        r = run(envelope(), trace(samples, sample_rate_hz=1.0 / step))
        assert r.check("trace_coverage").outcome is CheckOutcome.UNCHECKED
        assert "s" in r.check("trace_coverage").reason

    def test_the_floor_is_surfaced_in_the_result_even_when_met(self):
        r = run(envelope(), good())
        text = r.check("trace_coverage").statement
        assert str(MIN_TRACE_SAMPLES) in text and "not a standard" in text
        assert any("sanity floor" in c for c in r.checks_skipped)

    def test_a_declared_pfl_claim_with_no_contact_is_left_to_the_pfl_check(self):
        table = limits()
        samples = [sample(i, mode=OperatingMode.AUTOMATIC, separation=None)
                   for i in range(40)]
        r = run(pfl_envelope(table), trace(samples), limits=table)
        assert r.check("pfl_contact").outcome is CheckOutcome.UNCHECKED
        assert r.verdict is Verdict.INCOMPLETE


# -- (e) gaps apply to every "stayed within" check ------------------------

def gappy():
    times = [0.0, 0.02, 0.04, 60.04, 60.06, 60.08] + [60.08 + 0.02 * k
                                                       for k in range(1, 30)]
    return trace([sample(0, t=t) for t in times])


class TestGapsEverywhere:
    @pytest.mark.parametrize("name", ["workspace_containment", "speed_limit",
                                      "mode_consistency", "stop_characterisation",
                                      "ssm_separation"])
    def test_a_sixty_second_hole_makes_each_stayed_within_check_unchecked(self, name):
        r = run(envelope(), gappy())
        c = r.check(name)
        assert c.outcome is CheckOutcome.UNCHECKED, name
        assert "gap" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_violation_beside_a_gap_still_reads_as_violated(self):
        samples = [sample(0, t=0.0), sample(1, t=0.02, tcp=(5000.0, 0.0, 1000.0)),
                   sample(2, t=60.0)] + [sample(3, t=60.0 + 0.02 * k)
                                         for k in range(1, 30)]
        c = run(envelope(), trace(samples)).check("workspace_containment")
        assert c.outcome is CheckOutcome.VIOLATED

    def test_pfl_contact_across_a_gap_is_unchecked(self):
        table = limits()
        pts = pfl_samples([10.0] * 40)
        pts = [replace(s, t=s.t + (60.0 if i >= 20 else 0.0)) for i, s in enumerate(pts)]
        c = run(pfl_envelope(table), trace(pts), limits=table).check("pfl_contact")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "gap" in c.reason


# -- (f) future-dated inputs ----------------------------------------------

class TestFutureDates:
    def test_a_trace_that_started_in_2099_is_not_validated(self):
        tr = good()
        tr = replace(tr, started_at=datetime(2099, 1, 1, tzinfo=UTC))
        r = run(envelope(), tr)
        assert r.tier is not AssuranceTier.VALIDATED
        assert r.verdict is Verdict.INCOMPLETE
        assert r.check("input_dates").outcome is CheckOutcome.UNCHECKED
        assert "started_at" in r.check("input_dates").reason

    def test_a_figure_dated_2099_is_not_validated(self):
        future = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2099-01-01")
        r = run(envelope(stop=StopPerformance(0.1, 0.25, 120.0, 500.0, future)), good())
        assert r.tier is not AssuranceTier.VALIDATED
        assert r.verdict is Verdict.INCOMPLETE
        assert "2099-01-01" in r.check("input_dates").reason

    def test_a_sensing_figure_dated_in_the_future_is_caught_too(self):
        future = FigureBasis(kind="measured", reference="SCAN-1", date="2099-01-01")
        r = run(envelope(uncertainty=SensingUncertainty(100.0, 50.0, future)), good())
        assert r.check("input_dates").outcome is CheckOutcome.UNCHECKED

    def test_clock_skew_within_a_day_is_not_called_future(self):
        tr = replace(good(), started_at=datetime(2026, 10, 21, 20, 0, tzinfo=UTC))
        assert run(envelope(), tr).check("input_dates").outcome is CheckOutcome.VERIFIED

    def test_ordinary_past_dates_are_verified(self):
        assert run(envelope(), good()).check("input_dates").outcome is CheckOutcome.VERIFIED


# -- (g) zero figures -----------------------------------------------------

class TestZeroFiguresAreNotAMeasurement:
    @pytest.mark.parametrize("field", ["reaction_time_s", "stop_time_s", "stop_distance_mm"])
    def test_zero_stop_figures_are_refused(self, field):
        kw = {"reaction_time_s": 0.1, "stop_time_s": 0.25, "stop_distance_mm": 120.0,
              "measured_at_speed_mm_s": 500.0, "basis": MEASURED}
        kw[field] = 0.0
        with pytest.raises(EnvelopeError, match=field):
            StopPerformance(**kw)

    def test_zero_intrusion_distance_is_refused(self):
        with pytest.raises(EnvelopeError, match="intrusion_distance_mm"):
            envelope(intrusion_distance_mm=0.0)

    def test_the_all_zero_envelope_is_refused_from_a_dict_as_well(self):
        d = envelope().to_dict()
        d["stop"].update(reaction_time_s=0.0, stop_time_s=0.0, stop_distance_mm=0.0)
        d["uncertainty"].update(human_position_mm=0.0, robot_position_mm=0.0)
        d["intrusion_distance_mm"] = 0.0
        with pytest.raises(EnvelopeError):
            SafetyEnvelope.from_dict(d)

    @pytest.mark.parametrize("key", ["reaction_time_s", "stop_time_s", "stop_distance_mm"])
    def test_zero_stop_figures_are_refused_from_a_dict(self, key):
        d = envelope().to_dict()
        d["stop"][key] = 0.0
        with pytest.raises(EnvelopeError, match=key):
            SafetyEnvelope.from_dict(d)

    def test_zero_position_uncertainty_cannot_carry_a_measured_basis(self):
        env = envelope(uncertainty=SensingUncertainty(0.0, 0.0, MEASURED))
        assert env.tier_ceiling is AssuranceTier.PROFILE
        r = run(env, good())
        assert r.tier is AssuranceTier.PROFILE
        assert any("zero position uncertainty" in c for c in r.checks_skipped)

    def test_zero_robot_uncertainty_alone_also_caps_the_tier(self):
        env = envelope(uncertainty=SensingUncertainty(100.0, 0.0, MEASURED))
        assert env.tier_ceiling is AssuranceTier.PROFILE

    def test_positive_uncertainty_keeps_its_basis(self):
        assert envelope().tier_ceiling is AssuranceTier.VALIDATED


# -- (h) the PFL table must be pinned -------------------------------------

class TestPflTablePinned:
    def test_an_unpinned_table_with_a_huge_limit_does_not_pass(self):
        lax = limits(regions={"hand": BodyRegionLimit("hand", "Hand", 1e6, 1e6)})
        r = run(envelope(), trace(pfl_samples([5000.0] * 40)), limits=lax)
        c = r.check("pfl_contact")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "pin" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_table_that_does_not_match_the_pin_is_still_unchecked(self):
        table = limits()
        other = limits(edition="Other 2020")
        c = run(pfl_envelope(table), trace(pfl_samples([10.0] * 40)),
                limits=other).check("pfl_contact")
        assert c.outcome is CheckOutcome.UNCHECKED

    def test_a_verified_by_claim_with_no_pin_cannot_lift_the_tier(self):
        table = limits()
        assert table.tier_ceiling is AssuranceTier.COMMUNITY

    def test_the_claim_is_recorded_as_a_claim_in_the_tier_reason(self):
        table = limits()
        tier, reason = table.tier_for(table.content_hash())
        assert tier is AssuranceTier.COMMUNITY
        assert "author's claim" in reason and "was not used" in reason

    @pytest.mark.parametrize("pin", ["", "0" * 64])
    def test_a_claim_the_envelope_does_not_pin_is_community_and_says_why(self, pin):
        tier, reason = limits().tier_for(pin)
        assert tier is AssuranceTier.COMMUNITY
        assert "does not pin" in reason

    def test_a_table_without_a_verification_claim_is_community(self):
        table = limits(verified_by="", verified_on="")
        tier, reason = table.tier_for(table.content_hash())
        assert tier is AssuranceTier.COMMUNITY and reason

    def test_a_pinned_table_with_only_a_claim_stays_community_and_says_why(self):
        table = limits()
        r = run(pfl_envelope(table), trace(pfl_samples([10.0] * 40)), limits=table)
        assert r.check("pfl_contact").outcome is CheckOutcome.VERIFIED
        assert r.tier is AssuranceTier.COMMUNITY
        assert any("verified_by" in c and "claim" in c for c in r.checks_skipped)

    def test_a_pinned_table_without_a_claim_is_community(self):
        table = limits(verified_by="", verified_on="")
        r = run(pfl_envelope(table), trace(pfl_samples([10.0] * 40)), limits=table)
        assert r.tier is AssuranceTier.COMMUNITY

    def test_the_transient_multiplier_is_flagged_as_unused(self):
        table = limits()
        r = run(pfl_envelope(table), trace(pfl_samples([10.0] * 40)), limits=table)
        assert any("transient_multiplier" in c and "not used" in c
                   for c in r.checks_skipped)


# -- (i) what the separation check actually claims ------------------------

class TestSeparationStatementIsHonest:
    def test_the_statement_names_the_computation_not_the_standard(self):
        r = run(envelope(), good())
        text = r.check("ssm_separation").statement
        assert "ssm.py" in text and "envelope" in text
        assert "ISO/TS 15066 protective separation distance" not in text
        assert "every instant" not in text

    def test_the_fixed_limitation_is_always_listed(self):
        for r in (run(envelope(), good()),
                  run(envelope(), trace([sample(0, mode=OperatingMode.AUTOMATIC,
                                                separation=None)]))):
            assert any(FORMULA_LIMITATION in c for c in r.checks_skipped)

    def test_the_limitation_is_listed_on_a_failing_run_too(self):
        r = run(envelope(), good(separation=10.0))
        assert r.verdict is Verdict.FAIL
        assert any(FORMULA_LIMITATION in c for c in r.checks_skipped)

    def test_the_unchecked_and_gap_statements_do_not_overclaim_either(self):
        for tr in (gappy(), trace([sample(i, separation=None) for i in range(40)])):
            assert "ISO/TS 15066 protective" not in run(envelope(), tr).check(
                "ssm_separation").statement

    def test_an_undeclared_approach_speed_is_reported_as_default(self):
        env = envelope(human_approach_speed_mm_s=None)
        b = separation_required(env, robot_speed_mm_s=300.0)
        assert b.human_speed_source == "default"
        assert b.human_speed_mm_s == 1600.0
        r = run(env, good())
        assert any("default" in c and "1600" in c for c in r.checks_skipped)
        assert not any("declared approach speed" in c for c in r.checks_skipped)

    def test_a_declared_approach_speed_is_reported_as_declared(self):
        env = envelope(human_approach_speed_mm_s=2000.0)
        assert separation_required(env, robot_speed_mm_s=300.0).human_speed_source \
            == "declared"
        r = run(env, good())
        assert any("declared approach speed" in c for c in r.checks_skipped)

    def test_from_dict_without_the_field_is_default_and_survives_a_round_trip(self):
        d = envelope(human_approach_speed_mm_s=None).to_dict()
        d.pop("human_approach_speed_mm_s", None)
        env = SafetyEnvelope.from_dict(d)
        assert not env.approach_speed_declared
        again = SafetyEnvelope.from_dict(env.to_dict())
        assert not again.approach_speed_declared
        assert again.content_hash() == env.content_hash()

    def test_from_dict_with_the_field_is_declared(self):
        d = envelope().to_dict()
        assert SafetyEnvelope.from_dict(d).approach_speed_declared
