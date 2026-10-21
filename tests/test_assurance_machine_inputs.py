"""Physical inputs: what the machine package accepts, and what it must refuse.

Every test here began as a reproduction. The shape of the original defect was
always the same: a number that is not a number (NaN, infinity, a string, a
boolean, 1e308) was accepted, every comparison against it was false, and a
check that compares "is it short?" therefore reported "no". A pass must never be
the by-product of a comparison that could not be made.
"""

from __future__ import annotations

import copy
import json
import math
from datetime import UTC, datetime

import pytest

from assurance.machine.envelope import (
    EnvelopeError,
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsError, LimitsTable
from assurance.machine.quantities import QuantityError, number
from assurance.machine.ssm import separation_required
from assurance.machine.trace import (
    OperatingMode,
    Provenance,
    Sample,
    Trace,
    TraceError,
)
from assurance.machine.verify import CheckOutcome, Verdict, verify

NAN = float("nan")
INF = float("inf")
MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")


def envelope(**over):
    kw = {
        "envelope_id": "ENV-1", "product": "Cell", "product_version": "1.0.0",
        "workspace": Workspace(minimum=(-1000.0, -1000.0, 0.0),
                               maximum=(1000.0, 1000.0, 2000.0)),
        "max_tcp_speed_mm_s": {OperatingMode.SSM: 500.0, OperatingMode.PFL: 250.0},
        "stop": StopPerformance(reaction_time_s=0.1, stop_time_s=0.25,
                                stop_distance_mm=120.0, measured_at_speed_mm_s=500.0,
                                basis=MEASURED),
        "uncertainty": SensingUncertainty(human_position_mm=100.0,
                                          robot_position_mm=50.0, basis=MEASURED),
        "intrusion_distance_mm": 850.0,
    }
    kw.update(over)
    return SafetyEnvelope(**kw)


def sample(i=0, **over):
    kw = {"t": i / 50.0, "tcp": (0.0, 0.0, 1000.0), "tcp_speed": 500.0,
          "mode": OperatingMode.SSM, "separation": 2000.0}
    kw.update(over)
    return Sample(**kw)


def trace(samples, **over):
    kw = {"trace_id": "RUN-1", "provenance": Provenance.FIELD,
          "source_system": "fw 1.0", "sample_rate_hz": 50.0,
          "started_at": datetime(2026, 9, 12, 4, 31, tzinfo=UTC)}
    kw.update(over)
    return Trace(samples=tuple(samples), **kw)


def envelope_dict():
    return json.loads(json.dumps(envelope().to_dict()))


def sample_dict(**over):
    d = {"t": 0.0, "tcp": [0.0, 0.0, 1000.0], "tcp_speed": 500.0, "mode": "ssm",
         "separation": 2000.0}
    d.update(over)
    return d


def trace_dict(samples=None, **over):
    d = {"trace_id": "RUN-1", "provenance": "field", "source_system": "fw",
         "started_at": "2026-09-12T04:31:00Z", "sample_rate_hz": 50.0,
         "samples": samples if samples is not None else [sample_dict()]}
    d.update(over)
    return d


# =====================================================================
# the original defects: a non-number must never read as "not short"
# =====================================================================

class TestNonFiniteSamplesAreRefused:
    @pytest.mark.parametrize("bad", [NAN, INF, -INF])
    @pytest.mark.parametrize("field", [
        "t", "tcp_speed", "separation", "human_speed", "contact_force", "contact_area",
    ])
    def test_a_scalar_field_that_is_not_finite_is_refused(self, field, bad):
        with pytest.raises(TraceError, match=field):
            sample(**{field: bad})

    @pytest.mark.parametrize("bad", [NAN, INF, -INF])
    @pytest.mark.parametrize("axis", [0, 1, 2])
    def test_a_tcp_coordinate_that_is_not_finite_is_refused(self, axis, bad):
        tcp = [0.0, 0.0, 1000.0]
        tcp[axis] = bad
        with pytest.raises(TraceError, match="tcp"):
            sample(tcp=tuple(tcp))

    def test_nan_separation_used_to_pass_the_separation_check(self):
        """Reproduction. ``nan < required`` is False, so the old engine reported a
        verified margin of NaN and an overall PASS."""
        with pytest.raises(TraceError):
            trace([sample(separation=NAN)])

    def test_a_nan_tcp_used_to_read_as_inside_the_workspace(self):
        with pytest.raises(TraceError):
            trace([sample(tcp=(NAN, NAN, NAN))])

    def test_nan_timestamps_used_to_defeat_the_ordering_check(self):
        with pytest.raises(TraceError):
            trace([sample(0, t=NAN), sample(1, t=NAN)])

    def test_infinite_separation_is_not_a_clean_bill_of_health(self):
        with pytest.raises(TraceError, match="separation"):
            sample(separation=INF)


class TestTypeConfusionIsRefused:
    @pytest.mark.parametrize("field,value", [
        ("tcp_speed", "500"), ("tcp_speed", True), ("separation", "2000"),
        ("separation", False), ("t", "0.0"), ("human_speed", "1600"),
        ("contact_force", True), ("contact_area", "3"),
    ])
    def test_a_sample_field_that_is_a_string_or_a_boolean_is_refused(self, field, value):
        with pytest.raises(TraceError, match=field):
            Sample.from_dict(sample_dict(**{field: value}))

    def test_a_tcp_with_a_string_coordinate_is_refused(self):
        with pytest.raises(TraceError, match="tcp"):
            Sample.from_dict(sample_dict(tcp=["0", 0.0, 1000.0]))

    def test_a_tcp_that_is_not_a_triple_is_refused_as_a_trace_error(self):
        with pytest.raises(TraceError, match="tcp"):
            Sample.from_dict(sample_dict(tcp=[0.0, 0.0]))

    def test_an_unknown_operating_mode_is_a_trace_error_not_a_crash(self):
        with pytest.raises(TraceError, match="mode"):
            Sample.from_dict(sample_dict(mode="turbo"))

    def test_a_missing_required_field_is_a_trace_error_not_a_key_error(self):
        d = sample_dict()
        del d["tcp_speed"]
        with pytest.raises(TraceError, match="tcp_speed"):
            Sample.from_dict(d)

    @pytest.mark.parametrize("field,value", [
        ("sample_rate_hz", "50"), ("sample_rate_hz", True), ("sample_rate_hz", NAN),
        ("sample_rate_hz", INF), ("sample_rate_hz", 0), ("sample_rate_hz", -50.0),
        ("sample_rate_hz", 1e308),
    ])
    def test_a_trace_rate_that_is_not_a_positive_finite_number_is_refused(
            self, field, value):
        with pytest.raises(TraceError, match="sample_rate_hz"):
            Trace.from_dict(trace_dict(**{field: value}))

    def test_a_non_object_sample_is_refused(self):
        with pytest.raises(TraceError):
            Trace.from_dict(trace_dict(samples=[[0, 1, 2]]))

    def test_a_samples_field_that_is_not_a_list_is_refused(self):
        with pytest.raises(TraceError):
            Trace.from_dict(trace_dict(samples="abc"))

    def test_a_started_at_that_is_not_a_timestamp_is_a_trace_error(self):
        with pytest.raises(TraceError, match="started_at"):
            Trace.from_dict(trace_dict(started_at="yesterday"))


class TestPhysicalRangeOfSamples:
    @pytest.mark.parametrize("field,value", [
        ("tcp_speed", -1.0), ("separation", -0.001), ("human_speed", -1.0),
        ("contact_force", -100.0), ("contact_area", -5.0), ("contact_area", 0.0),
    ])
    def test_a_negative_or_zero_magnitude_is_refused(self, field, value):
        with pytest.raises(TraceError, match=field):
            sample(**{field: value})

    @pytest.mark.parametrize("field", [
        "tcp_speed", "separation", "human_speed", "contact_force", "contact_area", "t",
    ])
    def test_an_absurd_magnitude_is_refused_not_clamped(self, field):
        with pytest.raises(TraceError, match="plausib"):
            sample(**{field: 1e308})

    def test_zero_contact_area_used_to_divide_by_zero_inside_verify(self):
        with pytest.raises(TraceError, match="contact_area"):
            sample(mode=OperatingMode.PFL, contact_force=10.0, contact_area=0.0,
                   body_region="hand")

    def test_a_negative_contact_area_used_to_make_every_pressure_pass(self):
        with pytest.raises(TraceError, match="contact_area"):
            sample(mode=OperatingMode.PFL, contact_force=900.0, contact_area=-1.0,
                   body_region="hand")

    def test_a_rail_edge_value_is_accepted_and_one_past_it_is_not(self):
        sample(tcp_speed=1.0e6)
        with pytest.raises(TraceError):
            sample(tcp_speed=math.nextafter(1.0e6, math.inf))


class TestTraceStructure:
    def test_an_empty_trace_is_refused(self):
        with pytest.raises(TraceError, match="no samples"):
            trace([])

    def test_duplicate_timestamps_are_refused(self):
        with pytest.raises(TraceError, match="strictly increasing"):
            trace([sample(0, t=1.0), sample(1, t=1.0)])

    def test_a_decreasing_timestamp_is_refused(self):
        with pytest.raises(TraceError, match="strictly increasing"):
            trace([sample(0, t=2.0), sample(1, t=1.0)])

    def test_a_trace_beyond_the_sample_cap_is_refused_before_it_is_built(self, monkeypatch):
        import assurance.machine.trace as tmod
        monkeypatch.setattr(tmod, "MAX_SAMPLES", 3)
        with pytest.raises(TraceError, match="samples"):
            Trace.from_dict(trace_dict(samples=[sample_dict(t=i / 50) for i in range(4)]))

    def test_csv_columns_that_look_like_other_units_are_refused(self, tmp_path):
        """A CSV with ``separation_m`` and no ``separation`` used to load with
        every separation silently ``None``: nobody detected."""
        p = tmp_path / "run.csv"
        p.write_text("t,x,y,z,tcp_speed,mode,separation_m\n"
                     "0,0,0,1000,500,ssm,2.0\n", encoding="utf-8")
        with pytest.raises(TraceError, match="separation_m"):
            Trace.from_csv(p, trace_id="r", provenance=Provenance.FIELD,
                           source_system="s",
                           started_at=datetime(2026, 1, 1, tzinfo=UTC),
                           sample_rate_hz=50.0)

    def test_csv_closes_its_file(self, tmp_path):
        import warnings
        p = tmp_path / "run.csv"
        p.write_text("t,x,y,z,tcp_speed,mode\n0,0,0,1000,500,ssm\n", encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            Trace.from_csv(p, trace_id="r", provenance=Provenance.FIELD,
                           source_system="s",
                           started_at=datetime(2026, 1, 1, tzinfo=UTC),
                           sample_rate_hz=50.0)


# =====================================================================
# the envelope
# =====================================================================

class TestEnvelopeNumbers:
    @pytest.mark.parametrize("bad", [NAN, INF, "850", True, 1e308, -1.0])
    def test_intrusion_distance_must_be_a_finite_non_negative_number(self, bad):
        d = envelope_dict()
        d["intrusion_distance_mm"] = bad
        with pytest.raises(EnvelopeError, match="intrusion_distance_mm"):
            SafetyEnvelope.from_dict(d)

    @pytest.mark.parametrize("path,bad", [
        (("stop", "reaction_time_s"), NAN), (("stop", "stop_time_s"), INF),
        (("stop", "stop_distance_mm"), "120"), (("stop", "measured_at_speed_mm_s"), 0),
        (("stop", "measured_at_speed_mm_s"), NAN),
        (("stop", "stop_time_s"), 1e308), (("stop", "reaction_time_s"), True),
        (("uncertainty", "human_position_mm"), NAN),
        (("uncertainty", "robot_position_mm"), -1.0),
        (("uncertainty", "human_position_mm"), 1e308),
    ])
    def test_stop_and_uncertainty_figures_are_validated_where_they_are_loaded(
            self, path, bad):
        d = envelope_dict()
        d[path[0]][path[1]] = bad
        with pytest.raises(EnvelopeError, match=path[1]):
            SafetyEnvelope.from_dict(d)

    @pytest.mark.parametrize("bad", [NAN, INF, "1600", True, 0, -5.0, 1e308])
    def test_the_declared_approach_speed_must_be_positive_and_finite(self, bad):
        d = envelope_dict()
        d["human_approach_speed_mm_s"] = bad
        with pytest.raises(EnvelopeError, match="human_approach_speed_mm_s"):
            SafetyEnvelope.from_dict(d)

    def test_a_mode_speed_limit_must_be_finite(self):
        d = envelope_dict()
        d["max_tcp_speed_mm_s"]["ssm"] = NAN
        with pytest.raises(EnvelopeError, match="max_tcp_speed_mm_s"):
            SafetyEnvelope.from_dict(d)

    @pytest.mark.parametrize("which", ["minimum", "maximum"])
    def test_a_workspace_corner_must_be_finite(self, which):
        d = envelope_dict()
        d["workspace"][which][1] = NAN
        with pytest.raises(EnvelopeError, match="workspace"):
            SafetyEnvelope.from_dict(d)

    def test_a_workspace_must_have_three_coordinates(self):
        d = envelope_dict()
        d["workspace"]["minimum"] = [0.0, 0.0]
        with pytest.raises(EnvelopeError, match="workspace"):
            SafetyEnvelope.from_dict(d)

    def test_constructing_directly_is_validated_too(self):
        with pytest.raises(EnvelopeError, match="reaction_time_s"):
            StopPerformance(reaction_time_s=NAN, stop_time_s=0.25,
                            stop_distance_mm=120.0, measured_at_speed_mm_s=500.0,
                            basis=MEASURED)
        with pytest.raises(EnvelopeError, match="human_position_mm"):
            SensingUncertainty(human_position_mm=INF, robot_position_mm=0.0,
                               basis=MEASURED)
        with pytest.raises(EnvelopeError, match="intrusion_distance_mm"):
            envelope(intrusion_distance_mm=NAN)
        with pytest.raises(EnvelopeError, match="workspace"):
            Workspace(minimum=(0.0, 0.0, NAN), maximum=(1.0, 1.0, 1.0))

    def test_a_missing_required_figure_is_an_envelope_error_not_a_key_error(self):
        d = envelope_dict()
        del d["stop"]["stop_time_s"]
        with pytest.raises(EnvelopeError, match="stop_time_s"):
            SafetyEnvelope.from_dict(d)

    def test_an_unknown_operating_mode_in_the_limits_is_an_envelope_error(self):
        d = envelope_dict()
        d["max_tcp_speed_mm_s"]["turbo"] = 100.0
        with pytest.raises(EnvelopeError, match="turbo"):
            SafetyEnvelope.from_dict(d)


class TestUnitVariantKeysAreNotSilentlyIgnored:
    """A mis-typed unit used to fall through to a default or to nothing."""

    def test_a_metre_per_second_approach_speed_does_not_become_1600(self):
        d = envelope_dict()
        del d["human_approach_speed_mm_s"]
        d["human_approach_speed_m_s"] = 2.0
        with pytest.raises(EnvelopeError, match="human_approach_speed_m_s"):
            SafetyEnvelope.from_dict(d)

    @pytest.mark.parametrize("where,key", [
        ("stop", "stop_time_ms"), ("stop", "reaction_time_ms"),
        ("stop", "stop_distance_m"), ("uncertainty", "human_position_m"),
    ])
    def test_a_unit_variant_in_a_nested_object_is_refused(self, where, key):
        d = envelope_dict()
        d[where][key] = 1.0
        with pytest.raises(EnvelopeError, match=key):
            SafetyEnvelope.from_dict(d)

    def test_a_misspelt_pfl_hash_does_not_silently_drop_the_pfl_claim(self):
        d = envelope_dict()
        del d["pfl_limits_hash"]
        d["pfl_limit_hash"] = "ab" * 32
        with pytest.raises(EnvelopeError, match="pfl_limit_hash"):
            SafetyEnvelope.from_dict(d)

    def test_the_shipped_example_still_loads(self):
        SafetyEnvelope.from_json("examples/machine/envelope.json")


class TestFigureBasis:
    def test_a_whitespace_only_reference_is_not_a_reference(self):
        with pytest.raises(EnvelopeError, match="reference"):
            FigureBasis(kind="measured", reference="   ")

    def test_a_date_that_is_not_a_date_is_refused(self):
        with pytest.raises(EnvelopeError, match="date"):
            FigureBasis(kind="measured", reference="R-1", date="last spring")

    def test_an_empty_date_is_allowed(self):
        assert FigureBasis(kind="datasheet", reference="rev D").date == ""


# =====================================================================
# the arithmetic itself
# =====================================================================

class TestSeparationInputs:
    @pytest.mark.parametrize("bad", [NAN, INF, -1.0, 1e308, "500", True])
    def test_a_robot_speed_that_is_not_a_finite_magnitude_is_refused(self, bad):
        with pytest.raises(ValueError, match="robot_speed_mm_s"):
            separation_required(envelope(), robot_speed_mm_s=bad)

    @pytest.mark.parametrize("bad", [NAN, INF, -1.0, 1e308, "1600"])
    def test_a_sensed_human_speed_that_is_not_a_finite_magnitude_is_refused(self, bad):
        with pytest.raises(ValueError, match="human_speed_mm_s"):
            separation_required(envelope(), robot_speed_mm_s=100.0,
                                human_speed_mm_s=bad)

    def test_the_total_is_always_finite(self):
        """1e308 stop time overflowed Sh to ``inf``; ``inf`` then 'failed' every
        sample with a bound that cannot be written as JSON."""
        d = envelope_dict()
        d["stop"]["stop_time_s"] = 1e7
        d["human_approach_speed_mm_s"] = 1e6
        d["intrusion_distance_mm"] = 1e7
        e = SafetyEnvelope.from_dict(d)
        b = separation_required(e, robot_speed_mm_s=1e6)
        assert math.isfinite(b.total_mm)


# =====================================================================
# limits table
# =====================================================================

def limits_dict(**over):
    d = {"edition": "Example 2016", "transcribed_by": "a", "verified_by": "b",
         "verified_on": "2026-04-01", "transient_multiplier": 2.0,
         "regions": {"hand": {"label": "Hand", "max_pressure_n_cm2": 260.0,
                              "max_force_n": 140.0}}}
    d.update(over)
    return d


class TestLimitsNumbers:
    @pytest.mark.parametrize("bad", [NAN, INF, "140", True, 0, -1.0, 1e308])
    def test_a_region_limit_must_be_a_positive_finite_number(self, bad):
        d = limits_dict()
        d["regions"]["hand"]["max_force_n"] = bad
        with pytest.raises(LimitsError, match="max_force_n"):
            LimitsTable.from_dict(d)

    @pytest.mark.parametrize("bad", [NAN, INF, "2", True, 0, -2.0, 1e308])
    def test_the_transient_multiplier_must_be_a_positive_finite_number(self, bad):
        with pytest.raises(LimitsError, match="transient_multiplier"):
            LimitsTable.from_dict(limits_dict(transient_multiplier=bad))

    def test_a_region_that_is_not_an_object_is_a_limits_error(self):
        with pytest.raises(LimitsError, match="hand"):
            LimitsTable.from_dict(limits_dict(regions={"hand": 140}))

    def test_a_missing_limit_is_a_limits_error_not_a_key_error(self):
        d = limits_dict()
        del d["regions"]["hand"]["max_pressure_n_cm2"]
        with pytest.raises(LimitsError, match="max_pressure_n_cm2"):
            LimitsTable.from_dict(d)

    def test_a_limits_table_constructed_directly_is_validated(self):
        with pytest.raises(LimitsError):
            BodyRegionLimit(key="hand", label="Hand", max_pressure_n_cm2=NAN,
                            max_force_n=140.0)


# =====================================================================
# what the engine does with a trace it cannot fully read
# =====================================================================

class TestVerifyNeverPassesOnMissingData:
    def test_a_gap_inside_a_separation_controlled_stretch_cannot_be_verified(self):
        s = [sample(0), sample(1), sample(2, t=5.0)]
        r = verify(envelope(), trace(s))
        assert r.check("ssm_separation").outcome is CheckOutcome.UNCHECKED
        assert "gap" in r.check("ssm_separation").reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_gap_is_still_a_failure_if_something_was_violated(self):
        s = [sample(0, separation=10.0), sample(1), sample(2, t=5.0)]
        r = verify(envelope(), trace(s))
        assert r.check("ssm_separation").outcome is CheckOutcome.VIOLATED
        assert r.verdict is Verdict.FAIL

    def test_a_gap_that_touches_no_separation_controlled_sample_does_not_block(self):
        s = [sample(0, mode=OperatingMode.STOPPED, tcp_speed=0.0, separation=None),
             sample(1, mode=OperatingMode.STOPPED, tcp_speed=0.0, separation=None,
                    t=5.0),
             sample(2, t=5.02), sample(3, t=5.04)]
        r = verify(envelope(), trace(s))
        assert r.check("ssm_separation").outcome is CheckOutcome.VERIFIED

    def test_a_declared_rate_far_above_the_observed_rate_is_stated(self):
        s = [sample(i) for i in range(5)]
        r = verify(envelope(), trace(s, sample_rate_hz=5000.0))
        assert any("sample rate" in c for c in r.checks_skipped)
        assert r.check("ssm_separation").outcome is CheckOutcome.UNCHECKED

    def test_a_declared_rate_far_below_the_observed_rate_is_stated(self):
        s = [sample(i) for i in range(5)]
        r = verify(envelope(), trace(s, sample_rate_hz=0.5))
        assert any("sample rate" in c for c in r.checks_skipped)

    def test_contact_force_recorded_where_contact_is_not_permitted_is_not_ignored(self):
        s = [sample(0, contact_force=50.0, contact_area=2.0, body_region="hand")]
        r = verify(envelope(), trace(s))
        assert r.check("pfl_contact").outcome is not CheckOutcome.NOT_APPLICABLE
        assert r.verdict is not Verdict.PASS

    def test_the_declared_approach_speed_is_stated_when_it_was_used(self):
        r = verify(envelope(), trace([sample(i) for i in range(5)]))
        assert any("declared approach speed" in c for c in r.checks_skipped)

    def test_every_non_finite_input_is_refused_before_verify_can_see_it(self):
        """The invariant under all of the above: whatever reaches ``verify`` is
        finite, so no comparison inside it can silently be False."""
        for s in (sample(0), sample(1)):
            for v in (s.t, s.tcp_speed, s.separation, *s.tcp):
                assert math.isfinite(v)


class TestCliRefusesNonNumbers:
    def test_separation_with_a_nan_speed_exits_2(self, capsys):
        from assurance.machine.cli import main
        code = main(["separation", "--envelope", "examples/machine/envelope.json",
                     "--speed", "nan"])
        assert code == 2
        assert "robot_speed_mm_s" in capsys.readouterr().err

    def test_separation_with_an_infinite_human_speed_exits_2(self, capsys):
        from assurance.machine.cli import main
        code = main(["separation", "--envelope", "examples/machine/envelope.json",
                     "--speed", "500", "--human-speed", "inf"])
        assert code == 2

    def test_a_trace_file_with_nan_in_it_exits_2(self, tmp_path, capsys):
        from assurance.machine.cli import main
        d = trace_dict()
        raw = json.dumps(d).replace('"separation": 2000.0', '"separation": NaN')
        p = tmp_path / "t.json"
        p.write_text(raw, encoding="utf-8")
        code = main(["verify", "--envelope", "examples/machine/envelope.json",
                     "--trace", str(p), "--actor", "a.person"])
        assert code == 2
        assert "separation" in capsys.readouterr().err

    def test_a_json_file_that_is_not_json_exits_2(self, tmp_path):
        from assurance.machine.cli import main
        p = tmp_path / "t.json"
        p.write_text("{not json", encoding="utf-8")
        code = main(["verify", "--envelope", "examples/machine/envelope.json",
                     "--trace", str(p), "--actor", "a.person"])
        assert code == 2


class TestNumberHelper:
    def test_numpy_style_real_numbers_are_accepted(self):
        from fractions import Fraction
        assert number(Fraction(1, 2), "x", maximum=10.0) == 0.5

    def test_an_int_is_accepted_and_returned_as_float(self):
        v = number(3, "x", maximum=10.0)
        assert v == 3.0 and isinstance(v, float)

    def test_an_int_too_large_for_a_float_is_refused(self):
        with pytest.raises(QuantityError):
            number(10 ** 400, "x", maximum=1e308)

    def test_signed_allows_negative_up_to_the_rail(self):
        assert number(-5.0, "x", maximum=10.0, signed=True) == -5.0
        with pytest.raises(QuantityError):
            number(-11.0, "x", maximum=10.0, signed=True)

    def test_the_input_dict_is_not_mutated(self):
        d = envelope_dict()
        before = copy.deepcopy(d)
        SafetyEnvelope.from_dict(d)
        assert d == before


class TestLimitsVerificationDate:
    def test_a_verification_date_in_the_future_is_refused(self):
        with pytest.raises(LimitsError, match="future"):
            LimitsTable.from_dict(limits_dict(verified_on="2099-01-01"))

    def test_a_verification_date_that_is_not_a_date_is_refused(self):
        with pytest.raises(LimitsError, match="ISO date"):
            LimitsTable.from_dict(limits_dict(verified_on="last week"))

    def test_a_past_date_is_accepted(self):
        assert LimitsTable.from_dict(limits_dict(verified_on="2026-04-01")).is_verified
