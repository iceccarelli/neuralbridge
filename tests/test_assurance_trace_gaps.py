"""Gaps are measured against the shorter of the declared and the observed period."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import CheckOutcome, Verdict, verify

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")


def envelope():
    return SafetyEnvelope(
        envelope_id="E", product="Cell", product_version="1",
        workspace=Workspace((-1000.0, -1000.0, 0.0), (1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0},
        stop=StopPerformance(0.1, 0.25, 120.0, 500.0, MEASURED),
        uncertainty=SensingUncertainty(100.0, 50.0, MEASURED),
        intrusion_distance_mm=850.0)


def run(times, rate):
    samples = tuple(Sample(t=t, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                           mode=OperatingMode.SSM, separation=3000.0) for t in times)
    return Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                 started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=rate,
                 samples=samples)


def fifty_hz_with_a_hole(hole_s):
    first = [i / 50 for i in range(20)]
    last = first[-1]
    return first + [last + hole_s + i / 50 for i in range(20)]


class TestDeclaredRateCannotHideADropout:
    def test_a_one_second_hole_is_a_gap_even_when_the_declared_rate_is_1_hz(self):
        """Declared 1 Hz makes the nominal gap threshold 2 s, so a 1 s dropout in
        50 Hz data would pass unnoticed if the data's own period were ignored."""
        t = run(fifty_hz_with_a_hole(1.0), rate=1.0)
        assert len(t.gaps) == 1
        r = verify(envelope(), t)
        assert r.check("ssm_separation").outcome is CheckOutcome.UNCHECKED
        assert r.verdict is Verdict.INCOMPLETE

    def test_the_same_hole_is_found_at_the_true_rate(self):
        t = run(fifty_hz_with_a_hole(1.0), rate=50.0)
        assert len(t.gaps) == 1

    def test_a_declared_rate_that_is_too_high_marks_every_interval(self):
        t = run([i / 50 for i in range(10)], rate=5000.0)
        assert len(t.gaps) == 9
        assert t.rate_disagrees_with_data

    def test_a_clean_trace_at_its_declared_rate_has_no_gaps_and_no_disagreement(self):
        t = run([i / 50 for i in range(10)], rate=50.0)
        assert t.gaps == [] and not t.rate_disagrees_with_data

    def test_a_single_sample_trace_has_no_observed_period(self):
        t = run([0.0], rate=50.0)
        assert t.observed_period_s is None
        assert t.gaps == [] and not t.rate_disagrees_with_data

    @pytest.mark.parametrize("rate", [26.0, 40.0, 80.0])
    def test_a_rate_within_a_factor_of_two_of_the_data_is_not_called_a_disagreement(
            self, rate):
        t = run([i / 50 for i in range(10)], rate=rate)
        assert not t.rate_disagrees_with_data
