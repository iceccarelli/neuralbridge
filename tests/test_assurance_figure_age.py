"""The age of the figures a verdict rests on is stated, and never time-dependent.

No maximum age is invented: a threshold would be a number nobody can source. But a
stopping distance measured five years before the trace is something a reviewer is
entitled to see beside the verdict, and the sentence must be reproducible — a
caveat that depended on today's date would make every bundle fail its own replay.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import verify


def envelope(stop_date="2026-03-11", sensing_date=""):
    return SafetyEnvelope(
        envelope_id="E", product="Cell", product_version="1",
        workspace=Workspace((-1000.0, -1000.0, 0.0), (1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0},
        stop=StopPerformance(0.1, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-1", stop_date)),
        uncertainty=SensingUncertainty(100.0, 50.0,
                                       FigureBasis("datasheet", "rev D", sensing_date)),
        intrusion_distance_mm=850.0)


def run():
    samples = tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                           mode=OperatingMode.SSM, separation=3000.0) for i in range(4))
    return Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                 started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC),
                 sample_rate_hz=50.0, samples=samples)


def age_line(result):
    return next(c for c in result.checks_skipped if c.startswith("age of the figures"))


class TestAgeIsStated:
    def test_the_days_between_the_figure_and_the_run_are_stated(self):
        days = (date(2026, 9, 12) - date(2026, 3, 11)).days
        line = age_line(verify(envelope(), run()))
        assert f"stopping is dated 2026-03-11, {days} day(s) before the trace began" in line

    def test_an_undated_figure_says_so(self):
        assert "sensing is undated" in age_line(verify(envelope(), run()))

    def test_a_figure_dated_after_the_run_is_flagged(self):
        line = age_line(verify(envelope(stop_date="2026-10-01"), run()))
        assert "AFTER the trace began" in line

    def test_no_maximum_age_is_applied(self):
        r = verify(envelope(stop_date="2001-01-01"), run())
        assert r.verdict.value == "pass"
        assert "No maximum age is applied" in age_line(r)

    def test_the_sentence_does_not_depend_on_todays_date(self):
        a = verify(envelope(), run()).checks_skipped
        b = verify(envelope(), run()).checks_skipped
        assert a == b
