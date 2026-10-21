"""A power-and-force pass needs every contact sample evaluated.

The check's own docstring says force alone does not establish a PFL claim: a
compliant force through a small area is not a compliant contact. A contact sample
with no recorded area, or credited to a region the table does not cover, was not
evaluated — and a verified outcome beside a caveat saying so is a pass from
missing data.
"""

from __future__ import annotations

from datetime import UTC, datetime

from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import CheckOutcome, Verdict, verify

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")

TABLE = LimitsTable(
    edition="Example 2016", transcribed_by="a", verified_by="b", verified_on="2026-04-01",
    transient_multiplier=2.0,
    regions={"hand": BodyRegionLimit("hand", "Hand", 260.0, 140.0)})


def envelope():
    return SafetyEnvelope(
        envelope_id="E", product="Cell", product_version="1",
        workspace=Workspace((-1000.0, -1000.0, 0.0), (1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.PFL: 250.0},
        stop=StopPerformance(0.1, 0.25, 120.0, 500.0, MEASURED),
        uncertainty=SensingUncertainty(100.0, 50.0, MEASURED),
        intrusion_distance_mm=850.0, pfl_limits_hash=TABLE.content_hash())


def contact(i, **over):
    kw = {"t": i / 50, "tcp": (0.0, 0.0, 1000.0), "tcp_speed": 100.0,
          "mode": OperatingMode.PFL, "contact_force": 50.0, "contact_area": 2.0,
          "body_region": "hand"}
    kw.update(over)
    return Sample(**kw)


def run(*samples):
    return Trace(trace_id="R", provenance=Provenance.FIELD, source_system="s",
                 started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=50.0,
                 samples=tuple(samples))


class TestContactThatWasNotEvaluatedIsNotAPass:
    def test_every_contact_evaluated_is_a_pass(self):
        r = verify(envelope(), run(contact(0), contact(1)), limits=TABLE)
        assert r.check("pfl_contact").outcome is CheckOutcome.VERIFIED
        assert r.verdict is Verdict.PASS

    def test_a_force_with_no_area_is_unchecked_not_verified(self):
        r = verify(envelope(), run(contact(0), contact(1, contact_area=None)),
                   limits=TABLE)
        c = r.check("pfl_contact")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "area" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_one_contact_in_a_region_the_table_lacks_is_unchecked_not_verified(self):
        r = verify(envelope(), run(contact(0), contact(1, body_region="skull")),
                   limits=TABLE)
        c = r.check("pfl_contact")
        assert c.outcome is CheckOutcome.UNCHECKED
        assert "skull" in c.reason
        assert r.verdict is Verdict.INCOMPLETE

    def test_a_contact_with_no_region_named_is_unchecked(self):
        r = verify(envelope(), run(contact(0), contact(1, body_region="")),
                   limits=TABLE)
        assert r.check("pfl_contact").outcome is CheckOutcome.UNCHECKED

    def test_a_violation_still_outranks_an_unevaluated_sample(self):
        r = verify(envelope(), run(contact(0, contact_force=900.0),
                                   contact(1, contact_area=None)), limits=TABLE)
        assert r.check("pfl_contact").outcome is CheckOutcome.VIOLATED
        assert r.verdict is Verdict.FAIL

    def test_the_stated_limitations_still_say_what_was_skipped(self):
        r = verify(envelope(), run(contact(0), contact(1, contact_area=None)),
                   limits=TABLE)
        assert any("no contact area" in c for c in r.checks_skipped)
