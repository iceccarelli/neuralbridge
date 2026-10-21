"""Sealing a bundle: a precomputed result must belong to the inputs it is sealed with."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor
from assurance.core.tiers import AssuranceTier
from assurance.machine.bundle import BundleError, build_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import verify

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
ACTOR = Actor("v.grimaldi", "verification engineer")


def envelope(**over):
    kw = {
        "envelope_id": "E", "product": "Cell", "product_version": "1",
        "workspace": Workspace((-1000.0, -1000.0, 0.0), (1000.0, 1000.0, 2000.0)),
        "max_tcp_speed_mm_s": {OperatingMode.SSM: 500.0},
        "stop": StopPerformance(0.1, 0.25, 120.0, 500.0, MEASURED),
        "uncertainty": SensingUncertainty(100.0, 50.0, MEASURED),
        "intrusion_distance_mm": 850.0,
    }
    kw.update(over)
    return SafetyEnvelope(**kw)


def trace(provenance=Provenance.FIELD, separation=3000.0):
    samples = tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                           mode=OperatingMode.SSM, separation=separation)
                    for i in range(4))
    return Trace(trace_id="R", provenance=provenance, source_system="s",
                 started_at=datetime(2026, 9, 12, tzinfo=UTC), sample_rate_hz=50.0,
                 samples=samples)


class TestAPrecomputedResultMustBelongToTheInputs:
    def test_a_result_computed_for_this_envelope_and_trace_is_accepted(self):
        e, t = envelope(), trace()
        b = build_bundle(e, t, actor=ACTOR, result=verify(e, t))
        assert b.result.trace_hash == t.content_hash()

    def test_a_result_for_a_different_trace_is_refused(self):
        e = envelope()
        good = verify(e, trace(separation=3000.0))
        with pytest.raises(BundleError, match="trace"):
            build_bundle(e, trace(separation=10.0), actor=ACTOR, result=good)

    def test_a_result_for_a_different_envelope_is_refused(self):
        t = trace()
        good = verify(envelope(), t)
        with pytest.raises(BundleError, match="envelope"):
            build_bundle(envelope(intrusion_distance_mm=1.0), t, actor=ACTOR,
                         result=good)

    def test_a_result_claiming_more_than_its_inputs_allow_is_refused(self):
        e, t = envelope(), trace(Provenance.SIMULATION)
        honest = verify(e, t)
        forged = replace(honest, tier=AssuranceTier.VALIDATED)
        with pytest.raises(BundleError, match="tier"):
            build_bundle(e, t, actor=ACTOR, result=forged)

    def test_a_result_naming_another_provenance_is_refused(self):
        e, t = envelope(), trace(Provenance.SIMULATION)
        forged = replace(verify(e, t), provenance="field")
        with pytest.raises(BundleError, match="provenance"):
            build_bundle(e, t, actor=ACTOR, result=forged)

    def test_a_result_naming_another_product_is_refused(self):
        e, t = envelope(), trace()
        forged = replace(verify(e, t), product_version="2")
        with pytest.raises(BundleError, match="product"):
            build_bundle(e, t, actor=ACTOR, result=forged)
