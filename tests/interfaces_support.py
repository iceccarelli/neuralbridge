"""Shared inputs for the cross-interface tests (``tests/test_interfaces_*.py``).

Deliberately free of a ``pytest`` import, like :mod:`tests.support`.
"""

from __future__ import annotations

from datetime import datetime

from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace

__all__ = ["envelope", "envelope_dict", "trace", "trace_dict"]


def envelope_dict() -> dict:
    return envelope().to_dict()


def trace_dict(when: datetime, *, trace_id: str = "") -> dict:
    """The JSON a controller export would be, as ``Trace.from_dict`` reads it."""
    return trace(when, trace_id=trace_id).hashable_payload()


def envelope() -> SafetyEnvelope:
    return SafetyEnvelope(
        envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-11", "2026-01-18")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "CAL-003")),
        intrusion_distance_mm=850.0)


def trace(when: datetime, *, trace_id: str = "") -> Trace:
    """A passing field run that started at ``when``."""
    return Trace(
        trace_id=trace_id or f"RUN-{when:%Y%m%d%H%M%S}", provenance=Provenance.FIELD,
        source_system="AR-7 fw", started_at=when, sample_rate_hz=50.0,
        samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=400.0,
                             mode=OperatingMode.SSM, separation=2200.0)
                      for i in range(10)))
