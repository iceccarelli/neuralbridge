"""Stand-in for a verified recorder attestation, for tests of what comes *after* it.

No signer for trace recordings exists, so the engine never lifts a declared
provenance above ``community`` (``assurance.machine.provenance_trust``). Tests of the
code that consumes a ``validated`` verification (change cases, coverage, staleness,
passports) still need one. This helper patches the single extension point so that
``bench`` and ``field`` traces reach their own ceiling, exactly as a future verified
attestation would. It simulates that future; it is **not** evidence that a recorder
attestation works, and it must never be applied to a test of the cap itself.

``SHIM_DIR`` is for tests that run the product in a subprocess (the CLI): put it on
that process's ``PYTHONPATH`` and its ``sitecustomize`` applies the same patch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from assurance.machine import provenance_trust as pt

SHIM_DIR = str(Path(__file__).resolve().parent / "_recorder_attestation_shim")


def _attested(trace: Any) -> pt.ProvenanceAssessment:
    declared = trace.provenance
    return pt.ProvenanceAssessment(
        declared.value, pt.ProvenanceBasis.RECORDER_ATTESTED, declared.tier_ceiling,
        "TEST DOUBLE: a verified recorder attestation is assumed.")


def install() -> None:
    """Patch this process for good (a subprocess); tests use the fixture form below."""
    pt.assess_provenance = _attested  # type: ignore[assignment]
    pt.LIFTING_BASES = frozenset({pt.ProvenanceBasis.RECORDER_ATTESTED.value})


def simulate_verified_recorder_attestation(monkeypatch: Any) -> None:
    monkeypatch.setattr(pt, "assess_provenance", _attested)
    monkeypatch.setattr(
        pt, "LIFTING_BASES", frozenset({pt.ProvenanceBasis.RECORDER_ATTESTED.value}))
