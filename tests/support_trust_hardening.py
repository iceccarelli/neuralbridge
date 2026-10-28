"""Builders for the trust-hardening regression tests (unit binding, unassessed, tier honesty).

Everything goes through the production code paths: real sealed bundles
(:func:`assurance.machine.bundle.build_bundle`), real recorder attestations signed by a
throwaway key (``tests/support_recorder.py``), real SQLite ledgers. Nothing here mocks the
verification logic the tests are about, and nothing in ``src/`` imports this file.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.core.evidence import Actor, Evidence
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import EvidenceBundle, build_bundle
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)

from .support_recorder import Recorder
from .test_assurance_machine_provenance import ACTOR, envelope, laptop_trace

KEY = "Acme/AR-7#0001"
CHECKS = ("workspace_containment", "speed_limit")
FW = "a" * 64


def manifest(
    maker: str = "Acme", model: str = "AR-7", serial: str = "0001", *,
    functions: bool = True, checks: tuple[str, ...] = CHECKS, fw: str = FW,
    taken: datetime = datetime(2026, 9, 13, tzinfo=UTC),
) -> SafetyManifest:
    return SafetyManifest(
        manifest_id=f"M-{maker}-{model}-{serial}",
        machine=MachineIdentity(maker, model, serial),
        source=ManifestSource.AS_FOUND, taken_at=taken, taken_by=Actor("t", "tech"),
        items=(SafetyItem("fw", ItemKind.FIRMWARE, "fw", "1", fw,
                          HashSource.READ_FROM_MACHINE,
                          implements=("SF-1",) if functions else ()),),
        functions=((SafetyFunction("SF-1", "safe stop", verified_by=checks),)
                   if functions else ()),
    )


def ledger(tmp_path: Path, name: str = "ledger.db") -> EvidenceLedger:
    return EvidenceLedger(tmp_path / name)


def serial_of(unit_key: str) -> str:
    return unit_key.partition("#")[2]


def attested_bundle(
    unit_key: str, *, attest_serial: str | None = None, rec: Recorder | None = None,
    trace: Trace | None = None, file_under: EvidenceLedger | None = None,
) -> tuple[EvidenceBundle, Recorder]:
    """A bundle sealed FOR ``unit_key`` on a recording a trusted recorder attested.

    ``attest_serial`` defaults to the key's own serial (the honest case).
    """
    env, tr = envelope(), trace or laptop_trace()
    rec = rec or Recorder()
    att = rec.attest_for(
        env, tr, machine_serial=serial_of(unit_key) if attest_serial is None
        else attest_serial).to_dict()
    bundle = build_bundle(
        env, tr, actor=ACTOR, recorder_attestations=[att], recorder_trust=rec.trust(),
        subject=unit_key, ledger=file_under)
    return bundle, rec


def legacy_bundle(serial: str, *, rec: Recorder | None = None,
                  trace: Trace | None = None) -> tuple[EvidenceBundle, Recorder]:
    """A bundle as sealed before the unit key was recorded: bound to a serial only.

    Built honestly through ``build_bundle`` with a product-line subject and an explicit
    ``machine_serial``; it carries no maker/model.
    """
    env, tr = envelope(), trace or laptop_trace()
    rec = rec or Recorder()
    att = rec.attest_for(env, tr, machine_serial=serial).to_dict()
    bundle = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[att],
                          recorder_trust=rec.trust(), machine_serial=serial)
    return bundle, rec


def community_bundle(unit_key: str, trace: Trace | None = None,
                     file_under: EvidenceLedger | None = None) -> EvidenceBundle:
    """A bundle whose provenance the filer merely declared (tier community)."""
    return build_bundle(envelope(), trace or laptop_trace(), actor=ACTOR,
                        subject=unit_key, ledger=file_under)


def reseal_body(evidence: Evidence, **changes: Any) -> Evidence:
    """What an editor of the ledger file can do: change the body and recompute the hash."""
    return replace(evidence, body={**evidence.body, **changes}, content_hash="").seal()


def trace_in_modes(modes: tuple[OperatingMode, ...], *, speed: float = 300.0,
                   trace_id: str = "RUN-MODES", n: int = 20,
                   started_at: datetime = datetime(2026, 9, 12, 4, 31, tzinfo=UTC),
                   provenance: Provenance = Provenance.FIELD) -> Trace:
    """A trace whose samples cycle through ``modes`` (the envelope limits only SSM speed)."""
    return Trace(
        trace_id=trace_id, provenance=provenance, source_system="controller fw 1.0",
        started_at=started_at, sample_rate_hz=50.0,
        samples=tuple(
            Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=speed,
                   mode=modes[i % len(modes)], separation=3000.0)
            for i in range(n)))


def seal_fleet(led: EvidenceLedger, n: int, rec: Recorder | None = None, *, maker: str = "Acme",
               model: str = "AR-7") -> Recorder:
    """``n`` enrolled units, each with its own recording attested by one trusted recorder and a
    bundle sealed for its own unit key (the shape of a real fleet ledger)."""
    from dataclasses import replace as _replace

    from assurance.machinery.record import record_manifest

    rec = rec or Recorder()
    env, base = envelope(), laptop_trace()
    for i in range(n):
        serial = f"{i:05d}"
        key = f"{maker}/{model}#{serial}"
        trace = _replace(base, trace_id=f"RUN-{serial}")
        att = rec.attest_for(env, trace, machine_serial=serial).to_dict()
        record_manifest(led, manifest(maker, model, serial), actor=Actor("t", "tech"))
        build_bundle(env, trace, actor=ACTOR, recorder_attestations=[att],
                     recorder_trust=rec.trust(), subject=key, ledger=led)
    return rec
