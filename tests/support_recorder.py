"""A REAL recorder, for tests of what comes *after* a recorder attestation is accepted.

Many tests pin the other inputs of the tier floor (figure bases, limits review, dates,
coverage, change cases) and need a ``validated`` verification to do it. A declared
provenance alone is capped at ``community`` (``assurance.machine.provenance_trust``), so
they need a recorder attestation that the verifier accepts. This module provides one the
honest way: it generates a throwaway Ed25519 key, signs the **actual trace** with the
production signing function, builds a :class:`RecorderTrust` that lists that key, and
hands both to the production code path (``verify``, ``build_bundle``, the HTTP route or
the CLI). Nothing is patched, no production module is imported from here by name other
than for its public API, and nothing in ``src/`` imports this file.

A throwaway key trusted by a test's own trust list proves nothing about any real recorder;
it exercises the verifier. Tests of the cap and of every refusal live in
``test_assurance_recorder_attestation.py`` and ``test_assurance_machine_provenance.py``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.attest.keys import SigningKey
from assurance.core.evidence import Actor
from assurance.machine.bundle import EvidenceBundle, build_bundle
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.recorder_attestation import (
    RecorderAttestation,
    RecorderTrust,
    TrustedRecorder,
)
from assurance.machine.trace import Trace
from assurance.machine.verify import VerificationResult, verify


class Recorder:
    """A throwaway recorder: one key, a label, and what a verifier trusts it for."""

    def __init__(self, label: str = "test recorder",
                 provenance: Sequence[str] = ("bench", "field")) -> None:
        self.key = SigningKey.generate()
        self.label = label
        self.provenance = tuple(provenance)

    @property
    def fingerprint(self) -> str:
        return self.key.fingerprint

    def trust(self, *, provenance: Sequence[str] | None = None, revoked: bool = False,
              revoked_on: str = "") -> RecorderTrust:
        """The verifier's own trust list naming this key (and only this key)."""
        return RecorderTrust([TrustedRecorder(
            label=self.label, key=self.key.verifying,
            provenance=frozenset(provenance if provenance is not None else self.provenance),
            revoked=revoked or bool(revoked_on), revoked_on=revoked_on)])

    def trust_dict(self, **kw: Any) -> dict[str, Any]:
        return self.trust(**kw).to_dict()

    def write_trust(self, path: str | Path, **kw: Any) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.trust_dict(**kw)), encoding="utf-8")
        return p

    def attest(
        self, trace: Trace, *, product: str = "Cell", product_version: str = "1.0.0",
        machine_serial: str = "", attested_on: str | None = None, expires_on: str = "",
        recorder_id: str = "REC-TEST-1", attestation_id: str = "",
    ) -> RecorderAttestation:
        """Sign ``trace`` as it is, with the production signing function."""
        on = attested_on or min(trace.started_at.date(), datetime.now(UTC).date()).isoformat()
        return RecorderAttestation.sign(
            trace, self.key, recorder_id=recorder_id, product=product,
            product_version=product_version, attested_on=on,
            machine_serial=machine_serial, expires_on=expires_on,
            attestation_id=attestation_id)

    def attest_for(self, envelope: SafetyEnvelope, trace: Trace, **kw: Any) -> RecorderAttestation:
        """Attest ``trace`` for the machine ``envelope`` describes."""
        return self.attest(trace, product=envelope.product,
                           product_version=envelope.product_version, **kw)

    def attestation_dicts(self, envelope: SafetyEnvelope, trace: Trace,
                          **kw: Any) -> list[dict[str, Any]]:
        return [self.attest_for(envelope, trace, **kw).to_dict()]

    def write_attestation(self, path: str | Path, envelope: SafetyEnvelope, trace: Trace,
                          **kw: Any) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.attest_for(envelope, trace, **kw).to_dict()),
                     encoding="utf-8")
        return p


#: One recorder shared by the tests that only need *a* trusted recorder.
RECORDER = Recorder()


def attested(envelope: SafetyEnvelope, trace: Trace, *, recorder: Recorder | None = None,
             machine_serial: str = "", **kw: Any) -> dict[str, Any]:
    """Keyword arguments for ``verify`` / ``build_bundle``: a real attestation of ``trace``
    and the verifier's trust list that accepts it."""
    rec = recorder or RECORDER
    return {
        "recorder_attestations": rec.attestation_dicts(
            envelope, trace, machine_serial=machine_serial, **kw),
        "recorder_trust": rec.trust(),
        "machine_serial": machine_serial,
    }


def verify_attested(envelope: SafetyEnvelope, trace: Trace, *, recorder: Recorder | None = None,
                    **kw: Any) -> VerificationResult:
    """``verify`` with the trace attested by a recorder the verifier trusts."""
    given = {k: kw.pop(k) for k in ("recorder_attestations", "recorder_trust") if k in kw}
    if given:
        return verify(envelope, trace, **given, **kw)
    return verify(envelope, trace, **attested(envelope, trace, recorder=recorder), **kw)


def build_attested_bundle(envelope: SafetyEnvelope, trace: Trace, *, actor: Actor,
                          recorder: Recorder | None = None, **kw: Any) -> EvidenceBundle:
    """``build_bundle`` with the trace attested by a recorder the verifier trusts.

    When the bundle is filed under a machine key (``maker/model#serial``) the recorder
    names that serial, as a recorder attached to that unit would.
    """
    if "recorder_attestations" in kw or "recorder_trust" in kw:
        return build_bundle(envelope, trace, actor=actor, **kw)
    subject = str(kw.get("subject") or "")
    serial = kw.get("machine_serial") or (subject.rpartition("#")[2] if "#" in subject else "")
    extra = attested(envelope, trace, recorder=recorder, machine_serial=serial)
    return build_bundle(envelope, trace, actor=actor, **extra, **{
        k: v for k, v in kw.items() if k != "machine_serial"})


def server_trust(monkeypatch: Any, tmp_path: Path, recorder: Recorder | None = None) -> Path:
    """Configure the hosted service's OWN recorder trust list (a file + the env var)."""
    path = (recorder or RECORDER).write_trust(tmp_path / "recorder-trust.json")
    monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(path))
    return path


def with_attestation(payload: dict[str, Any], envelope: SafetyEnvelope, trace: Trace, *,
                     recorder: Recorder | None = None, **kw: Any) -> dict[str, Any]:
    """An HTTP ``/v1/machine/verify`` payload carrying a real attestation of its trace."""
    rec = recorder or RECORDER
    return {**payload, "recorder_attestations": rec.attestation_dicts(envelope, trace, **kw)}
