"""What a trace's declared provenance is worth to the tier.

A trace says where it came from (``simulation`` / ``bench`` / ``field``) in a field
its filer writes. By itself that word is the filer's claim and carries no more weight
than the ``source_system`` string beside it: a generator running on a laptop can be
filed as ``field``. So a **declared** provenance is recorded and sealed but does not
raise the tier: a verification over it is capped at ``community`` (or lower, if the
envelope's figures cap it lower).

The one route above that cap is a **signed recorder attestation**
(:mod:`assurance.machine.recorder_attestation`) assessed against a recorder trust list
that the *verifier* holds and the filer cannot supply. :func:`assess_provenance` runs
that assessment. Only an ``accepted`` attestation changes the basis to
``recorder_attested`` and lets the trace reach its own declared ceiling (``validated``
for bench and field, still subject to the envelope's and the limits review's caps via
``min()``; a simulation stays at ``community``). It proves a statement was signed by a
trusted key over these exact trace bytes; it does not prove the recording is physically
true (see that module for the full list of what is and is not established).

No caller-supplied word elevates a tier on its own: not ``provenance``, not
``source_system``, not a timestamp, and not a ``provenance_basis`` written into a
bundle body.

:data:`LIFTING_BASES` names the bases that *may* lift. It is not a static
allow-list of bundles: a bundle's recorded basis is believed only if the checker's
**own** re-assessment (``bundle`` replay, under the checker's trust list and today's
date) reproduces ``recorder_attested`` for the same attestation hash. A bundle that
claims it with no trust list to check it against is treated as ``declared_by_filer``
and reported as unverifiable, never as valid. (Before engine 6 this set was empty on
purpose, because nothing could be verified; engine 5 and earlier bundles can never be
read as recorder-attested.)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from assurance.core.tiers import AssuranceTier
from assurance.machine.recorder_attestation import (
    MachineRef,
    RecorderAttestationAssessment,
    RecorderTrust,
    assess_recorder_attestation,
)
from assurance.machine.trace import Trace

__all__ = [
    "LIFTING_BASES",
    "ProvenanceAssessment",
    "ProvenanceBasis",
    "assess_provenance",
]


class ProvenanceBasis(StrEnum):
    """Why the trace's provenance is believed to the extent it is."""

    #: The filer wrote it. Nothing independent supports it. Never lifts the tier.
    DECLARED_BY_FILER = "declared_by_filer"
    #: A signed recorder attestation was accepted under the verifier's own trust list.
    RECORDER_ATTESTED = "recorder_attested"


#: The bases that can let a declared provenance reach its own ceiling (``validated`` for
#: bench and field). Membership is necessary, not sufficient: ``assess_provenance``
#: assigns the basis only for an accepted attestation, and the bundle checker believes a
#: recorded one only if it re-assesses to the same attestation under its own trust.
LIFTING_BASES: frozenset[str] = frozenset({ProvenanceBasis.RECORDER_ATTESTED.value})


@dataclass(frozen=True)
class ProvenanceAssessment:
    """What the trace's provenance is worth to the tier. Sealed into the bundle."""

    declared: str
    basis: ProvenanceBasis
    #: The highest tier this assessment lets the trace reach on its own.
    ceiling: AssuranceTier
    explanation: str
    attestation: RecorderAttestationAssessment | None = None

    @property
    def lifts_tier(self) -> bool:
        return self.basis.value in LIFTING_BASES

    def to_dict(self) -> dict[str, Any]:
        att = self.attestation
        return {
            "declared": self.declared,
            "basis": self.basis.value,
            "ceiling": self.ceiling.value,
            "lifts_tier": self.lifts_tier,
            "attestation_hash": att.attestation_hash if att else "",
            "key_fingerprint": att.key_fingerprint if att else "",
            "explanation": self.explanation,
        }


def assess_provenance(
    trace: Trace,
    attestations: Iterable[Any] = (),
    trust: RecorderTrust | None = None,
    *,
    machine_ref: MachineRef | None = None,
    now: datetime | None = None,
) -> ProvenanceAssessment:
    """The tier ceiling the trace's provenance earns. Computed, never passed in.

    Without ``machine_ref`` no attestation can be matched to a machine, so none is
    accepted; :func:`assurance.machine.verify.verify` always supplies the envelope's.
    """
    declared = trace.provenance
    assessment = assess_recorder_attestation(
        trace, attestations, trust, machine_ref=machine_ref or MachineRef("", ""),
        now=now)

    if declared.value == "simulation":
        return ProvenanceAssessment(
            declared.value, ProvenanceBasis.DECLARED_BY_FILER, AssuranceTier.COMMUNITY,
            "the trace declares itself a simulation; a simulation never exceeds "
            "'community', and no recorder attestation lifts it.", assessment)
    if assessment.attested:
        return ProvenanceAssessment(
            declared.value, ProvenanceBasis.RECORDER_ATTESTED, declared.tier_ceiling,
            assessment.explanation, assessment)
    return ProvenanceAssessment(
        declared.value, ProvenanceBasis.DECLARED_BY_FILER, AssuranceTier.COMMUNITY,
        f"the trace declares provenance {declared.value!r}, stated by whoever filed it "
        f"(source_system {trace.source_system!r}, also their text). Recorder "
        f"attestation: {assessment.explanation} A declared provenance cannot lift the "
        "tier: the result is capped at 'community' and may not be used to claim how the hardware "
        "behaves. The route above that cap is a signed recorder attestation accepted "
        "under a recorder trust list the verifier holds (assurance.machine."
        "recorder_attestation); it still proves only that a trusted key signed these "
        "trace bytes, not that the recording is physically true.", assessment)
