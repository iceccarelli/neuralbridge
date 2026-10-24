"""Whether a trace's declared provenance may lift the tier: today it may not.

A trace says where it came from (``simulation`` / ``bench`` / ``field``) in a field
its filer writes. Nothing in this repository signs a recording, binds it to a
recorder, or lets a verifier check where it was made, so the word ``field`` on a
file is the filer's claim and carries no more weight than the ``source_system``
string beside it. A generator running on a laptop can be filed as ``field``.

So the declared provenance is **recorded and sealed, but it does not raise the
tier**. A verification over a trace whose provenance is only declared is capped at
``community`` (or lower, if the envelope's figures cap it lower): the engine can
say the recorded samples stayed inside the declared envelope, and cannot say the
samples came from a machine.

This module is the single extension point, mirroring
:mod:`assurance.machine.limits_review`: a future *signed recorder attestation*,
assessed against a trust list the verifier holds and the filer cannot supply, would
return a different :class:`ProvenanceBasis` from :func:`assess_provenance` and
register it in :data:`LIFTING_BASES`; the bundle checker already asks that set
(``bundle._provenance_lifts_tier``, reading this module's names at call time)
before it believes a ``validated`` tier. No signer exists yet, so :data:`LIFTING_BASES` is empty and no bundle can carry a
``validated`` machine verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from assurance.core.tiers import AssuranceTier
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
    #: Reserved for a verified signed recorder attestation. **Nothing produces it
    #: yet** and it is not in :data:`LIFTING_BASES`; tests stand in for the future
    #: verifier by patching this module (``tests/support_recorder_attestation.py``).
    RECORDER_ATTESTED = "recorder_attested"


#: The bases that let a declared provenance reach its own ceiling (``validated``
#: for bench and field). Empty on purpose: add a basis here only together with the
#: code that verifies the attestation it stands for, and bump ``ENGINE_VERSION``.
LIFTING_BASES: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ProvenanceAssessment:
    """What the trace's provenance is worth to the tier. Sealed into the bundle."""

    declared: str
    basis: ProvenanceBasis
    #: The highest tier this assessment lets the trace reach on its own.
    ceiling: AssuranceTier
    explanation: str

    @property
    def lifts_tier(self) -> bool:
        return self.basis.value in LIFTING_BASES

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared": self.declared,
            "basis": self.basis.value,
            "ceiling": self.ceiling.value,
            "lifts_tier": self.lifts_tier,
            "explanation": self.explanation,
        }


def assess_provenance(trace: Trace) -> ProvenanceAssessment:
    """The tier ceiling the trace's provenance earns. Computed, never passed in."""
    declared = trace.provenance
    if declared.value == "simulation":
        return ProvenanceAssessment(
            declared.value, ProvenanceBasis.DECLARED_BY_FILER, AssuranceTier.COMMUNITY,
            "the trace declares itself a simulation; a simulation never exceeds "
            "'community'.")
    return ProvenanceAssessment(
        declared.value, ProvenanceBasis.DECLARED_BY_FILER, AssuranceTier.COMMUNITY,
        f"the trace declares provenance {declared.value!r}, stated by whoever filed it "
        f"(source_system {trace.source_system!r}, also their text). Nothing here signs a "
        "recording or independently verifies the recorder, so a declared provenance "
        "cannot lift the tier: the result is capped at 'community' and may not be used "
        "to claim how the hardware behaves. A signed recorder attestation checked "
        "against a trust list the verifier holds is the only route above that cap, and "
        "none exists yet.")
