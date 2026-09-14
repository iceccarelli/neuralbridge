"""Assurance tiers.

The vocabulary that stops a demo being described as a validated system.

Each tier states the evidence that entitles a claim, and the ladder is strictly
ordered. A component sits at the highest tier whose evidence actually exists,
which in practice is usually lower than the marketing copy. That gap is the
finding, and naming it in code rather than in prose is what makes it survive
contact with a release deadline.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["AssuranceTier"]


class AssuranceTier(StrEnum):
    """What is actually known about a component, ordered weakest to strongest."""

    #: Numbers from a datasheet. No code of ours has exercised it.
    PROFILE = "profile"
    #: Passes a contract suite against a simulator or a fake. No physical run.
    COMMUNITY = "community"
    #: Exercised against the real thing, with recorded results.
    VALIDATED = "validated"
    #: Assessed by an accredited third party, with a certificate to cite.
    CERTIFIED = "certified"

    @property
    def rank(self) -> int:
        return {"profile": 0, "community": 1, "validated": 2, "certified": 3}[self.value]

    @property
    def evidence_required(self) -> str:
        return {
            "profile": "A cited datasheet or vendor specification. Nothing has been run.",
            "community": "A passing contract suite against a simulator or fake, with the run recorded.",
            "validated": "Recorded results from the physical system under stated conditions, "
            "within a declared operating envelope.",
            "certified": "A certificate from an accredited body, identified by number and scope.",
        }[self.value]

    @property
    def may_claim_physical_behaviour(self) -> bool:
        """Whether a claim about how the real hardware behaves is supportable.

        Simulation tells you about your model. It does not tell you about a
        gripper, a protective stop, or a controller's real latency.
        """
        return self.rank >= AssuranceTier.VALIDATED.rank

    @property
    def may_claim_conformity(self) -> bool:
        """Whether conformity may be asserted on a third party's authority."""
        return self is AssuranceTier.CERTIFIED

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, AssuranceTier):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, AssuranceTier):
            return NotImplemented
        return self.rank <= other.rank
