"""The evidence object.

Everything this system records is an evidence object, and every evidence object
carries the same seven facts: what it is, when, who, where it came from, what
state of validation it is in, how sure we are, and what it is linked to.

The uniformity is the point. A perception record from a robot cell, a test
result, a vulnerability triage decision and a regulatory filing are different
subjects with the same shape, so one ledger holds them, one query traverses
them, and one report renders them.

Two disciplines are enforced here rather than left to callers:

* **Sealing.** An evidence object is immutable once sealed, and its identity is
  the hash of its content. Amending a record means superseding it, which leaves
  both versions in the chain.
* **Declared gaps.** ``checks_skipped`` is a required part of every validated
  object. "Here is what I did not verify" is the sentence an auditor actually
  wants, and a system that cannot say it is claiming more than it knows.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from .errors import EvidenceIncompleteError, SealedObjectError
from .identity import content_hash_of, format_utc, utc_now

__all__ = [
    "Actor",
    "Confidence",
    "Evidence",
    "EvidenceObject",
    "EvidenceRef",
    "Origin",
    "ValidationState",
]


class ValidationState(StrEnum):
    """How far an object has got through verification.

    The vocabulary is deliberately unable to express "probably fine".
    """

    #: Recorded, nothing checked. The honest state for raw intake.
    UNVERIFIED = "unverified"
    #: Checked and consistent.
    VERIFIED = "verified"
    #: Checked and found wrong. Kept, never deleted.
    REFUTED = "refuted"
    #: Checks ran but could not reach a verdict; ``checks_skipped`` says why.
    INDETERMINATE = "indeterminate"
    #: Superseded by a later object that names this one as its predecessor.
    SUPERSEDED = "superseded"

    @property
    def is_dependable(self) -> bool:
        """True only for VERIFIED. Everything else is a reason to look closer."""
        return self is ValidationState.VERIFIED


class Confidence(StrEnum):
    """Qualitative confidence, used only where a number would be invented.

    A calibrated probability is better than this and should be used when one
    genuinely exists. Most of the time one does not, and a fabricated 0.92 is
    worse than an honest label.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ESTABLISHED = "established"


@dataclass(frozen=True)
class Actor:
    """Who did the thing. A person, a service, or a piece of automation.

    ``role`` matters more than ``name`` for an audit: "who was entitled to make
    this call" is the question, and an unattributed decision is a finding.
    """

    identifier: str
    role: str = ""
    kind: str = "person"  # person | service | automation

    def to_dict(self) -> dict[str, Any]:
        return {"identifier": self.identifier, "role": self.role, "kind": self.kind}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Actor:
        return cls(
            identifier=str(d["identifier"]),
            role=str(d.get("role", "")),
            kind=str(d.get("kind", "person")),
        )

    def __str__(self) -> str:
        return f"{self.identifier} ({self.role})" if self.role else self.identifier


@dataclass(frozen=True)
class Origin:
    """Where the fact came from, in enough detail to go back and check.

    ``system`` is the producing component, ``reference`` is the pointer a human
    follows (a ticket, an advisory URL, a test run id), and ``method`` is how
    the fact was obtained. A record whose origin is empty is hearsay.
    """

    system: str
    reference: str = ""
    method: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"system": self.system, "reference": self.reference, "method": self.method}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Origin:
        return cls(
            system=str(d["system"]),
            reference=str(d.get("reference", "")),
            method=str(d.get("method", "")),
        )


@dataclass(frozen=True)
class EvidenceRef:
    """A typed edge to another evidence object.

    Relationships are named, not implied by position, so a graph traversal can
    answer "what supersedes this" without knowing the subject domain.
    """

    relation: str          # supersedes | supports | refutes | derived_from | concerns | filed_as
    content_hash: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"relation": self.relation, "content_hash": self.content_hash, "note": self.note}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EvidenceRef:
        return cls(
            relation=str(d["relation"]),
            content_hash=str(d["content_hash"]),
            note=str(d.get("note", "")),
        )


@runtime_checkable
class EvidenceObject(Protocol):
    """What every piece of evidence must be able to say about itself.

    Structural, not nominal: a type satisfies this by having the attributes,
    which lets existing artifacts in other packages qualify without inheriting
    from anything here. That is the whole point of the protocol — a plan
    artifact produced by a planning engine becomes evidence without being
    rewritten to know about this package.
    """

    kind: str
    content_hash: str
    recorded_at: datetime
    actor: Actor
    origin: Origin
    validation_state: ValidationState
    checks_skipped: tuple[str, ...]
    relations: tuple[EvidenceRef, ...]

    def hashable_payload(self) -> dict[str, Any]: ...
    def to_dict(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Evidence:
    """The concrete, general-purpose evidence object.

    ``body`` carries the subject-specific facts. Everything outside ``body`` is
    the same for every subject, which is what makes one ledger and one report
    renderer sufficient.
    """

    kind: str
    body: dict[str, Any]
    actor: Actor
    origin: Origin
    validation_state: ValidationState = ValidationState.UNVERIFIED
    confidence: Confidence = Confidence.NONE
    checks_skipped: tuple[str, ...] = ()
    relations: tuple[EvidenceRef, ...] = ()
    schema_version: str = "1"

    #: Not hashed. Recorded for support, never for identity — otherwise two
    #: identical facts recorded a second apart would have different identities.
    recorded_at: datetime = field(default_factory=utc_now, compare=False)
    #: Set by :meth:`seal`. Empty means the object has not been sealed.
    content_hash: str = field(default="", compare=False)

    # -- identity ---------------------------------------------------------
    def hashable_payload(self) -> dict[str, Any]:
        """The fields that constitute this object's identity.

        ``recorded_at`` and ``content_hash`` are excluded by construction.
        """
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "body": self.body,
            "actor": self.actor.to_dict(),
            "origin": self.origin.to_dict(),
            "validation_state": self.validation_state.value,
            "confidence": self.confidence.value,
            "checks_skipped": list(self.checks_skipped),
            "relations": [r.to_dict() for r in self.relations],
        }

    def compute_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def seal(self) -> Evidence:
        """Return this object with its content hash fixed.

        Sealing twice is an error rather than a no-op: it almost always means
        a caller mutated a sealed object and is about to record the old hash
        against new content.
        """
        if self.content_hash:
            raise SealedObjectError(
                f"{self.kind} evidence {self.content_hash[:12]} is already sealed. "
                "Use supersede() to record a change."
            )
        if not self.actor.identifier:
            raise EvidenceIncompleteError(
                f"{self.kind} evidence has no actor. An unattributed record is not evidence."
            )
        if not self.origin.system:
            raise EvidenceIncompleteError(
                f"{self.kind} evidence has no origin. A fact with no source is hearsay."
            )
        return replace(self, content_hash=self.compute_hash())

    @property
    def is_sealed(self) -> bool:
        return bool(self.content_hash)

    def verify(self) -> bool:
        """True when the recorded hash still matches the content."""
        return bool(self.content_hash) and self.content_hash == self.compute_hash()

    def supersede(self, **changes: Any) -> Evidence:
        """Produce a successor that points back at this object.

        The predecessor is not modified and not removed. An evidence chain in
        which a record can vanish is not evidence.
        """
        if not self.content_hash:
            raise SealedObjectError("cannot supersede an unsealed object; seal it first")
        relations = (
            *changes.pop("relations", ()),
            EvidenceRef(relation="supersedes", content_hash=self.content_hash),
        )
        successor = replace(
            self,
            content_hash="",
            recorded_at=utc_now(),
            relations=relations,
            **changes,
        )
        return successor.seal()

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = self.hashable_payload()
        d["recorded_at"] = format_utc(self.recorded_at)
        d["content_hash"] = self.content_hash
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Evidence:
        from .identity import parse_utc

        obj = cls(
            kind=str(d["kind"]),
            body=dict(d.get("body", {})),
            actor=Actor.from_dict(d["actor"]),
            origin=Origin.from_dict(d["origin"]),
            validation_state=ValidationState(d.get("validation_state", "unverified")),
            confidence=Confidence(d.get("confidence", "none")),
            checks_skipped=tuple(d.get("checks_skipped", ())),
            relations=tuple(EvidenceRef.from_dict(r) for r in d.get("relations", ())),
            schema_version=str(d.get("schema_version", "1")),
            recorded_at=parse_utc(d["recorded_at"]) if d.get("recorded_at") else utc_now(),
            content_hash=str(d.get("content_hash", "")),
        )
        return obj

    def summary(self) -> str:
        gaps = f" | {len(self.checks_skipped)} check(s) skipped" if self.checks_skipped else ""
        return (
            f"{self.content_hash[:12] or '<unsealed>'} {self.kind} "
            f"[{self.validation_state.value}] by {self.actor}{gaps}"
        )
