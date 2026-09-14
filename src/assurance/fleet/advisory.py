"""Component advisories, and what it actually takes to match one to a machine.

A robot cell is assembled from other people's software. The robot controller is
one supplier's, the safety scanner another's, the safety PLC a third's. Each
publishes advisories to a mailing list. The integrator who took the CE liability
for the assembly receives them, and has no way on earth to answer the only
question that matters: *which of my machines, in which of my customers' plants,
is running the affected version?*

Matching is where this goes wrong, and the failure is always the same: a version
label is not an artefact. :mod:`assurance.machinery` already proves that a
firmware can be replaced without the version string moving. So an advisory is
matched on the strongest evidence available and the basis is reported, never
flattened:

``hash``
    The artefact on the machine is byte-identical to one the supplier named.
    There is nothing to argue about.

``hash_mismatch``
    The machine reports a version the advisory names, and the artefact does
    **not** hash to what the supplier published for that version. Either the
    supplier's figure is wrong or the machine is not running what it says. Both
    are serious and neither is "affected" or "not affected" — this is its own
    finding, and no other system on the market can produce it.

``version``
    The supplier, name and version label match. The supplier published no hash,
    so this rests on a label.

``name_only``
    Same supplier and component, version unknown or not listed. A human has to
    look.

No version-range arithmetic. Vendor version schemes are not semver, parsing them
as if they were is how a cell gets cleared that should have been stopped, and an
advisory that means "everything before 3.9" can enumerate the versions it means.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import content_hash_of, format_utc, parse_utc
from assurance.machinery.manifest import SafetyItem

__all__ = [
    "AdvisoryError",
    "AdvisorySeverity",
    "AffectedArtefact",
    "ComponentAdvisory",
    "MatchBasis",
    "match_item",
]


class AdvisoryError(AssuranceError):
    """An advisory is malformed, or identifies nothing it could be matched on."""


class AdvisorySeverity(StrEnum):
    #: Worth knowing. Does not by itself put a safety function in question.
    INFORMATIONAL = "informational"
    #: The supplier says a safety function may be compromised.
    SAFETY_RELEVANT = "safety_relevant"
    #: The supplier says the machine should not run until it is remedied.
    STOP_USE = "stop_use"

    @property
    def rank(self) -> int:
        return {"informational": 0, "safety_relevant": 1, "stop_use": 2}[self.value]

    @property
    def puts_functions_in_question(self) -> bool:
        return self.rank >= AdvisorySeverity.SAFETY_RELEVANT.rank


class MatchBasis(StrEnum):
    """What the match rests on. Never flattened into a boolean."""

    HASH = "hash"
    HASH_MISMATCH = "hash_mismatch"
    VERSION = "version"
    NAME_ONLY = "name_only"

    @property
    def confidence(self) -> str:
        return {
            "hash": "confirmed",
            "hash_mismatch": "contradictory",
            "version": "probable",
            "name_only": "possible",
        }[self.value]

    @property
    def needs_a_human(self) -> bool:
        return self in (MatchBasis.HASH_MISMATCH, MatchBasis.NAME_ONLY)


@dataclass(frozen=True)
class AffectedArtefact:
    """One component version set an advisory names.

    ``content_hashes`` is what a supplier should publish and mostly does not.
    When they do, the match is beyond argument; when they do not, the advisory
    still works on labels and every downstream statement says so.
    """

    supplier: str
    name: str
    versions: tuple[str, ...] = ()
    content_hashes: tuple[str, ...] = ()
    #: Free text where the supplier expressed a range. Displayed, never parsed.
    version_note: str = ""

    def __post_init__(self) -> None:
        if not self.supplier or not self.name:
            raise AdvisoryError(
                "an affected artefact needs a supplier and a component name; "
                "without both it cannot be matched to anything."
            )
        if not self.versions and not self.content_hashes:
            raise AdvisoryError(
                f"{self.supplier} {self.name}: the advisory names neither a version "
                "nor a hash, so it would match every version of this component ever "
                "shipped. List the affected versions, or the hashes."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "supplier": self.supplier, "name": self.name,
            "versions": list(self.versions),
            "content_hashes": list(self.content_hashes),
            "version_note": self.version_note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AffectedArtefact:
        return cls(
            supplier=str(d["supplier"]), name=str(d["name"]),
            versions=tuple(str(v) for v in (d.get("versions") or ())),
            content_hashes=tuple(str(h) for h in (d.get("content_hashes") or ())),
            version_note=str(d.get("version_note", "")),
        )


@dataclass(frozen=True)
class ComponentAdvisory:
    """A supplier's statement that a component version is affected.

    The advisory deliberately does **not** name the customer's safety functions.
    It cannot know them. It says what is affected and whether the matter is
    safety-relevant; which of *this* customer's functions are put in question is
    derived from *their* manifest, which is the only place that mapping honestly
    lives.
    """

    advisory_id: str
    issued_by: str
    issued_at: datetime
    title: str
    summary: str
    severity: AdvisorySeverity
    affected: tuple[AffectedArtefact, ...]
    remedy: str = ""
    #: Where a reader goes to check this against the source.
    reference: str = ""
    #: Versions or hashes the supplier says are not affected.
    fixed_versions: tuple[str, ...] = ()
    fixed_hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.advisory_id or not self.issued_by:
            raise AdvisoryError("an advisory needs an id and an issuer.")
        if not self.affected:
            raise AdvisoryError(
                f"advisory {self.advisory_id!r} names no affected artefact."
            )
        if self.issued_at.tzinfo is None:
            raise AdvisoryError(
                f"advisory {self.advisory_id!r} issued_at has no timezone.")
        if not self.reference:
            raise AdvisoryError(
                f"advisory {self.advisory_id!r} carries no reference. An advisory a "
                "reader cannot trace to its source is a rumour."
            )

    @property
    def publishes_hashes(self) -> bool:
        return any(a.content_hashes for a in self.affected)

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "issued_by": self.issued_by,
            "issued_at": format_utc(self.issued_at),
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity.value,
            "affected": [a.to_dict() for a in self.affected],
            "remedy": self.remedy,
            "reference": self.reference,
            "fixed_versions": list(self.fixed_versions),
            "fixed_hashes": list(self.fixed_hashes),
        }

    def content_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ComponentAdvisory:
        return cls(
            advisory_id=str(d["advisory_id"]),
            issued_by=str(d["issued_by"]),
            issued_at=parse_utc(str(d["issued_at"])),
            title=str(d.get("title", "")),
            summary=str(d.get("summary", "")),
            severity=AdvisorySeverity(str(d["severity"])),
            affected=tuple(AffectedArtefact.from_dict(a) for a in d["affected"]),
            remedy=str(d.get("remedy", "")),
            reference=str(d.get("reference", "")),
            fixed_versions=tuple(str(v) for v in (d.get("fixed_versions") or ())),
            fixed_hashes=tuple(str(h) for h in (d.get("fixed_hashes") or ())),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> ComponentAdvisory:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _same_component(artefact: AffectedArtefact, item: SafetyItem) -> bool:
    """Supplier and component name, compared case-insensitively and trimmed.

    Deliberately not fuzzy. "ControlCo" and "Control Co GmbH" are different
    strings, and guessing they are the same supplier is how an advisory silently
    fails to match, or matches something it should not.
    """
    return (artefact.supplier.strip().lower() == item.supplier.strip().lower()
            and artefact.name.strip().lower() == item.name.strip().lower())


def match_item(
    advisory: ComponentAdvisory, item: SafetyItem,
) -> tuple[MatchBasis, str] | None:
    """Does this advisory touch this item? Returns ``(basis, detail)`` or ``None``.

    The order of evidence is fixed: a hash that matches settles it; a version
    label that matches while the hash contradicts the supplier's published value
    is its own finding and outranks a plain label match.
    """
    for artefact in advisory.affected:
        if not _same_component(artefact, item):
            continue

        if item.content_hash and item.content_hash in artefact.content_hashes:
            return MatchBasis.HASH, (
                f"the artefact on this machine is byte-identical to one "
                f"{advisory.issued_by} named as affected "
                f"({item.content_hash[:12]})."
            )

        label_matches = item.version and item.version in artefact.versions

        if label_matches and artefact.content_hashes and item.content_hash:
            # The supplier published hashes for this version and ours is not
            # among them. This is not "affected" and not "clear".
            if item.content_hash in advisory.fixed_hashes:
                return MatchBasis.HASH_MISMATCH, (
                    f"this machine reports version {item.version!r}, which the "
                    f"advisory names, but the artefact hashes to a value "
                    f"{advisory.issued_by} lists as FIXED "
                    f"({item.content_hash[:12]}). The label is stale; the software "
                    "may already be remedied. Confirm before acting."
                )
            return MatchBasis.HASH_MISMATCH, (
                f"this machine reports version {item.version!r}, which the advisory "
                f"names, but the artefact hashes to {item.content_hash[:12]}, which "
                f"is not among the hashes {advisory.issued_by} published for that "
                "version. Either the supplier's figure is wrong or this machine is "
                "not running what it says it is running. Both need a person."
            )

        if label_matches:
            return MatchBasis.VERSION, (
                f"the version label {item.version!r} matches one the advisory names. "
                f"{advisory.issued_by} published no artefact hash, so this rests on "
                "a label, and a label is not an artefact."
            )

        if item.content_hash and item.content_hash in advisory.fixed_hashes:
            continue  # demonstrably remedied

        if item.version and (artefact.versions or advisory.fixed_versions):
            if item.version in advisory.fixed_versions:
                continue  # the supplier says this version is fixed
            continue  # a known version that is not on the affected list

        return MatchBasis.NAME_ONLY, (
            f"this is {artefact.supplier} {artefact.name}, which the advisory "
            "concerns, but the version on this machine is "
            + (f"{item.version!r}, which the advisory does not list"
               if item.version else "not recorded")
            + ". Somebody has to look."
        )

    return None
