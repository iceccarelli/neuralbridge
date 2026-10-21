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
import unicodedata
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
    "fold_hash",
    "fold_text",
    "match_item",
]


class AdvisoryError(AssuranceError):
    """An advisory is malformed, or identifies nothing it could be matched on."""


def fold_text(text: str) -> str:
    """The form in which two names or version labels are compared.

    Unicode compatibility-normalised, case-folded, with every run of whitespace
    (including a non-breaking space) reduced to one space and the ends trimmed.
    That is *identity of the same string in different dress* — composed against
    decomposed accents, ``ß`` against ``SS``, full-width letters, a trailing tab
    from a spreadsheet. It is not similarity: ``ControlCo`` and ``Control Co
    GmbH`` stay different, and so do strings that differ by an invisible
    character. An advisory that fails to match because of encoding clears a cell
    that should have been stopped; one that matches too eagerly costs a
    person ten minutes.
    """
    form = unicodedata.normalize("NFKC", text)
    form = " ".join(form.split()).casefold()
    return unicodedata.normalize("NFKC", form)


def fold_hash(text: str) -> str:
    """A content hash for comparison: trimmed, lower-cased, ``sha256:`` prefix dropped.

    Exact otherwise. A prefix of a hash is *not* the hash, and nothing here
    compares on one.
    """
    h = text.strip().lower()
    if h.startswith("sha256:"):
        h = h[len("sha256:"):].strip()
    return h


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
        if not fold_text(self.supplier) or not fold_text(self.name):
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
        if any(not fold_text(v) for v in self.versions) or any(
                not fold_hash(h) for h in self.content_hashes):
            raise AdvisoryError(
                f"{self.supplier} {self.name}: an affected version or hash is empty. "
                "A blank entry is not a value; it would read as 'a version nobody "
                "recorded' and match accordingly."
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
        if any(not fold_text(v) for v in self.fixed_versions) or any(
                not fold_hash(h) for h in self.fixed_hashes):
            raise AdvisoryError(
                f"advisory {self.advisory_id!r} lists an empty fixed version or hash. "
                "A blank 'fixed' entry would read as demonstrably remedied."
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
    """Supplier and component name, compared as :func:`fold_text` folds them.

    Deliberately not fuzzy. "ControlCo" and "Control Co GmbH" are different
    strings, and guessing they are the same supplier is how an advisory silently
    fails to match, or matches something it should not.
    """
    return (fold_text(artefact.supplier) == fold_text(item.supplier)
            and fold_text(artefact.name) == fold_text(item.name))


def _same_component_unknown_supplier(artefact: AffectedArtefact, item: SafetyItem) -> bool:
    """The component name matches and the item records no supplier at all.

    Neither affected nor clear: the advisory is about this component from a
    named supplier, and the machine does not say who made it.
    """
    return (not fold_text(item.supplier)
            and fold_text(artefact.name) == fold_text(item.name))


#: Strongest evidence first. When one advisory has several entries for the same
#: component, the answer is the strongest basis any of them supports, so the
#: order in which a supplier happened to list them cannot change it.
_PRIORITY = {MatchBasis.HASH: 0, MatchBasis.HASH_MISMATCH: 1, MatchBasis.VERSION: 2,
             MatchBasis.NAME_ONLY: 3}


def _match_artefact(
    advisory: ComponentAdvisory, artefact: AffectedArtefact, item: SafetyItem,
) -> tuple[MatchBasis, str] | None:
    if not _same_component(artefact, item):
        if _same_component_unknown_supplier(artefact, item):
            return MatchBasis.NAME_ONLY, (
                f"this is a {item.name!r} with no supplier recorded, and the advisory "
                f"concerns {artefact.supplier}'s {artefact.name}. The machine does "
                "not say who made it, so this can be neither confirmed nor cleared. "
                "Somebody has to look."
            )
        return None

    versions = {fold_text(v) for v in artefact.versions}
    affected_hashes = {fold_hash(h) for h in artefact.content_hashes}
    fixed_hashes = {fold_hash(h) for h in advisory.fixed_hashes}
    fixed_versions = {fold_text(v) for v in advisory.fixed_versions}
    label = fold_text(item.version)

    # A hash is evidence about this machine only if it was read from this
    # machine. One computed from a vendor's download, or typed in, says what
    # should be here, not what is.
    recorded = fold_hash(item.content_hash)
    machine_hash = recorded if item.hash_source.describes_this_unit else ""
    set_aside = (
        f" The hash recorded for it ({recorded[:12]}, {item.hash_source.value}) was "
        "not read from this machine, so it was not compared."
        if recorded and not machine_hash else ""
    )

    if machine_hash and machine_hash in affected_hashes:
        return MatchBasis.HASH, (
            f"the artefact on this machine is byte-identical to one "
            f"{advisory.issued_by} named as affected ({machine_hash[:12]})."
        )

    label_matches = bool(label) and label in versions

    if label_matches and machine_hash and (
            affected_hashes or machine_hash in fixed_hashes):
        # The label says affected and the artefact disagrees with the supplier's
        # own figures. This is not "affected" and not "clear".
        if machine_hash in fixed_hashes:
            return MatchBasis.HASH_MISMATCH, (
                f"this machine reports version {item.version!r}, which the "
                f"advisory names, but the artefact hashes to a value "
                f"{advisory.issued_by} lists as FIXED "
                f"({machine_hash[:12]}). The label is stale; the software "
                "may already be remedied. Confirm before acting."
            )
        return MatchBasis.HASH_MISMATCH, (
            f"this machine reports version {item.version!r}, which the advisory "
            f"names, but the artefact hashes to {machine_hash[:12]}, which "
            f"is not among the hashes {advisory.issued_by} published for that "
            "version. Either the supplier's figure is wrong or this machine is "
            "not running what it says it is running. Both need a person."
        )

    if label_matches:
        return MatchBasis.VERSION, (
            f"the version label {item.version!r} matches one the advisory names. "
            f"{advisory.issued_by} published no artefact hash for it that could be "
            "compared, so this rests on a label, and a label is not an artefact."
            + set_aside
        )

    if machine_hash and machine_hash in fixed_hashes:
        return None  # demonstrably remedied

    if label and (versions or fixed_versions):
        return None  # a known version that is not on the affected list

    return MatchBasis.NAME_ONLY, (
        f"this is {artefact.supplier} {artefact.name}, which the advisory "
        "concerns, but the version on this machine is "
        + (f"{item.version!r}, which the advisory does not list"
           if item.version else "not recorded")
        + ". Somebody has to look." + set_aside
    )


def match_item(
    advisory: ComponentAdvisory, item: SafetyItem,
) -> tuple[MatchBasis, str] | None:
    """Does this advisory touch this item? Returns ``(basis, detail)`` or ``None``.

    The order of evidence is fixed: a hash that matches settles it; a version
    label that matches while the hash contradicts the supplier's published value
    is its own finding and outranks a plain label match. Across the advisory's
    entries the strongest basis wins, in that order, so the answer does not
    depend on which entry the supplier listed first.

    Only a hash read from the machine counts as a hash. Names and version labels
    are compared as :func:`fold_text` folds them; hashes as :func:`fold_hash`
    folds them, and never by prefix.
    """
    best: tuple[MatchBasis, str] | None = None
    for artefact in advisory.affected:
        found = _match_artefact(advisory, artefact, item)
        if found is None:
            continue
        if best is None or _PRIORITY[found[0]] < _PRIORITY[best[0]]:
            best = found
    return best
