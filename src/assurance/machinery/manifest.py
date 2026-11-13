"""What safety-relevant software is on this machine, and how we know.

Machinery Regulation (EU) 2023/1230 applies from 20 January 2027. Annex III
1.1.9 requires a machine to identify the software installed on it that is necessary for it to
operate safely, and to collect evidence of an intervention in, or modification of, that software
or its configuration. That is a design requirement on the machine; this package is evidence
tooling for the manufacturer and does not by itself satisfy it. Doing either by hand is hard: the safety
PLC program may live on a laptop, the scanner zones in a vendor tool, the
robot's safety parameters in the controller, and the only record that a
technician changed any of them may be that technician's memory.

A manifest is the answer to "what is running on this machine right now", in a
form two manifests can be compared with. The whole product turns on one field
per item: :class:`HashSource`. A hash read out of the machine and a hash a
supplier emailed you are not the same evidence, and when the two disagree, the
one that was read from the machine is the one that is true.

A safety function is declared with the checks that exercise it. That is not
bureaucracy — it is the link that lets an intervention invalidate the
verification that preceded it, which is what :mod:`assurance.machinery.staleness`
computes.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of, format_utc, parse_utc
from assurance.core.placeholders import placeholder_problem
from assurance.core.tiers import AssuranceTier

__all__ = [
    "INCOMPLETE_COLLECTION_MARK",
    "SAFETY_DECLARATION_SCHEMA",
    "HashSource",
    "ItemKind",
    "MachineIdentity",
    "ManifestError",
    "ManifestSource",
    "SafetyFunction",
    "SafetyItem",
    "SafetyManifest",
    "incomplete_collection_note",
    "last_attribution",
    "manifest_is_incomplete",
    "not_a_look",
]


_HEX64 = frozenset("0123456789abcdef")

#: Written into a manifest's ``notes`` when a collection did not find or read every item its
#: plan names. Such a manifest is a partial look, not a configuration the machine was in.
#: The format is read back by the watch, the change workflow and the ledger reader, and it
#: is already in stored ledgers: do not change it. (``change.service`` and
#: ``machinery.record`` re-export it under their own names and a test pins them together.)
INCOMPLETE_COLLECTION_MARK = "[collection incomplete"

#: Version of the safety-function declaration hash. A declaration hash is only ever compared
#: with one of the same version.
SAFETY_DECLARATION_SCHEMA = "assurance.machinery.safety-declaration/1"


def normalised_digest(text: str) -> str:
    """The SHA-256 digest in ``text`` in comparison form, or ``""`` if it is not one.

    Trimmed, lower-cased, a leading ``sha256:`` dropped. Anything that is not exactly 64
    hex digits afterwards (``n/a``, ``unknown``, ``0``, whitespace, a truncated digest)
    is not a hash and returns ``""``: two manifests that both say ``n/a`` must never
    compare as an unchanged artefact.
    """
    h = text.strip().lower()
    if h.startswith("sha256:"):
        h = h[len("sha256:"):].strip()
    if len(h) != 64 or not set(h) <= _HEX64:
        return ""
    # 64 zeros is the null hash, how an uncomputed digest is written. It is not the digest of
    # any file, so it must never make an item "comparable" or "read from the machine".
    return "" if placeholder_problem("sha256", h) else h


class ManifestError(AssuranceError):
    """A manifest is incomplete, inconsistent, or claims more than it evidences."""


class ItemKind(StrEnum):
    """What sort of software-or-configuration this is.

    The distinction matters because the kinds fail differently. Firmware is
    replaced wholesale and rarely; a scanner's zone configuration is edited on a
    Tuesday afternoon by someone with a laptop and no change record.
    """

    FIRMWARE = "firmware"
    SAFETY_PROGRAM = "safety_program"
    SAFETY_CONFIGURATION = "safety_configuration"
    PARAMETER_SET = "parameter_set"
    LIBRARY = "library"


class HashSource(StrEnum):
    """How this item's identity was established. The ceiling on every claim about it."""

    #: Computed from the artefact as it was read off the machine. The only
    #: source that says anything about the unit in front of you.
    READ_FROM_MACHINE = "read_from_machine"
    #: Computed from a file the supplier provided. Says what should be there.
    SUPPLIED_BY_VENDOR = "supplied_by_vendor"
    #: Somebody typed a version number. Nothing was hashed.
    DECLARED = "declared"

    @property
    def tier_ceiling(self) -> AssuranceTier:
        if self is HashSource.READ_FROM_MACHINE:
            return AssuranceTier.VALIDATED
        if self is HashSource.SUPPLIED_BY_VENDOR:
            return AssuranceTier.COMMUNITY
        return AssuranceTier.PROFILE

    @property
    def describes_this_unit(self) -> bool:
        """Whether this says anything about the machine in front of you."""
        return self is HashSource.READ_FROM_MACHINE


class ManifestSource(StrEnum):
    """Why this manifest exists."""

    #: The configuration the machine was CE-marked with. The baseline.
    AS_DECLARED = "as_declared"
    #: What was on the machine when somebody looked. The observation.
    AS_FOUND = "as_found"
    #: What the manufacturer intends to ship. A plan, not a fact.
    AS_INTENDED = "as_intended"


@dataclass(frozen=True)
class MachineIdentity:
    """The unit this manifest is about.

    Serial number is required and not defaulted. Evidence about "the AR-7" is
    worth nothing to an inspector standing in front of AR-7 #0412.
    """

    manufacturer: str
    model: str
    serial: str
    #: Year of construction, per the Machinery Regulation's marking requirements.
    year: str = ""
    #: Where it physically is. Useful when a fleet manifest covers many sites.
    site: str = ""
    #: ISO 3166-1 alpha-2 of the territory this unit was made available in.
    #:
    #: This is here because of Article 14(2)(a) of the Cyber Resilience Act. An
    #: early warning must indicate the Member States in whose territory the
    #: manufacturer is aware the product has been made available, and that list
    #: is the one thing that cannot be assembled inside 24 hours from a
    #: standing start. A site string is not a country: "Plant 2, Line 4" tells
    #: nobody where the machine is, and guessing a country from free text is
    #: exactly the kind of inference that puts a wrong Member State on a
    #: regulatory filing. Recorded explicitly or not at all.
    country: str = ""

    def __post_init__(self) -> None:
        if self.country and (len(self.country) != 2 or not self.country.isalpha()):
            raise ManifestError(
                f"country {self.country!r} is not an ISO 3166-1 alpha-2 code. A "
                "regulatory filing names territories in that form, and a "
                "half-recognised country code is worse than an absent one."
            )
        for name in ("manufacturer", "model", "serial"):
            if not getattr(self, name):
                raise ManifestError(
                    f"MachineIdentity.{name} is empty. A manifest that does not "
                    "identify one specific unit cannot be compared with another."
                )

    @property
    def key(self) -> str:
        """The ledger subject for everything about this machine.

        Plain concatenation, and it stays that: stored ledgers are filed under it. It is
        therefore not injective over arbitrary strings (``A``/``B#1``/``2`` and
        ``A``/``B``/``1#2`` give the same key), which is why new identities are checked
        with :meth:`ambiguity_problems` where they are created, and why a ledger that
        already holds an ambiguous one is still readable.
        """
        return f"{self.manufacturer}/{self.model}#{self.serial}"

    @property
    def components(self) -> tuple[str, str, str]:
        """The three strings the key is made of, for telling two identities apart."""
        return (self.manufacturer, self.model, self.serial)

    def ambiguity_problems(self) -> tuple[str, ...]:
        """Why this identity cannot safely be the basis of a NEW record; empty if it can.

        The key is ``manufacturer/model#serial``. It parses back into exactly one tuple only if
        ``#`` appears in no part (the bundle reader splits at the first ``#`` and the watch
        ingester at the last) and ``/`` appears in neither the manufacturer nor the model. A ``/``
        in the SERIAL is allowed (real serials such as ``2023/00123`` contain one, and nothing
        parses the key at a serial ``/``). A component that breaks this, has leading or trailing
        whitespace, is blank, or contains a control or other non-printing character can make
        two different units share one key (so one would inherit the other's evidence), or
        make a key that no reader can take apart again. This is checked where an identity is
        created or enrolled and deliberately NOT where one is read back from a ledger: a
        record already sealed with such an identity stays readable.
        """
        out: list[str] = []
        for name, value in zip(("manufacturer", "model", "serial"), self.components,
                               strict=True):
            if not value.strip():
                out.append(f"{name} is blank")
                continue
            forbidden = "#" if name == "serial" else "/#"
            bad_sep = sorted({c for c in value if c in forbidden})
            if bad_sep:
                out.append(f"{name} {value!r} contains {' and '.join(repr(c) for c in bad_sep)}"
                           ", which separate the parts of the machine key")
            if value != value.strip():
                out.append(f"{name} {value!r} has leading or trailing whitespace")
            if any(not c.isprintable() for c in value):
                out.append(f"{name} {value!r} contains a control or non-printing character")
        return tuple(out)

    def require_unambiguous(self) -> MachineIdentity:
        """Raise :class:`ManifestError` if :meth:`ambiguity_problems` finds anything."""
        problems = self.ambiguity_problems()
        if problems:
            raise ManifestError(
                f"machine identity {self.key!r} is ambiguous: " + "; ".join(problems)
                + ". Two different units could share one key and so one record. Correct "
                "the manufacturer, model or serial; nothing was recorded.")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "manufacturer": self.manufacturer, "model": self.model,
            "serial": self.serial, "year": self.year, "site": self.site,
            "country": self.country,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MachineIdentity:
        return cls(
            manufacturer=str(d["manufacturer"]), model=str(d["model"]),
            serial=str(d["serial"]), year=str(d.get("year", "")),
            site=str(d.get("site", "")), country=str(d.get("country", "")).upper(),
        )


@dataclass(frozen=True)
class SafetyFunction:
    """A named safety function, and what actually demonstrates it.

    ``verified_by`` names the checks in :mod:`assurance.machine.verify` that
    exercise this function. A function with an empty ``verified_by`` is one this
    system cannot tell you anything about, and it is reported as exactly that
    rather than quietly passing.
    """

    function_id: str
    description: str
    #: Required performance level (ISO 13849-1, e.g. "PL d") or SIL (IEC 62061).
    required_performance: str = ""
    #: Names of machine-verification checks that exercise this function.
    verified_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.function_id:
            raise ManifestError("a safety function needs an identifier.")
        if not self.description:
            raise ManifestError(
                f"safety function {self.function_id!r} has no description. "
                "An identifier alone tells a reader nothing about what may be lost."
            )

    @property
    def is_demonstrable(self) -> bool:
        return bool(self.verified_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "description": self.description,
            "required_performance": self.required_performance,
            "verified_by": list(self.verified_by),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SafetyFunction:
        return cls(
            function_id=str(d["function_id"]),
            description=str(d.get("description", "")),
            required_performance=str(d.get("required_performance", "")),
            verified_by=tuple(str(v) for v in (d.get("verified_by") or ())),
        )


@dataclass(frozen=True)
class SafetyItem:
    """One piece of safety-relevant software or configuration."""

    item_id: str
    kind: ItemKind
    name: str
    version: str
    #: Hash of the artefact itself — the program export, the config file, the
    #: firmware image. Empty is allowed only when ``hash_source`` is DECLARED,
    #: and then the item cannot participate in divergence detection.
    content_hash: str
    hash_source: HashSource
    supplier: str = ""
    #: Safety function ids this item helps implement.
    implements: tuple[str, ...] = ()
    #: Whether a technician can change this on site. An item that can be changed
    #: on site and is not covered by an intervention record is the exact gap
    #: Annex III 1.1.9 exists to close.
    modifiable_in_field: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.item_id or not self.name:
            raise ManifestError("a safety item needs an item_id and a name.")
        if not self.content_hash and self.hash_source is not HashSource.DECLARED:
            raise ManifestError(
                f"item {self.item_id!r} claims hash_source "
                f"{self.hash_source.value!r} but carries no hash. Either hash the "
                "artefact or record the source as 'declared' and accept that this "
                "item cannot be compared between manifests."
            )

    @property
    def is_comparable(self) -> bool:
        """Whether a change to this item would be detectable at all.

        Only a real SHA-256 digest counts. A placeholder is not evidence that nothing
        changed, so it makes the item invisible to comparison, which the report says.
        """
        return bool(normalised_digest(self.content_hash))

    @property
    def effective_hash_source(self) -> HashSource:
        """What the item's identity is actually worth: ``declared`` without a real digest.

        An item that says ``read_from_machine`` beside ``n/a`` was not read from anything.
        """
        return self.hash_source if self.is_comparable else HashSource.DECLARED

    @property
    def is_safety_bearing(self) -> bool:
        return bool(self.implements)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "kind": self.kind.value,
            "name": self.name,
            "version": self.version,
            "content_hash": self.content_hash,
            "hash_source": self.hash_source.value,
            "supplier": self.supplier,
            "implements": list(self.implements),
            "modifiable_in_field": self.modifiable_in_field,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SafetyItem:
        return cls(
            item_id=str(d["item_id"]),
            kind=ItemKind(str(d["kind"])),
            name=str(d["name"]),
            version=str(d.get("version", "")),
            content_hash=str(d.get("content_hash", "")),
            hash_source=HashSource(str(d["hash_source"])),
            supplier=str(d.get("supplier", "")),
            implements=tuple(str(v) for v in (d.get("implements") or ())),
            modifiable_in_field=bool(d.get("modifiable_in_field", False)),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        item_id: str,
        kind: ItemKind,
        name: str,
        version: str = "",
        supplier: str = "",
        implements: tuple[str, ...] = (),
        modifiable_in_field: bool = False,
        hash_source: HashSource = HashSource.READ_FROM_MACHINE,
        notes: str = "",
    ) -> SafetyItem:
        """Hash an artefact on disk.

        ``hash_source`` defaults to READ_FROM_MACHINE because that is the only
        reason to point this at a file — but the caller may override it, and
        must, when the file came from a vendor's download page rather than off
        the controller.
        """
        import hashlib

        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return cls(
            item_id=item_id, kind=kind, name=name, version=version,
            content_hash=digest, hash_source=hash_source, supplier=supplier,
            implements=implements, modifiable_in_field=modifiable_in_field,
            notes=notes,
        )


@dataclass(frozen=True)
class SafetyManifest:
    """The safety-relevant software of one machine at one moment."""

    manifest_id: str
    machine: MachineIdentity
    source: ManifestSource
    taken_at: datetime
    taken_by: Actor
    items: tuple[SafetyItem, ...]
    functions: tuple[SafetyFunction, ...] = ()
    #: How the manifest was collected: the tool, the procedure, the work order.
    method: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.items:
            raise ManifestError(
                f"manifest {self.manifest_id!r} lists no items. An empty manifest "
                "asserts that the machine has no safety-relevant software, which "
                "is a claim, not a default."
            )
        if self.taken_at.tzinfo is None:
            raise ManifestError(f"manifest {self.manifest_id!r} taken_at has no timezone.")
        seen: set[str] = set()
        for item in self.items:
            if item.item_id in seen:
                raise ManifestError(
                    f"manifest {self.manifest_id!r} lists item {item.item_id!r} twice."
                )
            seen.add(item.item_id)
        declared: set[str] = set()
        for fn in self.functions:
            if fn.function_id in declared:
                raise ManifestError(
                    f"manifest {self.manifest_id!r} declares safety function "
                    f"{fn.function_id!r} twice. Two declarations of one function disagree "
                    "about what verifies it, and a reader would take the first."
                )
            declared.add(fn.function_id)
        known = {f.function_id for f in self.functions}
        for item in self.items:
            for fid in item.implements:
                if fid not in known:
                    raise ManifestError(
                        f"item {item.item_id!r} implements safety function {fid!r}, "
                        "which the manifest does not declare. An item credited to a "
                        "function nobody defined cannot be reasoned about."
                    )

    # -- views ------------------------------------------------------------
    def item(self, item_id: str) -> SafetyItem | None:
        return next((i for i in self.items if i.item_id == item_id), None)

    def function(self, function_id: str) -> SafetyFunction | None:
        return next((f for f in self.functions if f.function_id == function_id), None)

    @property
    def tier_ceiling(self) -> AssuranceTier:
        """The best any claim from this manifest could be worth.

        One declared item among fifty read from the machine drags the whole
        manifest down, and that is correct: the manifest is a statement about
        the machine's configuration as a whole.
        """
        return min((i.effective_hash_source.tier_ceiling for i in self.items),
                   default=AssuranceTier.PROFILE)

    @property
    def uncomparable_items(self) -> tuple[SafetyItem, ...]:
        """Items carrying no hash: a change to these would never be seen."""
        return tuple(i for i in self.items if not i.is_comparable)

    @property
    def field_modifiable_safety_items(self) -> tuple[SafetyItem, ...]:
        """Safety-bearing items a technician can change on site."""
        return tuple(i for i in self.items
                     if i.modifiable_in_field and i.is_safety_bearing)

    @property
    def undemonstrable_functions(self) -> tuple[SafetyFunction, ...]:
        """Declared functions that no check exercises."""
        return tuple(f for f in self.functions if not f.is_demonstrable)

    def functions_of(self, item: SafetyItem) -> tuple[SafetyFunction, ...]:
        return tuple(f for f in self.functions if f.function_id in item.implements)

    def resolve_function_ids(
        self, ids: Iterable[str],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Read hand-typed function ids against the functions this manifest declares.

        Returns ``(resolved, unknown)``. An id is resolved to the declared spelling: an
        exact match, else the one that differs only by case or surrounding spaces
        (``sf-1`` for ``SF-1``). Two declared ids that differ only by case are both
        kept for such an id, because choosing between them would be a guess and the
        conservative reading is that the change disturbed either. An id that matches
        nothing is ``unknown`` -- never silently dropped by the caller.
        """
        declared = [f.function_id for f in self.functions]
        resolved: list[str] = []
        unknown: list[str] = []
        for raw in ids:
            if raw in declared:
                hits = [raw]
            else:
                folded = raw.strip().casefold()
                hits = [d for d in declared if d.strip().casefold() == folded]
            if not hits:
                if raw not in unknown:
                    unknown.append(raw)
                continue
            resolved.extend(h for h in hits if h not in resolved)
        return tuple(resolved), tuple(unknown)

    def checks_for(self, function_ids: set[str]) -> set[str]:
        """Every verification check that exercises any of these functions."""
        out: set[str] = set()
        for f in self.functions:
            if f.function_id in function_ids:
                out.update(f.verified_by)
        return out

    # -- identity ---------------------------------------------------------
    def hashable_payload(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "machine": self.machine.to_dict(),
            "source": self.source.value,
            "taken_at": format_utc(self.taken_at),
            "taken_by": self.taken_by.to_dict(),
            "method": self.method,
            "notes": self.notes,
            "items": [i.to_dict() for i in sorted(self.items, key=lambda i: i.item_id)],
            "functions": [f.to_dict() for f in
                          sorted(self.functions, key=lambda f: f.function_id)],
        }

    def content_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def configuration_hash(self) -> str:
        """Identity of the configuration alone, ignoring who looked and when.

        Two manifests of the same machine taken a year apart by different
        engineers share this hash if nothing changed. That is the one-line
        answer to "is it still the machine we signed off".
        """
        return content_hash_of({
            "machine": self.machine.to_dict(),
            "items": [
                {"item_id": i.item_id, "kind": i.kind.value, "name": i.name,
                 "version": i.version, "content_hash": i.content_hash,
                 "implements": sorted(i.implements)}
                for i in sorted(self.items, key=lambda i: i.item_id)
            ],
        })

    def safety_declaration_hash(self) -> str:
        """Identity of what the manifest says its safety functions are and how they are shown.

        Separate from :meth:`configuration_hash`, which is in stored ledgers and does not
        change: that hash covers the items (and what each implements) but not the functions,
        so emptying a function's ``verified_by`` or lowering its required performance level
        left it equal. This one covers every declared function: id, description, required
        performance, and the set of checks that verify it. Versioned
        (:data:`SAFETY_DECLARATION_SCHEMA`); compare it only with one of the same version.
        """
        return content_hash_of({
            "schema": SAFETY_DECLARATION_SCHEMA,
            "functions": [
                {"function_id": f.function_id, "description": f.description,
                 "required_performance": f.required_performance,
                 "verified_by": sorted(f.verified_by)}
                for f in sorted(self.functions, key=lambda f: f.function_id)
            ],
        })

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SafetyManifest:
        return cls(
            manifest_id=str(d["manifest_id"]),
            machine=MachineIdentity.from_dict(d["machine"]),
            source=ManifestSource(str(d["source"])),
            taken_at=parse_utc(str(d["taken_at"])),
            taken_by=Actor.from_dict(d["taken_by"]),
            items=tuple(SafetyItem.from_dict(i) for i in d["items"]),
            functions=tuple(SafetyFunction.from_dict(f)
                            for f in (d.get("functions") or ())),
            method=str(d.get("method", "")),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> SafetyManifest:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def notes_mark_incomplete(notes: object) -> bool:
    """Do these manifest notes carry the incomplete-collection marker? Case- and whitespace-insensitive (fail-safe)."""
    text = " ".join(str(notes or "").split()).lower()
    return " ".join(INCOMPLETE_COLLECTION_MARK.split()).lower() in text


def manifest_is_incomplete(manifest: SafetyManifest) -> bool:
    """Is this manifest marked as a partial collection (see :data:`INCOMPLETE_COLLECTION_MARK`)?

    An incomplete manifest lacks items its plan names. It is a record of what was read, not
    a configuration the machine was in: it can be neither a baseline nor proof of a
    machine's state after a change. The marker is the only thing that says so, which is why
    every consumer that needs a complete look asks this one function.
    """
    # Case-insensitive and whitespace-normalised: a note edited or re-typed by hand must read
    # as incomplete rather than slip through as a whole look (fail-safe). The marker FORMAT
    # that is written is unchanged.
    return notes_mark_incomplete(manifest.notes)


def incomplete_collection_note(missing_items: Iterable[str]) -> str:
    """The note that marks a manifest as incomplete, naming what was not collected."""
    return f"{INCOMPLETE_COLLECTION_MARK}: {', '.join(missing_items)} not collected]"


def last_attribution(manifests: Iterable[SafetyManifest]) -> dict[str, tuple[str, ...]]:
    """For each item, the safety functions it was last credited with in a COMPLETE manifest.

    Oldest first in; the latest non-empty ``implements`` per item wins. A plan
    (``as_intended``) and a partial collection say nothing about the machine and are
    skipped. An item whose attribution was later dropped keeps the one it had: dropping an
    attribution is not evidence the item stopped mattering, so a change to that item still
    disturbs those functions (see :func:`assurance.machinery.divergence.compare`).
    """
    out: dict[str, tuple[str, ...]] = {}
    for m in manifests:
        if m.source is ManifestSource.AS_INTENDED or manifest_is_incomplete(m):
            continue
        for i in m.items:
            if i.implements:
                out[i.item_id] = tuple(i.implements)
    return out


def not_a_look(manifest: SafetyManifest) -> str:
    """Why this manifest cannot be a positive observation of the machine; "" if it can.

    A look is an ``as_found`` manifest whose every item was hashed off the unit
    (:attr:`HashSource.describes_this_unit`). ``configuration_hash`` deliberately
    ignores both ``source`` and ``hash_source``, so equal hashes say nothing about
    either: a *declared* manifest carrying the old baseline hash has the same
    configuration hash as the machine really reverting.
    """
    reasons: list[str] = []
    if manifest.source is not ManifestSource.AS_FOUND:
        reasons.append(f"its source is {manifest.source.value!r}, not 'as_found'")
    # The effective label, not the typed one: "read_from_machine" beside "n/a" or 64 zeros was
    # not read from anything (tier ceiling "profile"), and must not pass for a look.
    not_read = sorted(i.item_id for i in manifest.items
                      if not i.effective_hash_source.describes_this_unit)
    if not_read:
        reasons.append(
            "item(s) " + ", ".join(not_read) + " carry no hash read off the machine "
            "(supplied by a vendor, or declared)")
    if not reasons:
        return ""
    return ("the manifest is not a record of looking at this machine: "
            + "; ".join(reasons) + ". Equal hashes do not say what the unit holds.")
