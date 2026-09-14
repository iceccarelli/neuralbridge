"""What safety-relevant software is on this machine, and how we know.

Machinery Regulation (EU) 2023/1230 applies from 20 January 2027. Annex III
1.1.9 requires a machine to identify its safety-relevant software and to record
evidence of intervention in it. Almost nobody can do either today: the safety
PLC program lives on a laptop, the scanner zones live in a vendor tool, the
robot's safety parameters live in the controller, and the only record that a
technician changed any of them is that technician's memory.

A manifest is the answer to "what is running on this machine right now", in a
form two manifests can be compared with. The whole product turns on one field
per item: :class:`HashSource`. A hash read out of the machine and a hash a
supplier emailed you are not the same evidence, and when the two disagree, the
one that was read from the machine is the one that is true.

A safety function is declared with the checks that exercise it. That is not
bureaucracy — it is the link that lets an intervention invalidate the
verification that preceded it, which is what :mod:`assurance.machinery.staleness`
computes and what nobody else can currently produce.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of, format_utc, parse_utc
from assurance.core.tiers import AssuranceTier

__all__ = [
    "HashSource",
    "ItemKind",
    "MachineIdentity",
    "ManifestError",
    "ManifestSource",
    "SafetyFunction",
    "SafetyItem",
    "SafetyManifest",
]


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

    def __post_init__(self) -> None:
        for name in ("manufacturer", "model", "serial"):
            if not getattr(self, name):
                raise ManifestError(
                    f"MachineIdentity.{name} is empty. A manifest that does not "
                    "identify one specific unit cannot be compared with another."
                )

    @property
    def key(self) -> str:
        """The ledger subject for everything about this machine."""
        return f"{self.manufacturer}/{self.model}#{self.serial}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "manufacturer": self.manufacturer, "model": self.model,
            "serial": self.serial, "year": self.year, "site": self.site,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MachineIdentity:
        return cls(
            manufacturer=str(d["manufacturer"]), model=str(d["model"]),
            serial=str(d["serial"]), year=str(d.get("year", "")),
            site=str(d.get("site", "")),
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
        """Whether a change to this item would be detectable at all."""
        return bool(self.content_hash)

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
        return min((i.hash_source.tier_ceiling for i in self.items),
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
