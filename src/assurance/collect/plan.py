"""A collection plan: what to look for, where, and how to hash it.

A plan is written once per *machine type* and used for every unit of it. That is
where the leverage is. An integrator with forty AR-7 cells writes one plan, and
every cell thereafter is a two-minute job that produces a manifest nobody had to
type.

The plan is deliberately not a scanner. Nothing here goes looking for "anything
that might be safety-relevant", because a tool that guesses what is
safety-relevant will guess wrong in both directions: it will miss the parameter
set that actually implements the protective stop, and it will fill the manifest
with noise that makes the real findings invisible. A human who knows the machine
says what matters, once, and the machine does the rest forty times.

Every item spec carries the safety functions it implements, which is what makes
:mod:`assurance.machinery` able to say later which verification a change
invalidates. A plan that omits that mapping produces a manifest that can detect
drift and cannot tell you what the drift costs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assurance.collect.normalise import Rule
from assurance.core.errors import AssuranceError
from assurance.core.identity import content_hash_of
from assurance.machinery.manifest import ItemKind, SafetyFunction

__all__ = ["CollectionPlan", "ItemSpec", "PlanError", "VersionSource"]


class PlanError(AssuranceError):
    """A plan is malformed, or would produce a manifest that lies."""


@dataclass(frozen=True)
class VersionSource:
    """Where the version label comes from, when it can be had at all.

    ``unknown`` is a first-class answer and the default. A plan that invents a
    version for an item whose export does not carry one produces a manifest that
    will later match a supplier advisory on a label nobody ever read off the
    machine.
    """

    kind: str = "unknown"     # unknown | literal | regex | json
    value: str = ""           # the literal, the pattern (group 1), or the dotted key
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        if self.kind not in ("unknown", "literal", "regex", "json"):
            raise PlanError(
                f"version source {self.kind!r} is not one of unknown, literal, "
                "regex, json."
            )
        if self.kind != "unknown" and not self.value:
            raise PlanError(f"a {self.kind} version source needs a value.")
        if self.kind == "regex":
            try:
                if re.compile(self.value).groups < 1:
                    raise PlanError(
                        f"version pattern {self.value!r} has no capturing group; "
                        "group 1 is what is read as the version."
                    )
            except re.error as exc:
                raise PlanError(f"version pattern {self.value!r}: {exc}") from exc

    def read(self, data: bytes) -> str:
        """Extract the version from a file's bytes. Empty string when unknown."""
        if self.kind == "unknown":
            return ""
        if self.kind == "literal":
            return self.value
        try:
            text = data.decode(self.encoding, errors="replace")
        except LookupError:
            return ""
        if self.kind == "regex":
            m = re.search(self.value, text)
            return m.group(1).strip() if m else ""
        try:
            doc: Any = json.loads(text)
        except json.JSONDecodeError:
            return ""
        for part in self.value.split("."):
            if not isinstance(doc, dict) or part not in doc:
                return ""
            doc = doc[part]
        return str(doc) if not isinstance(doc, dict | list) else ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "encoding": self.encoding}

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> VersionSource:
        if not d:
            return cls()
        return cls(kind=str(d.get("kind", "unknown")), value=str(d.get("value", "")),
                   encoding=str(d.get("encoding", "utf-8")))


@dataclass(frozen=True)
class ItemSpec:
    """One safety-relevant item, and how to find and hash it."""

    item_id: str
    kind: ItemKind
    name: str
    #: Glob relative to the collection root. May match several files: a safety
    #: PLC project is a directory, not a file, and its identity is the set.
    source: str
    supplier: str = ""
    implements: tuple[str, ...] = ()
    modifiable_in_field: bool = False
    rule: Rule = field(default_factory=Rule)
    version: VersionSource = field(default_factory=VersionSource)
    #: When the file is absent, is that a finding or expected? An optional item
    #: that is missing is reported quietly; a required one is a loud warning and
    #: is left out of the manifest rather than invented.
    required: bool = True
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.item_id or not self.name or not self.source:
            raise PlanError(
                "an item spec needs item_id, name and source.")
        if Path(self.source).is_absolute() or ".." in Path(self.source).parts:
            raise PlanError(
                f"item {self.item_id!r} source {self.source!r} must be relative to the "
                "collection root and must not climb out of it. A plan that reads "
                "outside the root can hash a file that is not on this machine."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id, "kind": self.kind.value, "name": self.name,
            "source": self.source, "supplier": self.supplier,
            "implements": list(self.implements),
            "modifiable_in_field": self.modifiable_in_field,
            "rule": self.rule.to_dict(), "version": self.version.to_dict(),
            "required": self.required, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ItemSpec:
        return cls(
            item_id=str(d["item_id"]), kind=ItemKind(str(d["kind"])),
            name=str(d["name"]), source=str(d["source"]),
            supplier=str(d.get("supplier", "")),
            implements=tuple(str(f) for f in (d.get("implements") or ())),
            modifiable_in_field=bool(d.get("modifiable_in_field", False)),
            rule=Rule.from_dict(d.get("rule")),
            version=VersionSource.from_dict(d.get("version")),
            required=bool(d.get("required", True)),
            notes=str(d.get("notes", "")),
        )


@dataclass(frozen=True)
class CollectionPlan:
    """Written once per machine type. Used for every unit of it."""

    plan_id: str
    manufacturer: str
    model: str
    items: tuple[ItemSpec, ...]
    functions: tuple[SafetyFunction, ...] = ()
    #: Free text: where the exports come from, which tool produces them, what an
    #: engineer has to do before running the collection.
    procedure: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.plan_id or not self.manufacturer or not self.model:
            raise PlanError("a plan needs plan_id, manufacturer and model.")
        if not self.items:
            raise PlanError(
                f"plan {self.plan_id!r} collects nothing.")
        seen: set[str] = set()
        for item in self.items:
            if item.item_id in seen:
                raise PlanError(f"plan {self.plan_id!r} defines {item.item_id!r} twice.")
            seen.add(item.item_id)
        known = {f.function_id for f in self.functions}
        for item in self.items:
            for fid in item.implements:
                if fid not in known:
                    raise PlanError(
                        f"item {item.item_id!r} implements {fid!r}, which the plan "
                        "does not declare. Add the safety function, or the manifest "
                        "this plan produces will be refused."
                    )

    @property
    def unmapped_items(self) -> tuple[ItemSpec, ...]:
        """Items credited to no safety function.

        Not an error — a HMI runtime genuinely implements none — but worth
        seeing, because an item with no function cannot invalidate any
        verification, and if that is wrong the whole chain goes quiet.
        """
        return tuple(i for i in self.items if not i.implements)

    @property
    def undemonstrable_functions(self) -> tuple[SafetyFunction, ...]:
        return tuple(f for f in self.functions if not f.verified_by)

    def item(self, item_id: str) -> ItemSpec | None:
        return next((i for i in self.items if i.item_id == item_id), None)

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "procedure": self.procedure,
            "notes": self.notes,
            "items": [i.to_dict() for i in sorted(self.items, key=lambda i: i.item_id)],
            "functions": [f.to_dict() for f in
                          sorted(self.functions, key=lambda f: f.function_id)],
        }

    def content_hash(self) -> str:
        """Identity of the plan. Recorded in every manifest it produces.

        A manifest whose plan hash differs from another's was collected under
        different rules, and the two are not straightforwardly comparable even
        when the item digests look alike.
        """
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CollectionPlan:
        return cls(
            plan_id=str(d["plan_id"]),
            manufacturer=str(d["manufacturer"]),
            model=str(d["model"]),
            items=tuple(ItemSpec.from_dict(i) for i in d["items"]),
            functions=tuple(SafetyFunction.from_dict(f)
                            for f in (d.get("functions") or ())),
            procedure=str(d.get("procedure", "")),
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> CollectionPlan:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
