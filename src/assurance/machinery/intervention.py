"""Evidence of intervention in safety-relevant software.

Annex III 1.1.9 of Machinery Regulation (EU) 2023/1230 asks for a record that a
safety-relevant change was made. The regulation does not say what a good record
contains, so this module takes a position: a record that names only *what*
changed is a log, and a record that also names *who authorised it* and *what was
re-run afterwards* is evidence.

The distinction is the product. An intervention that carries no re-validation
reference on an item implementing a safety function is not an administrative
omission — it is the moment the machine stopped being covered by its own
validation, and :mod:`assurance.machinery.staleness` will say so by name.

An intervention is recorded whether or not it was authorised, and whether or not
anything was re-run. Refusing to record an undocumented change would simply
push it back to where it lives now, which is nowhere.
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

__all__ = [
    "Authorization",
    "Intervention",
    "InterventionError",
    "InterventionKind",
    "Revalidation",
]


class InterventionError(AssuranceError):
    """An intervention record is incomplete or self-contradictory."""


class InterventionKind(StrEnum):
    UPDATE = "update"            # an artefact was replaced by a different one
    PARAMETER_CHANGE = "parameter_change"   # a value inside it was edited
    INSTALL = "install"          # an item that was not there before
    REMOVAL = "removal"          # an item taken off the machine
    RESTORE = "restore"          # rolled back to a previous artefact
    #: Somebody found the machine already changed and is recording it after the
    #: fact. Honest, common, and worth marking as what it is.
    RECONSTRUCTED = "reconstructed"

    @property
    def is_contemporaneous(self) -> bool:
        return self is not InterventionKind.RECONSTRUCTED


@dataclass(frozen=True)
class Authorization:
    """Who permitted the change, on what basis."""

    authorised_by: Actor
    reference: str          # change request, work order, permit number
    basis: str = ""         # the reason the change was allowed

    def __post_init__(self) -> None:
        if not self.authorised_by.identifier:
            raise InterventionError(
                "an authorisation with no named authoriser is not an authorisation."
            )
        if not self.reference:
            raise InterventionError(
                "an authorisation needs a reference an auditor can pull: a change "
                "request, a work order, a permit number."
            )

    def to_dict(self) -> dict[str, Any]:
        return {"authorised_by": self.authorised_by.to_dict(),
                "reference": self.reference, "basis": self.basis}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Authorization:
        return cls(authorised_by=Actor.from_dict(d["authorised_by"]),
                   reference=str(d["reference"]), basis=str(d.get("basis", "")))


@dataclass(frozen=True)
class Revalidation:
    """What was re-run after the change, and what it produced.

    ``evidence_hash`` points at a sealed verification bundle. A revalidation
    that names no evidence is a claim that something was checked, with nothing
    to check it against, and :attr:`is_evidenced` says so.
    """

    performed_at: datetime
    performed_by: Actor
    description: str
    #: Content hash of the verification bundle produced. Empty means none exists.
    evidence_hash: str = ""
    #: Verification check names covered, when narrower than the whole bundle.
    checks_covered: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.performed_at.tzinfo is None:
            raise InterventionError("Revalidation.performed_at has no timezone.")
        if not self.description:
            raise InterventionError(
                "a revalidation needs a description of what was actually re-run."
            )

    @property
    def is_evidenced(self) -> bool:
        return bool(self.evidence_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "performed_at": format_utc(self.performed_at),
            "performed_by": self.performed_by.to_dict(),
            "description": self.description,
            "evidence_hash": self.evidence_hash,
            "checks_covered": list(self.checks_covered),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Revalidation:
        return cls(
            performed_at=parse_utc(str(d["performed_at"])),
            performed_by=Actor.from_dict(d["performed_by"]),
            description=str(d["description"]),
            evidence_hash=str(d.get("evidence_hash", "")),
            checks_covered=tuple(str(c) for c in (d.get("checks_covered") or ())),
        )


@dataclass(frozen=True)
class Intervention:
    """One recorded change to safety-relevant software on one machine."""

    intervention_id: str
    machine_key: str
    item_id: str
    kind: InterventionKind
    occurred_at: datetime
    performed_by: Actor
    reason: str
    from_hash: str = ""
    to_hash: str = ""
    #: Safety function ids the changed item is credited with, as understood at
    #: the time of the change. Copied in rather than looked up later, so the
    #: record stays readable when the manifest is re-declared.
    affects_functions: tuple[str, ...] = ()
    authorization: Authorization | None = None
    revalidation: Revalidation | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.intervention_id or not self.machine_key or not self.item_id:
            raise InterventionError(
                "an intervention needs an id, a machine and an item it touched."
            )
        if self.occurred_at.tzinfo is None:
            raise InterventionError(
                f"intervention {self.intervention_id!r} occurred_at has no timezone."
            )
        if not self.performed_by.identifier:
            raise InterventionError(
                f"intervention {self.intervention_id!r} names nobody who performed it. "
                "An unattributed change to safety-relevant software is the exact "
                "thing Annex III 1.1.9 exists to prevent."
            )
        if not self.reason:
            raise InterventionError(
                f"intervention {self.intervention_id!r} gives no reason. "
                "'Why' is the field a reviewer reads first."
            )
        if self.kind is InterventionKind.UPDATE and self.from_hash and self.to_hash \
                and self.from_hash == self.to_hash:
            raise InterventionError(
                f"intervention {self.intervention_id!r} is recorded as an update but "
                "the before and after hashes are identical. Nothing changed."
            )

    # -- the questions a reviewer asks ------------------------------------
    @property
    def is_authorised(self) -> bool:
        return self.authorization is not None

    @property
    def is_revalidated(self) -> bool:
        """Re-run, and with a sealed bundle to point at."""
        return self.revalidation is not None and self.revalidation.is_evidenced

    @property
    def is_safety_bearing(self) -> bool:
        return bool(self.affects_functions)

    @property
    def findings(self) -> tuple[str, ...]:
        """What is wrong with this record, in the order a reviewer would say it."""
        out: list[str] = []
        if self.is_safety_bearing and not self.is_revalidated:
            if self.revalidation is None:
                out.append(
                    "a safety-bearing item was changed and nothing was re-run. Every "
                    "verification of "
                    + ", ".join(self.affects_functions)
                    + " that predates this change no longer describes the machine."
                )
            else:
                out.append(
                    "a revalidation is claimed but names no sealed evidence, so there "
                    "is nothing for a third party to re-check."
                )
        if self.is_safety_bearing and not self.is_authorised:
            out.append("a safety-bearing item was changed with no recorded authorisation.")
        if not self.kind.is_contemporaneous:
            out.append(
                "this record was reconstructed after the fact, so the times and the "
                "attribution are somebody's recollection, not a contemporaneous log."
            )
        if self.kind in (InterventionKind.UPDATE, InterventionKind.PARAMETER_CHANGE) \
                and not (self.from_hash and self.to_hash):
            out.append(
                "the before and after hashes are not both recorded, so what changed "
                "cannot be established from this record alone."
            )
        return tuple(out)

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "intervention_id": self.intervention_id,
            "machine_key": self.machine_key,
            "item_id": self.item_id,
            "kind": self.kind.value,
            "occurred_at": format_utc(self.occurred_at),
            "performed_by": self.performed_by.to_dict(),
            "reason": self.reason,
            "from_hash": self.from_hash,
            "to_hash": self.to_hash,
            "affects_functions": sorted(self.affects_functions),
            "authorization": self.authorization.to_dict() if self.authorization else None,
            "revalidation": self.revalidation.to_dict() if self.revalidation else None,
            "notes": self.notes,
        }

    def content_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Intervention:
        auth = d.get("authorization")
        reval = d.get("revalidation")
        return cls(
            intervention_id=str(d["intervention_id"]),
            machine_key=str(d["machine_key"]),
            item_id=str(d["item_id"]),
            kind=InterventionKind(str(d["kind"])),
            occurred_at=parse_utc(str(d["occurred_at"])),
            performed_by=Actor.from_dict(d["performed_by"]),
            reason=str(d["reason"]),
            from_hash=str(d.get("from_hash", "")),
            to_hash=str(d.get("to_hash", "")),
            affects_functions=tuple(str(f) for f in (d.get("affects_functions") or ())),
            authorization=Authorization.from_dict(auth) if auth else None,
            revalidation=Revalidation.from_dict(reval) if reval else None,
            notes=str(d.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> Intervention:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def summary(self) -> str:
        head = (f"{self.intervention_id}  {format_utc(self.occurred_at)}  "
                f"{self.kind.value}  {self.item_id}  by {self.performed_by}")
        lines = [head, f"    {self.reason}"]
        if self.from_hash and self.to_hash:
            lines.append(f"    {self.from_hash[:12]} → {self.to_hash[:12]}")
        if self.affects_functions:
            lines.append(f"    affects {', '.join(sorted(self.affects_functions))}")
        lines.append(
            f"    authorised: {'yes — ' + self.authorization.reference if self.authorization else 'NO'}"
        )
        if self.revalidation is None:
            lines.append("    revalidated: NO")
        elif self.revalidation.is_evidenced:
            lines.append(f"    revalidated: {self.revalidation.evidence_hash[:12]}")
        else:
            lines.append("    revalidated: claimed, no evidence named")
        for f in self.findings:
            lines.append(f"    !! {f}")
        return "\n".join(lines)
