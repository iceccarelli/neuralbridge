"""The Declaration of Conformity, bound to a configuration that can be checked.

An EU Declaration of Conformity is the legal instrument. The manufacturer signs
that a machine conforms to the applicable legislation. It names the machine, the
legislation, the standards applied, and where relevant the notified body.

What it has never named is *which software configuration it was signed against*,
because until there was a configuration hash there was nothing to name. So the
declaration silently goes on describing a machine that stopped existing the day
a technician updated the firmware, and nobody can point at the moment it stopped
being true.

Binding a declaration to :meth:`SafetyManifest.configuration_hash` fixes that,
and produces the one sentence an integrator's lawyer needs to see:

    Your Declaration of Conformity covers configuration 108b15f43f26.
    Serial 0412 currently runs 6acb6ee2e14e. The declaration does not
    describe this machine.

This module makes no legal judgement and says so. Whether a changed
configuration amounts to a substantial modification requiring a new conformity
assessment is a question for the manufacturer and their notified body. What this
establishes is the fact the question rests on: the configuration is not the one
that was declared.
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
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.staleness import Coverage, CoverageReport

__all__ = [
    "DeclarationError",
    "DeclarationOfConformity",
    "DeclarationStatus",
    "DeclarationVerdict",
    "check_declaration",
]


class DeclarationError(AssuranceError):
    """A declaration is incomplete or cannot be bound to a configuration."""


class DeclarationVerdict(StrEnum):
    #: The machine runs the configuration the declaration was signed against,
    #: and the evidence for every declared safety function still stands.
    DESCRIBES_THE_MACHINE = "describes_the_machine"
    #: The configuration is the declared one; some safety evidence has lapsed.
    CONFIGURATION_INTACT_EVIDENCE_LAPSED = "configuration_intact_evidence_lapsed"
    #: The machine no longer runs the configuration that was declared.
    CONFIGURATION_CHANGED = "configuration_changed"
    #: The declaration is about a different machine.
    WRONG_MACHINE = "wrong_machine"

    @property
    def is_sound(self) -> bool:
        return self is DeclarationVerdict.DESCRIBES_THE_MACHINE


@dataclass(frozen=True)
class DeclarationOfConformity:
    """A declaration, bound to the configuration it was signed against."""

    doc_id: str
    machine_key: str
    issued_by: str
    issued_at: datetime
    #: The manifest configuration hash this declaration covers. This is the
    #: field the whole module exists for; without it a declaration cannot be
    #: checked against anything.
    configuration_hash: str
    #: e.g. "Regulation (EU) 2023/1230", "Regulation (EU) 2024/2847"
    legislation: tuple[str, ...] = ()
    #: Harmonised standards applied, as they appear on the declaration.
    standards: tuple[str, ...] = ()
    notified_body: str = ""
    notified_body_number: str = ""
    signatory: str = ""
    place: str = ""

    def __post_init__(self) -> None:
        if not self.doc_id or not self.machine_key:
            raise DeclarationError(
                "a declaration needs an identifier and the machine it is about.")
        if not self.configuration_hash:
            raise DeclarationError(
                f"declaration {self.doc_id!r} names no configuration hash. A "
                "declaration that is not bound to a configuration cannot be shown "
                "to describe, or to stop describing, any particular machine — "
                "which is the situation this module exists to end."
            )
        if self.issued_at.tzinfo is None:
            raise DeclarationError(
                f"declaration {self.doc_id!r} issued_at has no timezone.")
        if not self.legislation:
            raise DeclarationError(
                f"declaration {self.doc_id!r} names no legislation. A declaration "
                "of conformity to nothing in particular is not a declaration."
            )

    def covers(self, manifest: SafetyManifest) -> bool:
        """Whether this declaration was signed against this exact configuration."""
        return (manifest.machine.key == self.machine_key
                and manifest.configuration_hash() == self.configuration_hash)

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "machine_key": self.machine_key,
            "issued_by": self.issued_by,
            "issued_at": format_utc(self.issued_at),
            "configuration_hash": self.configuration_hash,
            "legislation": list(self.legislation),
            "standards": list(self.standards),
            "notified_body": self.notified_body,
            "notified_body_number": self.notified_body_number,
            "signatory": self.signatory,
            "place": self.place,
        }

    def content_hash(self) -> str:
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return self.hashable_payload()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DeclarationOfConformity:
        return cls(
            doc_id=str(d["doc_id"]),
            machine_key=str(d["machine_key"]),
            issued_by=str(d.get("issued_by", "")),
            issued_at=parse_utc(str(d["issued_at"])),
            configuration_hash=str(d.get("configuration_hash", "")),
            legislation=tuple(str(x) for x in (d.get("legislation") or ())),
            standards=tuple(str(x) for x in (d.get("standards") or ())),
            notified_body=str(d.get("notified_body", "")),
            notified_body_number=str(d.get("notified_body_number", "")),
            signatory=str(d.get("signatory", "")),
            place=str(d.get("place", "")),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> DeclarationOfConformity:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def bind(
        cls, manifest: SafetyManifest, *, doc_id: str, issued_by: str,
        issued_at: datetime, legislation: tuple[str, ...],
        standards: tuple[str, ...] = (), notified_body: str = "",
        notified_body_number: str = "", signatory: str = "", place: str = "",
    ) -> DeclarationOfConformity:
        """Create a declaration bound to the configuration in front of you."""
        return cls(
            doc_id=doc_id, machine_key=manifest.machine.key, issued_by=issued_by,
            issued_at=issued_at,
            configuration_hash=manifest.configuration_hash(),
            legislation=legislation, standards=standards,
            notified_body=notified_body, notified_body_number=notified_body_number,
            signatory=signatory, place=place,
        )


@dataclass(frozen=True)
class DeclarationStatus:
    """Whether the declaration still describes the machine, and on what evidence."""

    doc_id: str
    machine_key: str
    verdict: DeclarationVerdict
    declared_configuration: str
    current_configuration: str
    lapsed_functions: tuple[str, ...]
    statement: str
    checks_skipped: tuple[str, ...]

    @property
    def is_sound(self) -> bool:
        return self.verdict.is_sound

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "machine": self.machine_key,
            "verdict": self.verdict.value,
            "declared_configuration": self.declared_configuration,
            "current_configuration": self.current_configuration,
            "lapsed_functions": list(self.lapsed_functions),
            "statement": self.statement,
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        lines = [f"{self.doc_id} — {self.verdict.value.replace('_', ' ').upper()}",
                 f"  {self.statement}"]
        if self.lapsed_functions:
            lines.append(f"  lapsed: {', '.join(self.lapsed_functions)}")
        return "\n".join(lines)


def check_declaration(
    declaration: DeclarationOfConformity,
    manifest: SafetyManifest,
    coverage: CoverageReport | None = None,
) -> DeclarationStatus:
    """Does this declaration still describe this machine?

    Two separate questions, reported separately because they have different
    remedies. *Is the configuration the declared one?* — if not, the declaration
    is about software that is no longer installed. *Does the evidence for the
    declared safety functions still stand?* — if not, the configuration is right
    and the demonstration behind it has lapsed.
    """
    current = manifest.configuration_hash()
    caveats: list[str] = [
        "this establishes whether the configuration is the declared one. Whether a "
        "change amounts to a substantial modification requiring a new conformity "
        "assessment is a question for the manufacturer and, where one is involved, "
        "the notified body. Nothing here is legal advice.",
    ]

    if manifest.machine.key != declaration.machine_key:
        return DeclarationStatus(
            doc_id=declaration.doc_id, machine_key=manifest.machine.key,
            verdict=DeclarationVerdict.WRONG_MACHINE,
            declared_configuration=declaration.configuration_hash,
            current_configuration=current, lapsed_functions=(),
            statement=(
                f"declaration {declaration.doc_id} is about "
                f"{declaration.machine_key}, and this manifest is about "
                f"{manifest.machine.key}. It says nothing about this machine."
            ),
            checks_skipped=tuple(caveats),
        )

    if manifest.uncomparable_items:
        caveats.append(
            f"{len(manifest.uncomparable_items)} item(s) in this manifest carry no "
            "hash and therefore do not contribute to the configuration hash. A "
            "change confined to those items leaves the configuration hash unmoved "
            "and would not appear here."
        )

    lapsed: tuple[str, ...] = ()
    if coverage is not None:
        lapsed = tuple(f.function_id for f in coverage.functions
                       if f.coverage is not Coverage.CURRENT)
        undem = [f.function_id for f in coverage.functions
                 if f.coverage is Coverage.NOT_DEMONSTRABLE]
        if undem:
            caveats.append(
                "safety function(s) " + ", ".join(undem) + " declare no verification "
                "check, so this says nothing about whether they are demonstrated. "
                "They are counted as lapsed because 'not shown' is not 'shown'."
            )
    else:
        caveats.append(
            "no coverage assessment was supplied, so only the configuration was "
            "compared. The declaration may name a configuration that is intact and "
            "safety functions whose demonstration has lapsed."
        )

    if current != declaration.configuration_hash:
        return DeclarationStatus(
            doc_id=declaration.doc_id, machine_key=manifest.machine.key,
            verdict=DeclarationVerdict.CONFIGURATION_CHANGED,
            declared_configuration=declaration.configuration_hash,
            current_configuration=current, lapsed_functions=lapsed,
            statement=(
                f"declaration {declaration.doc_id}, issued "
                f"{format_utc(declaration.issued_at)[:10]} by "
                f"{declaration.issued_by or 'the manufacturer'}, covers configuration "
                f"{declaration.configuration_hash[:12]}. "
                f"{manifest.machine.key} currently runs {current[:12]}. The "
                "declaration does not describe this machine."
            ),
            checks_skipped=tuple(caveats),
        )

    if lapsed:
        return DeclarationStatus(
            doc_id=declaration.doc_id, machine_key=manifest.machine.key,
            verdict=DeclarationVerdict.CONFIGURATION_INTACT_EVIDENCE_LAPSED,
            declared_configuration=declaration.configuration_hash,
            current_configuration=current, lapsed_functions=lapsed,
            statement=(
                f"the configuration is the one declaration {declaration.doc_id} was "
                f"signed against ({current[:12]}), and the evidence for "
                + ", ".join(lapsed) + " no longer stands. The declaration names a "
                "machine that is unchanged and a demonstration that has lapsed."
            ),
            checks_skipped=tuple(caveats),
        )

    return DeclarationStatus(
        doc_id=declaration.doc_id, machine_key=manifest.machine.key,
        verdict=DeclarationVerdict.DESCRIBES_THE_MACHINE,
        declared_configuration=declaration.configuration_hash,
        current_configuration=current, lapsed_functions=(),
        statement=(
            f"{manifest.machine.key} runs configuration {current[:12]}, which is the "
            f"one declaration {declaration.doc_id} was signed against, and every "
            "declared safety function has evidence that still stands."
        ),
        checks_skipped=tuple(caveats),
    )
