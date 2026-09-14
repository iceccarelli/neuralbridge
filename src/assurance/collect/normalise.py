"""Hashing a vendor export without the export's own noise.

This module solves the problem that quietly ruins every configuration-drift
tool ever built for industrial software.

A safety PLC export, a scanner configuration, a robot parameter dump: almost
none of them are byte-stable. They carry the time of export, the name of the
engineer who pressed the button, a sequence number, a checksum of themselves.
Export the same unchanged machine twice and the bytes differ. Hash the file as
it is and every weekly collection reports drift on every machine, the customer
stops reading the report within a fortnight, and the one week the firmware
really did change is the week nobody looks.

The fix is not to hash less carefully. It is to declare, per item, exactly which
bytes are the machine and which are the export, and then to make that
declaration part of the item's identity — so two digests are only ever compared
when they were produced by the same rule, and a silently changed rule is as
visible as a silently changed artefact.

Every normaliser reports what it dropped. A declared rule that matched nothing
is a warning, not a success: either the rule is wrong or the vendor changed
their format, and both mean the digest is not what the author intended.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import canonical_json, content_hash_of

__all__ = [
    "NormalisationError",
    "NormalisationResult",
    "Normaliser",
    "Rule",
    "normalise_file",
]


class NormalisationError(AssuranceError):
    """A normalisation rule is malformed, or cannot be applied to this file."""


class Normaliser(StrEnum):
    """How to reduce a file to the bytes that are actually the machine."""

    #: Hash the file exactly as it is. Correct for firmware images and anything
    #: else the vendor ships as an opaque, stable blob.
    RAW = "raw"
    #: Read as text, drop every line matching a declared pattern, hash the rest.
    #: For exports that stamp a header with the time and the operator.
    TEXT_EXCLUDING = "text_excluding"
    #: Parse as JSON, remove declared keys by dotted path, hash canonically.
    #: Key order and whitespace stop mattering, which is usually what you want.
    JSON_EXCLUDING = "json_excluding"
    #: Hash named members of an archive, ignoring the archive's own metadata.
    #: A project export is a zip whose timestamps change on every save.
    ZIP_MEMBERS = "zip_members"

    @property
    def drops_content(self) -> bool:
        """Whether this rule can remove bytes, and so needs stating in the manifest."""
        return self is not Normaliser.RAW


@dataclass(frozen=True)
class Rule:
    """One declared normalisation. Part of the item's identity, not a setting."""

    kind: Normaliser = Normaliser.RAW
    #: Regular expressions; a line matching any of them is dropped.
    patterns: tuple[str, ...] = ()
    #: Dotted paths, e.g. ``export.timestamp`` or ``meta.operator``.
    keys: tuple[str, ...] = ()
    #: Archive member names to hash. Everything else in the archive is ignored.
    members: tuple[str, ...] = ()
    encoding: str = "utf-8"
    #: Why these bytes are the export rather than the machine. Required when the
    #: rule drops anything: an unexplained exclusion is indistinguishable from
    #: hiding a change.
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind is Normaliser.TEXT_EXCLUDING and not self.patterns:
            raise NormalisationError(
                "text_excluding with no patterns drops nothing; use raw instead so "
                "the manifest does not claim a normalisation that did not happen."
            )
        if self.kind is Normaliser.JSON_EXCLUDING and not self.keys and not self.note:
            raise NormalisationError(
                "json_excluding with no keys still canonicalises the document, which "
                "is a real change to what is hashed. List the keys you meant to drop, "
                "or say in `note` that canonicalisation alone is the intent."
            )
        if self.kind is Normaliser.ZIP_MEMBERS and not self.members:
            raise NormalisationError(
                "zip_members with no members would hash nothing at all."
            )
        if self.kind.drops_content and not self.note:
            raise NormalisationError(
                f"a {self.kind.value} rule removes bytes before hashing and carries no "
                "note. An unexplained exclusion cannot be told apart from hiding a "
                "change. Say which bytes belong to the export rather than the machine."
            )
        for p in self.patterns:
            try:
                re.compile(p)
            except re.error as exc:
                raise NormalisationError(f"pattern {p!r} is not a regex: {exc}") from exc

    def fingerprint(self) -> str:
        """Identity of the rule itself.

        Recorded alongside every digest it produces. Two digests are comparable
        only if this matches: a digest produced under a changed rule is a
        different measurement, not a changed machine.
        """
        return content_hash_of({
            "kind": self.kind.value,
            "patterns": sorted(self.patterns),
            "keys": sorted(self.keys),
            "members": sorted(self.members),
            "encoding": self.encoding,
        })[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value, "patterns": list(self.patterns),
            "keys": list(self.keys), "members": list(self.members),
            "encoding": self.encoding, "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> Rule:
        if not d:
            return cls()
        return cls(
            kind=Normaliser(str(d.get("kind", "raw"))),
            patterns=tuple(str(p) for p in (d.get("patterns") or ())),
            keys=tuple(str(k) for k in (d.get("keys") or ())),
            members=tuple(str(m) for m in (d.get("members") or ())),
            encoding=str(d.get("encoding", "utf-8")),
            note=str(d.get("note", "")),
        )


@dataclass(frozen=True)
class NormalisationResult:
    """A digest, and an honest account of how it was arrived at."""

    digest: str
    rule_fingerprint: str
    kind: Normaliser
    bytes_in: int
    bytes_hashed: int
    #: Per pattern/key/member: how many times it actually applied.
    applied: dict[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    @property
    def dropped_everything(self) -> bool:
        return self.bytes_hashed == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "rule_fingerprint": self.rule_fingerprint,
            "kind": self.kind.value,
            "bytes_in": self.bytes_in,
            "bytes_hashed": self.bytes_hashed,
            "applied": dict(sorted(self.applied.items())),
            "warnings": list(self.warnings),
        }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prune(obj: Any, parts: list[str]) -> tuple[Any, int]:
    """Remove one dotted path from a parsed JSON document. Returns (obj, hits)."""
    if not parts:
        return obj, 0
    head, rest = parts[0], parts[1:]
    hits = 0
    if isinstance(obj, dict):
        if not rest:
            if head in obj:
                obj = {k: v for k, v in obj.items() if k != head}
                hits += 1
            return obj, hits
        if head in obj:
            child, h = _prune(obj[head], rest)
            hits += h
            obj = {**obj, head: child}
        return obj, hits
    if isinstance(obj, list):
        out = []
        for element in obj:
            child, h = _prune(element, parts)
            hits += h
            out.append(child)
        return out, hits
    return obj, hits


def normalise_bytes(data: bytes, rule: Rule, *, label: str = "") -> NormalisationResult:
    """Apply a rule to bytes already in hand."""
    warnings: list[str] = []
    applied: dict[str, int] = {}
    where = f"{label}: " if label else ""

    if rule.kind is Normaliser.RAW:
        return NormalisationResult(
            digest=_sha(data), rule_fingerprint=rule.fingerprint(),
            kind=rule.kind, bytes_in=len(data), bytes_hashed=len(data),
        )

    if rule.kind is Normaliser.TEXT_EXCLUDING:
        try:
            text = data.decode(rule.encoding)
        except UnicodeDecodeError as exc:
            raise NormalisationError(
                f"{where}cannot read as {rule.encoding} text: {exc}. A binary export "
                "needs a raw or zip_members rule."
            ) from exc
        compiled = [(p, re.compile(p)) for p in rule.patterns]
        kept: list[str] = []
        for line in text.splitlines():
            hit = next((p for p, rx in compiled if rx.search(line)), None)
            if hit is None:
                kept.append(line)
            else:
                applied[hit] = applied.get(hit, 0) + 1
        for p, _ in compiled:
            if p not in applied:
                warnings.append(
                    f"{where}pattern {p!r} matched no line. Either the rule is wrong "
                    "or the vendor changed their export format; this digest is not "
                    "what the rule's author intended."
                )
        body = "\n".join(kept).encode("utf-8")
        return NormalisationResult(
            digest=_sha(body), rule_fingerprint=rule.fingerprint(), kind=rule.kind,
            bytes_in=len(data), bytes_hashed=len(body), applied=applied,
            warnings=tuple(warnings),
        )

    if rule.kind is Normaliser.JSON_EXCLUDING:
        try:
            doc = json.loads(data.decode(rule.encoding))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NormalisationError(
                f"{where}cannot parse as JSON: {exc}."
            ) from exc
        for key in rule.keys:
            doc, hits = _prune(doc, key.split("."))
            applied[key] = hits
            if hits == 0:
                warnings.append(
                    f"{where}key {key!r} was not present. Either the rule is wrong or "
                    "the vendor changed their export format."
                )
        body = canonical_json(doc).encode("utf-8")
        return NormalisationResult(
            digest=_sha(body), rule_fingerprint=rule.fingerprint(), kind=rule.kind,
            bytes_in=len(data), bytes_hashed=len(body), applied=applied,
            warnings=tuple(warnings),
        )

    raise NormalisationError(
        f"{rule.kind.value} needs a file on disk; use normalise_file()."
    )


def normalise_file(path: str | Path, rule: Rule) -> NormalisationResult:
    """Apply a rule to a file.

    ``zip_members`` is handled here because an archive is read member by member
    rather than as one blob: the archive's own directory carries modification
    times that change on every save and have nothing to do with the machine.
    """
    p = Path(path)
    if rule.kind is not Normaliser.ZIP_MEMBERS:
        return normalise_bytes(p.read_bytes(), rule, label=p.name)

    size = p.stat().st_size
    warnings: list[str] = []
    applied: dict[str, int] = {}
    parts: list[tuple[str, str]] = []
    hashed = 0

    try:
        archive = zipfile.ZipFile(p)
    except zipfile.BadZipFile as exc:
        raise NormalisationError(f"{p.name}: not a readable archive: {exc}") from exc

    with archive:
        present = set(archive.namelist())
        for member in rule.members:
            if member not in present:
                applied[member] = 0
                warnings.append(
                    f"{p.name}: member {member!r} is not in the archive. The digest "
                    "below was computed without it, so it is not comparable with one "
                    "taken when the member was present."
                )
                continue
            data = archive.read(member)
            applied[member] = 1
            hashed += len(data)
            parts.append((member, _sha(data)))

    if not parts:
        warnings.append(
            f"{p.name}: none of the declared members were found, so nothing was "
            "hashed."
        )

    digest = content_hash_of({"members": sorted(parts)})
    return NormalisationResult(
        digest=digest, rule_fingerprint=rule.fingerprint(), kind=rule.kind,
        bytes_in=size, bytes_hashed=hashed, applied=applied,
        warnings=tuple(warnings),
    )
