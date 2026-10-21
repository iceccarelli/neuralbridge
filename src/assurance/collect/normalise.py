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

The file is hostile until proven otherwise. It may be enormous, an archive that
inflates a thousandfold, a JSON document nested ten thousand deep, a text file
that is one endless line, or unreadable halfway through. Every limit below turns
into a :class:`NormalisationError` — "this item could not be hashed" — never
into a hang, a crash, or a digest of part of the file. A result that read less
than the whole of what it was asked to read says so with ``complete=False`` and
the collector reports the item as unreadable, which is INCOMPLETE, which is
never "unchanged".
"""

from __future__ import annotations

import codecs
import hashlib
import json
import re
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import canonical_json, content_hash_of

__all__ = [
    "MAX_ARCHIVE_ENTRIES",
    "MAX_ARCHIVE_MEMBER_BYTES",
    "MAX_ARCHIVE_TOTAL_BYTES",
    "MAX_LINE_CHARS",
    "MAX_RAW_BYTES",
    "MAX_TEXT_BYTES",
    "NormalisationError",
    "NormalisationResult",
    "Normaliser",
    "Rule",
    "normalise_file",
    "split_lines",
]

#: Resource limits. They are far above any real export and well below what would
#: exhaust a laptop; like the plausibility rails in the machine package they are
#: sanity limits, not figures from a standard. A file past one is refused, not
#: truncated.
MAX_RAW_BYTES = 4 * 1024**3             # a firmware image, streamed
MAX_TEXT_BYTES = 64 * 1024**2           # text / JSON are held in memory
MAX_LINE_CHARS = 1024**2                # one line of a text export
MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024**2
MAX_ARCHIVE_TOTAL_BYTES = 2 * 1024**3
_CHUNK = 1024 * 1024


class NormalisationError(AssuranceError):
    """A normalisation rule is malformed, or cannot be applied to this file."""


class Normaliser(StrEnum):
    """How to reduce a file to the bytes that are actually the machine."""

    #: Hash the file exactly as it is. Correct for firmware images and anything
    #: else the vendor ships as an opaque, stable blob.
    RAW = "raw"
    #: Read as text, drop every line matching a declared pattern, hash the rest.
    #: For exports that stamp a header with the time and the operator. Lines end
    #: at CR, LF or CRLF only; the three are one text. Any other separator
    #: (form feed, U+2028 …) stays inside its line, so changing one to a newline
    #: changes the digest.
    TEXT_EXCLUDING = "text_excluding"
    #: Parse as JSON, remove declared keys by dotted path, hash canonically.
    #: Key order and whitespace stop mattering, which is usually what you want.
    #: A document with a repeated key, or a NaN/Infinity constant, is refused.
    JSON_EXCLUDING = "json_excluding"
    #: Hash named members of an archive, ignoring the archive's own metadata.
    #: A project export is a zip whose timestamps change on every save.
    ZIP_MEMBERS = "zip_members"

    @property
    def drops_content(self) -> bool:
        """Whether this rule can remove bytes, and so needs stating in the manifest."""
        return self is not Normaliser.RAW


def _unsafe_member(name: str) -> bool:
    return (not name or name.startswith("/") or "\\" in name or "\x00" in name
            or ".." in PurePosixPath(name).parts)


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
        if self.kind is Normaliser.RAW and (self.patterns or self.keys or self.members):
            raise NormalisationError(
                "a raw rule hashes every byte. Patterns, keys or members on it would "
                "look like an exclusion that does not happen and would change the "
                "rule's fingerprint; use text_excluding, json_excluding or "
                "zip_members, or remove them."
            )
        if self.kind is Normaliser.TEXT_EXCLUDING and not self.patterns:
            raise NormalisationError(
                "text_excluding with no patterns drops nothing; use raw instead so "
                "the manifest does not claim a normalisation that did not happen."
            )
        if self.kind is Normaliser.JSON_EXCLUDING and not self.keys \
                and not self.note.strip():
            raise NormalisationError(
                "json_excluding with no keys still canonicalises the document, which "
                "is a real change to what is hashed. List the keys you meant to drop, "
                "or say in `note` that canonicalisation alone is the intent."
            )
        if self.kind is Normaliser.ZIP_MEMBERS and not self.members:
            raise NormalisationError(
                "zip_members with no members would hash nothing at all."
            )
        if self.kind.drops_content and not self.note.strip():
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
        try:
            codecs.lookup(self.encoding)
        except LookupError as exc:
            raise NormalisationError(
                f"encoding {self.encoding!r} is not a codec this system knows."
            ) from exc
        for m in self.members:
            if _unsafe_member(m):
                raise NormalisationError(
                    f"archive member {m!r} is empty, absolute, or climbs out of the "
                    "archive. Members are matched by name and never extracted, but a "
                    "name like that is not one a plan should declare."
                )

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
        try:
            kind = Normaliser(str(d.get("kind", "raw")))
        except ValueError as exc:
            raise NormalisationError(
                f"rule kind {d.get('kind')!r} is not one of "
                f"{', '.join(n.value for n in Normaliser)}."
            ) from exc
        return cls(
            kind=kind,
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
    #: False when the digest was computed from less than the rule asked for: a
    #: declared archive member was absent. The digest is then of a different
    #: thing and is not a measurement of the item.
    complete: bool = True

    @property
    def dropped_everything(self) -> bool:
        return self.bytes_hashed == 0

    @property
    def usable(self) -> bool:
        """Whether this digest may be recorded as the item's identity."""
        return self.complete and not self.dropped_everything

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "rule_fingerprint": self.rule_fingerprint,
            "kind": self.kind.value,
            "bytes_in": self.bytes_in,
            "bytes_hashed": self.bytes_hashed,
            "applied": dict(sorted(self.applied.items())),
            "warnings": list(self.warnings),
            "complete": self.complete,
        }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def split_lines(text: str) -> list[str]:
    """Split on CR, LF and CRLF only, as :attr:`Normaliser.TEXT_EXCLUDING` defines."""
    lines = re.split(r"\r\n|\r|\n", text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


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


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate key {k!r}")
        seen.add(k)
    return dict(pairs)


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"the non-standard constant {name} is not valid JSON")


def normalise_bytes(data: bytes, rule: Rule, *, label: str = "") -> NormalisationResult:
    """Apply a rule to bytes already in hand."""
    warnings: list[str] = []
    applied: dict[str, int] = {}
    where = f"{label}: " if label else ""

    if rule.kind is Normaliser.RAW:
        if len(data) > MAX_RAW_BYTES:
            raise NormalisationError(
                f"{where}{len(data)} bytes exceeds the {MAX_RAW_BYTES} this system "
                "will hash.")
        return NormalisationResult(
            digest=_sha(data), rule_fingerprint=rule.fingerprint(),
            kind=rule.kind, bytes_in=len(data), bytes_hashed=len(data),
        )

    if len(data) > MAX_TEXT_BYTES:
        raise NormalisationError(
            f"{where}{len(data)} bytes is too large to read as {rule.kind.value} "
            f"(the limit is {MAX_TEXT_BYTES}). Hash it raw, or as zip_members.")

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
        for line in split_lines(text):
            if len(line) > MAX_LINE_CHARS:
                raise NormalisationError(
                    f"{where}a line of {len(line)} characters exceeds the "
                    f"{MAX_LINE_CHARS} this system will match patterns against. "
                    "That is not a text export.")
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
            doc = json.loads(data.decode(rule.encoding),
                             object_pairs_hook=_no_duplicate_keys,
                             parse_constant=_refuse_constant)
            for key in rule.keys:
                doc, hits = _prune(doc, key.split("."))
                applied[key] = hits
                if hits == 0:
                    warnings.append(
                        f"{where}key {key!r} was not present. Either the rule is "
                        "wrong or the vendor changed their export format."
                    )
            body = canonical_json(doc).encode("utf-8")
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise NormalisationError(
                f"{where}cannot be read as JSON: {exc}."
            ) from exc
        return NormalisationResult(
            digest=_sha(body), rule_fingerprint=rule.fingerprint(), kind=rule.kind,
            bytes_in=len(data), bytes_hashed=len(body), applied=applied,
            warnings=tuple(warnings),
        )

    raise NormalisationError(
        f"{rule.kind.value} needs a file on disk; use normalise_file()."
    )


def _read_capped(path: Path, cap: int, what: str) -> bytes:
    """Read a whole file, refusing rather than reading past ``cap``."""
    try:
        with path.open("rb") as fh:
            data = fh.read(cap + 1)
    except OSError as exc:
        raise NormalisationError(f"{path.name}: cannot read it: {exc}") from exc
    if len(data) > cap:
        raise NormalisationError(
            f"{path.name}: more than {cap} bytes, too large to read as {what}.")
    return data


def _hash_raw_file(path: Path, rule: Rule) -> NormalisationResult:
    h = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as fh:
            while chunk := fh.read(_CHUNK):
                total += len(chunk)
                if total > MAX_RAW_BYTES:
                    raise NormalisationError(
                        f"{path.name}: more than {MAX_RAW_BYTES} bytes exceeds what "
                        "this system will hash.")
                h.update(chunk)
    except OSError as exc:
        raise NormalisationError(f"{path.name}: cannot read it: {exc}") from exc
    return NormalisationResult(
        digest=h.hexdigest(), rule_fingerprint=rule.fingerprint(), kind=rule.kind,
        bytes_in=total, bytes_hashed=total,
    )


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def _hash_zip_members(p: Path, rule: Rule) -> NormalisationResult:
    size = p.stat().st_size
    warnings: list[str] = []
    applied: dict[str, int] = {}
    parts: list[tuple[str, str]] = []
    hashed = 0
    complete = True

    try:
        archive = zipfile.ZipFile(p)
    except (zipfile.BadZipFile, OSError, EOFError, ValueError) as exc:
        raise NormalisationError(f"{p.name}: not a readable archive: {exc}") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise NormalisationError(
                f"{p.name}: {len(infos)} entries exceeds the {MAX_ARCHIVE_ENTRIES} "
                "this system will index.")
        counts = Counter(i.filename for i in infos)
        declared_total = 0
        for member in rule.members:
            if counts[member] == 0:
                applied[member] = 0
                complete = False
                warnings.append(
                    f"{p.name}: member {member!r} is not in the archive. The digest "
                    "below was computed without it, so it is not comparable with one "
                    "taken when the member was present."
                )
                continue
            if counts[member] > 1:
                raise NormalisationError(
                    f"{p.name}: member {member!r} appears more than once. Which copy "
                    "an extractor would use is up to the extractor, so the archive "
                    "does not say what it contains.")
            info = archive.getinfo(member)
            if info.is_dir():
                raise NormalisationError(
                    f"{p.name}: member {member!r} is a directory, not a file.")
            if _is_symlink(info):
                raise NormalisationError(
                    f"{p.name}: member {member!r} is a symbolic link. Its bytes are "
                    "the name of its target, not the target's content.")
            if info.flag_bits & 0x1:
                raise NormalisationError(
                    f"{p.name}: member {member!r} is encrypted and cannot be read.")
            if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise NormalisationError(
                    f"{p.name}: member {member!r} declares {info.file_size} bytes, "
                    f"which exceeds the {MAX_ARCHIVE_MEMBER_BYTES} this system will "
                    "inflate.")
            declared_total += info.file_size
            if declared_total > MAX_ARCHIVE_TOTAL_BYTES:
                raise NormalisationError(
                    f"{p.name}: the declared members total more than "
                    f"{MAX_ARCHIVE_TOTAL_BYTES} bytes.")
            h = hashlib.sha256()
            read = 0
            try:
                with archive.open(info) as fh:
                    while chunk := fh.read(_CHUNK):
                        read += len(chunk)
                        if read > MAX_ARCHIVE_MEMBER_BYTES:
                            raise NormalisationError(
                                f"{p.name}: member {member!r} inflated past the "
                                f"{MAX_ARCHIVE_MEMBER_BYTES} this system will read.")
                        h.update(chunk)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError,
                    zlib.error, OSError) as exc:
                raise NormalisationError(
                    f"{p.name}: member {member!r} cannot be read (corrupt or "
                    f"unsupported: {exc}).") from exc
            applied[member] = 1
            hashed += read
            parts.append((member, h.hexdigest()))

    if not parts:
        complete = False
        warnings.append(
            f"{p.name}: none of the declared members were found, so nothing was "
            "hashed."
        )

    digest = content_hash_of({"members": sorted(parts)})
    return NormalisationResult(
        digest=digest, rule_fingerprint=rule.fingerprint(), kind=rule.kind,
        bytes_in=size, bytes_hashed=hashed, applied=applied,
        warnings=tuple(warnings), complete=complete,
    )


def normalise_file(path: str | Path, rule: Rule) -> NormalisationResult:
    """Apply a rule to a file.

    ``zip_members`` is handled here because an archive is read member by member
    rather than as one blob: the archive's own directory carries modification
    times that change on every save and have nothing to do with the machine.
    Nothing is ever extracted: members are read by name, so a member called
    ``../x`` cannot write anywhere.

    Raises :class:`NormalisationError` for anything that makes the file unreadable
    or over a limit, including an operating-system error part-way through.
    """
    p = Path(path)
    if rule.kind is Normaliser.RAW:
        return _hash_raw_file(p, rule)
    if rule.kind is not Normaliser.ZIP_MEMBERS:
        return normalise_bytes(_read_capped(p, MAX_TEXT_BYTES, rule.kind.value), rule,
                               label=p.name)
    try:
        return _hash_zip_members(p, rule)
    except OSError as exc:
        raise NormalisationError(f"{p.name}: cannot read it: {exc}") from exc
