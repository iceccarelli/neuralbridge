"""What every import shares: a bounded, strict JSON reader and the record of what was supplied.

The two documents this package reads come from outside the trust boundary. The reader therefore
refuses, with a reason and before building anything, a document that is too large, nested too
deeply, not UTF-8, not JSON, carries a NUL byte, repeats a key inside one object (two readers can
take different values from it) or contains ``NaN``/``Infinity``. It never repairs anything.

The SHA-256 of the **bytes as received** is taken before any parsing and is what the record keeps
as the identity of the source. The name, timestamp and URL the caller says the document has are
kept exactly as supplied and are labelled as the caller's words: nothing here checks them.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc
from assurance.core.text import invisible_characters

__all__ = [
    "MAX_DOCUMENT_BYTES",
    "MAX_JSON_DEPTH",
    "IngestError",
    "SourceRecord",
    "check_label",
    "make_source",
    "parse_json_document",
]

#: The largest document read. The HTTP API is bounded further by its request-body cap.
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
#: How deeply arrays/objects may nest before the document is refused unread.
MAX_JSON_DEPTH = 40
MAX_LABEL_CHARS = 300
MAX_URL_CHARS = 2000

_HEX64 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]', re.S)
_URL = re.compile(r"https?://[^\s/?#][^\s]*")


class IngestError(AssuranceError):
    """An import is refused. Nothing was recorded.

    ``code`` is a short stable token (``invalid_sbom``, ``invalid_csaf``, ``too_large`` ...) the
    API returns as ``error``; ``violations`` lists, one per rule broken, why the document was
    refused, so a person can fix the source rather than guess.
    """

    def __init__(self, message: str, *, code: str = "invalid_document",
                 violations: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.code = code
        self.violations = violations


def check_label(value: Any, what: str, *, max_chars: int = MAX_LABEL_CHARS) -> str:
    """A caller-supplied label as it was given, or :class:`IngestError`. Never edited."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise IngestError(f"{what} must be text.", code="invalid_source")
    if len(value) > max_chars:
        raise IngestError(f"{what} is longer than {max_chars} characters.", code="invalid_source")
    bad = invisible_characters(value)
    if bad:
        raise IngestError(
            f"{what} contains a control or invisible character ({', '.join(bad)}); it is "
            "recorded as supplied or not at all, so it is refused.", code="invalid_source")
    return value


@dataclass(frozen=True)
class SourceRecord:
    """The source of a document, as the importer saw it and as the caller said it was."""

    #: SHA-256 of the document's bytes exactly as received (before any decoding).
    sha256: str
    size_bytes: int
    #: As supplied by the caller (a file name, a feed name). Not verified.
    name: str = ""
    #: As supplied by the caller: when the document was produced or fetched. Not verified.
    supplied_at: str = ""
    #: As supplied by the caller: where the document came from. Not fetched, not verified.
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256, "sha256_basis": "of the document's bytes as received",
            "size_bytes": self.size_bytes,
            "name_as_supplied": self.name, "supplied_at_as_supplied": self.supplied_at,
            "url_as_supplied": self.url,
            "supplied_fields_verified": False,
        }


def make_source(raw: bytes, *, name: str | None = None, supplied_at: str | None = None,
                url: str | None = None, claimed_sha256: str | None = None) -> SourceRecord:
    """Hash the bytes and validate the labels. ``claimed_sha256`` must equal the computed hash."""
    if not isinstance(raw, bytes | bytearray):
        raise IngestError("the document must be bytes.", code="invalid_source")
    digest = hashlib.sha256(bytes(raw)).hexdigest()
    if claimed_sha256:
        claim = claimed_sha256.strip().lower()
        if not _HEX64.fullmatch(claim):
            raise IngestError("source_sha256 is not 64 hexadecimal characters.",
                              code="invalid_source")
        if claim != digest:
            raise IngestError(
                "the document's SHA-256 is not the one the caller stated "
                f"(computed {digest[:16]}..., stated {claim[:16]}...). The bytes received are "
                "not the bytes described; nothing was recorded.", code="source_hash_mismatch")
    label = check_label(name, "the source name")
    when = check_label(supplied_at, "the supplied timestamp", max_chars=64)
    if when:
        try:
            parse_utc(when)
        except ValueError as exc:
            raise IngestError(
                f"the supplied timestamp {when!r} is not an ISO-8601 time with a timezone "
                f"({exc}). It is kept as supplied or not at all.", code="invalid_source") from exc
    where = check_label(url, "the source URL", max_chars=MAX_URL_CHARS)
    if where and not _URL.fullmatch(where):
        raise IngestError("the source URL must be an absolute http(s) URL.",
                          code="invalid_source")
    return SourceRecord(sha256=digest, size_bytes=len(raw), name=label, supplied_at=when, url=where)


def _depth_exceeds(text: str, limit: int) -> bool:
    depth = 0
    for match in _TOKEN.finditer(text):
        char = match.group()[0]
        if char in "[{":
            depth += 1
            if depth > limit:
                return True
        elif char in "]}":
            depth -= 1
    return False


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r} in a JSON object")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def parse_json_document(raw: bytes, what: str, *, max_bytes: int = MAX_DOCUMENT_BYTES,
                        max_depth: int = MAX_JSON_DEPTH) -> Any:
    """Parse ``raw`` as strict JSON or raise :class:`IngestError`. See the module docstring."""
    if len(raw) > max_bytes:
        raise IngestError(
            f"the {what} is {len(raw):,} bytes, over the {max_bytes:,} this importer reads; it "
            "is refused rather than truncated.", code="too_large")
    if not raw.strip():
        raise IngestError(f"the {what} is empty.", code="invalid_document")
    if b"\x00" in raw:
        raise IngestError(f"the {what} contains a NUL byte.", code="invalid_document")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError(f"the {what} is not UTF-8 text ({exc.reason}).",
                          code="invalid_document") from exc
    if _depth_exceeds(text, max_depth):
        raise IngestError(
            f"the {what} nests arrays or objects more than {max_depth} deep; it is refused "
            "unread.", code="too_deep")
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_refuse_constant)
    except RecursionError as exc:
        raise IngestError(f"the {what} is nested so deeply that it was refused.",
                          code="too_deep") from exc
    except ValueError as exc:
        raise IngestError(f"the {what} is not valid JSON: {exc}", code="invalid_document") from exc
