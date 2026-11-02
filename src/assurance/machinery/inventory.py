"""Bulk enrolment from the inventory export a customer already has.

``machinery enrol`` takes one machine at a time. A plant that wants ten, or two hundred, machines
on the register already holds a list: an asset-management or CMDB export (SAP PM, Maximo, a
spreadsheet). This module turns **a file** of that kind into one manifest per row and enrols each
row through :func:`assurance.machinery.enrol.enrol_machine`, the one front door. It does not
reimplement sealing, idempotence, conflict detection or the actor rule.

What this is: a file importer. It is not a CMDB connector, not a supported adapter and not an
integration with any asset-management product; nothing here talks to a live system.

What the data is, and how the record says so. Every row is **customer-provided, as declared by the
customer's own system, and not collected from the machine**. In the existing vocabulary: the
manifest source is ``as_declared`` and every item's hash source is ``declared`` (a digest the
export carries is a digest somebody typed or exported; nothing was hashed off a unit). The
provenance travels in the sealed manifest: importer version, source system, export date, the file's
SHA-256 and the row number. No new trust tier is invented; the ceiling is the lowest the model has.

What a row does not do:

* a bad row (``rejected``) never aborts the batch and never writes;
* a malformed digest rejects the **row**; it is never repaired or guessed;
* a duplicate machine key inside the file is rejected on its second occurrence;
* rows past ``max_rows`` are **not processed** and are reported as a count, never dropped silently;
* a cell that begins with ``= + - @`` is kept as text. Nothing here evaluates a cell;
* control characters and invisible format characters are refused, field lengths are capped.

The file is read and checked completely before the ledger is opened for writing. A dry run
enrols into a throw-away copy of the ledger (the real ledger is only read, never opened and never
created) so that the outcomes shown are the ones the real run would produce.

Parsing stays on the caller's side of the API: the server accepts canonical rows
(:func:`canonical_row`), not an uploaded CSV.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import shutil
import sqlite3
import tempfile
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import (
    ALREADY_ENROLLED,
    CONFIGURATION_DIFFERS,
    ENROLLED,
    IDENTITY_CONFLICT,
    enrol_machine,
    require_person,
)
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)

__all__ = [
    "DEFAULT_MAX_ROWS",
    "IMPORTER",
    "IMPORT_KIND",
    "InventoryImportError",
    "InventoryRow",
    "ImportMapping",
    "ImportReport",
    "LedgerChainUnverifiedError",
    "REJECTED",
    "RowOutcome",
    "RowRejected",
    "canonical_row",
    "import_file",
    "import_rows",
    "load_mapping",
]

IMPORTER = "assurance.machinery.inventory/1"
IMPORT_KIND = "machinery.inventory_import"
IMPORT_SCHEMA = "assurance.machinery.inventory_import/1"

REJECTED = "rejected"
DEFAULT_MAX_ROWS = 500
#: The API takes canonical rows, never a file; a request carries at most this many.
API_MAX_ROWS = 200
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FIELD_CHARS = 200
MAX_ITEMS_PER_ROW = 50
MAX_REASON_CHARS = 300

_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_WHITESPACE_CONTROLS = frozenset("\t\r\n")

NOT_ESTABLISHED = (
    "the inventory is as declared by the customer's own system: nothing was read from a machine",
    "no verification has been run for any imported machine",
    "the export may be incomplete: a machine or software item absent from the file is absent "
    "from the record, and completeness is unknown",
    "identity is as declared, not authenticated to a physical unit",
    "an item without a digest cannot be compared later (uncomparable)",
)

NEXT_STEPS = (
    "verify the machines that matter: run `machine verify` per safety function and record it "
    "into this ledger, then `machinery coverage`",
    "resolve every row that is not enrolled: each carries its reason or a pointer",
)


class InventoryImportError(AssuranceError):
    """The file, mapping or request is refused as a whole. Nothing was written."""


class LedgerChainUnverifiedError(InventoryImportError):
    """The ledger chain does not verify, so nothing was imported."""


class RowRejected(Exception):  # noqa: N818  (a per-row verdict, not an error of the batch)
    """One row cannot be turned into a manifest. The reason never contains a cell value."""


# -- text hygiene --------------------------------------------------------------


def _clean(value: Any, what: str, *, required: bool = False) -> str:
    """One cell as plain text, or :class:`RowRejected`. Never evaluates, never repairs."""
    if value is None:
        text = ""
    elif isinstance(value, bool) or not isinstance(value, str | int):
        raise RowRejected(f"{what}: must be text")
    else:
        text = str(value)
    if len(text) > MAX_FIELD_CHARS:
        raise RowRejected(f"{what}: longer than {MAX_FIELD_CHARS} characters")
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in _WHITESPACE_CONTROLS:
            continue
        if cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            raise RowRejected(f"{what}: contains a control or invisible character "
                              f"(U+{ord(ch):04X})")
    text = " ".join(text.split())
    if required and not text:
        raise RowRejected(f"{what}: empty")
    return text


# -- canonical rows ------------------------------------------------------------


@dataclass(frozen=True)
class ItemDecl:
    name: str
    version: str
    supplier: str = ""
    sha256: str = ""
    kind: str = ItemKind.FIRMWARE.value
    implements: tuple[str, ...] = ()
    #: Stable position of this item among the mapping's items; part of the item id.
    slot: int = 0
    label: str = ""


@dataclass(frozen=True)
class InventoryRow:
    """One machine as the customer's export declares it, in canonical form."""

    row: int
    manufacturer: str
    model: str
    serial: str
    site: str = ""
    owner: str = ""
    year: str = ""
    country: str = ""
    items: tuple[ItemDecl, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.manufacturer}/{self.model}#{self.serial}"


@dataclass(frozen=True)
class FunctionDecl:
    function_id: str
    description: str
    required_performance: str = ""
    verified_by: tuple[str, ...] = ()


_ROW_KEYS = frozenset({"manufacturer", "model", "serial", "site", "owner", "year", "country",
                       "items"})
_ITEM_KEYS = frozenset({"name", "version", "supplier", "sha256", "kind", "implements"})


def _slug(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")
    return slug[:40] or "item"


def canonical_row(raw: Mapping[str, Any], row: int,
                  known_functions: frozenset[str] = frozenset()) -> InventoryRow:
    """A canonical machine dict -> :class:`InventoryRow`, or :class:`RowRejected`.

    The one validator for both the CLI (after mapping) and ``POST /v1/machinery/enrol/batch``.
    """
    if not isinstance(raw, Mapping):
        raise RowRejected("row is not an object")
    unknown = sorted(str(k) for k in raw if k not in _ROW_KEYS)
    if unknown:
        raise RowRejected("unknown field(s): " + ", ".join(unknown[:5]))
    manufacturer = _clean(raw.get("manufacturer"), "manufacturer", required=True)
    model = _clean(raw.get("model"), "model", required=True)
    serial = _clean(raw.get("serial"), "serial", required=True)
    site = _clean(raw.get("site"), "site")
    owner = _clean(raw.get("owner"), "owner")
    year = _clean(raw.get("year"), "year")
    if year and not re.fullmatch(r"\d{4}", year):
        raise RowRejected("year: not a four-digit year")
    country = _clean(raw.get("country"), "country").upper()
    if country and not (len(country) == 2 and country.isascii() and country.isalpha()):
        raise RowRejected("country: not an ISO 3166-1 alpha-2 code")
    raw_items = raw.get("items")
    if not isinstance(raw_items, list | tuple):
        raise RowRejected("items: missing")
    if len(raw_items) > MAX_ITEMS_PER_ROW:
        raise RowRejected(f"items: more than {MAX_ITEMS_PER_ROW}")
    items: list[ItemDecl] = []
    notes: list[str] = []
    for slot, entry in enumerate(raw_items):
        if not isinstance(entry, Mapping):
            raise RowRejected(f"item {slot + 1}: not an object")
        bad = sorted(str(k) for k in entry if k not in _ITEM_KEYS)
        if bad:
            raise RowRejected(f"item {slot + 1}: unknown field(s): " + ", ".join(bad[:5]))
        label = f"item {slot + 1}"
        name = _clean(entry.get("name"), f"{label} name")
        if not name:
            continue                                   # nothing listed in this slot
        version = _clean(entry.get("version"), f"{label} version")
        if not version:
            notes.append(f"{label} ({_slug(name)}) has no version in the export; not listed")
            continue
        supplier = _clean(entry.get("supplier"), f"{label} supplier")
        digest = _clean(entry.get("sha256"), f"{label} sha256")
        if digest and not _HEX64.fullmatch(digest):
            raise RowRejected(f"{label} sha256: not 64 hexadecimal characters; "
                              "never repaired or guessed")
        kind = _clean(entry.get("kind"), f"{label} kind") or ItemKind.FIRMWARE.value
        if kind not in {k.value for k in ItemKind}:
            raise RowRejected(f"{label} kind: not one of "
                              + ", ".join(sorted(k.value for k in ItemKind)))
        implements = entry.get("implements") or ()
        if not isinstance(implements, list | tuple) or not all(
                isinstance(i, str) for i in implements):
            raise RowRejected(f"{label} implements: must be a list of function ids")
        unknown_fn = sorted(set(implements) - known_functions)
        if unknown_fn:
            raise RowRejected(f"{label} implements: function(s) not declared: "
                              + ", ".join(unknown_fn[:5]))
        items.append(ItemDecl(name=name, version=version, supplier=supplier,
                              sha256=digest.lower(), kind=kind,
                              implements=tuple(implements), slot=slot, label=label))
    if not items:
        raise RowRejected("no software or firmware items listed for this machine")
    for field_name, value in (("manufacturer", manufacturer), ("model", model),
                              ("serial", serial), ("site", site), ("owner", owner)):
        if value[:1] in "=+-@":
            notes.append(f"{field_name} begins with {value[:1]!r}: kept as text, never evaluated")
    return InventoryRow(row=row, manufacturer=manufacturer, model=model, serial=serial,
                        site=site, owner=owner, year=year, country=country,
                        items=tuple(items), notes=tuple(notes))


# -- mapping -------------------------------------------------------------------

_MAPPING_KEYS = frozenset({"source_system", "export_date", "columns", "items", "functions"})
_COLUMN_FIELDS = ("manufacturer", "model", "serial", "site", "owner", "year", "country")
_REQUIRED_COLUMNS = ("manufacturer", "model", "serial")
_ITEM_MAP_KEYS = frozenset({"name", "name_column", "version_column", "supplier",
                            "supplier_column", "sha256_column", "kind", "implements"})


@dataclass(frozen=True)
class ImportMapping:
    source_system: str
    export_date: date
    columns: Mapping[str, str]
    items: tuple[Mapping[str, Any], ...]
    functions: tuple[FunctionDecl, ...] = ()
    sha256: str = ""

    @property
    def required_columns(self) -> tuple[str, ...]:
        cols = list(self.columns.values())
        for spec in self.items:
            for k in ("name_column", "version_column", "supplier_column", "sha256_column"):
                if spec.get(k):
                    cols.append(spec[k])
        return tuple(dict.fromkeys(cols))


def _source_label(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise InventoryImportError(f"{what} must be text")
    try:
        text = _clean(value, what, required=True)
    except RowRejected as exc:
        raise InventoryImportError(str(exc)) from exc
    return text


def parse_functions(raw: Any) -> tuple[FunctionDecl, ...]:
    """Functions declared once for every machine in the batch (mapping or API body)."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise InventoryImportError("functions must be a list")
    out: list[FunctionDecl] = []
    for f in raw:
        if not isinstance(f, Mapping) or set(f) - {"function_id", "description",
                                                   "required_performance", "verified_by"}:
            raise InventoryImportError("each function needs function_id, description and "
                                       "optionally required_performance, verified_by")
        verified = f.get("verified_by") or []
        if not isinstance(verified, list) or not all(isinstance(v, str) for v in verified):
            raise InventoryImportError("function verified_by must be a list of check names")
        decl = FunctionDecl(
            function_id=_source_label(f.get("function_id"), "function_id"),
            description=_source_label(f.get("description"), "function description"),
            required_performance=(_source_label(f["required_performance"], "required_performance")
                                  if f.get("required_performance") else ""),
            verified_by=tuple(verified))
        if decl.function_id in {d.function_id for d in out}:
            raise InventoryImportError(f"function {decl.function_id!r} is declared twice")
        out.append(decl)
    return tuple(out)


def load_mapping(path: Path) -> ImportMapping:
    """Read and validate a mapping file. Any fault refuses the import before anything is read."""
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        raw = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InventoryImportError(f"mapping {path}: not valid UTF-8 JSON ({exc})") from exc
    if not isinstance(raw, dict):
        raise InventoryImportError("mapping: must be a JSON object")
    extra = sorted(set(raw) - _MAPPING_KEYS)
    if extra:
        raise InventoryImportError("mapping: unknown key(s): " + ", ".join(extra))
    source_system = _source_label(raw.get("source_system"), "mapping source_system")
    try:
        export_date = date.fromisoformat(str(raw.get("export_date", "")))
    except ValueError as exc:
        raise InventoryImportError(
            "mapping export_date is required and must be YYYY-MM-DD (the date the customer's "
            "system produced the export)") from exc
    cols = raw.get("columns")
    if not isinstance(cols, dict):
        raise InventoryImportError("mapping: 'columns' must map canonical fields to column names")
    bad = sorted(set(cols) - set(_COLUMN_FIELDS))
    if bad:
        raise InventoryImportError("mapping columns: unknown field(s): " + ", ".join(bad))
    for need in _REQUIRED_COLUMNS:
        if need not in cols:
            raise InventoryImportError(f"mapping columns: {need} is required")
    if not all(isinstance(v, str) and v for v in cols.values()):
        raise InventoryImportError("mapping columns: every value is a non-empty column name")
    functions = parse_functions(raw.get("functions"))
    fn_ids = {f.function_id for f in functions}
    items_raw = raw.get("items")
    if not isinstance(items_raw, list) or not items_raw:
        raise InventoryImportError("mapping: 'items' must list at least one software/firmware "
                                   "column group")
    if len(items_raw) > MAX_ITEMS_PER_ROW:
        raise InventoryImportError(f"mapping: more than {MAX_ITEMS_PER_ROW} items")
    seen: set[str] = set()
    for n, spec in enumerate(items_raw, 1):
        if not isinstance(spec, dict) or set(spec) - _ITEM_MAP_KEYS:
            raise InventoryImportError(
                f"mapping item {n}: unknown key(s) "
                f"{sorted(set(spec) - _ITEM_MAP_KEYS) if isinstance(spec, dict) else ''}")
        if bool(spec.get("name")) == bool(spec.get("name_column")):
            raise InventoryImportError(f"mapping item {n}: give exactly one of name, name_column")
        if not spec.get("version_column"):
            raise InventoryImportError(f"mapping item {n}: version_column is required")
        if spec.get("supplier") and spec.get("supplier_column"):
            raise InventoryImportError(f"mapping item {n}: supplier or supplier_column, not both")
        label = spec.get("name") or spec.get("name_column")
        if label in seen:
            raise InventoryImportError(f"mapping item {n}: {label!r} is listed twice")
        seen.add(label)
        if spec.get("kind", "firmware") not in {k.value for k in ItemKind}:
            raise InventoryImportError(f"mapping item {n}: kind is not an item kind")
        impl = spec.get("implements", [])
        if not isinstance(impl, list) or set(impl) - fn_ids:
            raise InventoryImportError(
                f"mapping item {n}: implements names a function the mapping does not declare")
    return ImportMapping(source_system=source_system, export_date=export_date, columns=cols,
                         items=tuple(items_raw), functions=functions, sha256=digest)


def _apply_mapping(mapping: ImportMapping, record: Mapping[str, Any], row: int,
                   known: frozenset[str]) -> InventoryRow:
    raw: dict[str, Any] = {f: record.get(c) for f, c in mapping.columns.items()}
    items: list[dict[str, Any]] = []
    for spec in mapping.items:
        items.append({
            "name": spec["name"] if spec.get("name") else record.get(spec["name_column"]),
            "version": record.get(spec["version_column"]),
            "supplier": (spec.get("supplier") if spec.get("supplier")
                         else record.get(spec["supplier_column"]) if spec.get("supplier_column")
                         else ""),
            "sha256": record.get(spec["sha256_column"]) if spec.get("sha256_column") else "",
            "kind": spec.get("kind", "firmware"),
            "implements": spec.get("implements", []),
        })
    raw["items"] = items
    return canonical_row(raw, row, known)


# -- reading the file ----------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r} in a JSON object")
        out[k] = v
    return out


def _read_records(data: bytes, path: Path) -> tuple[list[str], Iterable[Mapping[str, Any] | str]]:
    """``(header, records)`` where a record that cannot be read is a ``str`` reason."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InventoryImportError(f"{path}: not valid UTF-8 ({exc.reason}); nothing was "
                                   "imported") from exc
    if "\x00" in text:
        raise InventoryImportError(f"{path}: contains a NUL byte; refused")
    stripped = text.lstrip()
    if path.suffix.lower() == ".json" or stripped[:1] in ("[", "{"):
        try:
            doc = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        except ValueError as exc:
            raise InventoryImportError(f"{path}: not valid JSON ({exc})") from exc
        if not isinstance(doc, list):
            raise InventoryImportError(f"{path}: a JSON inventory is an array of objects")
        header: list[str] = []
        for rec in doc:
            if isinstance(rec, dict):
                header.extend(k for k in rec if k not in header)
        return header, [r if isinstance(r, dict) else "row is not an object" for r in doc]
    first = text.split("\n", 1)[0]
    delimiter = ";" if first.count(";") > first.count(",") else ","
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
    try:
        head = next(reader)
    except StopIteration:
        raise InventoryImportError(f"{path}: empty file") from None
    except csv.Error as exc:
        raise InventoryImportError(f"{path}: header is not valid CSV ({exc})") from exc
    header = [h.strip() for h in head]
    if len(set(header)) != len(header):
        raise InventoryImportError(f"{path}: duplicate column names in the header")

    def records() -> Iterable[Mapping[str, Any] | str]:
        while True:
            try:
                fields = next(reader)
            except StopIteration:
                return
            except csv.Error as exc:
                yield f"not valid CSV ({exc})"
                return                                  # the reader cannot resync reliably
            if not fields:
                continue                                # a blank line is not a row
            if len(fields) != len(header):
                yield f"has {len(fields)} fields, the header has {len(header)}"
                continue
            yield dict(zip(header, fields, strict=True))

    return header, records()


# -- outcomes ------------------------------------------------------------------


@dataclass(frozen=True)
class RowOutcome:
    row: int
    status: str
    machine: str = ""
    reason: str = ""
    pointer: str = ""
    notes: tuple[str, ...] = ()
    enrolment_entry: int = 0

    @property
    def ok(self) -> bool:
        return self.status in (ENROLLED, ALREADY_ENROLLED)

    def to_dict(self) -> dict[str, Any]:
        return {"row": self.row, "status": self.status, "machine": self.machine,
                "reason": self.reason, "pointer": self.pointer, "notes": list(self.notes),
                "enrolment_entry": self.enrolment_entry}


STATUSES = (ENROLLED, ALREADY_ENROLLED, CONFIGURATION_DIFFERS, IDENTITY_CONFLICT, REJECTED)


@dataclass(frozen=True)
class ImportReport:
    dry_run: bool
    source_system: str
    export_date: str
    file_sha256: str
    file_sha256_basis: str
    mapping_sha256: str
    actor: str
    rows_read: int
    not_processed: int
    outcomes: tuple[RowOutcome, ...]
    batch_entry: int = 0
    batch_content_hash: str = ""
    blank_note: str = ""

    @property
    def counts(self) -> dict[str, int]:
        return {s: sum(1 for o in self.outcomes if o.status == s) for s in STATUSES}

    @property
    def ok(self) -> bool:
        """Every processed row is enrolled or already enrolled, and nothing was left out."""
        return not self.not_processed and all(o.ok for o in self.outcomes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": IMPORT_SCHEMA, "importer": IMPORTER, "dry_run": self.dry_run,
            "source_system": self.source_system, "export_date": self.export_date,
            "file_sha256": self.file_sha256, "file_sha256_basis": self.file_sha256_basis,
            "mapping_sha256": self.mapping_sha256, "actor": self.actor,
            "data_basis": "customer-provided; as declared by the customer's system; "
                          "not collected from the machine",
            "rows_read": self.rows_read, "rows_not_processed": self.not_processed,
            "counts": self.counts, "all_enrolled": self.ok,
            "outcomes": [o.to_dict() for o in self.outcomes],
            "batch_entry": self.batch_entry, "batch_content_hash": self.batch_content_hash,
            "does_not_establish": list(NOT_ESTABLISHED),
            "next_steps": list(NEXT_STEPS),
        }

    def summary(self) -> str:
        c = self.counts
        head = "DRY RUN (nothing written): outcomes the import would produce" \
            if self.dry_run else "inventory import"
        lines = [head,
                 f"  source        {self.source_system} (export dated {self.export_date}; "
                 "customer-provided, not collected from the machines)",
                 f"  file sha256   {self.file_sha256[:16]} ({self.file_sha256_basis})"]
        if self.mapping_sha256:
            lines.append(f"  mapping       {self.mapping_sha256[:16]}")
        lines.append(f"  actor         {self.actor}")
        lines.append(f"  rows          {self.rows_read} read, "
                     f"{len(self.outcomes)} processed, {self.not_processed} not processed")
        for s in STATUSES:
            lines.append(f"  {s:<22}{c[s]}")
        if self.not_processed:
            lines.append(f"  !! {self.not_processed} rows not processed: over the row limit; "
                         "split the file or raise --max-rows")
        for o in self.outcomes:
            if not o.ok:
                lines.append(f"  row {o.row}: {o.status}"
                             + (f" [{o.machine}]" if o.machine else "")
                             + (f": {o.reason}" if o.reason else ""))
                if o.pointer:
                    lines.append(f"      {o.pointer}")
        noted = [o for o in self.outcomes if o.notes]
        for o in noted:
            for n in o.notes:
                lines.append(f"  row {o.row} note: {n}")
        if self.batch_entry:
            lines.append(f"  batch record  entry {self.batch_entry} "
                         f"({self.batch_content_hash[:16]})")
        lines.append("  this import does NOT establish:")
        lines.extend(f"    - {n}" for n in NOT_ESTABLISHED)
        lines.append("  next steps:")
        lines.extend(f"    - {s}" for s in NEXT_STEPS)
        return "\n".join(lines)


# -- the domain function -------------------------------------------------------


def _manifest_for(row: InventoryRow, *, actor: Actor, source_system: str,
                  export_date: date | None, file_sha256: str,
                  functions: tuple[FunctionDecl, ...]) -> SafetyManifest:
    items = tuple(
        SafetyItem(
            item_id=f"ITM-{d.slot + 1}-{_slug(d.name)}", kind=ItemKind(d.kind), name=d.name,
            version=d.version, content_hash=d.sha256, hash_source=HashSource.DECLARED,
            supplier=d.supplier, implements=d.implements,
            notes="listed in a customer-provided inventory export; not read from the machine")
        for d in row.items)
    taken = (datetime(export_date.year, export_date.month, export_date.day, tzinfo=UTC)
             if export_date else datetime.now(UTC))
    provenance = (
        f"importer={IMPORTER}; source_system={source_system}; "
        f"export_date={export_date.isoformat() if export_date else 'not declared'}; "
        f"file_sha256={file_sha256 or 'not supplied'}; row={row.row}; "
        "customer-provided inventory entry, not collected from the machine")
    return SafetyManifest(
        manifest_id=f"INV-{(file_sha256 or 'nofile')[:12]}-R{row.row}",
        machine=MachineIdentity(manufacturer=row.manufacturer, model=row.model,
                                serial=row.serial, year=row.year, site=row.site,
                                country=row.country),
        source=ManifestSource.AS_DECLARED, taken_at=taken, taken_by=actor, items=items,
        functions=tuple(SafetyFunction(f.function_id, f.description, f.required_performance,
                                       f.verified_by) for f in functions),
        method="customer-provided inventory export imported from a file; not collected from "
               "the machine",
        notes=provenance)


def _short(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= MAX_REASON_CHARS else text[:MAX_REASON_CHARS] + "..."


def _enrol_all(
    ledger: EvidenceLedger, parsed: Iterable[tuple[int, InventoryRow | str]], *, actor: Actor,
    source_system: str, export_date: date | None, file_sha256: str,
    functions: tuple[FunctionDecl, ...],
) -> list[RowOutcome]:
    outcomes: list[RowOutcome] = []
    seen: dict[str, int] = {}
    for number, item in parsed:
        if isinstance(item, str):
            outcomes.append(RowOutcome(number, REJECTED, reason=_short(item)))
            continue
        key = item.key
        if key in seen:
            outcomes.append(RowOutcome(number, REJECTED, machine=key,
                                       reason=f"duplicate in file (first seen at row {seen[key]})",
                                       notes=item.notes))
            continue
        seen[key] = number
        try:
            manifest = _manifest_for(item, actor=actor, source_system=source_system,
                                     export_date=export_date, file_sha256=file_sha256,
                                     functions=functions)
            receipt = enrol_machine(ledger, manifest, actor=actor, owner=item.owner or None)
        except (AssuranceError, ValueError, KeyError, TypeError) as exc:
            outcomes.append(RowOutcome(number, REJECTED, machine=key, reason=_short(exc),
                                       notes=item.notes))
            continue
        outcomes.append(RowOutcome(
            number, receipt.status, machine=receipt.machine_key,
            pointer=receipt.pointer if receipt.refused else "",
            notes=item.notes + tuple(receipt.notes), enrolment_entry=receipt.enrolment_entry))
    return outcomes


def _seal_batch(ledger: EvidenceLedger, *, actor: Actor, source_system: str, export_date: str,
                file_sha256: str, mapping_sha256: str, channel: str, rows_read: int,
                not_processed: int, outcomes: list[RowOutcome]) -> tuple[int, str]:
    """One record of the import itself. Machine keys and statuses only; no row contents."""
    counts = {s: sum(1 for o in outcomes if o.status == s) for s in STATUSES}
    body = {
        "schema": IMPORT_SCHEMA, "importer": IMPORTER, "channel": channel,
        "source_system": source_system, "export_date": export_date,
        "file_sha256": file_sha256, "mapping_sha256": mapping_sha256,
        "data_basis": "customer-provided; not collected from the machine",
        "rows_read": rows_read, "rows_not_processed": not_processed, "counts": counts,
        "machines": [{"row": o.row, "machine": o.machine, "status": o.status}
                     for o in outcomes],
        "does_not_establish": list(NOT_ESTABLISHED),
    }
    evidence = Evidence(
        kind=IMPORT_KIND, body=body, actor=actor,
        origin=Origin(system="assurance.machinery.inventory",
                      reference=f"{source_system} / file {file_sha256[:16] or 'not supplied'}",
                      method="rows of a customer-provided inventory export, each enrolled "
                             "through the enrolment front door by a named person"),
        validation_state=ValidationState.UNVERIFIED, confidence=Confidence.LOW,
        checks_skipped=NOT_ESTABLISHED,
    ).seal()
    appended = ledger.append(evidence, subject=f"inventory-import/{file_sha256[:16] or 'api'}")
    return appended.seq, evidence.content_hash


def _verified(ledger: EvidenceLedger) -> None:
    ok, problems = ledger.verify_chain()
    if not ok:
        raise LedgerChainUnverifiedError(
            "the ledger chain does not verify, so nothing was imported: "
            + "; ".join(problems[:3]))


def _run(
    make_ledger: Callable[[], EvidenceLedger], *, parsed: list[tuple[int, Any]],
    actor: Actor, source_system: str, export_date: date | None, file_sha256: str,
    file_basis: str, mapping_sha256: str, functions: tuple[FunctionDecl, ...],
    rows_read: int, not_processed: int, dry_run: bool, channel: str,
) -> ImportReport:
    ledger = make_ledger()
    _verified(ledger)
    outcomes = _enrol_all(ledger, parsed, actor=actor, source_system=source_system,
                          export_date=export_date, file_sha256=file_sha256, functions=functions)
    entry, chash = 0, ""
    if not dry_run and any(o.status == ENROLLED for o in outcomes):
        entry, chash = _seal_batch(
            ledger, actor=actor, source_system=source_system,
            export_date=export_date.isoformat() if export_date else "",
            file_sha256=file_sha256, mapping_sha256=mapping_sha256, channel=channel,
            rows_read=rows_read, not_processed=not_processed, outcomes=outcomes)
    return ImportReport(
        dry_run=dry_run, source_system=source_system,
        export_date=export_date.isoformat() if export_date else "not declared",
        file_sha256=file_sha256, file_sha256_basis=file_basis, mapping_sha256=mapping_sha256,
        actor=actor.identifier, rows_read=rows_read, not_processed=not_processed,
        outcomes=tuple(outcomes), batch_entry=entry, batch_content_hash=chash)


def _scratch_copy(source: Path, into: Path) -> Path:
    """A throw-away copy of a ledger (or an empty path when there is none). Source is only read."""
    dest = into / "dry-run.db"
    if source.is_file():
        shutil.copyfile(source, dest)
        wal = source.with_name(source.name + "-wal")
        if wal.is_file():
            shutil.copyfile(wal, dest.with_name(dest.name + "-wal"))
    return dest


def _guarded(run: Callable[[], ImportReport]) -> ImportReport:
    try:
        return run()
    except sqlite3.DatabaseError as exc:
        raise InventoryImportError(f"the ledger file cannot be read as a ledger ({exc})") from exc


def import_rows(
    ledger_path: Path, rows: list[tuple[int, InventoryRow | str]], *, actor: Actor | None,
    source_system: str, export_date: date | None = None, file_sha256: str = "",
    file_sha256_basis: str = "not supplied", mapping_sha256: str = "",
    functions: tuple[FunctionDecl, ...] = (), rows_read: int | None = None,
    not_processed: int = 0, dry_run: bool = False, channel: str = "cli",
    ledger: EvidenceLedger | None = None,
) -> ImportReport:
    """Enrol canonical rows. ``rows`` pairs a row number with an :class:`InventoryRow` or the
    reason that row was rejected before it reached here.

    ``ledger`` is the account's open ledger (API); otherwise ``ledger_path`` is opened for
    writing (created on first use, like ``machinery enrol``) or, for a dry run, only read.
    """
    who = require_person(actor, "inventory import")     # before any ledger exists
    source_system = _source_label(source_system, "source_system")
    read = len(rows) if rows_read is None else rows_read
    kwargs: dict[str, Any] = {
        "parsed": rows, "actor": who, "source_system": source_system,
        "export_date": export_date, "file_sha256": file_sha256, "file_basis": file_sha256_basis,
        "mapping_sha256": mapping_sha256, "functions": functions, "rows_read": read,
        "not_processed": not_processed, "channel": channel,
    }
    if ledger is not None:
        return _run(lambda: ledger, dry_run=dry_run, **kwargs)
    if dry_run:
        with tempfile.TemporaryDirectory(prefix="nb-inventory-dry-") as tmp:
            scratch = _scratch_copy(ledger_path, Path(tmp))
            return _guarded(lambda: _run(lambda: EvidenceLedger(scratch), dry_run=True, **kwargs))
    return _guarded(lambda: _run(lambda: EvidenceLedger(ledger_path), dry_run=False, **kwargs))


def import_file(
    path: Path, mapping_path: Path, ledger_path: Path, *, actor: Actor | None,
    dry_run: bool = False, max_rows: int = DEFAULT_MAX_ROWS,
) -> ImportReport:
    """Read ``path`` with the mapping, then enrol every row. See the module docstring."""
    if max_rows < 1:
        raise InventoryImportError("--max-rows must be at least 1")
    require_person(actor, "inventory import")
    mapping = load_mapping(mapping_path)
    size = Path(path).stat().st_size
    if size > MAX_FILE_BYTES:
        raise InventoryImportError(f"{path}: {size} bytes exceeds the {MAX_FILE_BYTES} accepted")
    data = Path(path).read_bytes()
    file_sha = hashlib.sha256(data).hexdigest()
    header, records = _read_records(data, Path(path))
    missing = [c for c in mapping.required_columns if c not in header]
    if missing:
        raise InventoryImportError(
            "the file has no column named " + ", ".join(repr(m) for m in missing)
            + " (mapping refers to it). Nothing was imported.")
    known = frozenset(f.function_id for f in mapping.functions)
    parsed: list[tuple[int, InventoryRow | str]] = []
    total = 0
    for number, record in enumerate(records, 1):
        total = number
        if number > max_rows:
            continue                                    # counted, never processed
        if isinstance(record, str):
            parsed.append((number, record))
            continue
        try:
            parsed.append((number, _apply_mapping(mapping, record, number, known)))
        except RowRejected as exc:
            parsed.append((number, str(exc)))
    return import_rows(
        ledger_path, parsed, actor=actor, source_system=mapping.source_system,
        export_date=mapping.export_date, file_sha256=file_sha,
        file_sha256_basis="of the file as read", mapping_sha256=mapping.sha256,
        functions=mapping.functions, rows_read=total, not_processed=max(0, total - max_rows),
        dry_run=dry_run, channel="cli")


def rows_from_api(raw_rows: list[Any], functions: tuple[FunctionDecl, ...]
                  ) -> list[tuple[int, InventoryRow | str]]:
    known = frozenset(f.function_id for f in functions)
    out: list[tuple[int, InventoryRow | str]] = []
    for n, raw in enumerate(raw_rows, 1):
        try:
            out.append((n, canonical_row(raw, n, known)))
        except RowRejected as exc:
            out.append((n, str(exc)))
    return out
