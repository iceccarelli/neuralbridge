"""Import a CSAF 2.0 security advisory as a :class:`~assurance.fleet.advisory.ComponentAdvisory`.

Industrial vendors and national CERTs publish advisories as CSAF documents. Without an
importer the only way to put one in front of this product is to retype it, and retyping is
where an affected version gets dropped.

What an import is, and is not
-----------------------------
An import is **unsigned third-party content**. It carries no signature this product has
checked, so the result is only ever fit for the inspect-only path. Nothing here pins a key,
opens a case or decides that anything is affected; it translates what the publisher wrote.
And the translation says so *inside the advisory it writes*: an
:class:`~assurance.fleet.advisory.ImportRecord` (origin, trust, whether the translation is
partial and which products it dropped, where the severity came from, TLP, tracking status,
document category) is part of the advisory, covered by its content hash, so no later reader
can mistake the file for a complete, trusted one.

The translation is conservative wherever the document is less precise than this product's
model:

* a ``product_version`` that is a single plain token (``V2.001``) becomes an exact affected
  version. Anything else in that position (``All versions < V3.1``, ``V2.x``, ``2.0 and
  earlier``) is **range text**, not a label, and is treated as one;
* range text, a ``product_version_range`` (``vers:...``, ``<12.002``) and the boundaries
  ``first_affected`` / ``last_affected`` are **not parsed**. The text is kept as
  ``version_note``, which the matcher treats as "a person has to read this against the
  version", never as a clear;
* ``under_investigation`` products are kept as affected, with that said in the note;
* ``known_not_affected`` is ignored: it is never used to clear a machine;
* a fixed version is kept **per component**, and only for a component that has no range:
  one vulnerability's fix is not the end of another's range;
* only a ``vendor_fix`` remediation becomes ``remedy``. A mitigation or workaround is not
  represented as a vendor patch;
* severity is **not invented**. CSAF does not say whether something is safety-relevant, so
  the default is ``safety_relevant`` (an over-report costs minutes, an under-report can
  clear a machine that needed stopping), the record says it was defaulted, and the caller
  may override it (the record then says that);
* a ``draft`` or ``interim`` document is refused unless the caller asks, and then the
  translation is marked partial.

Anything affected that cannot be mapped is recorded as *dropped* and makes the translation
**partial**; a partial advisory is never reported as clear by any consumer. A document that
yields no affected product at all is refused: an advisory that matches nothing would read as
"nothing is affected".

Hostile input is a refusal, never a traceback: wrong-typed fields, invisible characters in a
name that is compared, a tree nested deeper than :data:`MAX_DEPTH` or defining more than
:data:`MAX_PRODUCTS` products, a file over :data:`MAX_FILE_BYTES`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assurance.core.identity import format_utc, parse_utc
from assurance.core.text import invisible_characters, strip_invisible
from assurance.fleet.advisory import (
    IMPORT_ORIGINS,
    TRUST_UNSIGNED_INSPECT_ONLY,
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    DroppedProduct,
    ImportRecord,
)

__all__ = [
    "MAX_DEPTH",
    "MAX_FILE_BYTES",
    "MAX_PRODUCTS",
    "CsafImport",
    "advisory_from_csaf",
    "load_csaf_document",
]

#: Product definitions (tree leaves plus ``full_product_names`` plus relationships) one
#: document may carry. A real advisory has dozens; 40,000 imports in a fraction of a second.
MAX_PRODUCTS = 100_000
#: How deeply ``product_tree.branches`` may nest. Real trees are four or five levels deep.
MAX_DEPTH = 64
#: The largest document read from disk.
MAX_FILE_BYTES = 8 * 1024 * 1024

_AFFECTED = ("known_affected", "first_affected", "last_affected")
_BOUNDARY = {"first_affected": "first affected", "last_affected": "last affected"}
_FIXED = ("fixed", "first_fixed")
_UNLISTED_NOTE = ("unsigned CSAF import: a version this advisory does not list is not "
                  "known to be unaffected")
_TLP_LABELS = frozenset({"WHITE", "GREEN", "AMBER", "RED", "CLEAR", "AMBER+STRICT"})

#: Characters that make a version "label" something other than one plain token.
_RANGE_CHARS = re.compile(r"[\s<>=~^|,;()\[\]≤≥]")
_WILDCARD = re.compile(r"(^|[.\-_])[xX*]($|[.\-_])")
_RANGE_WORDS = frozenset({"all", "any", "earlier", "later", "before", "after", "prior",
                          "through", "below", "above"})


@dataclass(frozen=True)
class CsafImport:
    """The translated advisory and everything the translation had to leave out or decide."""

    advisory: ComponentAdvisory
    notes: tuple[str, ...]


@dataclass(frozen=True)
class _Product:
    vendor: str
    name: str
    #: One plain version token, or ``""``.
    exact: str
    #: Range text from a ``product_version_range`` branch, or from a ``product_version`` name
    #: that is not one plain token.
    ranges: tuple[str, ...]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def is_plain_version_token(label: str) -> bool:
    """True only for one token that names a single version.

    ``V2.001`` and ``3.8.2-rc1`` are. ``All versions < V3.1``, ``vers:all/<V3``, ``V2.x``,
    ``2.*``, ``V2.0+``, ``all`` and ``earlier`` describe a set of versions and must not be
    compared as if they were one.
    """
    token = label.strip()
    if not token or _RANGE_CHARS.search(token) or _WILDCARD.search(token):
        return False
    low = token.casefold()
    return not (low.startswith("vers:") or low.endswith("+") or low in _RANGE_WORDS)


# --------------------------------------------------------------------------- reading a file

def load_csaf_document(path: Path) -> Any:
    """Read and parse a CSAF file. Every way that can fail is an :class:`AdvisoryError`."""
    try:
        if path.is_dir():
            raise AdvisoryError(f"{path} is a directory, not a CSAF document.")
        if not path.is_file():
            raise AdvisoryError(
                f"{path} is not a regular file (a device or a pipe is never read as a "
                "document).")
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise AdvisoryError(
                f"{path} is larger than {MAX_FILE_BYTES:,} bytes; the importer reads at "
                "most that much and will not guess at a larger document.")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise AdvisoryError(f"{path} could not be read: {exc.strerror or exc}.") from exc

    def refuse_constant(name: str) -> Any:
        raise ValueError(f"{name} is not valid JSON")

    try:
        return json.loads(raw.decode("utf-8-sig"), parse_constant=refuse_constant)
    except RecursionError as exc:
        raise AdvisoryError(
            "the document is nested so deeply that it was refused rather than read.") from exc
    except UnicodeDecodeError as exc:
        raise AdvisoryError(f"{path} is not UTF-8 text ({exc.reason}).") from exc
    except ValueError as exc:
        raise AdvisoryError(f"{path} is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------- type discipline

def _list_of(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AdvisoryError(
            f"{where} must be a list, not {type(value).__name__}; the document is "
            "malformed and was not read further.")
    return value


def _ids(status: Mapping[str, Any], key: str, where: str) -> list[str]:
    out: list[str] = []
    for position, pid in enumerate(_list_of(status.get(key), f"{where}.{key}")):
        if not isinstance(pid, str) or not pid.strip():
            raise AdvisoryError(
                f"{where}.{key}[{position}] is not a product id (a non-empty string).")
        out.append(pid.strip())
    return out


def _display(raw: str, field: str, notes: list[str]) -> str:
    """Display text with unsafe characters removed (and said)."""
    clean, removed = strip_invisible(raw)
    if removed:
        notes.append(f"{field}: removed {len(removed)} control, invisible or "
                     f"direction-changing character(s) ({', '.join(removed)}).")
    return clean


def _matching(raw: str, field: str) -> str:
    """Text that is compared. An invisible character is refused, never removed."""
    bad = invisible_characters(raw)
    if bad:
        raise AdvisoryError(
            f"{field} contains an invisible or control character ({', '.join(bad)}). "
            "Removing it would change what is compared, and keeping it would make two "
            "names that read the same compare as different, so the document is refused.")
    return raw


# --------------------------------------------------------------------------- the product tree

@dataclass
class _Tree:
    products: dict[str, _Product]
    #: ids defined twice with different content
    conflicting: set[str]
    #: ids defined where this importer cannot read a vendor, name and version
    elsewhere: dict[str, str]
    #: ids defined in the tree but unusable, with the reason
    unusable: dict[str, str]
    notes: list[str]


def _walk(tree: Mapping[str, Any]) -> _Tree:
    out = _Tree({}, set(), {}, {}, [])
    count = 0
    stack: list[tuple[Any, tuple[tuple[str, str], ...], int]] = [
        (n, (), 1) for n in reversed(_list_of(tree.get("branches"), "product_tree.branches"))]
    seen_duplicates: set[str] = set()
    defs: dict[str, _Product] = {}
    while stack:
        node, path, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise AdvisoryError(
                f"the product tree is nested deeper than {MAX_DEPTH} levels; a tree that "
                "deep is refused rather than walked.")
        if not isinstance(node, Mapping):
            raise AdvisoryError("a product tree branch is not an object.")
        here = path + ((_text(node.get("category")), _text(node.get("name"))),)
        product = node.get("product")
        if isinstance(product, Mapping) and product.get("product_id") is not None:
            pid = product["product_id"]
            if not isinstance(pid, str) or not pid.strip():
                raise AdvisoryError("a product_id in the product tree is not a string.")
            pid = pid.strip()
            count += 1
            if count > MAX_PRODUCTS:
                raise AdvisoryError(
                    f"the product tree defines more than {MAX_PRODUCTS:,} products; the "
                    "importer refuses a document that large.")
            vendor = next((n for c, n in reversed(here) if c == "vendor" and n), "")
            name = next((n for c, n in reversed(here) if c == "product_name" and n), "")
            exact = next((n for c, n in reversed(here) if c == "product_version" and n), "")
            ranged = next(
                (n for c, n in reversed(here) if c == "product_version_range" and n), "")
            ranges: list[str] = [ranged] if ranged else []
            if exact and not is_plain_version_token(exact):
                ranges.insert(0, exact)
                exact = ""
            candidate = _Product(vendor, name, exact, tuple(ranges))
            if pid not in defs:
                defs[pid] = candidate
            elif defs[pid] == candidate:
                if pid not in seen_duplicates:
                    seen_duplicates.add(pid)
                    out.notes.append(
                        f"product id {pid!r} is defined more than once in the product "
                        "tree (duplicate definitions with the same content).")
            elif pid not in out.conflicting:
                out.conflicting.add(pid)
                out.notes.append(
                    f"product id {pid!r} is defined more than once with different "
                    "vendor, name or version; it is ambiguous, so it is not used.")
        children = node.get("branches")
        if children is not None:
            for child in reversed(_list_of(children, "a product tree branch's branches")):
                stack.append((child, here, depth + 1))

    for pid, candidate in defs.items():
        if candidate.vendor and candidate.name and (candidate.exact or candidate.ranges):
            out.products[pid] = candidate
        else:
            out.unusable[pid] = (
                "its branch path in the product tree lacks a vendor, a product name or "
                "a version, so it cannot be matched to a machine")

    for key in ("full_product_names", "relationships"):
        entries = _list_of(tree.get(key), f"product_tree.{key}")
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            fpn = entry if key == "full_product_names" else entry.get("full_product_name")
            pid = _text(fpn.get("product_id")) if isinstance(fpn, Mapping) else ""
            if pid:
                count += 1
                if count > MAX_PRODUCTS:
                    raise AdvisoryError(
                        f"the product tree defines more than {MAX_PRODUCTS:,} products; the "
                        "importer refuses a document that large.")
                if key == "full_product_names":
                    out.elsewhere.setdefault(pid, (
                        "it is defined only in product_tree.full_product_names, which has "
                        "no vendor/product/version structure this importer reads"))
                else:
                    out.elsewhere.setdefault(pid, (
                        "it is defined only through product_tree.relationships (a product "
                        "combined with another), which are not interpreted"))
        if entries and key == "relationships":
            out.notes.append(
                "The product tree uses 'relationships' (a product combined with another). "
                "They are not interpreted; products that exist only as relationships were "
                "not imported.")
    return out


# --------------------------------------------------------------------------- the translation

@dataclass
class _Slot:
    versions: dict[str, None]
    notes: dict[str, None]
    fixed: dict[str, None]


def advisory_from_csaf(
    document: Mapping[str, Any], *,
    severity: AdvisorySeverity | None = None,
    allow_draft: bool = False,
) -> CsafImport:
    """Translate a parsed CSAF 2.0 document. Raises :class:`AdvisoryError` if it cannot be.

    ``severity=None`` means the importer chooses (``safety_relevant``) and the record says
    it did; passing a severity, even the same one, records it as the operator's choice.
    """
    if not isinstance(document, Mapping) or not isinstance(document.get("document"), Mapping):
        raise AdvisoryError("not a CSAF document: there is no 'document' object.")
    head = document["document"]
    version = _text(head.get("csaf_version"))
    if version != "2.0":
        raise AdvisoryError(
            f"csaf_version is {version!r}; this importer reads 2.0 and will not guess "
            "at a different schema.")

    notes: list[str] = [
        "Imported from an unsigned CSAF document: it has not been authenticated, so it is "
        "fit for inspection only and must not drive a change to a safety system.",
    ]
    partial_reasons: list[str] = []

    tracking = head.get("tracking") if isinstance(head.get("tracking"), Mapping) else {}
    advisory_id = _matching(_text(tracking.get("id")), "the tracking id")
    if not advisory_id:
        raise AdvisoryError("the document has no tracking id.")
    status = _text(tracking.get("status")).casefold()
    if status != "final":
        if not allow_draft:
            raise AdvisoryError(
                f"the document's tracking status is {status or 'missing'!r}, not 'final'. A "
                "draft or interim advisory can still change or be withdrawn; pass "
                "--allow-draft to import it anyway (it is then marked partial).")
        partial_reasons.append(
            f"the document's tracking status is {status or 'missing'!r}, not 'final', so "
            "it may change or be withdrawn")
    try:
        issued_at = parse_utc(_text(tracking.get("current_release_date")))
    except ValueError as exc:
        raise AdvisoryError(
            "current_release_date is missing or has no timezone; a release date that "
            f"cannot be placed in time is not used ({exc}).") from exc
    publisher = head.get("publisher") if isinstance(head.get("publisher"), Mapping) else {}
    issued_by = _display(_text(publisher.get("name")), "publisher name", notes)
    if not issued_by:
        raise AdvisoryError("the document names no publisher.")

    category = _display(_text(head.get("category")), "document category", notes)
    if category not in ("csaf_security_advisory", "csaf_vex"):
        notes.append(
            f"The document category is {category or 'missing'!r}, not a security advisory "
            "or a VEX document; read what it claims with care.")

    tlp = ""
    distribution = head.get("distribution")
    if isinstance(distribution, Mapping) and isinstance(distribution.get("tlp"), Mapping):
        tlp = _display(_text(distribution["tlp"].get("label")), "TLP label", notes).upper()
        if tlp and tlp not in _TLP_LABELS:
            notes.append(f"The TLP label {tlp!r} is not one this importer recognises; treat "
                         "the document as restricted.")
    if tlp in ("AMBER", "RED", "AMBER+STRICT"):
        notes.append(f"The document is marked TLP:{tlp}: it may not be forwarded beyond the "
                     "people the publisher named. The marker travels with the advisory.")

    refs = [r for r in _list_of(head.get("references"), "document.references")
            if isinstance(r, Mapping) and _text(r.get("url"))]
    reference = next((_text(r["url"]) for r in refs if _text(r.get("category")) == "self"),
                     _text(refs[0]["url"]) if refs else "")
    if not reference:
        raise AdvisoryError(
            "the document carries no reference URL, so a reader could not trace it to its "
            "source.")
    _matching(reference, "the reference URL")

    if severity is None:
        chosen, severity_source = AdvisorySeverity.SAFETY_RELEVANT, "defaulted_by_importer"
        notes.append(
            "CSAF does not state whether the issue is safety-relevant. It was imported as "
            "'safety_relevant' so affected machines are reviewed rather than passed over; "
            "override the severity if the publisher says otherwise.")
    else:
        chosen, severity_source = severity, "operator_flag"
        notes.append(f"Severity {chosen.value!r} was chosen by the operator; CSAF does not "
                     "state it, and the publisher did not.")

    tree_node = document.get("product_tree")
    tree = _walk(tree_node if isinstance(tree_node, Mapping) else {})
    notes.extend(tree.notes)

    vulns = document.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise AdvisoryError("the document lists no vulnerabilities.")
    classes: dict[str, dict[str, None]] = {}     # product_id -> how the publisher classed it
    fixed_ids: dict[str, None] = {}
    not_affected: dict[str, None] = {}
    stated: dict[str, None] = {}                  # classed by the publisher, not as affected
    elsewhere_ids: dict[str, str] = {}            # named only outside product_status
    cves: list[str] = []
    remedy = ""
    for index, vuln in enumerate(vulns):
        where = f"vulnerabilities[{index}]"
        if not isinstance(vuln, Mapping):
            raise AdvisoryError(f"{where} is not an object.")
        cve = _display(_text(vuln.get("cve")), f"{where}.cve", notes)
        if cve and cve not in cves:
            cves.append(cve)
        product_status = vuln.get("product_status")
        if product_status is None:
            partial_reasons.append(
                f"{where} has no product_status, so it states no affected product (any "
                "product it concerns is named only elsewhere, if at all)")
        else:
            if not isinstance(product_status, Mapping):
                raise AdvisoryError(f"{where}.product_status must be an object.")
            for pid in _ids(product_status, "recommended", f"{where}.product_status"):
                stated[pid] = None
            for key in _AFFECTED + ("under_investigation",):
                for pid in _ids(product_status, key, f"{where}.product_status"):
                    classes.setdefault(pid, {})[key] = None
            for key in _FIXED:
                for pid in _ids(product_status, key, f"{where}.product_status"):
                    fixed_ids[pid] = None
            for pid in _ids(product_status, "known_not_affected", f"{where}.product_status"):
                not_affected[pid] = None
        for rem in _list_of(vuln.get("remediations"), f"{where}.remediations"):
            if (isinstance(rem, Mapping) and _text(rem.get("category")) == "vendor_fix"
                    and not remedy):
                remedy = _display(_text(rem.get("details")), "remedy", notes)
        for section, key in (("remediations", "product_ids"), ("threats", "product_ids"),
                             ("flags", "product_ids"), ("scores", "products")):
            for entry in _list_of(vuln.get(section), f"{where}.{section}"):
                if isinstance(entry, Mapping):
                    for pid in _ids(entry, key, f"{where}.{section}[]"):
                        elsewhere_ids.setdefault(pid, f"{where}.{section}")
    if not_affected:
        notes.append(
            f"{len(not_affected)} product(s) are listed as known_not_affected. That is "
            "ignored: it is never used to clear a machine.")

    dropped: list[DroppedProduct] = []
    for pid, section in elsewhere_ids.items():
        if pid not in classes and pid not in fixed_ids and pid not in not_affected \
                and pid not in stated:
            dropped.append(DroppedProduct(pid, (
                f"it is named only in {section} and in no product_status, so the publisher "
                "does not state whether it is affected")))
    grouped: dict[tuple[str, str], _Slot] = {}
    for pid, how in classes.items():
        product = tree.products.get(pid)
        if pid in tree.conflicting or product is None:
            dropped.append(DroppedProduct(pid, (
                "it is defined more than once in the product tree with different vendor, "
                "name or version" if pid in tree.conflicting else
                tree.unusable.get(pid) or tree.elsewhere.get(pid)
                or "it is not in the product tree")))
            continue
        vendor = _matching(product.vendor, f"product {pid!r} vendor name")
        name = _matching(product.name, f"product {pid!r} name")
        slot = grouped.setdefault((vendor, name), _Slot({}, {}, {}))
        if product.exact:
            slot.versions[_matching(product.exact, f"product {pid!r} version")] = None
        for text in product.ranges:
            _matching(text, f"product {pid!r} version range")
            slot.versions[text] = None
            slot.notes[text] = None
        label = product.exact or "; ".join(product.ranges)
        boundary = [_BOUNDARY[k] for k in how if k in _BOUNDARY]
        if boundary:
            slot.notes[f"{label}: {' and '.join(boundary)} version of an affected range; "
                       "versions beyond it are not known to be unaffected"] = None
        if set(how) == {"under_investigation"}:
            slot.notes[f"{label}: under investigation by the publisher, not confirmed"] = None
    if dropped:
        partial_reasons.append(
            f"{len(dropped)} affected product(s) could not be imported: "
            + ", ".join(repr(d.product_id) for d in dropped))
        for d in dropped:
            notes.append(f"affected product {d.product_id!r} was NOT imported: {d.reason}.")
    if not grouped:
        raise AdvisoryError(
            "no affected product could be mapped, so the advisory would match nothing and "
            "read as 'nothing is affected'. " + "; ".join(
                f"{d.product_id!r}: {d.reason}" for d in dropped))

    for pid in fixed_ids:
        product = tree.products.get(pid)
        if pid in tree.conflicting or product is None or product.ranges or not product.exact:
            notes.append(
                f"fixed product {pid!r} has no single exact version in the product tree, "
                "so it is not listed as a fix.")
            continue
        slot = grouped.get((product.vendor, product.name))
        if slot is None:
            notes.append(f"fixed product {pid!r} ({product.name} {product.exact}) is not a "
                         "component any affected product belongs to; it is not listed.")
        else:
            slot.fixed[_matching(product.exact, f"product {pid!r} fixed version")] = None

    if any(s.versions for s in grouped.values()):
        notes.append(
            "Version labels are copied as the publisher wrote them. A machine whose label "
            "differs only in spelling (for example '2.001' for 'V2.001') is reported for a "
            "person to look at, never cleared.")

    # Written into the data, not only the record: if the record is removed from the file the
    # advisory still answers "a person has to look" for every label it does not list.
    for slot in grouped.values():
        slot.notes[_UNLISTED_NOTE] = None
    affected = tuple(
        AffectedArtefact(
            supplier=vendor, name=name, versions=tuple(slot.versions),
            version_note="; ".join(slot.notes), fixed_versions=tuple(slot.fixed))
        for (vendor, name), slot in sorted(grouped.items()))

    summary = ""
    for note in _list_of(head.get("notes"), "document.notes"):
        if isinstance(note, Mapping) and _text(note.get("category")) == "summary":
            summary = _display(_text(note.get("text")), "summary", notes)
            break
    if cves:
        summary = (summary + " " if summary else "") + "CVE: " + ", ".join(cves)
    title = _display(_text(head.get("title")), "title", notes)
    # The same fail-safe in the two texts every consumer prints, whatever happens to the record.
    label = "unsigned CSAF import"
    if dropped:
        shown = ", ".join(strip_invisible(d.product_id)[0] for d in dropped)
        label += f", partial: not imported {shown}"
    elif partial_reasons:
        label += ", partial"
    title = f"[{label}] {title}".rstrip()
    summary = f"[{label}] {summary}".rstrip()

    record = ImportRecord(
        origin=IMPORT_ORIGINS[0], trust=TRUST_UNSIGNED_INSPECT_ONLY,
        partial=bool(dropped or partial_reasons), dropped=tuple(dropped),
        partial_reasons=tuple(partial_reasons),
        severity_source=severity_source, tlp=tlp, tracking_status=status,
        document_category=category, document_date=format_utc(issued_at),
        notes=tuple(dict.fromkeys(notes)))
    return CsafImport(
        advisory=ComponentAdvisory(
            advisory_id=advisory_id, issued_by=issued_by, issued_at=issued_at,
            title=title, summary=summary, severity=chosen,
            affected=affected, remedy=remedy, reference=reference, import_record=record),
        notes=record.notes,
    )
