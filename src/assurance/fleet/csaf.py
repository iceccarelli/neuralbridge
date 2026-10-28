"""Import a CSAF 2.0 security advisory as a :class:`~assurance.fleet.advisory.ComponentAdvisory`.

Industrial vendors and national CERTs publish advisories as CSAF documents. Without an
importer the only way to put one in front of this product is to retype it, and retyping is
where an affected version gets dropped.

What an import is, and is not
-----------------------------
An import is **unsigned third-party content**. It carries no signature this product has
checked, so the result is only ever fit for the inspect-only path (``assurance fleet
advisory FILE`` already labels a bare file that way). Nothing here pins a key, opens a case
or decides that anything is affected; it translates what the publisher wrote.

The translation is conservative wherever the document is less precise than this product's
model:

* an exact ``product_version`` branch becomes an exact affected version;
* a ``product_version_range`` (``vers:...``, ``<12.002``, "and earlier") is **not parsed**.
  Its text is kept as the affected label and as ``version_note``, which the matcher treats
  as "a person has to read this against the version", never as a clear;
* ``under_investigation`` products are kept as affected, with that said in the note;
* ``known_not_affected`` is ignored: it is never used to clear a machine;
* only a ``vendor_fix`` remediation becomes ``remedy``. A mitigation or workaround is not
  represented as a vendor patch;
* severity is **not invented**. CSAF does not say whether something is safety-relevant, so
  the default is ``safety_relevant`` (an over-report costs minutes, an under-report can
  clear a machine that needed stopping) and the notes say so. The caller may override it.

Anything that cannot be mapped is returned in ``notes`` rather than dropped silently. A
document that yields no affected product at all is refused: an advisory that matches
nothing would read as "nothing is affected".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from assurance.core.identity import parse_utc
from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)

__all__ = ["CsafImport", "advisory_from_csaf"]

_AFFECTED = ("known_affected", "first_affected", "last_affected")
_FIXED = ("fixed", "first_fixed")


@dataclass(frozen=True)
class CsafImport:
    """The translated advisory and everything the translation had to leave out or decide."""

    advisory: ComponentAdvisory
    notes: tuple[str, ...]


@dataclass(frozen=True)
class _Product:
    vendor: str
    name: str
    version: str
    is_range: bool


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _walk(
    branches: Any, path: tuple[tuple[str, str], ...], out: dict[str, _Product],
    skipped: list[str],
) -> None:
    if not isinstance(branches, list):
        return
    for node in branches:
        if not isinstance(node, Mapping):
            continue
        here = path + ((_text(node.get("category")), _text(node.get("name"))),)
        product = node.get("product")
        if isinstance(product, Mapping) and _text(product.get("product_id")):
            pid = _text(product["product_id"])
            vendor = next((n for c, n in reversed(here) if c == "vendor" and n), "")
            name = next((n for c, n in reversed(here) if c == "product_name" and n), "")
            exact = next((n for c, n in reversed(here) if c == "product_version" and n), "")
            ranged = next(
                (n for c, n in reversed(here) if c == "product_version_range" and n), "")
            if not vendor or not name or not (exact or ranged):
                skipped.append(
                    f"product {pid!r} lacks a vendor, a product name or a version in the "
                    "product tree, so it cannot be matched to a machine")
            else:
                out[pid] = _Product(vendor, name, exact or ranged, is_range=not exact)
        _walk(node.get("branches"), here, out, skipped)


def advisory_from_csaf(
    document: Mapping[str, Any], *,
    severity: AdvisorySeverity = AdvisorySeverity.SAFETY_RELEVANT,
) -> CsafImport:
    """Translate a parsed CSAF 2.0 document. Raises :class:`AdvisoryError` if it cannot be."""
    if not isinstance(document, Mapping) or not isinstance(document.get("document"), Mapping):
        raise AdvisoryError("not a CSAF document: there is no 'document' object.")
    head = document["document"]
    version = _text(head.get("csaf_version"))
    if version != "2.0":
        raise AdvisoryError(
            f"csaf_version is {version!r}; this importer reads 2.0 and will not guess "
            "at a different schema.")

    tracking = head.get("tracking") if isinstance(head.get("tracking"), Mapping) else {}
    advisory_id = _text(tracking.get("id"))
    if not advisory_id:
        raise AdvisoryError("the document has no tracking id.")
    try:
        issued_at = parse_utc(_text(tracking.get("current_release_date")))
    except ValueError as exc:
        raise AdvisoryError(
            "current_release_date is missing or has no timezone; a release date that "
            f"cannot be placed in time is not used ({exc}).") from exc
    publisher = head.get("publisher") if isinstance(head.get("publisher"), Mapping) else {}
    issued_by = _text(publisher.get("name"))
    if not issued_by:
        raise AdvisoryError("the document names no publisher.")

    refs = [r for r in (head.get("references") or []) if isinstance(r, Mapping)
            and _text(r.get("url"))]
    reference = next((_text(r["url"]) for r in refs if _text(r.get("category")) == "self"),
                     _text(refs[0]["url"]) if refs else "")
    if not reference:
        raise AdvisoryError(
            "the document carries no reference URL, so a reader could not trace it to its "
            "source.")

    notes: list[str] = [
        "Imported from an unsigned CSAF document: it has not been authenticated, so it is "
        "fit for inspection only and must not drive a change to a safety system.",
    ]
    if severity is AdvisorySeverity.SAFETY_RELEVANT:
        notes.append(
            "CSAF does not state whether the issue is safety-relevant. It was imported as "
            "'safety_relevant' so affected machines are reviewed rather than passed over; "
            "override the severity if the publisher says otherwise.")

    tree = document.get("product_tree") if isinstance(
        document.get("product_tree"), Mapping) else {}
    products: dict[str, _Product] = {}
    skipped: list[str] = []
    _walk(tree.get("branches"), (), products, skipped)
    if tree.get("relationships"):
        notes.append(
            "The product tree uses 'relationships' (a product combined with another). "
            "They are not interpreted; products that exist only as relationships were "
            "not imported.")

    affected_ids: dict[str, str] = {}   # product_id -> how the publisher classed it
    fixed_ids: set[str] = set()
    cves: list[str] = []
    remedy = ""
    vulns = document.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise AdvisoryError("the document lists no vulnerabilities.")
    for vuln in vulns:
        if not isinstance(vuln, Mapping):
            continue
        if _text(vuln.get("cve")) and _text(vuln["cve"]) not in cves:
            cves.append(_text(vuln["cve"]))
        status = vuln.get("product_status")
        if isinstance(status, Mapping):
            for key in _AFFECTED:
                for pid in status.get(key) or []:
                    affected_ids.setdefault(str(pid), key)
            for pid in status.get("under_investigation") or []:
                affected_ids.setdefault(str(pid), "under_investigation")
            for key in _FIXED:
                fixed_ids.update(str(p) for p in status.get(key) or [])
        for rem in vuln.get("remediations") or []:
            if (isinstance(rem, Mapping) and _text(rem.get("category")) == "vendor_fix"
                    and not remedy):
                remedy = _text(rem.get("details"))

    grouped: dict[tuple[str, str], dict[str, list[str]]] = {}
    for pid, how in affected_ids.items():
        product = products.get(pid)
        if product is None:
            skipped.append(
                f"affected product {pid!r} is not in the product tree with a vendor, name "
                "and version, so it was not imported")
            continue
        slot = grouped.setdefault((product.vendor, product.name),
                                  {"versions": [], "notes": []})
        if product.version not in slot["versions"]:
            slot["versions"].append(product.version)
        if product.is_range:
            slot["notes"].append(product.version)
        if how == "under_investigation":
            slot["notes"].append(
                f"{product.version}: under investigation by the publisher, not confirmed")
    if not grouped:
        raise AdvisoryError(
            "no affected product could be mapped, so the advisory would match nothing and "
            "read as 'nothing is affected'. " + ("; ".join(skipped) or ""))

    affected = tuple(
        AffectedArtefact(
            supplier=vendor, name=name, versions=tuple(slot["versions"]),
            version_note="; ".join(dict.fromkeys(slot["notes"])))
        for (vendor, name), slot in sorted(grouped.items()))

    fixed_versions: list[str] = []
    for pid in sorted(fixed_ids):
        product = products.get(pid)
        if product is None or product.is_range:
            skipped.append(
                f"fixed product {pid!r} has no exact version in the product tree, so it "
                "was not used to clear anything")
        elif product.version not in fixed_versions:
            fixed_versions.append(product.version)
    if fixed_versions and len(grouped) > 1:
        notes.append(
            "Fixed versions apply to the whole advisory in this product's model, not per "
            "product: a machine on one of them is treated as corrected whichever listed "
            "product it is.")

    notes.extend(dict.fromkeys(skipped))
    summary = ""
    for note in head.get("notes") or []:
        if isinstance(note, Mapping) and _text(note.get("category")) == "summary":
            summary = _text(note.get("text"))
            break
    if cves:
        summary = (summary + " " if summary else "") + "CVE: " + ", ".join(cves)

    return CsafImport(
        advisory=ComponentAdvisory(
            advisory_id=advisory_id, issued_by=issued_by, issued_at=issued_at,
            title=_text(head.get("title")), summary=summary, severity=severity,
            affected=affected, remedy=remedy, reference=reference,
            fixed_versions=tuple(fixed_versions)),
        notes=tuple(notes),
    )
