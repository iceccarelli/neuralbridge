"""Read a CycloneDX SBOM (JSON, spec 1.4 / 1.5 / 1.6) into a DRAFT machine-software inventory.

What an SBOM is, and is not
---------------------------
An SBOM is a list somebody produced of software they say is in a product. It does not say that any
of it is installed on a particular machine, that it was read off the unit, which of it the machine
needs in order to operate safely (Machinery Regulation Annex III 1.1.9), or what the machine's
serial number is. So the draft this module builds:

* never has a machine serial: the identity fields are *candidates* the document names, and the
  serial is always empty. A person types it at review;
* never marks a component safety-relevant, and never gives it a safety function (``implements`` is
  empty). Safety relevance is ``not_assessed`` and the decision is ``pending_review``;
* never uses a hash source stronger than ``declared``: nothing in an SBOM was hashed off a unit,
  so no component can be ``read_from_machine`` (the existing vocabulary's word for *measured*),
  and a vendor-supplied SHA-256 is kept as a declared digest, not as evidence about the unit;
* records an unsupplied version, purl, supplier or hash as ``unknown`` (a ``null`` and an entry in
  the component's ``unknown`` list). A version is never taken from a purl, a purl is never built
  from a name, and a supplier is never taken from a ``group``.

Validation
----------
The CycloneDX JSON schemas are large, reference further schemas and are not vendored here.
:func:`parse_cyclonedx` instead applies the explicit structural rules listed in :data:`RULES`; each
violation names its rule and the JSON path it was found at, and *any* violation refuses the whole
document (nothing is guessed around). It is a structural check, not a full schema validation:
``additionalProperties`` is not enforced (fields it does not know are listed in
``unrecognised_fields``, not refused), licence, pedigree, evidence, dependency, composition and
vulnerability content are not examined, and a signature on the document is not checked.

Hostile input: size, JSON depth, component count, component nesting, field length and invisible
characters are bounded (see the constants); duplicate JSON keys and duplicate ``bom-ref`` values
are refused.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from assurance.core.identity import parse_utc
from assurance.core.text import invisible_characters
from assurance.ingest.common import (
    IngestError,
    SourceRecord,
    parse_json_document,
)
from assurance.machinery.manifest import ItemKind

__all__ = [
    "CYCLONEDX_HASH_ALGORITHMS",
    "CYCLONEDX_TYPES",
    "DRAFT_SCHEMA",
    "IMPORTER",
    "MAX_COMPONENTS",
    "MAX_COMPONENT_NESTING",
    "NOT_ESTABLISHED",
    "RULES",
    "SUPPORTED_SPEC_VERSIONS",
    "SbomDraft",
    "draft_id_for",
    "parse_cyclonedx",
    "review_template",
]

IMPORTER = "assurance.ingest.sbom/1"
DRAFT_SCHEMA = "assurance.ingest.sbom_draft/1"
SUPPORTED_SPEC_VERSIONS = ("1.4", "1.5", "1.6")

#: Components one draft may hold. Over it, the document is refused, never truncated.
MAX_COMPONENTS = 5_000
#: How deeply ``components`` may nest inside ``components``.
MAX_COMPONENT_NESTING = 8
MAX_FIELD_CHARS = 500
MAX_PURL_CHARS = 1_000
MAX_HASHES_PER_COMPONENT = 20
MAX_VIOLATIONS = 50

_BASE_TYPES = ("application", "framework", "library", "container", "operating-system", "device",
               "firmware", "file")
#: Component ``type`` enumeration per spec version.
CYCLONEDX_TYPES: dict[str, frozenset[str]] = {
    "1.4": frozenset(_BASE_TYPES),
    "1.5": frozenset((*_BASE_TYPES, "platform", "device-driver", "machine-learning-model",
                      "data")),
    "1.6": frozenset((*_BASE_TYPES, "platform", "device-driver", "machine-learning-model",
                      "data", "cryptographic-asset")),
}
#: Hash algorithm -> hexadecimal digest length (``BLAKE3`` has none fixed: see ``_hash_ok``).
CYCLONEDX_HASH_ALGORITHMS: dict[str, int] = {
    "MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128,
    "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128,
    "BLAKE2b-256": 64, "BLAKE2b-384": 96, "BLAKE2b-512": 128, "BLAKE3": 0,
}
_SCOPES = ("required", "optional", "excluded")
_SERIAL = re.compile(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX = re.compile(r"[0-9a-fA-F]+")
_PURL = re.compile(r"pkg:[A-Za-z][A-Za-z0-9.+-]*/[^\s]+")
_KNOWN_COMPONENT_KEYS = frozenset({
    "type", "mime-type", "bom-ref", "supplier", "manufacturer", "author", "publisher", "group",
    "name", "version", "description", "scope", "hashes", "licenses", "copyright", "cpe", "purl",
    "swid", "modified", "pedigree", "externalReferences", "properties", "components", "evidence",
    "releaseNotes", "modelCard", "data", "cryptoProperties", "tags", "signature", "omniborId",
    "swhid", "authors"})

#: The component types the existing manifest vocabulary has a word for. Everything else has no
#: proposal: a person picks the kind, or leaves the component out.
_KIND_PROPOSAL = {"firmware": ItemKind.FIRMWARE.value, "library": ItemKind.LIBRARY.value,
                  "framework": ItemKind.LIBRARY.value}

#: The rules a document is checked against. The number is quoted in every violation.
RULES: dict[str, str] = {
    "SBOM-R01": "the document is a JSON object",
    "SBOM-R02": "bomFormat is exactly 'CycloneDX'",
    "SBOM-R03": "specVersion is present and one of " + ", ".join(SUPPORTED_SPEC_VERSIONS),
    "SBOM-R04": "serialNumber, when present, is 'urn:uuid:' and a lower-case UUID",
    "SBOM-R05": "version, when present, is an integer of at least 1",
    "SBOM-R06": "metadata, when present, is an object; metadata.timestamp is an ISO-8601 time "
                "with a timezone",
    "SBOM-R07": "components, when present, is an array of objects",
    "SBOM-R08": "every component has a type from the enumeration of the declared specVersion",
    "SBOM-R09": "every component has a non-empty string name",
    "SBOM-R10": "version, group, publisher, description, cpe and purl are strings when present; "
                "scope is required, optional or excluded",
    "SBOM-R11": "bom-ref is a non-empty string and is unique in the whole document "
                "(components, nested components, metadata.component and services)",
    "SBOM-R12": "hashes is an array of {alg, content}; alg is a CycloneDX algorithm and content "
                "is hexadecimal of that algorithm's length",
    "SBOM-R13": "supplier, when present, is an object whose name, when present, is a string",
    "SBOM-R14": "no more than " + str(MAX_COMPONENTS) + " components, nested no deeper than "
                + str(MAX_COMPONENT_NESTING),
    "SBOM-R15": "text fields are at most " + str(MAX_FIELD_CHARS) + " characters and contain no "
                "control, invisible or direction-changing character",
}

NOT_ESTABLISHED = (
    "an SBOM lists software; it does not say which of it is necessary for the machine to "
    "operate safely. Every component's safety relevance is NOT ASSESSED and every decision about "
    "it is pending review by a named person",
    "nothing in an SBOM was read off a machine: every component is 'declared', and a digest in "
    "it is kept as a declared digest, never as evidence about a unit",
    "the machine's manufacturer, model and serial number are not established by an SBOM; the "
    "serial is never taken from it and is entered by the reviewer",
    "completeness is unknown: software absent from the SBOM is absent from the draft",
    "the document was checked against documented structural rules (assurance.ingest.sbom.RULES), "
    "not against the full CycloneDX JSON schema, and its signature, if any, was not checked",
    "an unsupplied version, purl, supplier or digest is recorded as unknown and is never inferred",
)


def draft_id_for(source_sha256: str) -> str:
    """The id of the draft made from a document with this SHA-256 (the same bytes, the same id)."""
    return f"sbom-{source_sha256[:32]}"


def _slug(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")[:30] or "item"


class _Violations:
    def __init__(self) -> None:
        self.found: list[str] = []
        self.overflow = 0

    def add(self, rule: str, path: str, message: str) -> None:
        if len(self.found) >= MAX_VIOLATIONS:
            self.overflow += 1
        else:
            self.found.append(f"{rule} at {path}: {message}")

    def __bool__(self) -> bool:
        return bool(self.found)


def _str_field(node: dict[str, Any], key: str, path: str, rule: str, bad: _Violations,
               *, max_chars: int = MAX_FIELD_CHARS) -> str | None:
    """A text field exactly as supplied, ``None`` when absent. A wrong type or an unsafe value
    is a violation (and ``None``)."""
    if key not in node:
        return None
    value = node[key]
    if not isinstance(value, str):
        bad.add(rule, f"{path}.{key}", f"must be a string, not {type(value).__name__}")
        return None
    if len(value) > max_chars:
        bad.add("SBOM-R15", f"{path}.{key}", f"is longer than {max_chars} characters")
        return None
    hidden = invisible_characters(value)
    if hidden:
        bad.add("SBOM-R15", f"{path}.{key}",
                f"contains a control or invisible character ({', '.join(hidden)})")
        return None
    return value


def _hash_ok(alg: str, content: str) -> bool:
    if not _HEX.fullmatch(content):
        return False
    if alg == "BLAKE3":
        return len(content) in (32, 40, 64, 96, 128)
    return len(content) == CYCLONEDX_HASH_ALGORITHMS[alg]


def _supplier_name(node: dict[str, Any], key: str, path: str, bad: _Violations) -> str | None:
    if key not in node:
        return None
    sup = node[key]
    if not isinstance(sup, dict):
        bad.add("SBOM-R13", f"{path}.{key}", "must be an object")
        return None
    return _str_field(sup, "name", f"{path}.{key}", "SBOM-R13", bad)


@dataclass
class _Walk:
    spec: str
    bad: _Violations
    refs: dict[str, str]
    unrecognised: dict[str, None]


def _read_component(node: Any, path: str, walk: _Walk, *, subject: bool = False
                    ) -> dict[str, Any] | None:
    bad = walk.bad
    if not isinstance(node, dict):
        bad.add("SBOM-R07", path, "must be an object")
        return None
    ctype = _str_field(node, "type", path, "SBOM-R08", bad)
    if ctype is None:
        if "type" not in node:
            bad.add("SBOM-R08", path, "has no type")
    elif ctype not in CYCLONEDX_TYPES[walk.spec]:
        bad.add("SBOM-R08", path, f"type {ctype!r} is not a CycloneDX {walk.spec} component type")
    name = _str_field(node, "name", path, "SBOM-R09", bad)
    if name is None:
        if "name" not in node:
            bad.add("SBOM-R09", path, "has no name")
    elif not name.strip():
        bad.add("SBOM-R09", path, "has an empty name")
    version = _str_field(node, "version", path, "SBOM-R10", bad)
    group = _str_field(node, "group", path, "SBOM-R10", bad)
    publisher = _str_field(node, "publisher", path, "SBOM-R10", bad)
    _str_field(node, "description", path, "SBOM-R10", bad, max_chars=4_000)
    cpe = _str_field(node, "cpe", path, "SBOM-R10", bad)
    purl = _str_field(node, "purl", path, "SBOM-R10", bad, max_chars=MAX_PURL_CHARS)
    scope = _str_field(node, "scope", path, "SBOM-R10", bad)
    if scope is not None and scope not in _SCOPES:
        bad.add("SBOM-R10", f"{path}.scope", f"{scope!r} is not one of {', '.join(_SCOPES)}")
    bom_ref = _str_field(node, "bom-ref", path, "SBOM-R11", bad)
    if bom_ref is not None:
        if not bom_ref.strip():
            bad.add("SBOM-R11", f"{path}.bom-ref", "is empty")
        elif bom_ref in walk.refs:
            bad.add("SBOM-R11", f"{path}.bom-ref",
                    f"duplicates the bom-ref at {walk.refs[bom_ref]} (a reference must name "
                    "one thing)")
        else:
            walk.refs[bom_ref] = path
    supplier = _supplier_name(node, "supplier", path, bad)
    manufacturer = _supplier_name(node, "manufacturer", path, bad)

    hashes: list[dict[str, str]] = []
    if "hashes" in node:
        raw_hashes = node["hashes"]
        if not isinstance(raw_hashes, list):
            bad.add("SBOM-R12", f"{path}.hashes", "must be an array")
        elif len(raw_hashes) > MAX_HASHES_PER_COMPONENT:
            bad.add("SBOM-R12", f"{path}.hashes",
                    f"has more than {MAX_HASHES_PER_COMPONENT} entries")
        else:
            for i, entry in enumerate(raw_hashes):
                where = f"{path}.hashes[{i}]"
                if not isinstance(entry, dict):
                    bad.add("SBOM-R12", where, "must be an object")
                    continue
                alg, content = entry.get("alg"), entry.get("content")
                if not isinstance(alg, str) or alg not in CYCLONEDX_HASH_ALGORITHMS:
                    bad.add("SBOM-R12", where, "alg is missing or not a CycloneDX algorithm")
                elif not isinstance(content, str) or not _hash_ok(alg, content):
                    bad.add("SBOM-R12", where,
                            f"content is not hexadecimal of the length {alg} produces")
                else:
                    hashes.append({"alg": alg, "content": content})
    for key in node:
        if key not in _KNOWN_COMPONENT_KEYS and len(walk.unrecognised) < 100:
            walk.unrecognised.setdefault(f"{path}.{key}", None)

    sha256 = sorted({h["content"].lower() for h in hashes if h["alg"] == "SHA-256"})
    unknown = [label for label, present in (
        ("version", version is not None and version.strip() != ""),
        ("purl", purl is not None and purl.strip() != ""),
        ("supplier", supplier is not None and supplier.strip() != ""),
        ("sha256", len(sha256) == 1)) if not present]
    purl_ok = None if not purl else bool(_PURL.fullmatch(purl))
    return {
        "path": path, "bom_ref": bom_ref, "type": ctype, "group": group or None,
        "name": name, "version": version if version and version.strip() else None,
        "publisher": publisher or None, "supplier": supplier if supplier and supplier.strip() else None,
        "manufacturer": manufacturer or None, "cpe": cpe or None,
        "purl": purl if purl and purl.strip() else None, "purl_well_formed": purl_ok,
        "scope": scope, "hashes_as_supplied": hashes,
        # one SHA-256 and only one: two different values are ambiguous and are not used
        "sha256": sha256[0] if len(sha256) == 1 else None,
        "sha256_ambiguous": len(sha256) > 1,
        "unknown": unknown,
        "_nested": node.get("components") if not subject else None,
    }


@dataclass(frozen=True)
class SbomDraft:
    """A parsed SBOM, as a draft awaiting a named person's review. ``body`` is JSON-safe."""

    draft_id: str
    source: SourceRecord
    body: dict[str, Any]

    @property
    def components(self) -> list[dict[str, Any]]:
        return list(self.body["components"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self.body)


def _candidates(metadata: dict[str, Any], walk: _Walk) -> dict[str, list[dict[str, str]]]:
    """Names the document gives for the machine's manufacturer and model. Candidates only."""
    manufacturers: list[dict[str, str]] = []
    models: list[dict[str, str]] = []
    comp: dict[str, Any] = {}
    if isinstance(metadata.get("component"), dict):
        comp = metadata["component"]
    for where, node in (("metadata.manufacture", metadata.get("manufacture")),
                        ("metadata.manufacturer", metadata.get("manufacturer")),
                        ("metadata.supplier", metadata.get("supplier")),
                        ("metadata.component.manufacturer", comp.get("manufacturer")),
                        ("metadata.component.supplier", comp.get("supplier"))):
        if isinstance(node, dict) and isinstance(node.get("name"), str) and node["name"].strip() \
                and not invisible_characters(node["name"]):
            manufacturers.append({"value": node["name"], "from": where})
    pub = comp.get("publisher")
    if isinstance(pub, str) and pub.strip() and not invisible_characters(pub):
        manufacturers.append({"value": pub, "from": "metadata.component.publisher"})
    cname = comp.get("name")
    if isinstance(cname, str) and cname.strip() and not invisible_characters(cname):
        models.append({"value": cname, "from": "metadata.component.name"})
    return {"manufacturer": manufacturers, "model": models, "serial": []}


def parse_cyclonedx(raw: bytes, *, source: SourceRecord) -> SbomDraft:
    """A CycloneDX JSON document -> :class:`SbomDraft`, or :class:`IngestError` naming every rule
    it breaks. Nothing is recorded here; see :mod:`assurance.ingest.sbom_store`."""
    doc = parse_json_document(raw, "SBOM")
    bad = _Violations()
    if not isinstance(doc, dict):
        raise IngestError("the SBOM is not a JSON object.", code="invalid_sbom",
                          violations=("SBOM-R01 at $: the document must be a JSON object",))
    if doc.get("bomFormat") != "CycloneDX":
        bad.add("SBOM-R02", "$.bomFormat", f"is {str(doc.get('bomFormat'))[:40]!r}, not 'CycloneDX'")
    spec = doc.get("specVersion")
    if not isinstance(spec, str) or spec not in SUPPORTED_SPEC_VERSIONS:
        shown = str(spec)[:20]
        raise IngestError(
            f"specVersion {shown!r} is not supported; this importer reads CycloneDX JSON "
            f"{', '.join(SUPPORTED_SPEC_VERSIONS)} and will not guess at another schema.",
            code="unsupported_spec_version",
            violations=(*bad.found, f"SBOM-R03 at $.specVersion: {shown!r} is not supported"))
    serial = doc.get("serialNumber")
    if serial is not None and (not isinstance(serial, str) or not _SERIAL.fullmatch(serial)):
        bad.add("SBOM-R04", "$.serialNumber", "is not 'urn:uuid:' and a lower-case UUID")
        serial = None
    bom_version = doc.get("version")
    if bom_version is not None and (isinstance(bom_version, bool)
                                    or not isinstance(bom_version, int) or bom_version < 1):
        bad.add("SBOM-R05", "$.version", "must be an integer of at least 1")
        bom_version = None

    walk = _Walk(spec=spec, bad=bad, refs={}, unrecognised={})
    metadata = doc.get("metadata")
    timestamp: str | None = None
    subject: dict[str, Any] | None = None
    candidates: dict[str, list[dict[str, str]]] = {"manufacturer": [], "model": [], "serial": []}
    if metadata is not None:
        if not isinstance(metadata, dict):
            bad.add("SBOM-R06", "$.metadata", "must be an object")
        else:
            ts = metadata.get("timestamp")
            if ts is not None:
                if not isinstance(ts, str):
                    bad.add("SBOM-R06", "$.metadata.timestamp", "must be a string")
                else:
                    try:
                        parse_utc(ts)
                        timestamp = ts
                    except ValueError:
                        bad.add("SBOM-R06", "$.metadata.timestamp",
                                "is not an ISO-8601 time with a timezone")
            if "component" in metadata:
                subject = _read_component(metadata["component"], "$.metadata.component", walk,
                                          subject=True)
            candidates = _candidates(metadata, walk)

    raw_services = doc.get("services")
    if isinstance(raw_services, list):
        for i, svc in enumerate(raw_services[:MAX_COMPONENTS]):
            if isinstance(svc, dict) and isinstance(svc.get("bom-ref"), str) and svc["bom-ref"]:
                ref = svc["bom-ref"]
                if ref in walk.refs:
                    bad.add("SBOM-R11", f"$.services[{i}].bom-ref",
                            f"duplicates the bom-ref at {walk.refs[ref]}")
                else:
                    walk.refs[ref] = f"$.services[{i}]"

    top = doc.get("components")
    components: list[dict[str, Any]] = []
    if top is None:
        top = []
    if not isinstance(top, list):
        bad.add("SBOM-R07", "$.components", "must be an array")
        top = []
    stack: list[tuple[Any, str, int]] = [(n, f"$.components[{i}]", 1)
                                         for i, n in reversed(list(enumerate(top)))]
    while stack:
        node, path, depth = stack.pop()
        if len(components) >= MAX_COMPONENTS:
            bad.add("SBOM-R14", path, f"more than {MAX_COMPONENTS} components; the SBOM is "
                    "refused rather than truncated")
            break
        if depth > MAX_COMPONENT_NESTING:
            bad.add("SBOM-R14", path,
                    f"components nest deeper than {MAX_COMPONENT_NESTING} levels")
            continue
        comp = _read_component(node, path, walk)
        if comp is None:
            continue
        nested = comp.pop("_nested")
        if nested is not None:
            if not isinstance(nested, list):
                bad.add("SBOM-R07", f"{path}.components", "must be an array")
            else:
                stack.extend((n, f"{path}.components[{i}]", depth + 1)
                             for i, n in reversed(list(enumerate(nested))))
        components.append(comp)
    if bad:
        extra = f" (and {bad.overflow} more)" if bad.overflow else ""
        raise IngestError(
            f"the SBOM breaks {len(bad.found) + bad.overflow} structural rule(s){extra}; it is "
            "not a valid CycloneDX document of the version it declares, so nothing was "
            "recorded.", code="invalid_sbom", violations=tuple(bad.found))
    if not components:
        raise IngestError(
            "the SBOM lists no components, so there is nothing to draft. An empty inventory "
            "would assert that the machine has no software.", code="no_components",
            violations=("SBOM-R07 at $.components: no components",))

    used: set[str] = set()
    for n, comp in enumerate(components, 1):
        base = "ITM-" + _slug(comp["name"]) + "-" + hashlib.sha256(
            f"{comp['type']}\0{comp['group'] or ''}\0{comp['name']}".encode()).hexdigest()[:8]
        item_id, k = base, 1
        while item_id in used:
            k += 1
            item_id = f"{base}-{k}"
        used.add(item_id)
        comp.update({
            "ref": f"c{n:04d}", "item_id": item_id,
            "provenance_class": "declared_in_sbom",
            "hash_source_if_enrolled": "declared",
            "kind_proposal": _KIND_PROPOSAL.get(comp["type"]),
            "safety_relevance": "not_assessed",
            "implements": [],
            "review": "pending_review",
        })

    types: dict[str, int] = {}
    for comp in components:
        types[comp["type"]] = types.get(comp["type"], 0) + 1
    counts = {
        "components": len(components), "by_type": dict(sorted(types.items())),
        "without_version": sum(1 for c in components if "version" in c["unknown"]),
        "without_purl": sum(1 for c in components if "purl" in c["unknown"]),
        "without_supplier": sum(1 for c in components if "supplier" in c["unknown"]),
        "without_sha256": sum(1 for c in components if "sha256" in c["unknown"]),
        "with_ambiguous_sha256": sum(1 for c in components if c["sha256_ambiguous"]),
    }
    warnings: list[str] = []
    if counts["without_version"]:
        warnings.append(f"{counts['without_version']} component(s) carry no version: recorded as "
                        "unknown, not guessed (not even from a purl)")
    if counts["without_sha256"]:
        warnings.append(f"{counts['without_sha256']} component(s) carry no usable SHA-256: a "
                        "change to them could not be detected by comparison")
    malformed = [c["path"] for c in components if c["purl_well_formed"] is False]
    if malformed:
        warnings.append(f"{len(malformed)} purl(s) are not well formed ({', '.join(malformed[:3])}"
                        f"{'...' if len(malformed) > 3 else ''}); kept as supplied, never used")
    if subject is None:
        warnings.append("the SBOM names no metadata.component, so it does not say which product "
                        "it describes")

    draft_id = draft_id_for(source.sha256)
    body: dict[str, Any] = {
        "schema": DRAFT_SCHEMA, "importer": IMPORTER, "draft_id": draft_id,
        "review_state": "pending_review",
        "source": source.to_dict(),
        "bom": {
            "format": "CycloneDX", "spec_version": spec, "serial_number_as_supplied": serial,
            "bom_version": bom_version, "metadata_timestamp_as_supplied": timestamp,
            "subject_component": ({k: v for k, v in subject.items() if k != "_nested"}
                                  if subject else None),
        },
        "proposed_identity": {
            **candidates,
            "note": "candidates the document names; none is accepted. The serial number is "
                    "never taken from an SBOM and is entered by the reviewer.",
        },
        "components": components, "counts": counts,
        "unrecognised_fields": sorted(walk.unrecognised),
        "warnings": warnings,
        "decisions_required": [
            "machine identity: manufacturer, model and serial number (typed by the reviewer)",
            "for EVERY component: include or exclude it, and its item kind",
            "for each included component: whether it implements a declared safety function "
            "(the only way anything in this draft becomes safety-relevant)",
        ],
        "does_not_establish": list(NOT_ESTABLISHED),
    }
    return SbomDraft(draft_id=draft_id, source=source, body=body)


def review_template(draft_body: dict[str, Any]) -> dict[str, Any]:
    """A review request with every decision left blank (``null``).

    A request that still holds a blank decision is refused, so a draft cannot be approved by
    submitting its own template: each component and the machine's identity need an answer from
    the reviewer.
    """
    return {
        "draft_id": draft_body["draft_id"],
        "decision": None,
        "reason": "",
        "identity": {"manufacturer": "", "model": "", "serial": "", "site": "", "owner": "",
                     "year": "", "country": ""},
        "functions": [],
        "components": [
            {"ref": c["ref"], "name": c["name"], "version_in_sbom": c["version"],
             "include": None, "kind": c["kind_proposal"], "implements": [],
             "modifiable_in_field": None, "version": None, "supplier": None}
            for c in draft_body["components"]],
        "instructions": "Fill every null. kind must be one of "
                        + ", ".join(k.value for k in ItemKind)
                        + ". A function an item implements must be declared in 'functions'. "
                        "'version' and 'supplier' may be filled only where the SBOM supplied none.",
    }
