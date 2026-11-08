"""Import a CSAF 2.0 document as a recorded SUPPLIER ADVISORY and match it to the enrolled fleet.

:mod:`assurance.fleet.csaf` already translates a CSAF document into this product's
``ComponentAdvisory`` (for the inspect-only fan-out and for opening a case). That translation
deliberately drops what a fleet-wide *statement* needs: it ignores ``known_not_affected``, keeps
no per-vulnerability status, and does not keep the publisher or the document's identity. This
module reads the same product tree through the same reader (:func:`read_product_tree`) and adds
what is missing, without a second parser of the product tree:

* the document is checked against the CSAF 2.0 structure documented in :data:`RULES` (not the
  full JSON schema: it is large, references other schemas and is not vendored; see the docs) and
  *any* violation refuses the whole document;
* the record keeps the SHA-256 of the bytes as received, the publisher exactly as written
  (``name``, ``namespace``, ``category``), the tracking id / version / status, the initial and
  current release dates, the TLP label, the source name / timestamp / URL as the caller supplied
  them, and each vulnerability's ``product_status`` as the publisher wrote it;
* the translation to ``ComponentAdvisory`` is stored with it when one can be made, so the existing
  case workflow can use it, and the reason when none can (a VEX with nothing affected, say).

Matching a machine
------------------
For every enrolled machine, each manifest item is compared with the product definitions, and every
vulnerability gives one result per item. The result vocabulary is closed:

``affected``
    a product the publisher lists as ``known_affected`` / ``first_affected`` / ``last_affected``
    matches the item with certainty;
``under_investigation``, ``fixed``, ``not_affected``
    the same for ``under_investigation``, ``fixed`` / ``first_fixed`` and ``known_not_affected``;
``unknown``
    everything else, with a reason code. In particular:

    * the supplier differs, or the item records none: the component name matches and nothing more
      is known (``supplier_differs``, ``supplier_missing``). There is no fuzzy matching;
    * the item's version is not the one the publisher names, or is outside, or is not comparable
      with, a stated range: the publisher said nothing about *this* version
      (``version_not_covered``, ``version_scheme_ambiguous``);
    * a range is compared only when both it and the item's version are dotted decimal numbers
      with no leading zeros and the range is one clause or one lower-and-upper interval
      (``vers:semver/`` prefix allowed); every other spelling is not interpreted;
    * the item's hash was read off the unit and the publisher states a different hash for the
      version the label names (``hash_mismatch``): neither affected nor clear;
    * the publisher's statements about the item contradict each other (``status_conflict``);
    * the vulnerability's ``product_status`` does not mention the item at all
      (``not_addressed_by_vulnerability``): absence is not a statement.

A machine's result is the worst of its items' results, in the order ``affected``,
``under_investigation``, ``unknown``, ``fixed``, ``not_affected``. A machine none of whose
components the document names is ``unknown`` with the reason ``not_named``: that is not a
statement that it is unaffected. ``fixed`` and ``not_affected`` are further withheld (made
``unknown``) when the document is not ``final``, when the ledger chain does not verify, or when
the latest look at the machine was incomplete.

Every result is **inspect-only**: the document is unsigned third-party content, the match is
a label or hash comparison, and the safety conclusion is a person's.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from assurance.core.errors import AssuranceError, LedgerConflictError
from assurance.core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from assurance.core.identity import parse_utc
from assurance.core.text import invisible_characters
from assurance.evidence.ledger import EvidenceLedger, LedgerEntry
from assurance.fleet.advisory import AdvisoryError, fold_text
from assurance.fleet.csaf import (
    MAX_DEPTH,
    advisory_from_csaf,
    read_product_tree,
)
from assurance.fleet.registry import Fleet
from assurance.ingest.common import IngestError, SourceRecord, parse_json_document
from assurance.machinery.manifest import ManifestSource, SafetyItem, normalised_digest

__all__ = [
    "IMPORTER",
    "NOT_ESTABLISHED",
    "RECORD_KIND",
    "RULES",
    "STATES",
    "csaf_impact",
    "get_csaf_advisory",
    "import_csaf",
    "list_csaf_advisories",
    "match_machine",
    "parse_version",
    "validate_csaf",
]

IMPORTER = "assurance.ingest.csaf/1"
RECORD_KIND = "ingest.csaf_advisory"
RECORD_SCHEMA = "assurance.ingest.csaf_advisory/1"
IMPACT_SCHEMA = "assurance.ingest.csaf_impact/1"
SUPPORTED_CATEGORIES = ("csaf_security_advisory", "csaf_vex")
#: Product definitions and vulnerabilities one record may hold; over either, the document is
#: refused (never truncated: a record that dropped a product would read as the whole document).
MAX_STORED_PRODUCTS = 5_000
MAX_VULNERABILITIES = 2_000
MAX_VIOLATIONS = 50

#: The closed vocabulary of results.
STATES = ("affected", "under_investigation", "unknown", "fixed", "not_affected")
_WORST_FIRST = {s: i for i, s in enumerate(STATES)}

_PUBLISHER_CATEGORIES = ("coordinator", "discoverer", "other", "translator", "user", "vendor")
_STATUS_GROUPS = {
    "known_affected": "affected", "first_affected": "affected", "last_affected": "affected",
    "known_not_affected": "not_affected", "fixed": "fixed", "first_fixed": "fixed",
    "under_investigation": "under_investigation"}
_STATUS_KEYS = (*_STATUS_GROUPS, "recommended")
_BRANCH_CATEGORIES = frozenset({
    "architecture", "host_name", "language", "legacy", "patch_level", "product_family",
    "product_name", "product_version", "product_version_range", "service_pack", "specification",
    "vendor"})
_RELATIONSHIP_CATEGORIES = frozenset({
    "default_component_of", "external_component_of", "installed_on", "installed_with",
    "optional_component_of"})
_VERSION_NUMBER = re.compile(r"(0|[1-9][0-9]*)")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_TRACKING_VERSION = re.compile(
    r"(0|[1-9][0-9]*)|(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(-((0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?")
_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s]+")

RULES: dict[str, str] = {
    "CSAF-R01": "the document is a JSON object with a 'document' object",
    "CSAF-R02": "document.csaf_version is exactly '2.0'",
    "CSAF-R03": "document.category is a non-empty string, and one this importer reads: "
                + ", ".join(SUPPORTED_CATEGORIES),
    "CSAF-R04": "document.title is a non-empty string",
    "CSAF-R05": "document.publisher has a category (coordinator, discoverer, other, translator, "
                "user, vendor), a non-empty name and a namespace that is an absolute URI",
    "CSAF-R06": "document.tracking has an id, a status (draft, final, interim), a version "
                "(integer or semantic version), initial_release_date and current_release_date "
                "(RFC 3339 with a timezone, current not before initial) and a non-empty "
                "revision_history of {date, number, summary} that includes the version",
    "CSAF-R07": "a security advisory or VEX has a product_tree and at least one vulnerability",
    "CSAF-R08": "every product tree branch has a known category, a name, and exactly one of "
                "'branches' and 'product'; a product has a name and a product_id",
    "CSAF-R09": "every product_id is defined exactly once (branches, full_product_names, "
                "relationships)",
    "CSAF-R10": "each vulnerability is an object; cve, when present, is CVE-yyyy-nnnn; "
                "product_status keys are CSAF's and hold lists of product ids",
    "CSAF-R11": "every product id used in a product_status, remediation, threat, flag, score or "
                "relationship is defined in the product tree",
    "CSAF-R12": "in one vulnerability a product is in at most one of the groups affected, "
                "not affected, fixed and under investigation",
    "CSAF-R13": "no more than " + str(MAX_STORED_PRODUCTS) + " product definitions and "
                + str(MAX_VULNERABILITIES) + " vulnerabilities; branches nest at most "
                + str(MAX_DEPTH) + " deep",
    "CSAF-R14": "text that is stored or compared contains no control, invisible or "
                "direction-changing character",
}

NOT_ESTABLISHED = (
    "the document is unsigned third-party content: nothing here authenticates its publisher, so "
    "the record is inspect-only and must not drive a change to a safety system",
    "a match is a comparison of names, version labels and (where read from the unit) hashes; a "
    "label is not an artefact, and a machine's real software may differ from its manifest",
    "'not_affected' and 'fixed' are the publisher's statements, relayed only where the match is "
    "certain; they are not this product's finding that the machine is safe",
    "a machine none of whose components the document names is 'unknown' (not_named); the "
    "document is silent about it, which is not a statement that it is unaffected",
    "the document was checked against documented structural rules (assurance.ingest.csaf.RULES), "
    "not against the full CSAF JSON schema",
)


# --------------------------------------------------------------------------- validation

class _Bad:
    def __init__(self) -> None:
        self.found: list[str] = []
        self.overflow = 0

    def add(self, rule: str, path: str, message: str) -> None:
        if len(self.found) >= MAX_VIOLATIONS:
            self.overflow += 1
        else:
            self.found.append(f"{rule} at {path}: {message}")


def _string(node: Mapping[str, Any], key: str, path: str, rule: str, bad: _Bad,
            *, required: bool = True, max_chars: int = 1_000) -> str:
    if key not in node:
        if required:
            bad.add(rule, f"{path}.{key}", "is required")
        return ""
    value = node[key]
    if not isinstance(value, str) or (required and not value.strip()):
        bad.add(rule, f"{path}.{key}", "must be a non-empty string")
        return ""
    if len(value) > max_chars:
        bad.add("CSAF-R14", f"{path}.{key}", f"is longer than {max_chars} characters")
        return ""
    hidden = invisible_characters(value)
    if hidden:
        bad.add("CSAF-R14", f"{path}.{key}",
                f"contains a control or invisible character ({', '.join(hidden)})")
        return ""
    return value


def _date(value: Any, path: str, bad: _Bad) -> Any:
    if not isinstance(value, str):
        bad.add("CSAF-R06", path, "must be an RFC 3339 date-time string")
        return None
    try:
        return parse_utc(value)
    except ValueError:
        bad.add("CSAF-R06", path, "is not a date-time with a timezone")
        return None


def _validate_header(doc: Mapping[str, Any], bad: _Bad) -> None:
    if doc.get("csaf_version") != "2.0":
        bad.add("CSAF-R02", "$.document.csaf_version",
                f"is {str(doc.get('csaf_version'))[:20]!r}; this importer reads exactly '2.0'")
    category = _string(doc, "category", "$.document", "CSAF-R03", bad, max_chars=200)
    if category and category not in SUPPORTED_CATEGORIES:
        bad.add("CSAF-R03", "$.document.category",
                f"{category[:60]!r} is not supported; supported: {', '.join(SUPPORTED_CATEGORIES)}")
    _string(doc, "title", "$.document", "CSAF-R04", bad)
    pub = doc.get("publisher")
    if not isinstance(pub, Mapping):
        bad.add("CSAF-R05", "$.document.publisher", "is required and must be an object")
    else:
        if pub.get("category") not in _PUBLISHER_CATEGORIES:
            bad.add("CSAF-R05", "$.document.publisher.category",
                    "must be one of " + ", ".join(_PUBLISHER_CATEGORIES))
        _string(pub, "name", "$.document.publisher", "CSAF-R05", bad, max_chars=500)
        ns = _string(pub, "namespace", "$.document.publisher", "CSAF-R05", bad)
        if ns and not _URI.fullmatch(ns):
            bad.add("CSAF-R05", "$.document.publisher.namespace", "is not an absolute URI")
    refs = doc.get("references")
    for i, ref in enumerate(refs[:20] if isinstance(refs, list) else []):
        if isinstance(ref, Mapping):
            _string(ref, "url", f"$.document.references[{i}]", "CSAF-R14", bad, required=False,
                    max_chars=2_000)
    tracking = doc.get("tracking")
    if not isinstance(tracking, Mapping):
        bad.add("CSAF-R06", "$.document.tracking", "is required and must be an object")
        return
    _string(tracking, "id", "$.document.tracking", "CSAF-R06", bad, max_chars=500)
    if tracking.get("status") not in ("draft", "final", "interim"):
        bad.add("CSAF-R06", "$.document.tracking.status", "must be draft, final or interim")
    version = tracking.get("version")
    if not isinstance(version, str) or not _TRACKING_VERSION.fullmatch(version):
        bad.add("CSAF-R06", "$.document.tracking.version",
                "must be an integer or a semantic version, as text")
        version = None
    initial = _date(tracking.get("initial_release_date"),
                    "$.document.tracking.initial_release_date", bad)
    current = _date(tracking.get("current_release_date"),
                    "$.document.tracking.current_release_date", bad)
    if initial and current and current < initial:
        bad.add("CSAF-R06", "$.document.tracking.current_release_date",
                "is before initial_release_date")
    history = tracking.get("revision_history")
    if not isinstance(history, list) or not history:
        bad.add("CSAF-R06", "$.document.tracking.revision_history", "must be a non-empty array")
        return
    numbers: list[str] = []
    for i, entry in enumerate(history[:1_000]):
        where = f"$.document.tracking.revision_history[{i}]"
        if not isinstance(entry, Mapping):
            bad.add("CSAF-R06", where, "must be an object")
            continue
        _date(entry.get("date"), f"{where}.date", bad)
        number = _string(entry, "number", where, "CSAF-R06", bad, max_chars=100)
        _string(entry, "summary", where, "CSAF-R06", bad)
        if number:
            numbers.append(number)
    if version is not None and numbers and version not in numbers:
        bad.add("CSAF-R06", "$.document.tracking.version",
                "does not appear among the revision_history numbers")


def _defined_ids(tree: Mapping[str, Any], bad: _Bad) -> dict[str, str]:
    """Every product id the tree defines -> where. Structural rules R08, R09, R13 are applied."""
    defined: dict[str, str] = {}

    def define(pid: Any, path: str) -> None:
        if not isinstance(pid, str) or not pid.strip():
            bad.add("CSAF-R08", path, "product_id must be a non-empty string")
            return
        hidden = invisible_characters(pid)
        if hidden:
            bad.add("CSAF-R14", path, f"product_id contains an invisible character "
                                      f"({', '.join(hidden)})")
            return
        if pid in defined:
            bad.add("CSAF-R09", path, f"product id {pid[:60]!r} is also defined at {defined[pid]}")
        else:
            defined[pid] = path

    branches = tree.get("branches")
    if branches is not None and not isinstance(branches, list):
        bad.add("CSAF-R08", "$.product_tree.branches", "must be an array")
        branches = []
    stack: list[tuple[Any, str, int]] = [
        (b, f"$.product_tree.branches[{i}]", 1)
        for i, b in reversed(list(enumerate(branches or [])))]
    count = 0
    while stack:
        node, path, depth = stack.pop()
        if depth > MAX_DEPTH:
            bad.add("CSAF-R13", path, f"branches nest deeper than {MAX_DEPTH} levels")
            continue
        if not isinstance(node, Mapping):
            bad.add("CSAF-R08", path, "a branch must be an object")
            continue
        if node.get("category") not in _BRANCH_CATEGORIES:
            bad.add("CSAF-R08", f"{path}.category", "is not a CSAF branch category")
        _string(node, "name", path, "CSAF-R08", bad, max_chars=500)
        has_children, has_product = "branches" in node, "product" in node
        if has_children == has_product:
            bad.add("CSAF-R08", path, "must have exactly one of 'branches' and 'product'")
        if has_product:
            product = node["product"]
            if not isinstance(product, Mapping):
                bad.add("CSAF-R08", f"{path}.product", "must be an object")
            else:
                _string(product, "name", f"{path}.product", "CSAF-R08", bad, max_chars=500)
                count += 1
                define(product.get("product_id"), f"{path}.product.product_id")
        if has_children:
            kids = node["branches"]
            if not isinstance(kids, list) or not kids:
                bad.add("CSAF-R08", f"{path}.branches", "must be a non-empty array")
            else:
                stack.extend((k, f"{path}.branches[{i}]", depth + 1)
                             for i, k in reversed(list(enumerate(kids))))
        if count > MAX_STORED_PRODUCTS:
            bad.add("CSAF-R13", path, f"more than {MAX_STORED_PRODUCTS} product definitions")
            break

    for key in ("full_product_names", "relationships"):
        entries = tree.get(key)
        if entries is None:
            continue
        if not isinstance(entries, list):
            bad.add("CSAF-R08", f"$.product_tree.{key}", "must be an array")
            continue
        for i, entry in enumerate(entries[:MAX_STORED_PRODUCTS + 1]):
            where = f"$.product_tree.{key}[{i}]"
            if not isinstance(entry, Mapping):
                bad.add("CSAF-R08", where, "must be an object")
                continue
            fpn = entry if key == "full_product_names" else entry.get("full_product_name")
            if key == "relationships" and entry.get("category") not in _RELATIONSHIP_CATEGORIES:
                bad.add("CSAF-R08", f"{where}.category", "is not a CSAF relationship category")
            if not isinstance(fpn, Mapping):
                bad.add("CSAF-R08", where, "has no full_product_name object")
                continue
            _string(fpn, "name", where, "CSAF-R08", bad, max_chars=500)
            count += 1
            define(fpn.get("product_id"), f"{where}.product_id")
    if count > MAX_STORED_PRODUCTS:
        bad.add("CSAF-R13", "$.product_tree",
                f"defines more than {MAX_STORED_PRODUCTS} products; refused, not truncated")
    return defined


def _validate_vulnerabilities(vulns: Any, defined: Mapping[str, str], bad: _Bad) -> None:
    if not isinstance(vulns, list):
        bad.add("CSAF-R10", "$.vulnerabilities", "must be an array")
        return
    if len(vulns) > MAX_VULNERABILITIES:
        bad.add("CSAF-R13", "$.vulnerabilities",
                f"more than {MAX_VULNERABILITIES} vulnerabilities; refused, not truncated")
        return

    def refs(ids: Any, where: str) -> list[str]:
        if not isinstance(ids, list) or not all(isinstance(p, str) and p for p in ids):
            bad.add("CSAF-R10", where, "must be an array of product ids")
            return []
        for pid in ids:
            if pid not in defined:
                bad.add("CSAF-R11", where, f"product id {pid[:60]!r} is not defined in the "
                                           "product tree")
        return ids

    for i, vuln in enumerate(vulns):
        path = f"$.vulnerabilities[{i}]"
        if not isinstance(vuln, Mapping):
            bad.add("CSAF-R10", path, "must be an object")
            continue
        cve = vuln.get("cve")
        if cve is not None and (not isinstance(cve, str) or not _CVE.fullmatch(cve)):
            bad.add("CSAF-R10", f"{path}.cve", "is not of the form CVE-yyyy-nnnn")
        status = vuln.get("product_status")
        if status is not None:
            if not isinstance(status, Mapping):
                bad.add("CSAF-R10", f"{path}.product_status", "must be an object")
            else:
                groups: dict[str, set[str]] = {}
                for key, ids in status.items():
                    if key not in _STATUS_KEYS:
                        bad.add("CSAF-R10", f"{path}.product_status.{key}",
                                "is not a CSAF product status")
                        continue
                    listed = refs(ids, f"{path}.product_status.{key}")
                    group = _STATUS_GROUPS.get(key)
                    if group:
                        for pid in listed:
                            groups.setdefault(pid, set()).add(group)
                for pid, seen in groups.items():
                    if len(seen) > 1:
                        bad.add("CSAF-R12", f"{path}.product_status",
                                f"product {pid[:60]!r} is in more than one of: "
                                + ", ".join(sorted(seen)))
        for section, key in (("remediations", "product_ids"), ("threats", "product_ids"),
                             ("flags", "product_ids"), ("scores", "products")):
            entries = vuln.get(section)
            if entries is None:
                continue
            if not isinstance(entries, list):
                bad.add("CSAF-R10", f"{path}.{section}", "must be an array")
                continue
            for j, entry in enumerate(entries):
                if isinstance(entry, Mapping) and key in entry:
                    refs(entry[key], f"{path}.{section}[{j}].{key}")


def validate_csaf(document: Any) -> list[str]:
    """Every rule of :data:`RULES` a parsed document breaks; empty when it breaks none."""
    bad = _Bad()
    if not isinstance(document, Mapping) or not isinstance(document.get("document"), Mapping):
        return ["CSAF-R01 at $: the document must be a JSON object with a 'document' object"]
    _validate_header(document["document"], bad)
    tree = document.get("product_tree")
    category = document["document"].get("category")
    if category in SUPPORTED_CATEGORIES:
        if not isinstance(tree, Mapping):
            bad.add("CSAF-R07", "$.product_tree", "a security advisory or VEX needs a product_tree")
        if not isinstance(document.get("vulnerabilities"), list) or not document.get(
                "vulnerabilities"):
            bad.add("CSAF-R07", "$.vulnerabilities", "needs at least one vulnerability")
    defined: dict[str, str] = {}
    if isinstance(tree, Mapping):
        defined = _defined_ids(tree, bad)
    elif tree is not None:
        bad.add("CSAF-R08", "$.product_tree", "must be an object")
    if "vulnerabilities" in document:
        _validate_vulnerabilities(document["vulnerabilities"], defined, bad)
    out = list(bad.found)
    if bad.overflow:
        out.append(f"... and {bad.overflow} more violation(s)")
    return out


# --------------------------------------------------------------------------- versions

_RANGE_CLAUSE = re.compile(r"(<=|>=|<|>)\s*([vV]?[0-9][0-9.]*)")


def parse_version(label: str) -> tuple[int, ...] | None:
    """A dotted decimal version as a tuple of integers, or ``None`` if the scheme is not
    unambiguous: more than four components, a leading zero (``2.001`` is neither 2.1 nor 2.001),
    a prerelease or build suffix, or anything that is not digits and dots (one leading ``v``
    allowed)."""
    text = label.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or not all(_VERSION_NUMBER.fullmatch(p) for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    pa, pb = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (pa > pb) - (pa < pb)


def _in_range(version: tuple[int, ...], text: str) -> bool | None:
    """Is ``version`` in the range ``text``? ``None`` when the range is not one this module
    interprets (see the module docstring)."""
    body = text.strip()
    if body.casefold().startswith("vers:"):
        scheme, _, rest = body[5:].partition("/")
        if scheme.casefold() != "semver":
            return None
        body = rest
    clauses = [c.strip() for c in body.split("|")]
    if not 1 <= len(clauses) <= 2:
        return None
    parsed: list[tuple[str, tuple[int, ...]]] = []
    for clause in clauses:
        m = _RANGE_CLAUSE.fullmatch(clause)
        if not m:
            return None
        bound = parse_version(m.group(2))
        if bound is None:
            return None
        parsed.append((m.group(1), bound))
    if len(parsed) == 2:
        ops = {parsed[0][0][0], parsed[1][0][0]}
        if ops != {"<", ">"}:                  # exactly one lower and one upper bound
            return None
    for op, bound in parsed:
        c = _cmp(version, bound)
        if not ((op == "<" and c < 0) or (op == "<=" and c <= 0)
                or (op == ">" and c > 0) or (op == ">=" and c >= 0)):
            return False
    return True


def _relation(item_version: str, product: Mapping[str, Any]) -> tuple[str, str]:
    """How the item's version stands to the product's.

    ``equal`` / ``in_range``: the publisher's statement covers this version. ``different`` /
    ``outside``: both are comparable and the item is not covered. ``undetermined``: they cannot
    be compared without guessing at a version scheme. The second element is a reason code for
    anything that is not a cover.
    """
    label = fold_text(item_version)
    if not label:
        return "undetermined", "version_missing"
    numeric = parse_version(item_version)
    exact = str(product.get("version") or "")
    ranges = list(product.get("ranges") or [])
    undetermined = False
    if exact:
        if fold_text(exact) == label:
            return "equal", ""
        other = parse_version(exact)
        if other is None or numeric is None:
            undetermined = True
        elif _cmp(other, numeric) == 0:
            return "equal", ""                      # 3.1 and 3.1.0
    for text in ranges:
        verdict = None if numeric is None else _in_range(numeric, text)
        if verdict is True:
            return "in_range", ""
        if verdict is None:
            undetermined = True
    if undetermined:
        return "undetermined", "version_scheme_ambiguous"
    return ("outside" if ranges else "different"), "version_not_covered"


# --------------------------------------------------------------------------- the record

def _record_products(document: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    try:
        tree = read_product_tree(document)
    except AdvisoryError as exc:
        raise IngestError(f"the product tree cannot be read: {exc}", code="invalid_csaf",
                          violations=(f"CSAF-R13 at $.product_tree: {exc}",)) from exc
    products: dict[str, dict[str, Any]] = {}
    for pid, p in tree.products.items():
        products[pid] = {
            "vendor": p.vendor, "name": p.name, "version": p.exact or None,
            "ranges": list(p.ranges), "sha256": list(p.hashes), "purl": p.purl or None,
            "cpe": p.cpe or None}
    uninterpreted: dict[str, str] = {}
    for pid, why in {**tree.elsewhere, **tree.unusable}.items():
        uninterpreted[pid] = why
    return products, uninterpreted


def _doc_summary(doc: Mapping[str, Any]) -> dict[str, Any]:
    tracking, pub = doc["tracking"], doc["publisher"]
    tlp = (doc.get("distribution") or {}).get("tlp") if isinstance(
        doc.get("distribution"), Mapping) else None
    refs = [{"url": r.get("url"), "category": r.get("category", "external"),
             "summary": r.get("summary")}
            for r in (doc.get("references") or [])[:20]
            if isinstance(r, Mapping) and isinstance(r.get("url"), str)]
    return {
        "csaf_version": doc["csaf_version"], "category": doc["category"], "title": doc["title"],
        "lang": doc["lang"] if isinstance(doc.get("lang"), str)
        and re.fullmatch(r"[A-Za-z0-9-]{1,35}", doc["lang"]) else None,
        "publisher": {
            "category": pub["category"], "name": pub["name"], "namespace": pub["namespace"]},
        "tracking": {
            "id": tracking["id"], "version": tracking["version"], "status": tracking["status"],
            "initial_release_date": tracking["initial_release_date"],
            "current_release_date": tracking["current_release_date"],
            "revisions": len(tracking["revision_history"])},
        "tlp_label": tlp.get("label") if isinstance(tlp, Mapping)
        and isinstance(tlp.get("label"), str) else None,
        "references": refs,
    }


def _record_vulns(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    out = []
    for i, v in enumerate(document.get("vulnerabilities") or []):
        status = v.get("product_status") if isinstance(v.get("product_status"), Mapping) else {}
        ids = [{"system_name": x.get("system_name"), "text": x.get("text")}
               for x in (v.get("ids") or []) if isinstance(x, Mapping)][:10]
        out.append({
            "index": i, "cve": v.get("cve"), "ids": ids,
            "title": v.get("title") if isinstance(v.get("title"), str) else None,
            "product_status": {k: list(status.get(k) or []) for k in _STATUS_KEYS
                               if status.get(k)}})
    return out


def advisory_ref_for(source_sha256: str) -> str:
    return f"csaf-{source_sha256[:32]}"


def _subject(source_sha256: str) -> str:
    return f"ingest/csaf/{source_sha256}"


def _build_record(raw: bytes, source: SourceRecord, *, allow_draft: bool) -> dict[str, Any]:
    document = parse_json_document(raw, "CSAF document", max_depth=2 * MAX_DEPTH + 12)
    violations = validate_csaf(document)
    if violations:
        raise IngestError(
            f"the document breaks {len(violations)} CSAF 2.0 structural rule(s); it is not "
            "recorded.", code="invalid_csaf", violations=tuple(violations))
    head = document["document"]
    status = head["tracking"]["status"]
    partial_reasons: list[str] = []
    if status != "final":
        if not allow_draft:
            raise IngestError(
                f"the document's tracking status is {status!r}, not 'final'. A draft or interim "
                "advisory can still change or be withdrawn; import it only with allow_draft, and "
                "it is then recorded as partial and can state no 'fixed' or 'not_affected'.",
                code="document_not_final",
                violations=(f"CSAF-R06 at $.document.tracking.status: {status!r}",))
        partial_reasons.append(f"the tracking status is {status!r}, not 'final', so it may change "
                               "or be withdrawn")
    products, uninterpreted = _record_products(document)
    vulns = _record_vulns(document)
    used = {pid for v in vulns for ids in v["product_status"].values() for pid in ids}
    lost = sorted(p for p in used if p in uninterpreted)
    if lost:
        partial_reasons.append(
            f"{len(lost)} product id(s) named in a product_status cannot be matched to a machine "
            f"(no vendor / name / version in a branch path, or defined only through "
            f"full_product_names / relationships): {', '.join(repr(p) for p in lost[:5])}"
            f"{'...' if len(lost) > 5 else ''}")
    translation: dict[str, Any]
    try:
        imported = advisory_from_csaf(document, allow_draft=allow_draft)
        translation = {"ok": True, "reason": "", "advisory": imported.advisory.to_dict(),
                       "advisory_content_hash": imported.advisory.content_hash(),
                       "notes": list(imported.notes)}
    except (AdvisoryError, AssuranceError, KeyError, ValueError, TypeError) as exc:
        translation = {"ok": False, "reason": str(exc), "advisory": None}
    return {
        "schema": RECORD_SCHEMA, "importer": IMPORTER,
        "advisory_ref": advisory_ref_for(source.sha256), "source": source.to_dict(),
        "document": _doc_summary(head), "validation": {"valid": True, "rules": sorted(RULES)},
        "products": products, "uninterpreted_products": uninterpreted,
        "vulnerabilities": vulns, "translation": translation,
        "partial": bool(partial_reasons), "partial_reasons": partial_reasons,
        "trust": "unsigned_inspect_only", "does_not_establish": list(NOT_ESTABLISHED),
    }


def _read(ledger: EvidenceLedger) -> tuple[list[tuple[LedgerEntry, dict[str, Any]]], list[int]]:
    readable, damaged, _ = ledger.read_subject(None, RECORD_KIND)
    good: list[tuple[LedgerEntry, dict[str, Any]]] = []
    bad = [d.seq for d in damaged]
    for entry in readable:
        try:
            evidence = entry.evidence()
        except (AssuranceError, KeyError, ValueError, TypeError):
            bad.append(entry.seq)
            continue
        if evidence.verify():
            good.append((entry, evidence.body))
        else:
            bad.append(entry.seq)
    return good, sorted(bad)


def _row(entry: LedgerEntry, body: Mapping[str, Any]) -> dict[str, Any]:
    doc = body["document"]
    return {
        "advisory_ref": body["advisory_ref"], "tracking_id": doc["tracking"]["id"],
        "tracking_version": doc["tracking"]["version"],
        "tracking_status": doc["tracking"]["status"],
        "publisher_name": doc["publisher"]["name"],
        "publisher_namespace": doc["publisher"]["namespace"],
        "publisher_category": doc["publisher"]["category"],
        "title": doc["title"], "current_release_date": doc["tracking"]["current_release_date"],
        "source_name": body["source"]["name_as_supplied"], "source_sha256": body["source"]["sha256"],
        "vulnerabilities": len(body["vulnerabilities"]), "products": len(body["products"]),
        "partial": body["partial"], "imported_at": entry.at, "entry": entry.seq,
        "content_hash": entry.content_hash, "trust": body["trust"],
    }


def import_csaf(
    ledger: EvidenceLedger | None, raw: bytes, *, source: SourceRecord, actor: Actor,
    allow_draft: bool = False, dry_run: bool = False,
) -> dict[str, Any]:
    """Validate and record a CSAF 2.0 document as a supplier advisory. Returns a receipt.

    ``status`` is ``imported``, ``already_imported`` (the same bytes were imported: nothing is
    written) or ``dry_run`` (nothing written; the record is in ``record``). Raises
    :class:`IngestError` for a document that is refused.
    """
    record = _build_record(raw, source, allow_draft=allow_draft)
    head = record["document"]
    base: dict[str, Any] = {
        "advisory_ref": record["advisory_ref"], "source": record["source"],
        "publisher": head["publisher"], "tracking": head["tracking"], "title": head["title"],
        "vulnerabilities": len(record["vulnerabilities"]), "products": len(record["products"]),
        "partial": record["partial"], "partial_reasons": record["partial_reasons"],
        "uninterpreted_products": len(record["uninterpreted_products"]),
        "translation_ok": record["translation"]["ok"], "trust": record["trust"],
        "does_not_establish": list(NOT_ESTABLISHED),
    }
    if dry_run:
        return {**base, "status": "dry_run", "written": False, "record": record}
    if ledger is None:
        raise IngestError("a ledger is needed to record an advisory.", code="invalid_request")
    ok, problems = ledger.verify_chain()
    if not ok:
        raise IngestError("the ledger chain does not verify, so nothing was recorded: "
                          + "; ".join(problems[:3]), code="ledger_chain_unverified")
    for _ in range(2):
        held, _damaged = _read(ledger)
        for entry, body in held:
            if body["advisory_ref"] == record["advisory_ref"]:
                return {**base, "status": "already_imported", "written": False,
                        "entry": entry.seq, "content_hash": entry.content_hash}
        siblings = [b["advisory_ref"] for _, b in held
                    if b["document"]["tracking"]["id"] == head["tracking"]["id"]
                    and b["document"]["publisher"]["namespace"] == head["publisher"]["namespace"]]
        evidence = Evidence(
            kind=RECORD_KIND, body=record, actor=actor,
            origin=Origin(
                system="assurance.ingest.csaf",
                reference=f"{source.name or 'unnamed'} / sha256 {source.sha256[:16]}",
                method="CSAF 2.0 JSON validated against documented structural rules and recorded "
                       "as an unsigned supplier statement"),
            validation_state=ValidationState.UNVERIFIED, confidence=Confidence.LOW,
            checks_skipped=NOT_ESTABLISHED).seal()
        try:
            entry = ledger.append(evidence, subject=_subject(source.sha256),
                                  expect_subject_head=0, expect_kinds=[RECORD_KIND])
        except LedgerConflictError:
            continue
        out = {**base, "status": "imported", "written": True, "entry": entry.seq,
               "content_hash": entry.content_hash}
        if siblings:
            out["same_tracking_id_as"] = siblings
            out["sibling_note"] = ("a document with this publisher and tracking id was imported "
                                   "before with different content (another revision?). Both are "
                                   "kept; read each, none supersedes the other here.")
        return out
    raise IngestError("this document is being imported concurrently; try again.",
                      code="conflict")


def list_csaf_advisories(ledger: EvidenceLedger) -> dict[str, Any]:
    held, damaged = _read(ledger)
    return {"advisories": [_row(e, b) for e, b in held], "damaged_entries": damaged,
            "damaged_note": ("these records no longer match their seal or cannot be read; they "
                             "are not listed" if damaged else "")}


def _find(ledger: EvidenceLedger, advisory_ref: str) -> tuple[LedgerEntry, dict[str, Any]]:
    for entry, body in _read(ledger)[0]:
        if body["advisory_ref"] == advisory_ref:
            return entry, body
    raise IngestError(f"no CSAF advisory {advisory_ref!r} in this ledger.",
                      code="advisory_not_found")


def get_csaf_advisory(ledger: EvidenceLedger, advisory_ref: str) -> dict[str, Any]:
    entry, body = _find(ledger, advisory_ref)
    return {**_row(entry, body), "record": body}


# --------------------------------------------------------------------------- matching

def _identity(item: SafetyItem, product: Mapping[str, Any], item_hash: str
              ) -> tuple[str, str]:
    """``(strength, basis)``: ``certain`` or ``uncertain`` and what it rests on."""
    if item_hash and item_hash in set(product.get("sha256") or ()):
        return "certain", "hash_read_from_unit"
    supplier = fold_text(item.supplier)
    if not supplier:
        return "uncertain", "supplier_missing"
    if supplier == fold_text(str(product.get("vendor") or "")):
        return "certain", "name_and_supplier"
    return "uncertain", "supplier_differs"


#: A statement about one item: ``(product id, state, reason code if unknown, certain, stated,
#: via_hash)``. ``state`` is one of the publisher's four or ``unknown``; ``stated`` is what the
#: publisher said about the product, kept even where the match is uncertain so a doubtful
#: "affected" is not lost; ``via_hash`` is true when the product was matched by a hash read off
#: the unit.
_Candidate = tuple[str, str, str, bool, str, bool]
_REASON_ORDER = ("hash_mismatch", "supplier_differs", "supplier_missing", "version_missing",
                 "version_scheme_ambiguous", "version_not_covered")


def _resolve(candidates: list[_Candidate]) -> tuple[str, str]:
    """Collapse the statements about one item in one vulnerability to ``(state, reason_code)``."""
    definite = {c[1] for c in candidates if c[3] and c[1] != "unknown"}
    doubtful = [c for c in candidates if not c[3] and c[4] in ("affected", "under_investigation")]
    if definite == {"affected", "under_investigation"}:
        definite = {"affected"}
    if len(definite) > 1:
        # a hash read off the unit says one thing and the label another: the label is stale
        # or the unit is not what it says it is. Neither affected nor clear.
        return "unknown", ("hash_mismatch" if any(c[5] for c in candidates) else
                           "status_conflict")
    if len(definite) == 1:
        state = next(iter(definite))
        if state in ("fixed", "not_affected") and doubtful:
            return "unknown", doubtful[0][2]
        return state, ""
    reasons = {c[2] for c in candidates if c[1] == "unknown" and c[2]}
    for preferred in _REASON_ORDER:
        if preferred in reasons:
            return "unknown", preferred
    return "unknown", next(iter(sorted(reasons)), "version_not_covered")


_Index = tuple[dict[str, list[str]], dict[str, list[str]], list[dict[str, str]]]


def build_index(body: Mapping[str, Any]) -> _Index:
    """Product ids by folded name and by stated hash, and each vulnerability's id -> state map."""
    by_name: dict[str, list[str]] = {}
    by_hash: dict[str, list[str]] = {}
    for pid, product in body["products"].items():
        by_name.setdefault(fold_text(product["name"]), []).append(pid)
        for digest in product.get("sha256") or ():
            by_hash.setdefault(digest, []).append(pid)
    pid_states: list[dict[str, str]] = []
    for v in body["vulnerabilities"]:
        mapping: dict[str, str] = {}
        for key, ids in v["product_status"].items():
            group = _STATUS_GROUPS.get(key)
            if group:
                for pid in ids:
                    mapping[pid] = group
        pid_states.append(mapping)
    return by_name, by_hash, pid_states


def match_machine(
    items: tuple[SafetyItem, ...], body: Mapping[str, Any], *, document_final: bool,
    index: _Index | None = None,
) -> list[dict[str, Any]]:
    """One result per manifest item the document names: its state and the evidence for it.

    Items the document does not name are not returned (a machine with none is ``not_named``).
    """
    products: Mapping[str, Mapping[str, Any]] = body["products"]
    by_name, by_hash, pid_states = index or build_index(body)
    vulns = body["vulnerabilities"]
    results: list[dict[str, Any]] = []
    for item in items:
        read_hash = normalised_digest(item.content_hash) if item.hash_source.describes_this_unit \
            else ""
        linked = list(dict.fromkeys([*by_name.get(fold_text(item.name), []),
                                     *(by_hash.get(read_hash, []) if read_hash else [])]))
        if not linked:
            continue
        links = {pid: _identity(item, products[pid], read_hash) for pid in linked}
        per_vuln: list[dict[str, Any]] = []
        for vi, mapping in enumerate(pid_states):
            candidates: list[_Candidate] = []
            for pid in linked:
                if pid not in mapping:
                    continue
                strength, basis = links[pid]
                product = products[pid]
                said = mapping[pid]
                if basis == "hash_read_from_unit":
                    candidates.append((pid, said, "", True, said, True))
                    continue
                if strength == "uncertain":
                    candidates.append((pid, "unknown", basis, False, said, False))
                    continue
                relation, why = _relation(item.version, product)
                if relation in ("equal", "in_range"):
                    stated = list(product.get("sha256") or ())
                    if read_hash and stated and read_hash not in stated:
                        candidates.append((pid, "unknown", "hash_mismatch", True, said, False))
                    else:
                        candidates.append((pid, said, "", True, said, False))
                else:
                    candidates.append((pid, "unknown", why, True, said, False))
            if not candidates:
                state, reason = "unknown", "not_addressed_by_vulnerability"
            else:
                state, reason = _resolve(candidates)
            if state in ("fixed", "not_affected") and not document_final:
                state, reason = "unknown", "document_not_final"
            vuln = vulns[vi]
            per_vuln.append({
                "vulnerability": vuln["cve"] or f"vulnerabilities[{vi}]", "state": state,
                "reason_code": reason,
                "product_ids": sorted({c[0] for c in candidates})})
        worst = min((p["state"] for p in per_vuln), key=_WORST_FIRST.__getitem__,
                    default="unknown")
        reasons = sorted({p["reason_code"] for p in per_vuln if p["reason_code"]
                          and p["state"] == worst})
        shown = per_vuln[:100]
        results.append({
            "item_id": item.item_id, "item_name": item.name, "item_version": item.version,
            "item_supplier": item.supplier, "state": worst, "reason_codes": reasons,
            "identity": sorted({f"{links[p][0]}:{links[p][1]}" for p in linked}),
            "item_hash_basis": ("read_from_unit" if read_hash else
                                "not read from the unit; the label decided"),
            "matched_product_ids": sorted(linked),
            "vulnerabilities": shown, "vulnerabilities_not_shown": len(per_vuln) - len(shown)})
    return results


def _provenance(entry: LedgerEntry, body: Mapping[str, Any]) -> dict[str, Any]:
    doc = body["document"]
    return {
        "advisory_ref": body["advisory_ref"], "ledger_entry": entry.seq,
        "document_sha256": body["source"]["sha256"],
        "source_name_as_supplied": body["source"]["name_as_supplied"],
        "source_url_as_supplied": body["source"]["url_as_supplied"],
        "publisher": doc["publisher"], "tracking": doc["tracking"],
        "tlp_label": doc["tlp_label"], "trust": body["trust"],
        "inspect_only": True, "automated_consequences_permitted": False,
    }


def csaf_impact(ledger: EvidenceLedger, advisory_ref: str, *, recorder_trust: Any = None
                ) -> dict[str, Any]:
    """What the recorded advisory says about each enrolled machine. Records nothing."""
    entry, body = _find(ledger, advisory_ref)
    fleet = Fleet.from_ledger(ledger, recorder_trust=recorder_trust)
    final = body["document"]["tracking"]["status"] == "final"
    machines: list[dict[str, Any]] = []
    index = build_index(body)
    for record in fleet.records:
        manifest = record.manifest
        item_results = match_machine(manifest.items, body, document_final=final, index=index)
        caveats: list[str] = []
        if not item_results:
            state, reasons = "unknown", ["not_named"]
        else:
            state = min((r["state"] for r in item_results), key=_WORST_FIRST.__getitem__)
            reasons = sorted({c for r in item_results if r["state"] == state
                              for c in r["reason_codes"]})
        withheld = ""
        if state in ("fixed", "not_affected"):
            if not fleet.chain_verified:
                withheld = "ledger_chain_unverified"
            elif record.look_problems:
                withheld = "look_incomplete"
        if withheld:
            state, reasons = "unknown", [withheld]
            caveats.append("a 'fixed' / 'not_affected' result is withheld: " + (
                "the ledger chain does not verify" if withheld == "ledger_chain_unverified"
                else "the latest look at this machine was incomplete or failed"))
        if manifest.source is not ManifestSource.AS_FOUND:
            caveats.append("the configuration is known only from a declared baseline: what is "
                           "installed was never observed")
        if manifest.uncomparable_items:
            caveats.append(f"{len(manifest.uncomparable_items)} item(s) carry no hash, so a "
                           "label decided every match for them")
        machines.append({
            "machine": record.machine_key, "site": record.site, "state": state,
            "reason_codes": reasons, "named_by_advisory": bool(item_results),
            "configuration_basis": manifest.source.value, "items": item_results,
            "caveats": caveats, "look_problems": list(record.look_problems),
        })
    counts = {s: sum(1 for m in machines if m["state"] == s) for s in STATES}
    not_named = sum(1 for m in machines if not m["named_by_advisory"])
    caveats = list(NOT_ESTABLISHED)
    if not fleet.chain_verified:
        caveats.insert(0, "THE LEDGER CHAIN DOES NOT VERIFY: every statement here is drawn from "
                          "a store whose integrity is in question")
    if not machines:
        caveats.insert(0, "no machine is enrolled in this ledger, so none was assessed")
    if body["partial"]:
        caveats.insert(0, "the recorded advisory is PARTIAL: " + "; ".join(body["partial_reasons"]))
    complete = (fleet.chain_verified and bool(machines) and not body["partial"]
                and counts["unknown"] == not_named and counts["under_investigation"] == 0)
    return {
        "schema": IMPACT_SCHEMA, "advisory_ref": advisory_ref,
        "provenance": _provenance(entry, body),
        "machines_in_fleet": len(machines), "counts": counts, "not_named": not_named,
        "machines_affected": sorted(m["machine"] for m in machines if m["state"] == "affected"),
        "complete": complete,
        "complete_note": ("every machine is affected, fixed, not_affected or not named by the "
                          "advisory" if complete else
                          "some machine is under_investigation or unknown, or the advisory or the "
                          "ledger is incomplete: this is not a clear"),
        "ledger_chain_verified": fleet.chain_verified,
        "machines": machines, "does_not_establish": caveats,
    }
