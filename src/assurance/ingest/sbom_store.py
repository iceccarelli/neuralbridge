"""Record an SBOM draft in a ledger, list it, and let a named person review it.

The draft (:mod:`assurance.ingest.sbom`) is recorded as an ``ingest.sbom_draft`` evidence object:
unverified, low confidence, every decision in it pending. It is *not* a manifest and nothing reads
it as one: no coverage, fleet, advisory or passport function looks at this kind.

The only way a draft becomes part of a machine's record is :func:`review_sbom_draft`, which

1. requires a **named person** (the same rule enrolment applies, :func:`require_person`);
2. requires an explicit answer for the machine's manufacturer, model and serial number and for
   **every** component (included or not, its kind, which declared safety function it implements):
   nothing is defaulted, so a draft cannot be approved by submitting its own template;
3. refuses a serial number that is the SBOM's own ``serialNumber`` or a placeholder;
4. builds an ``as_declared`` manifest whose items are all ``declared`` and enrols it through
   :func:`assurance.machinery.enrol.enrol_machine`, the one front door, so enrolment's own refusals
   (a configuration that differs, an identity conflict, a broken chain) apply unchanged;
5. records the review itself, naming the draft, the reviewer and every decision.

A draft is reviewed once. A rejected draft stays rejected; to start again, import a corrected SBOM.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from assurance.core.errors import AssuranceError, LedgerConflictError
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    EvidenceRef,
    Origin,
    ValidationState,
)
from assurance.core.identity import utc_now
from assurance.core.text import invisible_characters
from assurance.evidence.ledger import EvidenceLedger, LedgerEntry
from assurance.ingest.common import IngestError, SourceRecord
from assurance.ingest.sbom import NOT_ESTABLISHED, parse_cyclonedx, review_template
from assurance.machinery.enrol import enrol_machine, require_person
from assurance.machinery.inventory import InventoryImportError, parse_functions
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestError,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)

__all__ = [
    "DRAFT_KIND",
    "REVIEW_KIND",
    "REVIEW_SCHEMA",
    "get_sbom_draft",
    "import_sbom",
    "list_sbom_drafts",
    "review_sbom_draft",
]

DRAFT_KIND = "ingest.sbom_draft"
REVIEW_KIND = "ingest.sbom_review"
REVIEW_SCHEMA = "assurance.ingest.sbom_review/1"
_PLACEHOLDER_SERIALS = frozenset({
    "", "unknown", "n/a", "na", "tbd", "none", "null", "nil", "-", "--", "?", "todo", "xxx",
    "unspecified", "not supplied", "not available", "serial", "serial number"})
_REVIEW_KEYS = frozenset({"draft_id", "decision", "reason", "identity", "functions",
                          "components", "instructions"})
_IDENTITY_KEYS = ("manufacturer", "model", "serial", "site", "owner", "year", "country")
_COMPONENT_KEYS = frozenset({"ref", "name", "version_in_sbom", "include", "kind", "implements",
                             "modifiable_in_field", "version", "supplier"})
MAX_REASON_CHARS = 2_000


def _subject(source_sha256: str) -> str:
    return f"ingest/sbom/{source_sha256}"


def _read(ledger: EvidenceLedger, kind: str) -> tuple[list[tuple[LedgerEntry, Evidence]], list[int]]:
    """Every readable, still-sealed record of ``kind`` oldest first, and the seqs of damaged ones."""
    readable, damaged, _ = ledger.read_subject(None, kind)
    good: list[tuple[LedgerEntry, Evidence]] = []
    bad = [d.seq for d in damaged]
    for entry in readable:
        try:
            evidence = entry.evidence()
        except (AssuranceError, KeyError, ValueError, TypeError):
            bad.append(entry.seq)
            continue
        if not evidence.verify():
            bad.append(entry.seq)
            continue
        good.append((entry, evidence))
    return good, sorted(bad)


def _reviews(ledger: EvidenceLedger) -> dict[str, tuple[LedgerEntry, dict[str, Any]]]:
    out: dict[str, tuple[LedgerEntry, dict[str, Any]]] = {}
    for entry, evidence in _read(ledger, REVIEW_KIND)[0]:
        draft_id = str(evidence.body.get("draft_id", ""))
        out.setdefault(draft_id, (entry, evidence.body))
    return out


def _find_draft(ledger: EvidenceLedger, draft_id: str
                ) -> tuple[LedgerEntry, Evidence] | None:
    for entry, evidence in _read(ledger, DRAFT_KIND)[0]:
        if evidence.body.get("draft_id") == draft_id:
            return entry, evidence
    return None


def _summary(entry: LedgerEntry, body: dict[str, Any],
             review: tuple[LedgerEntry, dict[str, Any]] | None) -> dict[str, Any]:
    state = "pending_review"
    if review is not None:
        state = "approved_and_enrolled" if review[1].get("decision") == "approved" else "rejected"
    return {
        "draft_id": body["draft_id"], "review_state": state,
        "source_name": body["source"]["name_as_supplied"],
        "source_sha256": body["source"]["sha256"],
        "spec_version": body["bom"]["spec_version"],
        "components": body["counts"]["components"],
        "imported_at": entry.at, "entry": entry.seq, "content_hash": entry.content_hash,
        "reviewed_by": review[1].get("reviewer", {}).get("identifier", "") if review else "",
        "machine": review[1].get("machine", "") if review else "",
    }


def import_sbom(
    ledger: EvidenceLedger | None, raw: bytes, *, source: SourceRecord, actor: Actor,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Parse, validate and record an SBOM as a draft. Returns a receipt.

    ``status`` is ``imported``, ``already_imported`` (the same bytes were imported before: nothing
    is written, the existing draft is returned) or ``dry_run`` (nothing written; the whole draft
    is in ``draft``). Raises :class:`IngestError` for a document that is refused. ``ledger`` may be
    ``None`` only for a dry run.
    """
    draft = parse_cyclonedx(raw, source=source)
    base: dict[str, Any] = {
        "draft_id": draft.draft_id, "review_state": "pending_review",
        "source": draft.source.to_dict(), "counts": draft.body["counts"],
        "warnings": draft.body["warnings"],
        "decisions_required": draft.body["decisions_required"],
        "does_not_establish": list(NOT_ESTABLISHED),
    }
    if dry_run:
        return {**base, "status": "dry_run", "written": False, "draft": draft.to_dict()}
    if ledger is None:
        raise IngestError("a ledger is needed to record a draft.", code="invalid_request")
    ok, problems = ledger.verify_chain()
    if not ok:
        raise IngestError("the ledger chain does not verify, so nothing was recorded: "
                          + "; ".join(problems[:3]), code="ledger_chain_unverified")
    for _ in range(2):
        found = _find_draft(ledger, draft.draft_id)
        if found is not None:
            entry, evidence = found
            review = _reviews(ledger).get(draft.draft_id)
            return {**base, "status": "already_imported", "written": False,
                    "review_state": _summary(entry, evidence.body, review)["review_state"],
                    "entry": entry.seq, "content_hash": entry.content_hash}
        evidence = Evidence(
            kind=DRAFT_KIND, body=draft.to_dict(), actor=actor,
            origin=Origin(
                system="assurance.ingest.sbom",
                reference=f"{source.name or 'unnamed'} / sha256 {source.sha256[:16]}",
                method="CycloneDX JSON parsed and structurally validated; every mapping and "
                       "safety-relevance decision is a draft pending named human review"),
            validation_state=ValidationState.UNVERIFIED, confidence=Confidence.LOW,
            checks_skipped=NOT_ESTABLISHED,
        ).seal()
        try:
            entry = ledger.append(evidence, subject=_subject(source.sha256),
                                  expect_subject_head=0, expect_kinds=[DRAFT_KIND])
        except LedgerConflictError:
            continue                      # the same bytes were imported meanwhile: read again
        return {**base, "status": "imported", "written": True, "entry": entry.seq,
                "content_hash": entry.content_hash}
    raise IngestError("this document is being imported concurrently; nothing further was "
                      "written. Try again.", code="conflict")


def list_sbom_drafts(ledger: EvidenceLedger) -> dict[str, Any]:
    """Every draft in the ledger, oldest first, with its review state."""
    drafts, damaged = _read(ledger, DRAFT_KIND)
    reviews = _reviews(ledger)
    return {
        "drafts": [_summary(e, ev.body, reviews.get(ev.body.get("draft_id", "")))
                   for e, ev in drafts],
        "damaged_entries": damaged,
        "damaged_note": ("these draft records no longer match their seal or cannot be read; "
                         "they are not listed as drafts" if damaged else ""),
    }


def get_sbom_draft(ledger: EvidenceLedger, draft_id: str) -> dict[str, Any]:
    """One draft in full, with its review (if any) and a blank review template."""
    found = _find_draft(ledger, draft_id)
    if found is None:
        raise IngestError(f"no SBOM draft {draft_id!r} in this ledger.", code="draft_not_found")
    entry, evidence = found
    review = _reviews(ledger).get(draft_id)
    summary = _summary(entry, evidence.body, review)
    body = dict(evidence.body)
    body["review_state"] = summary["review_state"]
    return {
        **summary, "draft": body,
        "review": ({"entry": review[0].seq, **review[1]} if review else None),
        "review_template": review_template(body) if review is None else None,
    }


# --------------------------------------------------------------------------- the review

@dataclass(frozen=True)
class _Decision:
    ref: str
    include: bool
    kind: ItemKind | None = None
    implements: tuple[str, ...] = ()
    modifiable_in_field: bool = False
    version: str | None = None
    supplier: str | None = None


def _text(value: Any, what: str, bad: list[str], *, required: bool = False,
          max_chars: int = 200) -> str:
    if value is None or value == "":
        if required:
            bad.append(f"{what} is required")
        return ""
    if not isinstance(value, str):
        bad.append(f"{what} must be text")
        return ""
    if len(value) > max_chars:
        bad.append(f"{what} is longer than {max_chars} characters")
    hidden = invisible_characters(value)
    if hidden:
        bad.append(f"{what} contains a control or invisible character ({', '.join(hidden)})")
    return value


def _decisions(request: Mapping[str, Any], draft: dict[str, Any], function_ids: frozenset[str],
               bad: list[str]) -> list[_Decision]:
    by_ref = {c["ref"]: c for c in draft["components"]}
    raw = request.get("components")
    if not isinstance(raw, list):
        bad.append("components must be a list with one decision per component")
        return []
    out: list[_Decision] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw):
        where = f"components[{i}]"
        if not isinstance(entry, Mapping):
            bad.append(f"{where} must be an object")
            continue
        extra = sorted(str(k) for k in entry if k not in _COMPONENT_KEYS)
        if extra:
            bad.append(f"{where} has unknown field(s): {', '.join(extra[:5])}")
        ref = entry.get("ref")
        if not isinstance(ref, str) or ref not in by_ref:
            bad.append(f"{where} names no component of this draft (ref {str(ref)[:20]!r})")
            continue
        if ref in seen:
            bad.append(f"{where}: component {ref} is decided twice")
            continue
        seen.add(ref)
        comp = by_ref[ref]
        include = entry.get("include")
        if not isinstance(include, bool):
            bad.append(f"{ref} ({comp['name'][:40]}): 'include' must be true or false; it is "
                       "not defaulted")
            continue
        if not include:
            out.append(_Decision(ref=ref, include=False))
            continue
        kind_raw = entry.get("kind")
        kind: ItemKind | None = None
        if not isinstance(kind_raw, str) or kind_raw not in {k.value for k in ItemKind}:
            bad.append(f"{ref} ({comp['name'][:40]}): 'kind' must be one of "
                       + ", ".join(k.value for k in ItemKind))
        else:
            kind = ItemKind(kind_raw)
        implements = entry.get("implements")
        if not isinstance(implements, list) or not all(isinstance(s, str) for s in implements):
            bad.append(f"{ref}: 'implements' must be a list of declared function ids "
                       "(an empty list says the item implements none)")
            implements = []
        unknown_fn = sorted(set(implements) - function_ids)
        if unknown_fn:
            bad.append(f"{ref}: implements function(s) not declared in 'functions': "
                       + ", ".join(unknown_fn[:5]))
        mod = entry.get("modifiable_in_field")
        if not isinstance(mod, bool):
            bad.append(f"{ref}: 'modifiable_in_field' must be true or false; it is not defaulted")
            mod = False
        version = entry.get("version")
        if version not in (None, ""):
            _text(version, f"{ref} version", bad, max_chars=200)
            if comp["version"] is not None:
                bad.append(f"{ref}: the SBOM supplied version {comp['version']!r}; a reviewer "
                           "fills a version only where the SBOM gave none")
        supplier = entry.get("supplier")
        if supplier not in (None, ""):
            _text(supplier, f"{ref} supplier", bad, max_chars=200)
            if comp["supplier"] is not None:
                bad.append(f"{ref}: the SBOM supplied supplier {comp['supplier']!r}; a reviewer "
                           "fills a supplier only where the SBOM gave none")
        out.append(_Decision(
            ref=ref, include=True, kind=kind, implements=tuple(implements),
            modifiable_in_field=mod, version=version or None, supplier=supplier or None))
    missing = sorted(set(by_ref) - seen)
    if missing:
        bad.append(f"{len(missing)} component(s) have no decision ({', '.join(missing[:6])}"
                   f"{'...' if len(missing) > 6 else ''}); every component needs an explicit "
                   "include/exclude")
    return out


def _identity(request: Mapping[str, Any], draft: dict[str, Any], bad: list[str]
              ) -> dict[str, str]:
    raw = request.get("identity")
    if not isinstance(raw, Mapping):
        bad.append("identity must be an object with manufacturer, model and serial")
        return {}
    extra = sorted(str(k) for k in raw if k not in _IDENTITY_KEYS)
    if extra:
        bad.append(f"identity has unknown field(s): {', '.join(extra[:5])}")
    ident = {k: _text(raw.get(k), f"identity.{k}", bad, required=k in ("manufacturer", "model",
                                                                       "serial"))
             for k in _IDENTITY_KEYS}
    serial = ident["serial"]
    if serial.strip().casefold() in _PLACEHOLDER_SERIALS and "identity.serial is required" not in bad:
        bad.append(f"identity.serial {serial!r} is a placeholder, not a serial number")
    bom = draft["bom"]
    own = {bom.get("serial_number_as_supplied")}
    subject = bom.get("subject_component") or {}
    own.add(subject.get("bom_ref"))
    if serial and serial in {s for s in own if s}:
        bad.append("identity.serial equals an identifier of the SBOM itself (its serialNumber or "
                   "the bom-ref of its subject component). That identifies the document, not "
                   "the machine; type the number on the unit's rating plate")
    return ident


def review_sbom_draft(
    ledger: EvidenceLedger, draft_id: str, request: Mapping[str, Any], *, reviewer: Actor | None,
    attribution: str = "",
) -> dict[str, Any]:
    """A named person's decision on a draft: approve (and enrol) or reject. See the module doc.

    Raises :class:`~assurance.machinery.enrol.EnrolmentError` when the reviewer is not a named
    person, and :class:`IngestError` for everything else that is refused (``invalid_review`` with
    one violation per fault, ``draft_not_found``, ``already_reviewed``, or enrolment's own refusal
    as ``configuration_differs`` / ``identity_conflict``). Nothing is recorded on a refusal.

    ``attribution`` is text a hosting service composes about how it established who the reviewer
    is (an authenticated operator key, say). It is recorded beside the reviewer, never inside the
    reviewer's role, which stays free text without the service's separators.
    """
    who = require_person(reviewer, "SBOM draft review")
    found = _find_draft(ledger, draft_id)
    if found is None:
        raise IngestError(f"no SBOM draft {draft_id!r} in this ledger.", code="draft_not_found")
    draft_entry, draft_evidence = found
    draft = draft_evidence.body
    if draft_id in _reviews(ledger):
        raise IngestError(f"draft {draft_id} has already been reviewed; a review is not "
                          "repeated or overwritten. Import a corrected SBOM to start again.",
                          code="already_reviewed")
    bad: list[str] = []
    extra = sorted(str(k) for k in request if k not in _REVIEW_KEYS)
    if extra:
        bad.append(f"unknown field(s): {', '.join(extra[:5])}")
    if request.get("draft_id") not in (None, draft_id):
        bad.append("the request names a different draft than the one being reviewed")
    decision = request.get("decision")
    if decision not in ("approve", "reject"):
        bad.append("decision must be 'approve' or 'reject'; it is not defaulted")
    reason = _text(request.get("reason"), "reason", bad, required=True, max_chars=MAX_REASON_CHARS)
    relations = (EvidenceRef("concerns", draft_entry.content_hash, "the SBOM draft reviewed"),)
    origin = Origin(system="assurance.ingest.sbom", reference=draft_id,
                    method="a named person's review of an SBOM draft")

    if decision == "reject":
        if bad:
            raise IngestError("the review is not valid; nothing was recorded.",
                              code="invalid_review", violations=tuple(bad))
        body = {"schema": REVIEW_SCHEMA, "draft_id": draft_id,
                "draft_content_hash": draft_entry.content_hash,
                "source_sha256": draft["source"]["sha256"], "decision": "rejected",
                "reason": reason, "reviewer": who.to_dict(), "reviewer_attribution": attribution,
                "machine": ""}
        review = Evidence(kind=REVIEW_KIND, body=body, actor=who, origin=origin,
                          validation_state=ValidationState.UNVERIFIED, confidence=Confidence.LOW,
                          checks_skipped=NOT_ESTABLISHED, relations=relations).seal()
        entry = ledger.append(review, subject=_subject(draft["source"]["sha256"]))
        return {"status": "rejected", "draft_id": draft_id, "review_entry": entry.seq,
                "review_content_hash": entry.content_hash, "machine": "", "enrolment": None}

    try:
        functions = parse_functions(request.get("functions"))
    except InventoryImportError as exc:
        bad.append(f"functions: {exc}")
        functions = ()
    function_ids = frozenset(f.function_id for f in functions)
    identity = _identity(request, draft, bad)
    decisions = _decisions(request, draft, function_ids, bad)
    if not bad and not any(d.include for d in decisions):
        bad.append("every component is excluded, so there is nothing to enrol; an empty "
                   "inventory would assert that the machine has no software")
    if bad:
        raise IngestError(
            f"the review is not valid ({len(bad)} problem(s)); nothing was recorded.",
            code="invalid_review", violations=tuple(bad[:60]))

    by_ref = {c["ref"]: c for c in draft["components"]}
    items: list[SafetyItem] = []
    for d in decisions:
        if not d.include or d.kind is None:
            continue
        comp = by_ref[d.ref]
        digest = comp["sha256"] or ""
        notes = (f"declared in SBOM {draft['source']['sha256'][:16]} at {comp['path']}"
                 f"{' (bom-ref ' + comp['bom_ref'] + ')' if comp['bom_ref'] else ''}"
                 f"{'; purl ' + comp['purl'] if comp['purl'] else ''}; not read from the machine; "
                 f"included by {who.identifier}")
        try:
            items.append(SafetyItem(
                item_id=comp["item_id"], kind=d.kind, name=comp["name"],
                version=comp["version"] or d.version or "", content_hash=digest,
                hash_source=HashSource.DECLARED, supplier=comp["supplier"] or d.supplier or "",
                implements=d.implements, modifiable_in_field=d.modifiable_in_field,
                notes=notes))
        except ManifestError as exc:
            raise IngestError(f"{d.ref}: {exc}", code="invalid_review",
                              violations=(str(exc),)) from exc
    try:
        machine = MachineIdentity(
            manufacturer=identity["manufacturer"], model=identity["model"],
            serial=identity["serial"], year=identity["year"], site=identity["site"],
            country=identity["country"].upper())
        machine.require_unambiguous()
        manifest = SafetyManifest(
            manifest_id=f"SBOM-{draft['source']['sha256'][:12]}", machine=machine,
            source=ManifestSource.AS_DECLARED, taken_at=utc_now(), taken_by=who,
            items=tuple(items),
            functions=tuple(SafetyFunction(f.function_id, f.description, f.required_performance,
                                           f.verified_by) for f in functions),
            method="components of a CycloneDX SBOM draft, reviewed by a named person; nothing "
                   "was collected from the machine",
            notes=(f"importer={draft['importer']}; draft={draft_id}; "
                   f"sbom_sha256={draft['source']['sha256']}; "
                   f"spec={draft['bom']['spec_version']}; reviewer={who.identifier}; "
                   "every item is declared, none was read from the machine"))
    except ManifestError as exc:
        raise IngestError(str(exc), code="invalid_review", violations=(str(exc),)) from exc

    receipt = enrol_machine(ledger, manifest, actor=who, owner=identity["owner"] or None)
    if receipt.refused:
        raise IngestError(
            f"enrolment refused ({receipt.status}): {receipt.pointer} Nothing was recorded; "
            "the draft is still pending.", code=receipt.status,
            violations=(receipt.pointer,))

    included = [d for d in decisions if d.include]
    body = {
        "schema": REVIEW_SCHEMA, "draft_id": draft_id,
        "draft_content_hash": draft_entry.content_hash,
        "source_sha256": draft["source"]["sha256"], "decision": "approved", "reason": reason,
        "reviewer": who.to_dict(), "reviewer_attribution": attribution,
        "machine": manifest.machine.key,
        "identity_as_typed_by_reviewer": identity,
        "functions": [{"function_id": f.function_id, "description": f.description,
                       "required_performance": f.required_performance,
                       "verified_by": list(f.verified_by)} for f in functions],
        "components": [
            {"ref": d.ref, "include": d.include,
             **({"kind": d.kind.value if d.kind else "", "implements": list(d.implements),
                 "modifiable_in_field": d.modifiable_in_field,
                 "version_filled_by_reviewer": d.version or "",
                 "supplier_filled_by_reviewer": d.supplier or ""} if d.include else {})}
            for d in decisions],
        "safety_relevance_decided_by": who.identifier,
        "manifest": {"manifest_id": manifest.manifest_id,
                     "configuration_hash": manifest.configuration_hash(),
                     "items": len(manifest.items), "tier_ceiling": manifest.tier_ceiling.value},
        "enrolment": {"status": receipt.status, "entry": receipt.enrolment_entry,
                      "manifest_entry": receipt.manifest_entry},
        "excluded": len(decisions) - len(included),
    }
    review = Evidence(kind=REVIEW_KIND, body=body, actor=who, origin=origin,
                      validation_state=ValidationState.UNVERIFIED, confidence=Confidence.LOW,
                      checks_skipped=NOT_ESTABLISHED, relations=relations).seal()
    entry = ledger.append(review, subject=_subject(draft["source"]["sha256"]))
    return {"status": "approved", "draft_id": draft_id, "review_entry": entry.seq,
            "review_content_hash": entry.content_hash, "machine": manifest.machine.key,
            "configuration_hash": manifest.configuration_hash(),
            "enrolment": receipt.to_dict(),
            "tier_ceiling": manifest.tier_ceiling.value,
            "does_not_establish": list(NOT_ESTABLISHED)}
