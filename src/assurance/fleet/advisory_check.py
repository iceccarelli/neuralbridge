"""Is this ONE machine affected by this ONE advisory? No ledger, no account, nothing sealed.

The body of ``POST /v1/fleet/advisory/check`` and of ``assurance fleet advisory-check``: one
function, so the two cannot answer differently. The match basis is always reported. ``hash``
settles it; ``version`` rests on a label, and this system has already shown a label can be
wrong; ``hash_mismatch`` means the machine's own label and artefact disagree against the
supplier's published figures, which is neither affected nor clear.
"""

from __future__ import annotations

from typing import Any

from assurance.fleet.advisory import ComponentAdvisory, match_item
from assurance.fleet.impact import advisory_provenance
from assurance.machinery.manifest import SafetyManifest
from assurance.supplier.trust import TRUST_STATEMENT

__all__ = ["BARE_REQUEST_BODY_PROVENANCE", "check_one_machine"]

#: An advisory handed over as a JSON body (or a file) has no signature to check and no key to
#: pin. It can be assessed; it is not a trusted supplier statement.
BARE_REQUEST_BODY_PROVENANCE: dict[str, Any] = {
    "source": "request_body", "trust_state": "unauthenticated_input",
    "trust_basis": "none", "signature_state": "none",
    "automated_consequences_permitted": False, "inspect_only": True,
    "override": None, "implications_reviewed": False,
    "trust_statement": TRUST_STATEMENT,
}


def check_one_machine(advisory: ComponentAdvisory, manifest: SafetyManifest) -> dict[str, Any]:
    """One advisory against one manifest, with everything the answer does not establish."""
    matches = []
    for item in manifest.items:
        matched = match_item(advisory, item)
        if matched is None:
            continue
        basis, detail = matched
        matches.append({
            "item_id": item.item_id,
            "item_name": item.name,
            "item_version": item.version,
            "basis": basis.value,
            "confidence": basis.confidence,
            "needs_a_human": basis.needs_a_human,
            "detail": detail,
            "implements": list(item.implements),
        })

    skipped = [
        "this compares one advisory against one manifest. It says nothing about "
        "any other machine, and it does not assess whether the safety evidence for "
        "the affected functions still stands — that needs the ledger.",
    ]
    if not advisory.publishes_hashes:
        skipped.append(
            f"{advisory.issued_by} published no artefact hashes, so any match here "
            "rests on a version label.")
    record = advisory.import_record
    if record is not None:
        skipped.append(
            "this advisory is an unsigned CSAF import: nobody has authenticated it.")
        if record.partial:
            skipped.append(
                "this advisory is a PARTIAL translation (not imported: "
                + (", ".join(record.dropped_ids) or "; ".join(record.partial_reasons))
                + "), so 'not affected' here is not a statement that nothing is affected.")
    unhashed = [i.item_id for i in manifest.uncomparable_items]
    if unhashed:
        skipped.append(
            "item(s) " + ", ".join(unhashed) + " carry no hash, so an affected "
            "component hiding in them would not be found.")

    return {
        "advisory_id": advisory.advisory_id,
        "issued_by": advisory.issued_by,
        "severity": advisory.severity.value,
        "reference": advisory.reference,
        "machine": manifest.machine.key,
        "affected": bool(matches),
        "matches": matches,
        "remedy": advisory.remedy,
        "checks_skipped": skipped,
        "provenance": advisory_provenance(advisory, BARE_REQUEST_BODY_PROVENANCE),
        "advisory_import": record.to_dict() if record is not None else None,
        "incomplete": bool(record is not None and record.partial),
    }
