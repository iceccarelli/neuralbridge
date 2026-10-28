"""CSAF 2.0 import: a faithful, conservative translation of third-party content.

The document below is SYNTHETIC. It mirrors the shape of real CSAF advisories (vendor ->
product_name -> product_version branches, product_status, remediations) but describes no real
product, vendor or vulnerability.
"""

from __future__ import annotations

import copy
import json

import pytest

from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.fleet.cli import main
from assurance.fleet.csaf import advisory_from_csaf
from assurance.machinery.manifest import HashSource, ItemKind, SafetyItem

VENDOR = "Example Controls GmbH"


def _leaf(pid, name):
    return {"category": "product_version", "name": name,
            "product": {"product_id": pid, "name": f"{pid} {name}"}}


def csaf():
    return copy.deepcopy({
        "document": {
            "csaf_version": "2.0", "category": "csaf_security_advisory",
            "title": "SYNTHETIC: Example module memory-safety issue",
            "publisher": {"name": VENDOR, "category": "vendor",
                          "namespace": "https://example.invalid"},
            "tracking": {"id": "EX-2026-001", "status": "final", "version": "1",
                         "initial_release_date": "2026-10-01T00:00:00Z",
                         "current_release_date": "2026-10-02T08:30:00+02:00"},
            "references": [{"category": "self", "url": "https://example.invalid/EX-2026-001",
                            "summary": "advisory"}],
            "notes": [{"category": "summary", "text": "A crafted packet halts the module."}],
        },
        "product_tree": {"branches": [{
            "category": "vendor", "name": VENDOR, "branches": [
                {"category": "product_name", "name": "EX-100", "branches": [
                    _leaf("P1", "V2.001"),
                    {"category": "product_version_range", "name": "vers:all/<V2.001",
                     "product": {"product_id": "P2", "name": "EX-100 range"}},
                    _leaf("P3", "V2.002"),
                ]},
                {"category": "product_name", "name": "EX-50", "branches": [
                    _leaf("P4", "V1.006"),
                ]},
            ]}]},
        "vulnerabilities": [{
            "cve": "CVE-2026-0001",
            "product_status": {"known_affected": ["P1", "P2", "P4"], "fixed": ["P3"],
                               "known_not_affected": ["P9"]},
            "remediations": [
                {"category": "vendor_fix", "details": "Update EX-100 to V2.002.",
                 "product_ids": ["P1"]},
                {"category": "mitigation", "details": "Block port 44818 at the cell firewall.",
                 "product_ids": ["P4"]},
            ],
        }],
    })


def item(name, version):
    return SafetyItem("I", ItemKind.FIRMWARE, name, version, "", HashSource.DECLARED,
                      supplier=VENDOR, implements=("SF-1",))


def imported(**kw):
    return advisory_from_csaf(csaf(), **kw)


def test_the_header_is_translated():
    a = imported().advisory
    assert (a.advisory_id, a.issued_by) == ("EX-2026-001", VENDOR)
    assert a.reference == "https://example.invalid/EX-2026-001"
    assert a.issued_at.isoformat() == "2026-10-02T06:30:00+00:00"  # offset normalised to UTC
    assert "CVE-2026-0001" in a.summary and "crafted packet" in a.summary


def test_it_is_labelled_unsigned_and_the_severity_is_stated_as_a_default():
    notes = " ".join(imported().notes)
    assert "unsigned" in notes and "inspection only" in notes
    assert "does not state whether the issue is safety-relevant" in notes
    assert imported().advisory.severity is AdvisorySeverity.SAFETY_RELEVANT
    explicit = imported(severity=AdvisorySeverity.INFORMATIONAL)
    assert explicit.advisory.severity is AdvisorySeverity.INFORMATIONAL
    assert "does not state whether" not in " ".join(explicit.notes)


def test_exact_versions_range_and_fixed_are_mapped_as_the_publisher_wrote_them():
    a = imported().advisory
    ex100 = next(x for x in a.affected if x.name == "EX-100")
    assert ex100.versions == ("V2.001", "vers:all/<V2.001")
    assert ex100.version_note == "vers:all/<V2.001"
    # Changed from `a.fixed_versions == ("V2.002",)`: that was the bug. A fixed version was
    # unioned across the whole advisory and used to clear a machine inside another
    # product's (or another CVE's) range. A fixed version is now kept per component, and a
    # component that has a range keeps none, because one fix is not the end of every range.
    assert a.fixed_versions == () and ex100.fixed_versions == ()


def test_matching_follows_the_publishers_facts():
    a = imported().advisory
    assert match_item(a, item("EX-100", "V2.001"))[0] is MatchBasis.VERSION
    assert match_item(a, item("EX-50", "V1.006"))[0] is MatchBasis.VERSION
    assert match_item(a, item("EX-999", "V2.001")) is None            # another product
    # Changed from `... "V2.002")) is None  # fixed`: EX-100 also carries a range, so its
    # fixed version clears nothing (see the test above); a person looks.
    assert match_item(a, item("EX-100", "V2.002"))[0] is MatchBasis.NAME_ONLY
    # Without a range, the component's own fixed version still clears.
    plain = csaf()
    plain["product_tree"]["branches"][0]["branches"][0]["branches"].pop(1)   # drop the range
    plain["vulnerabilities"][0]["product_status"]["known_affected"].remove("P2")
    assert match_item(advisory_from_csaf(plain).advisory, item("EX-100", "V2.002")) is None


def test_a_range_is_never_a_clear_for_a_version_the_matcher_cannot_place():
    found = match_item(imported().advisory, item("EX-100", "V1.500"))
    assert found is not None and found[0] is MatchBasis.NAME_ONLY and found[0].needs_a_human


def test_a_mitigation_is_not_presented_as_a_vendor_fix():
    a = imported().advisory
    assert a.remedy == "Update EX-100 to V2.002."
    assert "firewall" not in a.remedy and "44818" not in a.remedy
    doc = csaf()
    doc["vulnerabilities"][0]["remediations"] = [
        {"category": "mitigation", "details": "Block port 44818.", "product_ids": ["P4"]}]
    assert advisory_from_csaf(doc).advisory.remedy == ""


def test_known_not_affected_never_clears_anything():
    # Rewritten: the old assertion (a product the advisory never names reads None) passed
    # whether known_not_affected was honoured or ignored. Here P3 (EX-100 V2.002) appears
    # ONLY as known_not_affected. Honoured as "not affected" it would read None; ignored, a
    # machine on V2.002 is a label the advisory does not list, which is for a person.
    doc = csaf()
    doc["product_tree"]["branches"][0]["branches"][0]["branches"].pop(1)     # drop the range
    doc["vulnerabilities"][0]["product_status"] = {
        "known_affected": ["P1"], "known_not_affected": ["P3", "P4"]}
    a = advisory_from_csaf(doc).advisory
    assert a.fixed_versions == ()
    assert all(not x.fixed_versions for x in a.affected)
    found = match_item(a, item("EX-100", "V2.002"))
    assert found is not None and found[0] is MatchBasis.NAME_ONLY
    assert match_item(a, item("EX-50", "V1.006")) is None      # EX-50 is not in the advisory


def test_under_investigation_is_kept_as_affected_and_says_so():
    doc = csaf()
    doc["vulnerabilities"][0]["product_status"] = {"under_investigation": ["P4"]}
    a = advisory_from_csaf(doc).advisory
    assert a.affected[0].name == "EX-50" and "under investigation" in a.affected[0].version_note


def test_what_cannot_be_mapped_is_reported_not_dropped():
    doc = csaf()
    doc["vulnerabilities"][0]["product_status"]["known_affected"].append("P-MISSING")
    notes = " ".join(advisory_from_csaf(doc).notes)
    assert "P-MISSING" in notes


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["document"].update(csaf_version="2.1"), "csaf_version"),
    (lambda d: d["document"]["tracking"].pop("id"), "tracking id"),
    (lambda d: d["document"]["tracking"].update(current_release_date="2026-10-02T08:30:00"),
     "timezone"),
    (lambda d: d["document"]["publisher"].pop("name"), "publisher"),
    (lambda d: d["document"].pop("references"), "reference"),
    (lambda d: d.pop("vulnerabilities"), "no vulnerabilities"),
    (lambda d: d["vulnerabilities"][0]["product_status"].update(
        known_affected=["NOT-IN-TREE"]), "match nothing"),
])
def test_a_document_that_cannot_be_trusted_to_mean_something_is_refused(mutate, message):
    doc = csaf()
    mutate(doc)
    with pytest.raises(AdvisoryError, match=message):
        advisory_from_csaf(doc)


def test_not_a_csaf_document_is_refused():
    with pytest.raises(AdvisoryError):
        advisory_from_csaf({"hello": "world"})
    with pytest.raises(AdvisoryError):
        advisory_from_csaf([])  # type: ignore[arg-type]


def test_the_output_round_trips_through_the_advisory_format(tmp_path):
    out = tmp_path / "adv.json"
    src = tmp_path / "in.json"
    src.write_text(json.dumps(csaf()), encoding="utf-8")
    assert main(["import-csaf", str(src), "--out", str(out)]) == 0
    again = ComponentAdvisory.from_json(out)
    assert again.to_dict() == imported().advisory.to_dict()


def test_the_cli_prints_the_advisory_and_the_notes_separately(tmp_path, capsys):
    src = tmp_path / "in.json"
    src.write_text(json.dumps(csaf()), encoding="utf-8")
    assert main(["import-csaf", str(src)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["advisory_id"] == "EX-2026-001"
    assert "unsigned" in captured.err and "imported EX-2026-001" in captured.err


def test_the_cli_refuses_a_bad_document_with_exit_2(tmp_path, capsys):
    src = tmp_path / "bad.json"
    src.write_text(json.dumps({"document": {"csaf_version": "2.1"}}), encoding="utf-8")
    assert main(["import-csaf", str(src)]) == 2
    assert "csaf_version" in capsys.readouterr().err


def test_importing_is_a_translation_that_writes_no_ledger(tmp_path):
    """No ledger, no case, no decision: the only file created is the one asked for."""
    src = tmp_path / "in.json"
    src.write_text(json.dumps(csaf()), encoding="utf-8")
    main(["import-csaf", str(src), "--out", str(tmp_path / "o.json")])
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.json", "o.json"]
