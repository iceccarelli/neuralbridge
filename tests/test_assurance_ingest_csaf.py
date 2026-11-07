"""CSAF 2.0 import: a recorded, unsigned supplier advisory, and a result for every machine.

The result vocabulary is closed (affected, under_investigation, fixed, not_affected, unknown). An
uncertain product match stays ``unknown``: never upgraded to affected or not_affected by fuzzy
matching, and a version range is compared only when the version scheme is unambiguous. All
documents are SYNTHETIC (``examples/ingest/``).
"""

from __future__ import annotations

import copy
import hashlib
import sqlite3
from typing import Any

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory
from assurance.ingest import csaf
from assurance.ingest.common import IngestError, make_source
from assurance.machinery.manifest import HashSource, ManifestSource
from assurance.machinery.record import record_manifest

from .ingest_support import FW_SHA, PERSON, SERVICE, csaf_doc, enrol, item, manifest, raw

SOURCE_KW = {"name": "synthetic-advisory.csaf.json", "supplied_at": "2026-03-12T09:00:00Z",
             "url": "https://controlco.example/csaf/cc-syn-2026-0001.json"}
FW = "Safety controller firmware"


def do_import(ledger: EvidenceLedger | None, doc: Any, **kw: Any) -> dict[str, Any]:
    data = doc if isinstance(doc, bytes) else raw(doc)
    return csaf.import_csaf(ledger, data, source=make_source(data, **SOURCE_KW), actor=SERVICE, **kw)


def violations(doc: Any) -> list[str]:
    with pytest.raises(IngestError) as caught:
        do_import(None, doc, dry_run=True)
    assert caught.value.code in ("invalid_csaf", "too_deep", "too_large", "invalid_document"), \
        caught.value.code
    return list(caught.value.violations)


def refused_with(doc: Any, rule: str) -> None:
    found = violations(doc)
    assert any(v.startswith(rule) for v in found), (rule, found)


@pytest.fixture()
def ledger(tmp_path) -> EvidenceLedger:
    return EvidenceLedger(tmp_path / "ledger.db")


def product(doc: dict[str, Any], pid: str) -> dict[str, Any]:
    stack = list(doc["product_tree"]["branches"])
    while stack:
        node = stack.pop()
        if node.get("product", {}).get("product_id") == pid:
            return node
        stack.extend(node.get("branches", []))
    raise KeyError(pid)


def status(doc: dict[str, Any]) -> dict[str, list[str]]:
    return doc["vulnerabilities"][0]["product_status"]


# =============================================================================================
class TestTheRecordKeepsWhatWasSupplied:
    def test_the_identity_of_the_document_and_its_publisher(self, ledger):
        receipt = do_import(ledger, csaf_doc())
        assert receipt["status"] == "imported" and receipt["written"] is True
        body = ledger.entries()[0].evidence().body
        data = raw(csaf_doc())
        assert body["source"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert body["source"]["name_as_supplied"] == SOURCE_KW["name"]
        assert body["source"]["supplied_at_as_supplied"] == SOURCE_KW["supplied_at"]
        assert body["source"]["url_as_supplied"] == SOURCE_KW["url"]
        doc = body["document"]
        assert doc["publisher"] == {"category": "vendor", "name": "ControlCo (SYNTHETIC)",
                                    "namespace": "https://controlco.example"}
        assert doc["tracking"] == {
            "id": "CC-SYN-2026-0001", "version": "2", "status": "final",
            "initial_release_date": "2026-03-01T08:00:00Z",
            "current_release_date": "2026-03-12T08:00:00Z", "revisions": 2}
        assert doc["tlp_label"] == "WHITE" and doc["csaf_version"] == "2.0"
        assert doc["references"][0]["url"].endswith("CC-SYN-2026-0001")
        assert body["trust"] == "unsigned_inspect_only"

    def test_each_vulnerabilitys_product_status_is_kept_as_the_publisher_wrote_it(self, ledger):
        do_import(ledger, csaf_doc())
        vuln = ledger.entries()[0].evidence().body["vulnerabilities"][0]
        assert vuln["cve"] == "CVE-2026-0001"
        assert vuln["product_status"] == {
            "known_affected": ["CSAFPID-0001", "CSAFPID-0004", "CSAFPID-0006"],
            "fixed": ["CSAFPID-0002"], "known_not_affected": ["CSAFPID-0003", "CSAFPID-0005"]}

    def test_the_products_carry_their_stated_hashes_and_ranges(self, ledger):
        do_import(ledger, csaf_doc())
        products = ledger.entries()[0].evidence().body["products"]
        assert products["CSAFPID-0001"]["sha256"] == [FW_SHA]
        assert products["CSAFPID-0004"]["ranges"] == ["vers:semver/<3.6.0"]
        assert products["CSAFPID-0006"]["vendor"] == "Open Motion GmbH"

    def test_the_translation_to_the_existing_advisory_format_is_stored(self, ledger):
        do_import(ledger, csaf_doc())
        tr = ledger.entries()[0].evidence().body["translation"]
        assert tr["ok"] is True
        advisory = ComponentAdvisory.from_dict(tr["advisory"])
        assert advisory.advisory_id == "CC-SYN-2026-0001" and advisory.import_record is not None
        assert advisory.import_record.trust == "unsigned_inspect_only"

    def test_a_vex_with_nothing_affected_is_recorded_and_says_why_it_has_no_translation(
            self, ledger):
        doc = csaf_doc()
        doc["document"]["category"] = "csaf_vex"
        doc["vulnerabilities"][0]["product_status"] = {"known_not_affected": ["CSAFPID-0003"]}
        doc["vulnerabilities"][0].pop("remediations")
        do_import(ledger, doc)
        tr = ledger.entries()[0].evidence().body["translation"]
        assert tr["ok"] is False and "no affected product" in tr["reason"]

    def test_the_same_bytes_again_write_nothing(self, ledger):
        do_import(ledger, csaf_doc())
        again = do_import(ledger, csaf_doc())
        assert again["status"] == "already_imported" and again["written"] is False
        assert len(ledger) == 1

    def test_the_same_publisher_and_tracking_id_with_other_bytes_is_kept_and_flagged(
            self, ledger):
        first = do_import(ledger, csaf_doc())
        other = csaf_doc()
        other["document"]["title"] = "SYNTHETIC: a different revision"
        out = do_import(ledger, other)
        assert out["status"] == "imported"
        assert out["same_tracking_id_as"] == [first["advisory_ref"]]
        assert len(ledger) == 2

    def test_a_dry_run_writes_nothing(self, tmp_path):
        out = do_import(None, csaf_doc(), dry_run=True)
        assert out["status"] == "dry_run" and out["record"]["products"]
        assert not list(tmp_path.iterdir())

    def test_a_refusal_records_nothing(self, ledger):
        doc = csaf_doc()
        doc["document"]["csaf_version"] = "2.1"
        with pytest.raises(IngestError):
            do_import(ledger, doc)
        assert len(ledger) == 0

    def test_a_ledger_whose_chain_does_not_verify_takes_no_record(self, ledger):
        do_import(ledger, csaf_doc())
        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET link_hash = ? WHERE seq = 1", ("f" * 64,))
        db.commit()
        db.close()
        other = csaf_doc()
        other["document"]["title"] = "SYNTHETIC: another"
        with pytest.raises(IngestError) as caught:
            do_import(ledger, other)
        assert caught.value.code == "ledger_chain_unverified"

    def test_listing_and_showing(self, ledger):
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        rows = csaf.list_csaf_advisories(ledger)["advisories"]
        assert rows[0]["advisory_ref"] == ref and rows[0]["publisher_name"].startswith("ControlCo")
        assert csaf.get_csaf_advisory(ledger, ref)["record"]["advisory_ref"] == ref
        with pytest.raises(IngestError) as caught:
            csaf.get_csaf_advisory(ledger, "csaf-" + "0" * 32)
        assert caught.value.code == "advisory_not_found"


# =============================================================================================
class TestStructuralValidation:
    def test_the_example_breaks_no_rule(self):
        assert csaf.validate_csaf(csaf_doc()) == []

    @pytest.mark.parametrize("rule,mutate", [
        ("CSAF-R01", lambda d: d.pop("document")),
        ("CSAF-R02", lambda d: d["document"].update(csaf_version="2.1")),
        ("CSAF-R03", lambda d: d["document"].update(category="csaf_base")),
        ("CSAF-R03", lambda d: d["document"].update(category="")),
        ("CSAF-R04", lambda d: d["document"].pop("title")),
        ("CSAF-R05", lambda d: d["document"].pop("publisher")),
        ("CSAF-R05", lambda d: d["document"]["publisher"].update(category="company")),
        ("CSAF-R05", lambda d: d["document"]["publisher"].update(name="")),
        ("CSAF-R05", lambda d: d["document"]["publisher"].update(namespace="not a uri")),
        ("CSAF-R06", lambda d: d["document"].pop("tracking")),
        ("CSAF-R06", lambda d: d["document"]["tracking"].update(status="released")),
        ("CSAF-R06", lambda d: d["document"]["tracking"].update(version="v2")),
        ("CSAF-R06", lambda d: d["document"]["tracking"].update(
            current_release_date="2026-03-12T08:00:00")),
        ("CSAF-R06", lambda d: d["document"]["tracking"].update(
            initial_release_date="2027-01-01T00:00:00Z")),
        ("CSAF-R06", lambda d: d["document"]["tracking"].update(revision_history=[])),
        ("CSAF-R06", lambda d: d["document"]["tracking"].update(version="3")),
        ("CSAF-R06", lambda d: d["document"]["tracking"]["revision_history"][0].pop("summary")),
        ("CSAF-R07", lambda d: d.pop("product_tree")),
        ("CSAF-R07", lambda d: d.update(vulnerabilities=[])),
        ("CSAF-R08", lambda d: product(d, "CSAFPID-0001").update(category="nope")),
        ("CSAF-R08", lambda d: product(d, "CSAFPID-0001").update(branches=[{}])),
        ("CSAF-R08", lambda d: product(d, "CSAFPID-0001").pop("name")),
        ("CSAF-R08", lambda d: product(d, "CSAFPID-0001")["product"].pop("product_id")),
        ("CSAF-R09", lambda d: product(d, "CSAFPID-0002")["product"].update(
            product_id="CSAFPID-0001")),
        ("CSAF-R10", lambda d: d["vulnerabilities"][0].update(cve="CVE-26-1")),
        ("CSAF-R10", lambda d: status(d).update(probably_affected=["CSAFPID-0001"])),
        ("CSAF-R10", lambda d: status(d).update(fixed="CSAFPID-0002")),
        ("CSAF-R11", lambda d: status(d)["known_affected"].append("CSAFPID-9999")),
        ("CSAF-R11", lambda d: d["vulnerabilities"][0]["remediations"][0].update(
            product_ids=["CSAFPID-9999"])),
        ("CSAF-R12", lambda d: status(d)["known_not_affected"].append("CSAFPID-0001")),
        ("CSAF-R12", lambda d: status(d).update(under_investigation=["CSAFPID-0002"])),
        ("CSAF-R14", lambda d: d["document"].update(title="evil‮title")),
        ("CSAF-R14", lambda d: d["document"]["publisher"].update(name="Ctrl​Co")),
        ("CSAF-R14", lambda d: product(d, "CSAFPID-0001").update(name="3.8​.2")),
        ("CSAF-R14", lambda d: d["document"]["references"][0].update(url="https://x/\x1b[2J")),
    ])
    def test_each_rule_refuses_the_document_naming_itself(self, rule, mutate):
        doc = csaf_doc()
        mutate(doc)
        refused_with(doc, rule)

    def test_a_security_advisory_with_an_unsupported_category_is_named(self):
        doc = csaf_doc()
        doc["document"]["category"] = "csaf_informational_advisory"
        assert any("not supported" in v for v in violations(doc))

    def test_not_an_object_or_not_json(self):
        assert any(v.startswith("CSAF-R01") for v in violations(b"[]"))
        violations(b"{nope")
        violations(b"")

    def test_a_relationship_defined_product_is_a_valid_definition(self):
        doc = csaf_doc()
        doc["product_tree"]["full_product_names"] = [
            {"name": "ControlCo bundle", "product_id": "CSAFPID-0100"}]
        doc["product_tree"]["relationships"] = [{
            "category": "installed_on", "product_reference": "CSAFPID-0100",
            "relates_to_product_reference": "CSAFPID-0001",
            "full_product_name": {"name": "bundle on firmware", "product_id": "CSAFPID-0101"}}]
        status(doc)["known_affected"].append("CSAFPID-0101")
        assert csaf.validate_csaf(doc) == []

    def test_one_refusal_lists_every_violation(self):
        doc = csaf_doc()
        doc["document"]["csaf_version"] = "9"
        doc["document"]["title"] = ""
        status(doc)["known_affected"].append("CSAFPID-9999")
        assert len(violations(doc)) >= 3


class TestHostileInput:
    def test_a_document_over_the_size_limit_is_refused_unread(self):
        big = b" " * (8 * 1024 * 1024 + 1)
        with pytest.raises(IngestError) as caught:
            csaf.import_csaf(None, big, source=make_source(big), actor=SERVICE, dry_run=True)
        assert caught.value.code == "too_large"

    def test_json_nested_beyond_the_limit_is_refused_before_it_is_parsed(self):
        with pytest.raises(IngestError) as caught:
            do_import(None, b"[" * 3000 + b"]" * 3000, dry_run=True)
        assert caught.value.code == "too_deep"

    def test_a_product_tree_nested_beyond_64_levels_is_refused(self):
        leaf: dict[str, Any] = {"category": "product_version", "name": "1",
                                "product": {"name": "p", "product_id": "P-1"}}
        node = leaf
        for i in range(66):
            node = {"category": "product_family", "name": f"f{i}", "branches": [node]}
        doc = csaf_doc()
        doc["product_tree"] = {"branches": [node]}
        doc["vulnerabilities"][0]["product_status"] = {"known_affected": ["P-1"]}
        doc["vulnerabilities"][0].pop("remediations")
        refused_with(doc, "CSAF-R13")

    def test_more_products_than_the_limit_are_refused_never_truncated(self):
        doc = csaf_doc()
        doc["product_tree"]["full_product_names"] = [
            {"name": f"n{i}", "product_id": f"X-{i}"} for i in range(csaf.MAX_STORED_PRODUCTS + 1)]
        refused_with(doc, "CSAF-R13")

    def test_more_vulnerabilities_than_the_limit_are_refused(self):
        doc = csaf_doc()
        doc["vulnerabilities"] = [copy.deepcopy(doc["vulnerabilities"][0])
                                  for _ in range(csaf.MAX_VULNERABILITIES + 1)]
        refused_with(doc, "CSAF-R13")

    def test_a_repeated_json_key_is_refused(self):
        text = raw(csaf_doc()).decode().replace('"status": "final"',
                                                '"status": "final", "status": "draft"', 1)
        violations(text.encode())

    def test_nul_and_not_utf8_are_refused(self):
        violations(raw(csaf_doc()) + b"\x00")
        violations(b"\xff\xfe{}")

    def test_a_hostile_title_is_not_echoed_unescaped(self):
        doc = csaf_doc()
        doc["document"]["title"] = "\x1b[2Jowned"
        assert "\x1b" not in " ".join(violations(doc))

    def test_a_draft_document_is_refused_unless_asked_and_is_then_partial(self, ledger):
        doc = csaf_doc()
        doc["document"]["tracking"]["status"] = "draft"
        with pytest.raises(IngestError) as caught:
            do_import(ledger, doc)
        assert caught.value.code == "document_not_final"
        out = do_import(ledger, doc, allow_draft=True)
        assert out["partial"] is True and "not 'final'" in out["partial_reasons"][0]

    def test_a_status_naming_a_product_that_cannot_be_matched_makes_the_record_partial(
            self, ledger):
        doc = csaf_doc()
        doc["product_tree"]["full_product_names"] = [
            {"name": "only here", "product_id": "CSAFPID-0200"}]
        status(doc)["known_affected"].append("CSAFPID-0200")
        out = do_import(ledger, doc)
        assert out["partial"] is True and out["uninterpreted_products"] == 1


# =============================================================================================
class TestVersionsAreComparedOnlyWhenTheSchemeIsUnambiguous:
    @pytest.mark.parametrize("label,expected", [
        ("3.8.2", (3, 8, 2)), ("v3.8.2", (3, 8, 2)), ("V3.8", (3, 8)), ("3", (3,)),
        ("3.10.0.1", (3, 10, 0, 1)), (" 3.8.2 ", (3, 8, 2)),
        ("V2.001", None), ("2.001", None), ("3.8.2-rc1", None), ("3.8.2+b5", None),
        ("2.x", None), ("2.*", None), ("all", None), ("", None), ("1.2.3.4.5", None),
        ("1..2", None), ("1.", None), ("0x10", None), ("١٢٣", None)])
    def test_parse_version(self, label, expected):
        assert csaf.parse_version(label) == expected

    @pytest.mark.parametrize("version,text,expected", [
        ((3, 5, 1), "vers:semver/<3.6.0", True), ((3, 6, 0), "vers:semver/<3.6.0", False),
        ((3, 6), "<3.6.0", False), ((3, 5), "<=3.5.0", True),
        ((2, 5), "vers:semver/>=2.0.0|<3.0.0", True), ((3, 0), "vers:semver/>=2.0.0|<3.0.0", False),
        ((1, 9), ">=2.0|<3.0", False), ((3, 1, 0), "3.1.0", None),
        ((3, 0), "vers:semver/<1.0|>=2.0|<3.0", None), ((3, 0), "vers:semver/>=1.0|>=2.0", None),
        ((3, 0), "vers:semver/!=3.0", None), ((3, 0), "vers:generic/<4", None),
        ((3, 0), "vers:maven/<4", None), ((3, 0), "All versions < V3.1", None),
        ((3, 0), "<3.1-rc1", None), ((3, 0), "<", None), ((3, 0), "", None),
        ((3, 0), "vers:semver/*", None)])
    def test_range_evaluation(self, version, text, expected):
        assert csaf._in_range(version, text) is expected

    def test_equal_versions_pad_with_zeros(self):
        assert csaf._relation("3.1", {"version": "3.1.0"})[0] == "equal"

    def test_undetermined_is_never_equal_or_in_range(self):
        for label in ("V2.001", "3.8.2-rc1", "2.x"):
            assert csaf._relation(label, {"version": "3.8.2", "ranges": ["vers:semver/<4.0.0"]}
                                  )[0] == "undetermined"


# =============================================================================================
def states(impact: dict[str, Any]) -> dict[str, str]:
    return {m["machine"].rsplit("#", 1)[1]: m["state"] for m in impact["machines"]}


def reasons(impact: dict[str, Any], serial: str) -> list[str]:
    return next(m for m in impact["machines"] if m["machine"].endswith("#" + serial))[
        "reason_codes"]


@pytest.fixture()
def fleet(ledger):
    """A fleet that exercises every result, against the example advisory."""
    enrol(ledger, "AFF", item(FW, "3.8.2"))
    enrol(ledger, "FIX", item(FW, "3.9.0"))
    enrol(ledger, "NOT", item(FW, "3.7.0"))
    enrol(ledger, "RNG", item(FW, "3.5.1"))
    enrol(ledger, "GAP", item(FW, "3.6.5"))
    enrol(ledger, "RC1", item(FW, "3.8.2-rc1"))
    enrol(ledger, "SUP", item("libmotion", "1.4.0", supplier="OpenMotion"))
    enrol(ledger, "NOS", item("libmotion", "1.4.0", supplier=""))
    enrol(ledger, "SAM", item("libmotion", "1.4.0", supplier="Open Motion GmbH"))
    enrol(ledger, "GWY", item("Unrelated gateway", "1.0"))
    enrol(ledger, "OTH", item("Something else entirely", "7"))
    ref = do_import(ledger, csaf_doc())["advisory_ref"]
    return ledger, ref


class TestEveryMachineGetsOneOfFiveResults:
    def test_the_vocabulary_is_closed_and_each_example_gets_its_result(self, fleet):
        ledger, ref = fleet
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {
            "AFF": "affected", "FIX": "fixed", "NOT": "not_affected", "RNG": "affected",
            "GAP": "unknown", "RC1": "unknown", "SUP": "unknown", "NOS": "unknown",
            "SAM": "affected", "GWY": "not_affected", "OTH": "unknown"}
        assert {m["state"] for m in impact["machines"]} <= set(csaf.STATES)

    def test_the_reasons_for_unknown_are_stated(self, fleet):
        ledger, ref = fleet
        impact = csaf.csaf_impact(ledger, ref)
        assert reasons(impact, "GAP") == ["version_not_covered"]
        assert reasons(impact, "RC1") == ["version_scheme_ambiguous"]
        assert reasons(impact, "SUP") == ["supplier_differs"]
        assert reasons(impact, "NOS") == ["supplier_missing"]
        assert reasons(impact, "OTH") == ["not_named"]

    def test_a_machine_the_document_does_not_name_is_unknown_not_unaffected(self, fleet):
        ledger, ref = fleet
        impact = csaf.csaf_impact(ledger, ref)
        other = next(m for m in impact["machines"] if m["machine"].endswith("#OTH"))
        assert other["named_by_advisory"] is False and other["state"] == "unknown"
        assert impact["not_named"] == 1

    def test_an_affected_machine_makes_the_impact_not_a_clear_and_counts_add_up(self, fleet):
        ledger, ref = fleet
        impact = csaf.csaf_impact(ledger, ref)
        assert impact["counts"] == {"affected": 3, "under_investigation": 0, "unknown": 5,
                                    "fixed": 1, "not_affected": 2}
        assert sum(impact["counts"].values()) == impact["machines_in_fleet"] == 11
        assert impact["machines_affected"] == sorted(impact["machines_affected"])
        assert impact["complete"] is False

    def test_the_evidence_for_each_result_is_in_it(self, fleet):
        ledger, ref = fleet
        impact = csaf.csaf_impact(ledger, ref)
        aff = next(m for m in impact["machines"] if m["machine"].endswith("#AFF"))
        it = aff["items"][0]
        assert it["identity"] == ["certain:name_and_supplier"]
        assert it["matched_product_ids"] and it["vulnerabilities"][0]["vulnerability"] == \
            "CVE-2026-0001"
        assert "label decided" in it["item_hash_basis"]
        prov = impact["provenance"]
        assert prov["document_sha256"] == hashlib.sha256(raw(csaf_doc())).hexdigest()
        assert prov["publisher"]["namespace"] == "https://controlco.example"
        assert prov["tracking"]["version"] == "2" and prov["tracking"]["status"] == "final"
        assert prov["inspect_only"] is True and prov["automated_consequences_permitted"] is False
        assert prov["source_url_as_supplied"] == SOURCE_KW["url"]

    def test_the_impact_records_nothing_and_opens_no_case(self, fleet):
        ledger, ref = fleet
        before = len(ledger)
        csaf.csaf_impact(ledger, ref)
        assert len(ledger) == before
        assert not [e for e in ledger.entries() if e.kind.startswith("change.")]

    def test_the_label_of_a_declared_hash_item_decides_and_says_so(self, ledger):
        enrol(ledger, "DEC", item(FW, "3.8.2", content_hash=FW_SHA, source=HashSource.DECLARED))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        it = csaf.csaf_impact(ledger, ref)["machines"][0]["items"][0]
        assert it["state"] == "affected" and "label decided" in it["item_hash_basis"]
        assert it["identity"] == ["certain:name_and_supplier"]


class TestHashes:
    def fleet_with(self, ledger, serial, version, digest, source=HashSource.READ_FROM_MACHINE):
        enrol(ledger, serial, item(FW, version, content_hash=digest, source=source))

    def test_a_hash_read_off_the_unit_identifies_the_product_whatever_the_label(self, ledger):
        self.fleet_with(ledger, "HSH", "3.9.0", FW_SHA)
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"HSH": "unknown"}
        assert reasons(impact, "HSH") == ["hash_mismatch"]     # label says fixed; artefact says affected

    def test_a_matching_hash_and_label_is_affected_by_hash(self, ledger):
        self.fleet_with(ledger, "HOK", "3.8.2", FW_SHA)
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        it = csaf.csaf_impact(ledger, ref)["machines"][0]["items"][0]
        assert it["state"] == "affected" and "read_from_unit" in it["item_hash_basis"]
        assert "certain:hash_read_from_unit" in it["identity"]

    def test_a_different_hash_against_the_named_label_is_neither_affected_nor_clear(self, ledger):
        self.fleet_with(ledger, "HBD", "3.8.2", "ab" * 32)
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"HBD": "unknown"} and reasons(impact, "HBD") == ["hash_mismatch"]

    def test_a_hash_that_was_not_read_off_the_unit_is_not_compared(self, ledger):
        self.fleet_with(ledger, "VND", "3.8.2", "ab" * 32, HashSource.SUPPLIED_BY_VENDOR)
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"VND": "affected"}      # decided by the label, and says so
        assert "label decided" in impact["machines"][0]["items"][0]["item_hash_basis"]


class TestAnUncertainMatchIsNeverUpgraded:
    """The guards. Mutating any one of these away makes one of these tests fail."""

    def test_guard_a_supplier_that_differs_is_unknown_even_with_the_exact_version(self, ledger):
        enrol(ledger, "A", item("libmotion", "1.4.0", supplier="Open Motion"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        assert states(csaf.csaf_impact(ledger, ref)) == {"A": "unknown"}

    def test_guard_a_supplier_that_differs_is_not_cleared_by_a_not_affected_either(self, ledger):
        doc = csaf_doc()
        # the publisher says libmotion 1.4.0 from "Open Motion GmbH" is NOT affected
        status(doc)["known_affected"].remove("CSAFPID-0006")
        status(doc)["known_not_affected"].append("CSAFPID-0006")
        enrol(ledger, "B", item("libmotion", "1.4.0", supplier="OpenMotion"))
        ref = do_import(ledger, doc)["advisory_ref"]
        assert states(csaf.csaf_impact(ledger, ref)) == {"B": "unknown"}

    def test_guard_a_doubtful_affected_blocks_a_certain_not_affected(self, ledger):
        doc = csaf_doc()
        # a second vendor spelling lists the same component as affected
        doc["product_tree"]["branches"].append({
            "category": "vendor", "name": "ControlCo Ltd", "branches": [{
                "category": "product_name", "name": FW, "branches": [{
                    "category": "product_version", "name": "3.7.0",
                    "product": {"name": "x", "product_id": "CSAFPID-0300"}}]}]})
        status(doc)["known_affected"].append("CSAFPID-0300")
        enrol(ledger, "C", item(FW, "3.7.0"))
        ref = do_import(ledger, doc)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"C": "unknown"} and reasons(impact, "C") == ["supplier_differs"]

    def test_guard_a_version_the_publisher_does_not_name_is_not_not_affected(self, ledger):
        enrol(ledger, "D", item(FW, "3.6.5"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        assert states(csaf.csaf_impact(ledger, ref)) == {"D": "unknown"}

    def test_guard_a_range_is_not_applied_to_an_ambiguous_version(self, ledger):
        enrol(ledger, "E", item(FW, "V3.5.001"))          # leading zeros: 3.5.1 or 3.5.001?
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"E": "unknown"}
        assert reasons(impact, "E") == ["version_scheme_ambiguous"]

    def test_guard_a_range_text_that_is_not_interpreted_is_unknown(self, ledger):
        doc = csaf_doc()
        product(doc, "CSAFPID-0004")["name"] = "All versions < V3.6"
        product(doc, "CSAFPID-0004")["category"] = "product_version_range"
        enrol(ledger, "F", item(FW, "3.5.1"))
        ref = do_import(ledger, doc)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"F": "unknown"}
        assert reasons(impact, "F") == ["version_scheme_ambiguous"]

    def test_guard_an_item_with_no_version_is_unknown(self, ledger):
        enrol(ledger, "G", item(FW, ""))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"G": "unknown"} and reasons(impact, "G") == ["version_missing"]

    def test_guard_names_are_not_matched_fuzzily(self, ledger):
        for serial, name in (("H1", "Safety controller firmware v2"), ("H2", "Safety Controller"),
                             ("H3", "safety-controller-firmware")):
            enrol(ledger, serial, item(name, "3.8.2"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        assert set(states(csaf.csaf_impact(ledger, ref)).values()) == {"unknown"}
        assert all(r == ["not_named"] for r in (
            reasons(csaf.csaf_impact(ledger, ref), s) for s in ("H1", "H2", "H3")))

    def test_names_that_differ_only_by_case_or_width_do_match(self, ledger):
        enrol(ledger, "I", item("SAFETY CONTROLLER FIRMWARE", "3.8.2", supplier="ＣｏｎｔｒｏｌＣｏ"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        assert states(csaf.csaf_impact(ledger, ref)) == {"I": "affected"}

    def test_guard_not_named_is_never_counted_as_not_affected(self, ledger):
        enrol(ledger, "J", item("Other thing", "1.0"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert impact["counts"]["not_affected"] == 0 and impact["counts"]["unknown"] == 1

    def test_guard_a_vulnerability_that_does_not_mention_the_product_is_unknown(self, ledger):
        doc = csaf_doc()
        second = copy.deepcopy(doc["vulnerabilities"][0])
        second["cve"] = "CVE-2026-0002"
        second["product_status"] = {"known_affected": ["CSAFPID-0006"]}      # says nothing of 3.7.0
        second.pop("remediations")
        doc["vulnerabilities"].append(second)
        enrol(ledger, "K", item(FW, "3.7.0"))
        ref = do_import(ledger, doc)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"K": "unknown"}
        assert reasons(impact, "K") == ["not_addressed_by_vulnerability"]

    def test_contradictory_statements_about_one_item_are_unknown(self, ledger):
        doc = csaf_doc()
        status(doc)["known_not_affected"].append("CSAFPID-0004")     # range <3.6.0 now also "not affected"
        status(doc)["known_affected"].remove("CSAFPID-0004")
        status(doc)["known_affected"].append("CSAFPID-0300")
        doc["product_tree"]["branches"][0]["branches"][0]["branches"].append({
            "category": "product_version_range", "name": "vers:semver/<3.7.0",
            "product": {"name": "x", "product_id": "CSAFPID-0300"}})
        enrol(ledger, "L", item(FW, "3.5.1"))
        ref = do_import(ledger, doc)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"L": "unknown"} and reasons(impact, "L") == ["status_conflict"]


class TestUnderInvestigationAndFixed:
    def test_under_investigation_is_its_own_result(self, ledger):
        doc = csaf_doc()
        status(doc)["known_affected"].remove("CSAFPID-0001")
        status(doc)["under_investigation"] = ["CSAFPID-0001"]
        enrol(ledger, "U", item(FW, "3.8.2"))
        ref = do_import(ledger, doc)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"U": "under_investigation"}
        assert impact["complete"] is False

    def test_first_and_last_affected_count_as_affected_and_first_fixed_as_fixed(self, ledger):
        doc = csaf_doc()
        status(doc)["known_affected"].remove("CSAFPID-0001")
        status(doc)["first_affected"] = ["CSAFPID-0001"]
        status(doc)["fixed"].remove("CSAFPID-0002")
        status(doc)["first_fixed"] = ["CSAFPID-0002"]
        enrol(ledger, "P", item(FW, "3.8.2"))
        enrol(ledger, "Q", item(FW, "3.9.0"))
        ref = do_import(ledger, doc)["advisory_ref"]
        assert states(csaf.csaf_impact(ledger, ref)) == {"P": "affected", "Q": "fixed"}

    def test_a_worse_item_decides_the_machine(self, ledger):
        enrol(ledger, "R", item("libmotion", "1.4.0", supplier="Open Motion GmbH",
                                item_id="I1"), item(FW, "3.9.0", item_id="I2"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"R": "affected"}
        assert {i["item_id"]: i["state"] for i in impact["machines"][0]["items"]} == {
            "I1": "affected", "I2": "fixed"}


class TestFixedAndNotAffectedAreWithheldWhenTheBasisIsWeak:
    def test_guard_a_draft_document_states_no_fixed_or_not_affected(self, ledger):
        doc = csaf_doc()
        doc["document"]["tracking"]["status"] = "interim"
        enrol(ledger, "S1", item(FW, "3.9.0"))
        enrol(ledger, "S2", item(FW, "3.7.0"))
        enrol(ledger, "S3", item(FW, "3.8.2"))
        ref = do_import(ledger, doc, allow_draft=True)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"S1": "unknown", "S2": "unknown", "S3": "affected"}
        assert reasons(impact, "S1") == ["document_not_final"]
        assert impact["complete"] is False

    def test_guard_a_ledger_whose_chain_does_not_verify_withholds_them(self, ledger):
        enrol(ledger, "T1", item(FW, "3.9.0"))
        enrol(ledger, "T2", item(FW, "3.8.2"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET link_hash = ? WHERE seq = 1", ("f" * 64,))
        db.commit()
        db.close()
        impact = csaf.csaf_impact(ledger, ref)
        assert impact["ledger_chain_verified"] is False
        assert states(impact)["T1"] == "unknown"
        assert reasons(impact, "T1") == ["ledger_chain_unverified"]
        assert impact["complete"] is False
        assert "DOES NOT VERIFY" in impact["does_not_establish"][0]

    def test_guard_a_machine_last_looked_at_incompletely_is_not_cleared(self, ledger):
        key = enrol(ledger, "V1", item(FW, "3.9.0"))
        partial = manifest(
            "V1", item(FW, "3.9.0"), source=ManifestSource.AS_FOUND, manifest_id="LOOK-2",
            notes="[collection incomplete: other-item not collected]")
        record_manifest(ledger, partial, actor=PERSON)
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"V1": "unknown"} and key.endswith("#V1")
        assert reasons(impact, "V1") == ["look_incomplete"]

    def test_a_partial_advisory_is_never_a_clear(self, ledger):
        doc = csaf_doc()
        doc["product_tree"]["full_product_names"] = [{"name": "x", "product_id": "CSAFPID-0200"}]
        status(doc)["known_affected"].append("CSAFPID-0200")
        enrol(ledger, "W", item(FW, "3.9.0"))
        ref = do_import(ledger, doc)["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"W": "fixed"} and impact["complete"] is False
        assert "PARTIAL" in impact["does_not_establish"][0]

    def test_an_empty_fleet_is_not_a_clear(self, ledger):
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert impact["machines_in_fleet"] == 0 and impact["complete"] is False
        assert "no machine is enrolled" in impact["does_not_establish"][0]

    def test_every_machine_fixed_or_not_named_is_the_only_complete_answer(self, ledger):
        enrol(ledger, "X1", item(FW, "3.9.0"))
        enrol(ledger, "X2", item("Other thing", "1.0"))
        ref = do_import(ledger, csaf_doc())["advisory_ref"]
        impact = csaf.csaf_impact(ledger, ref)
        assert states(impact) == {"X1": "fixed", "X2": "unknown"} and impact["complete"] is True

    def test_an_unknown_advisory_ref(self, ledger):
        with pytest.raises(IngestError) as caught:
            csaf.csaf_impact(ledger, "csaf-" + "0" * 32)
        assert caught.value.code == "advisory_not_found"


class TestNothingIsAuthenticated:
    def test_the_record_and_the_impact_say_unsigned_and_inspect_only(self, ledger):
        enrol(ledger, "Y", item(FW, "3.8.2"))
        out = do_import(ledger, csaf_doc())
        assert out["trust"] == "unsigned_inspect_only"
        impact = csaf.csaf_impact(ledger, out["advisory_ref"])
        assert any("unsigned third-party content" in n for n in impact["does_not_establish"])
        assert Actor("x").kind == "person"          # (the import actor is a service, not a person)
        assert ledger.entries()[-1].actor == "assurance-ingest"


def test_guard_nothing_to_go_on_is_unknown_never_not_affected():
    assert csaf._resolve([]) == ("unknown", "version_not_covered")
    assert csaf._resolve([("p", "unknown", "", True, "not_affected", False)])[0] == "unknown"
