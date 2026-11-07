"""CycloneDX SBOM import: a DRAFT that invents nothing, and a review only a named person makes.

All documents are SYNTHETIC (``examples/ingest/``). Every refusal and every hostile-input case has
a test here; the guards that matter most are named in ``TestTheGuardsTheDraftDependsOn`` so a
mutation of any one of them fails something.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.ingest import sbom, sbom_store
from assurance.ingest.common import IngestError, make_source
from assurance.machinery.enrol import EnrolmentError
from assurance.machinery.manifest import HashSource
from assurance.machinery.record import manifests_from_ledger

from .ingest_support import FW_SHA, PERSON, SERVICE, approve, raw, sbom_doc, spec

SOURCE_KW = {"name": "synthetic-sbom.cdx.json", "supplied_at": "2026-03-01T08:30:00Z",
             "url": "https://sbom.example/ar7"}


def parse(doc: Any, **kw: Any) -> sbom.SbomDraft:
    data = doc if isinstance(doc, bytes) else raw(doc)
    return sbom.parse_cyclonedx(data, source=make_source(data, **kw))


def refused(doc: Any, code: str | None = None) -> IngestError:
    with pytest.raises(IngestError) as caught:
        parse(doc)
    if code:
        assert caught.value.code == code, (caught.value.code, caught.value.violations)
    return caught.value


@pytest.fixture()
def ledger(tmp_path) -> EvidenceLedger:
    return EvidenceLedger(tmp_path / "ledger.db")


@pytest.fixture()
def imported(ledger):
    data = raw(sbom_doc())
    receipt = sbom_store.import_sbom(ledger, data, source=make_source(data, **SOURCE_KW),
                                     actor=SERVICE)
    return receipt


def template(ledger, draft_id: str) -> dict[str, Any]:
    return sbom_store.get_sbom_draft(ledger, draft_id)["review_template"]


# =============================================================================================
class TestWhatIsRecordedExactlyAsSupplied:
    def test_the_sha256_is_of_the_bytes_received_and_the_labels_are_as_supplied(self):
        data = raw(sbom_doc())
        draft = parse(data, **SOURCE_KW)
        src = draft.body["source"]
        assert src["sha256"] == hashlib.sha256(data).hexdigest() == draft.source.sha256
        assert src["size_bytes"] == len(data)
        assert src["name_as_supplied"] == "synthetic-sbom.cdx.json"
        assert src["supplied_at_as_supplied"] == "2026-03-01T08:30:00Z"
        assert src["url_as_supplied"] == "https://sbom.example/ar7"
        assert src["supplied_fields_verified"] is False

    def test_the_bom_header_is_recorded_as_supplied(self):
        bom = parse(sbom_doc()).body["bom"]
        assert bom["spec_version"] == "1.5"
        assert bom["serial_number_as_supplied"] == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        assert bom["metadata_timestamp_as_supplied"] == "2026-03-01T08:30:00Z"
        assert bom["subject_component"]["name"].startswith("AR-7 Palletising Cell")

    def test_components_are_recorded_with_their_paths_and_supplied_fields(self):
        fw = parse(sbom_doc()).components[0]
        assert (fw["path"], fw["type"], fw["name"], fw["version"]) == (
            "$.components[0]", "firmware", "Safety controller firmware", "3.8.2")
        assert fw["bom_ref"] == "fw-safety-controller" and fw["supplier"] == "ControlCo"
        assert fw["purl"].startswith("pkg:generic/controlco/")
        assert fw["hashes_as_supplied"] == [{"alg": "SHA-256", "content": FW_SHA}]

    def test_the_same_bytes_give_the_same_draft_id(self):
        data = raw(sbom_doc())
        assert parse(data).draft_id == parse(data).draft_id == sbom.draft_id_for(
            hashlib.sha256(data).hexdigest())


# =============================================================================================
class TestTheDraftNeverInventsAnything:
    """NEVER invent the serial; NEVER mark safety-relevant; NEVER mark measured."""

    def test_there_is_no_machine_serial_only_candidates_for_the_rest(self):
        ident = parse(sbom_doc()).body["proposed_identity"]
        assert ident["serial"] == []
        assert ident["manufacturer"] == [{"value": "DemoCo", "from": "metadata.component.supplier"}]
        assert ident["model"] == [{"value": "AR-7 Palletising Cell (SYNTHETIC DEMO)",
                                   "from": "metadata.component.name"}]
        assert "never taken from an SBOM" in ident["note"]

    def test_the_boms_serial_number_is_not_offered_as_the_machine_serial(self):
        text = json.dumps(parse(sbom_doc()).body["proposed_identity"])
        assert "3e671687" not in text

    def test_no_component_is_safety_relevant_whatever_it_is_called(self):
        doc = sbom_doc()
        doc["components"][0]["name"] = "Safety PLC safety function monitor"
        doc["components"][0]["properties"] = [{"name": "safety-relevant", "value": "true"}]
        for comp in parse(doc).components:
            assert comp["safety_relevance"] == "not_assessed"
            assert comp["implements"] == []
            assert comp["review"] == "pending_review"

    def test_no_component_is_ever_read_from_the_machine_even_with_a_sha256(self):
        draft = parse(sbom_doc())
        assert draft.components[0]["sha256"] == FW_SHA
        for comp in draft.components:
            assert comp["hash_source_if_enrolled"] == "declared"
            assert comp["provenance_class"] == "declared_in_sbom"
            assert "read_from_machine" not in json.dumps(comp)

    def test_every_decision_is_pending_review_and_the_draft_says_so(self):
        body = parse(sbom_doc()).body
        assert body["review_state"] == "pending_review"
        assert any("serial" in d for d in body["decisions_required"])
        assert any("NOT ASSESSED" in n for n in body["does_not_establish"])

    def test_the_kind_is_a_proposal_only_where_the_vocabulary_has_a_word_for_it(self):
        kinds = {c["name"]: c["kind_proposal"] for c in parse(sbom_doc()).components}
        assert kinds == {"Safety controller firmware": "firmware", "libmotion": "library",
                         "operator-hmi": None, "rt-linux": None}


# =============================================================================================
class TestMissingDataIsUnknownNeverGuessed:
    def comp(self, **fields: Any) -> dict[str, Any]:
        doc = sbom_doc()
        doc["components"] = [{"type": "library", "name": "thing", **fields}]
        return parse(doc).components[0]

    def test_a_missing_version_is_null_and_not_taken_from_the_purl(self):
        c = self.comp(purl="pkg:generic/x/thing@9.9.9")
        assert c["version"] is None and "version" in c["unknown"]

    def test_a_missing_purl_is_null_and_not_built_from_the_name(self):
        c = self.comp(version="1.0")
        assert c["purl"] is None and "purl" in c["unknown"]

    def test_a_group_or_publisher_is_not_a_supplier(self):
        c = self.comp(group="org.example", publisher="Example Publisher", version="1.0")
        assert c["supplier"] is None and "supplier" in c["unknown"]
        assert c["group"] == "org.example" and c["publisher"] == "Example Publisher"

    def test_a_missing_hash_is_unknown(self):
        c = self.comp(version="1.0")
        assert c["sha256"] is None and "sha256" in c["unknown"]

    def test_two_different_sha256_values_are_ambiguous_and_neither_is_used(self):
        c = self.comp(version="1.0", hashes=[{"alg": "SHA-256", "content": "a" * 64},
                                             {"alg": "SHA-256", "content": "b" * 64}])
        assert c["sha256"] is None and c["sha256_ambiguous"] is True

    def test_a_64_hex_digest_of_another_algorithm_is_not_a_sha256(self):
        c = self.comp(version="1.0", hashes=[{"alg": "BLAKE2b-256", "content": "c" * 64}])
        assert c["sha256"] is None
        assert c["hashes_as_supplied"] == [{"alg": "BLAKE2b-256", "content": "c" * 64}]

    def test_an_empty_version_string_is_unknown(self):
        assert self.comp(version="  ")["version"] is None

    def test_a_malformed_purl_is_kept_as_supplied_and_flagged_never_used(self):
        c = self.comp(version="1.0", purl="not-a-purl")
        assert c["purl"] == "not-a-purl" and c["purl_well_formed"] is False

    def test_the_counts_and_warnings_say_what_is_unknown(self):
        body = parse(sbom_doc()).body
        assert body["counts"]["without_version"] == 1 and body["counts"]["without_sha256"] == 3
        assert any("no version" in w for w in body["warnings"])


# =============================================================================================
class TestSpecVersions:
    @pytest.mark.parametrize("version", ["1.4", "1.5", "1.6"])
    def test_the_supported_versions_are_read(self, version):
        assert parse(spec(sbom_doc(), version)).body["bom"]["spec_version"] == version

    @pytest.mark.parametrize("version", ["1.3", "1.7", "2.0", "", "1.5.0", 1.5, None])
    def test_any_other_version_is_refused_not_read_as_the_nearest(self, version):
        doc = sbom_doc()
        doc["specVersion"] = version
        refused(doc, "unsupported_spec_version")

    def test_a_missing_spec_version_is_refused(self):
        doc = sbom_doc()
        del doc["specVersion"]
        refused(doc, "unsupported_spec_version")

    def test_a_component_type_must_belong_to_the_declared_version(self):
        doc = sbom_doc()
        doc["components"] = [{"type": "platform", "name": "p", "version": "1"}]
        refused(spec(doc, "1.4"), "invalid_sbom")
        assert parse(spec(doc, "1.5")).components[0]["type"] == "platform"
        doc["components"] = [{"type": "cryptographic-asset", "name": "k", "version": "1"}]
        refused(spec(doc, "1.5"), "invalid_sbom")
        assert parse(spec(doc, "1.6")).components[0]["type"] == "cryptographic-asset"

    def test_the_unknown_type_is_refused_with_the_rule_and_path(self):
        doc = sbom_doc()
        doc["components"][1]["type"] = "gizmo"
        err = refused(doc, "invalid_sbom")
        assert any(v.startswith("SBOM-R08 at $.components[1]") for v in err.violations)


# =============================================================================================
class TestStructuralRules:
    def test_each_rule_names_itself_and_where(self):
        cases = [
            ("SBOM-R02", lambda d: d.update(bomFormat="SPDX")),
            ("SBOM-R04", lambda d: d.update(serialNumber="3e671687")),
            ("SBOM-R05", lambda d: d.update(version=0)),
            ("SBOM-R05", lambda d: d.update(version=True)),
            ("SBOM-R06", lambda d: d["metadata"].update(timestamp="2026-03-01 08:30")),
            ("SBOM-R06", lambda d: d.update(metadata=[])),
            ("SBOM-R07", lambda d: d.update(components={"a": 1})),
            ("SBOM-R07", lambda d: d["components"].append("a string")),
            ("SBOM-R08", lambda d: d["components"][0].pop("type")),
            ("SBOM-R09", lambda d: d["components"][0].pop("name")),
            ("SBOM-R09", lambda d: d["components"][0].update(name="   ")),
            ("SBOM-R10", lambda d: d["components"][0].update(version=3)),
            ("SBOM-R10", lambda d: d["components"][0].update(scope="sometimes")),
            ("SBOM-R11", lambda d: d["components"][0].update(**{"bom-ref": ""})),
            ("SBOM-R12", lambda d: d["components"][0].update(hashes="abc")),
            ("SBOM-R12", lambda d: d["components"][0].update(
                hashes=[{"alg": "SHA-256", "content": "ab" * 31}])),
            ("SBOM-R12", lambda d: d["components"][0].update(
                hashes=[{"alg": "SHA-256", "content": "z" * 64}])),
            ("SBOM-R12", lambda d: d["components"][0].update(
                hashes=[{"alg": "ROT13", "content": "a" * 64}])),
            ("SBOM-R13", lambda d: d["components"][0].update(supplier="ControlCo")),
            ("SBOM-R13", lambda d: d["components"][0].update(supplier={"name": 5})),
        ]
        for rule, mutate in cases:
            doc = sbom_doc()
            mutate(doc)
            err = refused(doc, "invalid_sbom")
            assert any(v.startswith(rule) for v in err.violations), (rule, err.violations)

    def test_one_refusal_lists_every_rule_broken_so_the_source_can_be_fixed(self):
        doc = sbom_doc()
        doc["bomFormat"] = "x"
        doc["components"][0]["version"] = 1
        doc["components"][1].pop("name")
        assert len(refused(doc).violations) >= 3

    def test_the_document_must_be_an_object(self):
        refused(b"[]", "invalid_sbom")
        refused(b'"CycloneDX"', "invalid_sbom")

    def test_no_components_is_refused_an_empty_inventory_asserts_nothing_is_installed(self):
        doc = sbom_doc()
        doc["components"] = []
        refused(doc, "no_components")
        del doc["components"]
        refused(doc, "no_components")

    def test_unknown_fields_are_listed_not_refused(self):
        doc = sbom_doc()
        doc["x-vendor-extension"] = {"a": 1}
        doc["components"][0]["x-note"] = "hello"
        listed = parse(doc).body["unrecognised_fields"]
        assert "$.components[0].x-note" in listed

    def test_nested_components_are_read_with_their_paths(self):
        doc = sbom_doc()
        doc["components"][1]["components"] = [{"type": "library", "name": "inner", "version": "2"}]
        names = {c["path"]: c["name"] for c in parse(doc).components}
        assert names["$.components[1].components[0]"] == "inner"


# =============================================================================================
class TestDuplicateBomRefs:
    def test_two_components_with_one_bom_ref_are_refused(self):
        doc = sbom_doc()
        doc["components"][1]["bom-ref"] = doc["components"][0]["bom-ref"]
        err = refused(doc, "invalid_sbom")
        assert any("SBOM-R11" in v and "duplicates the bom-ref" in v for v in err.violations)

    def test_a_nested_component_cannot_reuse_a_top_level_ref(self):
        doc = sbom_doc()
        doc["components"][1]["components"] = [
            {"type": "library", "name": "inner", "bom-ref": "fw-safety-controller"}]
        refused(doc, "invalid_sbom")

    def test_the_subject_component_cannot_reuse_a_ref(self):
        doc = sbom_doc()
        doc["metadata"]["component"]["bom-ref"] = "fw-safety-controller"
        refused(doc, "invalid_sbom")

    def test_a_service_cannot_reuse_a_component_ref(self):
        doc = sbom_doc()
        doc["services"] = [{"name": "svc", "bom-ref": "lib-motion"}]
        refused(doc, "invalid_sbom")


# =============================================================================================
class TestHostileInput:
    def test_a_document_over_the_size_limit_is_refused_unread(self):
        big = b" " * (8 * 1024 * 1024 + 1)
        with pytest.raises(IngestError) as caught:
            sbom.parse_cyclonedx(big, source=make_source(big))
        assert caught.value.code == "too_large"

    def test_json_nested_too_deep_is_refused_before_it_is_parsed(self):
        deep = b"[" * 5000 + b"]" * 5000
        refused(deep, "too_deep")
        refused(b'{"a":' * 60 + b"1" + b"}" * 60, "too_deep")

    def test_brackets_inside_strings_do_not_count_as_nesting(self):
        doc = sbom_doc()
        doc["components"][0]["description"] = "[" * 500 + "{" * 500
        assert parse(doc).components

    def test_component_nesting_beyond_the_limit_is_refused(self):
        node: dict[str, Any] = {"type": "library", "name": "leaf", "version": "1"}
        for i in range(sbom.MAX_COMPONENT_NESTING + 1):
            node = {"type": "library", "name": f"n{i}", "version": "1", "components": [node]}
        doc = sbom_doc()
        doc["components"] = [node]
        err = refused(doc, "invalid_sbom")
        assert any("SBOM-R14" in v for v in err.violations)

    def test_too_many_components_are_refused_never_truncated(self):
        doc = sbom_doc()
        doc["components"] = [{"type": "library", "name": f"c{i}", "version": "1"}
                             for i in range(sbom.MAX_COMPONENTS + 1)]
        err = refused(doc, "invalid_sbom")
        assert any("SBOM-R14" in v and "refused rather than truncated" in v
                   for v in err.violations)

    def test_exactly_the_maximum_is_accepted(self):
        doc = sbom_doc()
        doc["components"] = [{"type": "library", "name": f"c{i}", "version": "1"}
                             for i in range(sbom.MAX_COMPONENTS)]
        assert len(parse(doc).components) == sbom.MAX_COMPONENTS

    def test_a_repeated_key_inside_one_object_is_refused(self):
        text = raw(sbom_doc()).decode().replace('"specVersion": "1.5"',
                                                '"specVersion": "1.5", "specVersion": "1.4"')
        refused(text.encode(), "invalid_document")

    @pytest.mark.parametrize("payload", [b'{"bomFormat": NaN}', b'{"version": Infinity}',
                                         b'{"a": -Infinity}'])
    def test_nan_and_infinity_are_not_json(self, payload):
        refused(payload, "invalid_document")

    def test_a_nul_byte_not_utf8_empty_and_not_json_are_refused(self):
        refused(raw(sbom_doc()) + b"\x00", "invalid_document")
        refused(b"\xff\xfe\x00{", "invalid_document")
        refused(b"   ", "invalid_document")
        refused(b"{not json", "invalid_document")

    def test_a_utf8_bom_is_tolerated_and_the_hash_is_of_the_bytes_as_received(self):
        data = b"\xef\xbb\xbf" + raw(sbom_doc())
        draft = parse(data)
        assert draft.source.sha256 == hashlib.sha256(data).hexdigest()

    def test_invisible_and_control_characters_in_a_text_field_are_refused(self):
        for bad in ("evil‮name", "zero​width", "line\nbreak", "esc\x1b[2J"):
            doc = sbom_doc()
            doc["components"][0]["name"] = bad
            err = refused(doc, "invalid_sbom")
            assert any("SBOM-R15" in v for v in err.violations), bad

    def test_an_overlong_text_field_is_refused(self):
        doc = sbom_doc()
        doc["components"][0]["name"] = "x" * 501
        err = refused(doc, "invalid_sbom")
        assert any("SBOM-R15" in v for v in err.violations)

    def test_a_hostile_value_is_not_echoed_unescaped_in_the_refusal(self):
        doc = sbom_doc()
        doc["bomFormat"] = "\x1b[2Jowned"
        err = refused(doc, "invalid_sbom")
        assert "\x1b" not in " ".join(err.violations)

    def test_formula_like_text_is_kept_as_text(self):
        doc = sbom_doc()
        doc["components"][0]["name"] = "=cmd|'/c calc'!A1"
        assert parse(doc).components[0]["name"] == "=cmd|'/c calc'!A1"


# =============================================================================================
class TestTheSourceRecord:
    def test_a_stated_sha256_that_differs_from_the_bytes_is_refused(self):
        data = raw(sbom_doc())
        with pytest.raises(IngestError) as caught:
            make_source(data, claimed_sha256="0" * 64)
        assert caught.value.code == "source_hash_mismatch"

    def test_a_stated_sha256_that_matches_is_accepted_in_any_case(self):
        data = raw(sbom_doc())
        make_source(data, claimed_sha256=hashlib.sha256(data).hexdigest().upper())

    @pytest.mark.parametrize("kw", [
        {"supplied_at": "yesterday"}, {"supplied_at": "2026-03-01T08:30:00"},
        {"url": "ftp://x/y"}, {"url": "javascript:alert(1)"}, {"name": "a\x1bb"},
        {"name": "x" * 301}, {"claimed_sha256": "xyz"}])
    def test_a_bad_label_is_refused_not_repaired(self, kw):
        with pytest.raises(IngestError) as caught:
            make_source(b"{}", **kw)
        assert caught.value.code in ("invalid_source",)


# =============================================================================================
class TestRecordingTheDraft:
    def test_import_writes_one_unverified_draft_and_nothing_else(self, ledger, imported):
        assert imported["status"] == "imported" and imported["written"] is True
        assert imported["review_state"] == "pending_review"
        entries = ledger.entries()
        assert [e.kind for e in entries] == ["ingest.sbom_draft"]
        evidence = entries[0].evidence()
        assert evidence.validation_state.value == "unverified"
        assert evidence.confidence.value == "low"
        assert evidence.verify()

    def test_the_draft_is_not_a_manifest_and_enrols_nothing(self, ledger, imported):
        assert len(Fleet.from_ledger(ledger)) == 0
        assert manifests_from_ledger(ledger, "DemoCo/AR-7#DEMO-0001") == []

    def test_the_same_bytes_again_write_nothing(self, ledger, imported):
        data = raw(sbom_doc())
        again = sbom_store.import_sbom(ledger, data, source=make_source(data), actor=SERVICE)
        assert again["status"] == "already_imported" and again["written"] is False
        assert len(ledger) == 1

    def test_a_dry_run_writes_nothing_and_needs_no_ledger(self, tmp_path):
        data = raw(sbom_doc())
        out = sbom_store.import_sbom(None, data, source=make_source(data), actor=SERVICE,
                                     dry_run=True)
        assert out["status"] == "dry_run" and out["written"] is False
        assert out["draft"]["components"]
        assert not list(tmp_path.iterdir())

    def test_a_real_import_needs_a_ledger(self):
        data = raw(sbom_doc())
        with pytest.raises(IngestError):
            sbom_store.import_sbom(None, data, source=make_source(data), actor=SERVICE)

    def test_a_refused_document_records_nothing(self, ledger):
        doc = sbom_doc()
        doc["bomFormat"] = "x"
        with pytest.raises(IngestError):
            sbom_store.import_sbom(ledger, raw(doc), source=make_source(raw(doc)), actor=SERVICE)
        assert len(ledger) == 0

    def test_a_ledger_whose_chain_does_not_verify_takes_no_draft(self, ledger, imported):
        import sqlite3

        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET link_hash = ? WHERE seq = 1", ("f" * 64,))
        db.commit()
        db.close()
        doc = sbom_doc()
        doc["components"][0]["version"] = "9.9.9"
        data = raw(doc)
        with pytest.raises(IngestError) as caught:
            sbom_store.import_sbom(ledger, data, source=make_source(data), actor=SERVICE)
        assert caught.value.code == "ledger_chain_unverified"

    def test_listing_shows_the_state_and_a_damaged_draft_is_not_listed_as_a_draft(self, ledger,
                                                                                 imported):
        listed = sbom_store.list_sbom_drafts(ledger)
        assert [d["review_state"] for d in listed["drafts"]] == ["pending_review"]
        assert listed["drafts"][0]["source_name"] == "synthetic-sbom.cdx.json"

    def test_an_unknown_draft_is_not_found(self, ledger):
        with pytest.raises(IngestError) as caught:
            sbom_store.get_sbom_draft(ledger, "sbom-" + "0" * 32)
        assert caught.value.code == "draft_not_found"


# =============================================================================================
class TestTheReviewIsAHumanActAndDefaultsNothing:
    def review(self, ledger, imported, mutate=None, reviewer: Actor | None = PERSON):
        req = approve(template(ledger, imported["draft_id"]))
        if mutate:
            mutate(req)
        return sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=reviewer)

    def violations(self, ledger, imported, mutate) -> tuple[str, ...]:
        with pytest.raises(IngestError) as caught:
            self.review(ledger, imported, mutate)
        assert caught.value.code == "invalid_review"
        assert len(ledger) == 1, "a refused review must record nothing"
        return caught.value.violations

    def test_approval_enrols_through_the_front_door_with_declared_items_only(self, ledger,
                                                                            imported):
        out = self.review(ledger, imported)
        assert out["status"] == "approved" and out["machine"] == "DemoCo/AR-7#DEMO-0001"
        assert out["enrolment"]["status"] == "enrolled"
        manifest = manifests_from_ledger(ledger, out["machine"])[0]
        assert {i.name for i in manifest.items} == {"Safety controller firmware", "libmotion"}
        assert all(i.hash_source is HashSource.DECLARED for i in manifest.items)
        assert out["tier_ceiling"] == "profile"
        fw = next(i for i in manifest.items if i.name.startswith("Safety"))
        assert fw.content_hash == FW_SHA and fw.hash_source is HashSource.DECLARED
        assert fw.implements == ("SF-01", "SF-02")
        assert next(i for i in manifest.items if i.name == "libmotion").implements == ()

    def test_the_serial_is_exactly_what_the_reviewer_typed(self, ledger, imported):
        out = self.review(ledger, imported, lambda r: r["identity"].update(serial="X-77"))
        assert out["machine"] == "DemoCo/AR-7#X-77"

    def test_safety_relevance_comes_only_from_the_reviewers_implements(self, ledger, imported):
        def nothing_safety_relevant(req):
            for c in req["components"]:
                c["implements"] = []
            req["functions"] = []
        out = self.review(ledger, imported, nothing_safety_relevant)
        manifest = manifests_from_ledger(ledger, out["machine"])[0]
        assert all(not i.implements for i in manifest.items)

    def test_the_review_record_names_the_draft_the_reviewer_and_every_decision(self, ledger,
                                                                              imported):
        out = self.review(ledger, imported)
        review = [e for e in ledger.entries() if e.kind == "ingest.sbom_review"][0]
        body = review.evidence().body
        assert body["draft_id"] == imported["draft_id"] and body["decision"] == "approved"
        assert body["reviewer"]["identifier"] == "A. Integrator"
        assert body["safety_relevance_decided_by"] == "A. Integrator"
        assert body["source_sha256"] == hashlib.sha256(raw(sbom_doc())).hexdigest()
        assert len(body["components"]) == 4 and body["excluded"] == 2
        assert body["enrolment"]["entry"] == out["enrolment"]["enrolment_entry"]
        assert review.evidence().relations[0].relation == "concerns"
        assert sbom_store.list_sbom_drafts(ledger)["drafts"][0]["review_state"] == \
            "approved_and_enrolled"

    # ---- refusals
    def test_a_service_or_unnamed_reviewer_is_refused(self, ledger, imported):
        for who in (SERVICE, None, Actor("bot", "x", "person"), Actor("A. Integrator", "", "service"),
                    Actor("   ", "", "person")):
            with pytest.raises(EnrolmentError):
                self.review(ledger, imported, reviewer=who)
        assert len(ledger) == 1

    def test_the_blank_template_is_not_an_approval(self, ledger, imported):
        req = template(ledger, imported["draft_id"])
        req["decision"] = "approve"
        req["reason"] = "r"
        with pytest.raises(IngestError) as caught:
            sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)
        assert caught.value.code == "invalid_review"
        assert len(ledger) == 1

    def test_decision_and_reason_are_required(self, ledger, imported):
        assert any("decision" in v for v in self.violations(
            ledger, imported, lambda r: r.update(decision=None)))
        assert any("decision" in v for v in self.violations(
            ledger, imported, lambda r: r.update(decision="maybe")))
        assert any("reason" in v for v in self.violations(
            ledger, imported, lambda r: r.update(reason="")))

    @pytest.mark.parametrize("serial", ["", "   ", "n/a", "TBD", "unknown", "none", "-", "?"])
    def test_a_missing_or_placeholder_serial_is_refused(self, ledger, imported, serial):
        found = self.violations(ledger, imported,
                                lambda r: r["identity"].update(serial=serial))
        assert any("serial" in v for v in found)

    def test_the_boms_own_serial_number_is_not_the_machines_serial(self, ledger, imported):
        found = self.violations(ledger, imported, lambda r: r["identity"].update(
            serial="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"))
        assert any("identifies the document, not the machine" in v for v in found)

    def test_the_subject_components_bom_ref_is_not_the_machines_serial_either(self, ledger,
                                                                              imported):
        found = self.violations(ledger, imported, lambda r: r["identity"].update(
            serial="synthetic-machine-ar7"))
        assert any("identifies the document" in v for v in found)

    def test_manufacturer_and_model_are_required_and_nothing_is_taken_from_the_candidates(
            self, ledger, imported):
        found = self.violations(ledger, imported, lambda r: r["identity"].update(
            manufacturer="", model=""))
        assert any("manufacturer" in v for v in found) and any("model" in v for v in found)

    def test_every_component_needs_a_decision(self, ledger, imported):
        found = self.violations(ledger, imported, lambda r: r["components"].pop())
        assert any("no decision" in v for v in found)

    def test_include_is_never_defaulted(self, ledger, imported):
        found = self.violations(ledger, imported,
                                lambda r: r["components"][0].update(include=None))
        assert any("'include' must be true or false" in v for v in found)

    def test_an_included_component_needs_a_kind_and_a_modifiable_decision(self, ledger, imported):
        found = self.violations(ledger, imported,
                                lambda r: r["components"][1].update(kind=None))
        assert any("'kind' must be one of" in v for v in found)
        found = self.violations(ledger, imported,
                                lambda r: r["components"][1].update(modifiable_in_field=None))
        assert any("modifiable_in_field" in v for v in found)

    def test_a_function_an_item_implements_must_be_declared(self, ledger, imported):
        found = self.violations(ledger, imported,
                                lambda r: r["components"][0].update(implements=["SF-99"]))
        assert any("not declared" in v for v in found)

    def test_an_unknown_or_repeated_component_is_refused(self, ledger, imported):
        found = self.violations(ledger, imported, lambda r: r["components"].append(
            {"ref": "c9999", "include": False}))
        assert any("names no component" in v for v in found)
        found = self.violations(ledger, imported,
                                lambda r: r["components"].append(dict(r["components"][0])))
        assert any("decided twice" in v for v in found)

    def test_every_component_excluded_is_refused_an_empty_inventory_is_a_claim(self, ledger,
                                                                              imported):
        def exclude_all(req):
            for c in req["components"]:
                c.update(include=False)
        found = self.violations(ledger, imported, exclude_all)
        assert any("nothing to enrol" in v for v in found)

    def test_a_reviewer_cannot_overwrite_a_supplied_version_or_supplier(self, ledger, imported):
        found = self.violations(ledger, imported,
                                lambda r: r["components"][0].update(version="9.9.9"))
        assert any("fills a version only where the SBOM gave none" in v for v in found)
        found = self.violations(ledger, imported,
                                lambda r: r["components"][0].update(supplier="Other"))
        assert any("supplier only where the SBOM gave none" in v for v in found)

    def test_a_reviewer_may_fill_what_the_sbom_left_unknown_and_it_is_recorded_as_theirs(
            self, ledger, imported):
        def fill(req):
            hmi = next(c for c in req["components"] if c["name"] == "operator-hmi")
            hmi.update(include=True, kind="library", implements=[], modifiable_in_field=True,
                       version="4.2", supplier="ControlCo")
        out = self.review(ledger, imported, fill)
        manifest = manifests_from_ledger(ledger, out["machine"])[0]
        hmi = next(i for i in manifest.items if i.name == "operator-hmi")
        assert (hmi.version, hmi.supplier) == ("4.2", "ControlCo")
        body = [e for e in ledger.entries() if e.kind == "ingest.sbom_review"][0].evidence().body
        decided = next(c for c in body["components"] if c.get("version_filled_by_reviewer"))
        assert decided["version_filled_by_reviewer"] == "4.2"

    def test_unknown_fields_in_the_request_are_refused(self, ledger, imported):
        found = self.violations(ledger, imported, lambda r: r.update(auto_approve=True))
        assert any("unknown field" in v for v in found)

    def test_text_with_invisible_characters_is_refused(self, ledger, imported):
        found = self.violations(ledger, imported,
                                lambda r: r["identity"].update(model="AR‮-7"))
        assert any("invisible" in v for v in found)

    def test_an_ambiguous_identity_is_refused(self, ledger, imported):
        found = self.violations(ledger, imported,
                                lambda r: r["identity"].update(model="AR/7"))
        assert any("ambiguous" in v for v in found)

    def test_a_review_of_a_draft_that_does_not_exist(self, ledger):
        with pytest.raises(IngestError) as caught:
            sbom_store.review_sbom_draft(ledger, "sbom-" + "0" * 32, {}, reviewer=PERSON)
        assert caught.value.code == "draft_not_found"

    def test_a_draft_is_reviewed_once(self, ledger, imported):
        req = approve(template(ledger, imported["draft_id"]))
        sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)
        with pytest.raises(IngestError) as caught:
            sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)
        assert caught.value.code == "already_reviewed"

    def test_a_rejection_is_recorded_enrols_nothing_and_is_final(self, ledger, imported):
        approving = approve(template(ledger, imported["draft_id"]))
        req = {"decision": "reject", "reason": "this SBOM describes the wrong product"}
        out = sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)
        assert out["status"] == "rejected" and out["machine"] == ""
        assert len(Fleet.from_ledger(ledger)) == 0
        assert sbom_store.list_sbom_drafts(ledger)["drafts"][0]["review_state"] == "rejected"
        with pytest.raises(IngestError) as caught:
            sbom_store.review_sbom_draft(ledger, imported["draft_id"], approving, reviewer=PERSON)
        assert caught.value.code == "already_reviewed"

    def test_a_rejection_needs_a_named_person_and_a_reason(self, ledger, imported):
        with pytest.raises(EnrolmentError):
            sbom_store.review_sbom_draft(ledger, imported["draft_id"],
                                         {"decision": "reject", "reason": "x"}, reviewer=SERVICE)
        with pytest.raises(IngestError):
            sbom_store.review_sbom_draft(ledger, imported["draft_id"], {"decision": "reject"},
                                         reviewer=PERSON)

    def test_enrolments_own_refusal_applies_and_the_draft_stays_pending(self, ledger, imported):
        from .ingest_support import enrol, item

        enrol(ledger, "DEMO-0001", item("Something else", "1.0"))
        before = len(ledger)
        with pytest.raises(IngestError) as caught:
            self.review(ledger, imported)
        assert caught.value.code == "configuration_differs"
        assert len(ledger) == before
        assert sbom_store.list_sbom_drafts(ledger)["drafts"][0]["review_state"] == "pending_review"

    def test_a_ledger_whose_chain_does_not_verify_takes_no_review(self, ledger, imported):
        import sqlite3

        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET link_hash = ? WHERE seq = 1", ("f" * 64,))
        db.commit()
        db.close()
        with pytest.raises(AssuranceError):
            self.review(ledger, imported)


# =============================================================================================
class TestTheGuardsTheDraftDependsOn:
    """One test per guard whose removal would let the draft claim something it must not. If a
    guard is mutated away, the test named here fails (the mutation check in the report)."""

    def test_guard_serial_is_never_inferred(self):
        assert parse(sbom_doc()).body["proposed_identity"]["serial"] == []

    def test_guard_no_component_is_safety_relevant_by_default(self):
        assert {c["safety_relevance"] for c in parse(sbom_doc()).components} == {"not_assessed"}
        assert {tuple(c["implements"]) for c in parse(sbom_doc()).components} == {()}

    def test_guard_nothing_is_measured(self):
        assert {c["hash_source_if_enrolled"] for c in parse(sbom_doc()).components} == {"declared"}

    def test_guard_duplicate_bom_refs_are_refused(self):
        doc = sbom_doc()
        doc["components"][1]["bom-ref"] = doc["components"][0]["bom-ref"]
        refused(doc, "invalid_sbom")

    def test_guard_review_requires_a_person(self, ledger, imported):
        with pytest.raises(EnrolmentError):
            sbom_store.review_sbom_draft(
                ledger, imported["draft_id"], approve(template(ledger, imported["draft_id"])),
                reviewer=SERVICE)

    def test_guard_review_requires_an_explicit_decision_for_every_component(self, ledger, imported):
        req = approve(template(ledger, imported["draft_id"]))
        req["components"].pop()
        with pytest.raises(IngestError):
            sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)

    def test_guard_the_boms_serial_is_not_accepted_as_the_machines(self, ledger, imported):
        req = approve(template(ledger, imported["draft_id"]),
                      serial="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")
        with pytest.raises(IngestError):
            sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)

    def test_guard_the_imported_hash_never_reads_as_a_look_at_the_machine(self, ledger, imported):
        from assurance.machinery.manifest import not_a_look

        req = approve(template(ledger, imported["draft_id"]))
        out = sbom_store.review_sbom_draft(ledger, imported["draft_id"], req, reviewer=PERSON)
        manifest = manifests_from_ledger(ledger, out["machine"])[0]
        assert "carry no hash read off the machine" in not_a_look(manifest)
        assert copy.deepcopy(out["tier_ceiling"]) == "profile"
