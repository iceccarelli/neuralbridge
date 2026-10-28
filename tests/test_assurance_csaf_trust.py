"""An imported CSAF record is never silently upgraded into trusted or signed evidence.

``assurance fleet import-csaf`` (PR #53) translates a CSAF 2.0 document into an unsigned,
inspect-only :class:`~assurance.fleet.advisory.ComponentAdvisory`. The invariant these tests hold
is about every boundary the result can cross afterwards, not only the importer:

* H1  the translation record (origin, trust, partial, what was dropped, where the severity came
      from, TLP, tracking status, category) is IN the advisory, so a partial translation cannot
      read as "clear" at any consumer;
* H2  version semantics: nothing inside a range, a boundary or an unlisted label is matched as
      "not affected";
* H3  nothing opens a case, an Art. 14 signal, a report or a check verdict from an unsigned
      import without saying so, and a case needs a named person's explicit override;
* M1  an unsigned import never rewrites a case opened from a different advisory;
* M2  a severity the importer chose is recorded as such;
* M3  hostile text never reaches a terminal; invisible characters never silently defeat a match;
  draft documents and TLP are read;
* LOW hostile input is a clear message and exit 2, never a traceback; the importer is not quadratic.

Every document below is SYNTHETIC. Assertions are on structured output (JSON fields, exit codes,
ledger entries), not on prose.
"""

from __future__ import annotations

import copy
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet import csaf as csaf_module
from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.fleet.csaf import advisory_from_csaf
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import record_manifest

from .test_assurance_change import account_store, client  # noqa: F401  (fixtures)

VENDOR = "Example Controls GmbH"
ENG = Actor("a.integrator", "safety engineer")
FIXTURES = Path(__file__).parent / "fixtures" / "csaf_trust"
FUNCS = (SafetyFunction("SF-01", "Protective stop", "PL d",
                        verified_by=("stop_characterisation",)),)


# --------------------------------------------------------------------------- builders

def item(name="EX-100", version="V2.001", supplier=VENDOR, iid="ITM-1"):
    return SafetyItem(iid, ItemKind.FIRMWARE, name, version, "", HashSource.DECLARED,
                      supplier=supplier, implements=("SF-01",))


def manifest(serial, *items, country="DE"):
    machine = MachineIdentity("Grimaldi", "AR-7", serial, site="Plant 2", country=country)
    return SafetyManifest(
        manifest_id=f"MAN-{serial}-{items[0].version}", machine=machine,
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 9, 1, tzinfo=UTC),
        taken_by=ENG, items=items, functions=FUNCS, method="read via service port")


def make_ledger(path, *manifests):
    ledger = EvidenceLedger(Path(path))
    for m in manifests:
        record_manifest(ledger, m)
    return ledger


def leaf(pid, name, cat="product_version"):
    return {"category": cat, "name": name, "product": {"product_id": pid, "name": f"{pid} {name}"}}


def name_branch(name, kids):
    return {"category": "product_name", "name": name, "branches": kids}


def doc(branches, vulns, *, tid="EX-2026-001", vendor=VENDOR, status="final", tlp=None,
        category="csaf_security_advisory", extra_tree=None, title="SYNTHETIC advisory"):
    d = {
        "document": {
            "csaf_version": "2.0", "category": category, "title": title,
            "publisher": {"name": vendor, "category": "vendor",
                          "namespace": "https://example.invalid"},
            "tracking": {"id": tid, "status": status, "version": "1",
                         "initial_release_date": "2026-10-01T00:00:00Z",
                         "current_release_date": "2026-10-02T08:30:00Z"},
            "references": [{"category": "self", "url": "https://example.invalid/x"}],
        },
        "product_tree": {"branches": [{"category": "vendor", "name": vendor,
                                       "branches": branches}]},
        "vulnerabilities": vulns,
    }
    if tlp:
        d["document"]["distribution"] = {"tlp": {"label": tlp}}
    if extra_tree:
        d["product_tree"].update(extra_tree)
    return d


def affected(*pids, **status):
    return [{"cve": "CVE-2026-0001", "product_status": {"known_affected": list(pids), **status}}]


def simple_doc(**kw):
    return doc([name_branch("EX-100", [leaf("A", "V2.001")])], affected("A"), **kw)


def partial_doc():
    """A is mappable; B is affected but defined only in full_product_names."""
    return doc([name_branch("EX-100", [leaf("A", "V2.001")])], affected("A", "B"),
               extra_tree={"full_product_names": [
                   {"product_id": "B", "name": f"{VENDOR} EX-200 V1.0"}]})


def run_import(tmp_path, document, *flags, name="in.json", raw=None):
    """``fleet import-csaf`` in process. Returns ``(rc, advisory_dict | None, out_path)``."""
    from assurance.fleet.cli import main

    src = tmp_path / name
    if raw is not None:
        src.write_bytes(raw)
    else:
        src.write_text(document if isinstance(document, str) else json.dumps(document),
                       encoding="utf-8")
    out = tmp_path / "adv.json"
    out.unlink(missing_ok=True)
    try:
        rc = main(["import-csaf", str(src), "--out", str(out), *flags])
    except SystemExit as exc:      # argparse refusing a flag is exit 2, whatever the cause
        rc = int(exc.code or 0)
    return rc, (json.loads(out.read_text("utf-8")) if out.exists() else None), out


def imported_file(tmp_path, document=None, *flags):
    rc, adv, out = run_import(tmp_path, document or simple_doc(), *flags)
    assert rc == 0 and adv is not None
    return out


def fleet_advisory(path, ledger_path, capsys, *extra):
    from assurance.fleet.cli import main

    capsys.readouterr()
    rc = main(["advisory", str(path), "--ledger", str(ledger_path), "--json", *extra])
    out = capsys.readouterr()
    return rc, (json.loads(out.out) if out.out.strip() else None), out


def change_cli(capsys, *argv):
    from assurance.change.cli import main

    capsys.readouterr()
    try:
        rc = main(list(argv))
    except SystemExit as exc:
        rc = int(exc.code or 0)
    out = capsys.readouterr()
    return rc, out.out, out.err


def case_store(ledger_path):
    from assurance.change import CaseStore

    return CaseStore(EvidenceLedger(Path(ledger_path)))


def verdict_of(document, version, name="EX-100"):
    return match_item(advisory_from_csaf(document).advisory, item(name, version))


# ===================================================================== H1: the record is IN the advisory

class TestTheTranslationRecordIsInTheAdvisory:
    def test_a_clean_import_writes_origin_trust_and_provenance_into_the_file(self, tmp_path):
        _, adv, _ = run_import(tmp_path, simple_doc(tlp="GREEN"))
        record = adv["import_record"]
        assert record["origin"] == "csaf_import"
        assert record["trust"] == "unsigned_inspect_only"
        assert record["partial"] is False and record["dropped"] == []
        assert record["severity_source"] == "defaulted_by_importer"
        assert record["tlp"] == "GREEN"
        assert record["tracking_status"] == "final"
        assert record["document_category"] == "csaf_security_advisory"
        assert record["document_date"] == "2026-10-02T08:30:00Z"

    @pytest.mark.parametrize("extra_tree", [
        {"full_product_names": [{"product_id": "B", "name": f"{VENDOR} EX-200 V1.0"}]},
        {"relationships": [{"category": "default_component_of", "product_reference": "A",
                            "relates_to_product_reference": "A",
                            "full_product_name": {"product_id": "B", "name": "EX-100 on A"}}]},
    ], ids=["full_product_names_only", "relationships_only"])
    def test_an_affected_product_that_could_not_be_mapped_makes_the_file_partial(
            self, tmp_path, extra_tree):
        d = doc([name_branch("EX-100", [leaf("A", "V2.001")])], affected("A", "B"),
                extra_tree=extra_tree)
        rc, adv, _ = run_import(tmp_path, d)
        assert rc == 0
        record = adv["import_record"]
        assert record["partial"] is True
        assert [x["product_id"] for x in record["dropped"]] == ["B"]
        assert all(x["reason"] for x in record["dropped"])

    def test_the_record_survives_a_round_trip_and_is_part_of_the_content_hash(self, tmp_path):
        _, adv, _ = run_import(tmp_path, partial_doc())
        again = ComponentAdvisory.from_dict(adv)
        assert again.to_dict() == adv
        assert again.content_hash() == ComponentAdvisory.from_dict(adv).content_hash()
        tampered = copy.deepcopy(adv)
        tampered["import_record"]["partial"] = False
        tampered["import_record"]["dropped"] = []
        assert ComponentAdvisory.from_dict(tampered).content_hash() != again.content_hash()

    def test_a_per_component_fixed_version_survives_a_round_trip(self, tmp_path):
        d = doc([name_branch("EX-100", [leaf("A", "V2.001"), leaf("F", "V2.002")])],
                [{"cve": "C", "product_status": {"known_affected": ["A"], "fixed": ["F"]}}])
        _, adv, _ = run_import(tmp_path, d)
        assert adv["affected"][0]["fixed_versions"] == ["V2.002"]
        again = ComponentAdvisory.from_dict(adv)
        assert again.affected[0].fixed_versions == ("V2.002",)
        assert match_item(again, item("EX-100", "V2.002")) is None

    def test_a_record_claiming_a_trusted_state_is_refused(self, tmp_path):
        _, adv, _ = run_import(tmp_path, simple_doc())
        adv["import_record"]["trust"] = "signed"
        with pytest.raises(AdvisoryError):
            ComponentAdvisory.from_dict(adv)

    @pytest.mark.parametrize("field, value", [
        ("partial", "false"), ("partial", 0), ("origin", "supplier_feed"),
        ("severity_source", "stated_by_publisher"), ("dropped", "B"),
    ])
    def test_a_malformed_record_is_refused_when_read(self, tmp_path, field, value):
        _, adv, _ = run_import(tmp_path, simple_doc())
        adv["import_record"][field] = value
        with pytest.raises(AdvisoryError):
            ComponentAdvisory.from_dict(adv)

    def test_a_record_that_dropped_products_but_says_complete_is_refused(self, tmp_path):
        _, adv, _ = run_import(tmp_path, partial_doc())
        adv["import_record"]["partial"] = False
        with pytest.raises(AdvisoryError):
            ComponentAdvisory.from_dict(adv)

    def test_severity_chosen_by_the_importer_is_recorded_as_such(self, tmp_path):
        _, defaulted, _ = run_import(tmp_path, simple_doc())
        assert defaulted["severity"] == "safety_relevant"
        assert defaulted["import_record"]["severity_source"] == "defaulted_by_importer"

    @pytest.mark.parametrize("flag", ["safety_relevant", "informational", "stop_use"])
    def test_a_severity_given_on_the_command_line_is_recorded_and_used(self, tmp_path, flag):
        _, adv, _ = run_import(tmp_path, simple_doc(), "--severity", flag)
        assert adv["severity"] == flag
        assert adv["import_record"]["severity_source"] == "operator_flag"


class TestAPartialTranslationNeverReadsAsClear:
    def _machine_running_b(self, tmp_path):
        return make_ledger(tmp_path / "l.jsonl",
                           manifest("0500", item("EX-200", "V1.0")))

    def test_fleet_advisory_on_a_partial_file_is_not_clear_and_has_its_own_exit_code(
            self, tmp_path, capsys):
        self._machine_running_b(tmp_path)
        path = imported_file(tmp_path, partial_doc())
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        report = payload["advisories"][0]
        assert report["verdict"] != "clear"
        assert report["incomplete"] is True
        assert report["clear_is_complete"] is False
        assert [x["product_id"] for x in report["advisory_import"]["dropped"]] == ["B"]
        assert rc == 3   # documented: nothing matched, but the translation was incomplete

    def test_the_human_readable_output_does_not_say_clear_either(self, tmp_path, capsys):
        from assurance.fleet.cli import main

        self._machine_running_b(tmp_path)
        path = imported_file(tmp_path, partial_doc())
        capsys.readouterr()
        rc = main(["advisory", str(path), "--ledger", str(tmp_path / "l.jsonl")])
        out = capsys.readouterr().out
        assert rc != 0
        assert "CLEAR — no machine in this fleet matches this advisory" not in out

    def test_a_partial_file_with_a_real_match_exits_1_and_is_still_marked_incomplete(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0412", item("EX-100", "V2.001")))
        path = imported_file(tmp_path, partial_doc())
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        report = payload["advisories"][0]
        assert rc == 1 and report["incomplete"] is True
        assert report["machines_affected"] == ["Grimaldi/AR-7#0412"]

    def test_a_complete_import_with_no_match_is_still_clear_and_exits_0(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0500", item("OTHER-9", "V1")))
        path = imported_file(tmp_path, simple_doc())
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        report = payload["advisories"][0]
        assert (rc, report["verdict"], report["incomplete"]) == (0, "clear", False)

    def test_the_change_command_does_not_call_a_partial_advisory_clear(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0500", item("EX-200", "V1.0")))
        path = imported_file(tmp_path, partial_doc())
        rc, out, err = change_cli(
            capsys, "assess-advisory", "--advisory", str(path), "--ledger",
            str(tmp_path / "l.jsonl"), "--accept-unsigned", "--actor", "a.integrator")
        assert "touches no machine" not in out
        assert rc == 0
        (case,) = case_store(tmp_path / "l.jsonl").list()
        assert case.provenance["advisory_partial"] == "true"
        assert "B" in case.provenance["advisory_dropped_products"]
        assert any("'B'" in q for q in case.human_decisions_required)


class TestExistingAdvisoriesAndSignaturesAreUntouched:
    def test_a_signed_feed_written_before_the_import_record_still_verifies_with_the_same_hashes(
            self):
        from assurance.attest.keys import VerifyingKey
        from assurance.supplier import AdvisoryFeed, verify_feed

        golden = json.loads((FIXTURES / "legacy_hashes.json").read_text("utf-8"))
        key = VerifyingKey.from_file(FIXTURES / "legacy_feed.pub.pem")
        records = AdvisoryFeed(FIXTURES / "legacy_feed.jsonl").read()
        verdict = verify_feed(records, key, expect_supplier="controlco")
        assert verdict.ok, verdict
        assert len(records) == 2
        for record in records:
            component = record.component()
            assert component.content_hash() == golden[record.advisory_id]
            assert "import_record" not in component.to_dict()
            assert component.import_record is None
            assert all(set(a.to_dict()) == {"supplier", "name", "versions", "content_hashes",
                                            "version_note"} for a in component.affected)

    def test_a_hand_written_advisory_file_without_the_new_fields_loads_as_today(self):
        legacy = {
            "advisory_id": "CTRL-1", "issued_by": "ControlCo",
            "issued_at": "2026-09-12T08:00:00Z", "title": "t", "summary": "s",
            "severity": "safety_relevant", "reference": "https://controlco.example/1",
            "affected": [{"supplier": "ControlCo", "name": "FW", "versions": ["1"]}],
        }
        advisory = ComponentAdvisory.from_dict(legacy)
        assert advisory.import_record is None
        assert "import_record" not in advisory.to_dict()


# ===================================================================== H2: version semantics

class TestNothingInsideARangeOrBoundaryIsClear:
    def test_a_fixed_version_of_one_cve_does_not_clear_a_machine_inside_another_cves_range(self):
        d = doc([name_branch("EX-100", [
            leaf("R1", "vers:all/<V2.0", "product_version_range"),
            leaf("R2", "vers:all/<V3.0", "product_version_range"),
            leaf("F2", "V2.0"), leaf("F3", "V3.0")])],
            [{"cve": "CVE-1", "product_status": {"known_affected": ["R1"], "fixed": ["F2"]}},
             {"cve": "CVE-2", "product_status": {"known_affected": ["R2"], "fixed": ["F3"]}}])
        found = verdict_of(d, "V2.0")
        assert found is not None and found[0].needs_a_human

    @pytest.mark.parametrize("text", [
        "All versions < V3.1", "V2.x", "2.*", "vers:all/<V3.1", "<=V2.0", ">= V0.1",
        "V2.0 and earlier", "all", "earlier", "V1.0 - V3.0", "V2.0+", "up to V3.0 (inclusive)",
        "vers:semver/1.2.3", "below", "ANY",
    ])
    def test_range_text_in_a_version_branch_is_not_an_exact_label(self, text):
        d = doc([name_branch("EX-100", [leaf("A", text)])], affected("A"))
        found = verdict_of(d, "V0.9")
        assert found is not None, f"{text!r} was imported as an exact version; V0.9 was CLEARED"
        assert found[0] is MatchBasis.NAME_ONLY
        # Kept as range text, said so in the note...
        assert advisory_from_csaf(d).advisory.affected[0].version_note == text

    @pytest.mark.parametrize("text", ["All versions < V3.1", "V2.x", "vers:semver/1.2.3",
                                      "V2.0+", "all", "V2.0 and earlier"])
    def test_a_fixed_version_does_not_clear_a_machine_inside_range_text(self, text):
        # ...and, the reason it matters: a fixed version of the same component must not clear.
        d = doc([name_branch("EX-100", [leaf("A", text), leaf("F", "V0.5")])],
                [{"cve": "C", "product_status": {"known_affected": ["A"], "fixed": ["F"]}}])
        found = verdict_of(d, "V0.5")
        assert found is not None and found[0] is MatchBasis.NAME_ONLY

    def test_last_affected_is_a_boundary_not_an_exact_version(self):
        d = doc([name_branch("EX-100", [leaf("L", "V2.0")])],
                [{"cve": "C", "product_status": {"last_affected": ["L"]}}])
        assert verdict_of(d, "V1.5") is not None
        assert verdict_of(d, "V2.0") is not None

    @pytest.mark.parametrize("status, words", [("first_affected", "first affected"),
                                               ("last_affected", "last affected")])
    def test_a_boundary_is_said_in_the_note_and_a_fixed_version_does_not_clear_it(
            self, status, words):
        d = doc([name_branch("EX-100", [leaf("L", "V2.0"), leaf("F", "V1.0")])],
                [{"cve": "C", "product_status": {status: ["L"], "fixed": ["F"]}}])
        adv = advisory_from_csaf(d).advisory
        assert words in adv.affected[0].version_note
        assert match_item(adv, item("EX-100", "V1.0"))[0] is MatchBasis.NAME_ONLY

    def test_first_affected_is_a_boundary_not_an_exact_version(self):
        d = doc([name_branch("EX-100", [leaf("L", "V2.0")])],
                [{"cve": "C", "product_status": {"first_affected": ["L"]}}])
        assert verdict_of(d, "V2.5") is not None
        assert verdict_of(d, "V2.0") is not None

    @pytest.mark.parametrize("machine_label", ["2.001", "V 2.001", "V2.001.0", "V2.1"])
    def test_a_label_the_advisory_does_not_list_is_for_a_person_not_a_clear(self, machine_label):
        found = verdict_of(simple_doc(), machine_label)
        assert found is not None and found[0] is MatchBasis.NAME_ONLY

    def test_the_same_label_in_a_hand_written_advisory_keeps_its_designed_meaning(self):
        # A hand-written advisory enumerates the versions it means; an unlisted one is not it.
        hand = ComponentAdvisory(
            advisory_id="H-1", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V2.001",)),),
            reference="https://example.invalid/h")
        assert match_item(hand, item("EX-100", "V2.002")) is None

    def test_an_imported_advisory_never_lets_a_fixed_label_outrank_its_range(self):
        # Defence in depth for a hand-edited import file: a global fixed list plus a range.
        record = advisory_from_csaf(simple_doc()).advisory.import_record
        adv = ComponentAdvisory(
            advisory_id="I-1", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V1",),
                                       version_note="vers:all/<V3"),),
            fixed_versions=("V2",), reference="https://example.invalid/i", import_record=record)
        assert match_item(adv, item("EX-100", "V2"))[0] is MatchBasis.NAME_ONLY
        # ...while a supplier-authored advisory (no import record) keeps its designed meaning.
        authored = ComponentAdvisory.from_dict({k: v for k, v in adv.to_dict().items()
                                                if k != "import_record"})
        assert match_item(authored, item("EX-100", "V2")) is None

    def test_a_range_group_does_not_use_a_fixed_version_to_clear(self):
        d = doc([name_branch("EX-100", [
            leaf("R", "vers:all/<V2.5", "product_version_range"), leaf("F", "V2.0")])],
            [{"cve": "C", "product_status": {"known_affected": ["R"], "fixed": ["F"]}}])
        adv = advisory_from_csaf(d).advisory
        assert all(not a.to_dict().get("fixed_versions") for a in adv.affected)
        assert adv.fixed_versions == ()
        assert match_item(adv, item("EX-100", "V2.0"))[0] is MatchBasis.NAME_ONLY


class TestFixedVersionsBelongToTheirOwnProduct:
    def _doc(self):
        return doc([
            name_branch("EX-100", [leaf("A", "V2.001"), leaf("F", "V2.002")]),
            name_branch("EX-50", [leaf("B", "V1.006"), leaf("G", "V1.007")]),
        ], [{"cve": "C", "product_status": {"known_affected": ["A", "B"],
                                              "fixed": ["F"], "first_fixed": ["G"]}}])

    def test_a_fixed_version_clears_only_its_own_product(self):
        d = self._doc()
        assert verdict_of(d, "V2.002", "EX-100") is None            # fixed, no range
        assert verdict_of(d, "V1.007", "EX-50") is None             # first_fixed
        assert verdict_of(d, "V2.001", "EX-100")[0] is MatchBasis.VERSION
        # EX-100's fixed label is not a statement about EX-50, and vice versa.
        assert verdict_of(d, "V2.002", "EX-50")[0] is MatchBasis.NAME_ONLY
        assert verdict_of(d, "V1.007", "EX-100")[0] is MatchBasis.NAME_ONLY

    def test_a_fixed_product_that_is_a_range_is_never_used_as_a_fix(self):
        d = doc([name_branch("EX-100", [
            leaf("A", "V2.001"), leaf("F", "vers:all/>=V3.0", "product_version_range")])],
            [{"cve": "C", "product_status": {"known_affected": ["A"], "fixed": ["F"]}}])
        adv = advisory_from_csaf(d).advisory
        assert all("vers:" not in v for v in adv.fixed_versions)
        assert all("vers:" not in v for a in adv.affected
                   for v in a.to_dict().get("fixed_versions", []))

    def test_a_fixed_product_with_a_version_and_a_range_is_never_used_as_a_fix(self):
        fixed = {"category": "product_version", "name": "V3.0", "branches": [
            {"category": "product_version_range", "name": "vers:all/>=V3.0",
             "product": {"product_id": "F", "name": "fixed"}}]}
        d = doc([name_branch("EX-100", [leaf("A", "V2.001"), fixed])],
                [{"cve": "C", "product_status": {"known_affected": ["A"], "fixed": ["F"]}}])
        adv = advisory_from_csaf(d).advisory
        assert all(not a.fixed_versions for a in adv.affected)
        assert match_item(adv, item("EX-100", "V3.0"))[0] is MatchBasis.NAME_ONLY

    def test_known_not_affected_is_ignored_and_does_not_clear(self):
        # P3 is EX-100 V2.002, which the publisher lists ONLY as known_not_affected. Honouring
        # that as a fix would make a machine on V2.002 read None; ignoring it leaves the machine
        # a label the advisory does not list, which is for a person.
        d = doc([name_branch("EX-100", [leaf("P1", "V2.001"), leaf("P3", "V2.002")])],
                [{"cve": "C", "product_status": {"known_affected": ["P1"],
                                                   "known_not_affected": ["P3"]}}])
        adv = advisory_from_csaf(d).advisory
        assert adv.fixed_versions == ()
        assert all(not a.to_dict().get("fixed_versions") for a in adv.affected)
        found = match_item(adv, item("EX-100", "V2.002"))
        assert found is not None and found[0] is MatchBasis.NAME_ONLY


# ===================================================================== H3: boundaries

def _ledger_with_a_machine(tmp_path, version="V2.001"):
    path = tmp_path / "l.jsonl"
    make_ledger(path, manifest("0412", item("EX-100", version)))
    return path


def _actors_of(ledger_path, case_id):
    ledger = EvidenceLedger(Path(ledger_path))
    return [e.evidence().actor for e in ledger.entries(subject=case_id)]


class TestACaseFromAnUnsignedImportNeedsANamedPersonsOverride:
    @pytest.mark.parametrize("argv", [
        [],
        ["--actor", "a.integrator"],
        ["--accept-unsigned"],
        ["--accept-unsigned", "--actor", "automation"],
        ["--accept-unsigned", "--actor", "Agent"],
    ], ids=["no_flags", "name_only", "flag_only", "reserved_name", "reserved_name_2"])
    def test_without_the_override_and_a_person_no_case_is_opened(self, tmp_path, capsys, argv):
        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path)
        rc, _, _ = change_cli(capsys, "assess-advisory", "--advisory", str(path),
                              "--ledger", str(ledger), *argv)
        assert rc != 0
        assert case_store(ledger).list() == []

    def test_a_complete_import_that_matches_nothing_needs_no_override_and_opens_nothing(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0500", item("OTHER-9", "V1")))
        path = imported_file(tmp_path)
        rc, out, _ = change_cli(capsys, "assess-advisory", "--advisory", str(path),
                                "--ledger", str(tmp_path / "l.jsonl"))
        assert rc == 0 and out.startswith("clear:")
        assert case_store(tmp_path / "l.jsonl").list() == []

    def test_with_the_override_the_case_carries_the_trust_state_and_who_accepted_it(
            self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path, partial_doc(), "--severity", "stop_use")
        rc, out, _ = change_cli(
            capsys, "assess-advisory", "--advisory", str(path), "--ledger", str(ledger),
            "--accept-unsigned", "--actor", "a.integrator",
            "--reason", "reviewed against the publisher's page")
        assert rc == 0
        (case,) = case_store(ledger).list()
        p = case.provenance
        assert p["advisory_trust"] == "unsigned_inspect_only"
        assert p["advisory_origin"] == "csaf_import"
        assert p["advisory_partial"] == "true"
        assert p["advisory_dropped_products"] == "B"
        assert p["advisory_severity_source"] == "operator_flag"
        assert p["advisory_accepted_by"] == "a.integrator"
        assert p["advisory_accept_reason"] == "reviewed against the publisher's page"
        assert {a.kind for a in _actors_of(ledger, case.case_id)} == {"person"}

    def test_the_marker_is_in_show_json_and_in_the_export(self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path, simple_doc(tlp="AMBER"))
        change_cli(capsys, "assess-advisory", "--advisory", str(path), "--ledger",
                   str(ledger), "--accept-unsigned", "--actor", "a.integrator")
        (case,) = case_store(ledger).list()
        _, shown, _ = change_cli(capsys, "show", "--ledger", str(ledger), case.case_id, "--json")
        assert json.loads(shown)["provenance"]["advisory_trust"] == "unsigned_inspect_only"
        assert json.loads(shown)["provenance"]["advisory_tlp"] == "AMBER"
        _, exported, _ = change_cli(capsys, "export", "--ledger", str(ledger), case.case_id)
        bundle = json.loads(exported)

        def provenances(node):
            if isinstance(node, dict):
                if isinstance(node.get("provenance"), dict):
                    yield node["provenance"]
                for v in node.values():
                    yield from provenances(v)
            elif isinstance(node, list):
                for v in node:
                    yield from provenances(v)

        marked = [p for p in provenances(bundle) if p.get("advisory_trust")]
        assert marked and all(p["advisory_trust"] == "unsigned_inspect_only" for p in marked)
        assert all(p["advisory_tlp"] == "AMBER" for p in marked)

    def test_the_text_view_of_the_case_carries_the_marker_too(self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path, partial_doc(), "--severity", "stop_use")
        change_cli(capsys, "assess-advisory", "--advisory", str(path), "--ledger",
                   str(ledger), "--accept-unsigned", "--actor", "a.integrator")
        (case,) = case_store(ledger).list()
        _, shown, _ = change_cli(capsys, "show", "--ledger", str(ledger), case.case_id)
        marker = next(line for line in shown.splitlines() if "UNAUTHENTICATED ADVISORY" in line)
        assert "unsigned_inspect_only" in marker and "a.integrator" in marker
        assert "PARTIAL" in marker and "operator flag" in marker

    def test_a_hand_written_bare_advisory_needs_a_named_person_and_the_case_says_so(
            self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        hand = ComponentAdvisory(
            advisory_id="H-1", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V2.001",)),),
            reference="https://example.invalid/h")
        path = tmp_path / "hand.json"
        path.write_text(json.dumps(hand.to_dict()), encoding="utf-8")
        rc, _, _ = change_cli(capsys, "assess-advisory", "--advisory", str(path),
                              "--ledger", str(ledger))
        assert rc != 0 and case_store(ledger).list() == []
        rc, _, _ = change_cli(capsys, "assess-advisory", "--advisory", str(path),
                              "--ledger", str(ledger), "--actor", "a.integrator")
        assert rc == 0
        (case,) = case_store(ledger).list()
        assert case.provenance["advisory_trust"] == "unauthenticated_file"
        assert case.provenance["advisory_accepted_by"] == "a.integrator"


class TestEveryOtherBoundaryCarriesTheMarker:
    def test_the_art14_signal_is_marked_and_not_dated_by_the_documents_own_date(
            self, tmp_path, capsys):
        from assurance.bridge.cli import main

        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path, partial_doc(), "--severity", "stop_use")
        register = tmp_path / "register.jsonl"
        capsys.readouterr()
        before = datetime.now(UTC)
        rc = main(["art14", str(path), "--ledger", str(ledger), "--received-by",
                   "a.integrator", "--open", "--register", str(register), "--json"])
        out = capsys.readouterr().out
        assert rc in (0, 1)
        payload = json.loads(out)
        assert payload["advisory_provenance"]["trust"] == "unsigned_inspect_only"
        assert payload["advisory_provenance"]["partial"] is True
        received = datetime.fromisoformat(payload["signal"]["received_at"].replace("Z", "+00:00"))
        assert received >= before.replace(microsecond=0), \
            "received_at was taken from the document's own date"
        assert "2026-10-02T08:30:00Z" in payload["signal"]["description"]
        sealed = [e.evidence().body["signal"] for e in EvidenceLedger(register).entries()
                  if "signal" in e.evidence().body
                  and e.evidence().body["signal"].get("channel") == "component_supplier_advisory"]
        assert sealed and "unsigned" in sealed[0]["description"].lower()
        assert "PARTIAL" in sealed[0]["description"] and "B" in sealed[0]["description"]
        assert sealed[0]["received_at"] == payload["signal"]["received_at"]

    def test_an_art14_intake_from_a_partial_import_that_matches_nothing_says_why(
            self, tmp_path, capsys):
        from assurance.bridge.cli import main

        ledger = make_ledger(tmp_path / "l.jsonl", manifest("0500", item("EX-200", "V1.0")))
        del ledger
        path = imported_file(tmp_path, partial_doc())
        capsys.readouterr()
        rc = main(["art14", str(path), "--ledger", str(tmp_path / "l.jsonl"),
                   "--received-by", "a.integrator"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "'B'" in err and "INCOMPLETE" in err

    def test_the_art14_summary_carries_the_marker(self, tmp_path, capsys):
        from assurance.bridge.cli import main

        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path, partial_doc())
        capsys.readouterr()
        main(["art14", str(path), "--ledger", str(ledger), "--received-by", "a.integrator"])
        out = capsys.readouterr().out
        assert "UNSIGNED CSAF IMPORT" in out and "PARTIAL TRANSLATION" in out

    def test_the_report_carries_the_marker_and_the_tlp(self, tmp_path):
        from assurance.report.cli import main

        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path, partial_doc(), "--severity", "stop_use")
        page = json.loads(path.read_text("utf-8"))
        page["import_record"]["tlp"] = "AMBER"
        path.write_text(json.dumps(page), encoding="utf-8")
        out = tmp_path / "r.html"
        assert main(["build", "--ledger", str(ledger), "--out", str(out),
                     "--advisory", str(path)]) == 0
        html = out.read_text("utf-8")
        assert 'data-advisory-trust="unsigned_inspect_only"' in html
        assert 'data-advisory-tlp="AMBER"' in html
        assert 'data-advisory-partial="true"' in html

    def test_fleet_advisory_text_names_the_trust_state_and_where_severity_came_from(
            self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path)
        _, payload, _ = fleet_advisory(path, ledger, capsys)
        report = payload["advisories"][0]
        assert report["provenance"]["inspect_only"] is True
        assert report["advisory_import"]["trust"] == "unsigned_inspect_only"
        assert report["advisory_import"]["severity_source"] == "defaulted_by_importer"

    def test_a_signed_feed_cannot_launder_an_unsigned_import(self, tmp_path):
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        ledger = make_ledger(tmp_path / "l.jsonl", manifest("0412", item("EX-100", "V2.001")))
        advisory = advisory_from_csaf(simple_doc()).advisory
        trusted = {"source": "supplier_feed", "trust_state": "pinned",
                   "trust_basis": "pinned_key_policy", "inspect_only": False,
                   "automated_consequences_permitted": True}
        report = assess_impact(advisory, Fleet.from_ledger(ledger), provenance=trusted)
        assert report.provenance["inspect_only"] is True
        assert report.provenance["automated_consequences_permitted"] is False
        assert report.provenance["trust_state"] == "unsigned_import"
        assert report.provenance["trust_basis"] == "none"
        assert report.provenance["supplied_provenance"]["trust_state"] == "pinned"


from .test_assurance_watch_advisories import plant  # noqa: E402,F401  (fixture)


class TestTheWatchNeverActsOnAnUnsignedImport:
    def test_an_import_inside_a_verified_signed_feed_is_inspect_only_and_opens_no_case(
            self, request):
        import base64
        import dataclasses

        from assurance.supplier.publish import FEED_FORMAT, SignedAdvisory

        from .test_assurance_watch_advisories import IDENTITY, _advisory, _run

        env = request.getfixturevalue("plant")
        _run(env)
        record = advisory_from_csaf(simple_doc()).advisory.import_record
        advisory = dataclasses.replace(_advisory(), import_record=record)
        # publish() refuses this (below), so a key holder's hand-made record stands in for it.
        unsigned = SignedAdvisory(
            format=FEED_FORMAT, sequence=1, supplier=IDENTITY,
            key_fingerprint=env["key"].fingerprint, published_at="2026-09-10T08:00:00Z",
            previous="", advisory=advisory.to_dict())
        env["feed"].append(dataclasses.replace(unsigned, signature=base64.b64encode(
            env["key"].sign(unsigned.signed_payload())).decode("ascii")))
        run = _run(env)
        findings = [f for f in run.advisories.findings if f.advisory_id == "CTRL-2026-11"]
        assert len(findings) == 1
        assert findings[0].inspect_only is True and findings[0].state == "untrusted"
        assert findings[0].machines == () and findings[0].stops_use is False
        assert findings[0].case_id == ""
        from assurance.change import CaseStore
        assert CaseStore(env["ledger"]).list() == []

    def test_a_supplier_cannot_publish_an_unsigned_import_under_its_signature(self, request):
        import dataclasses

        from assurance.supplier import PublishError, publish

        from .test_assurance_watch_advisories import IDENTITY, _advisory

        env = request.getfixturevalue("plant")
        record = advisory_from_csaf(simple_doc()).advisory.import_record
        with pytest.raises(PublishError, match="unsigned import"):
            publish(dataclasses.replace(_advisory(), import_record=record), IDENTITY,
                    env["key"], env["feed"])
        assert env["feed"].read() == []

    def test_the_same_advisory_without_the_record_is_acted_on_as_before(self, request):
        from assurance.supplier import publish

        from .test_assurance_watch_advisories import IDENTITY, _advisory, _run

        env = request.getfixturevalue("plant")
        _run(env)
        publish(_advisory(), IDENTITY, env["key"], env["feed"])
        run = _run(env)
        (finding,) = [f for f in run.advisories.findings if f.advisory_id == "CTRL-2026-11"]
        assert finding.inspect_only is False and finding.stops_use


class TestHttpBoundaries:
    @pytest.fixture
    def fx(self, request):
        from .test_assurance_change import fw, keyed
        from .test_assurance_change import manifest as cmanifest

        http = request.getfixturevalue("client")
        headers = keyed(request.getfixturevalue("account_store"), "cell")
        r = http.post("/v1/machinery/manifest",
                        json={"manifest": cmanifest(fw(), manifest_id="MAN-0412").to_dict()},
                        headers=headers)
        assert r.status_code == 200, r.text
        return http, headers, cmanifest, fw

    @staticmethod
    def _csaf_adv():
        d = doc([name_branch("Safety controller firmware", [leaf("P0", "3.8.2")])],
                affected("P0"), vendor="ControlCo")
        return advisory_from_csaf(d).advisory.to_dict()

    def test_assess_advisory_refuses_an_unsigned_import_without_the_override(self, fx):
        http, headers, *_ = fx
        r = http.post("/v1/change/assess/advisory", json={"advisory": self._csaf_adv()},
                        headers=headers)
        assert r.status_code == 409, r.text
        r = http.post("/v1/change/assess/advisory",
                        json={"advisory": self._csaf_adv(), "actor": "a.integrator"},
                        headers=headers)
        assert r.status_code == 409, r.text
        assert http.get("/v1/change/cases", headers=headers).json()["cases"] == []

    def test_with_the_override_the_response_and_the_case_carry_the_marker(self, fx):
        http, headers, *_ = fx
        r = http.post("/v1/change/assess/advisory",
                        json={"advisory": self._csaf_adv(), "actor": "a.integrator",
                              "accept_unsigned": True, "reason": "checked at the source"},
                        headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["opened"] is True
        p = body["case"]["provenance"]
        assert p["advisory_trust"] == "unsigned_inspect_only"
        assert p["advisory_accepted_by"] == "a.integrator"
        assert body["advisory_trust"]["inspect_only"] is True

    def test_a_bare_advisory_in_the_body_needs_a_named_person_and_is_marked(self, fx):
        http, headers, *_ = fx
        hand = ComponentAdvisory(
            advisory_id="H-1", issued_by="ControlCo",
            issued_at=datetime(2026, 10, 1, tzinfo=UTC), title="t", summary="s",
            severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact("ControlCo", "Safety controller firmware",
                                       versions=("3.8.2",)),),
            reference="https://example.invalid/h").to_dict()
        r = http.post("/v1/change/assess/advisory", json={"advisory": hand}, headers=headers)
        assert r.status_code == 409, r.text
        r = http.post("/v1/change/assess/advisory",
                        json={"advisory": hand, "actor": "a.integrator"}, headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["case"]["provenance"]["advisory_trust"] == "unauthenticated_input"

    def test_the_free_check_carries_the_provenance_and_a_partial_import_is_not_no_impact(
            self, fx):
        http, _, cmanifest, fw = fx
        d = doc([name_branch("Other component", [leaf("P0", "9.9.9")])],
                affected("P0", "B"), vendor="ControlCo",
                extra_tree={"full_product_names": [{"product_id": "B", "name": "other"}]})
        body = {"manifest": cmanifest(fw(version="3.8.0"), manifest_id="M1").to_dict(),
                "advisory": advisory_from_csaf(d).advisory.to_dict()}
        r = http.post("/v1/check/machine", json=body)
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["advisory_provenance"]["inspect_only"] is True
        assert out["advisory_import"]["trust"] == "unsigned_inspect_only"
        assert out["incomplete"] is True
        assert out["verdict"] != "no_impact_found"

    def test_the_fleet_check_route_reports_a_partial_import_as_incomplete(self, fx):
        http, headers, *_ = fx
        d = doc([name_branch("Other component", [leaf("P0", "1")])], affected("P0", "B"),
                vendor="ControlCo",
                extra_tree={"full_product_names": [{"product_id": "B", "name": "other"}]})
        r = http.post("/v1/fleet/advisory",
                        json={"advisory": advisory_from_csaf(d).advisory.to_dict()},
                        headers=headers)
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["verdict"] != "clear" and out["incomplete"] is True
        assert out["clear_is_complete"] is False


# ===================================================================== M1: case identity

class TestAnImportNeverRewritesAnotherAdvisorysCase:
    def _trusted(self):
        return ComponentAdvisory(
            advisory_id="EX-9", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="trusted", summary="s", severity=AdvisorySeverity.STOP_USE,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V1", "V2")),),
            reference="https://example.invalid/trusted")

    def _open_trusted(self, ledger_path):
        from assurance.change import assess_advisory
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        ledger = EvidenceLedger(Path(ledger_path))
        fleet = Fleet.from_ledger(ledger)
        trusted = {"source": "supplier_feed", "trust_state": "pinned",
                   "trust_basis": "pinned_key_policy", "inspect_only": False,
                   "automated_consequences_permitted": True, "override": None}
        return assess_advisory(case_store(ledger_path),
                               assess_impact(self._trusted(), fleet, provenance=trusted),
                               actor=ENG)

    def test_an_unsigned_import_with_the_same_tracking_id_opens_its_own_case(
            self, tmp_path, capsys):
        ledger = tmp_path / "l.jsonl"
        make_ledger(ledger, manifest("A", item("EX-100", "V1")),
                    manifest("B", item("EX-100", "V2")))
        first = self._open_trusted(ledger)
        assert len(first.machines) == 2
        path = imported_file(tmp_path, doc(
            [name_branch("EX-100", [leaf("P", "V1")])], affected("P"), tid="EX-9"))
        change_cli(capsys, "assess-advisory", "--advisory", str(path), "--ledger",
                   str(ledger), "--accept-unsigned", "--actor", "a.integrator")
        cases = case_store(ledger).list()
        assert len(cases) == 2, "the unsigned import was folded into the trusted case"
        original = case_store(ledger).get(first.case_id)
        assert original.machines == first.machines
        assert original.linked_evidence == first.linked_evidence
        assert original.provenance == first.provenance

    def test_two_publishers_with_the_same_tracking_id_do_not_share_a_case(
            self, tmp_path, capsys):
        ledger = tmp_path / "l.jsonl"
        make_ledger(ledger, manifest("A", item("EX-100", "V1")),
                    manifest("B", item("OTHER-1", "V1", supplier="Other Corp")))
        first = imported_file(tmp_path, doc(
            [name_branch("EX-100", [leaf("P", "V1")])], affected("P"), tid="2026-001"))
        change_cli(capsys, "assess-advisory", "--advisory", str(first), "--ledger",
                   str(ledger), "--accept-unsigned", "--actor", "a.integrator")
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        second = imported_file(other_dir, doc(
            [name_branch("OTHER-1", [leaf("P", "V1")])], affected("P"), tid="2026-001",
            vendor="Other Corp"))
        change_cli(capsys, "assess-advisory", "--advisory", str(second), "--ledger",
                   str(ledger), "--accept-unsigned", "--actor", "a.integrator")
        cases = case_store(ledger).list()
        assert len(cases) == 2
        assert sorted(len(c.machines) for c in cases) == [1, 1]

    def test_an_existing_trusted_advisorys_case_id_is_unchanged(self):
        from assurance.change import TriggerType, case_id_for

        # Pinned from a135c0e: ids of cases already in a ledger are history and must not move.
        assert case_id_for(TriggerType.SUPPLIER_ADVISORY, "EX-9") == "case-69a298c9975b3ec5"

    def test_once_work_has_started_a_reissued_advisory_still_appends_its_link(self, tmp_path):
        from assurance.change import advance, assess_advisory, claim
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        ledger_path = tmp_path / "l.jsonl"
        ledger = make_ledger(ledger_path, manifest("A", item("EX-100", "V1")),
                             manifest("B", item("EX-100", "V2")))
        trusted = {"source": "supplier_feed", "trust_state": "pinned",
                   "trust_basis": "pinned_key_policy", "inspect_only": False,
                   "automated_consequences_permitted": True, "override": None}
        store = case_store(ledger_path)
        first = assess_advisory(
            store, assess_impact(self._trusted(), Fleet.from_ledger(ledger),
                                 provenance=trusted), actor=ENG)
        claim(store, first.case_id, owner="v.grimaldi", actor=Actor("v.grimaldi", "reviewer"))
        advance(store, first.case_id, actor=Actor("v.grimaldi", "reviewer"))
        assert store.get(first.case_id).status.value == "awaiting_action"
        reissued = ComponentAdvisory.from_dict({**self._trusted().to_dict(), "title": "again"})
        assess_advisory(store, assess_impact(reissued, Fleet.from_ledger(ledger),
                                             provenance=trusted), actor=ENG)
        links = {r["content_hash"] for r in store.get(first.case_id).linked_evidence}
        assert {first.linked_evidence[0]["content_hash"], reissued.content_hash()} <= links

    def test_a_bare_file_with_the_same_id_never_rewrites_a_trusted_advisorys_case(
            self, tmp_path, capsys):
        ledger = tmp_path / "l.jsonl"
        make_ledger(ledger, manifest("A", item("EX-100", "V1")),
                    manifest("B", item("EX-100", "V2")))
        first = self._open_trusted(ledger)
        narrower = tmp_path / "narrower.json"
        narrower.write_text(json.dumps({
            **self._trusted().to_dict(), "title": "doctored",
            "affected": [{"supplier": VENDOR, "name": "EX-100", "versions": ["V1"]}]}),
            encoding="utf-8")
        rc, *_ = change_cli(capsys, "assess-advisory", "--advisory", str(narrower),
                            "--ledger", str(ledger), "--actor", "a.integrator")
        assert rc == 0
        (only,) = case_store(ledger).list()
        assert only.case_id == first.case_id
        assert only.machines == first.machines
        assert only.linked_evidence == first.linked_evidence
        assert only.changed_items == first.changed_items
        assert "advisory_trust" not in only.provenance

    def test_a_repeat_look_before_work_starts_never_drops_a_machine_or_a_link(self, tmp_path):
        from assurance.change import assess_advisory
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        ledger_path = tmp_path / "l.jsonl"
        ledger = make_ledger(ledger_path, manifest("A", item("EX-100", "V1")),
                             manifest("B", item("EX-100", "V2")))
        trusted = {"source": "supplier_feed", "trust_state": "pinned",
                   "trust_basis": "pinned_key_policy", "inspect_only": False,
                   "automated_consequences_permitted": True, "override": None}
        store = case_store(ledger_path)
        first = assess_advisory(
            store, assess_impact(self._trusted(), Fleet.from_ledger(ledger),
                                 provenance=trusted), actor=ENG)
        # The same advisory id, re-issued narrower, then re-assessed before any work.
        narrower = ComponentAdvisory.from_dict(
            {**self._trusted().to_dict(), "title": "re-issued",
             "affected": [{"supplier": VENDOR, "name": "EX-100", "versions": ["V1"]}]})
        again = assess_advisory(
            store, assess_impact(narrower, Fleet.from_ledger(ledger), provenance=trusted),
            actor=ENG)
        assert set(again.machines) >= set(first.machines)
        old = {r["content_hash"] for r in first.linked_evidence}
        assert old <= {r["content_hash"] for r in again.linked_evidence}


# ===================================================================== M3: text, TLP, draft

class TestHostileTextAndUnreadMetadata:
    BAD_TITLE = "\x1b[2J\x1b[1;1HCLEAR ‮evil​"

    def test_a_terminal_escape_in_a_hand_written_title_is_never_printed_raw(
            self, tmp_path, capsys):
        from assurance.fleet.cli import main

        ledger = _ledger_with_a_machine(tmp_path)
        hand = ComponentAdvisory(
            advisory_id="H-2", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title=self.BAD_TITLE, summary="s\x07\x1b]0;x\x07",
            severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V2.001",)),),
            reference="https://example.invalid/h")
        path = tmp_path / "h.json"
        path.write_text(json.dumps(hand.to_dict()), encoding="utf-8")
        capsys.readouterr()
        main(["advisory", str(path), "--ledger", str(ledger)])
        out = capsys.readouterr().out
        for ch in ("\x1b", "\x07", "‮", "​"):
            assert ch not in out

    def test_a_case_built_from_a_hostile_advisory_prints_no_raw_escape(self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        hand = ComponentAdvisory(
            advisory_id="H-4", issued_by="Example\x1b[31m Controls GmbH\u202e",
            issued_at=datetime(2026, 10, 1, tzinfo=UTC), title="t", summary="s",
            severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact("Example\x1b[31m Controls GmbH\u202e", "EX-100",
                                       versions=("V2.001",)),),
            reference="https://example.invalid/h")
        item_ = SafetyItem("ITM-9", ItemKind.FIRMWARE, "EX-100", "V2.001", "",
                           HashSource.DECLARED, supplier="Example\x1b[31m Controls GmbH\u202e",
                           implements=("SF-01",))
        make_ledger(tmp_path / "l2.jsonl", manifest("0777", item_))
        path = tmp_path / "h.json"
        path.write_text(json.dumps(hand.to_dict()), encoding="utf-8")
        change_cli(capsys, "assess-advisory", "--advisory", str(path), "--ledger",
                   str(tmp_path / "l2.jsonl"), "--actor", "a.integrator")
        (case,) = case_store(tmp_path / "l2.jsonl").list()
        _, shown, _ = change_cli(capsys, "show", "--ledger", str(tmp_path / "l2.jsonl"),
                                 case.case_id)
        assert "\x1b" not in shown and "\u202e" not in shown
        assert ledger.exists()

    def test_the_importer_neutralises_control_and_bidi_characters_in_display_text(
            self, tmp_path):
        rc, adv, _ = run_import(tmp_path, simple_doc(title=self.BAD_TITLE))
        assert rc == 0
        for ch in ("\x1b", "‮", "​"):
            assert ch not in adv["title"]
        assert any("title" in n for n in adv["import_record"]["notes"])

    def test_control_characters_in_the_publisher_name_are_removed_and_said(self, tmp_path):
        d = simple_doc()
        d["document"]["publisher"]["name"] = "Example\x1b[2J Controls GmbH\u202e"
        rc, adv, _ = run_import(tmp_path, d)
        assert rc == 0
        assert "\x1b" not in adv["issued_by"] and "\u202e" not in adv["issued_by"]
        assert any("publisher name" in n for n in adv["import_record"]["notes"])

    @pytest.mark.parametrize("where", ["product_name", "product_version", "vendor"])
    def test_an_invisible_character_in_a_matching_field_is_refused_naming_the_field(
            self, tmp_path, capsys, where):
        name, version, vendor = "EX-100", "V2.001", VENDOR
        if where == "product_name":
            name = "EX-​100"
        elif where == "product_version":
            version = "V2.​001"
        else:
            vendor = "Example​ Controls GmbH"
        d = doc([name_branch(name, [leaf("A", version)])], affected("A"), vendor=vendor)
        capsys.readouterr()
        rc, adv, _ = run_import(tmp_path, d)
        err = capsys.readouterr().err
        assert rc == 2 and adv is None
        assert "U+200B" in err

    @pytest.mark.parametrize("status", ["draft", "interim", ""])
    def test_a_draft_or_interim_document_is_refused_by_default(self, tmp_path, status):
        rc, adv, _ = run_import(tmp_path, simple_doc(status=status))
        assert rc == 2 and adv is None

    @pytest.mark.parametrize("status", ["draft", "interim"])
    def test_a_draft_can_be_imported_on_request_and_is_marked_partial(self, tmp_path, status):
        rc, adv, _ = run_import(tmp_path, simple_doc(status=status), "--allow-draft")
        assert rc == 0
        record = adv["import_record"]
        assert record["tracking_status"] == status
        assert record["partial"] is True

    @pytest.mark.parametrize("label", ["WHITE", "GREEN", "AMBER", "RED", "AMBER+STRICT", "CLEAR"])
    def test_the_tlp_label_is_carried_in_the_record(self, tmp_path, label):
        _, adv, _ = run_import(tmp_path, simple_doc(tlp=label))
        assert adv["import_record"]["tlp"] == label

    def test_the_document_category_is_carried_in_the_record(self, tmp_path):
        _, adv, _ = run_import(tmp_path, simple_doc(category="csaf_vex"))
        assert adv["import_record"]["document_category"] == "csaf_vex"


# ===================================================================== LOW: hostile input

class TestHostileInputIsAMessageAndExit2:
    @pytest.mark.parametrize("label, mutate", [
        ("known_affected is a number",
         lambda d: d["vulnerabilities"][0]["product_status"].update(known_affected=5)),
        ("known_affected is a string",
         lambda d: d["vulnerabilities"][0]["product_status"].update(known_affected="A")),
        ("fixed is a number",
         lambda d: d["vulnerabilities"][0]["product_status"].update(fixed=7)),
        ("a product id is not a string",
         lambda d: d["vulnerabilities"][0]["product_status"].update(known_affected=[["A"]])),
        ("remediations is a number", lambda d: d["vulnerabilities"][0].update(remediations=5)),
        ("references is a number", lambda d: d["document"].update(references=3)),
        ("notes is a number", lambda d: d["document"].update(notes=3)),
        ("branches is an object",
         lambda d: d["product_tree"]["branches"][0].update(branches={"a": 1})),
        ("a branch is a string",
         lambda d: d["product_tree"]["branches"][0]["branches"].append("EX-100")),
        ("a vulnerability is not an object",
         lambda d: d["vulnerabilities"].append("not a mapping")),
        ("product_status is a list",
         lambda d: d["vulnerabilities"][0].update(product_status=["A"])),
    ])
    def test_wrong_typed_fields_are_refused_without_a_traceback(
            self, tmp_path, capsys, label, mutate):
        d = simple_doc()
        mutate(d)
        capsys.readouterr()
        rc, adv, _ = run_import(tmp_path, d)
        err = capsys.readouterr().err
        assert rc == 2, label
        assert adv is None and err.strip()

    def test_deeply_nested_json_is_refused(self, tmp_path, capsys):
        n = 100_000
        rc, adv, _ = run_import(tmp_path, '{"document":' + "[" * n + "]" * n + "}")
        assert rc == 2 and adv is None
        assert capsys.readouterr().err.strip()

    def test_a_very_deep_product_tree_is_refused_or_imported_but_never_a_traceback(
            self, tmp_path):
        import sys

        d = simple_doc()
        node = {"category": "product_name", "name": "EX-100", "product": {"product_id": "A"}}
        for _ in range(3000):
            node = {"category": "product_family", "name": "x", "branches": [node]}
        d["product_tree"]["branches"] = [node]
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(20_000)
        try:
            text = json.dumps(d)
        finally:
            sys.setrecursionlimit(old)
        rc, adv, _ = run_import(tmp_path, text)
        assert rc == 2 and adv is None

    def test_a_deep_tree_handed_to_the_library_is_an_advisory_error_not_a_recursion_error(
            self):
        d = simple_doc()
        node = {"category": "product_name", "name": "EX-100", "product": {"product_id": "A"}}
        for _ in range(5000):
            node = {"category": "product_family", "name": "x", "branches": [node]}
        d["product_tree"]["branches"] = [node]
        with pytest.raises(AdvisoryError, match="deep"):
            advisory_from_csaf(d)

    def test_nan_and_infinity_are_not_json_and_are_refused(self, tmp_path):
        text = json.dumps(simple_doc()).replace('"version": "1"', '"version": NaN')
        rc, adv, _ = run_import(tmp_path, text)
        assert rc == 2 and adv is None

    def test_a_file_over_the_stated_size_limit_is_refused(self, tmp_path, monkeypatch):
        assert csaf_module.MAX_FILE_BYTES >= 1024 * 1024
        monkeypatch.setattr(csaf_module, "MAX_FILE_BYTES", 100)
        rc, adv, _ = run_import(tmp_path, simple_doc())
        assert rc == 2 and adv is None

    def test_a_device_is_never_read_as_a_document(self, capsys):
        from assurance.fleet.cli import main

        # /dev/zero is endless: reading it to the end would exhaust memory.
        capsys.readouterr()
        assert main(["import-csaf", "/dev/zero"]) == 2
        assert "not a regular file" in capsys.readouterr().err

    def test_a_bom_is_read_as_the_text_it_precedes(self, tmp_path):
        rc, adv, _ = run_import(tmp_path, None, raw=b"\xef\xbb\xbf" + json.dumps(simple_doc()).encode())
        assert rc == 0 and adv["advisory_id"] == "EX-2026-001"

    def test_a_missing_file_is_exit_2(self, tmp_path):
        from assurance.fleet.cli import main

        assert main(["import-csaf", str(tmp_path / "nope.json")]) == 2

    def test_a_directory_is_exit_2_and_says_so(self, tmp_path, capsys):
        from assurance.fleet.cli import main

        capsys.readouterr()
        assert main(["import-csaf", str(tmp_path)]) == 2
        assert "is a directory, not a CSAF document" in capsys.readouterr().err

    def test_an_invisible_character_in_the_tracking_id_is_refused(self, tmp_path, capsys):
        capsys.readouterr()
        rc, adv, _ = run_import(tmp_path, simple_doc(tid="EX-2026-\u200b001"))
        assert rc == 2 and adv is None and "tracking id" in capsys.readouterr().err

    def test_utf16_is_exit_2(self, tmp_path):
        rc, adv, _ = run_import(tmp_path, None, raw=json.dumps(simple_doc()).encode("utf-16"))
        assert rc == 2 and adv is None

    def test_out_equal_to_the_input_is_refused_and_the_input_survives(self, tmp_path):
        from assurance.fleet.cli import main

        src = tmp_path / "in.json"
        src.write_text(json.dumps(simple_doc()), encoding="utf-8")
        before = src.read_bytes()
        assert main(["import-csaf", str(src), "--out", str(src)]) == 2
        assert src.read_bytes() == before

    def test_out_that_is_the_same_file_through_a_symlink_is_refused(self, tmp_path):
        from assurance.fleet.cli import main

        src = tmp_path / "in.json"
        src.write_text(json.dumps(simple_doc()), encoding="utf-8")
        link = tmp_path / "link.json"
        os.symlink(src, link)
        before = src.read_bytes()
        assert main(["import-csaf", str(src), "--out", str(link)]) == 2
        assert src.read_bytes() == before

    def test_a_forty_thousand_product_document_imports_quickly(self):
        n = 40_000
        d = doc([name_branch("EX-100", [leaf(f"P{i}", f"V{i}") for i in range(n)])],
                affected(*[f"P{i}" for i in range(n)]))
        start = time.perf_counter()
        advisory = advisory_from_csaf(d).advisory
        assert time.perf_counter() - start < 2.0, "the importer is quadratic again"
        assert len(advisory.affected[0].versions) == n

    def test_a_document_over_the_stated_product_limit_is_refused(self, tmp_path, monkeypatch):
        assert isinstance(csaf_module.MAX_PRODUCTS, int) and csaf_module.MAX_PRODUCTS >= 40_000
        monkeypatch.setattr(csaf_module, "MAX_PRODUCTS", 3)
        d = doc([name_branch("EX-100", [leaf(f"P{i}", f"V{i}") for i in range(5)])],
                affected("P0"))
        rc, adv, _ = run_import(tmp_path, d)
        assert rc == 2 and adv is None

    def test_a_duplicate_product_id_is_noted_and_a_conflicting_one_makes_it_partial(
            self, tmp_path):
        same = doc([name_branch("EX-100", [leaf("A", "V2.001"), leaf("A", "V2.001")])],
                   affected("A"))
        _, adv, _ = run_import(tmp_path, same)
        assert adv["import_record"]["partial"] is False
        assert any("duplicate" in n.lower() for n in adv["import_record"]["notes"])
        clash = doc([name_branch("EX-100", [leaf("A", "V2.001"), leaf("A", "V9.999")]),
                     name_branch("EX-50", [leaf("B", "V1.006")])],
                    affected("A", "B"))
        _, adv, _ = run_import(tmp_path, clash)
        record = adv["import_record"]
        assert record["partial"] is True
        assert "A" in [x["product_id"] for x in record["dropped"]]


# ===================================================================== survivors of the PR #53 tests

class TestTheImporterStillMeansWhatPr53Said:
    def test_the_reference_check_is_the_importers_own(self):
        d = simple_doc()
        d["document"].pop("references")
        with pytest.raises(AdvisoryError, match="trace it to its source"):
            advisory_from_csaf(d)

    def test_a_self_reference_is_preferred_to_the_first_one(self):
        d = simple_doc()
        d["document"]["references"] = [
            {"category": "external", "url": "https://example.invalid/other"},
            {"category": "self", "url": "https://example.invalid/self"}]
        assert advisory_from_csaf(d).advisory.reference == "https://example.invalid/self"

    def test_the_first_vendor_fix_is_the_remedy_and_a_mitigation_is_not(self):
        d = simple_doc()
        d["vulnerabilities"][0]["remediations"] = [
            {"category": "mitigation", "details": "Block the port."},
            {"category": "vendor_fix", "details": "Update to V2.002."},
            {"category": "vendor_fix", "details": "Later fix."}]
        assert advisory_from_csaf(d).advisory.remedy == "Update to V2.002."

    def test_a_product_id_is_matched_after_stripping_and_the_output_is_sorted(self):
        d = doc([name_branch("EX-200", [leaf(" B ", "V1")]),
                 name_branch("EX-100", [leaf("A", "V2")])],
                affected("B", "A"))
        adv = advisory_from_csaf(d).advisory
        assert [a.name for a in adv.affected] == ["EX-100", "EX-200"]

    def test_the_innermost_vendor_and_the_exact_version_win(self):
        d = {"document": simple_doc()["document"],
             "product_tree": {"branches": [{
                 "category": "vendor", "name": "Reseller AG", "branches": [{
                     "category": "vendor", "name": VENDOR, "branches": [{
                         "category": "product_name", "name": "EX-100", "branches": [{
                             "category": "product_version", "name": "V2.001",
                             "branches": [{"category": "product_version_range",
                                           "name": "vers:all/<V9",
                                           "product": {"product_id": "A"}}]}]}]}]}]},
             "vulnerabilities": affected("A")}
        adv = advisory_from_csaf(d).advisory
        assert adv.affected[0].supplier == VENDOR
        assert adv.affected[0].versions[0] == "V2.001"
        assert adv.affected[0].version_note == "vers:all/<V9"

    def test_the_first_classification_of_a_product_wins(self):
        d = doc([name_branch("EX-100", [leaf("A", "V2.001")])],
                [{"cve": "C", "product_status": {
                    "known_affected": ["A"], "under_investigation": ["A"]}}])
        adv = advisory_from_csaf(d).advisory
        assert "under investigation" not in adv.affected[0].version_note

    def test_relationships_are_reported_in_the_record(self):
        d = simple_doc()
        d["product_tree"]["relationships"] = [{"category": "default_component_of"}]
        notes = advisory_from_csaf(d).advisory.import_record.notes
        assert any("relationships" in n for n in notes)

    def test_the_cli_writes_json_to_stdout_when_no_out_is_given(self, tmp_path, capsys):
        from assurance.fleet.cli import main

        src = tmp_path / "in.json"
        src.write_text(json.dumps(simple_doc()), encoding="utf-8")
        capsys.readouterr()
        assert main(["import-csaf", str(src), "--severity", "informational"]) == 0
        captured = capsys.readouterr()
        written = json.loads(captured.out)
        assert written["severity"] == "informational"
        assert written["import_record"]["trust"] == "unsigned_inspect_only"
        assert "severity: informational (operator flag)" in captured.err   # and its source


# ===================================================================== core/text.py

class TestNeutralise:
    def test_controls_bidi_and_zero_width_become_visible_escapes(self):
        from assurance.core.text import neutralise

        out = neutralise("a\x1b[2Jb\u202ec\u200bd\x07")
        assert out == "a\\x1b[2Jb\\u202ec\\u200bd\\x07"

    def test_a_single_line_field_cannot_start_a_line_of_its_own(self):
        from assurance.core.text import neutralise

        assert neutralise("x\n  CLEAR") == "x\\x0a  CLEAR"
        assert neutralise("x\r\ty") == "x\\x0d\\x09y"
        assert neutralise("x\n y\tz", multiline=True) == "x\n y\tz"

    def test_the_invisible_characters_are_named_once_each(self):
        from assurance.core.text import invisible_characters, strip_invisible

        assert invisible_characters("a\u200b\u200bb\x1bc") == ["U+200B", "U+001B"]
        assert invisible_characters("plain text, accents \u00e9 and \u00df") == []
        assert strip_invisible("a\u200b b\n c\u202e") == ("a b c", ["U+200B", "U+000A", "U+202E"])


class TestMoreBoundaries:
    @pytest.fixture
    def fx(self, request):
        from .test_assurance_change import fw, keyed
        from .test_assurance_change import manifest as cmanifest

        http = request.getfixturevalue("client")
        headers = keyed(request.getfixturevalue("account_store"), "cell")
        return http, headers, cmanifest, fw

    def test_the_free_advisory_check_marks_an_unsigned_partial_import(self, fx):
        http, _, cmanifest, fw = fx
        d = doc([name_branch("Other component", [leaf("P0", "1")])], affected("P0", "B"),
                vendor="ControlCo",
                extra_tree={"full_product_names": [{"product_id": "B", "name": "other"}]})
        r = http.post("/v1/fleet/advisory/check", json={
            "advisory": advisory_from_csaf(d).advisory.to_dict(),
            "manifest": cmanifest(fw(version="3.8.0"), manifest_id="M1").to_dict()})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["incomplete"] is True and out["affected"] is False
        assert out["advisory_import"]["trust"] == "unsigned_inspect_only"
        assert out["provenance"]["inspect_only"] is True
        assert out["provenance"]["advisory_trust"] == "unsigned_inspect_only"

    def test_the_first_acceptance_of_an_unsigned_import_is_kept(self, tmp_path, capsys):
        ledger = _ledger_with_a_machine(tmp_path)
        path = imported_file(tmp_path)
        for who in ("a.integrator", "b.integrator"):
            rc, *_ = change_cli(capsys, "assess-advisory", "--advisory", str(path),
                                "--ledger", str(ledger), "--accept-unsigned", "--actor", who,
                                "--reason", f"{who} read it")
            assert rc == 0
        (case,) = case_store(ledger).list()
        assert case.provenance["advisory_accepted_by"] == "a.integrator"
        assert case.provenance["advisory_accept_reason"] == "a.integrator read it"

    def test_a_case_on_an_unauthenticated_advisory_is_never_high_confidence(
            self, tmp_path, capsys):
        h = "1" * 64
        path = tmp_path / "l.jsonl"
        make_ledger(path, manifest("0412", SafetyItem(
            "ITM-1", ItemKind.FIRMWARE, "EX-100", "V2.001", h, HashSource.READ_FROM_MACHINE,
            supplier=VENDOR, implements=("SF-01",))))
        hand = ComponentAdvisory(
            advisory_id="H-3", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V2.001",),
                                       content_hashes=(h,)),),
            reference="https://example.invalid/h")
        adv = tmp_path / "hand.json"
        adv.write_text(json.dumps(hand.to_dict()), encoding="utf-8")
        rc, *_ = change_cli(capsys, "assess-advisory", "--advisory", str(adv),
                            "--ledger", str(path), "--actor", "a.integrator")
        assert rc == 0
        (case,) = case_store(path).list()
        assert case.changed_items[0]["confidence"] == "confirmed"      # the match is by hash...
        assert case.confidence == "medium"                              # ...the case is not

    def test_an_exit_3_is_not_used_when_the_ledger_chain_does_not_verify(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0500", item("EX-200", "V1.0")),
                    manifest("0501", item("EX-300", "V1.0")))
        path = imported_file(tmp_path, partial_doc())
        import sqlite3

        db = sqlite3.connect(tmp_path / "l.jsonl")
        try:
            db.execute("UPDATE chain SET payload = replace(payload, 'Grimaldi', 'Grimaldx') "
                       "WHERE seq = 1")
            db.commit()
        finally:
            db.close()
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        assert payload["advisories"][0]["chain_verified"] is False
        assert payload["advisories"][0]["incomplete"] is True
        assert rc == 1
