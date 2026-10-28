"""Round 2 of the review of the CSAF import: what a second, independent look still found.

Round 1 (``test_assurance_csaf_trust.py``) made an import carry its own translation record and
refused to open a case on it without a named person. This file holds what that left open:

* F-1  a supplier spelled differently ("Example Controls" for "Example Controls GmbH") read
       CLEAR for a machine on exactly the affected version;
* F-2  the record is a label, not a seal: stripping it must not turn the file into a CLEAR one;
* F-3  an account-level key with a made-up name must not pass ``accept_unsigned``;
* F-4  a "fixed" label of one vulnerability cleared a machine for another;
* F-5  a vulnerability with no ``product_status`` contributed nothing and the import stayed complete;
* F-6  ``bridge art14 --open`` had no gate and a case id that a trusted advisory could not follow;
* F-7  the signed-feed row of a pinned feed claimed consequences were permitted for an import;
* F-8  ``bridge art14`` printed raw escapes;   F-9 a dropped update said ``opened: true``;
* F-10 100k artefacts took 30 s to assess and a 32 MiB file of ``{},`` took 865 MB;
* plus the survivors of round 1's mutation run.

Assertions are on structured output, as in round 1.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime

import pytest

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

from .test_assurance_change import account_store, client  # noqa: F401  (fixtures)
from .test_assurance_csaf_trust import (
    VENDOR,
    affected,
    case_store,
    change_cli,
    doc,
    fleet_advisory,
    imported_file,
    item,
    leaf,
    make_ledger,
    manifest,
    name_branch,
    run_import,
    simple_doc,
)


def verdict_of(document, version, name="EX-100", supplier=VENDOR):
    return match_item(advisory_from_csaf(document).advisory, item(name, version, supplier=supplier))


# ===================================================================== F-1: the supplier string

class TestASupplierSpelledDifferentlyIsForAPerson:
    @pytest.mark.parametrize("supplier", [
        "Example Controls", "Example Controls GmbH & Co. KG", "Example-Controls GmbH",
        "Controls Example GmbH", "Some Other Company",
    ])
    def test_the_same_component_from_a_differently_spelled_supplier_is_not_clear(self, supplier):
        found = verdict_of(simple_doc(), "V2.001", supplier=supplier)
        assert found is not None and found[0] is MatchBasis.NAME_ONLY
        assert "supplier differs" in found[1]
        assert VENDOR in found[1] and supplier in found[1]

    @pytest.mark.parametrize("supplier", ["example controls gmbh", " Example   Controls GmbH "])
    def test_case_and_whitespace_are_still_the_same_supplier(self, supplier):
        found = verdict_of(simple_doc(), "V2.001", supplier=supplier)
        assert found is not None and found[0] is MatchBasis.VERSION

    def test_a_different_component_is_still_not_matched(self):
        assert verdict_of(simple_doc(), "V2.001", name="EX-999", supplier="Example Controls") is None

    def test_a_hand_written_advisory_keeps_exact_supplier_matching(self):
        hand = ComponentAdvisory(
            advisory_id="H-1", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V2.001",)),),
            reference="https://example.invalid/h")
        assert match_item(hand, item("EX-100", "V2.001", supplier="Example Controls")) is None

    def test_a_fix_under_one_spelling_does_not_clear_a_range_under_another_in_one_document(self):
        d = doc([name_branch("EX-100", [leaf("A", "V1.0"), leaf("F", "V2.0")])],
                [{"cve": "C1", "product_status": {"known_affected": ["A"], "fixed": ["F"]}},
                 {"cve": "C2", "product_status": {"known_affected": ["R"]}}])
        d["product_tree"]["branches"].append({
            "category": "vendor", "name": "Example Controls", "branches": [
                name_branch("EX-100", [leaf("R", "vers:all/<V3.0", "product_version_range")])]})
        for supplier in (VENDOR, "Example Controls"):
            found = verdict_of(d, "V2.0", supplier=supplier)
            assert found is not None and found[0] is MatchBasis.NAME_ONLY, supplier

    def test_fleet_advisory_exits_nonzero_for_a_machine_on_the_exact_version(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl",
                    manifest("0412", item("EX-100", "V2.001", supplier="Example Controls")))
        path = imported_file(tmp_path)
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        report = payload["advisories"][0]
        assert rc == 1 and report["verdict"] == "needs_review"
        assert report["machines_affected"] == ["Grimaldi/AR-7#0412"]

    def test_an_import_that_matches_nothing_lists_the_names_it_looked_for(
            self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0500", item("OTHER-9", "V1")))
        path = imported_file(tmp_path)
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        report = payload["advisories"][0]
        assert (rc, report["verdict"]) == (0, "clear")     # a product truly absent is clear
        listed = [c for c in report["checks_skipped"] if "no component name matched exactly" in c]
        assert listed and "EX-100" in listed[0] and VENDOR in listed[0]


# ===================================================================== F-2: the record is a label

class TestStrippingTheRecordLeavesTheFailSafeInTheData:
    def _stripped(self, tmp_path):
        _, adv, _ = run_import(tmp_path, doc(
            [name_branch("EX-100", [leaf("A", "V2.001")])], affected("A", "B"),
            extra_tree={"full_product_names": [{"product_id": "B", "name": "other"}]}))
        stripped = {k: v for k, v in adv.items() if k != "import_record"}
        return adv, stripped

    def test_every_affected_artefact_carries_a_note_so_an_unlisted_label_is_for_a_person(
            self, tmp_path):
        adv, stripped = self._stripped(tmp_path)
        assert all(a["version_note"] for a in adv["affected"])
        hand = ComponentAdvisory.from_dict(stripped)
        assert hand.import_record is None
        found = match_item(hand, item("EX-100", "V2.5"))
        assert found is not None and found[0] is MatchBasis.NAME_ONLY

    def test_title_and_summary_say_what_it_is_whatever_a_consumer_prints(self, tmp_path):
        adv, stripped = self._stripped(tmp_path)
        marker = "[unsigned CSAF import, partial: not imported B]"
        assert stripped["title"].startswith(marker) and stripped["summary"].startswith(marker)

    def test_a_complete_import_is_marked_in_the_text_too(self, tmp_path):
        _, adv, _ = run_import(tmp_path, simple_doc())
        assert adv["title"].startswith("[unsigned CSAF import] ")
        assert adv["summary"].startswith("[unsigned CSAF import] ")

    def test_the_fleet_command_prints_the_marker_beside_the_verdict_of_a_stripped_file(
            self, tmp_path, capsys):
        from assurance.fleet.cli import main

        _, stripped = self._stripped(tmp_path)
        path = tmp_path / "stripped.json"
        path.write_text(json.dumps(stripped), encoding="utf-8")
        make_ledger(tmp_path / "l.jsonl", manifest("0412", item("EX-100", "V2.5")))
        capsys.readouterr()
        rc = main(["advisory", str(path), "--ledger", str(tmp_path / "l.jsonl")])
        out = capsys.readouterr().out
        assert rc == 1                              # V2.5 is unlisted: for a person, not clear
        head = next(line for line in out.splitlines() if line.startswith("EX-2026-001 — "))
        assert "[unsigned CSAF import, partial: not imported B]" in head


# ===================================================================== F-3: who may accept

class TestOnlyAnOperatorWithTheDeciderRoleMayAcceptAnUnsignedImport:
    @pytest.fixture
    def fx(self, client, account_store):  # noqa: F811
        from .test_assurance_change import fw, keyed
        from .test_assurance_change import manifest as cmanifest

        headers = keyed(account_store, "cell")
        r = client.post("/v1/machinery/manifest",
                        json={"manifest": cmanifest(fw(), manifest_id="MAN-0412").to_dict()},
                        headers=headers)
        assert r.status_code == 200, r.text
        d = doc([name_branch("Safety controller firmware", [leaf("P0", "3.8.2")])],
                affected("P0"), vendor="ControlCo", tid="EX-1")
        return client, account_store, headers, advisory_from_csaf(d).advisory.to_dict()

    def _body(self, adv, **over):
        return {"advisory": adv, "actor": "alice", "accept_unsigned": True,
                "reason": "read the vendor page", **over}

    def test_an_account_key_with_a_made_up_name_is_refused(self, fx):
        http, _, headers, adv = fx
        r = http.post("/v1/change/assess/advisory", json=self._body(adv), headers=headers)
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "operator_required"
        assert http.get("/v1/change/cases", headers=headers).json()["cases"] == []

    def test_a_contributor_operator_is_refused(self, fx):
        http, accounts, headers, adv = fx
        from assurance.api import deps

        principal = deps.get_accounts().peek_key(headers["X-API-Key"])
        _, op_key = accounts.create_operator(principal.account.id, "c.person", "contributor")
        r = http.post("/v1/change/assess/advisory", json=self._body(adv, actor="c.person"),
                      headers={"X-API-Key": op_key})
        assert r.status_code == 403 and r.json()["detail"]["error"] == "decider_role_required"

    def test_a_decider_may_and_the_case_says_how_the_name_was_established(self, fx):
        from .test_assurance_change import as_decider

        http, _, headers, adv = fx
        r = http.post("/v1/change/assess/advisory",
                      json=self._body(adv, actor="v.grimaldi"),
                      headers=as_decider(headers, "v.grimaldi"))
        assert r.status_code == 200, r.text
        p = r.json()["case"]["provenance"]
        assert p["advisory_accepted_by"] == "v.grimaldi"
        assert p["advisory_accepted_basis"] == "authenticated_operator"

    def test_a_reason_is_required_on_every_surface(self, fx, tmp_path, capsys):
        from .test_assurance_change import as_decider

        http, _, headers, adv = fx
        r = http.post("/v1/change/assess/advisory",
                      json=self._body(adv, actor="v.grimaldi", reason="  "),
                      headers=as_decider(headers, "v.grimaldi"))
        assert r.status_code == 409, r.text
        assert http.get("/v1/change/cases", headers=headers).json()["cases"] == []
        # ...and on the command line
        ledger = tmp_path / "l.jsonl"
        make_ledger(ledger, manifest("0412", item("EX-100", "V2.001")))
        path = imported_file(tmp_path)
        rc, *_ = change_cli(capsys, "assess-advisory", "--advisory", str(path), "--ledger",
                            str(ledger), "--accept-unsigned", "--actor", "a.integrator")
        assert rc != 0 and case_store(ledger).list() == []


# ===================================================================== F-4 and F-5

class TestAFixedLabelNeverClearsAnImport:
    def test_a_fix_for_one_vulnerability_does_not_clear_another(self):
        d = doc([name_branch("EX-100", [leaf("A", "V1.0"), leaf("F2", "V2.0"), leaf("F3", "V3.0")])],
                [{"cve": "CVE-1", "product_status": {"known_affected": ["A"], "fixed": ["F2"]}},
                 {"cve": "CVE-2", "product_status": {"known_affected": ["A"], "fixed": ["F3"]}}])
        for ver in ("V2.0", "V3.0"):
            found = verdict_of(d, ver)
            assert found is not None and found[0] is MatchBasis.NAME_ONLY
            assert "fixed" in found[1] and "V2.0" in found[1] and "V3.0" in found[1]

    def test_even_a_single_vulnerabilitys_fix_is_for_a_person(self):
        d = doc([name_branch("EX-100", [leaf("A", "V1.0"), leaf("F", "V2.0")])],
                [{"cve": "C", "product_status": {"known_affected": ["A"], "fixed": ["F"]}}])
        found = verdict_of(d, "V2.0")
        assert found is not None and found[0] is MatchBasis.NAME_ONLY
        assert advisory_from_csaf(d).advisory.affected[0].fixed_versions == ("V2.0",)

    def test_a_supplier_authored_advisory_keeps_its_designed_meaning(self):
        hand = ComponentAdvisory(
            advisory_id="H-1", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V1.0",)),),
            fixed_versions=("V2.0",), reference="https://example.invalid/h")
        assert match_item(hand, item("EX-100", "V2.0")) is None


class TestAVulnerabilityWithNoProductStatusIsNotSilentlyComplete:
    def _doc(self, **second):
        return doc([name_branch("EX-100", [leaf("A", "V1.0")]),
                    name_branch("EX-200", [leaf("B", "V1.0")])],
                   [{"cve": "CVE-1", "product_status": {"known_affected": ["A"]}},
                    {"cve": "CVE-2", **second}])

    def test_no_product_status_makes_the_import_partial_and_says_which_vulnerability(
            self, tmp_path):
        _, adv, _ = run_import(tmp_path, self._doc())
        record = adv["import_record"]
        assert record["partial"] is True
        assert any("vulnerabilities[1]" in r and "no product_status" in r
                   for r in record["partial_reasons"])

    def test_a_product_named_only_in_remediations_is_dropped_and_named(self, tmp_path, capsys):
        d = self._doc(remediations=[{"category": "vendor_fix", "details": "upgrade",
                                     "product_ids": ["B"]}])
        _, adv, _ = run_import(tmp_path, d)
        assert [x["product_id"] for x in adv["import_record"]["dropped"]] == ["B"]
        make_ledger(tmp_path / "l.jsonl", manifest("0500", item("EX-200", "V1.0")))
        path = tmp_path / "adv.json"
        rc, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        assert rc == 3 and payload["advisories"][0]["verdict"] != "clear"

    def test_ids_in_scores_and_threats_count_too_but_classified_ones_do_not(self, tmp_path):
        d = self._doc(product_status={"known_affected": ["A"], "known_not_affected": ["B"]},
                      scores=[{"products": ["B"], "cvss_v3": {}}],
                      threats=[{"category": "impact", "details": "x", "product_ids": ["A"]}])
        _, adv, _ = run_import(tmp_path, d)
        assert adv["import_record"]["partial"] is False


# ===================================================================== F-6: Article 14

class TestArt14OpeningNeedsTheSameOverrideAsACase:
    def _setup(self, tmp_path):
        ledger = tmp_path / "l.jsonl"
        make_ledger(ledger, manifest("0412", item("EX-100", "V2.001")))
        return ledger, imported_file(tmp_path, doc(
            [name_branch("EX-100", [leaf("A", "V2.001")])], affected("A"), tid="EX-9"))

    def _art14(self, capsys, path, ledger, register, *extra):
        from assurance.bridge.cli import main

        capsys.readouterr()
        try:
            rc = main(["art14", str(path), "--ledger", str(ledger), "--open",
                       "--register", str(register), "--json", *extra])
        except SystemExit as exc:
            rc = int(exc.code or 0)
        return rc, capsys.readouterr()

    @pytest.mark.parametrize("extra", [
        ["--received-by", "automation"],
        ["--received-by", "a.integrator"],
        ["--received-by", "a.integrator", "--accept-unsigned"],
        ["--received-by", "automation", "--accept-unsigned", "--reason", "x"],
        ["--received-by", "x", "--actor", "agent", "--accept-unsigned", "--reason", "x"],
    ])
    def test_opening_an_import_is_refused_without_a_named_person_the_flag_and_a_reason(
            self, tmp_path, capsys, extra):
        from assurance.evidence.ledger import EvidenceLedger

        ledger, path = self._setup(tmp_path)
        register = tmp_path / "register.jsonl"
        rc, out = self._art14(capsys, path, ledger, register, *extra)
        assert rc == 2 and "unsigned import" in out.err.lower()
        assert not register.exists() or EvidenceLedger(register).entries() == []

    def test_with_the_override_it_opens_under_a_case_id_of_its_own(self, tmp_path, capsys):
        ledger, path = self._setup(tmp_path)
        rc, out = self._art14(capsys, path, ledger, tmp_path / "register.jsonl",
                              "--received-by", "a.integrator", "--accept-unsigned",
                              "--reason", "checked the publisher page")
        assert rc in (0, 1), out.err
        payload = json.loads(out.out)
        assert payload["case_id"] != "CASE-EX-9" and payload["case_id"].startswith("CASE-EX-9-")
        assert payload["advisory_provenance"]["trust"] == "unsigned_inspect_only"

    def test_a_trusted_advisory_with_the_same_id_can_still_be_opened_afterwards(
            self, tmp_path, capsys):
        from assurance.bridge.art14 import draft_from_advisory, open_case
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet
        from assurance.security.art14.engine import Art14Register

        from .test_assurance_csaf_trust import ENG

        ledger, path = self._setup(tmp_path)
        register = tmp_path / "register.jsonl"
        rc, out = self._art14(capsys, path, ledger, register, "--received-by", "a.integrator",
                              "--accept-unsigned", "--reason", "r")
        assert rc in (0, 1), out.err
        trusted = ComponentAdvisory(
            advisory_id="EX-9", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="real", summary="s", severity=AdvisorySeverity.STOP_USE,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V2.001",)),),
            reference="https://example.invalid/t")
        from assurance.evidence.ledger import EvidenceLedger

        fleet = Fleet.from_ledger(EvidenceLedger(ledger))
        draft = draft_from_advisory(trusted, assess_impact(trusted, fleet), fleet,
                                    received_by="x.person")
        assert draft.case_id == "CASE-EX-9"                      # trusted ids do not move
        open_case(Art14Register(EvidenceLedger(register)), draft, ENG)

    def test_a_draft_without_open_needs_no_override(self, tmp_path, capsys):
        from assurance.bridge.cli import main

        ledger, path = self._setup(tmp_path)
        capsys.readouterr()
        rc = main(["art14", str(path), "--ledger", str(ledger), "--received-by", "automation",
                   "--json"])
        assert rc in (0, 1)


# ===================================================================== F-7: the signed-feed row

from .test_assurance_supplier_trust import _hdr, api, key  # noqa: E402,F401  (fixtures)


class TestAnImportInAPinnedFeedIsInspectOnlyInTheRowToo:
    def test_the_row_and_the_top_level_say_inspect_only_and_carry_the_marker(
            self, api, tmp_path, key):  # noqa: F811
        import base64
        import dataclasses

        from assurance.api.deps import tenant_ledger_path
        from assurance.evidence.ledger import EvidenceLedger
        from assurance.supplier.publish import FEED_FORMAT, AdvisoryFeed, SignedAdvisory

        from .test_assurance_fleet import enrol
        from .test_assurance_supplier_trust import IDENTITY, _adv, _pem

        http, accounts = api
        h, account = _hdr(accounts)
        enrol(EvidenceLedger(tenant_ledger_path(account.id)), "0001")
        record = advisory_from_csaf(doc(
            [name_branch("Safety controller firmware", [leaf("P", "3.8.2")])],
            affected("P"), tid="CTRL-2026-11")).advisory.import_record
        adv = dataclasses.replace(_adv(), import_record=record)
        unsigned = SignedAdvisory(
            format=FEED_FORMAT, sequence=1, supplier=IDENTITY, key_fingerprint=key.fingerprint,
            published_at="2026-09-10T08:00:00Z", previous="", advisory=adv.to_dict())
        signed = dataclasses.replace(unsigned, signature=base64.b64encode(
            key.sign(unsigned.signed_payload())).decode("ascii"))
        feed = AdvisoryFeed(tmp_path / "f.jsonl")
        feed.append(signed)
        http.post("/v1/supplier/trust/pin", headers=h, json={
            "supplier_id": "controlco", "public_key_pem": _pem(key), "obtained_via": "phone"})
        out = http.post("/v1/fleet/advisory/signed", headers=h,
                          json={"feed": feed.path.read_text()}).json()
        row = out["advisories"][0]
        assert row["automated_consequences_permitted"] is False
        assert row["inspect_only"] is True
        assert row["advisory_import"]["trust"] == "unsigned_inspect_only"
        assert out["inspect_only"] is True


# ===================================================================== F-8 / F-9

class TestNoRawEscapeInAnyTextPath:
    def _hostile(self, tmp_path):
        ledger = tmp_path / "l.jsonl"
        make_ledger(ledger, manifest("0412", item("EX-100", "V2.001")))
        hand = {"advisory_id": "H-1", "issued_by": "Evil\x1b[2JCorp‮",
                "issued_at": "2026-10-01T00:00:00Z", "title": "t\x1b[1;1H", "summary": "s",
                "severity": "safety_relevant", "reference": "https://x.invalid/",
                "affected": [{"supplier": VENDOR, "name": "EX-100", "versions": ["V2.001"],
                              "version_note": "n\x1b]0;x\x07"}]}
        path = tmp_path / "a.json"
        path.write_text(json.dumps(hand), encoding="utf-8")
        return ledger, path

    def test_bridge_art14_text_output(self, tmp_path, capsys):
        from assurance.bridge.cli import main

        ledger, path = self._hostile(tmp_path)
        capsys.readouterr()
        main(["art14", str(path), "--ledger", str(ledger), "--received-by", "a.integrator"])
        out = capsys.readouterr().out
        for ch in ("\x1b", "\x07", "‮"):
            assert ch not in out

    def test_report_and_change_text_paths(self, tmp_path, capsys):
        ledger, path = self._hostile(tmp_path)
        rc, out, _ = change_cli(capsys, "assess-advisory", "--advisory", str(path),
                                "--ledger", str(ledger), "--actor", "a.integrator")
        assert rc == 0
        _, listing, _ = change_cli(capsys, "list", "--ledger", str(ledger))
        for text in (out, listing):
            for ch in ("\x1b", "\x07", "‮"):
                assert ch not in text


class TestADroppedUpdateIsSaidNotReportedAsOpened:
    def test_a_bare_advisory_that_met_a_case_without_the_marker_gets_an_explicit_answer(
            self, tmp_path, capsys):
        from assurance.change import assess_advisory
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        from .test_assurance_csaf_trust import ENG

        ledger_path = tmp_path / "l.jsonl"
        ledger = make_ledger(ledger_path, manifest("A", item("EX-100", "V1")),
                             manifest("B", item("EX-100", "V2")))
        trusted = {"source": "supplier_feed", "trust_state": "pinned", "inspect_only": False,
                   "trust_basis": "pinned_key_policy", "automated_consequences_permitted": True}
        wide = ComponentAdvisory(
            advisory_id="EX-9", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.STOP_USE,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V1", "V2")),),
            reference="https://example.invalid/t")
        first = assess_advisory(case_store(ledger_path), assess_impact(
            wide, Fleet.from_ledger(ledger), provenance=trusted), actor=ENG)
        narrow = tmp_path / "narrow.json"
        narrow.write_text(json.dumps({**wide.to_dict(), "affected": [
            {"supplier": VENDOR, "name": "EX-100", "versions": ["V1"]}]}), encoding="utf-8")
        rc, out, err = change_cli(capsys, "assess-advisory", "--advisory", str(narrow),
                                  "--ledger", str(ledger_path), "--actor", "a.integrator")
        assert rc != 0 and first.case_id in err and "not updated" in err
        assert "[OPEN]" not in out
        assert case_store(ledger_path).get(first.case_id).machines == first.machines


# ===================================================================== F-10: cost and caps

class TestCostAndCaps:
    def test_fifty_thousand_artefacts_are_assessed_against_a_fleet_in_seconds(self, tmp_path):
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        n = 50_000
        ledger = make_ledger(
            tmp_path / "l.jsonl",
            *[manifest(f"S{i}", item("EX-100", "V1"), item("EX-200", "V1", iid="ITM-2"),
                       item("EX-300", "V1", iid="ITM-3")) for i in range(30)])
        d = doc([name_branch(f"EX-{i}", [leaf(f"P{i}", "V9")]) for i in range(n)],
                affected(*[f"P{i}" for i in range(n)]))
        advisory = advisory_from_csaf(d).advisory
        fleet = Fleet.from_ledger(ledger)
        start = time.perf_counter()
        report = assess_impact(advisory, fleet)
        assert time.perf_counter() - start < 3.0, "the matcher is linear in artefacts x items"
        assert report.verdict == "needs_review"      # EX-100 V1 is an unlisted label of EX-100

    def test_the_file_cap_is_proved_with_valid_json_just_over_it(self, tmp_path, monkeypatch):
        text = json.dumps(simple_doc())
        monkeypatch.setattr(csaf_module, "MAX_FILE_BYTES", len(text))
        rc, adv, _ = run_import(tmp_path, text)
        assert rc == 0 and adv is not None                       # exactly at the cap: read
        rc, adv, _ = run_import(tmp_path, text + " ")            # one valid byte over: refused
        assert rc == 2 and adv is None

    def test_the_stated_file_cap_bounds_memory(self):
        assert csaf_module.MAX_FILE_BYTES <= 8 * 1024 * 1024


# ===================================================================== round 1's survivors

class TestRoundOnesSurvivors:
    @pytest.mark.parametrize("value", [{}, False, 0, "", []])
    def test_a_falsy_import_record_is_malformed_not_absent(self, value):
        d = dict(advisory_from_csaf(simple_doc()).advisory.to_dict())
        d["import_record"] = value
        with pytest.raises(AdvisoryError):
            ComponentAdvisory.from_dict(d)

    def test_an_empty_per_component_fixed_version_is_refused(self):
        with pytest.raises(AdvisoryError):
            AffectedArtefact.from_dict({"supplier": "S", "name": "N", "versions": ["1"],
                                        "fixed_versions": [" "]})

    def test_a_pre_work_re_look_keeps_the_rows_it_already_has(self, tmp_path):
        from assurance.change import assess_advisory
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet

        ledger_path = tmp_path / "l.jsonl"
        ledger = make_ledger(ledger_path, manifest("A", item("EX-100", "V1")),
                             manifest("B", item("EX-100", "V2")))
        trusted = {"source": "supplier_feed", "trust_state": "pinned", "inspect_only": False,
                   "trust_basis": "pinned_key_policy", "automated_consequences_permitted": True}
        wide = ComponentAdvisory(
            advisory_id="EX-9", issued_by=VENDOR, issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            title="t", summary="s", severity=AdvisorySeverity.STOP_USE,
            affected=(AffectedArtefact(VENDOR, "EX-100", versions=("V1", "V2")),),
            reference="https://example.invalid/t")
        narrow = ComponentAdvisory.from_dict({**wide.to_dict(), "title": "again", "affected": [
            {"supplier": VENDOR, "name": "EX-100", "versions": ["V1"]}]})
        store = case_store(ledger_path)
        from .test_assurance_csaf_trust import ENG

        first = assess_advisory(store, assess_impact(wide, Fleet.from_ledger(ledger),
                                                     provenance=trusted), actor=ENG)
        again = assess_advisory(store, assess_impact(narrow, Fleet.from_ledger(ledger),
                                                     provenance=trusted), actor=ENG)
        kept = {c["item_id"] for c in again.changed_items}
        assert {c["item_id"] for c in first.changed_items} <= kept
        # the same advisory again does not duplicate its link
        assess_advisory(store, assess_impact(narrow, Fleet.from_ledger(ledger),
                                             provenance=trusted), actor=ENG)
        assert len(store.get(first.case_id).linked_evidence) == 2

    def test_the_enrolled_check_marks_a_partial_import_incomplete(self, client, account_store):  # noqa: F811
        from .test_assurance_change import fw, keyed
        from .test_assurance_change import manifest as cmanifest

        headers = keyed(account_store, "cell")
        assert client.post("/v1/machinery/manifest", headers=headers, json={
            "manifest": cmanifest(fw(), manifest_id="MAN-0412").to_dict()}).status_code == 200
        d = doc([name_branch("Other component", [leaf("P0", "1")])], affected("P0", "B"),
                vendor="ControlCo",
                extra_tree={"full_product_names": [{"product_id": "B", "name": "other"}]})
        machine = cmanifest(fw(), manifest_id="x").machine.key
        r = client.post("/v1/check/fleet-machine", headers=headers, json={
            "machine_key": machine, "advisory": advisory_from_csaf(d).advisory.to_dict()})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["incomplete"] is True and out["verdict"] != "no_impact_found"
        assert out["advisory_import"]["trust"] == "unsigned_inspect_only"
        assert out["advisory_provenance"]["inspect_only"] is True

    def test_art14_decisions_name_the_dropped_products(self, tmp_path, capsys):
        from assurance.bridge.cli import main

        make_ledger(tmp_path / "l.jsonl", manifest("0412", item("EX-100", "V2.001")))
        path = imported_file(tmp_path, doc(
            [name_branch("EX-100", [leaf("A", "V2.001")])], affected("A", "B"),
            extra_tree={"full_product_names": [{"product_id": "B", "name": "other"}]}))
        capsys.readouterr()
        main(["art14", str(path), "--ledger", str(tmp_path / "l.jsonl"), "--received-by",
              "a.integrator", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert any("incomplete translation" in d and "'B'" in d
                   for d in payload["decisions_required"])

    def test_fleet_advisory_json_carries_the_unsigned_note(self, tmp_path, capsys):
        make_ledger(tmp_path / "l.jsonl", manifest("0412", item("EX-100", "V2.001")))
        path = imported_file(tmp_path)
        _, payload, _ = fleet_advisory(path, tmp_path / "l.jsonl", capsys)
        assert any("unsigned CSAF import" in n and "EX-2026-001" in n
                   for n in payload["provenance_notes"])

    def test_the_free_advisory_check_lists_the_unsigned_import_as_unchecked(
            self, client, account_store):  # noqa: F811
        from .test_assurance_change import fw
        from .test_assurance_change import manifest as cmanifest

        d = doc([name_branch("Other component", [leaf("P0", "1")])], affected("P0"),
                vendor="ControlCo")
        r = client.post("/v1/fleet/advisory/check", json={
            "advisory": advisory_from_csaf(d).advisory.to_dict(),
            "manifest": cmanifest(fw(version="3.8.0"), manifest_id="M1").to_dict()})
        assert r.status_code == 200, r.text
        assert any("unsigned CSAF import" in c for c in r.json()["checks_skipped"])
