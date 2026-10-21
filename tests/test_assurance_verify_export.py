"""An exported bundle must be checkable by someone with only the file.

Each test tampers with a bundle the real ledger exported and expects the
offline verifier — which reads no ledger — to say so.
"""

from __future__ import annotations

import copy
import json

import pytest

from assurance.cli import main as cli_main
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger
from assurance.evidence.verify_export import verify_export, verify_export_file


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


@pytest.fixture()
def ledger(tmp_path):
    led = EvidenceLedger(tmp_path / "e.db")
    for i in range(6):
        led.append(_ev(i), subject="CASE-A" if i % 2 == 0 else "CASE-B")
    return led


def test_a_whole_bundle_verifies(ledger):
    result = verify_export(ledger.export())
    assert result.ok and result.entries == 6 and result.scope == "whole ledger"
    assert any("attest" in c for c in result.checks_skipped)


def test_a_subject_bundle_verifies_and_says_what_it_did_not_check(ledger):
    result = verify_export(ledger.export(subject="CASE-A"))
    assert result.ok and result.entries == 3
    assert any("one subject" in c for c in result.checks_skipped)


def test_editing_an_evidence_body_is_found(ledger):
    bundle = ledger.export()
    bundle["entries"][2]["evidence"]["body"]["n"] = 999
    result = verify_export(bundle)
    assert not result.ok and any("edited" in p for p in result.problems)


def test_editing_a_link_field_is_found(ledger):
    bundle = ledger.export()
    bundle["entries"][1]["at"] = "2020-01-01T00:00:00Z"
    assert not verify_export(bundle).ok


def test_removing_a_middle_record_of_a_whole_bundle_is_found(ledger):
    bundle = ledger.export()
    del bundle["entries"][3]
    result = verify_export(bundle)
    assert not result.ok


def test_cutting_records_from_the_end_is_found_by_the_attestation(ledger):
    bundle = ledger.export()
    bundle["entries"] = bundle["entries"][:-2]
    result = verify_export(bundle)
    assert not result.ok and any("cut from the end" in p for p in result.problems)


def test_a_foreign_entry_in_a_subject_bundle_is_found(ledger):
    bundle = ledger.export(subject="CASE-A")
    bundle["subject"] = "CASE-B"
    assert not verify_export(bundle).ok


def test_swapping_in_evidence_with_a_valid_hash_but_another_identity_is_found(ledger):
    bundle = copy.deepcopy(ledger.export())
    other = _ev(42).to_dict()
    bundle["entries"][0]["evidence"] = other
    assert not verify_export(bundle).ok


@pytest.mark.parametrize("junk", [None, [], "x", {}, {"entries": "no"}])
def test_garbage_is_reported_not_raised(junk):
    assert not verify_export(junk).ok


def test_cli_exit_codes_separate_wrong_from_unreadable(ledger, tmp_path, capsys):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(ledger.export()))
    bad_bundle = ledger.export()
    bad_bundle["entries"][0]["evidence"]["body"]["n"] = -1
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(bad_bundle))
    assert cli_main(["evidence", "verify", str(good)]) == 0
    assert cli_main(["evidence", "verify", str(bad)]) == 1
    assert cli_main(["evidence", "verify", str(tmp_path / "missing.json")]) == 2
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "DOES NOT VERIFY" in out
    assert verify_export_file(good).ok


def test_an_empty_whole_bundle_cannot_hide_an_attestation_naming_records(ledger):
    bundle = ledger.export()
    bundle["entries"] = []
    result = verify_export(bundle)
    assert not result.ok and any("cut from the end" in p for p in result.problems)


def test_a_genuinely_empty_ledger_still_verifies(tmp_path):
    empty = EvidenceLedger(tmp_path / "empty.db")
    assert verify_export(empty.export()).ok


def test_rewriting_the_actor_column_is_found(ledger):
    bundle = ledger.export()
    bundle["entries"][0]["actor"] = "someone.else"
    result = verify_export(bundle)
    assert not result.ok and any("actor" in p for p in result.problems)
