"""POST /v1/evidence/verify — the free, anonymous, stateless evidence checker.

Every export checked here is produced by the real ledger through the real
change-assurance flow (and the real machine-verification engine and attestation
signer); nothing is a hand-written JSON file. The tests tamper with those and
expect structured findings, never a 500, and never a bare "valid".
"""

from __future__ import annotations

import copy
import importlib
import json
import logging

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.api.evidence_routes import MAX_DEPTH, analyse
from assurance.attest import AttestationLog, SigningKey, attest
from assurance.billing.plans import PLANS
from assurance.change import CaseStore, assess_drift, claim
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
from assurance.evidence.verify_export import verify_export
from assurance.machinery.divergence import compare
from assurance.machinery.record import (
    interventions_from_ledger,
    record_intervention,
    record_manifest,
)
from assurance.machinery.staleness import VerificationRecord

from .test_assurance_change import (
    ENG,
    MACHINE,
    REVIEWER,
    intervention,
    item,
    manifest,
    seal_a_real_verification,
)

URL = "/v1/evidence/verify"
MARKER = "UNIQUE-MARKER-must-not-be-kept-4f1c9a"


# ---------------------------------------------------------------------------
# fixtures: genuine evidence, produced by the real engines
# ---------------------------------------------------------------------------
def build_real_ledger(path):
    """A ledger holding what a real change-assurance run leaves behind."""
    from datetime import UTC, datetime

    ledger = EvidenceLedger(path)
    store = CaseStore(ledger)
    record_manifest(ledger, manifest(manifest_id="BASE"))
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
    record_intervention(ledger, intervention())
    observed = manifest(item(content_hash="d" * 64), manifest_id="AFTER")
    divergence = compare(manifest(manifest_id="BASE"), observed)
    verifications = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
    interventions = interventions_from_ledger(ledger, MACHINE.key)
    case = assess_drift(store, divergence, observed, verifications, interventions, actor=ENG)
    assert case is not None
    claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
    return ledger, case.case_id


@pytest.fixture()
def real(tmp_path):
    ledger, case_id = build_real_ledger(tmp_path / "real" / "ledger.db")
    return ledger, case_id


@pytest.fixture()
def whole(real):
    return real[0].export()


@pytest.fixture()
def case_export(real):
    ledger, case_id = real
    return ledger.export(subject=case_id)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "service" / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "service" / "accounts.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.delenv("ASSURANCE_MAX_EVIDENCE_BODY_BYTES", raising=False)
    monkeypatch.delenv("ASSURANCE_MAX_BODY_BYTES", raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


def post(client, doc, **kw):
    body = doc if isinstance(doc, (bytes, str)) else json.dumps(doc)
    return client.post(URL, content=body, **kw)


def check(client, doc, **kw):
    response = post(client, doc, **kw)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# a genuine export
# ---------------------------------------------------------------------------
class TestGenuineLedgerExport:
    def test_a_whole_ledger_export_is_consistent_and_says_what_it_did_not_show(
            self, client, whole):
        result = check(client, whole)
        assert result["kind"] == "ledger_export"
        assert result["ok"] is True and result["outcome"] == "no_inconsistency_found"
        assert result["scope"] == "whole ledger"
        assert result["entries"] == len(whole["entries"]) >= 3
        assert result["problems"] == []
        assert result["stored"] is False
        # three separate lists, none of them empty, none merged
        assert any("hashes to the content hash" in f for f in result["verified"])
        assert any("actor column" in f for f in result["verified"])
        assert any("genesis" in f for f in result["verified"])
        assert any("not that it matches the ledger its operator holds" in n
                   for n in result["not_checked"])
        assert any("signed head attestation" in n for n in result["not_checked"])
        assert result["assumptions"]
        head = whole["entries"][-1]
        assert result["head"] == {"seq": head["seq"], "link_hash": head["link_hash"],
                                  "length": len(whole["entries"])}
        # the summary and the keys never say "valid"
        blob = json.dumps(result).lower()
        assert "valid" not in blob.replace("not valid json", "")

    def test_a_case_export_is_a_subject_bundle_and_names_its_limits(
            self, client, case_export):
        result = check(client, case_export)
        assert result["ok"] is True and result["kind"] == "ledger_export"
        assert result["scope"].startswith("subject ")
        assert any("one subject" in n and "other subjects" in n
                   for n in result["not_checked"])
        assert result["head"] is None  # a subject bundle has no ledger head to show

    def test_the_result_is_the_same_for_a_paid_key_and_is_not_capped(self, client, env):
        store = deps.get_accounts()
        account = store.upsert_account(email="p@example.de", tier="register",
                                       stripe_customer_id="cus_p")
        headers = {"X-API-Key": store.issue_key(account.id)}
        ledger = EvidenceLedger(env / "p.db")
        bundle = ledger.export()
        for _ in range(PLANS["free"].validations_per_day + 2):
            response = client.post(URL, content=json.dumps(bundle), headers=headers)
            assert response.status_code == 200
        assert "X-Assurance-Quota-Limit" not in response.headers


# ---------------------------------------------------------------------------
# every tamper class
# ---------------------------------------------------------------------------
def _edit_body(b):
    b["entries"][2]["evidence"]["body"]["tampered"] = 1


def _edit_one_char_of_a_hash(b):
    h = b["entries"][1]["content_hash"]
    b["entries"][1]["content_hash"] = ("0" if h[0] != "0" else "1") + h[1:]


def _edit_time(b):
    b["entries"][1]["at"] = "2020-01-01T00:00:00Z"


def _edit_actor_column(b):
    b["entries"][0]["actor"] = "someone.else"


def _edit_actor_inside_evidence(b):
    b["entries"][0]["evidence"]["actor"]["role"] = "chief executive"


def _reorder(b):
    e = b["entries"]
    e[1], e[2] = e[2], e[1]


def _remove_middle(b):
    del b["entries"][2]


def _truncate_tail(b):
    b["entries"] = b["entries"][:-2]


def _empty_vs_attestation(b):
    b["entries"] = []


def _drop_head_attestation(b):
    del b["attestation"]


def _unsealed_extra_field(b):
    b["entries"][0]["evidence"]["approved_by_regulator"] = True


def _unsealed_nested_extra(b):
    b["entries"][0]["evidence"]["actor"]["badge"] = "TUV"


def _wrong_format_version(b):
    b["ledger_schema_version"] = 99


def _seq_as_bool(b):
    b["entries"][0]["seq"] = True


def _seq_as_text(b):
    b["entries"][0]["seq"] = "1"


def _subject_not_text(b):
    b["subject"] = 5


def _entry_not_object(b):
    b["entries"][1] = "nope"


def _entry_missing_field(b):
    del b["entries"][1]["link_hash"]


def _evidence_not_object(b):
    b["entries"][1]["evidence"] = ["x"]


def _chain_verified_false(b):
    b["chain_verified"] = False


def _first_not_seq_one(b):
    del b["entries"][0]


def _duplicate_entry(b):
    b["entries"].insert(2, copy.deepcopy(b["entries"][1]))


TAMPERS = {
    "edit evidence body": _edit_body,
    "edit one character of a content hash": _edit_one_char_of_a_hash,
    "edit a timestamp": _edit_time,
    "edit the actor column": _edit_actor_column,
    "edit the actor inside the evidence": _edit_actor_inside_evidence,
    "reorder two entries": _reorder,
    "remove a middle entry": _remove_middle,
    "truncate the tail": _truncate_tail,
    "empty the entries but keep the attestation": _empty_vs_attestation,
    "drop the head attestation": _drop_head_attestation,
    "add an unsealed field to the evidence": _unsealed_extra_field,
    "add an unsealed field inside the actor": _unsealed_nested_extra,
    "unsupported format version": _wrong_format_version,
    "seq as a boolean": _seq_as_bool,
    "seq as text": _seq_as_text,
    "subject that is not text": _subject_not_text,
    "entry that is not an object": _entry_not_object,
    "entry missing a field": _entry_missing_field,
    "evidence that is not an object": _evidence_not_object,
    "chain_verified false": _chain_verified_false,
    "bundle that does not start at seq 1": _first_not_seq_one,
    "duplicated entry": _duplicate_entry,
}


class TestTamperedLedgerExport:
    @pytest.mark.parametrize("name", sorted(TAMPERS))
    def test_each_tamper_is_a_structured_finding(self, client, whole, name):
        TAMPERS[name](whole)
        result = check(client, whole)
        assert result["ok"] is False, name
        assert result["outcome"] == "inconsistent", name
        assert result["problems"], name
        assert result["verified"] is not None
        # a file with a problem never carries the whole-file facts
        assert not any("genesis" in f for f in result["verified"]), name
        assert not any("declares ledger format" in f for f in result["verified"]), name

    def test_one_byte_of_the_serialised_file_is_found(self, client, whole):
        text = json.dumps(whole, sort_keys=True)
        marker = '"n": 0' if '"n": 0' in text else None
        index = text.index('"kind"', text.index('"entries"')) + 3
        flipped = text[:index] + ("X" if text[index] != "X" else "Y") + text[index + 1:]
        result = check(client, flipped)
        assert result["ok"] is False
        assert marker is None or result["problems"]

    def test_a_tampered_subject_bundle_is_found_too(self, client, case_export):
        case_export["entries"][1]["evidence"]["body"]["x"] = 1
        result = check(client, case_export)
        assert result["ok"] is False and result["problems"]

    def test_a_foreign_entry_in_a_subject_bundle_is_found(self, client, case_export):
        case_export["subject"] = "SOME-OTHER-SUBJECT"
        result = check(client, case_export)
        assert result["ok"] is False
        assert any("belongs to subject" in p for p in result["problems"])

    def test_a_genuinely_empty_ledger_is_consistent_but_shows_nothing(self, client, tmp_path):
        empty = EvidenceLedger(tmp_path / "empty.db").export()
        result = check(client, empty)
        assert result["ok"] is True and result["entries"] == 0
        assert any("no entries" in n for n in result["not_checked"])
        assert not any("hashes to the content hash" in f for f in result["verified"])

    def test_a_problem_file_still_names_the_checks_that_ran_clean(self, client, whole):
        _edit_actor_column(whole)
        result = check(client, whole)
        assert any("hashes to the content hash" in f for f in result["verified"])
        assert not any("actor column" in f for f in result["verified"])


# ---------------------------------------------------------------------------
# input that is not an evidence file
# ---------------------------------------------------------------------------
GARBAGE = {
    "empty": b"",
    "whitespace": b"  \n ",
    "not json": b"this is not json",
    "truncated json": b'{"entries": [{"seq": 1',
    "null": b"null",
    "number": b"42",
    "string": b'"entries"',
    "empty object": b"{}",
    "empty list": b"[]",
    "entries not a list": b'{"entries": 5}',
    "bytes that are not utf-8": b"\xff\xfe\x00garbage\x80",
    "nan constant": b'{"entries": [], "x": NaN}',
    "infinity constant": b'{"entries": [], "x": -Infinity}',
    "huge integer": b'{"entries": [], "x": ' + b"9" * 6000 + b"}",
    "plain object of the wrong shape": b'{"hello": "world"}',
    "list of numbers": b"[1, 2, 3]",
}


class TestNotAnEvidenceFile:
    @pytest.mark.parametrize("name", sorted(GARBAGE))
    def test_garbage_is_a_structured_result_never_a_500(self, client, name):
        response = post(client, GARBAGE[name])
        assert response.status_code == 200, (name, response.text)
        result = response.json()
        assert result["ok"] is False
        assert result["outcome"] in {"unreadable", "unsupported", "inconsistent"}
        assert result["problems"], name
        assert result["verified"] == []
        assert result["not_checked"], name

    def test_duplicate_keys_are_refused_not_resolved(self, client, whole):
        text = json.dumps(whole)
        doubled = text[:-1] + ', "subject": "someone-else"}'
        result = check(client, doubled)
        assert result["outcome"] == "unreadable"
        assert "appears twice" in result["problems"][0]

    def test_duplicate_keys_nested_inside_an_entry_are_refused(self, client, whole):
        text = json.dumps(whole)
        text = text.replace('"seq": 1,', '"seq": 1, "seq": 2,', 1)
        assert check(client, text)["outcome"] == "unreadable"

    @pytest.mark.parametrize("shape", ["[", "{\"a\":"])
    def test_hostile_nesting_is_refused_without_recursing_the_server(self, client, shape):
        closing = {"[": "]", "{\"a\":": "}"}[shape]
        deep = shape * 200_000 + "1" + closing * 200_000
        result = check(client, deep)
        assert result["outcome"] == "unreadable" and result["ok"] is False

    def test_nesting_beyond_the_limit_inside_a_real_bundle_is_refused(self, client, whole):
        node: dict = {}
        cursor = node
        for _ in range(MAX_DEPTH + 5):
            cursor["n"] = {}
            cursor = cursor["n"]
        whole["entries"][0]["evidence"]["body"]["deep"] = node
        result = check(client, whole)
        assert result["outcome"] == "unreadable"
        assert "levels deep" in result["problems"][0]

    def test_a_utf8_bom_from_a_windows_editor_is_tolerated(self, client, whole):
        result = check(client, b"\xef\xbb\xbf" + json.dumps(whole).encode())
        assert result["ok"] is True

    def test_other_json_objects_say_what_is_supported(self, client):
        result = check(client, {"hello": "world"})
        assert result["outcome"] == "unsupported" and result["kind"] == "unknown"
        assert any("ledger export" in n for n in result["not_checked"])
        assert any("machine verification bundle" in n for n in result["not_checked"])

    def test_a_check_that_crashes_is_reported_as_not_a_pass(self, monkeypatch):
        from assurance.api import evidence_routes

        def boom(_doc):
            raise RuntimeError("boom")

        monkeypatch.setattr(evidence_routes, "verify_export", boom)
        result = analyse(json.dumps({"entries": []}).encode())
        assert result["ok"] is False and result["outcome"] == "check_failed"


# ---------------------------------------------------------------------------
# machine verification bundle
# ---------------------------------------------------------------------------
@pytest.fixture()
def machine_bundle(tmp_path):
    from datetime import UTC, datetime

    led = EvidenceLedger(tmp_path / "m" / "m.db")
    return seal_a_real_verification(led, when=datetime(2026, 2, 9, tzinfo=UTC)).to_dict()


class TestMachineBundle:
    def test_a_genuine_bundle_reports_tier_and_what_it_cannot_show(self, client, machine_bundle):
        result = check(client, machine_bundle)
        assert result["kind"] == "machine_bundle" and result["ok"] is True
        tier = result["tier"]
        assert tier["recorded_tier"] == machine_bundle["result"]["tier"]
        assert tier["recorded_verdict"] == machine_bundle["result"]["verdict"]
        assert isinstance(tier["may_claim_physical_behaviour"], bool)
        assert tier["evidence_required"]
        assert any("hashes to the hash it carries" in f for f in result["verified"])
        assert any("envelope copy" in f for f in result["verified"])
        assert any("nothing here shows the machine behaved" in n
                   for n in result["not_checked"])
        assert any("never recorded in a ledger" in n or "ever recorded in a ledger" in n
                   for n in result["not_checked"])

    def test_editing_the_sealed_verdict_is_found(self, client, machine_bundle):
        machine_bundle["evidence"]["body"]["verdict"] = "pass"
        machine_bundle["evidence"]["body"]["checks"][0]["outcome"] = "violated"
        result = check(client, machine_bundle)
        assert result["ok"] is False and result["verified"] == []
        assert any("edited after sealing" in p for p in result["problems"])

    def test_a_hand_written_verdict_that_its_own_checks_contradict_is_found(
            self, client, machine_bundle):
        # reseal-proof: change the verdict inside the evidence AND keep the hash
        # consistent by editing only the readable copy.
        machine_bundle["result"]["verdict"] = "fail"
        result = check(client, machine_bundle)
        assert result["ok"] is False
        assert any("unsealed result block" in p for p in result["problems"])

    def test_editing_the_readable_tier_is_found(self, client, machine_bundle):
        machine_bundle["result"]["tier"] = "certified"
        result = check(client, machine_bundle)
        assert result["ok"] is False
        assert any("tier" in p for p in result["problems"])

    def test_editing_the_readable_envelope_is_found(self, client, machine_bundle):
        machine_bundle["envelope"]["intrusion_distance_mm"] = 1.0
        result = check(client, machine_bundle)
        assert result["ok"] is False
        assert any("envelope copy" in p for p in result["problems"])

    def test_an_unreadable_envelope_copy_is_found(self, client, machine_bundle):
        machine_bundle["envelope"] = {"nonsense": True}
        result = check(client, machine_bundle)
        assert result["ok"] is False

    def test_another_schema_is_found(self, client, machine_bundle):
        machine_bundle["schema"] = "assurance.machine.bundle/9"
        result = check(client, machine_bundle)
        assert result["ok"] is False
        assert any("schema" in p for p in result["problems"])

    def test_a_bundle_with_a_broken_sealed_object_is_a_finding_not_a_crash(
            self, client, machine_bundle):
        machine_bundle["evidence"] = {"kind": "x"}
        result = check(client, machine_bundle)
        assert result["ok"] is False and result["problems"]

    def test_the_route_agrees_with_the_existing_bundle_check_on_a_genuine_bundle(
            self, client, machine_bundle):
        old = client.post("/v1/machine/bundle/check", json={"bundle": machine_bundle}).json()
        new = check(client, machine_bundle)
        assert old["ok"] is True and new["ok"] is True
        assert old["recorded_tier"] == new["tier"]["recorded_tier"]


# ---------------------------------------------------------------------------
# signed head attestations
# ---------------------------------------------------------------------------
@pytest.fixture()
def signed(tmp_path):
    ledger, _ = build_real_ledger(tmp_path / "att" / "ledger.db")
    key = SigningKey.generate()
    log = AttestationLog(tmp_path / "att" / "log.jsonl")
    attest(ledger, key, log, note="first")
    ledger.append(
        Evidence(kind="t.more", body={"n": 1}, actor=Actor("a.person", "engineer"),
                 origin=Origin("pytest")).seal(), subject="S")
    attest(ledger, key, log, note="second")
    return {
        "records": [r.to_dict() for r in log.read()],
        "text": (tmp_path / "att" / "log.jsonl").read_text(),
        "pem": key.verifying.pem(),
        "other_pem": SigningKey.generate().verifying.pem(),
        "ledger": ledger,
    }


class TestAttestationLog:
    def test_without_a_key_only_the_structure_is_checked_and_the_page_says_so(
            self, client, signed):
        result = check(client, {"attestations": signed["records"]})
        assert result["kind"] == "attestation_log" and result["ok"] is True
        assert any("NOT verified" in n for n in result["not_checked"])
        assert not any("signature(s) verify" in f for f in result["verified"])
        assert result["head"]["length"] == signed["records"][-1]["ledger_length"]

    def test_with_the_issuers_key_the_signatures_are_checked(self, client, signed):
        result = check(client, signed["records"],
                       params={"public_key_pem": signed["pem"]})
        assert result["ok"] is True
        assert any("signature(s) verify against the public key you supplied" in f
                   for f in result["verified"])
        assert any("channel" in a for a in result["assumptions"])
        assert any("ledger itself was not examined" in n for n in result["not_checked"])

    def test_the_wrong_key_is_a_finding(self, client, signed):
        result = check(client, signed["records"],
                       params={"public_key_pem": signed["other_pem"]})
        assert result["ok"] is False
        assert any("signature does not verify" in p for p in result["problems"])

    def test_an_edited_record_fails_the_signature_check(self, client, signed):
        signed["records"][1]["ledger_length"] += 5
        result = check(client, signed["records"],
                       params={"public_key_pem": signed["pem"]})
        assert result["ok"] is False

    def test_an_edited_record_is_not_visible_without_the_key_and_says_so(
            self, client, signed):
        # A change to a signed field that keeps the chain intact is exactly what
        # needs the key: without it the page must not claim signatures hold.
        signed["records"][1]["note"] = "edited"
        result = check(client, signed["records"])
        assert any("NOT verified" in n for n in result["not_checked"])
        assert result["verified"] == [] or not any(
            "signature(s) verify" in f for f in result["verified"])

    def test_a_removed_middle_record_is_found_without_a_key(self, client, signed):
        result = check(client, [signed["records"][1]])
        assert result["ok"] is False
        assert any("out of order" in p or "does not name" in p for p in result["problems"])

    def test_a_spliced_log_is_found_without_a_key(self, client, signed):
        signed["records"][1]["previous"] = "0" * 64
        result = check(client, signed["records"])
        assert result["ok"] is False
        assert any("does not name the attestation before it" in p for p in result["problems"])

    def test_a_shortened_ledger_between_two_attestations_is_found(self, client, signed):
        a, b = signed["records"]
        b["ledger_length"] = a["ledger_length"] - 1
        result = check(client, [a, b])
        assert result["ok"] is False and any("fewer records" in p for p in result["problems"])

    def test_the_jsonl_file_the_cli_writes_is_accepted(self, client, signed):
        result = check(client, signed["text"], params={"public_key_pem": signed["pem"]})
        assert result["kind"] == "attestation_log" and result["ok"] is True

    def test_a_single_record_and_the_attest_response_shape_are_accepted(self, client, signed):
        assert check(client, signed["records"][0])["kind"] == "attestation_log"
        assert check(client, {"attestation": signed["records"][0]})["kind"] == "attestation_log"

    def test_an_unreadable_key_is_a_structured_result(self, client, signed):
        result = check(client, signed["records"], params={"public_key_pem": "-----BEGIN junk"})
        assert result["outcome"] == "unreadable"
        assert "public key" in result["problems"][0]

    def test_a_record_missing_fields_is_a_finding(self, client, signed):
        del signed["records"][0]["head_link_hash"]
        broken = [signed["records"][0], signed["records"][1]]
        result = check(client, broken)
        assert result["ok"] is False

    def test_key_free_structure_checks_agree_with_verify_log(self, signed):
        """The key-free subset must not accept what the full verifier rejects."""
        from assurance.api.evidence_routes import _structure_problems
        from assurance.attest import HeadAttestation, VerifyingKey, verify_log

        key = VerifyingKey.from_pem(signed["pem"])
        for mutate in (
            lambda r: r[1].update(previous="1" * 64),
            lambda r: r[1].update(sequence=7),
            lambda r: r[1].update(ledger_length=0, head_seq=0, head_link_hash="0" * 64),
        ):
            records = copy.deepcopy(signed["records"])
            mutate(records)
            parsed = [HeadAttestation.from_dict(r) for r in records]
            assert not verify_log(parsed, key).ok
            assert _structure_problems(parsed), "key-free check missed what verify_log found"

    def test_an_export_head_can_be_joined_to_a_signed_head_by_the_reader(self, client, signed):
        export = signed["ledger"].export()
        shown = check(client, export)["head"]
        latest = signed["records"][-1]
        assert shown["seq"] == latest["head_seq"]
        assert shown["link_hash"] == latest["head_link_hash"]


# ---------------------------------------------------------------------------
# metering, body cap, statelessness
# ---------------------------------------------------------------------------
class TestQuota:
    def test_an_anonymous_address_has_a_daily_allowance_and_then_a_429(self, client, whole):
        limit = PLANS["free"].validations_per_day
        assert limit is not None
        for used in range(1, limit + 1):
            response = post(client, whole)
            assert response.status_code == 200
            assert response.headers["X-Assurance-Quota-Remaining"] == str(limit - used)
        blocked = post(client, whole)
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        assert detail["error"] == "quota_exceeded" and detail["scope"] == "evidence_verify"

    def test_the_allowance_is_its_own_bucket(self, client, whole):
        limit = PLANS["free"].validations_per_day
        for _ in range(limit):
            assert post(client, whole).status_code == 200
        assert post(client, whole).status_code == 429
        # the Article 14 validator's allowance is untouched
        assert client.post("/v1/spec/validate", json={}).status_code != 429

    def test_a_429_does_not_parse_the_body(self, client, whole, monkeypatch):
        from assurance.api import evidence_routes

        limit = PLANS["free"].validations_per_day
        for _ in range(limit):
            post(client, b"{}")
        monkeypatch.setattr(evidence_routes, "analyse",
                            lambda *a, **k: pytest.fail("parsed after the quota was spent"))
        assert post(client, whole).status_code == 429

    def test_the_other_free_verifiers_stay_unmetered(self, client, machine_bundle):
        for _ in range(PLANS["free"].validations_per_day + 3):
            assert client.post("/v1/machine/bundle/check",
                               json={"bundle": machine_bundle}).status_code == 200

    def test_a_bad_key_is_still_a_401(self, client, whole):
        assert post(client, whole, headers={"X-API-Key": "nope"}).status_code == 401


class TestBodyCap:
    def test_the_path_cap_is_a_few_mebibytes_for_everyone_and_nothing_else_changes(self):
        assert deps.max_body_bytes(URL) == 4 * 1024 * 1024
        assert deps.max_body_bytes(URL, authenticated=True) == 4 * 1024 * 1024
        assert deps.max_body_bytes("/v1/spec/validate") == 1024 * 1024
        assert deps.max_body_bytes("/v1/machine/verify") == 1024 * 1024
        assert deps.max_body_bytes("/v1/machine/bundle/check") == 1024 * 1024

    def test_a_declared_oversize_body_is_a_413_for_an_anonymous_caller(self, client):
        response = client.post(URL, content=b" " * (4 * 1024 * 1024 + 1))
        assert response.status_code == 413
        assert response.json()["detail"]["limit_bytes"] == 4 * 1024 * 1024

    def test_a_chunked_body_that_declares_nothing_is_counted_as_it_arrives(self, client):
        def chunks():
            for _ in range(5):
                yield b" " * (1024 * 1024)

        response = client.post(URL, content=chunks())
        assert response.status_code == 413

    def test_a_bundle_of_a_few_mebibytes_is_accepted_and_checked(self, client, whole):
        whole["entries"][0]["evidence"]["body"]["pad"] = "x" * (3 * 1024 * 1024)
        response = post(client, whole)
        assert response.status_code == 200
        assert response.json()["ok"] is False  # padded after sealing: found, not refused

    def test_the_cap_follows_its_environment_variable(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_EVIDENCE_BODY_BYTES", "2000")
        assert post(client, b" " * 3000).status_code == 413
        assert post(client, b"{}").status_code == 200


class TestNothingIsKept:
    def test_nothing_about_the_file_is_stored_or_logged(self, client, whole, env, caplog):
        whole["entries"][0]["evidence"]["body"]["note"] = MARKER
        caplog.set_level(logging.DEBUG)
        before = {p for p in (env / "service").rglob("*") if p.is_file()}
        result = check(client, whole)
        assert result["ok"] is False  # edited, so a finding — and still not kept
        assert MARKER not in caplog.text
        assert MARKER not in json.dumps(result)
        for path in (p for p in env.rglob("*") if p.is_file()):
            assert MARKER.encode() not in path.read_bytes(), path
        created = {p for p in (env / "service").rglob("*") if p.is_file()} - before
        # the accounts store may be created for the quota counter; no ledger is
        assert not any(p.name.startswith("art14") for p in created)
        assert not any((env / "service").rglob("tenants/*"))

    def test_the_response_is_not_cacheable(self, client, whole):
        assert post(client, whole).headers["Cache-Control"] == "no-store"


# ---------------------------------------------------------------------------
# the verifier itself (src/assurance/evidence/verify_export.py)
# ---------------------------------------------------------------------------
class TestVerifierStrictness:
    """Things the offline verifier used to accept and must not."""

    def test_an_unsealed_extra_field_on_the_evidence_is_found(self, whole):
        whole["entries"][0]["evidence"]["approved_by_regulator"] = True
        result = verify_export(whole)
        assert not result.ok and any("seal does not cover" in p for p in result.problems)

    def test_an_unsupported_format_version_is_found(self, whole):
        whole["ledger_schema_version"] = 99
        assert any("unsupported ledger format" in p for p in verify_export(whole).problems)

    def test_a_missing_format_version_is_found(self, whole):
        del whole["ledger_schema_version"]
        assert not verify_export(whole).ok

    @pytest.mark.parametrize("bad", [True, "1", 1.0, None, 0, -1])
    def test_seq_must_be_a_real_positive_integer(self, whole, bad):
        whole["entries"][0]["seq"] = bad
        assert not verify_export(whole).ok

    def test_a_genuine_export_carries_every_fact_and_the_limits(self, whole):
        result = verify_export(whole)
        assert result.ok and len(result.verified) >= 6
        assert result.assumptions and result.checks_skipped
        assert "CHECKED" in result.text() and "NOT CHECKED" in result.text()
        assert "ASSUMED" in result.text()
        assert result.to_dict()["verified"] == list(result.verified)

    def test_the_recorded_at_limit_is_stated_because_nothing_authenticates_it(self, whole):
        # Documented, not fixed: the evidence's own recorded_at is outside its
        # seal. If this ever starts failing the limit can be dropped from the text.
        whole["entries"][0]["evidence"]["recorded_at"] = "2019-01-01T00:00:00Z"
        result = verify_export(whole)
        assert result.ok
        assert any("recorded_at" in c for c in result.checks_skipped)
