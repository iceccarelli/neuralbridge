"""Review findings on the export verifier, each pinned by a test that fails without its guard.

* A-H1: a head the signer was only TOLD (``declared_by_holder``) is not an anchor.
  Any paid account can have the one service key sign three numbers it made up, so a
  fabricated, back-dated, re-linked ledger carrying such a signature must never read
  as ``anchored``; and a record dated after the head was signed cannot be under it.
* C-H1: "completeness could not be established" is not "this file was tampered with".
* A-M2: the skeleton, genesis, empty-subject and printed-result guards each fail a test
  when removed.
* A-M3: the seal hashes every number as ``round(float(v), 6)``; a number that rounding
  cannot tell from its neighbour is reported, not silently called sealed.
* A-L6 / A-L7: the CLI exit status, and a file that makes the attestation reader overflow.
"""

# ruff: noqa: F811 - fixtures imported from the export-api tests are used by name
from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from assurance.attest import AttestationLog, SigningKey, attest
from assurance.attest.attestation import AttestationBasis, LedgerHead
from assurance.cli import main as cli_main
from assurance.core import Actor, Evidence, Origin
from assurance.core.errors import EvidenceIncompleteError
from assurance.evidence import EvidenceLedger
from assurance.evidence.ledger import GENESIS, LedgerEntry
from assurance.evidence.verify_export import (
    ANCHORED,
    ANCHORED_PARTIAL,
    DECLARED_HEAD,
    FAILED,
    NOT_CHECKED,
    verify_export,
)
from assurance.machine.bundle import check_bundle_data

from .test_assurance_export_api import (  # noqa: F401 - fixtures
    _account,
    _check,
    _read_sign,
    _service_key_header,
    _signal,
    api,
    tenants,
)
from .test_assurance_export_completeness import _ev, _relink, _rewrite_attestation
from .test_assurance_machine_provenance import honest_raw


def _ledger(tmp_path, n=5, name="l.db"):
    led = EvidenceLedger(tmp_path / name)
    for i in range(n):
        led.append(_ev(i), subject="CASE-A" if i % 2 == 0 else "CASE-B")
    return led


def _declared(tmp_path, bundle, key, name="declared.jsonl"):
    """What POST /v1/ledger/attest does: the service signs three numbers it was handed."""
    head = bundle["entries"][-1]
    log = AttestationLog(tmp_path / name)
    return attest(LedgerHead(len(bundle["entries"]), head["seq"], head["link_hash"],
                             AttestationBasis.DECLARED_BY_HOLDER), key, log)


def _fabricate(tmp_path, n=5, dated="2019-03-{:02d}T10:00:00Z"):
    """A whole-ledger bundle made up offline: back-dated, re-linked, own head rewritten."""
    bundle = _ledger(tmp_path, n).export()
    for i, e in enumerate(bundle["entries"], start=1):
        e["at"] = dated.format(i)
    bundle["entries"] = _relink(bundle["entries"])
    _rewrite_attestation(bundle, bundle["entries"])
    return bundle


# ---------------------------------------------------------------------------
# A-H1
# ---------------------------------------------------------------------------
class TestADeclaredHeadIsNotAnAnchor:
    def test_a_fabricated_backdated_ledger_with_a_declared_signature_is_never_anchored(
            self, tmp_path):
        key = SigningKey.generate()
        bundle = _fabricate(tmp_path)
        bundle["anchor"] = _declared(tmp_path, bundle, key).to_dict()
        r = verify_export(bundle, trusted_key=key.verifying)
        assert r.completeness == DECLARED_HEAD
        assert r.completeness not in (ANCHORED, ANCHORED_PARTIAL)
        assert r.ok  # no inconsistency was found; that is all `ok` ever means
        assert r.anchor and r.anchor["basis"] == "declared_by_holder"
        text = r.text()
        assert "anchored to a signed head" not in text
        assert not text.startswith("VERIFIED")
        first = text.splitlines()[0].lower()
        assert "declared" in first and "never" in first
        assert any("never read the chain" in a or "did not read the chain" in a
                   or "never saw" in a for a in r.assumptions)
        assert r.checks_skipped[0].startswith("COMPLETENESS NOT CHECKED")

    def test_entries_dated_after_the_head_was_signed_cannot_be_under_it(self, tmp_path):
        key = SigningKey.generate()
        bundle = _fabricate(tmp_path, dated="2031-01-{:02d}T00:00:00Z")
        bundle["anchor"] = _declared(tmp_path, bundle, key).to_dict()
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and r.completeness == FAILED
        assert any("dated" in p and "after" in p and "signed" in p for p in r.problems)

    def test_an_unreadable_timestamp_cannot_dodge_the_time_check(self, tmp_path):
        key = SigningKey.generate()
        bundle = _fabricate(tmp_path, dated="sometime-{}")
        bundle["anchor"] = _declared(tmp_path, bundle, key).to_dict()
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and r.completeness == FAILED
        assert any("not a timestamp" in p for p in r.problems)

    def test_a_read_anchor_is_held_to_the_same_clock(self, tmp_path):
        """A record the signer read at time T cannot be dated after T."""
        led = _ledger(tmp_path, 4)
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)
        bundle = led.export(anchor=log.require_last().to_dict())
        assert verify_export(bundle, trusted_key=key.verifying).completeness == ANCHORED
        later = copy.deepcopy(bundle)
        later["entries"][1]["at"] = "2099-01-01T00:00:00Z"
        later["entries"] = _relink(later["entries"])
        _rewrite_attestation(later, later["entries"])
        r = verify_export(later, trusted_key=key.verifying)
        assert not r.ok and r.completeness == FAILED

    def test_records_after_the_signed_head_may_be_newer_than_it(self, tmp_path):
        led = _ledger(tmp_path, 3)
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)
        led.append(_ev(9), subject="CASE-A")
        r = verify_export(led.export(anchor=log.require_last().to_dict()),
                          trusted_key=key.verifying)
        assert r.ok and r.completeness == ANCHORED_PARTIAL

    def test_an_honest_declared_head_is_still_a_declared_head_not_an_anchor(self, tmp_path):
        led = _ledger(tmp_path, 4)
        key = SigningKey.generate()
        bundle = led.export()
        bundle["anchor"] = _declared(tmp_path, bundle, key).to_dict()
        r = verify_export(bundle, trusted_key=key.verifying)
        assert r.ok and r.completeness == DECLARED_HEAD

    def test_a_declared_head_still_catches_a_cut(self, tmp_path):
        """What it does do: a bundle shorter than the declared head contradicts it."""
        led = _ledger(tmp_path, 6)
        key = SigningKey.generate()
        full = led.export()
        anchor = _declared(tmp_path, full, key).to_dict()
        cut = copy.deepcopy(full)
        cut["entries"] = cut["entries"][:4]
        _rewrite_attestation(cut, cut["entries"])
        cut["anchor"] = anchor
        r = verify_export(cut, trusted_key=key.verifying)
        assert not r.ok and r.completeness == FAILED

    def test_a_read_anchor_beside_a_declared_one_still_anchors(self, tmp_path):
        led = _ledger(tmp_path, 4)
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)
        bundle = led.export(anchor=log.require_last().to_dict())
        declared = _declared(tmp_path, bundle, key, name="d.jsonl")
        r = verify_export(bundle, trusted_key=key.verifying, anchors=[declared])
        assert r.ok and r.completeness == ANCHORED
        assert r.anchor["basis"] == "read_from_ledger"

    def test_the_api_names_the_basis_and_never_says_anchored(self, api):
        """The forgery from the review: a tenant buys the service's signature on a head it
        invented, embeds it in a fabricated, back-dated whole-ledger file, and verifies it."""
        _, ha = _account("forger@example.de")
        _signal(api, ha, "C1")
        _signal(api, ha, "C2")
        bundle = api.get("/v1/cases/C1/export", headers=ha).json()
        entries = bundle["entries"]
        for i, e in enumerate(entries, start=1):
            e["at"] = f"2019-01-{i:02d}T00:00:00Z"
        entries = _relink(entries)
        bundle["subject"] = ""
        for k in ("skeleton", "skeleton_truncated", "anchor"):
            bundle.pop(k, None)
        _rewrite_attestation(bundle, entries)
        r = api.post("/v1/ledger/attest", headers=ha, json={
            "ledger_length": len(entries), "head_seq": len(entries),
            "head_link_hash": entries[-1]["link_hash"]})
        assert r.status_code == 200, r.text
        bundle["anchor"] = r.json()["attestation"]
        got = _check(api, bundle, _service_key_header(api))
        assert got["completeness"] == "declared_head"
        assert got["completeness"] != "anchored"
        assert got["anchor"]["basis"] == "declared_by_holder"
        assert got["outcome"] == "no_inconsistency_found"  # `ok` is not "complete"
        summary = got["summary"].lower()
        assert "declared_by_holder" in summary and "never read the chain" in summary
        assert "which signs its last record" not in summary
        assert got["not_checked"][0].startswith("COMPLETENESS NOT CHECKED")

    def test_the_api_names_the_basis_of_a_read_anchor_too(self, tenants):
        api, (_, ha), _, _ = tenants
        got = _check(api, api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json(),
                     _service_key_header(api))
        assert got["completeness"] == "anchored_partial"
        assert got["anchor"]["basis"] == "read_from_ledger"
        assert "read_from_ledger" in got["summary"]


# ---------------------------------------------------------------------------
# C-H1
# ---------------------------------------------------------------------------
class TestCompletenessNotEstablishedIsNotTampering:
    def test_an_untouched_default_hosted_export_is_not_called_tampered(self, tenants):
        api, (_, ha), _, _ = tenants
        bundle = api.get("/v1/cases/C1/export", headers=ha).json()
        got = _check(api, bundle, _service_key_header(api))
        assert got["outcome"] == "not_established"
        assert got["ok"] is False
        assert got["problems"] == []
        assert got["completeness"] == "not_checked"
        assert got["summary"].startswith("Completeness could not be established")
        assert "skeleton=true" in got["summary"]
        assert "not what the exporter wrote" not in json.dumps(got)
        assert any("skeleton" in u for u in got["unestablished"])

    def test_the_same_file_with_its_skeleton_is_established(self, tenants):
        api, (_, ha), _, _ = tenants
        got = _check(api, api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json(),
                     _service_key_header(api))
        assert got["ok"] and got["unestablished"] == []

    def test_a_removed_anchor_is_not_established_but_a_rebuilt_chain_is_still_inconsistent(
            self, tenants):
        api, (_, ha), _, _ = tenants
        stripped = api.get("/v1/cases/C1/export?anchor=false&skeleton=true",
                           headers=ha).json()
        got = _check(api, stripped, _service_key_header(api))
        assert got["outcome"] == "not_established" and got["problems"] == []
        assert any("no signed anchor" in u for u in got["unestablished"])

    def test_python_reports_the_reason_apart_from_problems(self, tenants, tmp_path):
        api, (_, ha), _, _ = tenants
        from assurance.attest.keys import VerifyingKey

        key = VerifyingKey.from_pem(
            api.get("/v1/ledger/attest/key").json()["public_key_pem"])
        r = verify_export(api.get("/v1/cases/C1/export", headers=ha).json(), trusted_key=key)
        assert not r.ok and r.problems == () and r.unestablished
        assert r.completeness == NOT_CHECKED
        assert r.text().startswith("NOT ESTABLISHED")
        assert "DOES NOT VERIFY" not in r.text()
        assert r.to_dict()["unestablished"] == list(r.unestablished)

    def test_none_of_the_long_remedies_is_clipped(self, tenants):
        api, (_, ha), _, _ = tenants
        for path, key in (("/v1/cases/C1/export", True), ("/v1/cases/C1/export", False),
                          ("/v1/cases/C1/export?skeleton=true", True),
                          ("/v1/cases/C1/export?anchor=false", True)):
            got = _check(api, api.get(path, headers=ha).json(),
                         _service_key_header(api) if key else None)
            assert "(clipped)" not in json.dumps(got), (path, key)


# ---------------------------------------------------------------------------
# A-M2: guards that nothing used to pin
# ---------------------------------------------------------------------------
class TestGuardsThatMustFailATestWhenRemoved:
    def test_a_forged_skeleton_record_whose_successor_was_not_relinked(self, tmp_path):
        """seq 4 (another subject) replaced by a record with a correct own link hash;
        seq 5 still names the old seq 4. Only the prev_hash continuity check sees it."""
        led = _ledger(tmp_path, 8)
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)
        bundle = led.export(subject="CASE-A", anchor=log.require_last().to_dict(),
                            skeleton=True)
        honest = verify_export(bundle, trusted_key=key.verifying)
        assert honest.ok and honest.completeness == ANCHORED
        forged = copy.deepcopy(bundle)
        for s in forged["skeleton"]:
            if s["seq"] == 4:
                s["kind"], s["at"] = "t.other", "2019-01-01T00:00:00Z"
                s["link_hash"] = LedgerEntry(
                    seq=4, at=s["at"], kind=s["kind"], subject=s["subject"],
                    content_hash=s["content_hash"], prev_hash=s["prev_hash"],
                    link_hash="", actor="", payload={}).expected_link_hash()
        r = verify_export(forged, trusted_key=key.verifying)
        assert not r.ok and r.completeness != ANCHORED
        assert any("seq 5" in p and "prev_hash" in p for p in r.problems)
        plain = verify_export(forged)  # and without any key
        assert not plain.ok and any("seq 5" in p for p in plain.problems)

    def test_a_whole_ledger_whose_first_record_does_not_chain_to_genesis(self, tmp_path):
        bundle = _ledger(tmp_path, 4).export()
        records = bundle["entries"]
        prev = "ab" * 32
        for i, r in enumerate(records, start=1):
            r["seq"], r["prev_hash"] = i, prev
            r["link_hash"] = LedgerEntry(
                seq=i, at=r["at"], kind=r["kind"], subject=r["subject"],
                content_hash=r["content_hash"], prev_hash=prev, link_hash="",
                actor="", payload={}).expected_link_hash()
            prev = r["link_hash"]
        _rewrite_attestation(bundle, records)
        assert records[0]["prev_hash"] != GENESIS
        r = verify_export(bundle)
        assert not r.ok
        assert any("genesis" in p for p in r.problems)

    def test_an_empty_subject_bundle_verifies_nothing(self, tmp_path):
        led = _ledger(tmp_path, 3)
        r = verify_export(led.export(subject="NO-SUCH-CASE"))
        assert not r.ok and r.entries == 0
        assert any("no entries" in p for p in r.problems)

    def test_the_printed_result_cannot_disagree_with_the_sealed_provenance_basis(self):
        raw, _, _ = honest_raw()
        assert check_bundle_data(copy.deepcopy(raw)).ok
        assert raw["evidence"]["body"]["provenance_basis"] == "declared_by_filer"
        raw["result"]["provenance_basis"] = "recorder_attested"  # the unsealed copy only
        res = check_bundle_data(raw)
        assert not res.ok
        assert any("provenance_basis" in p and "result block was edited" in p
                   for p in res.problems), res.problems


# ---------------------------------------------------------------------------
# A-M3: numbers the seal cannot tell apart
# ---------------------------------------------------------------------------
def _legacy_ledger(tmp_path, **body):
    """A ledger holding a body sealed before the number limit existed (hash semantics
    are unchanged, so such a record still verifies; only `seal()` now refuses it)."""
    led = EvidenceLedger(tmp_path / "legacy.db")
    ev = Evidence(kind="t.record", body={"n": 1, **body}, actor=Actor("a.person", "engineer"),
                  origin=Origin("unit-test"))
    led.append(replace(ev, content_hash=ev.compute_hash()), subject="M-1")
    led.append(_ev(2), subject="M-1")
    return led


class TestNumbersTheSealCannotDistinguish:
    def test_a_serial_beyond_2_pow_53_is_reported_not_called_sealed(self, tmp_path):
        led = _legacy_ledger(tmp_path, serial=1760000000123456789)
        bundle = led.export()
        r = verify_export(bundle)
        assert not r.ok and r.problems == ()
        assert any("serial" in u and "cannot distinguish" in u for u in r.unestablished)
        # the hole itself: the neighbouring serial hashes identically
        bundle["entries"][0]["evidence"]["body"]["serial"] = 1760000000123456790
        again = verify_export(bundle)
        assert not again.ok and again.unestablished  # still reported, never a clean pass

    def test_a_margin_below_the_sixth_decimal_is_reported(self, tmp_path):
        r = verify_export(_legacy_ledger(tmp_path, margin_mm=0.0000004).export())
        assert not r.ok and any("margin_mm" in u for u in r.unestablished)

    def test_the_limit_is_stated_where_the_old_claim_was_made(self, tmp_path):
        r = verify_export(_ledger(tmp_path, 3).export())
        assert r.ok
        claim = next(v for v in r.verified if "still hashes to the content hash" in v)
        assert "carries no field outside that seal" not in claim
        assert "6 decimal places" in claim and "2^53" in claim

    @pytest.mark.parametrize("body", [
        {"serial": 2**53}, {"serial": -(2**53)}, {"x": 0.5}, {"x": 0.123456},
        {"x": 1e-06}, {"x": -0.0}, {"x": 1e22}, {"flag": True}, {"x": [1, 2.25, {"y": 3}]},
        {"x": 123456789.123456}])
    def test_ordinary_numbers_still_verify_cleanly(self, tmp_path, body):
        led = EvidenceLedger(tmp_path / "ok.db")
        led.append(Evidence(kind="t.record", body=body, actor=Actor("a.person", "engineer"),
                            origin=Origin("unit-test")).seal(), subject="S")
        r = verify_export(led.export())
        assert r.ok and r.unestablished == (), (body, r.unestablished)

    @pytest.mark.parametrize("body", [
        {"serial": 2**53 + 1}, {"x": 4e-07}, {"x": 0.1 + 0.2}, {"x": [{"deep": 2**70}]},
        {"x": 0.1234567}, {"x": float("1e-7")}])
    def test_new_seals_of_such_numbers_are_refused(self, body):
        ev = Evidence(kind="t.record", body=body, actor=Actor("a.person", "engineer"),
                      origin=Origin("unit-test"))
        with pytest.raises(EvidenceIncompleteError, match="cannot distinguish"):
            ev.seal()

    def test_the_hash_of_a_legacy_body_is_unchanged(self):
        """The limit is a validation, not a new hash: sealed bodies keep verifying."""
        ev = Evidence(kind="t.record", body={"serial": 2**60, "m": 4e-07},
                      actor=Actor("a.person", "engineer"), origin=Origin("unit-test"))
        legacy = replace(ev, content_hash=ev.compute_hash())
        assert legacy.verify()
        # the very collision the limit exists to report: unchanged hash semantics
        neighbour = replace(legacy, body={"serial": 2**60 + 1, "m": 3e-07})
        assert neighbour.compute_hash() == legacy.content_hash


# ---------------------------------------------------------------------------
# A-L6: the CLI exit status
# ---------------------------------------------------------------------------
class TestCliExitStatusWithAKey:
    @pytest.fixture()
    def setup(self, tmp_path):
        led = EvidenceLedger(tmp_path / "led.db")
        for i in range(6):
            led.append(_ev(i), subject="CASE-A" if i % 2 == 0 else "CASE-B")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "att.jsonl")
        attest(led, key, log)
        pub = tmp_path / "signer.pub"
        pub.write_text(key.verifying.pem(), encoding="utf-8")
        return led, key, log, pub

    def _write(self, tmp_path, bundle, name="b.json"):
        p = tmp_path / name
        p.write_text(json.dumps(bundle), encoding="utf-8")
        return str(p)

    def test_anchored_is_the_only_pass_with_a_key(self, tmp_path, setup, capsys):
        led, _, log, pub = setup
        path = self._write(tmp_path, led.export(subject="CASE-A",
                                                anchor=log.require_last().to_dict(),
                                                skeleton=True))
        assert cli_main(["evidence", "verify", path, "--public-key", str(pub)]) == 0
        assert capsys.readouterr().out.startswith("VERIFIED — anchored to a signed head")

    def test_partial_is_exit_3_and_not_headlined_verified(self, tmp_path, setup, capsys):
        led, _, log, pub = setup
        led.append(_ev(9), subject="CASE-A")
        path = self._write(tmp_path, led.export(subject="CASE-A",
                                                anchor=log.require_last().to_dict(),
                                                skeleton=True))
        assert cli_main(["evidence", "verify", path, "--public-key", str(pub)]) == 3
        first = capsys.readouterr().out.splitlines()[0]
        assert not first.startswith("VERIFIED") and "no signature" in first

    def test_a_declared_head_is_exit_3(self, tmp_path, setup, capsys):
        led, key, _, pub = setup
        bundle = led.export()
        bundle["anchor"] = _declared(tmp_path, bundle, key).to_dict()
        path = self._write(tmp_path, bundle)
        assert cli_main(["evidence", "verify", path, "--public-key", str(pub)]) == 3
        first = capsys.readouterr().out.splitlines()[0]
        assert not first.startswith("VERIFIED") and "declared" in first.lower()

    def test_not_established_is_exit_3_not_1(self, tmp_path, setup, capsys):
        led, _, log, pub = setup
        path = self._write(tmp_path, led.export(subject="CASE-A",
                                                anchor=log.require_last().to_dict()))
        assert cli_main(["evidence", "verify", path, "--public-key", str(pub)]) == 3
        assert "skeleton" in capsys.readouterr().out

    def test_a_cut_is_still_exit_1_and_no_key_is_still_exit_0(self, tmp_path, setup, capsys):
        led, _, log, pub = setup
        cut = led.export(anchor=log.require_last().to_dict())
        cut["entries"] = cut["entries"][:3]
        _rewrite_attestation(cut, cut["entries"])
        path = self._write(tmp_path, cut)
        assert cli_main(["evidence", "verify", path, "--public-key", str(pub)]) == 1
        plain = self._write(tmp_path, led.export(), "plain.json")
        assert cli_main(["evidence", "verify", plain]) == 0
        capsys.readouterr()


# ---------------------------------------------------------------------------
# A-L7: a file that overflows the attestation reader
# ---------------------------------------------------------------------------
class TestOverflowIsAReportNotACrash:
    def _anchor(self, **over):
        return {"format": "assurance.head-attestation.v1", "sequence": 1,
                "ledger_length": 1, "head_seq": 1, "head_link_hash": "a" * 64,
                "basis": "declared_by_holder", "attested_at": "2026-01-01T00:00:00Z",
                "key_fingerprint": "f", "previous": "", "signature": "AAAA", **over}

    def test_verify_export_reports_an_infinite_number_in_an_anchor(self, tmp_path):
        key = SigningKey.generate()
        bundle = _ledger(tmp_path, 2).export()
        bundle["anchor"] = self._anchor(ledger_length=float("inf"))
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and any("not a readable head attestation" in p for p in r.problems)

    def test_the_api_reports_1e999_in_an_anchor(self, tenants):
        api, (_, ha), _, _ = tenants
        bundle = api.get("/v1/cases/C1/export", headers=ha).json()
        bundle["anchor"] = self._anchor(ledger_length="PLACEHOLDER")
        raw = json.dumps(bundle).replace('"PLACEHOLDER"', "1e999")
        r = api.post("/v1/evidence/verify", content=raw, headers={
            "Content-Type": "application/json",
            "X-Issuer-Public-Key": _service_key_header(api)})
        assert r.status_code == 200
        assert r.json()["outcome"] == "inconsistent", r.json()["summary"]

    def test_the_api_reports_1e999_in_an_attestation_log(self, tenants):
        api, *_ = tenants
        raw = json.dumps([self._anchor(sequence="PLACEHOLDER")]).replace('"PLACEHOLDER"',
                                                                         "1e999")
        r = api.post("/v1/evidence/verify", content=raw,
                     headers={"Content-Type": "application/json"})
        assert r.status_code == 200
        assert r.json()["outcome"] == "inconsistent", r.json()["summary"]
