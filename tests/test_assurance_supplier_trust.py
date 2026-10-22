"""Trusted supplier-advisory handling.

Six things get called "verified" and they are not one thing: the feed parses; a
signature is valid under *a* key; that key is pinned for *this* supplier by a
person, from a source that is not the feed; the chain is intact; the advisory
matches enrolled machines; a human reviewed the implications. These tests keep
them apart, and several of them are written so that deleting the check they
cover makes them fail (see ``TestTheChecksAreLoadBearing``).
"""

from __future__ import annotations

import base64
import importlib
import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from assurance.attest.keys import SigningKey
from assurance.billing.accounts import AccountStore
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)
from assurance.fleet.cli import main as fleet_main
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import HashSource, ManifestSource
from assurance.machinery.record import record_manifest
from assurance.supplier.cli import main as supplier_main
from assurance.supplier.publish import (
    AdvisoryFeed,
    SignedAdvisory,
    SupplierIdentity,
    publish,
    verify_feed,
    withdraw,
)
from assurance.supplier.trust import (
    TRUST_KIND,
    TRUST_SUBJECT,
    SupplierTrustError,
    SupplierTrustStore,
    evaluate_feed,
)
from assurance.watch.advisories import check_feeds
from assurance.watch.config import FeedSubscription

from .test_assurance_fleet import (
    FIXED_FW,
    GOOD_FW,
    OTHER_FW,
    enrol,
    fw,
    manifest,
)

IDENTITY = SupplierIdentity(supplier_id="controlco", legal_name="ControlCo GmbH",
                            key_contact="the 2025 supply contract")
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _adv(advisory_id: str = "CTRL-2026-11", **over) -> ComponentAdvisory:
    body: dict = {
        "advisory_id": advisory_id, "issued_by": "controlco",
        "issued_at": parse_utc("2026-09-10T08:00:00Z"),
        "title": "Watchdog may not trip", "summary": "The watchdog can fail.",
        "severity": AdvisorySeverity.STOP_USE,
        "reference": "https://controlco.example/psirt/" + advisory_id,
        "remedy": "Update to 3.9.0.",
        "affected": (AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.2",), content_hashes=(GOOD_FW,)),),
        "fixed_versions": ("3.9.0",), "fixed_hashes": (FIXED_FW,),
    }
    body.update(over)
    return ComponentAdvisory(**body)


@pytest.fixture()
def key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture()
def feed(tmp_path) -> AdvisoryFeed:
    return AdvisoryFeed(tmp_path / "feed.jsonl")


@pytest.fixture()
def store(tmp_path) -> SupplierTrustStore:
    return SupplierTrustStore(EvidenceLedger(tmp_path / "account.db"))


def _pin(store, key, supplier="controlco", **kw):
    kw.setdefault("effective_from", T0)
    return store.pin(supplier, key.verifying.pem(), actor="a.engineer",
                     obtained_via="read aloud by ControlCo PSIRT on the phone", **kw)


def _resign(record: SignedAdvisory, key: SigningKey, **changes) -> SignedAdvisory:
    r = replace(record, signature="", **changes)
    return replace(r, signature=base64.b64encode(key.sign(r.signed_payload())).decode())


# =====================================================================
# the six states stay separate
# =====================================================================
class TestStatesAreSeparate:
    def test_a_pinned_key_and_a_clean_feed_is_trusted_with_every_state_shown(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        t = evaluate_feed(feed.read(), store)
        assert t.policy_satisfied and t.trust_state == "trusted"
        d = t.to_dict()
        assert (d["structurally_readable"], d["signature_state"], d["key_trust_state"],
                d["chain_valid"]) == (True, "all_valid", "pinned", True)
        # there is deliberately no single `verified` flag to collapse them into
        assert "verified" not in d and "ok" not in d
        assert d["advisories"][0]["implications_reviewed"] is False

    def test_the_statement_about_what_a_signature_proves_travels_with_the_output(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        d = evaluate_feed(feed.read(), store).to_dict()
        assert "correct, complete or timely" in d["trust_statement"]

    def test_unknown_key_signatures_can_be_valid_without_being_trusted(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        t = evaluate_feed(feed.read(), store, candidate_key=key.verifying)
        assert t.signature_state == "all_valid"          # state 2
        assert t.key_trust_state == "unknown_key"        # state 3 missing
        assert t.trust_state == "untrusted_unknown_key"
        assert not t.policy_satisfied and t.inspect_only
        assert t.records[0].signature_valid_under_candidate is True

    def test_without_any_key_signatures_are_not_checkable_not_invalid(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        t = evaluate_feed(feed.read(), store)
        assert t.signature_state == "not_checkable"
        assert t.trust_state == "untrusted_unknown_key"

    def test_no_trust_store_at_all_trusts_nothing(self, feed, key):
        publish(_adv(), IDENTITY, key, feed)
        t = evaluate_feed(feed.read(), None, candidate_key=key.verifying)
        assert not t.policy_satisfied
        assert t.trust_state == "untrusted_no_trust_store"

    def test_an_empty_feed_is_untrusted_not_clean(self, store):
        t = evaluate_feed([], store)
        assert t.trust_state == "untrusted_empty" and not t.structurally_readable


# =====================================================================
# the forger's options
# =====================================================================
class TestForgery:
    def test_a_forger_publishing_under_the_suppliers_name_with_their_own_key_is_untrusted(
            self, tmp_path, feed, key, store):
        _pin(store, key)                                  # the real key
        forger = SigningKey.generate()
        forged = AdvisoryFeed(tmp_path / "forged.jsonl")
        publish(_adv(), IDENTITY, forger, forged)
        t = evaluate_feed(forged.read(), store, candidate_key=forger.verifying)
        # the forger's signatures are perfectly valid under the forger's key ...
        assert t.signature_state == "all_valid"
        # ... and that is worth nothing: the fingerprint inside the feed is not a pin
        assert t.key_trust_state == "unknown_key" and not t.policy_satisfied

    def test_claiming_the_real_fingerprint_with_the_wrong_key_fails_the_signature(
            self, tmp_path, feed, key, store):
        _pin(store, key)
        forger = SigningKey.generate()
        forged = AdvisoryFeed(tmp_path / "forged.jsonl")
        publish(_adv(), IDENTITY, forger, forged)
        rec = forged.read()[0]
        liar = _resign(rec, forger, key_fingerprint=key.fingerprint)
        t = evaluate_feed([liar], store)
        assert t.signature_state == "some_invalid"
        assert t.trust_state == "untrusted_signature_invalid"

    def test_a_key_pinned_for_another_supplier_does_not_vouch_for_this_one(
            self, feed, key, store):
        _pin(store, key, supplier="otherco")
        publish(_adv(), IDENTITY, key, feed)
        t = evaluate_feed(feed.read(), store)
        assert t.key_trust_state == "wrong_supplier" and not t.policy_satisfied

    def test_changed_feed_contents_fail_the_signature(self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        raw = json.loads(feed.path.read_text().splitlines()[0])
        raw["advisory"]["remedy"] = "Flash http://evil.example/fw.bin now."
        feed.path.write_text(json.dumps(raw) + "\n")
        t = evaluate_feed(feed.read(), store)
        assert t.trust_state == "untrusted_signature_invalid"
        assert t.signature_state == "some_invalid"
        assert not t.permitted("CTRL-2026-11")

    def test_a_record_removed_from_the_chain_is_named(self, feed, key, store):
        publish(_adv("A-1"), IDENTITY, key, feed)
        publish(_adv("A-2"), IDENTITY, key, feed)
        publish(_adv("A-3"), IDENTITY, key, feed)
        _pin(store, key)
        lines = feed.path.read_text().splitlines()
        feed.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
        t = evaluate_feed(feed.read(), store)
        assert not t.chain_valid and t.trust_state == "untrusted_chain_broken"
        assert any("out of order" in p or "predecessor" in p for p in t.chain_problems)
        # every remaining signature is fine; the chain is what fails (states differ)
        assert t.signature_state == "all_valid"

    def test_a_malformed_signature_is_damage_not_absence(self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        rec = replace(feed.read()[0], signature="!!!not base64!!!")
        t = evaluate_feed([rec], store)
        assert t.records[0].signature == "malformed"
        assert not t.policy_satisfied


class TestDuplicatesAndConflicts:
    def test_the_same_advisory_twice_is_a_duplicate(self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        r1 = feed.read()[0]
        r2 = _resign(replace(r1, sequence=2, previous=r1.content_hash()), key)
        t = evaluate_feed([r1, r2], store)
        assert t.duplicate_advisories == ("CTRL-2026-11",)
        assert not t.policy_satisfied

    def test_same_id_with_different_content_is_a_conflict_and_cannot_be_overridden(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        r1 = feed.read()[0]
        changed = _adv(summary="Actually it is fine, ignore this.").to_dict()
        r2 = _resign(replace(r1, sequence=2, previous=r1.content_hash(),
                             advisory=changed), key)
        t = evaluate_feed([r1, r2], store)
        assert t.conflicting_advisories == ("CTRL-2026-11",)
        assert t.trust_state == "untrusted_conflicting_advisories"
        with pytest.raises(SupplierTrustError, match="cannot be overridden"):
            store.override(t, "CTRL-2026-11", actor="a.engineer", reason="trust me")


# =====================================================================
# rotation, revocation, withdrawal
# =====================================================================
class TestRotationRevocationWithdrawal:
    def _history(self, tmp_path, store):
        old, new = SigningKey.generate(), SigningKey.generate()
        f = AdvisoryFeed(tmp_path / "rot.jsonl")
        publish(_adv("A-1"), IDENTITY, old, f, now=parse_utc("2026-06-01T00:00:00Z"))
        publish(_adv("A-2"), IDENTITY, new, f, rotating=True,
                now=parse_utc("2026-09-01T00:00:00Z"))
        _pin(store, old)
        store.rotate("controlco", new.verifying.pem(),
                     retire_fingerprint=old.fingerprint,
                     effective_at=parse_utc("2026-08-01T00:00:00Z"),
                     actor="a.engineer", obtained_via="new fingerprint on the 2026 contract")
        return old, new, f

    def test_a_rotation_is_trusted_across_both_keys_over_their_own_spans(
            self, tmp_path, store):
        old, new, f = self._history(tmp_path, store)
        t = evaluate_feed(f.read(), store)
        assert t.policy_satisfied
        assert set(t.key_fingerprints) == {old.fingerprint, new.fingerprint}
        pins = {p.fingerprint: p for p in store.pins("controlco")}
        assert pins[old.fingerprint].status == "retired"
        assert pins[old.fingerprint].retired_at == "2026-08-01T00:00:00Z"

    def test_the_old_key_signing_after_its_retirement_is_not_trusted(
            self, tmp_path, store):
        old, _new, f = self._history(tmp_path, store)
        late = AdvisoryFeed(tmp_path / "late.jsonl")
        publish(_adv("A-9"), IDENTITY, old, late, now=parse_utc("2026-09-15T00:00:00Z"))
        t = evaluate_feed(late.read(), store)
        assert t.key_trust_state == "retired" and not t.policy_satisfied
        assert t.trust_state == "untrusted_key_not_in_force"

    def test_revocation_makes_everything_the_key_signed_untrusted(
            self, tmp_path, feed, key, store):
        publish(_adv(), IDENTITY, key, feed, now=parse_utc("2026-06-01T00:00:00Z"))
        _pin(store, key)
        assert evaluate_feed(feed.read(), store).policy_satisfied
        store.revoke("controlco", key.fingerprint, actor="a.engineer",
                     reason="the supplier told us the key leaked")
        t = evaluate_feed(feed.read(), store)
        assert t.trust_state == "untrusted_revoked_key"
        # a revoked key's advisory cannot be waved through by an override either
        with pytest.raises(SupplierTrustError, match="revoked key"):
            store.override(t, "CTRL-2026-11", actor="a.engineer", reason="x")

    def test_a_signed_withdrawal_is_honoured_and_the_original_stays(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        withdraw("CTRL-2026-11", "issued against the wrong firmware", IDENTITY, key, feed)
        _pin(store, key)
        t = evaluate_feed(feed.read(), store)
        assert t.policy_satisfied
        assert t.withdrawn == ("CTRL-2026-11",) and t.advisories == ()
        assert len(feed.read()) == 2

    def test_a_forged_withdrawal_does_not_cancel_a_standing_advisory(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        withdraw("CTRL-2026-11", "genuine reason", IDENTITY, key, feed)
        _pin(store, key)
        raw = [json.loads(line) for line in feed.path.read_text().splitlines()]
        raw[1]["withdrawal_reason"] = "attacker edit"          # breaks its signature
        feed.path.write_text("\n".join(json.dumps(r) for r in raw) + "\n")
        t = evaluate_feed(feed.read(), store)
        assert t.unauthenticated_withdrawals == ("CTRL-2026-11",)
        assert [a["advisory_id"] for a in t.advisories] == ["CTRL-2026-11"]
        assert not t.policy_satisfied

    def test_a_withdrawal_carrying_different_content_is_a_conflict(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        withdraw("CTRL-2026-11", "r", IDENTITY, key, feed)
        _pin(store, key)
        r1, r2 = feed.read()
        bad = _resign(r2, key, advisory=_adv(title="Something else entirely").to_dict())
        t = evaluate_feed([r1, bad], store)
        assert "CTRL-2026-11" in t.conflicting_advisories


# =====================================================================
# the store: attributed, append-only, per account
# =====================================================================
class TestStore:
    def test_a_pin_must_say_how_the_fingerprint_was_learned(self, key, store):
        with pytest.raises(SupplierTrustError, match="obtained_via"):
            store.pin("controlco", key.verifying.pem(), actor="a", obtained_via=" ")

    def test_a_pin_must_match_the_fingerprint_given_independently(self, key, store):
        with pytest.raises(SupplierTrustError, match="Do not pin it"):
            store.pin("controlco", key.verifying.pem(), actor="a",
                      obtained_via="phone", expected_fingerprint="0" * 16)
        assert store.pins() == []

    def test_a_pin_needs_a_named_actor(self, key, store):
        with pytest.raises(SupplierTrustError, match="actor"):
            store.pin("controlco", key.verifying.pem(), actor=" ", obtained_via="phone")

    def test_a_second_key_is_a_rotation_not_a_second_pin(self, key, store):
        _pin(store, key)
        with pytest.raises(SupplierTrustError, match="rotation"):
            _pin(store, SigningKey.generate())

    def test_one_key_cannot_be_pinned_for_two_suppliers(self, key, store):
        _pin(store, key)
        with pytest.raises(SupplierTrustError, match="One key, one supplier"):
            _pin(store, key, supplier="otherco")

    def test_a_revoked_key_is_never_re_pinned(self, key, store):
        _pin(store, key)
        store.revoke("controlco", key.fingerprint, actor="a", reason="leaked")
        with pytest.raises(SupplierTrustError, match="never re-pinned"):
            _pin(store, key)

    def test_every_decision_is_in_the_accounts_ledger_with_its_actor(self, key, store):
        _pin(store, key)
        store.revoke("controlco", key.fingerprint, actor="b.lead", reason="leaked")
        entries = store.ledger.entries(subject=TRUST_SUBJECT, kind=TRUST_KIND)
        assert [e.actor for e in entries] == ["a.engineer", "b.lead"]
        hist = store.history()
        assert [h["event"] for h in hist] == ["pin", "revoke"]
        assert all("public_key_pem" not in h for h in hist)

    def test_two_accounts_do_not_share_pins(self, tmp_path, key):
        a = SupplierTrustStore(EvidenceLedger(tmp_path / "a.db"))
        b = SupplierTrustStore(EvidenceLedger(tmp_path / "b.db"))
        _pin(a, key)
        assert a.pins() and b.pins() == []

    def test_an_edited_trust_record_fails_closed(self, tmp_path, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        assert evaluate_feed(feed.read(), store).policy_satisfied
        db = sqlite3.connect(store.ledger.path)
        row = db.execute("SELECT seq, payload FROM chain WHERE kind = ?",
                         (TRUST_KIND,)).fetchone()
        body = json.loads(row[1])
        body["body"]["supplier_id"] = "someone-else"
        db.execute("UPDATE chain SET payload = ? WHERE seq = ?", (json.dumps(body), row[0]))
        db.commit()
        db.close()
        t = evaluate_feed(feed.read(), store)
        assert t.trust_state == "untrusted_store_unhealthy"
        assert not t.policy_satisfied


# =====================================================================
# overrides
# =====================================================================
class TestOverride:
    def test_an_override_is_explicit_attributed_and_in_the_ledger(
            self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)                 # key never pinned
        t = evaluate_feed(feed.read(), store)
        assert not t.permitted("CTRL-2026-11")
        store.override(t, "CTRL-2026-11", actor="m.safety", reason="phoned PSIRT, confirmed")
        after = evaluate_feed(feed.read(), store)
        row = after.advisories[0]
        assert row["automated_consequences_permitted"] is True
        assert row["trust_basis"] == "manual_override"
        assert row["override"]["actor"] == "m.safety"
        assert row["override"]["reason"] == "phoned PSIRT, confirmed"
        assert after.trust_state != "trusted" and not after.policy_satisfied
        assert any(e.actor == "m.safety" for e in
                   store.ledger.entries(subject=TRUST_SUBJECT, kind=TRUST_KIND))

    def test_an_override_needs_an_actor_and_a_reason(self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        t = evaluate_feed(feed.read(), store)
        with pytest.raises(SupplierTrustError, match="actor"):
            store.override(t, "CTRL-2026-11", actor="", reason="x")
        with pytest.raises(SupplierTrustError, match="reason"):
            store.override(t, "CTRL-2026-11", actor="a", reason=" ")

    def test_an_override_does_not_survive_a_change_to_the_advisory(
            self, tmp_path, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        store.override(evaluate_feed(feed.read(), store), "CTRL-2026-11",
                       actor="a", reason="checked")
        other = AdvisoryFeed(tmp_path / "other.jsonl")
        publish(_adv(remedy="Different remedy."), IDENTITY, key, other)
        assert not evaluate_feed(other.read(), store).permitted("CTRL-2026-11")

    def test_a_failed_signature_cannot_be_overridden(self, feed, key, store):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        raw = json.loads(feed.path.read_text().splitlines()[0])
        raw["advisory"]["title"] = "tampered"
        feed.path.write_text(json.dumps(raw) + "\n")
        t = evaluate_feed(feed.read(), store)
        with pytest.raises(SupplierTrustError, match="tampering"):
            store.override(t, "CTRL-2026-11", actor="a", reason="x")


# =====================================================================
# adversarial: --unsigned-anyway and verify_feed.live
# =====================================================================
class TestFailedSignaturesNeverDriveLive:
    def _tampered(self, feed, key):
        publish(_adv("A-1"), IDENTITY, key, feed)
        publish(_adv("A-2"), IDENTITY, key, feed)
        lines = feed.path.read_text().splitlines()
        raw = json.loads(lines[1])
        raw["advisory"]["remedy"] = "Flash http://evil.example/fw.bin"
        feed.path.write_text("\n".join([lines[0], json.dumps(raw)]) + "\n")

    def test_verify_feed_live_excludes_a_record_whose_signature_failed(self, feed, key):
        self._tampered(feed, key)
        v = verify_feed(feed.read(), key.verifying)
        assert not v.ok and v.failed_signatures == (2,)
        assert [r.advisory_id for r in v.live] == ["A-1"]

    def test_a_failed_withdrawal_cancels_nothing(self, feed, key):
        publish(_adv("A-1"), IDENTITY, key, feed)
        withdraw("A-1", "reason", IDENTITY, key, feed)
        raw = [json.loads(line) for line in feed.path.read_text().splitlines()]
        raw[1]["withdrawal_reason"] = "edited"
        feed.path.write_text("\n".join(json.dumps(r) for r in raw) + "\n")
        v = verify_feed(feed.read(), key.verifying)
        assert [r.advisory_id for r in v.live] == ["A-1"] and v.withdrawn == ()

    def _write_pub(self, tmp_path, key):
        p = tmp_path / "k.pub"
        p.write_text(key.verifying.pem())
        return p

    def test_the_cli_override_excludes_the_failed_record_and_records_the_actor(
            self, tmp_path, feed, key, capsys):
        self._tampered(feed, key)
        enrol(EvidenceLedger(tmp_path / "l.db"), "0412")
        capsys.readouterr()
        rc = fleet_main(["advisory", "--feed", str(feed.path), "--supplier-key",
                         str(self._write_pub(tmp_path, key)), "--unsigned-anyway",
                         "--override-actor", "m.safety", "--override-reason", "urgent",
                         "--ledger", str(tmp_path / "l.db"), "--json"])
        assert rc in (0, 1)
        out = json.loads(capsys.readouterr().out)
        ids = [a["advisory_id"] for a in out["advisories"]]
        assert ids == ["A-1"]                                # A-2 failed: not assessed
        assert any("EXCLUDED A-2" in n for n in out["provenance_notes"])
        prov = out["advisories"][0]["provenance"]
        assert prov["trust_basis"] == "manual_override"
        assert prov["override"]["actor"] == "m.safety"
        assert prov["inspect_only"] is False
        # and the override is in the account ledger, attributed
        led = EvidenceLedger(tmp_path / "l.db")
        assert any(e.actor == "m.safety"
                   for e in led.entries(subject=TRUST_SUBJECT, kind=TRUST_KIND))

    def test_the_cli_override_without_an_actor_is_refused(self, tmp_path, feed, key, capsys):
        publish(_adv(), IDENTITY, key, feed)
        enrol(EvidenceLedger(tmp_path / "l.db"), "0412")
        rc = fleet_main(["advisory", "--feed", str(feed.path), "--unsigned-anyway",
                         "--ledger", str(tmp_path / "l.db")])
        assert rc == 2
        assert "--override-actor" in capsys.readouterr().err

    def test_a_bare_advisory_file_is_marked_unauthenticated_on_the_report(
            self, tmp_path, capsys):
        (tmp_path / "a.json").write_text(json.dumps(_adv().to_dict()))
        enrol(EvidenceLedger(tmp_path / "l.db"), "0412")
        fleet_main(["advisory", str(tmp_path / "a.json"), "--ledger",
                    str(tmp_path / "l.db"), "--json"])
        prov = json.loads(capsys.readouterr().out)["advisories"][0]["provenance"]
        assert prov["trust_state"] == "unauthenticated_file" and prov["inspect_only"]

    def test_a_pinned_key_lets_the_cli_run_without_any_key_argument(
            self, tmp_path, feed, key, capsys):
        publish(_adv(), IDENTITY, key, feed)
        led = tmp_path / "l.db"
        enrol(EvidenceLedger(led), "0412")
        pub = self._write_pub(tmp_path, key)
        assert supplier_main(["trust", "pin", "--ledger", str(led), "--supplier-id",
                              "controlco", "--public-key", str(pub), "--fingerprint",
                              key.fingerprint, "--obtained-via", "phone call",
                              "--actor", "a.engineer"]) == 0
        capsys.readouterr()
        rc = fleet_main(["advisory", "--feed", str(feed.path), "--ledger", str(led),
                         "--json"])
        assert rc in (0, 1)
        out = json.loads(capsys.readouterr().out)
        assert out["advisories"][0]["provenance"]["trust_basis"] == "pinned_key_policy"
        assert out["feed_trust"]["policy_satisfied"] is True

    def test_the_cli_refuses_to_pin_a_fingerprint_that_does_not_match(
            self, tmp_path, key, capsys):
        pub = self._write_pub(tmp_path, key)
        rc = supplier_main(["trust", "pin", "--ledger", str(tmp_path / "l.db"),
                            "--supplier-id", "controlco", "--public-key", str(pub),
                            "--fingerprint", "0" * 16, "--obtained-via", "phone",
                            "--actor", "a"])
        assert rc == 1 and "Do not pin it" in capsys.readouterr().err

    def test_trust_check_exits_nonzero_for_an_untrusted_feed(
            self, tmp_path, feed, key, capsys):
        publish(_adv(), IDENTITY, key, feed)
        rc = supplier_main(["trust", "check", "--feed", str(feed.path), "--ledger",
                            str(tmp_path / "l.db"), "--public-key",
                            str(self._write_pub(tmp_path, key))])
        out = capsys.readouterr().out
        assert rc == 1 and "UNTRUSTED" in out
        assert "2 signatures        all_valid" in out
        assert "3 key trusted for   unknown_key" in out


# =====================================================================
# fleet impact: matching basis and what stays unknown
# =====================================================================
class TestImpactClassification:
    def _fleet(self, tmp_path):
        led = EvidenceLedger(tmp_path / "fleet.db")
        enrol(led, "0001", fw_hash=GOOD_FW)                              # hash
        enrol(led, "0002", fw_hash=OTHER_FW)                             # contradictory
        record_manifest(led, manifest(
            "0003", fw("", "3.8.2", hash_source=HashSource.DECLARED)))   # version only
        record_manifest(led, manifest(
            "0004", fw("", "", hash_source=HashSource.DECLARED)))        # name only
        record_manifest(led, manifest(
            "0005", fw(FIXED_FW, "3.9.0"),
            source=ManifestSource.AS_DECLARED))                          # declared only
        record_manifest(led, manifest(
            "0006", fw(FIXED_FW, "3.9.0")))                              # genuinely clear
        return Fleet.from_ledger(led)

    def test_each_machine_gets_its_own_basis_never_a_flattened_yes(self, tmp_path):
        r = assess_impact(_adv(), self._fleet(tmp_path))
        by = {c.machine_key.split("#")[1]: c for c in r.classifications}
        assert by["0001"].classification == "match_by_hash"
        assert by["0002"].classification == "contradictory_label_vs_hash"
        assert by["0003"].classification == "match_by_version_only"
        assert by["0004"].classification == "possible_match_name_only"
        assert by["0005"].classification == "unknown"
        assert by["0006"].classification == "no_match_found" or \
            by["0006"].classification == "unknown"

    def test_a_label_match_is_never_cleared_when_the_hash_contradicts_it(self, tmp_path):
        led = EvidenceLedger(tmp_path / "x.db")
        enrol(led, "0002", fw_hash=OTHER_FW)
        r = assess_impact(_adv(), Fleet.from_ledger(led))
        assert r.verdict != "clear"
        assert r.classifications[0].classification == "contradictory_label_vs_hash"
        assert not r.clear_is_complete
        assert r.confirmed == ()                      # and it is not "confirmed" either

    def test_a_clear_verdict_is_not_complete_while_a_machine_is_unknown(self, tmp_path):
        led = EvidenceLedger(tmp_path / "x.db")
        record_manifest(led, manifest("0005", fw(FIXED_FW, "3.9.0"),
                                      source=ManifestSource.AS_DECLARED))
        r = assess_impact(_adv(), Fleet.from_ledger(led))
        assert r.verdict == "clear"
        assert r.unknown_machines and not r.clear_is_complete
        assert "UNKNOWN" in r.summary()
        assert r.to_dict()["clear_is_complete"] is False

    def test_unhashed_items_from_the_named_supplier_leave_functions_unknown(
            self, tmp_path):
        led = EvidenceLedger(tmp_path / "x.db")
        record_manifest(led, manifest("0007", fw("", "4.0.0",
                                                 hash_source=HashSource.DECLARED)))
        r = assess_impact(_adv(), Fleet.from_ledger(led))
        assert {f["function_id"] for f in r.unknown_functions} == {"SF-01", "SF-02"}

    def test_prior_evidence_that_may_no_longer_describe_the_machine_is_listed(
            self, tmp_path):
        led = EvidenceLedger(tmp_path / "x.db")
        enrol(led, "0001")                                  # verified, hash match
        enrol(led, "0002", fw_hash=OTHER_FW)                # verified, contradictory
        r = assess_impact(_adv(), Fleet.from_ledger(led))
        prior = {(p["machine"].split("#")[1], p["function_id"]): p
                 for p in r.prior_evidence_in_question}
        assert prior[("0001", "SF-01")]["resolved"] is True
        assert prior[("0002", "SF-01")]["resolved"] is False
        assert prior[("0001", "SF-01")]["last_verified_at"]

    def test_the_payload_carries_basis_uncertainty_and_provenance(self, tmp_path):
        r = assess_impact(_adv(), self._fleet(tmp_path),
                          provenance={"trust_state": "x", "inspect_only": True})
        d = r.to_dict()
        row = next(c for c in d["machine_classification"] if c["machine"].endswith("#0003"))
        assert row["basis"] == "version" and "label" in row["uncertainty"]
        assert d["provenance"]["inspect_only"] is True
        assert d["unknown_machines"] and "prior_evidence_in_question" in d
        assert "INSPECT ONLY" in r.summary()


# =====================================================================
# watch: untrusted advisories carry no consequence
# =====================================================================
class TestWatchConsequences:
    def _setup(self, tmp_path, key):
        led = EvidenceLedger(tmp_path / "w.db")
        enrol(led, "0001")
        f = AdvisoryFeed(tmp_path / "feed.jsonl")
        publish(_adv(), IDENTITY, key, f)
        sub = FeedSubscription(supplier_id="controlco", feed=str(f.path),
                               public_key=str(tmp_path / "unused.pub"))
        return led, f, sub

    def test_an_unpinned_feed_is_inspect_only_with_no_stop_use_and_no_case(
            self, tmp_path, key):
        led, _f, sub = self._setup(tmp_path, key)
        store = SupplierTrustStore(led)
        other = SigningKey.generate()
        _pin(store, other)                       # a DIFFERENT key is pinned
        result = check_feeds([sub], Fleet.from_ledger(led), trust_store=store)
        f = result.findings[0]
        assert f.inspect_only and f.state == "untrusted"
        assert f.machines == () and f.report is None     # nothing to open a case from
        assert f.inspect_machines                         # but the operator can inspect
        assert not f.stops_use and result.stop_use == ()
        assert result.new == () and not result.is_finding
        assert result.feeds[0].status == "untrusted" and result.feeds[0].is_degraded

    def test_a_pinned_feed_drives_stop_use(self, tmp_path, key):
        led, _f, sub = self._setup(tmp_path, key)
        store = SupplierTrustStore(led)
        _pin(store, key)
        result = check_feeds([sub], Fleet.from_ledger(led), trust_store=store)
        f = result.findings[0]
        assert f.state == "new" and f.stops_use and f.report is not None
        assert f.trust_basis == "pinned_key_policy"
        assert result.feeds[0].status == "verified"

    def test_a_manual_override_re_enables_the_consequence_and_says_so(
            self, tmp_path, key):
        led, f, sub = self._setup(tmp_path, key)
        store = SupplierTrustStore(led)
        _pin(store, SigningKey.generate())
        store.override(evaluate_feed(f.read(), store), "CTRL-2026-11",
                       actor="m.safety", reason="confirmed by phone")
        result = check_feeds([sub], Fleet.from_ledger(led), trust_store=store)
        finding = result.findings[0]
        assert finding.trust_basis == "manual_override" and finding.stops_use

    def test_an_untrusted_withdrawal_does_not_announce_a_retraction(
            self, tmp_path, key):
        led, f, sub = self._setup(tmp_path, key)
        withdraw("CTRL-2026-11", "reason", IDENTITY, key, f)
        store = SupplierTrustStore(led)
        _pin(store, SigningKey.generate())
        result = check_feeds([sub], Fleet.from_ledger(led), trust_store=store,
                             previously_seen={"CTRL-2026-11": "new"})
        assert result.withdrawn == ()


# =====================================================================
# the checks are load-bearing: remove one and a test above must fail
# =====================================================================
class TestTheChecksAreLoadBearing:
    def test_without_the_pin_check_a_forged_feed_would_be_trusted(
            self, tmp_path, feed, key, store, monkeypatch):
        """Mutation guard. With the lookup disabled the forger's feed passes, which
        is precisely what ``test_a_forger_publishing_...`` forbids."""
        forger = SigningKey.generate()
        publish(_adv(), IDENTITY, forger, feed)
        _pin(store, key)
        assert not evaluate_feed(feed.read(), store).policy_satisfied
        from assurance.supplier import trust as mod

        real = mod.SupplierTrustStore._replay

        def permissive(self):
            state = real(self)
            from assurance.supplier.trust import KeyPin
            pins = dict(state.pins)
            pins[forger.fingerprint] = KeyPin(
                "controlco", forger.fingerprint, forger.verifying.pem(), "active",
                "2020-01-01T00:00:00Z", "mutant", "mutant", "2020-01-01T00:00:00Z")
            return replace(state, pins=pins)

        monkeypatch.setattr(mod.SupplierTrustStore, "_replay", permissive)
        assert evaluate_feed(feed.read(), store).policy_satisfied

    def test_without_the_signature_check_a_tampered_feed_would_be_trusted(
            self, feed, key, store, monkeypatch):
        publish(_adv(), IDENTITY, key, feed)
        _pin(store, key)
        raw = json.loads(feed.path.read_text().splitlines()[0])
        raw["advisory"]["remedy"] = "evil"
        feed.path.write_text(json.dumps(raw) + "\n")
        assert not evaluate_feed(feed.read(), store).policy_satisfied
        monkeypatch.setattr(SignedAdvisory, "verified_by", lambda self, k: True)
        assert evaluate_feed(feed.read(), store).policy_satisfied

    def test_without_the_effective_date_check_a_retired_key_would_be_trusted(
            self, tmp_path, key, store, monkeypatch):
        new = SigningKey.generate()
        f = AdvisoryFeed(tmp_path / "late.jsonl")
        publish(_adv(), IDENTITY, key, f, now=parse_utc("2026-09-15T00:00:00Z"))
        _pin(store, key)
        store.rotate("controlco", new.verifying.pem(), retire_fingerprint=key.fingerprint,
                     effective_at=parse_utc("2026-08-01T00:00:00Z"), actor="a",
                     obtained_via="contract")
        assert not evaluate_feed(f.read(), store).policy_satisfied
        from assurance.supplier.trust import KeyPin

        monkeypatch.setattr(KeyPin, "in_force_at", lambda self, when: "trusted")
        assert evaluate_feed(f.read(), store).policy_satisfied


# =====================================================================
# API
# =====================================================================
def _pem(k: SigningKey) -> str:
    return k.verifying.pem()


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "feeds"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_do_not_ship")
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    service = importlib.import_module("assurance.api.service")
    accounts = AccountStore(str(tmp_path / "accounts.db"))
    with TestClient(service.create_app()) as client:
        yield client, accounts


def _hdr(accounts, email="a@b.de", tier="cell"):
    account = accounts.upsert_account(email=email, tier=tier)
    return {"X-API-Key": accounts.issue_key(account.id)}, account


class TestApi:
    def test_no_key_is_401_and_an_unentitled_key_is_402(self, api):
        client, accounts = api
        assert client.get("/v1/supplier/trust").status_code == 401
        h, _ = _hdr(accounts, tier="free")
        r = client.get("/v1/supplier/trust", headers=h)
        assert r.status_code == 402

    def test_pin_evaluate_and_the_states_come_back_separately(self, api, tmp_path, key):
        client, accounts = api
        h, _ = _hdr(accounts)
        f = AdvisoryFeed(tmp_path / "f.jsonl")
        publish(_adv(), IDENTITY, key, f)
        feed_text = f.path.read_text()
        before = client.post("/v1/supplier/trust/evaluate", headers=h,
                             json={"feed": feed_text}).json()["trust"]
        assert before["policy_satisfied"] is False
        assert before["key_trust_state"] == "unknown_key"
        r = client.post("/v1/supplier/trust/pin", headers=h, json={
            "supplier_id": "controlco", "public_key_pem": _pem(key),
            "expected_fingerprint": key.fingerprint, "actor": "a.engineer",
            "obtained_via": "phone"})
        assert r.status_code == 201
        after = client.post("/v1/supplier/trust/evaluate", headers=h,
                            json={"feed": feed_text}).json()["trust"]
        assert after["policy_satisfied"] is True and after["trust_state"] == "trusted"
        assert after["signature_state"] == "all_valid"
        listing = client.get("/v1/supplier/trust", headers=h).json()
        assert listing["pins"][0]["fingerprint"] == key.fingerprint
        assert "account" in listing["history"][0]["actor"]

    def test_a_wrong_fingerprint_is_refused_with_409(self, api, key):
        client, accounts = api
        h, _ = _hdr(accounts)
        r = client.post("/v1/supplier/trust/pin", headers=h, json={
            "supplier_id": "controlco", "public_key_pem": _pem(key),
            "expected_fingerprint": "f" * 16, "actor": "a", "obtained_via": "phone"})
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "trust_decision_refused"

    def test_pins_are_per_account(self, api, tmp_path, key):
        client, accounts = api
        ha, _ = _hdr(accounts, "a@b.de")
        hb, _ = _hdr(accounts, "c@d.de")
        client.post("/v1/supplier/trust/pin", headers=ha, json={
            "supplier_id": "controlco", "public_key_pem": _pem(key), "actor": "a",
            "obtained_via": "phone"})
        assert client.get("/v1/supplier/trust", headers=hb).json()["pins"] == []

    def test_an_unreadable_feed_is_a_state_not_a_crash(self, api):
        client, accounts = api
        h, _ = _hdr(accounts)
        t = client.post("/v1/supplier/trust/evaluate", headers=h,
                        json={"feed": "this is not json"}).json()["trust"]
        assert t["structurally_readable"] is False and t["policy_satisfied"] is False

    def test_fleet_signed_marks_an_unpinned_feed_inspect_only(self, api, tmp_path, key):
        client, accounts = api
        h, account = _hdr(accounts)
        from assurance.api.deps import tenant_ledger_path

        enrol(EvidenceLedger(tenant_ledger_path(account.id)), "0001")
        f = AdvisoryFeed(tmp_path / "f.jsonl")
        publish(_adv(), IDENTITY, key, f)
        body = {"feed": f.path.read_text(),
                "candidate_public_key_pem": _pem(key)}
        r = client.post("/v1/fleet/advisory/signed", headers=h, json=body).json()
        assert r["inspect_only"] is True
        row = r["advisories"][0]
        assert row["automated_consequences_permitted"] is False
        assert row["impact"]["provenance"]["inspect_only"] is True
        assert row["impact"]["machine_classification"][0]["classification"] == \
            "match_by_hash"
        assert r["trust"]["signature_state"] == "all_valid"
        assert r["trust"]["key_trust_state"] == "unknown_key"
        assert "correct, complete or timely" in r["trust_statement"]
        # pin, and the same request is now trusted
        client.post("/v1/supplier/trust/pin", headers=h, json={
            "supplier_id": "controlco", "public_key_pem": _pem(key), "actor": "a",
            "obtained_via": "phone"})
        r2 = client.post("/v1/fleet/advisory/signed", headers=h, json=body).json()
        assert r2["inspect_only"] is False
        assert r2["advisories"][0]["impact"]["provenance"]["trust_basis"] == \
            "pinned_key_policy"

    def test_override_through_the_api_is_attributed(self, api, tmp_path, key):
        client, accounts = api
        h, account = _hdr(accounts)
        f = AdvisoryFeed(tmp_path / "f.jsonl")
        publish(_adv(), IDENTITY, key, f)
        r = client.post("/v1/supplier/trust/override", headers=h, json={
            "feed": f.path.read_text(), "advisory_id": "CTRL-2026-11",
            "actor": "m.safety", "reason": "confirmed by phone"})
        assert r.status_code == 200
        hist = client.get("/v1/supplier/trust", headers=h).json()
        assert hist["overrides"][0]["actor"] == f"m.safety (account {account.id})"

    def test_the_operator_ledger_never_holds_pins(self, key):
        from fastapi import HTTPException

        from assurance.api.supplier_routes import account_trust_store
        from assurance.billing.accounts import Principal

        with pytest.raises(HTTPException) as exc:
            account_trust_store(Principal(account=None, key_prefix=""), object())
        assert exc.value.status_code == 403
