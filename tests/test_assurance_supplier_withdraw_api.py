"""POST /v1/supplier/advisory/withdraw: the hosted form of `assurance supplier withdraw`.

The supplier signs the withdrawal offline (the server never holds a private key),
the route verifies it under the key the account pinned for that supplier, and the
withdrawal is appended as a new record. The original is never edited or removed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from assurance.attest.keys import SigningKey
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.fleet.registry import Fleet
from assurance.supplier.cli import main as supplier_main
from assurance.supplier.publish import (
    AdvisoryFeed,
    SignedAdvisory,
    SupplierIdentity,
    publish,
    withdraw,
)
from assurance.supplier.trust import SupplierTrustStore
from assurance.watch.advisories import check_feeds
from assurance.watch.config import FeedSubscription

from . import interfaces_fixtures as fx
from .test_assurance_fleet import FIXED_FW, GOOD_FW, enrol

live_api = fx.live_api

IDENTITY = SupplierIdentity(supplier_id="controlco", legal_name="ControlCo GmbH",
                            key_contact="the 2025 supply contract")
ADV = "CTRL-2026-11"
WITHDRAW = "/v1/supplier/advisory/withdraw"
PUBLISH = "/v1/supplier/advisory"


def _adv(advisory_id: str = ADV) -> ComponentAdvisory:
    return ComponentAdvisory(
        advisory_id=advisory_id, issued_by="controlco",
        issued_at=parse_utc("2026-09-10T08:00:00Z"),
        title="Watchdog may not trip", summary="The watchdog can fail.",
        severity=AdvisorySeverity.STOP_USE,
        reference="https://controlco.example/psirt/" + advisory_id,
        remedy="Update to 3.9.0.",
        affected=(AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.2",), content_hashes=(GOOD_FW,)),),
        fixed_versions=("3.9.0",), fixed_hashes=(FIXED_FW,))


def _pin(ledger, key: SigningKey) -> None:
    SupplierTrustStore(ledger).pin(
        "controlco", key.verifying.pem(), actor="sales (operator-assigned)",
        obtained_via="read aloud by ControlCo PSIRT on the phone",
        effective_from=parse_utc("2026-01-01T00:00:00Z"))


def _resign(record: SignedAdvisory, key: SigningKey, **changes) -> SignedAdvisory:
    import base64

    r = replace(record, signature="", **changes)
    return replace(r, signature=base64.b64encode(key.sign(r.signed_payload())).decode())


class Hosted:
    """One supplier account with a pinned key and an advisory already published."""

    def __init__(self, live_api, tmp_path, monkeypatch, email="sup@example.de"):
        monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "feeds"))
        self.api = live_api
        self.tmp = tmp_path
        self.account_id, self.headers = live_api.account(email, "supplier")
        self.key = SigningKey.generate()
        _pin(live_api.tenant_ledger(self.account_id), self.key)
        self.client = live_api.client()
        self.feed_file = tmp_path / "feeds" / f"{self.account_id}.jsonl"

    def publish(self, advisory_id: str = ADV):
        local = AdvisoryFeed(self.tmp / f"local-{advisory_id}.jsonl")
        record = publish(_adv(advisory_id), IDENTITY, self.key, local)
        r = self.client.post(PUBLISH, json=record.to_dict(), headers=self.headers)
        assert r.status_code == 201, r.text
        return record

    def hosted_text(self) -> str:
        r = self.client.get(f"/v1/supplier/feed/{self.account_id}")
        assert r.status_code == 200
        return r.text

    def sign_withdrawal(self, advisory_id: str = ADV, reason: str = "range was wrong",
                        key: SigningKey | None = None) -> SignedAdvisory:
        """What a supplier does: copy the hosted feed, `withdraw` on the copy, take the new line."""
        copy = self.tmp / "copy.jsonl"
        copy.write_text(self.hosted_text(), "utf-8")
        return withdraw(advisory_id, reason, IDENTITY, key or self.key, AdvisoryFeed(copy),
                        rotating=key is not None)

    def post(self, record: SignedAdvisory | dict, headers=None):
        body = record if isinstance(record, dict) else record.to_dict()
        return self.client.post(WITHDRAW, json=body, headers=headers or self.headers)


@pytest.fixture()
def hosted(live_api, tmp_path, monkeypatch):
    h = Hosted(live_api, tmp_path, monkeypatch)
    h.publish()
    yield h
    h.client.close()


class TestAccepted:
    def test_a_signed_withdrawal_is_appended_after_the_original(self, hosted):
        record = hosted.sign_withdrawal()
        r = hosted.post(record)
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["state"], body["sequence"], body["advisory_id"], body["written"]) == (
            "withdrawn", 2, ADV, True)
        lines = hosted.hosted_text().splitlines()
        assert len(lines) == 2                       # feed GET shows both
        first, second = (json.loads(x) for x in lines)
        assert first["withdraws"] == "" and second["withdraws"] == ADV
        assert second["withdrawal_reason"] == "range was wrong"
        assert second["previous"] == SignedAdvisory.from_dict(first).content_hash()

    def test_the_original_record_is_byte_for_byte_unchanged(self, hosted):
        before = hosted.feed_file.read_bytes()
        assert hosted.post(hosted.sign_withdrawal()).status_code == 201
        after = hosted.feed_file.read_bytes()
        assert after.startswith(before) and len(after) > len(before)
        assert hashlib.sha256(after[:len(before)]).hexdigest() == hashlib.sha256(before).hexdigest()
        served = hosted.hosted_text().encode("utf-8")
        assert served == after                        # the feed is served as written

    def test_a_repeat_is_idempotent_and_writes_nothing(self, hosted):
        record = hosted.sign_withdrawal()
        assert hosted.post(record).status_code == 201
        before = hosted.feed_file.read_bytes()
        again = hosted.post(record)
        assert again.status_code == 200
        assert again.json()["state"] == "already_withdrawn"
        assert again.json()["written"] is False and again.json()["sequence"] == 2
        assert hosted.feed_file.read_bytes() == before

    def test_a_second_withdrawal_with_another_reason_is_also_not_written(self, hosted):
        first = hosted.sign_withdrawal()
        other = _resign(first, hosted.key, withdrawal_reason="a different reason")
        assert hosted.post(first).status_code == 201
        before = hosted.feed_file.read_bytes()
        r = hosted.post(other)
        assert r.status_code == 200 and r.json()["state"] == "already_withdrawn"
        assert hosted.feed_file.read_bytes() == before

    def test_the_cli_and_the_api_accept_the_same_record_bytes(self, hosted):
        keyfile = hosted.tmp / "psirt.pem"
        hosted.key.save(keyfile)      # the supplier's key file, as `supplier keygen` writes it
        # the CLI signs the withdrawal on a local copy of the hosted feed
        copy = hosted.tmp / "cli-copy.jsonl"
        copy.write_text(hosted.hosted_text(), "utf-8")
        rc = supplier_main(["withdraw", ADV, "--reason", "range was wrong", "--feed", str(copy),
                            "--key", str(keyfile), "--supplier-id", "controlco",
                            "--legal-name", "ControlCo GmbH", "--key-contact",
                            "the 2025 supply contract"])
        assert rc == 0
        cli_line = copy.read_text("utf-8").splitlines()[-1]
        r = hosted.post(json.loads(cli_line))
        assert r.status_code == 201, r.text
        hosted_line = hosted.hosted_text().splitlines()[-1]
        assert json.loads(hosted_line) == json.loads(cli_line)
        assert hosted_line == cli_line               # same bytes, not merely the same fields


class TestRefused:
    def _unchanged(self, hosted, fn):
        before = hosted.feed_file.read_bytes()
        r = fn()
        assert hosted.feed_file.read_bytes() == before
        return r

    def test_unsigned_is_422(self, hosted):
        body = hosted.sign_withdrawal().to_dict()
        body["signature"] = ""
        r = self._unchanged(hosted, lambda: hosted.post(body))
        assert r.status_code == 422 and r.json()["detail"]["error"] == "unsigned_advisory"

    def test_a_tampered_record_is_refused(self, hosted):
        body = hosted.sign_withdrawal().to_dict()
        body["withdrawal_reason"] = "actually, ignore the advisory entirely"
        r = self._unchanged(hosted, lambda: hosted.post(body))
        assert r.status_code == 403 and r.json()["detail"]["error"] == "signature_invalid"

    def test_a_key_that_is_not_pinned_is_refused(self, hosted):
        stranger = SigningKey.generate()
        record = hosted.sign_withdrawal(key=stranger)
        r = self._unchanged(hosted, lambda: hosted.post(record))
        assert r.status_code == 403 and r.json()["detail"]["error"] == "supplier_key_not_pinned"

    def test_naming_the_pinned_fingerprint_does_not_make_a_foreign_signature_pass(self, hosted):
        stranger = SigningKey.generate()
        forged = _resign(hosted.sign_withdrawal(), stranger,
                         key_fingerprint=hosted.key.fingerprint)
        r = self._unchanged(hosted, lambda: hosted.post(forged))
        assert r.status_code == 403 and r.json()["detail"]["error"] == "signature_invalid"

    def test_a_revoked_key_is_refused(self, hosted):
        record = hosted.sign_withdrawal()
        SupplierTrustStore(hosted.api.tenant_ledger(hosted.account_id)).revoke(
            "controlco", hosted.key.fingerprint, actor="sales", reason="key lost")
        r = self._unchanged(hosted, lambda: hosted.post(record))
        assert r.status_code == 403 and r.json()["detail"]["error"] == "supplier_key_not_in_force"

    def test_an_account_with_no_pin_cannot_withdraw(self, live_api, tmp_path, monkeypatch):
        h = Hosted(live_api, tmp_path, monkeypatch, email="nopin@example.de")
        h.publish()
        other_acct, other_headers = live_api.account("other@example.de", "supplier")
        record = h.sign_withdrawal()
        r = h.post(record, headers=other_headers)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "supplier_key_not_pinned"
        h.client.close()

    def test_an_unknown_advisory_is_404(self, hosted):
        ghost = _resign(hosted.sign_withdrawal(), hosted.key, withdraws="NOPE-1")
        r = self._unchanged(hosted, lambda: hosted.post(ghost))
        assert r.status_code == 404 and r.json()["detail"]["error"] == "advisory_not_in_feed"

    def test_a_withdrawal_that_changes_the_advisory_is_refused(self, hosted):
        record = hosted.sign_withdrawal()
        changed = dict(record.advisory, title="something else")
        bad = _resign(record, hosted.key, advisory=changed)
        r = self._unchanged(hosted, lambda: hosted.post(bad))
        assert r.status_code == 422 and r.json()["detail"]["error"] == "withdrawal_content_mismatch"

    def test_a_publication_is_not_a_withdrawal(self, hosted):
        record = hosted.sign_withdrawal()
        body = _resign(record, hosted.key, withdraws="", withdrawal_reason="").to_dict()
        r = hosted.post(body)
        assert r.status_code == 422 and r.json()["detail"]["error"] == "not_a_withdrawal"

    def test_a_stale_chain_is_a_409(self, hosted):
        record = hosted.sign_withdrawal()
        stale = _resign(record, hosted.key, previous="0" * 64)
        r = self._unchanged(hosted, lambda: hosted.post(stale))
        assert r.status_code == 409 and r.json()["detail"]["error"] == "chain_mismatch"

    def test_a_malformed_body_is_422(self, hosted):
        r = hosted.post({"not": "a record"})
        assert r.status_code == 422


class TestGateAndTenancy:
    def test_no_key_is_401(self, live_api):
        with live_api.client() as c:
            assert c.post(WITHDRAW, json={}).status_code == 401

    def test_a_cell_key_is_402_not_403(self, live_api):
        _, headers = live_api.account("cell@example.de", "cell")
        with live_api.client() as c:
            r = c.post(WITHDRAW, json={}, headers=headers)
        assert r.status_code == 402
        assert r.json()["detail"]["error"] == "plan_does_not_include_supplier_publish"

    def test_another_tenant_cannot_withdraw_from_this_feed(self, hosted):
        rival_id, headers = hosted.api.account("rival@example.de", "supplier")
        record = hosted.sign_withdrawal()
        # no pin of its own: refused before the feed is even looked at
        r = hosted.post(record, headers=headers)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "supplier_key_not_pinned"
        # even holding the same pinned key it has no such advisory: its feed is its own
        _pin(hosted.api.tenant_ledger(rival_id), hosted.key)
        before = hosted.feed_file.read_bytes()
        r = hosted.post(record, headers=headers)
        assert r.status_code == 404
        assert hosted.feed_file.read_bytes() == before
        assert not (hosted.tmp / "feeds" / f"{rival_id}.jsonl").exists()
        assert hosted.client.get(f"/v1/supplier/feed/{rival_id}").status_code == 404


class TestEndToEnd:
    def test_publish_evaluate_standing_withdraw_evaluate_withdrawn_and_watch(
            self, hosted, tmp_path):
        # an integrator (a Cell account) pins the supplier's key in its OWN ledger
        consumer_id, consumer = hosted.api.account("integrator@example.de", "cell")
        _pin(hosted.api.tenant_ledger(consumer_id), hosted.key)

        def evaluate() -> dict:
            r = hosted.client.post("/v1/supplier/trust/evaluate", headers=consumer,
                                   json={"hosted_feed_id": hosted.account_id})
            assert r.status_code == 200, r.text
            return r.json()["trust"]

        standing = evaluate()
        assert [a["advisory_id"] for a in standing["advisories"]] == [ADV]
        assert standing["withdrawn"] == []

        # a plant watch (integrator side) with an enrolled machine and its own pin
        led = EvidenceLedger(tmp_path / "plant.db")
        enrol(led, "0001")
        store = SupplierTrustStore(led)
        _pin(led, hosted.key)
        plant_feed = tmp_path / "plant-feed.jsonl"
        plant_feed.write_text(hosted.hosted_text(), "utf-8")
        sub = FeedSubscription(supplier_id="controlco", feed=str(plant_feed),
                               public_key=str(tmp_path / "unused.pub"))
        first = check_feeds([sub], Fleet.from_ledger(led), trust_store=store)
        assert first.findings[0].state == "new" and first.withdrawn == ()

        assert hosted.post(hosted.sign_withdrawal(reason="3.8.2 is not affected")).status_code == 201

        after = evaluate()
        assert after["advisories"] == [] and after["withdrawn"] == [ADV]
        assert after["policy_satisfied"] is True

        plant_feed.write_text(hosted.hosted_text(), "utf-8")
        second = check_feeds([sub], Fleet.from_ledger(led), trust_store=store,
                             previously_seen={ADV: "new"})
        assert [f.advisory_id for f in second.withdrawn] == [ADV]
        assert "3.8.2 is not affected" in second.withdrawn[0].withdrawal_reason
