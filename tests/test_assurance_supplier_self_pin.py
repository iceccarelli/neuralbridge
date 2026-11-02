"""POST /v1/supplier/advisory/key: a Supplier-tier account pins ITS OWN publishing key.

The pin is the account holder's declaration, in the account's own ledger, for the
supplier id its feed carries. It never names another supplier id, never accepts a
private key, never reaches another tenant, and rotation retires (not deletes).
"""

from __future__ import annotations

import pytest

from assurance.attest.keys import SigningKey
from assurance.supplier.publish import (
    AdvisoryFeed,
    SignedAdvisory,
    _parse_feed_text,
    publish,
    withdraw,
)
from assurance.supplier.trust import SupplierTrustStore, evaluate_feed

from . import interfaces_fixtures as fx
from .test_assurance_supplier_withdraw_api import ADV, IDENTITY, PUBLISH, WITHDRAW, _adv

live_api = fx.live_api
KEY = "/v1/supplier/advisory/key"
FAKE_PRIVATE = ("-----BEGIN PRIVATE KEY-----\n"
                "MC4CAQAwBQYDK2VwBCIEIEXAMPLESECRETMATERIALxxxxxxxxxxxxxxxxxxx\n"
                "-----END PRIVATE KEY-----\n")


class Sup:
    """A supplier account with a decider operator, a published advisory and NO pin."""

    def __init__(self, live_api, tmp_path, monkeypatch, email="sup@example.de",
                 publish_first=True):
        monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "feeds"))
        self.api, self.tmp = live_api, tmp_path
        self.account_id, self.account_headers = live_api.account(email, "supplier")
        self.headers = live_api.operator_headers(self.account_id, "p.engineer")
        self.key = SigningKey.generate()
        self.client = live_api.client()
        if publish_first:
            self.publish()

    def publish(self):
        local = AdvisoryFeed(self.tmp / f"local-{self.account_id}.jsonl")
        rec = publish(_adv(), IDENTITY, self.key, local)
        r = self.client.post(PUBLISH, json=rec.to_dict(), headers=self.account_headers)
        assert r.status_code == 201, r.text

    def pin(self, key=None, headers=None, **extra):
        return self.client.post(KEY, headers=headers or self.headers,
                                json={"public_key_pem": (key or self.key).verifying.pem(), **extra})

    def store(self) -> SupplierTrustStore:
        return SupplierTrustStore(self.api.tenant_ledger(self.account_id))

    def hosted_text(self) -> str:
        return self.client.get(f"/v1/supplier/feed/{self.account_id}").text

    def withdrawal(self, reason="range was wrong") -> SignedAdvisory:
        copy = self.tmp / "copy.jsonl"
        copy.write_text(self.hosted_text(), "utf-8")
        return withdraw(ADV, reason, IDENTITY, self.key, AdvisoryFeed(copy))


@pytest.fixture()
def sup(live_api, tmp_path, monkeypatch):
    s = Sup(live_api, tmp_path, monkeypatch)
    yield s
    s.client.close()


class TestSelfPin:
    def test_publish_pin_withdraw_evaluate_shows_withdrawn(self, sup):
        rec = sup.withdrawal()
        # before the pin the withdrawal is refused
        r = sup.client.post(WITHDRAW, json=rec.to_dict(), headers=sup.headers)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "supplier_key_not_pinned"

        r = sup.pin()
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["state"], body["written"], body["supplier_id"]) == ("pinned", True, "controlco")
        assert body["pin"]["fingerprint"] == sup.key.verifying.fingerprint
        assert "as declared by this account" in body["statement"].lower()
        assert "not evidence of the supplier's real-world identity" in body["statement"]
        assert "p.engineer" in body["pin"]["pinned_by"]
        assert "self-pin" in body["pin"]["obtained_via"]

        w = sup.client.post(WITHDRAW, json=rec.to_dict(), headers=sup.headers)
        assert w.status_code == 201, w.text
        trust = evaluate_feed(_parse_feed_text(sup.hosted_text(), source="t"), sup.store(),
                              expect_supplier="controlco").to_dict()
        assert trust["withdrawn"] == [ADV] and trust["advisories"] == []
        assert trust["policy_satisfied"] is True

    def test_the_same_key_again_is_idempotent(self, sup):
        assert sup.pin().status_code == 201
        r = sup.pin()
        assert r.status_code == 200
        assert (r.json()["state"], r.json()["written"]) == ("already_pinned", False)
        assert len(sup.store().history()) == 1

    def test_effective_from_is_honoured(self, sup):
        r = sup.pin(effective_from="2030-01-01T00:00:00Z")
        assert r.status_code == 201
        assert r.json()["pin"]["effective_from"].startswith("2030-01-01")
        w = sup.client.post(WITHDRAW, json=sup.withdrawal().to_dict(), headers=sup.headers)
        assert w.status_code == 403 and w.json()["detail"]["error"] == "supplier_key_not_in_force"

    def test_the_pin_is_for_the_supplier_id_the_feed_carries(self, sup):
        sup.pin()
        assert {p.supplier_id for p in sup.store().pins()} == {"controlco"}


class TestRotation:
    def test_a_second_key_needs_effective_at_and_retires_the_old_one(self, sup):
        assert sup.pin().status_code == 201
        new = SigningKey.generate()
        r = sup.pin(new)
        assert r.status_code == 422 and r.json()["detail"]["error"] == "rotation_needs_effective_at"
        assert len(sup.store().pins()) == 1
        r = sup.pin(new, effective_at="2026-06-01T00:00:00Z")
        assert r.status_code == 201, r.text
        assert r.json()["state"] == "rotated"
        pins = {p.fingerprint: p for p in sup.store().pins("controlco")}
        assert len(pins) == 2                       # retired, not deleted
        old, fresh = pins[sup.key.verifying.fingerprint], pins[new.verifying.fingerprint]
        assert old.status == "retired" and old.retired_at.startswith("2026-06-01")
        assert fresh.status == "active"

    def test_a_retired_key_cannot_be_pinned_again(self, sup):
        new = SigningKey.generate()
        assert sup.pin().status_code == 201
        assert sup.pin(new, effective_at="2026-06-01T00:00:00Z").status_code == 201
        r = sup.pin(sup.key, effective_at="2026-07-01T00:00:00Z")
        assert r.status_code == 409 and r.json()["detail"]["error"] == "trust_decision_refused"


class TestRefused:
    def test_no_key_is_401(self, live_api):
        with live_api.client() as c:
            assert c.post(KEY, json={}).status_code == 401

    def test_a_cell_key_is_402_exactly_as_publish(self, live_api):
        _, headers = live_api.account("cell@example.de", "cell")
        with live_api.client() as c:
            r = c.post(KEY, json={}, headers=headers)
            p = c.post(PUBLISH, json={}, headers=headers)
        assert r.status_code == p.status_code == 402
        assert r.json() == p.json()
        assert r.json()["detail"]["error"] == "plan_does_not_include_supplier_publish"

    def test_a_private_key_is_refused_unread_and_not_echoed(self, sup):
        for payload in ({"public_key_pem": FAKE_PRIVATE},
                        {"public_key_pem": "x", "other": FAKE_PRIVATE},
                        {"public_key_pem": "x", "reason": "k", "supplier_id": FAKE_PRIVATE}):
            for headers in (sup.headers, sup.account_headers):
                r = sup.client.post(KEY, json=payload, headers=headers)
                assert r.status_code == 422, r.text
                assert r.json()["detail"]["error"] == "private_key_refused"
                assert "EXAMPLESECRET" not in r.text and "MC4CAQAw" not in r.text
        assert sup.store().pins() == []

    @pytest.mark.parametrize("pem", [
        "", "not a pem",
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"])
    def test_garbage_pem_is_422(self, sup, pem):
        r = sup.client.post(KEY, json={"public_key_pem": pem}, headers=sup.headers)
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_public_key"

    def test_oversize_pem_is_422_and_not_echoed(self, sup):
        r = sup.client.post(KEY, json={"public_key_pem": "A" * 5000}, headers=sup.headers)
        assert r.status_code == 422 and "AAAAAAAAAA" not in r.text

    def test_cannot_name_another_supplier_id(self, sup):
        for name in ("supplier_id", "supplier"):
            r = sup.pin(**{name: "someone-else"})
            assert r.status_code == 422 and r.json()["detail"]["error"] == "unexpected_fields"
        assert sup.store().pins() == []

    def test_no_published_feed_means_no_identity_409(self, live_api, tmp_path, monkeypatch):
        s = Sup(live_api, tmp_path, monkeypatch, publish_first=False)
        try:
            r = s.pin()
            assert r.status_code == 409 and r.json()["detail"]["error"] == "no_supplier_identity"
        finally:
            s.client.close()

    def test_an_account_level_key_is_not_a_named_person(self, sup):
        r = sup.pin(headers=sup.account_headers)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "operator_required"
        assert sup.store().pins() == []

    def test_the_operator_account_is_refused(self, live_api, tmp_path, monkeypatch):
        monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "feeds"))
        monkeypatch.setenv("ASSURANCE_API_KEYS", "operator-test-key")
        with live_api.client() as c:
            r = c.post(KEY, json={"public_key_pem": SigningKey.generate().verifying.pem()},
                       headers={"X-API-Key": "operator-test-key"})
        # the operator "account" is not on the Supplier plan, so the publish gate already
        # refuses it; nothing is written to the shared ledger
        assert r.status_code == 402, r.text
        assert not (tmp_path / "operator.db").exists() or SupplierTrustStore(
            live_api.tenant_ledger("operator")).pins() == []

    def test_the_route_uses_the_per_account_store_helper(self):
        """Defence in depth: even past the gate the operator ledger holds no pins."""
        from fastapi import HTTPException

        from assurance.api.supplier_routes import account_trust_store
        from assurance.billing.accounts import Principal

        with pytest.raises(HTTPException) as exc:
            account_trust_store(Principal(account=None, key_prefix=""), object())
        assert exc.value.status_code == 403
        assert exc.value.detail["error"] == "supplier_trust_is_per_account"


class TestTenancy:
    def test_another_tenant_neither_sees_nor_is_affected_by_the_pin(
            self, live_api, tmp_path, monkeypatch):
        a = Sup(live_api, tmp_path, monkeypatch, "a@example.de")
        try:
            assert a.pin().status_code == 201
            b_id, b_acct = live_api.account("b@example.de", "supplier")
            b_headers = live_api.operator_headers(b_id, "b.engineer")
            assert SupplierTrustStore(live_api.tenant_ledger(b_id)).pins() == []
            # B publishes a record signed by A's key; A's pin does not exist for B
            rec = publish(_adv(), IDENTITY, a.key, AdvisoryFeed(tmp_path / "b-local.jsonl"))
            assert a.client.post(PUBLISH, json=rec.to_dict(), headers=b_acct).status_code == 201
            copy = tmp_path / "b-copy.jsonl"
            copy.write_text(a.client.get(f"/v1/supplier/feed/{b_id}").text, "utf-8")
            w = withdraw(ADV, "x", IDENTITY, a.key, AdvisoryFeed(copy))
            r = a.client.post(WITHDRAW, json=w.to_dict(), headers=b_headers)
            assert r.status_code == 403 and r.json()["detail"]["error"] == "supplier_key_not_pinned"
            assert SupplierTrustStore(live_api.tenant_ledger(b_id)).pins() == []
        finally:
            a.client.close()
