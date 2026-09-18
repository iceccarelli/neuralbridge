"""The hosted supplier feed over HTTP: fails closed the same way every
other paid gate in this codebase does, and never re-derives the feed
invariants differently than the CLI does.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from assurance.attest.keys import SigningKey
from assurance.billing.accounts import AccountStore
from assurance.core.identity import parse_utc
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.supplier.publish import AdvisoryFeed, SupplierIdentity, publish

IDENTITY = SupplierIdentity(
    supplier_id="controlco",
    legal_name="ControlCo GmbH",
    key_contact="printed on every quotation, and at controlco.example/psirt/key",
)


def _advisory(advisory_id: str = "CTRL-2026-11") -> ComponentAdvisory:
    return ComponentAdvisory(
        advisory_id=advisory_id,
        issued_by="controlco",
        issued_at=parse_utc("2026-09-10T08:00:00Z"),
        title="Authentication bypass in safety controller firmware",
        summary="A crafted frame permits a safety parameter write.",
        severity=AdvisorySeverity.STOP_USE,
        reference="https://controlco.example/psirt/CTRL-2026-11",
        remedy="Update to 3.9.1.",
        affected=(AffectedArtefact(supplier="ControlCo", name="Safety controller firmware",
                                    versions=("3.8.2", "3.9.0")),),
    )


def _signed_record(feed_path, advisory_id="CTRL-2026-11", key=None):
    key = key or SigningKey.generate()
    feed = AdvisoryFeed(feed_path)
    return publish(_advisory(advisory_id), IDENTITY, key, feed)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "supplier-feeds"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_do_not_ship")
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    return tmp_path


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


@pytest.fixture()
def store(env):
    return AccountStore(str(env / "accounts.db"))


class TestPublish:
    def test_no_key_is_a_401(self, client):
        response = client.post("/v1/supplier/advisory", json={})
        assert response.status_code == 401

    def test_a_cell_key_is_a_402_not_a_403(self, client, store):
        # The obstacle is payment, same as every other gate — never a 403.
        account = store.upsert_account(email="a@b.de", tier="cell")
        key = store.issue_key(account.id)
        response = client.post(
            "/v1/supplier/advisory", json={}, headers={"X-API-Key": key}
        )
        assert response.status_code == 402
        assert response.json()["detail"]["error"] == "plan_does_not_include_supplier_publish"

    def test_an_unsigned_record_is_rejected(self, client, store, env):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        record = _signed_record(env / "local-feed.jsonl")
        body = record.to_dict()
        body["signature"] = ""
        response = client.post(
            "/v1/supplier/advisory", json=body, headers={"X-API-Key": key}
        )
        assert response.status_code == 422
        assert response.json()["detail"]["error"] == "unsigned_advisory"

    def test_a_malformed_body_is_rejected(self, client, store):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        response = client.post(
            "/v1/supplier/advisory", json={"not": "an advisory"}, headers={"X-API-Key": key}
        )
        assert response.status_code == 422
        assert response.json()["detail"]["error"] == "malformed_advisory"

    def test_a_first_signed_advisory_publishes(self, client, store, env):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        record = _signed_record(env / "local-feed.jsonl")

        response = client.post(
            "/v1/supplier/advisory", json=record.to_dict(), headers={"X-API-Key": key}
        )
        assert response.status_code == 201
        body = response.json()
        assert body["sequence"] == 1
        assert body["advisory_id"] == "CTRL-2026-11"
        assert body["feed_url"] == f"/v1/supplier/feed/{account.id}"

    def test_a_second_record_must_chain_onto_the_first(self, client, store, env):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        signing_key = SigningKey.generate()
        local_feed_path = env / "local-feed.jsonl"

        first = _signed_record(local_feed_path, key=signing_key)
        assert client.post(
            "/v1/supplier/advisory", json=first.to_dict(), headers={"X-API-Key": key}
        ).status_code == 201

        # A second, independently-signed record that never saw the hosted
        # feed's own history — it still chains correctly because it was
        # built on top of the same local feed file, which is exactly how a
        # real supplier would work: sign locally, publish, sign the next one.
        second = _signed_record(local_feed_path, advisory_id="CTRL-2026-12", key=signing_key)
        response = client.post(
            "/v1/supplier/advisory", json=second.to_dict(), headers={"X-API-Key": key}
        )
        assert response.status_code == 201
        assert response.json()["sequence"] == 2

    def test_a_stale_sequence_is_refused(self, client, store, env):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        record = _signed_record(env / "local-feed.jsonl")
        assert client.post(
            "/v1/supplier/advisory", json=record.to_dict(), headers={"X-API-Key": key}
        ).status_code == 201

        # Replaying the same (sequence 1) record a second time must not be
        # silently accepted as a no-op — it is a stale write.
        response = client.post(
            "/v1/supplier/advisory", json=record.to_dict(), headers={"X-API-Key": key}
        )
        assert response.status_code == 409

    def test_a_different_supplier_identity_on_the_same_account_is_refused(self, client, store, env):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        first = _signed_record(env / "feed-a.jsonl")
        assert client.post(
            "/v1/supplier/advisory", json=first.to_dict(), headers={"X-API-Key": key}
        ).status_code == 201

        other_identity = SupplierIdentity(
            supplier_id="scanco", legal_name="ScanCo", key_contact="scanco.example/psirt"
        )
        other_advisory = ComponentAdvisory(
            advisory_id="SCAN-2026-01", issued_by="scanco",
            issued_at=parse_utc("2026-09-10T08:00:00Z"),
            title="x", summary="x", severity=AdvisorySeverity.STOP_USE,
            reference="https://scanco.example/x", remedy="x",
            affected=(AffectedArtefact(supplier="ScanCo", name="Scanner", versions=("1.0",)),),
        )
        stray_feed = AdvisoryFeed(env / "feed-b.jsonl")
        stray_record = publish(other_advisory, other_identity, SigningKey.generate(), stray_feed)

        response = client.post(
            "/v1/supplier/advisory", json=stray_record.to_dict(), headers={"X-API-Key": key}
        )
        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "supplier_identity_mismatch"


class TestReadFeed:
    def test_an_unpublished_feed_is_a_404(self, client):
        assert client.get("/v1/supplier/feed/nonexistent").status_code == 404

    def test_reading_a_feed_needs_no_account(self, client, store, env):
        account = store.upsert_account(email="a@b.de", tier="supplier")
        key = store.issue_key(account.id)
        record = _signed_record(env / "local-feed.jsonl")
        client.post("/v1/supplier/advisory", json=record.to_dict(), headers={"X-API-Key": key})

        response = client.get(f"/v1/supplier/feed/{account.id}")
        assert response.status_code == 200
        assert "CTRL-2026-11" in response.text


class TestOpenMode:
    def test_open_mode_grants_supplier_publish_for_local_eval(self, client, env, monkeypatch):
        monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
        record = _signed_record(env / "local-feed.jsonl")
        response = client.post("/v1/supplier/advisory", json=record.to_dict())
        assert response.status_code == 201
