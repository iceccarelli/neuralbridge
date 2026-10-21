"""An Idempotency-Key identifies one REQUEST, not one scope+quantity.

Red-team finding: a repeat key with the same scope and quantity returned the old
record, so 100 different bodies under one key were all served, counted once, and
the pre-check skipped the 429. A key now carries a fingerprint of the request
(scope, method, path, query, canonical body); a different request under the same
key is a 409 ``idempotency_key_reused`` and is neither served nor recorded.
"""

from __future__ import annotations

import importlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing.accounts import AccountStore, IdempotencyConflictError
from assurance.billing.plans import PLANS

OPERATOR_KEY = "operator-key-idem"
VALIDATE = {"track": "actively_exploited_vulnerability", "stage": "early_warning",
            "payload": {}}
ALLOWANCE = PLANS["free"].validations_per_day


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL",
                 "ASSURANCE_TENANT_LEDGERS", "ASSURANCE_TRUST_FLY_PROXY",
                 "ASSURANCE_PRICE_PAYG", "ASSURANCE_PAYG_METER_EVENT"):
        monkeypatch.delenv(name, raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def store(env):
    return AccountStore(env / "accounts.db")


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


def key_for(store, email="h@example.de"):
    account = store.upsert_account(email=email, tier="free")
    return account, {"X-API-Key": store.issue_key(account.id)}


def events(store, account_id):
    db = sqlite3.connect(store.path)
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(
            "SELECT * FROM usage_events WHERE account_id=? ORDER BY rowid", (account_id,))]
    finally:
        db.close()


def counter(store, account_id, scope="validate"):
    return store.usage_today(account_id).get(scope, 0)


def body(n: int) -> dict:
    return {**VALIDATE, "payload": {"n": n}}


class TestStore:
    def test_same_fingerprint_is_a_replay(self, store):
        a = store.upsert_account(email="a@example.de", tier="free")
        first = store.record_usage(a.id, "validate", 1, "k", fingerprint="fp-1")
        again = store.record_usage(a.id, "validate", 1, "k", fingerprint="fp-1")
        assert again.duplicate is True and again.event_id == first.event_id
        assert len(events(store, a.id)) == 1 and counter(store, a.id) == 1

    def test_other_fingerprint_is_a_conflict_and_records_nothing(self, store):
        a = store.upsert_account(email="a@example.de", tier="free")
        store.record_usage(a.id, "validate", 1, "k", fingerprint="fp-1")
        with pytest.raises(IdempotencyConflictError):
            store.record_usage(a.id, "validate", 1, "k", fingerprint="fp-2")
        with pytest.raises(IdempotencyConflictError):
            store.check_usage(a.id, "validate", 1, "k", fingerprint="fp-2")
        store.check_usage(a.id, "validate", 1, "k", fingerprint="fp-1")  # a replay passes
        assert len(events(store, a.id)) == 1 and counter(store, a.id) == 1

    def test_fingerprint_is_persisted_in_an_additive_column(self, store):
        a = store.upsert_account(email="a@example.de", tier="free")
        store.record_usage(a.id, "validate", 1, "k", fingerprint="fp-1")
        assert events(store, a.id)[0]["fingerprint"] == "fp-1"

    def test_a_row_without_a_fingerprint_still_replays_by_key(self, tmp_path):
        """Written by the previous build: the key alone decides, as it did."""
        path = tmp_path / "accounts.db"
        store = AccountStore(path)
        a = store.upsert_account(email="old@example.de", tier="free")
        db = sqlite3.connect(path)
        try:
            db.execute(
                "INSERT INTO usage_events (event_id, account_id, scope, quantity, "
                "idempotency_key, occurred_at, billed_state) "
                "VALUES ('uev_old', ?, 'validate', 1, 'legacy', '2026-01-01T00:00:00Z', "
                "'included')", (a.id,))
            db.commit()
        finally:
            db.close()
        rec = store.record_usage(a.id, "validate", 1, "legacy", fingerprint="fp-new")
        assert rec.duplicate is True and rec.event_id == "uev_old"

    def test_migration_adds_the_column_to_a_store_created_without_it(self, tmp_path):
        path = tmp_path / "accounts.db"
        AccountStore(path)
        db = sqlite3.connect(path)
        try:
            db.execute("ALTER TABLE usage_events DROP COLUMN fingerprint")
            db.commit()
        finally:
            db.close()
        AccountStore(path)
        db = sqlite3.connect(path)
        try:
            cols = {r[1] for r in db.execute("PRAGMA table_info(usage_events)")}
        finally:
            db.close()
        assert "fingerprint" in cols


class TestOverHttp:
    def test_100_different_bodies_under_one_key_are_not_served(self, client, store):
        account, headers = key_for(store)
        h = {**headers, "Idempotency-Key": "one-key-many-bodies"}
        first = client.post("/v1/spec/validate", json=body(0), headers=h)
        assert first.status_code == 200, first.text
        codes = [client.post("/v1/spec/validate", json=body(i), headers=h).status_code
                 for i in range(1, 100)]
        assert set(codes) == {409}
        r = client.post("/v1/spec/validate", json=body(1), headers=h)
        assert r.json()["detail"]["error"] == "idempotency_key_reused"
        assert len(events(store, account.id)) == 1 and counter(store, account.id) == 1

    def test_the_same_body_is_a_replay_whatever_its_key_order_or_whitespace(
            self, client, store):
        account, headers = key_for(store)
        h = {**headers, "Idempotency-Key": "replay-me", "content-type": "application/json"}
        a = client.post("/v1/spec/validate", headers=h, content=json.dumps(
            {"track": VALIDATE["track"], "stage": VALIDATE["stage"],
             "payload": {"a": 1, "b": 2}}))
        b = client.post("/v1/spec/validate", headers=h, content=json.dumps(
            {"payload": {"b": 2, "a": 1}, "stage": VALIDATE["stage"],
             "track": VALIDATE["track"]}, indent=2))
        assert (a.status_code, b.status_code) == (200, 200), (a.text, b.text)
        assert len(events(store, account.id)) == 1 and counter(store, account.id) == 1

    def test_a_reused_key_with_a_new_body_is_refused_not_waved_through_when_full(
            self, client, store):
        account, headers = key_for(store)
        h = {**headers, "Idempotency-Key": "full-account"}
        assert client.post("/v1/spec/validate", json=body(0), headers=h).status_code == 200
        for i in range(ALLOWANCE - 1):
            assert client.post("/v1/spec/validate", json=body(i + 1000),
                               headers=headers).status_code == 200
        assert counter(store, account.id) == ALLOWANCE
        r = client.post("/v1/spec/validate", json=body(999), headers=h)
        assert r.status_code == 409, r.text  # not a served 200, not a skipped check
        assert client.post("/v1/spec/validate", json=body(5), headers=headers).status_code == 429
        # the true replay is still served
        assert client.post("/v1/spec/validate", json=body(0), headers=h).status_code == 200
        assert counter(store, account.id) == ALLOWANCE
