"""Billing and edge hardening.

Each class pins one defect that an audit confirmed against the code: account
takeover by email, a non-idempotent webhook, an entitlement mapping that
re-activated everything it did not recognise, plaintext keys that never
expired, advertised limits that nothing enforced, a free-tier quota shared by
the whole internet behind a proxy, keys that could not be revoked, an
unauthenticated health check that leaked a path and did O(n) work, and request
bodies of unbounded size.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import re
import sqlite3
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing import plans as plans_module
from assurance.billing.accounts import (
    ACCOUNTS_SCHEMA_VERSION,
    PENDING_KEY_TTL,
    AccountStore,
)
from assurance.billing.plans import PLANS
from assurance.core.identity import format_utc, utc_now

from .test_assurance_billing import WEBHOOK_SECRET, _signed

OPERATOR_KEY = "operator-key-hardening"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    for name in (
        "ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY", "ASSURANCE_PRICE_REGISTER",
        "ASSURANCE_PRICE_CELL", "ASSURANCE_TRUST_FLY_PROXY", "ASSURANCE_MAX_BODY_BYTES",
        "ASSURANCE_MAX_TRACE_BODY_BYTES", "ASSURANCE_TENANT_LEDGERS",
    ):
        monkeypatch.delenv(name, raising=False)
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


@pytest.fixture()
def store(client):
    return deps.get_accounts()


def rows(store, sql, *args):
    db = sqlite3.connect(store.path)
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def checkout(session="cs_1", customer="cus_1", tier="register", email="m@sk.de",
             event_id="evt_c1", created=1000, **over):
    obj = {
        "id": session, "customer": customer, "subscription": "sub_1",
        "payment_status": "paid",
        "customer_details": {"email": email},
        "metadata": {"tier": tier, "company": "SK"},
    }
    obj.update(over)
    return {"id": event_id, "created": created, "type": "checkout.session.completed",
            "data": {"object": obj}}


def subscription(status, customer="cus_1", event_id="evt_s1", created=2000,
                 kind="customer.subscription.updated", tier="register"):
    return {"id": event_id, "created": created, "type": kind,
            "data": {"object": {"customer": customer, "status": status,
                                "metadata": {"tier": tier}}}}


def hook(client, event):
    raw, headers = _signed(event)
    return client.post("/v1/billing/webhook", content=raw, headers=headers)


def collect(client, session="cs_1"):
    return client.get("/v1/checkout/complete", params={"session_id": session})


def can_use_register(client, key):
    return client.get("/v1/cases", headers={"X-API-Key": key}).status_code


# ---------------------------------------------------------------------------
# 2. account takeover by email
# ---------------------------------------------------------------------------
class TestNoAccountMergeByEmail:
    def test_a_new_customer_with_a_known_email_is_a_new_account(self, store):
        victim = store.upsert_account(email="cfo@victim.de", tier="cell",
                                      stripe_customer_id="cus_victim")
        attacker = store.upsert_account(email="cfo@victim.de", tier="register",
                                        stripe_customer_id="cus_attacker")
        assert attacker.id != victim.id
        after = store.account(victim.id)
        assert (after.tier, after.status, after.stripe_customer_id) == (
            "cell", "active", "cus_victim")

    def test_two_calls_without_an_identity_are_two_accounts(self, store):
        a = store.upsert_account(email="a@b.de", tier="register")
        b = store.upsert_account(email="a@b.de", tier="free")
        assert a.id != b.id
        assert store.account(a.id).tier == "register"

    def test_the_same_customer_is_still_the_same_account(self, store):
        a = store.upsert_account(email="a@b.de", tier="register", stripe_customer_id="cus_1")
        b = store.upsert_account(email="other@b.de", tier="cell", stripe_customer_id="cus_1")
        assert a.id == b.id
        assert store.account(a.id).tier == "cell"

    def test_an_explicit_account_id_updates_that_account(self, store):
        a = store.upsert_account(email="a@b.de", tier="register")
        b = store.upsert_account(email="a@b.de", tier="cell", account_id=a.id)
        assert b.id == a.id and store.account(a.id).tier == "cell"
        with pytest.raises(LookupError):
            store.upsert_account(email="a@b.de", tier="cell", account_id="acc_0000000000000000")

    def test_the_attack_through_the_webhook(self, client, store):
        # The victim pays for Cell. The attacker then checks out for Register,
        # typing the victim's email, and must neither inherit nor overwrite.
        assert hook(client, checkout("cs_v", "cus_victim", "cell", "cfo@victim.de",
                                     "evt_v", 1000)).status_code == 200
        victim_key = collect(client, "cs_v").json()["api_key"]

        assert hook(client, checkout("cs_a", "cus_attacker", "register", "cfo@victim.de",
                                     "evt_a", 1100)).status_code == 200
        attacker_key = collect(client, "cs_a").json()["api_key"]

        victim = client.get("/v1/me", headers={"X-API-Key": victim_key}).json()
        attacker = client.get("/v1/me", headers={"X-API-Key": attacker_key}).json()
        assert victim["tier"] == "cell"
        assert attacker["tier"] == "register"
        assert victim["account"]["id"] != attacker["account"]["id"]
        # And the attacker cannot see the victim's register.
        assert len(rows(store, "SELECT id FROM accounts")) == 2


# ---------------------------------------------------------------------------
# 3. webhook idempotency
# ---------------------------------------------------------------------------
class TestWebhookReplay:
    def test_the_same_event_twice_is_one_account_one_key_and_one_claim(self, client, store):
        first = hook(client, checkout())
        second = hook(client, checkout())
        assert first.status_code == 200 and "account_id" in first.json()
        assert second.status_code == 200
        assert second.json()["duplicate"] is True and second.json()["handled"] == (
            "checkout.session.completed")
        assert rows(store, "SELECT COUNT(*) FROM accounts")[0][0] == 1
        assert rows(store, "SELECT COUNT(*) FROM api_keys")[0][0] == 1

        got = collect(client)
        assert got.status_code == 200
        assert can_use_register(client, got.json()["api_key"]) == 200
        assert collect(client).status_code == 202   # exactly once

    def test_a_replay_after_collection_does_not_re_arm_the_handover(self, client, store):
        hook(client, checkout())
        collect(client)
        again = hook(client, checkout())
        assert again.json()["duplicate"] is True
        assert collect(client).status_code == 202
        assert rows(store, "SELECT COUNT(*) FROM pending_keys")[0][0] == 0
        assert rows(store, "SELECT COUNT(*) FROM api_keys")[0][0] == 1

    def test_a_different_event_for_the_same_session_does_not_mint_again(self, client, store):
        hook(client, checkout(event_id="evt_one"))
        collect(client)
        hook(client, checkout(event_id="evt_two"))
        assert rows(store, "SELECT COUNT(*) FROM api_keys")[0][0] == 1
        assert collect(client).status_code == 202

    def test_a_replayed_cancellation_cannot_undo_a_later_resubscription(self, client):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        hook(client, subscription("canceled", event_id="evt_x", created=2000))
        assert can_use_register(client, key) == 402
        hook(client, subscription("active", event_id="evt_y", created=3000))
        assert can_use_register(client, key) == 200
        assert hook(client, subscription("canceled", event_id="evt_x",
                                         created=2000)).json()["duplicate"] is True
        assert can_use_register(client, key) == 200

    def test_an_existing_database_opens_and_is_upgraded(self, tmp_path):
        # A database written before processed_events/last_event_at existed.
        path = tmp_path / "old.db"
        db = sqlite3.connect(path)
        db.executescript("""
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO meta VALUES ('schema_version', '1');
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY, email TEXT NOT NULL, company TEXT NOT NULL DEFAULT '',
                tier TEXT NOT NULL, stripe_customer_id TEXT NOT NULL DEFAULT '',
                stripe_subscription_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','past_due','cancelled')),
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            INSERT INTO accounts VALUES ('acc_0123456789abcdef','a@b.de','','register',
                'cus_old','sub_old','active','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
        """)
        db.commit()
        db.close()
        assert ACCOUNTS_SCHEMA_VERSION == 1   # additive only: old builds still open it
        store = AccountStore(path)
        again = AccountStore(path)               # idempotent
        assert store.account("acc_0123456789abcdef").tier == "register"
        assert again.account_by_customer("cus_old").last_event_at == 0
        assert rows(store, "SELECT COUNT(*) FROM processed_events")[0][0] == 0

    def test_a_future_schema_is_still_refused(self, tmp_path):
        path = tmp_path / "future.db"
        AccountStore(path)
        db = sqlite3.connect(path)
        db.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        db.commit()
        db.close()
        with pytest.raises(RuntimeError):
            AccountStore(path)


# ---------------------------------------------------------------------------
# 4. entitlement status mapping
# ---------------------------------------------------------------------------
class TestEntitlementMapping:
    @pytest.mark.parametrize("stripe_status,expected", [
        ("active", 200),
        ("trialing", 200),
        ("past_due", 200),
        ("canceled", 402),
        ("unpaid", 402),
        ("incomplete_expired", 402),
        ("paused", 402),
        ("incomplete", 402),
    ])
    def test_each_status_maps_explicitly(self, client, stripe_status, expected):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        resp = hook(client, subscription(stripe_status))
        assert resp.status_code == 200
        assert can_use_register(client, key) == expected

    def test_an_unknown_status_changes_nothing(self, client):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        hook(client, subscription("canceled", created=2000))
        resp = hook(client, subscription("some_future_status", event_id="evt_f", created=3000))
        assert resp.json()["result"] == "ignored_unknown_status"
        assert can_use_register(client, key) == 402   # not "reactivated"

    def test_a_paused_subscription_that_resumes_gets_its_plan_back(self, client):
        hook(client, checkout(tier="cell"))
        key = collect(client).json()["api_key"]
        hook(client, subscription("paused", event_id="e2", created=2000, tier="cell"))
        assert client.get("/v1/me", headers={"X-API-Key": key}).json()["tier"] == "free"
        hook(client, subscription("active", event_id="e3", created=3000, tier="cell"))
        assert client.get("/v1/me", headers={"X-API-Key": key}).json()["tier"] == "cell"

    def test_past_due_is_flagged_not_cut_off(self, client):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        hook(client, subscription("past_due"))
        me = client.get("/v1/me", headers={"X-API-Key": key}).json()
        assert me["account"]["status"] == "past_due" and me["tier"] == "register"
        assert "payment failed" in me["warning"]
        hook(client, subscription("active", event_id="e9", created=3000))
        assert "warning" not in client.get("/v1/me", headers={"X-API-Key": key}).json()

    def test_invoice_payment_failed_marks_past_due_but_cannot_revive_a_cancelled_account(
        self, client
    ):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        failed = {"id": "evt_i1", "created": 1500, "type": "invoice.payment_failed",
                  "data": {"object": {"customer": "cus_1"}}}
        assert hook(client, failed).json()["result"] == "marked_past_due"
        assert can_use_register(client, key) == 200
        hook(client, subscription("canceled", created=2000))
        late_retry = {**failed, "id": "evt_i2", "created": 2500}
        assert hook(client, late_retry).status_code == 200
        assert can_use_register(client, key) == 402   # still cancelled

    def test_invoice_payment_failed_for_an_unknown_customer_is_acknowledged(self, client):
        event = {"id": "evt_i3", "created": 1, "type": "invoice.payment_failed",
                 "data": {"object": {"customer": "cus_nobody"}}}
        assert hook(client, event).status_code == 200


class TestStaleAndOutOfOrder:
    def test_an_older_event_cannot_overwrite_a_newer_one(self, client):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        hook(client, subscription("canceled", event_id="e_new", created=3000))
        # Stripe delivers an older "active" late.
        stale = hook(client, subscription("active", event_id="e_old", created=2000))
        assert stale.json()["result"] == "ignored_stale"
        assert can_use_register(client, key) == 402

    def test_an_older_cancel_cannot_downgrade_a_newer_activation(self, client):
        hook(client, checkout())
        key = collect(client).json()["api_key"]
        hook(client, subscription("active", event_id="e_new", created=3000))
        hook(client, subscription("canceled", event_id="e_old", created=2000))
        assert can_use_register(client, key) == 200

    def test_a_subscription_event_that_overtakes_checkout_is_held_then_applied(
        self, client, store
    ):
        # subscription.updated arrives BEFORE checkout.session.completed.
        early = hook(client, subscription("canceled", customer="cus_9", created=2000))
        assert early.status_code == 200
        assert early.json()["result"] == "held_until_checkout"
        assert rows(store, "SELECT COUNT(*) FROM orphan_states")[0][0] == 1

        hook(client, checkout("cs_9", "cus_9", event_id="evt_c9", created=1000))
        key = collect(client, "cs_9").json()["api_key"]
        assert can_use_register(client, key) == 402          # the newer state won
        assert rows(store, "SELECT COUNT(*) FROM orphan_states")[0][0] == 0

    def test_a_held_state_older_than_checkout_is_discarded(self, client, store):
        hook(client, subscription("canceled", customer="cus_9", created=500))
        hook(client, checkout("cs_9", "cus_9", event_id="evt_c9", created=1000))
        key = collect(client, "cs_9").json()["api_key"]
        assert can_use_register(client, key) == 200
        assert rows(store, "SELECT COUNT(*) FROM orphan_states")[0][0] == 0

    def test_another_products_subscription_is_not_held_or_retried(self, client, store):
        # A customer this service has never seen, on a subscription that is not
        # one of its plans (no price or metadata it recognises): acknowledge.
        event = {"id": "evt_o", "created": 5, "type": "customer.subscription.updated",
                 "data": {"object": {"customer": "cus_other_product", "status": "canceled"}}}
        resp = hook(client, event)
        assert resp.status_code == 200
        assert resp.json()["result"] == "ignored_unknown_customer"
        assert rows(store, "SELECT COUNT(*) FROM orphan_states")[0][0] == 0


class TestCheckoutValidation:
    @pytest.mark.parametrize("tier", ["supplier", "free", "enterprise", "", None])
    def test_only_purchasable_tiers_can_be_granted(self, client, store, tier):
        event = checkout(tier=tier)
        if tier is None:
            del event["data"]["object"]["metadata"]["tier"]
        resp = hook(client, event)
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_tier"
        assert rows(store, "SELECT COUNT(*) FROM accounts")[0][0] == 0
        assert rows(store, "SELECT COUNT(*) FROM api_keys")[0][0] == 0
        assert "supplier" not in resp.text.replace("must be one of", "")

    def test_an_unpaid_session_grants_nothing_until_the_money_arrives(self, client, store):
        resp = hook(client, checkout(payment_status="unpaid"))
        assert resp.status_code == 200 and resp.json()["result"] == "awaiting_payment"
        assert rows(store, "SELECT COUNT(*) FROM accounts")[0][0] == 0
        assert collect(client).status_code == 202

        later = checkout(event_id="evt_late", created=1200)
        later["type"] = "checkout.session.async_payment_succeeded"
        assert hook(client, later).status_code == 200
        assert collect(client).status_code == 200

    def test_a_payment_status_we_do_not_recognise_is_refused(self, client, store):
        assert hook(client, checkout(payment_status="weird")).status_code == 400
        assert rows(store, "SELECT COUNT(*) FROM accounts")[0][0] == 0

    def test_no_payment_required_is_a_grant(self, client):
        assert hook(client, checkout(payment_status="no_payment_required")).status_code == 200

    def test_a_session_without_a_customer_is_refused(self, client, store):
        # Without a customer id no later subscription event could ever reach
        # this account: it could never be cancelled.
        assert hook(client, checkout(customer="")).status_code == 400
        assert rows(store, "SELECT COUNT(*) FROM accounts")[0][0] == 0


# ---------------------------------------------------------------------------
# 5. plaintext key staging
# ---------------------------------------------------------------------------
class TestPendingKeys:
    def test_collecting_deletes_the_staged_plaintext(self, client, store):
        hook(client, checkout())
        assert rows(store, "SELECT COUNT(*) FROM pending_keys")[0][0] == 1
        assert collect(client).status_code == 200
        assert rows(store, "SELECT COUNT(*) FROM pending_keys")[0][0] == 0

    def test_an_uncollected_key_expires_and_is_purged(self, client, store):
        hook(client, checkout())
        old = format_utc(utc_now() - PENDING_KEY_TTL - timedelta(minutes=1))
        db = sqlite3.connect(store.path)
        db.execute("UPDATE pending_keys SET created_at=?", (old,))
        db.commit()
        db.close()
        assert collect(client).status_code == 202
        assert rows(store, "SELECT COUNT(*) FROM pending_keys")[0][0] == 0
        # The key itself still works: only the plaintext handover lapsed.
        assert rows(store, "SELECT COUNT(*) FROM api_keys")[0][0] == 1

    def test_a_key_inside_the_window_is_collectable(self, client, store):
        hook(client, checkout())
        recent = format_utc(utc_now() - PENDING_KEY_TTL + timedelta(minutes=5))
        db = sqlite3.connect(store.path)
        db.execute("UPDATE pending_keys SET created_at=?", (recent,))
        db.commit()
        db.close()
        assert collect(client).status_code == 200

    def test_expired_rows_are_purged_on_the_next_checkout_too(self, client, store):
        hook(client, checkout("cs_old", "cus_old", event_id="e_old"))
        old = format_utc(utc_now() - PENDING_KEY_TTL - timedelta(hours=1))
        db = sqlite3.connect(store.path)
        db.execute("UPDATE pending_keys SET created_at=?", (old,))
        db.commit()
        db.close()
        hook(client, checkout("cs_new", "cus_new", event_id="e_new"))
        left = [r[0] for r in rows(store, "SELECT session_id FROM pending_keys")]
        assert left == ["cs_new"]

    def test_the_wording_is_truthful(self, client):
        hook(client, checkout())
        note = collect(client).json()["keep_this"]
        assert "24 hours" in note and "deleted" in note and "SHA-256" in note
        assert "seconds" not in (AccountStore.stage_pending_key.__doc__ or "")


# ---------------------------------------------------------------------------
# 6. entitlement copy tells the truth
# ---------------------------------------------------------------------------
SRC = Path(deps.__file__).resolve().parents[2]       # src/
_LIMIT_ALIASES = {"register_access": "register", "verifiable_export": "export"}


def _limit_attribute(key: str) -> str:
    return _LIMIT_ALIASES.get(key, key)


def _consumers(attribute: str) -> list[str]:
    """Source files, outside plans.py, that read ``<something>plan.<attribute>``."""
    pattern = re.compile(rf"\bplan\.{re.escape(attribute)}\b")
    found = []
    for source in SRC.rglob("*.py"):
        if source.name == "plans.py" and source.parent.name == "billing":
            continue
        if pattern.search(source.read_text(encoding="utf-8")):
            found.append(str(source.relative_to(SRC)))
    return found


class TestEntitlementCopy:
    def test_unenforced_caps_are_gone(self):
        fields = {f.name for f in dataclasses.fields(plans_module.Plan)}
        assert "cases_per_day" not in fields and "product_families" not in fields
        for plan in PLANS.values():
            limits = plan.to_public_dict()["limits"]
            assert "cases_per_day" not in limits and "product_families" not in limits

    def test_the_prose_matches_the_decision_that_cases_are_not_metered(self):
        text = {t: " | ".join(p.included) for t, p in PLANS.items()}
        for tier, body in text.items():
            assert "Unlimited" not in body, tier
            assert "product families" not in body, tier
            assert "Priority" not in body, tier
        assert "no per-case cap or charge" in text["register"]
        assert "Cases are not metered" in text["register"]
        assert "POST/GET /v1/change/*" in text["cell"]
        assert "named human decision" in text["cell"]

    def test_every_advertised_limit_has_a_backing_field_and_a_consumer(self):
        """If /v1/plans advertises it, some code in src/ must read it.

        A limit that is advertised and consulted nowhere is the defect this
        replaced (``cases_per_day``, ``product_families``). Add a new key to
        ``to_public_dict()['limits']`` and this fails until a route enforces it.
        """
        fields = {f.name for f in dataclasses.fields(plans_module.Plan)}
        limits = PLANS["free"].to_public_dict()["limits"]
        assert limits, "limits vanished"
        unenforced = []
        for key in limits:
            attribute = _limit_attribute(key)
            assert attribute in fields, f"limit {key!r} is not backed by a Plan field"
            if not _consumers(attribute):
                unenforced.append(key)
        assert unenforced == [], f"advertised but never enforced: {unenforced}"

    def test_the_consumer_scan_can_actually_fail(self):
        assert _consumers("validations_per_day")
        assert _consumers("no_such_limit_anywhere") == []

    def test_every_numeric_or_boolean_plan_field_is_advertised(self):
        # The reverse direction: a gate that is enforced but not advertised is
        # a feature the pricing page hides.
        advertised = {_limit_attribute(k) for k in PLANS["free"].to_public_dict()["limits"]}
        gates = {
            f.name for f in dataclasses.fields(plans_module.Plan)
            if f.name not in {"tier", "name", "blurb", "price_env", "price_label", "included"}
        }
        assert gates <= advertised, sorted(gates - advertised)

    def test_export_is_enforced_where_the_export_route_is(self, client, store, monkeypatch):
        account = store.upsert_account(email="e@b.de", tier="register", stripe_customer_id="c")
        headers = {"X-API-Key": store.issue_key(account.id)}
        assert client.get("/v1/cases/NONE/export", headers=headers).status_code != 402
        monkeypatch.setitem(PLANS, "register", dataclasses.replace(PLANS["register"], export=False))
        denied = client.get("/v1/cases/NONE/export", headers=headers)
        assert denied.status_code == 402
        assert denied.json()["detail"]["error"] == "plan_does_not_include_export"


# ---------------------------------------------------------------------------
# 7. the free-tier quota bucket behind a proxy
# ---------------------------------------------------------------------------
def _fake_request(host="10.0.0.9"):
    return SimpleNamespace(client=SimpleNamespace(host=host))


class TestClientAddress:
    def test_the_fly_header_is_ignored_unless_the_operator_opts_in(self):
        assert deps._client_address(_fake_request(), "203.0.113.5") == "10.0.0.9"

    def test_the_fly_header_is_used_when_trusted(self, monkeypatch):
        monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
        assert deps._client_address(_fake_request(), "203.0.113.5") == "203.0.113.5"
        assert deps._client_address(_fake_request(), "2001:db8::1") == "2001:db8::1"

    @pytest.mark.parametrize("junk", [None, "", "  ", "1.2.3.4, evil", "a" * 80,
                                      "<script>", "1.2.3.4\nX: y"])
    def test_a_malformed_header_falls_back_to_the_peer(self, monkeypatch, junk):
        monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
        assert deps._client_address(_fake_request(), junk) == "10.0.0.9"

    def test_quota_buckets_split_per_client_when_trusted(self, client, store, monkeypatch):
        monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
        body = {"track": "severe_incident", "stage": "early_warning", "payload": {}}
        for ip in ("203.0.113.5", "203.0.113.5", "198.51.100.7"):
            assert client.post("/v1/spec/validate", json=body,
                               headers={"Fly-Client-IP": ip}).status_code == 200
        assert store.usage_today("ip:203.0.113.5") == {"validate": 2}
        assert store.usage_today("ip:198.51.100.7") == {"validate": 1}

    def test_a_spoofed_header_cannot_dodge_the_quota_when_not_trusted(self, client, store):
        body = {"track": "severe_incident", "stage": "early_warning", "payload": {}}
        for ip in ("203.0.113.5", "198.51.100.7"):
            client.post("/v1/spec/validate", json=body, headers={"Fly-Client-IP": ip})
        assert store.usage_today("ip:203.0.113.5") == {}
        assert sum(sum(store.usage_today(f"ip:{h}").values()) for h in ("testclient",)) == 2


# ---------------------------------------------------------------------------
# 8. key management
# ---------------------------------------------------------------------------
def _acct(store, email="k@example.de", customer="cus_k"):
    account = store.upsert_account(email=email, tier="register", stripe_customer_id=customer)
    return account, store.issue_key(account.id, label="first")


class TestKeyManagement:
    def test_list_shows_prefixes_and_dates_never_secrets(self, client, store):
        account, key = _acct(store)
        resp = client.get("/v1/keys", headers={"X-API-Key": key})
        assert resp.status_code == 200
        body = resp.json()
        assert body["keys"][0]["prefix"] == key[:10]
        assert body["keys"][0]["revoked"] is False
        assert key not in resp.text
        assert hashlib.sha256(key.encode()).hexdigest() not in resp.text
        assert "key_hash" not in resp.text

    def test_issue_returns_plaintext_once_and_it_works(self, client, store):
        _, key = _acct(store)
        issued = client.post("/v1/keys", headers={"X-API-Key": key}, json={"label": "ci"})
        assert issued.status_code == 201
        new_key = issued.json()["api_key"]
        assert new_key != key and new_key.startswith("asr_")
        assert can_use_register(client, new_key) == 200
        listing = client.get("/v1/keys", headers={"X-API-Key": key})
        assert new_key not in listing.text
        assert {k["label"] for k in listing.json()["keys"]} == {"first", "ci"}
        # Only the digest is stored.
        stored = " ".join(str(r) for r in rows(store, "SELECT * FROM api_keys"))
        assert new_key not in stored

    def test_issue_with_no_body_works(self, client, store):
        _, key = _acct(store)
        assert client.post("/v1/keys", headers={"X-API-Key": key}).status_code == 201

    def test_a_revoked_key_is_a_401_immediately(self, client, store):
        _, key = _acct(store)
        second = client.post("/v1/keys", headers={"X-API-Key": key}).json()["api_key"]
        assert can_use_register(client, key) == 200
        out = client.post("/v1/keys/revoke", headers={"X-API-Key": key})
        assert out.status_code == 200 and out.json()["revoked"] is True
        assert can_use_register(client, key) == 401
        assert client.get("/v1/keys", headers={"X-API-Key": key}).status_code == 401
        assert can_use_register(client, second) == 200      # the other key is untouched

    def test_revoke_another_of_your_keys_by_prefix(self, client, store):
        _, key = _acct(store)
        second = client.post("/v1/keys", headers={"X-API-Key": key}).json()
        out = client.post("/v1/keys/revoke", headers={"X-API-Key": key},
                          json={"key_prefix": second["prefix"]})
        assert out.json()["revoked"] is True and out.json()["active_keys_remaining"] == 1
        assert can_use_register(client, second["api_key"]) == 401
        assert can_use_register(client, key) == 200
        again = client.post("/v1/keys/revoke", headers={"X-API-Key": key},
                            json={"key_prefix": second["prefix"]})
        assert again.json()["already_revoked"] is True

    def test_you_cannot_revoke_someone_elses_key(self, client, store):
        _, mine = _acct(store, "a@example.de", "cus_a")
        _, theirs = _acct(store, "b@example.de", "cus_b")
        out = client.post("/v1/keys/revoke", headers={"X-API-Key": mine},
                          json={"key_prefix": theirs[:10]})
        assert out.status_code == 404                       # same as "no such key"
        assert can_use_register(client, theirs) == 200
        # Nor does listing show it.
        assert theirs[:10] not in client.get("/v1/keys", headers={"X-API-Key": mine}).text

    def test_revoking_the_last_key_warns(self, client, store):
        _, key = _acct(store)
        out = client.post("/v1/keys/revoke", headers={"X-API-Key": key}).json()
        assert out["active_keys_remaining"] == 0 and "No active keys" in out["warning"]

    def test_an_ambiguous_prefix_is_not_guessed(self, client, store):
        account, key = _acct(store)
        db = sqlite3.connect(store.path)
        db.execute(
            "INSERT INTO api_keys (key_hash, prefix, account_id, label, created_at) "
            "VALUES ('h2', ?, ?, 'dup', '2026-01-01T00:00:00Z')", (key[:10], account.id))
        db.commit()
        db.close()
        out = client.post("/v1/keys/revoke", headers={"X-API-Key": key},
                          json={"key_prefix": key[:10]})
        assert out.status_code == 409 and out.json()["detail"]["error"] == "ambiguous_prefix"
        assert can_use_register(client, key) == 200

    def test_the_number_of_live_keys_is_capped(self, client, store):
        _, key = _acct(store)
        statuses = [client.post("/v1/keys", headers={"X-API-Key": key}).status_code
                    for _ in range(12)]
        assert statuses.count(201) == 9 and statuses[-1] == 409

    def test_the_operator_gets_a_clear_400(self, client):
        h = {"X-API-Key": OPERATOR_KEY}
        for method, path in (("get", "/v1/keys"), ("post", "/v1/keys"),
                             ("post", "/v1/keys/revoke")):
            resp = getattr(client, method)(path, headers=h)
            assert resp.status_code == 400, path
            assert resp.json()["detail"]["error"] == "operator_key_not_managed"
        assert client.get("/v1/cases", headers=h).status_code == 200   # unaffected

    def test_anonymous_callers_are_401(self, client):
        assert client.get("/v1/keys").status_code == 401
        assert client.post("/v1/keys").status_code == 401
        assert client.post("/v1/keys/revoke").status_code == 401

    def test_a_bad_prefix_shape_is_a_422(self, client, store):
        _, key = _acct(store)
        assert client.post("/v1/keys/revoke", headers={"X-API-Key": key},
                           json={"key_prefix": "not a prefix"}).status_code == 422

    def test_a_lapsed_account_can_still_revoke_a_leaked_key(self, client, store):
        account, key = _acct(store)
        store.set_status(stripe_customer_id="cus_k", status="cancelled", tier="free")
        assert client.post("/v1/keys/revoke", headers={"X-API-Key": key}).status_code == 200


# ---------------------------------------------------------------------------
# 9. /healthz
# ---------------------------------------------------------------------------
class TestHealthz:
    def test_it_is_public_cheap_and_does_not_leak(self, client, env):
        body = client.get("/healthz").json()
        assert body["status"] == "ok" and body["auth_mode"] == "api_key"
        assert body["ledger_ok"] is True and body["accounts_ok"] is True
        assert body["ledger_records"] == 0
        assert "chain_verified" not in body and "ledger" not in body
        assert str(env) not in json.dumps(body)

    def test_it_does_not_verify_the_chain(self, client, monkeypatch):
        from assurance.evidence.ledger import EvidenceLedger

        def boom(self):
            raise AssertionError("healthz must not do O(n) work")

        monkeypatch.setattr(EvidenceLedger, "verify_chain", boom)
        assert client.get("/healthz").status_code == 200

    def test_the_authenticated_verify_still_verifies(self, client):
        resp = client.get("/v1/ledger/verify", headers={"X-API-Key": OPERATOR_KEY})
        assert resp.status_code == 200 and resp.json()["verified"] is True

    def test_it_reports_a_store_that_will_not_open_without_naming_it(self, client, env):
        deps.shared_register()
        db = sqlite3.connect(env / "art14.db")
        db.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        db.commit()
        db.close()
        deps._register_for.cache_clear()
        resp = client.get("/healthz")
        assert resp.status_code == 503
        assert resp.json()["status"] == "unavailable" and resp.json()["ledger_ok"] is False
        assert str(env) not in resp.text


# ---------------------------------------------------------------------------
# 10. request body cap
# ---------------------------------------------------------------------------
class TestBodyCap:
    BODY = {"track": "severe_incident", "stage": "early_warning"}

    def _big(self, n):
        return {**self.BODY, "payload": {"summary": "x" * n}}

    def test_an_oversized_declared_body_is_a_413(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "2000")
        resp = client.post("/v1/spec/validate", json=self._big(5000))
        assert resp.status_code == 413
        assert resp.json()["detail"]["error"] == "request_too_large"
        assert resp.json()["detail"]["limit_bytes"] == 2000

    def test_an_undeclared_chunked_body_is_counted_as_it_arrives(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "2000")
        raw = json.dumps(self._big(5000)).encode()

        def chunks():
            for i in range(0, len(raw), 500):
                yield raw[i:i + 500]

        resp = client.post("/v1/spec/validate", content=chunks(),
                           headers={"content-type": "application/json"})
        assert resp.status_code == 413

    def test_a_body_under_the_cap_is_unaffected(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "20000")
        assert client.post("/v1/spec/validate", json=self._big(500)).status_code == 200

    def test_the_default_is_one_mebibyte(self, client):
        assert deps.max_body_bytes("/v1/spec/validate") == 1024 * 1024
        assert client.post("/v1/spec/validate", json=self._big(2 * 1024 * 1024)).status_code == 413

    def test_the_stripe_webhook_is_not_capped(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "100")
        resp = client.post("/v1/billing/webhook", content=b"x" * 5000)
        assert resp.status_code == 400                 # unsigned, not "too large"
        assert resp.json()["detail"]["error"] == "signature_rejected"

    def test_reads_and_non_v1_paths_are_not_capped(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "10")
        assert client.get("/v1/plans").status_code == 200
        assert client.get("/healthz").status_code == 200
        assert deps.max_body_bytes("/docs") is None

    def test_recorded_machine_traces_get_a_larger_allowance(self, client, store, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "2000")
        assert deps.max_body_bytes("/v1/machine/verify") == 32 * 1024 * 1024
        account = store.upsert_account(email="c@b.de", tier="cell", stripe_customer_id="cus_c")
        headers = {"X-API-Key": store.issue_key(account.id)}
        resp = client.post("/v1/machine/verify", headers=headers,
                           json={"envelope": {"pad": "x" * 5000}, "trace": {}})
        assert resp.status_code != 413

    def test_the_cap_is_inside_cors_so_a_browser_can_read_the_413(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_MAX_BODY_BYTES", "2000")
        resp = client.post("/v1/spec/validate", json=self._big(5000),
                           headers={"Origin": "https://neuralbridge.io"})
        assert resp.status_code == 413
        assert resp.headers["access-control-allow-origin"] == "https://neuralbridge.io"
