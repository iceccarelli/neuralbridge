"""Stripe <-> account-store reconciliation.

Everything here runs against a fake Stripe (an injected gateway object, or an
``httpx.MockTransport`` for the real gateway functions). Nothing touches the
network and there is no Stripe access: the reconciler has been verified against
a fake transport only.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing import reconcile as rec
from assurance.billing import stripe_gateway
from assurance.billing import subscription_state as shared
from assurance.billing.accounts import AccountStore
from assurance.billing.stripe_gateway import StripeError

from .test_assurance_billing import WEBHOOK_SECRET, _signed

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
TS = int(NOW.timestamp())
DAY = 86400
SECRET = "sk_test_ReconcileSecret123456"


# ---------------------------------------------------------------------------
# fixtures and fakes
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _prices(monkeypatch):
    monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", "price_reg")
    monkeypatch.setenv("ASSURANCE_PRICE_CELL", "price_cell")
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)


@pytest.fixture()
def store(tmp_path):
    return AccountStore(tmp_path / "accounts.db")


def sub(sid, customer, status="active", price="price_reg", created=TS - 90 * DAY,
        metadata=None, **extra):
    obj = {
        "id": sid, "customer": customer, "status": status, "created": created,
        "items": {"data": [{"price": {"id": price}}] if price else []},
        "metadata": metadata or {},
    }
    obj.update(extra)
    return obj


class FakeStripe:
    """The two read calls the reconciler uses, with Stripe's paging and filtering."""

    def __init__(self, subs=(), *, customers=(), page_size=100, fail_list_call=0,
                 fail_retrieve=None, on_retrieve=None):
        self.subs = list(subs)
        self.known = {s["customer"] for s in self.subs} | set(customers)
        self.page_size = page_size
        self.fail_list_call = fail_list_call
        self.fail_retrieve = fail_retrieve
        self.on_retrieve = on_retrieve
        self.calls: list[tuple] = []

    def list_subscriptions(self, customer=None, status="all", starting_after=None, limit=100):
        self.calls.append(("list", customer, status, starting_after, limit))
        if self.fail_list_call == sum(1 for c in self.calls if c[0] == "list"):
            raise StripeError("Stripe 500: upstream trouble", status=500)
        if customer and customer not in self.known:
            raise StripeError(f"Stripe 404: No such customer: '{customer}'",
                              status=404, code="resource_missing")
        # Stripe's default listing omits cancelled subscriptions; only "all" shows them.
        items = sorted(
            (s for s in self.subs
             if (not customer or s["customer"] == customer)
             and (status == "all" or s["status"] == status)),
            key=lambda s: s["id"],
        )
        start = 0
        if starting_after:
            start = [s["id"] for s in items].index(starting_after) + 1
        size = min(limit, self.page_size)
        page = items[start:start + size]
        return {"data": page, "has_more": start + size < len(items)}

    def retrieve_subscription(self, subscription_id):
        self.calls.append(("retrieve", subscription_id))
        if self.on_retrieve:
            self.on_retrieve(subscription_id)
        if self.fail_retrieve is not None:
            raise self.fail_retrieve
        for s in self.subs:
            if s["id"] == subscription_id:
                return dict(s)
        raise StripeError("Stripe 404: No such subscription", status=404, code="resource_missing")


def add(store, customer, tier="register", status="active", event_age_days=10,
        past_due_days=None, email=None):
    acct = store.upsert_account(
        email=email or f"{customer}@example.test", tier=tier, status=status,
        stripe_customer_id=customer, stripe_subscription_id="",
        event_created=TS - event_age_days * DAY,
    )
    if past_due_days is not None:
        _sql(store, "UPDATE accounts SET past_due_since=? WHERE id=?",
             TS - past_due_days * DAY, acct.id)
    return acct


def _sql(store, sql, *args):
    db = sqlite3.connect(store.path)
    try:
        db.execute(sql, args)
        db.commit()
    finally:
        db.close()


def _break_audit(store):
    """Make every audit insert fail, as a full disk or a locked table would."""
    _sql(store, "CREATE TRIGGER audit_refuses BEFORE INSERT ON entitlement_reconciliations "
                "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")


def rows(store, sql, *args):
    db = sqlite3.connect(store.path)
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def state(store, account_id):
    a = store.account(account_id)
    return (a.status, a.tier)


def everything(store):
    """All data the reconciler could possibly change."""
    return {
        t: rows(store, f"SELECT * FROM {t} ORDER BY 1, 2")
        for t in ("accounts", "api_keys", "processed_events", "pending_keys",
                  "entitlement_reconciliations", "orphan_states")
    }


def run(store, gateway, **kw):
    kw.setdefault("now", NOW)
    return rec.reconcile(store, gateway, **kw)


def cats(report):
    return {f.category for f in report.findings}


# ---------------------------------------------------------------------------
# the gateway calls
# ---------------------------------------------------------------------------
class TestGatewayCalls:
    @pytest.fixture()
    def seen(self, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        seen: list[httpx.Request] = []
        responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return responses.pop(0) if responses else httpx.Response(200, json={"data": []})

        client = httpx.Client(transport=httpx.MockTransport(handler))

        def fake_get(url, **kwargs):
            return client.get(url, **kwargs)

        monkeypatch.setattr(stripe_gateway.httpx, "get", fake_get)
        return seen, responses

    def test_list_sends_status_all_paging_and_customer_with_the_key_as_basic_auth(self, seen):
        requests, _ = seen
        stripe_gateway.list_subscriptions(customer="cus_1", starting_after="sub_9", limit=500)
        req = requests[0]
        assert req.method == "GET" and req.url.path == "/v1/subscriptions"
        q = dict(req.url.params)
        assert q == {"status": "all", "limit": "100", "customer": "cus_1",
                     "starting_after": "sub_9"}
        assert req.headers["authorization"].startswith("Basic ")
        assert req.headers["stripe-version"] == "2024-06-20"

    def test_a_plain_list_has_no_customer_or_cursor(self, seen):
        requests, _ = seen
        stripe_gateway.list_subscriptions()
        assert dict(requests[0].url.params) == {"status": "all", "limit": "100"}

    def test_retrieve_hits_the_subscription_path(self, seen):
        requests, responses = seen
        responses.append(httpx.Response(200, json={"id": "sub_1"}))
        assert stripe_gateway.retrieve_subscription("sub_1") == {"id": "sub_1"}
        assert requests[0].url.path == "/v1/subscriptions/sub_1"

    @pytest.mark.parametrize("bad", ["", "sub_1/../customers", "sub 1", "sub_1?x=1", "a" * 300])
    def test_retrieve_refuses_an_id_that_could_change_the_path(self, seen, bad):
        requests, _ = seen
        with pytest.raises(StripeError):
            stripe_gateway.retrieve_subscription(bad)
        assert requests == []

    def test_an_error_keeps_stripes_status_and_code(self, seen):
        _, responses = seen
        responses.append(httpx.Response(404, json={"error": {
            "message": "No such customer: 'cus_x'", "code": "resource_missing"}}))
        with pytest.raises(StripeError) as caught:
            stripe_gateway.list_subscriptions(customer="cus_x")
        assert caught.value.status == 404 and caught.value.code == "resource_missing"

    def test_an_error_never_carries_the_key_even_when_stripe_quotes_it(self, seen):
        _, responses = seen
        responses.append(httpx.Response(401, json={"error": {
            "message": f"Invalid API Key provided: {SECRET}, also sk_live_abcdef123456"}}))
        with pytest.raises(StripeError) as caught:
            stripe_gateway.list_subscriptions()
        text = str(caught.value)
        assert SECRET not in text and "sk_live_abcdef" not in text and "[redacted]" in text

    def test_a_non_json_error_body_is_a_stripe_error_not_a_crash(self, seen):
        _, responses = seen
        responses.append(httpx.Response(502, text="<html>bad gateway</html>"))
        with pytest.raises(StripeError, match="502"):
            stripe_gateway.list_subscriptions()

    def test_a_transport_failure_is_a_stripe_error_without_the_url(self, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)

        def boom(url, **kwargs):
            raise httpx.ConnectTimeout(f"timed out talking to {url}")

        monkeypatch.setattr(stripe_gateway.httpx, "get", boom)
        with pytest.raises(StripeError) as caught:
            stripe_gateway.list_subscriptions()
        assert "ConnectTimeout" in str(caught.value) and "api.stripe.com" not in str(caught.value)

    def test_the_timeout_and_version_match_the_existing_post_path(self, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        got = {}

        def fake_get(url, **kwargs):
            got.update(kwargs)
            return httpx.Response(200, json={"data": []}, request=httpx.Request("GET", url))

        monkeypatch.setattr(stripe_gateway.httpx, "get", fake_get)
        stripe_gateway.list_subscriptions()
        assert got["timeout"] == 20.0 and got["headers"] == {"Stripe-Version": "2024-06-20"}

    def test_no_key_is_the_same_error_as_everywhere_else(self, monkeypatch):
        monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
        with pytest.raises(StripeError, match="STRIPE_SECRET_KEY is not set"):
            stripe_gateway.list_subscriptions()


# ---------------------------------------------------------------------------
# the categories
# ---------------------------------------------------------------------------
class TestCategories:
    def test_an_account_that_agrees_with_stripe_is_in_sync(self, store):
        add(store, "cus_a", "register", "active")
        add(store, "cus_b", "cell", "cancelled")
        add(store, "cus_c", "free", "cancelled")
        stripe = FakeStripe([
            sub("sub_a", "cus_a"),
            sub("sub_b", "cus_b", status="canceled", price="price_cell"),
            sub("sub_c", "cus_c", status="canceled"),
        ])
        report = run(store, stripe)
        assert report.drift_count == 0 and report.in_sync == 3 and report.exit_code == 0
        assert report.complete

    def test_a_trialing_subscription_is_entitled_like_active(self, store):
        add(store, "cus_a", "register", "active")
        assert run(store, FakeStripe([sub("sub_a", "cus_a", status="trialing")])).drift_count == 0

    def test_stripe_active_but_we_deny_is_found_and_corrected_with_the_price_tier(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a", price="price_cell")])
        dry = run(store, stripe)
        assert cats(dry) == {"stripe_active_but_we_deny"} and dry.exit_code == 1
        assert state(store, acct.id) == ("cancelled", "free"), "a dry run writes nothing"
        done = run(store, stripe, apply=True)
        assert done.corrected == 1 and done.exit_code == 1
        assert state(store, acct.id) == ("active", "cell")

    def test_stripe_ended_but_we_grant_is_found_and_corrected_to_the_free_plan(self, store):
        acct = add(store, "cus_a", "cell", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a", status="canceled", price="price_cell")])
        assert cats(run(store, stripe)) == {"stripe_ended_but_we_grant"}
        run(store, stripe, apply=True)
        assert state(store, acct.id) == ("cancelled", "free")

    @pytest.mark.parametrize("stripe_status", ["unpaid", "incomplete_expired"])
    def test_every_terminal_status_ends_the_grant(self, store, stripe_status):
        acct = add(store, "cus_a", "register", "past_due")
        run(store, FakeStripe([sub("sub_a", "cus_a", status=stripe_status)]), apply=True)
        assert state(store, acct.id) == ("cancelled", "free")

    @pytest.mark.parametrize("stripe_status", ["paused", "incomplete"])
    def test_suspended_loses_access_but_the_tier_is_remembered(self, store, stripe_status):
        acct = add(store, "cus_a", "cell", "active")
        run(store, FakeStripe([sub("sub_a", "cus_a", status=stripe_status, price="price_cell")]),
            apply=True)
        assert state(store, acct.id) == ("cancelled", "cell")

    def test_tier_mismatch_follows_the_price_id(self, store):
        up = add(store, "cus_up", "register", "active")
        down = add(store, "cus_down", "cell", "active")
        stripe = FakeStripe([sub("sub_1", "cus_up", price="price_cell"),
                             sub("sub_2", "cus_down", price="price_reg")])
        report = run(store, stripe, apply=True)
        assert cats(report) == {"tier_mismatch"} and report.corrected == 2
        assert state(store, up.id) == ("active", "cell")
        assert state(store, down.id) == ("active", "register")

    def test_status_mismatch_between_active_and_past_due_changes_no_entitlement(self, store):
        flagged = add(store, "cus_a", "register", "past_due", past_due_days=2)
        unflagged = add(store, "cus_b", "register", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a", status="active"),
                             sub("sub_b", "cus_b", status="past_due")])
        report = run(store, stripe, apply=True)
        assert cats(report) == {"status_mismatch"}
        assert state(store, flagged.id) == ("active", "register")
        assert state(store, unflagged.id) == ("past_due", "register")
        assert store.account(flagged.id).plan.tier == "register"

    def test_a_customer_stripe_does_not_know_is_unknown_in_stripe_and_never_touched(self, store):
        acct = add(store, "cus_gone", "cell", "active")
        add(store, "cus_ok", "register", "active")
        stripe = FakeStripe([sub("sub_ok", "cus_ok")])
        report = run(store, stripe, apply=True)
        assert cats(report) == {"unknown_in_stripe"} and report.exit_code == 1
        assert state(store, acct.id) == ("active", "cell")
        (finding,) = report.findings
        assert not finding.correctable and finding.account_id == acct.id

    def test_a_customer_with_no_subscription_but_a_grant_is_reported_for_a_human(self, store):
        acct = add(store, "cus_a", "register", "active")
        stripe = FakeStripe([], customers=["cus_a"])
        report = run(store, stripe, apply=True)
        assert cats(report) == {"stripe_ended_but_we_grant"}
        assert not report.findings[0].correctable
        assert state(store, acct.id) == ("active", "register"), "no Stripe status was reported"

    def test_another_products_subscription_on_the_customer_is_not_ours(self, store):
        acct = add(store, "cus_a", "register", "active")
        stripe = FakeStripe([sub("sub_other", "cus_a", price="price_other")])
        assert cats(run(store, stripe, apply=True)) == {"stripe_ended_but_we_grant"}
        assert state(store, acct.id) == ("active", "register")

    def test_an_orphan_subscription_is_reported_and_never_creates_anything(self, store):
        add(store, "cus_a", "register", "active")
        stripe = FakeStripe([
            sub("sub_a", "cus_a"),
            sub("sub_orphan", "cus_orphan", price="price_cell"),
            sub("sub_old", "cus_old", status="canceled"),       # over: not a problem
            sub("sub_other", "cus_other", price="price_other"),  # not ours
        ])
        before = everything(store)
        report = run(store, stripe, apply=True)
        assert cats(report) == {"stripe_subscription_without_account"}
        (orphan,) = report.findings
        assert (orphan.account_id, orphan.stripe_subscription_id, orphan.stripe_customer_id) == (
            "", "sub_orphan", "cus_orphan")
        assert not orphan.correctable and orphan.action == "reported"
        assert everything(store) == before, "no account, no key, no row of any kind"
        assert rows(store, "SELECT COUNT(*) FROM accounts")[0][0] == 1
        assert rows(store, "SELECT COUNT(*) FROM api_keys")[0][0] == 0

    def test_past_due_too_long_ends_a_past_due_stripe_never_resolved(self, store):
        acct = add(store, "cus_a", "register", "past_due", past_due_days=45)
        stripe = FakeStripe([sub("sub_a", "cus_a", status="past_due")])
        report = run(store, stripe)
        assert cats(report) == {"past_due_too_long"}
        run(store, stripe, apply=True)
        assert state(store, acct.id) == ("cancelled", "register")

    def test_past_due_inside_the_window_is_left_alone_and_the_window_is_configurable(self, store):
        add(store, "cus_a", "register", "past_due", past_due_days=20)
        stripe = FakeStripe([sub("sub_a", "cus_a", status="past_due")])
        assert run(store, stripe).drift_count == 0
        assert cats(run(store, stripe, past_due_days=10)) == {"past_due_too_long"}

    def test_past_due_that_stripe_resolved_is_not_past_due_too_long(self, store):
        add(store, "cus_a", "register", "past_due", past_due_days=45)
        report = run(store, FakeStripe([sub("sub_a", "cus_a", status="active")]))
        assert cats(report) == {"status_mismatch"}

    def test_ending_a_stale_past_due_does_not_flap_back_on_the_next_run(self, store):
        acct = add(store, "cus_a", "register", "past_due", past_due_days=45)
        stripe = FakeStripe([sub("sub_a", "cus_a", status="past_due")])
        run(store, stripe, apply=True)
        later = NOW + timedelta(hours=1)
        again = run(store, stripe, apply=True, now=later)
        assert again.drift_count == 0 and again.corrected == 0
        assert state(store, acct.id) == ("cancelled", "register")
        # ...and when Stripe really recovers it, access returns.
        stripe.subs[0]["status"] = "active"
        back = run(store, stripe, apply=True, now=later + timedelta(hours=1))
        assert cats(back) == {"stripe_active_but_we_deny"}
        assert state(store, acct.id) == ("active", "register")

    def test_a_past_due_whose_start_is_unknown_is_not_ended_on_a_guess(self, store):
        add(store, "cus_a", "register", "past_due", event_age_days=0)
        _sql(store, "UPDATE accounts SET last_event_at=0, past_due_since=0")
        assert run(store, FakeStripe([sub("sub_a", "cus_a", status="past_due")])).drift_count == 0


# ---------------------------------------------------------------------------
# no upgrade on a guess
# ---------------------------------------------------------------------------
class TestAmbiguousIsNeverUpgraded:
    def test_an_unknown_stripe_status_changes_nothing(self, store):
        acct = add(store, "cus_a", "register", "cancelled")
        report = run(store, FakeStripe([sub("sub_a", "cus_a", status="brand_new_status")]),
                     apply=True)
        assert cats(report) == {"ambiguous"} and report.corrected == 0
        assert state(store, acct.id) == ("cancelled", "register")

    def test_a_tier_only_the_metadata_names_is_not_trusted_to_upgrade(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a", price=None, metadata={"tier": "cell"})])
        report = run(store, stripe, apply=True)
        assert cats(report) == {"ambiguous"}
        assert state(store, acct.id) == ("cancelled", "free")

    def test_a_metadata_tier_that_differs_does_not_rewrite_an_entitled_tier(self, store):
        acct = add(store, "cus_a", "register", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a", price="price_unmapped",
                                 metadata={"tier": "cell"})])
        assert cats(run(store, stripe, apply=True)) == {"ambiguous"}
        assert state(store, acct.id) == ("active", "register")

    def test_a_metadata_tier_that_agrees_is_in_sync(self, store):
        add(store, "cus_a", "cell", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a", price=None, metadata={"tier": "cell"})])
        assert run(store, stripe).drift_count == 0

    def test_two_live_subscriptions_that_disagree_are_not_resolved_by_guessing(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_1", "cus_a", price="price_reg"),
                             sub("sub_2", "cus_a", price="price_cell")])
        assert cats(run(store, stripe, apply=True)) == {"ambiguous"}
        assert state(store, acct.id) == ("cancelled", "free")

    def test_an_unknown_status_beside_a_good_subscription_still_blocks(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_1", "cus_a"), sub("sub_2", "cus_a", status="mystery")])
        assert cats(run(store, stripe, apply=True)) == {"ambiguous"}
        assert state(store, acct.id) == ("cancelled", "free")

    def test_an_old_cancelled_subscription_beside_an_active_one_is_not_ambiguous(self, store):
        acct = add(store, "cus_a", "register", "cancelled")
        stripe = FakeStripe([sub("sub_1", "cus_a", status="canceled"), sub("sub_2", "cus_a")])
        run(store, stripe, apply=True)
        assert state(store, acct.id) == ("active", "register")

    def test_the_store_itself_refuses_a_tier_it_cannot_grant(self, store):
        acct = add(store, "cus_a", "register", "active")
        for tier, status in (("supplier", "active"), ("gold", "active"), ("cell", "paused")):
            assert store.apply_reconciliation(
                run_id="r", account_id=acct.id, category="x", expect_status="active",
                expect_tier="register", new_status=status, new_tier=tier,
                snapshot_at=TS, skew_seconds=60) == "invalid_target"
        assert state(store, acct.id) == ("active", "register")


# ---------------------------------------------------------------------------
# who is never touched
# ---------------------------------------------------------------------------
class TestWhoIsNeverTouched:
    def test_the_operator_an_account_without_a_customer_and_a_sales_tier_are_skipped(self, store):
        operator = store.upsert_account(email="", tier="cell", stripe_customer_id="cus_op")
        _sql(store, "UPDATE accounts SET id='operator' WHERE id=?", operator.id)
        loner = store.upsert_account(email="x@example.test", tier="cell", status="active")
        supplier = add(store, "cus_sup", "supplier", "active")
        stripe = FakeStripe([
            sub("sub_op", "cus_op", status="canceled"),
            sub("sub_sup", "cus_sup", status="canceled"),
        ], customers=["cus_op"])
        before = everything(store)
        report = run(store, stripe, apply=True)
        assert report.drift_count == 0 and report.corrected == 0
        assert {s["account_id"] for s in report.skipped} == {"operator", loner.id, supplier.id}
        assert everything(store) == before

    def test_the_store_refuses_the_operator_and_a_customerless_account_directly(self, store):
        loner = store.upsert_account(email="x@example.test", tier="cell")
        _sql(store, "INSERT INTO accounts (id,email,company,tier,stripe_customer_id,"
                    "stripe_subscription_id,status,created_at,updated_at,last_event_at) "
                    "VALUES ('operator','','','cell','cus_op','','active','t','t',0)")
        for aid in (loner.id, "operator"):
            assert store.apply_reconciliation(
                run_id="r", account_id=aid, category="x", expect_status="active",
                expect_tier="cell", new_status="cancelled", new_tier="free",
                snapshot_at=TS, skew_seconds=60) == "not_stripe_account"
        assert state(store, loner.id) == ("active", "cell")
        assert state(store, "operator") == ("active", "cell")
        assert store.apply_reconciliation(
            run_id="r", account_id="acc_nope", category="x", expect_status="active",
            expect_tier="cell", new_status="cancelled", new_tier="free",
            snapshot_at=TS, skew_seconds=60) == "not_found"

    def test_only_status_and_tier_change_and_nothing_else_on_the_account(self, store):
        acct = add(store, "cus_a", "cell", "active", email="keep@example.test")
        key = store.issue_key(acct.id, "keep")
        before = store.account(acct.id)
        run(store, FakeStripe([sub("sub_a", "cus_a", status="canceled")]), apply=True)
        after = store.account(acct.id)
        assert (after.email, after.company, after.stripe_customer_id,
                after.stripe_subscription_id) == (before.email, before.company,
                                                  before.stripe_customer_id,
                                                  before.stripe_subscription_id)
        assert store.resolve_key(key) is not None, "keys are not revoked or minted here"
        assert store.active_key_count(acct.id) == 1


# ---------------------------------------------------------------------------
# dry run, apply, audit, idempotence
# ---------------------------------------------------------------------------
class TestApply:
    def drifted(self, store):
        a = add(store, "cus_a", "free", "cancelled")
        b = add(store, "cus_b", "cell", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a"),
                             sub("sub_b", "cus_b", status="canceled", price="price_cell")])
        return a, b, stripe

    def test_a_dry_run_writes_nothing_at_all(self, store):
        _, _, stripe = self.drifted(store)
        before = everything(store)
        report = run(store, stripe)
        assert report.drift_count == 2 and not report.apply
        assert {f.action for f in report.findings} == {"would_correct"}
        assert everything(store) == before
        assert not any(c[0] == "retrieve" for c in stripe.calls)

    def test_apply_writes_one_audit_row_per_correction_in_the_same_change(self, store):
        a, b, stripe = self.drifted(store)
        report = run(store, stripe, apply=True)
        assert report.corrected == 2
        audit = rows(store, "SELECT account_id, category, old_status, old_tier, new_status, "
                            "new_tier, stripe_subscription_id, stripe_status, snapshot_at, "
                            "run_id FROM entitlement_reconciliations ORDER BY account_id")
        assert sorted(audit) == sorted([
            (a.id, "stripe_active_but_we_deny", "cancelled", "free", "active", "register",
             "sub_a", "active", TS, report.run_id),
            (b.id, "stripe_ended_but_we_grant", "active", "cell", "cancelled", "free",
             "sub_b", "canceled", TS, report.run_id),
        ])

    def test_the_audit_row_holds_no_email(self, store):
        add(store, "cus_a", "free", "cancelled", email="private.person@example.test")
        run(store, FakeStripe([sub("sub_a", "cus_a")]), apply=True)
        dump = json.dumps(rows(store, "SELECT * FROM entitlement_reconciliations"))
        assert "private.person" not in dump and "@" not in dump

    def test_a_second_apply_is_a_no_op(self, store):
        a, b, stripe = self.drifted(store)
        run(store, stripe, apply=True)
        snapshot = everything(store)
        again = run(store, stripe, apply=True, now=NOW + timedelta(minutes=5))
        assert again.drift_count == 0 and again.corrected == 0 and again.exit_code == 0
        assert everything(store) == snapshot
        assert rows(store, "SELECT COUNT(*) FROM entitlement_reconciliations")[0][0] == 2

    def test_the_change_and_its_audit_row_are_one_transaction(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        _break_audit(store)
        with pytest.raises(sqlite3.IntegrityError):
            store.apply_reconciliation(
                run_id="r", account_id=acct.id, category="x", expect_status="cancelled",
                expect_tier="free", new_status="active", new_tier="register",
                snapshot_at=TS, skew_seconds=60)
        assert state(store, acct.id) == ("cancelled", "free"), "no audit row, so no change"

    def test_the_store_calls_a_repeat_a_noop_and_writes_one_audit_row(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        args = {"run_id": "r", "account_id": acct.id, "category": "x",
                "snapshot_at": TS, "skew_seconds": 60}
        first = store.apply_reconciliation(
            expect_status="cancelled", expect_tier="free", new_status="active",
            new_tier="register", **args)
        again = store.apply_reconciliation(
            expect_status="active", expect_tier="register", new_status="active",
            new_tier="register", **args)
        assert (first, again) == ("applied", "noop")
        assert rows(store, "SELECT COUNT(*) FROM entitlement_reconciliations")[0][0] == 1

    def test_the_report_says_when_the_store_failed_and_stops(self, store):
        add(store, "cus_a", "free", "cancelled")
        add(store, "cus_b", "free", "cancelled")
        _break_audit(store)
        stripe = FakeStripe([sub("sub_a", "cus_a"), sub("sub_b", "cus_b")])
        before = everything(store)
        report = run(store, stripe, apply=True)
        assert not report.complete and report.exit_code == 2 and report.corrected == 0
        assert "IntegrityError" in report.error
        assert everything(store) == before, "the failed change rolled back, the rest never ran"
        assert [f.action for f in report.findings] == ["refused", "skipped"]

    def test_a_subscription_that_changed_while_the_run_read_it_is_not_acted_on(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a")])
        original = stripe.retrieve_subscription

        def moved_on(subscription_id):
            obj = original(subscription_id)
            obj["status"] = "canceled"
            return obj

        stripe.retrieve_subscription = moved_on
        report = run(store, stripe, apply=True)
        assert report.corrected == 0 and report.findings[0].action == "skipped"
        assert state(store, acct.id) == ("cancelled", "free")


# ---------------------------------------------------------------------------
# a newer webhook always wins
# ---------------------------------------------------------------------------
class TestEventOrdering:
    def test_a_webhook_newer_than_the_snapshot_is_left_alone(self, store):
        # Stripe-side the sub is active, but our account was moved to cancelled by
        # an event stamped after this run began: the snapshot may predate it.
        acct = add(store, "cus_a", "register", "cancelled", event_age_days=0)
        _sql(store, "UPDATE accounts SET last_event_at=? WHERE id=?", TS + 5, acct.id)
        stripe = FakeStripe([sub("sub_a", "cus_a")])
        report = run(store, stripe, apply=True)
        assert report.drift_count == 0 and report.corrected == 0
        assert [d["account_id"] for d in report.deferred] == [acct.id]
        assert state(store, acct.id) == ("cancelled", "register")
        assert report.accounts_checked == 0

    def test_a_webhook_within_the_clock_skew_margin_is_also_left_alone(self, store):
        acct = add(store, "cus_a", "register", "cancelled", event_age_days=0)
        _sql(store, "UPDATE accounts SET last_event_at=? WHERE id=?", TS - 30, acct.id)
        report = run(store, FakeStripe([sub("sub_a", "cus_a")]), apply=True)
        assert report.deferred and state(store, acct.id) == ("cancelled", "register")

    def test_an_older_webhook_is_corrected(self, store):
        acct = add(store, "cus_a", "register", "cancelled", event_age_days=1)
        run(store, FakeStripe([sub("sub_a", "cus_a")]), apply=True)
        assert state(store, acct.id) == ("active", "register")

    def test_stripes_own_clock_running_ahead_widens_the_window(self, store):
        acct = add(store, "cus_a", "register", "cancelled", event_age_days=0)
        _sql(store, "UPDATE accounts SET last_event_at=? WHERE id=?", TS + 300, acct.id)
        ahead = sub("sub_a", "cus_a", canceled_at=TS + 3600)
        report = run(store, FakeStripe([ahead]), apply=True)
        assert not report.deferred, "Stripe's clock is later than the webhook"
        assert state(store, acct.id) == ("active", "register")

    def test_a_webhook_that_lands_between_planning_and_writing_wins(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a")])

        def webhook_lands(_):
            # while the run is confirming its plan, a real, newer event is applied
            assert store.set_status(stripe_customer_id="cus_a", status="cancelled",
                                    tier="free", event_created=TS + 120) == "applied"

        stripe.on_retrieve = webhook_lands
        report = run(store, stripe, apply=True)
        assert report.corrected == 0
        assert report.findings[0].action == "refused"
        assert report.findings[0].reason == "webhook_newer"
        assert state(store, acct.id) == ("cancelled", "free")

    def test_an_account_changed_after_it_was_read_is_not_overwritten(self, store):
        acct = add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a")])

        def changed(_):
            _sql(store, "UPDATE accounts SET status='active', tier='cell' WHERE id=?", acct.id)

        stripe.on_retrieve = changed
        report = run(store, stripe, apply=True)
        assert report.findings[0].reason == "changed_since_read"
        assert state(store, acct.id) == ("active", "cell")

    def test_a_delayed_older_webhook_cannot_undo_a_correction(self, store):
        acct = add(store, "cus_a", "register", "active")
        run(store, FakeStripe([sub("sub_a", "cus_a", status="canceled")]), apply=True)
        assert state(store, acct.id) == ("cancelled", "free")
        # Stripe redelivers an old "still active" event stamped before the run:
        stale = store.apply_subscription_event(
            event_id="evt_late", kind="customer.subscription.updated",
            stripe_customer_id="cus_a", status="active", tier="register",
            event_created=TS - 3 * DAY, hold_if_unknown=False)
        assert stale == "stale"
        assert state(store, acct.id) == ("cancelled", "free")

    def test_a_genuinely_newer_webhook_still_applies_after_a_correction(self, store):
        acct = add(store, "cus_a", "register", "active")
        run(store, FakeStripe([sub("sub_a", "cus_a", status="canceled")]), apply=True)
        applied = store.apply_subscription_event(
            event_id="evt_new", kind="customer.subscription.updated",
            stripe_customer_id="cus_a", status="active", tier="register",
            event_created=TS + 600, hold_if_unknown=False)
        assert applied == "applied" and state(store, acct.id) == ("active", "register")


# ---------------------------------------------------------------------------
# paging and Stripe failing
# ---------------------------------------------------------------------------
class TestStripeReading:
    def test_every_page_is_read_and_cancelled_subscriptions_are_asked_for(self, store):
        for i in range(5):
            add(store, f"cus_{i}", "register", "active")
        subs = [sub(f"sub_{i}", f"cus_{i}", status="canceled" if i == 4 else "active")
                for i in range(5)]
        stripe = FakeStripe(subs, page_size=2)
        report = run(store, stripe)
        assert cats(report) == {"stripe_ended_but_we_grant"}
        assert [f.account_id for f in report.findings] == [
            store.account_by_customer("cus_4").id]
        lists = [c for c in stripe.calls if c[0] == "list" and c[1] is None]
        assert len(lists) == 3, "5 subscriptions at 2 a page is 3 pages"
        assert lists[0][3] is None and lists[1][3] == "sub_1" and lists[2][3] == "sub_3"
        assert all(c[2] == "all" for c in lists), "Stripe's default listing hides cancelled"

    def test_a_subscription_on_the_last_page_is_not_missed(self, store):
        acct = add(store, "cus_9", "free", "cancelled")
        subs = [sub(f"sub_{i}", f"cus_other{i}", price="price_other") for i in range(7)]
        subs.append(sub("sub_z", "cus_9"))
        run(store, FakeStripe(subs, page_size=3), apply=True)
        assert state(store, acct.id) == ("active", "register")

    def test_a_stuck_cursor_is_an_incomplete_run_not_a_loop(self, store):
        add(store, "cus_a", "register", "active")

        class Stuck:
            def list_subscriptions(self, **kwargs):
                return {"data": [{"id": "sub_1", "customer": "cus_x"}], "has_more": True}

            def retrieve_subscription(self, _):  # pragma: no cover
                raise AssertionError

        report = run(store, Stuck())
        assert not report.complete and "did not advance" in report.error
        assert report.exit_code == 2

    def test_a_malformed_page_is_an_incomplete_run(self, store):
        add(store, "cus_a", "register", "active")

        class Bad:
            def list_subscriptions(self, **kwargs):
                return {"oops": True}

        assert run(store, Bad()).exit_code == 2

    def test_an_error_on_a_later_page_leaves_the_store_untouched_and_says_partial(self, store):
        add(store, "cus_a", "free", "cancelled")
        add(store, "cus_b", "cell", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a"),
                             sub("sub_b", "cus_b", status="canceled", price="price_cell")],
                            page_size=1, fail_list_call=2)
        before = everything(store)
        report = run(store, stripe, apply=True)
        assert not report.complete and report.exit_code == 2 and report.corrected == 0
        assert "Stripe error" in report.error
        assert len(report.unchecked) == 2 and report.findings == []
        assert everything(store) == before

    def test_an_error_while_confirming_a_correction_leaves_every_account_untouched(self, store):
        add(store, "cus_a", "free", "cancelled")
        add(store, "cus_b", "cell", "active")
        stripe = FakeStripe([sub("sub_a", "cus_a"),
                             sub("sub_b", "cus_b", status="canceled", price="price_cell")],
                            fail_retrieve=StripeError("Stripe 500: upstream", status=500))
        before = everything(store)
        report = run(store, stripe, apply=True)
        assert not report.complete and report.exit_code == 2 and report.corrected == 0
        assert everything(store) == before, "all reads precede the first write"

    def test_an_error_looking_up_one_customer_blocks_every_write_and_names_the_account(self, store):
        broken = add(store, "cus_broken", "register", "active")
        add(store, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a")], customers=["cus_broken"])
        original = stripe.list_subscriptions

        def flaky(customer=None, **kw):
            if customer == "cus_broken":
                raise StripeError("Stripe 429: rate limited", status=429)
            return original(customer=customer, **kw)

        stripe.list_subscriptions = flaky
        before = everything(store)
        report = run(store, stripe, apply=True)
        assert not report.complete and report.exit_code == 2
        assert [u["account_id"] for u in report.unchecked] == [broken.id]
        assert cats(report) == {"stripe_active_but_we_deny"}, "the rest is still reported"
        assert everything(store) == before and report.corrected == 0
        assert {f.action for f in report.findings} == {"would_correct"}


# ---------------------------------------------------------------------------
# secrets and PII
# ---------------------------------------------------------------------------
class TestNothingLeaks:
    def test_a_key_quoted_in_an_error_reaches_no_output(self, store, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        add(store, "cus_a", "register", "active", email="private.person@example.test")

        class Leaky:
            def list_subscriptions(self, **kwargs):
                raise StripeError(f"Stripe 401: Invalid API Key provided: {SECRET}")

        for argv in ([], ["--json"], ["--apply"]):
            code = rec.main(argv, gateway=Leaky(), now=NOW)
            out, err = capsys.readouterr()
            assert code == 2
            assert SECRET not in out + err and "ReconcileSecret" not in out + err
            assert "private.person" not in out + err

    def test_output_has_account_ids_and_counts_but_no_email_or_key(self, store, monkeypatch,
                                                                    capsys):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        acct = add(store, "cus_a", "free", "cancelled", email="private.person@example.test")
        stripe = FakeStripe([sub("sub_a", "cus_a"), sub("sub_o", "cus_o")])
        for argv in ([], ["--json"], ["--apply", "--json"]):
            rec.main(argv, gateway=stripe, now=NOW)
            out, err = capsys.readouterr()
            assert "private.person" not in out + err and SECRET not in out + err
            assert acct.id in out
        assert "cus_a@example.test" not in out

    def test_a_key_shaped_string_in_a_report_error_is_scrubbed_by_the_reconciler_too(self, store):
        add(store, "cus_a", "register", "active")

        class Leaky:
            def list_subscriptions(self, **kwargs):
                raise StripeError("rejected sk_live_abcdefghijkl and whsec_zzzz1234")

        report = run(store, Leaky())
        text = report.render() + json.dumps(report.to_dict())
        assert "sk_live_abcdefghijkl" not in text and "whsec_zzzz" not in text


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------
class TestCommandLine:
    @pytest.fixture()
    def cli(self, store, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        return store

    def test_exit_0_when_in_sync_and_the_sli_is_printed(self, cli, capsys):
        add(cli, "cus_a", "register", "active")
        assert rec.main([], gateway=FakeStripe([sub("sub_a", "cus_a")]), now=NOW) == 0
        out = capsys.readouterr().out
        assert "drift_count=0" in out and "IN SYNC" in out

    def test_exit_1_on_drift_with_or_without_apply_and_ids_only(self, cli, capsys):
        acct = add(cli, "cus_a", "free", "cancelled")
        stripe = FakeStripe([sub("sub_a", "cus_a")])
        assert rec.main([], gateway=stripe, now=NOW) == 1
        out = capsys.readouterr().out
        assert "drift_count=1" in out and acct.id in out and "would_correct" in out
        assert state(cli, acct.id) == ("cancelled", "free")
        assert rec.main(["--apply"], gateway=stripe, now=NOW) == 1
        out = capsys.readouterr().out
        assert "corrected" in out and state(cli, acct.id) == ("active", "register")
        assert rec.main(["--apply"], gateway=stripe, now=NOW + timedelta(minutes=2)) == 0

    def test_json_output_is_the_report(self, cli, capsys):
        acct = add(cli, "cus_a", "free", "cancelled")
        code = rec.main(["--json"], gateway=FakeStripe([sub("sub_a", "cus_a")]), now=NOW)
        data = json.loads(capsys.readouterr().out)
        assert code == 1 == data["exit_code"]
        assert data["drift_count"] == 1 and data["drift_account_ids"] == [acct.id]
        assert data["by_category"]["stripe_active_but_we_deny"] == 1
        assert data["mode"] == "dry_run" and data["complete"] is True
        assert "fake transport only" in data["notice"] and "test-mode key" in data["notice"]

    def test_the_text_report_carries_the_verification_notice(self, cli, capsys):
        rec.main([], gateway=FakeStripe([]), now=NOW)
        out = capsys.readouterr().out
        assert "fake transport only" in out and "Stripe test-mode key first" in out

    def test_past_due_days_flag(self, cli, capsys):
        add(cli, "cus_a", "register", "past_due", past_due_days=20)
        stripe = FakeStripe([sub("sub_a", "cus_a", status="past_due")])
        assert rec.main([], gateway=stripe, now=NOW) == 0
        assert rec.main(["--past-due-days", "10"], gateway=stripe, now=NOW) == 1

    def test_a_bad_past_due_days_is_a_usage_error_with_exit_2(self, cli):
        with pytest.raises(SystemExit) as caught:
            rec.main(["--past-due-days", "0"], gateway=FakeStripe([]), now=NOW)
        assert caught.value.code == 2

    def test_exit_2_when_stripe_fails(self, cli, capsys):
        add(cli, "cus_a", "register", "active")
        assert rec.main([], gateway=FakeStripe([], fail_list_call=1), now=NOW) == 2
        assert "INCOMPLETE" in capsys.readouterr().out

    def test_exit_2_without_a_stripe_key(self, store, monkeypatch, capsys):
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        assert rec.main([]) == 2
        err = capsys.readouterr().err
        assert "STRIPE_SECRET_KEY is not set" in err and "fake transport only" in err

    def test_exit_2_and_no_file_created_when_the_accounts_path_is_wrong(
            self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        missing = tmp_path / "typo.db"
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(missing))
        assert rec.main([], gateway=FakeStripe([])) == 2
        assert not missing.exists()
        assert SECRET not in capsys.readouterr().err

    def test_exit_2_for_a_store_this_build_cannot_read(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("STRIPE_SECRET_KEY", SECRET)
        path = tmp_path / "a.db"
        AccountStore(path)
        _sql(AccountStore(path), "UPDATE meta SET value='99' WHERE key='schema_version'")
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(path))
        assert rec.main([], gateway=FakeStripe([])) == 2
        assert "schema" in capsys.readouterr().err

    def test_it_runs_as_a_module(self):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "assurance.billing.reconcile", "--help"],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0 and "--apply" in result.stdout
        assert "fake transport only" in " ".join(result.stdout.split())


# ---------------------------------------------------------------------------
# schema: additive, old databases still open
# ---------------------------------------------------------------------------
class TestSchema:
    OLD = """
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO meta VALUES ('schema_version','1');
    CREATE TABLE accounts (
        id TEXT PRIMARY KEY, email TEXT NOT NULL, company TEXT NOT NULL DEFAULT '',
        tier TEXT NOT NULL, stripe_customer_id TEXT NOT NULL DEFAULT '',
        stripe_subscription_id TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active'
            CHECK (status IN ('active','past_due','cancelled')),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    INSERT INTO accounts VALUES ('acc_old','o@example.test','','register','cus_old','',
        'past_due','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
    """

    def test_a_database_from_before_this_change_still_opens_and_is_extended(self, tmp_path):
        path = tmp_path / "old.db"
        db = sqlite3.connect(path)
        db.executescript(self.OLD)
        db.commit()
        db.close()
        store = AccountStore(path)
        acct = store.account("acc_old")
        assert (acct.tier, acct.status, acct.past_due_since) == ("register", "past_due", 0)
        assert rows(store, "SELECT value FROM meta WHERE key='schema_version'") == [("1",)]
        assert rows(store, "SELECT COUNT(*) FROM entitlement_reconciliations") == [(0,)]
        assert [a.id for a in store.list_accounts()] == ["acc_old"]
        AccountStore(path)  # and again: idempotent

    def test_the_schema_version_is_unchanged(self):
        from assurance.billing.accounts import ACCOUNTS_SCHEMA_VERSION
        assert ACCOUNTS_SCHEMA_VERSION == 1

    def test_the_webhook_records_when_an_account_became_past_due(self, store):
        acct = add(store, "cus_a", "register", "active", event_age_days=60)
        store.apply_subscription_event(
            event_id="e1", kind="invoice.payment_failed", stripe_customer_id="cus_a",
            status="past_due", tier=None, event_created=TS - 40 * DAY,
            hold_if_unknown=False, only_from=frozenset({"active"}))
        assert store.account(acct.id).past_due_since == TS - 40 * DAY
        store.apply_subscription_event(
            event_id="e2", kind="customer.subscription.updated", stripe_customer_id="cus_a",
            status="past_due", tier=None, event_created=TS - 10 * DAY, hold_if_unknown=False)
        assert store.account(acct.id).past_due_since == TS - 40 * DAY, "a repeat keeps the start"
        store.apply_subscription_event(
            event_id="e3", kind="customer.subscription.updated", stripe_customer_id="cus_a",
            status="active", tier="register", event_created=TS - 5 * DAY,
            hold_if_unknown=False)
        assert store.account(acct.id).past_due_since == 0


# ---------------------------------------------------------------------------
# the webhook and the reconciler share one mapping
# ---------------------------------------------------------------------------
@pytest.fixture()
def hook_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "hook-accounts.db"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setenv("ASSURANCE_API_KEYS", "operator-key-reconcile")
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "ASSURANCE_TENANT_LEDGERS"):
        monkeypatch.delenv(name, raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as client:
        yield client
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


def _post(client, event):
    raw, headers = _signed(event)
    return client.post("/v1/billing/webhook", content=raw, headers=headers)


STATUSES = ["active", "trialing", "past_due", "canceled", "unpaid", "incomplete_expired",
            "paused", "incomplete", "something_new"]


class TestOneMapping:
    def test_the_webhook_uses_the_shared_function(self):
        from assurance.api import billing_routes
        assert billing_routes.map_subscription is shared.map_subscription

    @pytest.mark.parametrize("stripe_status", STATUSES)
    @pytest.mark.parametrize("price", ["price_reg", "price_cell"])
    def test_what_the_webhook_writes_is_exactly_what_the_reconciler_calls_in_sync(
            self, hook_client, stripe_status, price):
        tier = "register" if price == "price_reg" else "cell"
        customer = f"cus_{stripe_status}_{tier}"
        checkout = {"id": f"evt_c_{customer}", "created": TS - 30 * DAY,
                    "type": "checkout.session.completed", "data": {"object": {
                        "id": f"cs_{customer}", "customer": customer, "subscription": "sub_1",
                        "payment_status": "paid", "customer_details": {"email": "m@sk.de"},
                        "metadata": {"tier": tier}}}}
        assert _post(hook_client, checkout).status_code == 200
        live = sub("sub_1", customer, status=stripe_status, price=price)
        event = {"id": f"evt_s_{customer}", "created": TS - 20 * DAY,
                 "type": "customer.subscription.updated", "data": {"object": live}}
        assert _post(hook_client, event).status_code == 200
        report = run(deps.get_accounts(), FakeStripe([live]))
        if stripe_status == "something_new":
            # Unknown to the webhook (ignored, the account stays as it was) and
            # unknown to the reconciler: it refuses to judge rather than guess.
            assert cats(report) == {"ambiguous"}
        else:
            assert report.drift_count == 0, report.render()

    def test_the_mapping_table(self):
        def m(status, **kw):
            s = shared.map_subscription(sub("s", "c", status=status, **kw))
            return None if s is None else (s.status, s.tier, s.kind, s.ours)

        assert m("active") == ("active", "register", "entitled", True)
        assert m("trialing", price="price_cell") == ("active", "cell", "entitled", True)
        assert m("past_due") == ("past_due", None, "past_due", True)
        assert m("canceled") == ("cancelled", "free", "terminal", True)
        assert m("unpaid") == ("cancelled", "free", "terminal", True)
        assert m("incomplete_expired") == ("cancelled", "free", "terminal", True)
        assert m("paused") == ("cancelled", None, "suspended", True)
        assert m("incomplete") == ("cancelled", None, "suspended", True)
        assert m("zzz") is None
        assert m("active", price="other", metadata={}) == ("active", None, "entitled", False)
        assert shared.map_subscription(sub("s", "c", status="active"), deleted=True).kind == (
            "terminal")
        assert shared.subscription_tier_source(sub("s", "c")) == ("register", "price")
        assert shared.subscription_tier_source(
            sub("s", "c", price=None, metadata={"tier": "cell"})) == ("cell", "metadata")
        assert shared.subscription_tier_source(
            sub("s", "c", price=None, metadata={"tier": "supplier"})) == (None, "")
