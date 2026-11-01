"""Pay-as-you-go through Stripe: the outbox, the reporter, the reconciliation.

**Everything here runs against a fake Stripe transport.** No request is ever made
to Stripe, there is no Stripe key worth the name in any test, and nothing in this
file proves that Stripe behaves as the fake does. The fake models the parts of
Stripe's Billing Meters contract the code relies on (a 2xx with the event
echoed back, replay of a repeated identifier, a total per customer); the first
run in Stripe *test mode* is what would confirm them.

What is pinned: an event is sent once and only marked billed on acknowledgement;
every crash window recovers without double-reporting; nothing is sent unless
pay-as-you-go is fully configured; and the reconciliation finds drift and
settles an ambiguous event only when the provider's own total proves it.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing import payg, stripe_gateway
from assurance.billing import reconcile as rec
from assurance.billing.accounts import (
    AccountStore,
    QuotaExceededError,
    SpendLimitError,
)
from assurance.billing.payg import ReportError, StripeMeterGateway, report_usage
from assurance.billing.plans import PLANS
from assurance.billing.stripe_gateway import StripeError

from .test_assurance_billing import WEBHOOK_SECRET, _signed
from .test_assurance_reconcile import FakeStripe, sub

ALLOWANCE = PLANS["payg"].validations_per_day
EVENT = "nb_verification_ops"
METER = "mtr_test_fake"
# Mid-month, so that "now minus 30 hours" is still in the same account-month. With the real
# clock this file failed on the first day or so of every month: the reconciliation correctly
# works per account-month, and events straddling the boundary are two months, not one.
NOW = datetime.now(UTC).replace(day=15, hour=12, minute=0, second=0, microsecond=0)


# ---------------------------------------------------------------------------
# the fake Stripe transport
# ---------------------------------------------------------------------------
class FakeMeters:
    """A Billing Meter as far as this code relies on it. Thread-safe."""

    def __init__(self, customers=("cus_a",)):
        self.customers = set(customers)
        self.events: dict[str, dict] = {}
        self.requests: list[tuple[str, str, dict, dict]] = []
        self.script: list = []          # one behaviour per POST, then "ok"
        self.replays = 0
        self._lock = threading.Lock()

    # behaviours: "ok" | "timeout" | "accept_then_timeout" | ("status", code, error_code)
    def transport(self, method, path, form, headers):
        data = dict(form)
        with self._lock:
            self.requests.append((method, path, data, dict(headers)))
            if method == "GET":
                return self._summaries(path, data)
            behaviour = self.script.pop(0) if self.script else "ok"
            if behaviour == "timeout":
                raise StripeError("Stripe request failed (ReadTimeout)")
            if isinstance(behaviour, tuple):
                _, code, error = behaviour
                return code, {"error": {"code": error, "message": f"fake {code}"}}
            customer = data["payload[stripe_customer_id]"]
            if customer not in self.customers:
                return 400, {"error": {"code": "resource_missing",
                                       "message": f"No such customer: '{customer}'"}}
            identifier = data["identifier"]
            if identifier in self.events:
                self.replays += 1  # Stripe replays the stored response; nothing new counted
            else:
                self.events[identifier] = {
                    "customer": customer, "value": int(data["payload[value]"]),
                    "timestamp": int(data["timestamp"]), "event_name": data["event_name"]}
            if behaviour == "accept_then_timeout":
                raise StripeError("Stripe request failed (ReadTimeout)")
            return 200, {"object": "billing.meter_event", "identifier": identifier,
                         "event_name": data["event_name"], "livemode": False,
                         "timestamp": int(data["timestamp"]),
                         "payload": {"stripe_customer_id": customer,
                                     "value": data["payload[value]"]}}

    def _summaries(self, path, data):
        assert path == f"/billing/meters/{METER}/event_summaries"
        start, end = int(data["start_time"]), int(data["end_time"])
        assert start % 60 == 0 and end % 60 == 0, "Stripe needs minute-aligned windows"
        total = sum(e["value"] for e in self.events.values()
                    if e["customer"] == data["customer"] and start <= e["timestamp"] < end)
        return 200, {"object": "list", "has_more": False,
                     "data": [{"object": "billing.meter_event_summary", "aggregated_value": total,
                               "start_time": start, "end_time": end}]}

    def total(self, customer="cus_a"):
        return sum(e["value"] for e in self.events.values() if e["customer"] == customer)

    def posts(self):
        return [r for r in self.requests if r[0] == "POST"]

    def gateway(self):
        return StripeMeterGateway(transport=self.transport)


@pytest.fixture()
def meters():
    return FakeMeters()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", "operator-key-payg")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY", "ASSURANCE_PAYG_ALLOW_LIVE",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL", "ASSURANCE_PRICE_PAYG",
                 "ASSURANCE_PAYG_METER_EVENT", "ASSURANCE_PAYG_METER_ID",
                 "ASSURANCE_TENANT_LEDGERS"):
        monkeypatch.delenv(name, raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def payg_on(monkeypatch):
    monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_payg_test")
    monkeypatch.setenv("ASSURANCE_PAYG_METER_EVENT", EVENT)
    monkeypatch.setenv("ASSURANCE_PAYG_METER_ID", METER)


@pytest.fixture()
def store(env):
    return AccountStore(env / "accounts.db")


def account(store, customer="cus_a", limit=50, email=None):
    acct = store.upsert_account(email=email or f"{customer}@example.de", tier="payg",
                                stripe_customer_id=customer)
    store.set_spend_limit(acct.id, limit)
    return acct


def bill(store, acct, n, *, prefix="u", now=None):
    """Record ``ALLOWANCE`` included units (once) and ``n`` billable ones."""
    day = (now or datetime.now(UTC)).date().isoformat()
    db = sqlite3.connect(store.path)
    try:
        found = db.execute("SELECT count FROM usage WHERE subject=? AND scope='validate' AND day=?",
                           (acct.id, day)).fetchone()
    finally:
        db.close()
    for i in range(max(0, ALLOWANCE - (found[0] if found else 0))):
        store.record_usage(acct.id, "validate", 1, f"in-{prefix}-{i}", now=now)
    return [store.record_usage(acct.id, "validate", 1, f"{prefix}-{i}", now=now).event_id
            for i in range(n)]


def states(store, acct=None):
    db = sqlite3.connect(store.path)
    try:
        return {r[0]: r[1] for r in db.execute(
            "SELECT event_id, billed_state FROM usage_events WHERE billable_quantity > 0")}
    finally:
        db.close()


def row(store, event_id):
    db = sqlite3.connect(store.path)
    db.row_factory = sqlite3.Row
    try:
        return dict(db.execute("SELECT * FROM usage_events WHERE event_id=?", (event_id,)).fetchone())
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 1. the Stripe calls themselves
# ---------------------------------------------------------------------------
class TestMeterEventRequest:
    def test_the_request_has_exactly_the_documented_shape(self, meters):
        stripe_gateway.create_meter_event(
            event_name=EVENT, customer_id="cus_a", value=3, identifier="uev_abc",
            timestamp=1_790_000_000, transport=meters.transport)
        [(method, path, form, headers)] = meters.posts()
        assert (method, path) == ("POST", "/billing/meter_events")
        assert form == {"event_name": EVENT, "payload[stripe_customer_id]": "cus_a",
                        "payload[value]": "3", "identifier": "uev_abc",
                        "timestamp": "1790000000"}
        assert headers["Idempotency-Key"] == "uev_abc"
        assert headers["Stripe-Version"] == stripe_gateway.METER_API_VERSION

    @pytest.mark.parametrize("kwargs", [
        {"value": 0}, {"value": -2}, {"value": True}, {"value": 1.5},
        {"customer_id": ""}, {"customer_id": "cus a"}, {"customer_id": "../x"},
        {"identifier": ""}, {"identifier": "x" * 101},
    ])
    def test_bad_inputs_never_reach_the_transport(self, meters, kwargs):
        args = {"event_name": EVENT, "customer_id": "cus_a", "value": 1, "identifier": "uev_1",
                "timestamp": 1_790_000_000, "transport": meters.transport, **kwargs}
        with pytest.raises(StripeError):
            stripe_gateway.create_meter_event(**args)
        assert meters.requests == []

    def test_the_default_transport_is_plain_http_with_the_key_and_no_leaks(self, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_NotARealKey1234567890")
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(401, json={"error": {
                "message": "Invalid API Key provided: sk_test_NotARealKey1234567890"}})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        monkeypatch.setattr(stripe_gateway.httpx, "request",
                            lambda method, url, **kw: client.request(method, url, **kw))
        with pytest.raises(StripeError) as caught:
            stripe_gateway.create_meter_event(
                event_name=EVENT, customer_id="cus_a", value=1, identifier="uev_1",
                timestamp=1)
        assert "sk_test_NotARealKey" not in str(caught.value)
        assert str(seen[0].url) == "https://api.stripe.com/v1/billing/meter_events"
        assert seen[0].headers["idempotency-key"] == "uev_1"
        assert seen[0].headers["authorization"].startswith("Basic ")
        assert caught.value.status == 401

    def test_checkout_and_portal_posts_are_form_encoded_by_the_real_http_client(self, monkeypatch):
        """Regression: ``data=<list of tuples>`` is raw content to httpx, which then
        raised ``TypeError`` before a byte was sent - so checkout and the billing
        portal could never have worked. Every earlier test replaced the function."""
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_NotARealKey1234567890")
        bodies = []

        def handler(request: httpx.Request) -> httpx.Response:
            bodies.append((str(request.url), request.headers["content-type"],
                           request.content.decode()))
            return httpx.Response(200, json={"id": "cs_1", "url": "https://stripe.test/x"})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        monkeypatch.setattr(stripe_gateway.httpx, "post",
                            lambda url, **kw: client.post(url, **kw))
        stripe_gateway.create_checkout_session(
            price_id="price_1", email="a+b@example.de", company="A & B", success_url="https://x/y",
            cancel_url="https://x/z", tier="register")
        stripe_gateway.create_billing_portal_session(customer_id="cus_1", return_url="https://x/r")
        (url, ctype, body), (url2, _, body2) = bodies
        assert url.endswith("/v1/checkout/sessions") and url2.endswith("/v1/billing_portal/sessions")
        assert ctype == "application/x-www-form-urlencoded"
        assert "mode=subscription" in body and "line_items%5B0%5D%5Bprice%5D=price_1" in body
        assert "customer_email=a%2Bb%40example.de" in body and "A+%26+B" in body
        assert body2 == "customer=cus_1&return_url=https%3A%2F%2Fx%2Fr"

    def test_summaries_ask_for_minute_aligned_windows(self, meters):
        stripe_gateway.list_meter_event_summaries(
            meter_id=METER, customer_id="cus_a", start_time=1_790_000_017,
            end_time=1_790_000_061, transport=meters.transport)
        _, _, form, _ = meters.requests[0]
        assert int(form["start_time"]) % 60 == 0 and int(form["end_time"]) % 60 == 0
        assert int(form["start_time"]) <= 1_790_000_017 < 1_790_000_061 <= int(form["end_time"])

    @pytest.mark.parametrize("status,definitive", [
        (400, True), (422, True),
        # A rotated/revoked key (401/403) or a wrong meter path (404) is OUR
        # configuration, not a verdict on the event: the same event is fine
        # once the operator fixes it, so it must never be treated as final.
        (401, False), (403, False), (404, False),
        (408, False), (409, False), (429, False), (500, False), (503, False)])
    def test_which_refusals_are_final(self, status, definitive):
        assert stripe_gateway.is_definitive_rejection(StripeError("x", status=status)) is definitive
        assert stripe_gateway.is_definitive_rejection(StripeError("no answer")) is False

    @pytest.mark.parametrize("status,message,code,config", [
        (401, "Invalid API Key provided", "api_key_invalid", True),
        (403, "forbidden", "", True),
        (404, "Unrecognized request URL", "", True),
        (400, "No meter found with event_name nb_wrong", "resource_missing", True),
        (400, "Invalid event_name", "", True),
        (400, "No such customer: 'cus_x'", "resource_missing", False),
        (422, "x", "", False), (500, "x", "", False)])
    def test_run_level_configuration_errors_are_told_apart(self, status, message, code, config):
        exc = StripeError(message, status=status, code=code)
        assert stripe_gateway.is_configuration_error(exc) is config
        if config:
            assert stripe_gateway.is_definitive_rejection(exc) is False

    def test_no_answer_is_not_a_configuration_error(self):
        assert stripe_gateway.is_configuration_error(StripeError("no answer")) is False


# ---------------------------------------------------------------------------
# 2. the reporter: once, and only on acknowledgement
# ---------------------------------------------------------------------------
class TestReporterSendsOnce:
    def test_each_billable_event_is_sent_once_with_our_id_as_the_identifier(
            self, store, payg_on, meters):
        acct = account(store)
        ids = bill(store, acct, 3)
        result = report_usage(store, meters.gateway())
        assert (result.claimed, result.billed) == (3, 3)
        sent = {r[2]["identifier"]: r[2] for r in meters.posts()}
        assert set(sent) == set(ids)
        assert all(f["payload[stripe_customer_id]"] == "cus_a" and f["payload[value]"] == "1"
                   and f["event_name"] == EVENT for f in sent.values())
        for event_id in ids:
            r = row(store, event_id)
            assert (r["billed_state"], r["provider_event_id"]) == ("billed", event_id)
        assert meters.total() == 3

    def test_the_timestamp_is_when_the_usage_happened(self, store, payg_on, meters):
        acct = account(store)
        then = NOW - timedelta(hours=3)
        [event_id] = bill(store, acct, 1, now=then)
        report_usage(store, meters.gateway(), now=NOW)
        assert meters.events[event_id]["timestamp"] == int(then.replace(microsecond=0).timestamp())

    def test_a_second_run_sends_nothing(self, store, payg_on, meters):
        bill(store, account(store), 2)
        report_usage(store, meters.gateway())
        before = len(meters.posts())
        again = report_usage(store, meters.gateway())
        assert (again.claimed, len(meters.posts())) == (0, before)

    def test_included_usage_is_never_sent(self, store, payg_on, meters):
        acct = account(store)
        for i in range(ALLOWANCE):
            store.record_usage(acct.id, "validate", 1, f"k-{i}")
        assert report_usage(store, meters.gateway()).claimed == 0
        assert meters.requests == []

    def test_a_dry_run_sends_and_changes_nothing(self, store, payg_on, meters):
        ids = bill(store, account(store), 2)
        before = states(store)
        result = report_usage(store, meters.gateway(), dry_run=True)
        assert result.pending_seen == 2 and meters.requests == []
        assert states(store) == before and set(before) == set(ids)

    def test_only_a_matching_acknowledgement_marks_billed(self, store, payg_on):
        [event_id] = bill(store, account(store), 1)

        class WrongEcho:
            def create_meter_event(self, **kw):
                return {"object": "billing.meter_event", "identifier": "someone-else"}

        result = report_usage(store, WrongEcho())
        assert (result.billed, result.mismatched) == (0, 1)
        assert states(store)[event_id] == "sending"

    def test_an_account_with_no_customer_is_rejected_not_silently_dropped(
            self, store, payg_on, meters):
        acct = account(store)
        ids = bill(store, acct, 1)
        db = sqlite3.connect(store.path)
        db.execute("UPDATE accounts SET stripe_customer_id='' WHERE id=?", (acct.id,))
        db.commit()
        db.close()
        result = report_usage(store, meters.gateway())
        assert result.rejected == 1 and meters.requests == []
        assert states(store)[ids[0]] == "rejected"


class TestReporterIsOffUnlessConfigured:
    def test_not_configured_sends_nothing(self, store, env, meters, monkeypatch):
        # Billable events can exist (the deployment was configured, then was not);
        # an unconfigured reporter must leave them exactly as they are.
        monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_x")
        monkeypatch.setenv("ASSURANCE_PAYG_METER_EVENT", EVENT)
        ids = bill(store, account(store), 2)
        monkeypatch.delenv("ASSURANCE_PRICE_PAYG")
        with pytest.raises(ReportError):
            report_usage(store, meters.gateway())
        assert meters.requests == []
        assert set(states(store).values()) == {"pending"} and set(states(store)) == set(ids)

    def test_a_price_without_a_meter_sends_nothing(self, store, env, monkeypatch, meters):
        monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_x")
        with pytest.raises(ReportError):
            report_usage(store, meters.gateway())

    def test_a_live_key_is_refused_unless_explicitly_allowed(self, store, payg_on, monkeypatch, meters):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abcdef")
        with pytest.raises(ReportError):
            report_usage(store, meters.gateway())
        monkeypatch.setenv("ASSURANCE_PAYG_ALLOW_LIVE", "1")
        report_usage(store, meters.gateway())  # allowed: runs (nothing to send)

    def test_the_cli_exits_2_and_says_why(self, store, env, capsys, meters):
        assert payg.main(["report", "--json"], gateway=meters.gateway()) == 2
        assert "not configured" in capsys.readouterr().out

    def test_the_cli_reports_a_run(self, store, payg_on, meters, capsys):
        bill(store, account(store), 2)
        assert payg.main(["report", "--json"], gateway=meters.gateway()) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["billed"] == 2 and "fake Stripe transport" in out["notice"]


# ---------------------------------------------------------------------------
# 2b. our configuration failing must not cost revenue
# ---------------------------------------------------------------------------
class TestConfigurationErrorsDoNotRejectUsage:
    """A rotated key (401/403) or a wrong meter/event name (404, 400) used to move
    the whole batch from pending to rejected, permanently: nothing requeued it.
    Those are run-level errors: abort, leave the rows pending, say so."""

    @pytest.mark.parametrize("status,error", [
        (401, "api_key_invalid"), (403, "forbidden"), (404, "resource_missing")])
    def test_a_bad_key_or_path_aborts_the_run_and_leaves_every_row_pending(
            self, store, payg_on, meters, status, error):
        ids = bill(store, account(store), 3)
        meters.script = [("status", status, error)]
        result = report_usage(store, meters.gateway(), now=NOW)
        assert result.rejected == 0
        assert result.aborted and str(status) in result.aborted
        assert len(meters.posts()) == 1                    # stopped, not hammered 3 times
        assert {states(store)[i] for i in ids} == {"pending"}
        assert result.to_dict()["aborted"] == result.aborted
        # the operator fixes the configuration; the same rows are billed, once each
        again = report_usage(store, meters.gateway(), now=NOW + timedelta(minutes=1))
        assert again.billed == 3 and again.aborted == ""
        assert {states(store)[i] for i in ids} == {"billed"} and meters.total() == 3

    def test_a_wrong_meter_event_name_is_a_configuration_error_too(self, store, payg_on, meters):
        ids = bill(store, account(store), 2)

        def transport(method, path, form, headers):
            return 400, {"error": {"code": "resource_missing", "param": "event_name",
                                   "message": "No meter found with event_name 'nb_wrong'"}}
        result = report_usage(store, StripeMeterGateway(transport=transport), now=NOW)
        assert result.rejected == 0 and result.aborted
        assert {states(store)[i] for i in ids} == {"pending"}

    def test_released_rows_do_not_burn_their_dedupe_window_or_attempts(
            self, store, payg_on, meters):
        [event_id] = bill(store, account(store), 1)
        meters.script = [("status", 401, "api_key_invalid")]
        report_usage(store, meters.gateway(), now=NOW)
        r = row(store, event_id)
        assert (r["billed_state"], r["attempts"], r["first_attempt_at"]) == ("pending", 0, "")

    def test_the_aborted_message_never_carries_a_key(self, store, payg_on, monkeypatch, capsys):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_SUPERSECRETVALUE123")
        bill(store, account(store), 1)

        def transport(method, path, form, headers):
            return 401, {"error": {"code": "api_key_invalid", "message":
                         "Invalid API Key provided: sk_test_SUPERSECRETVALUE123"}}
        result = report_usage(store, StripeMeterGateway(transport=transport), now=NOW)
        assert "SUPERSECRET" not in json.dumps(result.to_dict())
        assert payg.main(["report", "--json"],
                         gateway=StripeMeterGateway(transport=transport), now=NOW) == 2
        out = capsys.readouterr().out
        assert "SUPERSECRET" not in out and "aborted" in out

    def test_an_event_specific_refusal_still_rejects_only_that_event(self, store, payg_on):
        good, bad = account(store, "cus_a"), account(store, "cus_unknown")
        [g] = bill(store, good, 1)
        [b] = bill(store, bad, 1)
        meters = FakeMeters(customers=("cus_a",))
        result = report_usage(store, meters.gateway(), now=NOW)
        assert (result.billed, result.rejected, result.aborted) == (1, 1, "")
        assert (states(store)[g], states(store)[b]) == ("billed", "rejected")


class TestRequeueRejected:
    """Rows rejected before this fix (or by a real per-event refusal an operator has
    since resolved) go back to pending only when someone explicitly asks."""

    def _rejected(self, store, meters_none=None):
        acct = account(store, customer="cus_unknown")
        [event_id] = bill(store, acct, 1)
        report_usage(store, FakeMeters(customers=()).gateway(), now=NOW)
        assert states(store)[event_id] == "rejected"
        return acct, event_id

    def test_nothing_requeues_by_itself(self, store, payg_on, meters):
        _, event_id = self._rejected(store)
        report_usage(store, meters.gateway(), now=NOW + timedelta(hours=1))
        assert states(store)[event_id] == "rejected" and meters.posts() == []

    def test_requeue_moves_only_rejected_rows_and_they_are_then_sent_once(
            self, store, payg_on):
        acct, event_id = self._rejected(store)
        [other] = bill(store, account(store, "cus_a"), 1)
        report_usage(store, FakeMeters().gateway(), now=NOW)
        assert states(store)[other] == "billed"
        db = sqlite3.connect(store.path)
        db.execute("UPDATE accounts SET stripe_customer_id='cus_a' WHERE id=?", (acct.id,))
        db.commit()
        db.close()
        moved = store.requeue_rejected_usage()
        assert moved == [event_id]
        assert states(store)[event_id] == "pending" and states(store)[other] == "billed"
        r = row(store, event_id)
        assert (r["attempts"], r["first_attempt_at"]) == (0, "") and "requeued" in r["last_error"]
        meters = FakeMeters()
        assert report_usage(store, meters.gateway(), now=NOW + timedelta(minutes=1)).billed == 1
        assert store.requeue_rejected_usage() == []        # nothing left to move

    def test_requeue_can_be_limited_to_named_events(self, store, payg_on):
        a1, e1 = self._rejected(store)
        a2 = account(store, customer="cus_unknown2")
        [e2] = bill(store, a2, 1)
        report_usage(store, FakeMeters(customers=()).gateway(), now=NOW)
        assert store.requeue_rejected_usage(event_ids=[e2]) == [e2]
        assert states(store)[e1] == "rejected" and states(store)[e2] == "pending"

    def test_the_cli_requeues_only_when_asked_and_never_needs_stripe(
            self, store, payg_on, capsys):
        _, event_id = self._rejected(store)
        assert payg.main(["requeue", "--json"]) == 2          # no selector: refuses, changes nothing
        assert "error" in json.loads(capsys.readouterr().out)
        assert states(store)[event_id] == "rejected"
        assert payg.main(["requeue", "--all-rejected", "--dry-run", "--json"]) == 0
        dry = json.loads(capsys.readouterr().out)
        assert (dry["requeued"], dry["matched"]) == (0, [event_id])
        assert states(store)[event_id] == "rejected"
        assert payg.main(["requeue", "--all-rejected", "--json"]) == 0
        assert states(store)[event_id] == "pending"


# ---------------------------------------------------------------------------
# 3. every crash window recovers, and nothing is reported twice
# ---------------------------------------------------------------------------
class TestCrashRecovery:
    def test_a_crash_between_recording_and_reporting_loses_nothing(
            self, env, payg_on, meters):
        first = AccountStore(env / "accounts.db")
        acct = account(first)
        ids = bill(first, acct, 2)
        del first  # the process dies here; nothing was reported
        revived = AccountStore(env / "accounts.db")  # a new process opens the same file
        assert set(states(revived)) == set(ids) and set(states(revived).values()) == {"pending"}
        report_usage(revived, meters.gateway())
        assert meters.total() == 2 and set(states(revived).values()) == {"billed"}

    def test_a_crash_after_claiming_waits_out_the_lease_then_sends_once(
            self, store, payg_on, meters):
        [event_id] = bill(store, account(store), 1)
        assert len(store.claim_usage_events(now=NOW)) == 1   # claimed ... and the process died
        assert report_usage(store, meters.gateway(), now=NOW + timedelta(minutes=1)).claimed == 0
        assert meters.requests == []                          # another reporter may be mid-flight
        later = report_usage(store, meters.gateway(), now=NOW + timedelta(minutes=11))
        assert (later.claimed, later.billed) == (1, 1)
        assert meters.total() == 1 and states(store)[event_id] == "billed"

    def test_stripe_accepted_it_but_the_answer_was_lost_so_the_retry_is_a_replay(
            self, store, payg_on, meters):
        [event_id] = bill(store, account(store), 1)
        meters.script = ["accept_then_timeout"]
        first = report_usage(store, meters.gateway(), now=NOW)
        assert (first.billed, first.retry_later) == (0, 1)
        assert states(store)[event_id] == "sending" and meters.total() == 1
        second = report_usage(store, meters.gateway(), now=NOW + timedelta(minutes=11))
        assert second.billed == 1
        assert meters.total() == 1 and meters.replays == 1   # counted once, replayed once
        first_key = meters.posts()[0][3]["Idempotency-Key"]
        assert {r[3]["Idempotency-Key"] for r in meters.posts()} == {first_key}

    def test_a_server_error_is_retried_with_the_same_identifier(self, store, payg_on, meters):
        [event_id] = bill(store, account(store), 1)
        meters.script = [("status", 503, "api_error"), "timeout"]
        for minutes in (0, 11, 22):
            report_usage(store, meters.gateway(), now=NOW + timedelta(minutes=minutes))
        assert states(store)[event_id] == "billed" and meters.total() == 1
        assert {r[2]["identifier"] for r in meters.posts()} == {event_id}
        assert row(store, event_id)["attempts"] == 3

    def test_a_definitive_refusal_is_not_retried_and_is_visible(self, store, payg_on):
        acct = account(store, customer="cus_unknown")
        [event_id] = bill(store, acct, 1)
        meters = FakeMeters(customers=())
        result = report_usage(store, meters.gateway(), now=NOW)
        assert result.rejected == 1
        report_usage(store, meters.gateway(), now=NOW + timedelta(days=1))
        assert len(meters.posts()) == 1
        r = row(store, event_id)
        assert r["billed_state"] == "rejected" and "No such customer" in r["last_error"]

    def test_past_the_dedupe_window_an_unproven_event_is_held_not_resent(
            self, store, payg_on, meters):
        [event_id] = bill(store, account(store), 1)
        meters.script = ["accept_then_timeout"]
        report_usage(store, meters.gateway(), now=NOW)
        late = report_usage(store, meters.gateway(), now=NOW + timedelta(hours=21))
        assert late.claimed == 0 and late.ambiguous == 1
        assert len(meters.posts()) == 1                       # NOT sent a second time
        assert states(store)[event_id] == "ambiguous"
        assert report_usage(store, meters.gateway(), now=NOW + timedelta(hours=40)).claimed == 0

    def test_usage_too_old_for_stripe_is_held_not_sent(self, store, payg_on, meters):
        bill(store, account(store), 1, now=NOW - timedelta(days=36))
        result = report_usage(store, meters.gateway(), now=NOW)
        assert (result.claimed, result.ambiguous) == (0, 1) and meters.requests == []

    def test_two_reporters_at_once_send_each_event_once(self, store, payg_on, meters):
        acct = account(store, limit=200)
        ids = bill(store, acct, 60)
        barrier = threading.Barrier(6)

        def work():
            mine = AccountStore(store.path)
            barrier.wait()
            for _ in range(3):
                report_usage(mine, meters.gateway(), batch=15)

        threads = [threading.Thread(target=work) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        sent = [r[2]["identifier"] for r in meters.posts()]
        assert sorted(sent) == sorted(set(sent)) == sorted(ids)
        assert meters.total() == 60 and set(states(store).values()) == {"billed"}

    def test_recording_while_reporting_loses_and_duplicates_nothing(self, store, payg_on, meters):
        acct = account(store, limit=500)
        bill(store, acct, 5, prefix="a")
        stop = threading.Event()

        def writer():
            mine = AccountStore(store.path)
            for i in range(80):
                mine.record_usage(acct.id, "validate", 1, f"w-{i}")
            stop.set()

        t = threading.Thread(target=writer)
        t.start()
        while not stop.is_set():
            report_usage(AccountStore(store.path), meters.gateway(), batch=10)
        t.join()
        report_usage(store, meters.gateway(), batch=500)
        billable = sum(e["billable_quantity"] for e in store.usage_events_all())
        assert billable >= 5 and meters.total() == billable
        assert set(states(store).values()) == {"billed"}


# ---------------------------------------------------------------------------
# 4. reconciliation: recorded usage against what was reported
# ---------------------------------------------------------------------------
def settled(store, acct, n, meters, *, prefix="s"):
    ids = bill(store, acct, n, prefix=prefix, now=NOW - timedelta(hours=2))
    report_usage(store, meters.gateway(), now=NOW - timedelta(hours=1))
    return ids


def cats(report):
    return sorted(f.category for f in report.findings)


class TestUsageReconciliation:
    def test_agreement_is_in_sync(self, store, payg_on, meters):
        settled(store, account(store), 4, meters)
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW)
        assert report.findings == [] and report.compared_with_provider and report.exit_code == 0

    def test_a_unit_stripe_does_not_have_is_drift(self, store, payg_on, meters):
        ids = settled(store, account(store), 4, meters)
        del meters.events[ids[0]]              # dropped by Stripe's async validation
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW)
        assert cats(report) == ["provider_has_fewer_than_billed"]
        assert report.findings[0].units == {"stripe": 3, "billed": 4, "sending": 0, "ambiguous": 0}
        assert report.exit_code == 1

    def test_a_unit_we_never_sent_is_drift(self, store, payg_on, meters):
        settled(store, account(store), 4, meters)
        meters.events["foreign"] = {"customer": "cus_a", "value": 2,
                                    "timestamp": int((NOW - timedelta(hours=1)).timestamp()),
                                    "event_name": EVENT}
        assert cats(payg.reconcile_usage(store, meters.gateway(), now=NOW)) == [
            "provider_has_more_than_sent"]

    def test_a_reporter_that_stopped_is_flagged_as_stale(self, store, payg_on, meters):
        bill(store, account(store), 2, now=NOW - timedelta(hours=30))
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW)
        assert "stale_unreported" in cats(report) and report.findings[0].units["units"] == 2

    def test_rejected_and_ambiguous_events_need_a_person(self, store, payg_on, meters):
        acct = account(store, customer="cus_unknown")
        bill(store, acct, 1)
        report_usage(store, FakeMeters(customers=()).gateway())
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW)
        assert "needs_attention" in cats(report)

    def test_a_billed_row_that_lost_its_acknowledgement_is_flagged(self, store, payg_on, meters):
        [event_id] = settled(store, account(store), 1, meters)
        db = sqlite3.connect(store.path)
        db.execute("UPDATE usage_events SET provider_event_id='' WHERE event_id=?", (event_id,))
        db.commit()
        db.close()
        assert "ack_mismatch" in cats(payg.reconcile_usage(store, meters.gateway(), now=NOW))

    def test_events_reported_a_moment_ago_are_deferred_not_called_drift(self, store, payg_on, meters):
        bill(store, account(store), 2, now=NOW - timedelta(minutes=3))
        report_usage(store, meters.gateway(), now=NOW - timedelta(minutes=2))
        meters.events.clear()
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW)
        assert report.findings == [] and len(report.deferred) == 1
        assert report.exit_code == 1  # not fully checked is not "clean"

    def test_without_a_meter_id_it_says_it_only_checked_its_own_records(self, store, payg_on, meters,
                                                                         monkeypatch):
        monkeypatch.delenv("ASSURANCE_PAYG_METER_ID")
        settled(store, account(store), 1, meters)
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW)
        assert not report.compared_with_provider and "ASSURANCE_PAYG_METER_ID" in report.notes[0]

    def test_a_stripe_outage_leaves_the_report_incomplete_and_the_store_untouched(
            self, store, payg_on, meters):
        settled(store, account(store), 2, meters)
        before = sqlite3.connect(store.path).execute(
            "SELECT group_concat(billed_state) FROM usage_events").fetchone()

        class Down:
            def list_meter_event_summaries(self, **kw):
                raise StripeError("Stripe 500: upstream", status=500)

        report = payg.reconcile_usage(store, Down(), now=NOW, apply=True)
        assert not report.complete and report.exit_code == 2
        assert sqlite3.connect(store.path).execute(
            "SELECT group_concat(billed_state) FROM usage_events").fetchone() == before

    def _ambiguous(self, store, meters, *, accepted):
        acct = account(store)
        ids = settled(store, acct, 2, meters, prefix="ok")
        [stuck] = bill(store, acct, 1, prefix="stuck", now=NOW - timedelta(hours=30))
        meters.script = ["accept_then_timeout" if accepted else "timeout"]
        report_usage(store, meters.gateway(), now=NOW - timedelta(hours=25))
        report_usage(store, meters.gateway(), now=NOW - timedelta(hours=2))
        assert states(store)[stuck] == "ambiguous"
        return ids, stuck

    def test_dry_run_proposes_but_writes_nothing(self, store, payg_on, meters):
        _, stuck = self._ambiguous(store, meters, accepted=False)
        readonly = AccountStore.open_readonly(store.path)
        before = store.path.read_bytes()
        report = payg.reconcile_usage(readonly, meters.gateway(), now=NOW, apply=False)
        assert [f.action for f in report.findings if f.event_id == stuck] == ["would_correct"]
        assert store.path.read_bytes() == before

    def test_apply_requeues_an_event_the_meter_provably_never_received(self, store, payg_on, meters):
        _, stuck = self._ambiguous(store, meters, accepted=False)
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW, apply=True)
        assert report.settled == 1 and states(store)[stuck] == "pending"
        report_usage(store, meters.gateway(), now=NOW)
        assert states(store)[stuck] == "billed" and meters.total() == 3

    def test_apply_marks_billed_an_event_the_meter_provably_holds(self, store, payg_on, meters):
        _, stuck = self._ambiguous(store, meters, accepted=True)
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW, apply=True)
        assert report.settled == 1 and states(store)[stuck] == "billed"
        assert meters.total() == 3          # nothing was sent again to get there

    def test_apply_leaves_an_event_alone_when_the_totals_prove_nothing(self, store, payg_on, meters):
        ids, stuck = self._ambiguous(store, meters, accepted=False)
        del meters.events[ids[0]]  # now the meter holds neither billed nor billed+ambiguous
        report = payg.reconcile_usage(store, meters.gateway(), now=NOW, apply=True)
        assert report.settled == 0 and states(store)[stuck] == "ambiguous"


# ---------------------------------------------------------------------------
# 5. the existing reconcile CLI carries the usage section
# ---------------------------------------------------------------------------
class BothStripe(FakeStripe):
    def __init__(self, meters, *a, **kw):
        super().__init__(*a, **kw)
        self._meters = meters

    def list_meter_event_summaries(self, **kw):
        return self._meters.gateway().list_meter_event_summaries(**kw)


class TestReconcileCliUsageSection:
    def _run(self, monkeypatch, store, meters, argv):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cli")
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", "price_reg")
        monkeypatch.setenv("ASSURANCE_PRICE_CELL", "price_cell")
        gateway = BothStripe(meters, [sub("sub_a", "cus_a", price="price_payg_test")])
        return rec.main(argv, gateway=gateway, now=NOW)

    def test_no_usage_section_when_there_is_no_billable_usage_and_payg_is_off(
            self, store, env, monkeypatch, capsys, meters):
        account(store)
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cli")
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_payg_test")
        monkeypatch.delenv("ASSURANCE_PAYG_METER_EVENT", raising=False)
        rec.main(["--json"], gateway=FakeStripe([]), now=NOW)
        assert "usage" not in json.loads(capsys.readouterr().out)

    def test_the_section_appears_and_agrees(self, store, payg_on, monkeypatch, capsys, meters):
        settled(store, account(store), 3, meters)
        code = self._run(monkeypatch, store, meters, ["--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["usage"]["compared_with_provider"] is True
        assert out["usage"]["drift_count"] == 0 and out["usage"]["billable_units_by_state"] == {
            "billed": 3}
        assert code == out["exit_code"]

    def test_usage_drift_alone_makes_the_exit_code_1(self, store, payg_on, monkeypatch, capsys, meters):
        ids = settled(store, account(store), 3, meters)
        del meters.events[ids[0]]
        code = self._run(monkeypatch, store, meters, ["--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["drift_count"] == 0                      # entitlements are fine
        assert out["usage"]["drift_count"] == 1 and code == 1

    def test_the_text_report_includes_it(self, store, payg_on, monkeypatch, capsys, meters):
        settled(store, account(store), 1, meters)
        self._run(monkeypatch, store, meters, [])
        assert "usage reconciliation" in capsys.readouterr().out

    def test_a_dry_run_does_not_write_even_the_usage_section(self, store, payg_on, monkeypatch,
                                                              capsys, meters):
        settled(store, account(store), 1, meters)
        before = store.path.read_bytes()
        self._run(monkeypatch, store, meters, ["--usage"])
        assert store.path.read_bytes() == before

    def test_the_live_key_guard_still_applies_to_apply(self, store, payg_on, monkeypatch, capsys,
                                                        meters):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_x")
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store.path))
        assert rec.main(["--apply"], gateway=BothStripe(meters, []), now=NOW) == 2


# ---------------------------------------------------------------------------
# 6. checkout and the webhook: the subscription that makes an account pay-as-you-go
# ---------------------------------------------------------------------------
@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


def _hook(client, event):
    raw, headers = _signed(event)
    return client.post("/v1/billing/webhook", content=raw, headers=headers)


def _checkout(tier="payg", customer="cus_p", event_id="evt_c", created=1000):
    return {"id": event_id, "created": created, "type": "checkout.session.completed",
            "data": {"object": {
                "id": f"cs_{event_id}", "customer": customer, "subscription": "sub_p",
                "payment_status": "paid", "customer_details": {"email": "p@example.de"},
                "metadata": {"tier": tier}}}}


class TestCheckoutAndWebhook:
    def test_checkout_is_refused_when_payg_is_not_configured(self, client, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
        called = []
        monkeypatch.setattr(stripe_gateway, "_post", lambda *a, **k: called.append(a))
        r = client.post("/v1/checkout", json={"tier": "payg", "email": "p@example.de"})
        assert r.status_code == 503 and r.json()["detail"]["error"] == "payg_not_available"
        assert called == []

    def test_checkout_sends_a_metered_line_item_without_a_quantity(self, client, payg_on,
                                                                   monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
        forms = []

        def fake_post(path, form):
            forms.append((path, dict(form)))
            return {"id": "cs_1", "url": "https://checkout.stripe.test/cs_1"}

        monkeypatch.setattr(stripe_gateway, "_post", fake_post)
        r = client.post("/v1/checkout", json={"tier": "payg", "email": "p@example.de"})
        assert r.status_code == 200, r.text
        path, form = forms[0]
        assert path == "/checkout/sessions" and form["mode"] == "subscription"
        assert form["line_items[0][price]"] == "price_payg_test"
        assert "line_items[0][quantity]" not in form
        assert form["metadata[tier]"] == "payg"
        assert form["subscription_data[metadata][tier]"] == "payg"

    def test_the_standing_plans_still_send_a_quantity(self, client, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
        monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", "price_reg")
        forms = []
        monkeypatch.setattr(stripe_gateway, "_post",
                            lambda path, form: forms.append(dict(form)) or
                            {"id": "cs_1", "url": "https://checkout.stripe.test/cs_1"})
        assert client.post("/v1/checkout", json={"tier": "register",
                                                  "email": "r@example.de"}).status_code == 200
        assert forms[0]["line_items[0][quantity]"] == "1"

    def test_the_webhook_binds_the_account_to_the_stripe_customer(self, client, store):
        assert _hook(client, _checkout()).status_code == 200
        acct = store.account_by_customer("cus_p")
        assert acct is not None and acct.tier == "payg" and acct.spend_limit_units == 0

    def test_a_payg_subscriber_is_sent_to_the_portal_not_a_second_checkout(
            self, client, store, payg_on):
        account(store, customer="cus_p")
        key = store.issue_key(store.account_by_customer("cus_p").id)
        r = client.post("/v1/checkout", json={"tier": "register", "email": "p@example.de"},
                        headers={"X-API-Key": key})
        assert r.status_code == 409 and r.json()["detail"]["error"] == "already_subscribed"

    def test_supplier_is_still_not_purchasable(self, client):
        assert _hook(client, _checkout(tier="supplier")).status_code == 400

    def test_cancellation_stops_billing_at_once_and_a_stale_event_cannot_restart_it(
            self, client, store, payg_on):
        acct = account(store, customer="cus_p", limit=100)
        for i in range(ALLOWANCE):
            store.record_usage(acct.id, "validate", 1, f"in-{i}")
        store.record_usage(acct.id, "validate", 1, "billable-1")
        _hook(client, {"id": "evt_d", "created": 3000, "type": "customer.subscription.deleted",
                       "data": {"object": {"customer": "cus_p", "status": "canceled",
                                           "metadata": {"tier": "payg"}}}})
        with pytest.raises(QuotaExceededError):
            store.record_usage(acct.id, "validate", 1, "billable-2")
        _hook(client, {"id": "evt_old", "created": 2000, "type": "customer.subscription.updated",
                       "data": {"object": {"customer": "cus_p", "status": "active",
                                           "metadata": {"tier": "payg"}}}})
        with pytest.raises(QuotaExceededError):
            store.record_usage(acct.id, "validate", 1, "billable-3")
        assert len(store.usage_events_all()) == 1   # only the one before cancel

    def test_past_due_pauses_billing_and_recovery_restores_it(self, client, store, payg_on):
        acct = account(store, customer="cus_p", limit=100)
        for i in range(ALLOWANCE):
            store.record_usage(acct.id, "validate", 1, f"in-{i}")
        _hook(client, {"id": "evt_pd", "created": 2000, "type": "invoice.payment_failed",
                       "data": {"object": {"customer": "cus_p"}}})
        assert store.account(acct.id).status == "past_due"
        with pytest.raises(QuotaExceededError):
            store.record_usage(acct.id, "validate", 1, "while-past-due")
        _hook(client, {"id": "evt_ok", "created": 3000, "type": "customer.subscription.updated",
                       "data": {"object": {"customer": "cus_p", "status": "active",
                                           "metadata": {"tier": "payg"}}}})
        assert store.record_usage(acct.id, "validate", 1, "after-recovery").billable_quantity == 1

    def test_webhook_processing_never_touches_recorded_usage(self, client, store, payg_on):
        acct = account(store, customer="cus_p", limit=100)
        ids = bill(store, acct, 3)
        before = [dict(e) for e in store.usage_events_all()]
        for i, status in enumerate(("past_due", "active", "canceled", "active")):
            _hook(client, {"id": f"evt_{i}", "created": 5000 + i,
                           "type": "customer.subscription.updated",
                           "data": {"object": {"customer": "cus_p", "status": status,
                                               "metadata": {"tier": "payg"}}}})
        assert [dict(e) for e in store.usage_events_all()] == before and len(ids) == 3

    def test_a_spend_limit_survives_a_status_flip(self, client, store, payg_on):
        acct = account(store, customer="cus_p", limit=7)
        _hook(client, {"id": "evt_x", "created": 4000, "type": "customer.subscription.updated",
                       "data": {"object": {"customer": "cus_p", "status": "past_due",
                                           "metadata": {"tier": "payg"}}}})
        assert store.account(acct.id).spend_limit_units == 7

    def test_a_new_payg_account_cannot_be_billed_until_it_sets_a_limit(self, client, store, payg_on):
        _hook(client, _checkout(customer="cus_new"))
        acct = store.account_by_customer("cus_new")
        for i in range(ALLOWANCE):
            store.record_usage(acct.id, "validate", 1, f"in-{i}")
        with pytest.raises(SpendLimitError):
            store.record_usage(acct.id, "validate", 1, "over")
