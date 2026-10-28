"""Seven small operational defects found by an independent review of origin/main.

L1  a lapsed customer who buys again was sent to Checkout with ``customer_email`` only, which
    makes a NEW Stripe customer, a new account and an empty ledger;
L2  ``watch push`` honoured HTTP(S)_PROXY, so a key sent to a loopback or plain-http host could
    be routed through a proxy the operator never named;
L3  the MCP relay sent ``X-API-Key`` over plain http to any host (``watch push`` refuses);
L4  an unauthenticated, deeply nested JSON body was a 500 with a RecursionError traceback;
L5  with ``ASSURANCE_TRUST_FLY_PROXY=1`` any non-IP string in ``Fly-Client-IP`` was a fresh
    quota bucket;
L6  ``POST /v1/keys`` (a plaintext key) and the exports were cacheable;
L7  the one-time key-claim capability ``session_id`` was written to the uvicorn access log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient

from assurance.billing import stripe_gateway

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    checkout_event,
    collect_key,
    send,
    subscription_event,
)

PORTS = (21300, 21301, 21302, 21303)  # this suite's loopback ports: 21300-21309 only


def _cell(client, customer="cus_1", sub="sub_1", session="cs_1"):
    assert send(client, checkout_event(session, customer, sub, "cell", T)).status_code == 200
    return collect_key(client, session)


# ---------------------------------------------------------------------------
# L1
# ---------------------------------------------------------------------------
@pytest.fixture()
def stripe_form(monkeypatch):
    """The transport edge of the Stripe gateway, replaced by a recorder. Nothing is sent."""
    captured: dict = {}

    def fake_post(path, form):
        captured["path"], captured["form"] = path, list(form)
        return {"id": "cs_new", "url": "https://checkout.invalid/x"}

    monkeypatch.setattr(stripe_gateway, "_post", fake_post)
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_throwaway_not_a_key")
    return captured


def test_l1_a_lapsed_customer_buys_again_on_their_own_stripe_customer(
        billing_client, stripe_form):
    c = billing_client
    key = _cell(c)
    send(c, subscription_event("customer.subscription.deleted", "cus_1", "sub_1",
                               "price_cell_test", "canceled", T + 5))
    r = c.post("/v1/checkout", headers={"X-API-Key": key},
               json={"tier": "cell", "email": "a@x.example"})
    assert r.status_code == 200, r.text
    form = dict(stripe_form["form"])
    assert form["customer"] == "cus_1"
    assert "customer_email" not in form       # Stripe refuses both, and email is not identity


def test_l1_an_anonymous_buyer_still_gets_a_new_customer_by_email(billing_client, stripe_form):
    r = billing_client.post("/v1/checkout", json={"tier": "cell", "email": "new@x.example"})
    assert r.status_code == 200, r.text
    form = dict(stripe_form["form"])
    assert form["customer_email"] == "new@x.example" and "customer" not in form


def test_l1_an_active_subscriber_is_still_told_they_are_subscribed(billing_client, stripe_form):
    key = _cell(billing_client)
    r = billing_client.post("/v1/checkout", headers={"X-API-Key": key},
                            json={"tier": "register", "email": "a@x.example"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "already_subscribed"
    assert "form" not in stripe_form


def test_l1_the_gateway_sends_customer_xor_email():
    seen: dict = {}

    def fake(path, form):
        seen["form"] = dict(form)
        return {"id": "cs", "url": "https://checkout.invalid"}

    original = stripe_gateway._post
    stripe_gateway._post = fake
    try:
        kw = {"price_id": "p", "company": "Co", "success_url": "s", "cancel_url": "c",
              "tier": "cell"}
        stripe_gateway.create_checkout_session(email="e@x.example", customer_id="cus_9", **kw)
        assert seen["form"]["customer"] == "cus_9" and "customer_email" not in seen["form"]
        stripe_gateway.create_checkout_session(email="e@x.example", **kw)
        assert "customer" not in seen["form"] and seen["form"]["customer_email"] == "e@x.example"
    finally:
        stripe_gateway._post = original


# ---------------------------------------------------------------------------
# L2
# ---------------------------------------------------------------------------
class _Quiet(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b'{"from":"the-named-host"}'
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def test_l2_watch_push_ignores_proxy_environment(monkeypatch):
    from assurance.watch.push import make_client

    sniffed: list[bytes] = []
    sniffer = socket.socket()
    sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sniffer.bind(("127.0.0.1", PORTS[0]))
    sniffer.listen(4)
    sniffer.settimeout(0.5)

    def sniff():
        end = time.monotonic() + 4
        while time.monotonic() < end:
            try:
                conn, _ = sniffer.accept()
            except (TimeoutError, OSError):
                continue
            sniffed.append(conn.recv(4096))
            conn.close()

    server = HTTPServer(("127.0.0.1", PORTS[1]), _Quiet)
    threads = [threading.Thread(target=sniff, daemon=True),
               threading.Thread(target=server.serve_forever, daemon=True)]
    for t in threads:
        t.start()
    try:
        for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.delenv(name, raising=False)
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{PORTS[0]}")
        with make_client(5) as client:
            reply = client.get(f"http://localhost:{PORTS[1]}/v1/watch/report")
        assert reply.json() == {"from": "the-named-host"}
    finally:
        server.shutdown()
        server.server_close()
        sniffer.close()
    assert sniffed == [], f"the request (and its key) went to a proxy: {sniffed[0][:80]!r}"


# ---------------------------------------------------------------------------
# L3
# ---------------------------------------------------------------------------
@pytest.fixture()
def mcp_sent(monkeypatch):
    sent: list[dict] = []

    async def fake_request(self, method, url, **kw):
        sent.append({"url": str(url), "headers": dict(kw.get("headers") or {})})
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
    monkeypatch.setenv("ASSURANCE_API_KEY", "asr_throwaway_not_a_key")
    return sent


@pytest.mark.parametrize("url", ["http://api.some-host.example", "http://10.0.0.5:8000",
                                 "ftp://api.example", "http://user:pw@127.0.0.1:8000"])
def test_l3_the_mcp_relay_does_not_send_a_key_where_watch_push_would_refuse(
        mcp_sent, monkeypatch, url):
    from assurance.mcp import server

    monkeypatch.setenv("ASSURANCE_API_URL", url)
    out = asyncio.run(server._call("GET", "/v1/me"))
    assert mcp_sent == [], f"X-API-Key was sent to {mcp_sent[0]['url']}"
    assert out["error"] == "assurance_api_url_not_allowed"
    assert "asr_throwaway" not in json.dumps(out)


@pytest.mark.parametrize("url", ["https://api.some-host.example", "http://127.0.0.1:8000",
                                 "http://localhost:8000", "http://[::1]:8000"])
def test_l3_https_and_loopback_are_still_served(mcp_sent, monkeypatch, url):
    from assurance.mcp import server

    monkeypatch.setenv("ASSURANCE_API_URL", url)
    out = asyncio.run(server._call("GET", "/v1/me"))
    assert out["status"] == 200
    assert mcp_sent[0]["headers"]["X-API-Key"].startswith("asr_")


# ---------------------------------------------------------------------------
# L4
# ---------------------------------------------------------------------------
def _deep(n: int, open_="{\"a\":", close="}", leaf="1") -> bytes:
    return (open_ * n + leaf + close * n).encode()


@pytest.mark.parametrize("shape", [("{\"a\":", "}"), ("[", "]")])
def test_l4_deeply_nested_json_is_not_a_500_and_leaves_no_traceback(
        billing_env, caplog, shape):
    import importlib

    service = importlib.import_module("assurance.api.service")
    client = TestClient(service.create_app(), raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG):
        r = client.post("/v1/spec/validate", content=_deep(1200, *shape),
                       headers={"content-type": "application/json"})
    assert r.status_code in (413, 422), (r.status_code, r.text[:80])
    assert "RecursionError" not in caplog.text and "Traceback" not in caplog.text
    assert "traceback" not in r.text.lower()


def test_l4_ordinary_nesting_is_not_refused_for_its_depth(billing_client):
    r = billing_client.post("/v1/spec/validate", content=_deep(20),
                            headers={"content-type": "application/json"})
    assert r.status_code == 422 and "nest" not in r.text.lower()   # a schema error, not depth


def test_l4_the_cap_counts_depth_not_brackets_in_strings(billing_client):
    body = json.dumps({"track": "x", "stage": "y", "payload": {"title": "[" * 5000 + "{" * 5000}})
    r = billing_client.post("/v1/spec/validate", content=body.encode(),
                            headers={"content-type": "application/json"})
    assert r.status_code != 413 and "nest" not in r.text.lower()


# ---------------------------------------------------------------------------
# L5
# ---------------------------------------------------------------------------
PAY = {"track": "actively_exploited_vulnerability", "stage": "early_warning", "payload": {
    "notification_type": "Vulnerability", "title": "t", "summary": "s", "product_name": "P",
    "product_version": "1", "member_states_available": ["DE"],
    "awareness_datetime": "2026-09-19T06:30:00Z"}}


def _burn(client, headers, n):
    return sum(client.post("/v1/spec/validate", json=PAY, headers=headers).status_code == 200
               for _ in range(n))


def test_l5_a_non_ip_fly_client_ip_is_not_a_fresh_quota_bucket(billing_client, monkeypatch):
    monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
    assert _burn(billing_client, {}, 25) == 20          # the peer's own allowance, spent
    fresh = sum(_burn(billing_client, {"Fly-Client-IP": f"dead{i}"}, 1) for i in range(30))
    assert fresh == 0, f"{fresh} fresh allowances from 30 invented 'addresses'"


def test_l5_real_addresses_still_get_their_own_bucket(billing_client, monkeypatch):
    monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
    assert _burn(billing_client, {"Fly-Client-IP": "203.0.113.7"}, 25) == 20
    assert _burn(billing_client, {"Fly-Client-IP": "203.0.113.8"}, 3) == 3
    assert _burn(billing_client, {"Fly-Client-IP": "2001:db8:1:2::1"}, 25) == 20
    assert _burn(billing_client, {"Fly-Client-IP": "2001:db8:1:2:ffff::9"}, 3) == 0   # same /64


# ---------------------------------------------------------------------------
# L6
# ---------------------------------------------------------------------------
def _no_store(r):
    return "no-store" in r.headers.get("cache-control", "") and \
        r.headers.get("pragma", "").lower() == "no-cache"


def test_l6_every_response_that_carries_a_plaintext_key_is_no_store(billing_client):
    c = billing_client
    assert send(c, checkout_event("cs_h", "cus_h", "sub_h", "cell", T)).status_code == 200
    pending = c.get("/v1/checkout/complete", params={"session_id": "nope"})
    assert pending.status_code == 202 and _no_store(pending)
    claimed = c.get("/v1/checkout/complete", params={"session_id": "cs_h"})
    assert claimed.status_code == 200 and _no_store(claimed)
    key = claimed.json()["api_key"]
    issued = c.post("/v1/keys", headers={"X-API-Key": key}, json={})
    assert issued.status_code == 201 and "api_key" in issued.json() and _no_store(issued)
    op = c.post("/v1/operators", headers={"X-API-Key": key},
                json={"name": "Vince", "role": "decider"})
    assert op.status_code == 201 and "api_key" in op.json() and _no_store(op)


def test_l6_exports_and_reports_are_no_store(billing_client):
    c = billing_client
    key = _cell(c)
    for path in ("/v1/cases/case-0000000000000000/export",
                 "/v1/change/cases/case-0000000000000000/export", "/v1/fleet/report"):
        r = c.get(path, headers={"X-API-Key": key})
        assert _no_store(r), (path, r.status_code, dict(r.headers))


def test_l6_listings_of_ordinary_public_data_stay_cacheable_by_default(billing_client):
    r = billing_client.get("/v1/plans")
    assert "no-store" not in r.headers.get("cache-control", "")


def test_l6_no_export_route_can_be_added_without_no_store():
    import importlib

    from assurance.api.cache_headers import is_no_store

    service = importlib.import_module("assurance.api.service")
    for path, methods in service.create_app().openapi()["paths"].items():
        for method in methods:
            if "export" in path or (method == "get" and path.endswith("/report")):
                assert is_no_store(method.upper(), path), (method, path)


# ---------------------------------------------------------------------------
# L7
# ---------------------------------------------------------------------------
def test_l7_the_claim_capability_is_redacted_from_an_access_log_line():
    from assurance.api.logging_filters import RedactQueryFilter

    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5", "GET", "/v1/checkout/complete?session_id=cs_live_SECRET&x=1", "1.1", 200),
        None)
    assert RedactQueryFilter().filter(record) is True
    line = record.getMessage()
    assert "cs_live_SECRET" not in line
    assert "session_id=[redacted]" in line and "x=1" in line


def test_l7_a_real_uvicorn_access_log_does_not_contain_the_session_id(billing_env, capfd):
    import uvicorn

    from assurance.api import service

    config = uvicorn.Config(service.create_app(), host="127.0.0.1", port=PORTS[2],
                            log_level="info", access_log=True)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        httpx.get(f"http://127.0.0.1:{PORTS[2]}/v1/checkout/complete",
                  params={"session_id": "cs_live_SECRET"}, timeout=5, trust_env=False)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    out = capfd.readouterr()
    joined = out.out + out.err
    assert "/v1/checkout/complete" in joined, joined
    assert "cs_live_SECRET" not in joined
