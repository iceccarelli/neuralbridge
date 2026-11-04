"""Per-address throttles on the unauthenticated, costly routes, with an injectable clock.

These limits are per process. A deployment with more than one process or machine, or one that
wants a limit before traffic reaches the app, needs an edge limit as well: that is the
operator's job and nothing here replaces it.
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing import stripe_gateway as stripe_gw
from assurance.billing.rate_limit import Limit, RateLimitedError, RateLimiter, env_limit

from .support_billing import (  # noqa: F401
    _billing_client_fixture,
    _billing_env_fixture,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# -- the limiter itself -------------------------------------------------------------------
def test_the_window_slides_and_a_refusal_is_not_counted():
    clock = Clock()
    rl = RateLimiter(clock=clock)
    lim = Limit(3, 60.0)
    for _ in range(3):
        rl.check("a", lim)
        clock.now += 10                      # t = 0, 10, 20 -> now 30
    with pytest.raises(RateLimitedError) as hit:
        rl.check("a", lim)
    assert hit.value.retry_after == 30       # the oldest event leaves the window at t=60
    clock.now += 5
    with pytest.raises(RateLimitedError) as again:
        rl.check("a", lim)
    assert again.value.retry_after == 25     # hammering did not push the ban out
    clock.now += 25                          # t = 60: the first event has left the window
    rl.check("a", lim)
    rl.check("b", lim)                       # another client is unaffected throughout


def test_zero_means_unlimited_and_memory_is_bounded():
    rl = RateLimiter(clock=Clock(), max_clients=50)
    for _ in range(1000):
        rl.check("x", Limit(0, 60.0))
    assert len(rl) == 0
    for i in range(500):
        rl.check(f"client-{i}", Limit(5, 60.0))
    assert len(rl) <= 50


def test_env_limit_parsing(monkeypatch):
    d = Limit(5, 60.0)
    for raw, want in (("", d), ("10", Limit(10, 60.0)), ("10/30", Limit(10, 30.0)),
                      ("0", Limit(0, 60.0)), ("x", d), ("-1", d), ("5/0", d), ("5/-3", d)):
        monkeypatch.setenv("NB_TEST_LIMIT", raw)
        assert env_limit("NB_TEST_LIMIT", d) == want, raw


# -- the routes ---------------------------------------------------------------------------
@pytest.fixture()
def shop(billing_client, monkeypatch):
    """The real app, a fake clock on it, and a Stripe session creator that counts its calls."""
    clock = Clock()
    billing_client.app.state.rate_clock = clock
    calls: list[int] = []

    def fake_create(**kw):
        calls.append(1)
        return stripe_gw.CheckoutSession(id=f"cs_t_{len(calls)}", url="https://stripe.invalid/x")

    monkeypatch.setattr(stripe_gw, "create_checkout_session", fake_create)
    return billing_client, clock, calls


BODY = {"tier": "cell", "email": "buyer@example.invalid"}


def test_checkout_is_throttled_per_address_with_retry_after(shop):
    c, clock, calls = shop
    assert [c.post("/v1/checkout", json=BODY).status_code for _ in range(5)] == [200] * 5
    r = c.post("/v1/checkout", json=BODY)
    assert r.status_code == 429
    assert r.json()["detail"]["error"] == "rate_limited"
    assert int(r.headers["retry-after"]) == r.json()["detail"]["retry_after_seconds"] >= 1
    assert len(calls) == 5                    # the refused request cost no Stripe call
    clock.now += 61
    assert c.post("/v1/checkout", json=BODY).status_code == 200


def test_a_flood_from_many_addresses_hits_the_stripe_call_budget(shop, monkeypatch):
    c, clock, calls = shop
    monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET", "7/3600")
    codes = [c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": f"203.0.113.{i}"}
                    ).status_code for i in range(1, 12)]
    assert codes == [200] * 7 + [429] * 4     # every address is under its own limit
    assert len(calls) == 7                    # Stripe was called exactly budget times
    clock.now += 3601
    assert c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": "203.0.113.99"}
                  ).status_code == 200


def test_fly_client_ip_is_honoured_only_when_the_operator_says_so(shop, monkeypatch):
    c, _, _ = shop
    # untrusted: a spoofed header does not buy a fresh bucket
    for i in range(5):
        assert c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": f"198.51.100.{i}"}
                      ).status_code == 200
    assert c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": "198.51.100.200"}
                  ).status_code == 429
    # trusted: the proxy's header keys the bucket
    monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
    assert c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": "198.51.100.201"}
                  ).status_code == 200


def test_the_limit_can_be_tuned_or_switched_off_by_the_operator(shop, monkeypatch):
    c, _, calls = shop
    monkeypatch.setenv("ASSURANCE_RATE_CHECKOUT", "0")
    assert all(c.post("/v1/checkout", json=BODY).status_code == 200 for _ in range(9))
    monkeypatch.setenv("ASSURANCE_RATE_CHECKOUT", "1/60")
    assert c.post("/v1/checkout", json=BODY).status_code == 200
    assert c.post("/v1/checkout", json=BODY).status_code == 429


def test_key_collection_is_throttled_and_a_refusal_does_not_touch_the_store(shop):
    c, clock, _ = shop
    body = {"session_id": "cs_guess", "claim_token": "x"}
    assert [c.post("/v1/checkout/complete", json=body).status_code for _ in range(20)] == [202] * 20
    r = c.post("/v1/checkout/complete", json=body)
    assert r.status_code == 429 and "retry-after" in r.headers
    clock.now += 61
    assert c.post("/v1/checkout/complete", json=body).status_code == 202


def test_a_refused_request_for_a_bad_tier_costs_neither_stripe_nor_budget(shop, monkeypatch):
    c, _, calls = shop
    monkeypatch.setenv("ASSURANCE_RATE_CHECKOUT", "0")
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET", "2/3600")
    for _ in range(5):
        assert c.post("/v1/checkout", json={"tier": "bogus", "email": "a@b.co"}).status_code == 422
    assert calls == []
    assert c.post("/v1/checkout", json=BODY).status_code == 200      # budget untouched


def test_the_throttle_dependency_is_reusable_by_any_route():
    """``rate_limited`` is what ``POST /v1/check/machine`` takes as a one-line dependency.

    (That route lives in ``check_routes.py``; wiring it is a one-line ``dependencies=`` there.)
    """
    app = FastAPI()
    clock = Clock()
    app.state.rate_clock = clock
    gate = deps.rate_limited("probe", Limit(2, 60.0), "NB_TEST_PROBE_LIMIT", what="probes")

    @app.post("/probe", dependencies=[Depends(gate)])
    def probe() -> dict:
        return {"ok": True}

    c = TestClient(app)
    assert [c.post("/probe").status_code for _ in range(3)] == [200, 200, 429]
    clock.now += 61
    assert c.post("/probe").status_code == 200
