"""A late, correctly signed resend cannot mint a second key; a signed non-event is a clean 400."""

from __future__ import annotations

import sqlite3

import pytest

from assurance.billing import stripe_gateway as stripe_gw

from .support_billing import (  # noqa: F401
    WEBHOOK_SECRET,
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    checkout_event,
    collect_key,
    send,
    sign,
    subscription_event,
)
from .support_sqlite import rows as sqlite_rows

OLD = "2020-01-01T00:00:00Z"


def _rows(env, sql):
    return sqlite_rows(env / "accounts.db", sql)


def test_the_session_marker_outlives_the_event_retention(billing_client, billing_env):
    c = billing_client
    event = checkout_event("cs_1", "cus_1", "sub_1", "cell", T, event_id="evt_checkout")
    assert send(c, event).status_code == 200
    collect_key(c, "cs_1")                       # the staged key is gone: only the marker remains
    assert _rows(billing_env, "SELECT COUNT(*) FROM pending_keys") == [(0,)]

    # 60 days pass. Per-delivery event ids age out; the session marker must not.
    db = sqlite3.connect(billing_env / "accounts.db")
    db.execute("UPDATE processed_events SET processed_at=?", (OLD,))
    db.commit()
    db.close()
    # any billing event runs the purge
    assert send(c, subscription_event("customer.subscription.updated", "cus_1", "sub_1",
                                      "price_cell_test", "active", T + 10)).status_code == 200
    kinds = [r[0] for r in _rows(billing_env, "SELECT event_id FROM processed_events")]
    assert "evt_checkout" not in kinds           # the per-delivery id was purged ...
    assert "session:cs_1" in kinds               # ... the session marker was not

    # Stripe (or anyone holding a captured, re-signed body) resends it, late
    again = send(c, event)
    assert again.status_code == 200 and again.json()["duplicate"] is True
    other_id = send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T, event_id="evt_other"))
    assert other_id.json()["duplicate"] is True
    assert _rows(billing_env, "SELECT COUNT(*) FROM api_keys") == [(1,)]
    assert _rows(billing_env, "SELECT COUNT(*) FROM pending_keys") == [(0,)]


@pytest.mark.parametrize("body", [b"not json at all", b"[1, 2]", b'"a string"', b"\xff\xfe\x00bad",
                                  b""])
def test_a_validly_signed_body_that_is_not_an_event_is_a_clean_400(billing_client, body):
    r = billing_client.post("/v1/billing/webhook", content=body,
                            headers={**sign(body), "content-type": "text/plain"})
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"] == "invalid_payload"


def test_verify_webhook_raises_the_payload_error_not_a_decode_error():
    import hashlib
    import hmac
    import time

    body = b"{broken"
    ts = str(int(time.time()))
    digest = hmac.new(WEBHOOK_SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    with pytest.raises(stripe_gw.PayloadError):
        stripe_gw.verify_webhook(body, f"t={ts},v1={digest}", secret=WEBHOOK_SECRET)
    # and a bad signature is still a SignatureError, checked first
    with pytest.raises(stripe_gw.SignatureError):
        stripe_gw.verify_webhook(body, f"t={ts},v1={'0' * 64}", secret=WEBHOOK_SECRET)
