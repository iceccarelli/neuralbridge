"""POST /v1/change/assess/advisory/signed: a pinned, valid advisory reaches a case with its trust.

The positive path is in ``test_golden_path_advisory_to_passport_e2e``. These are the guards:
anything short of "pinned key, valid signature, expected supplier, in this account" behaves
exactly like the bare route (a named person is required), and nothing here closes a case.
"""

from __future__ import annotations

import json

import pytest

from . import interfaces_fixtures as fx
from .interfaces_scenario import PERSON
from .test_golden_path_advisory_to_passport_e2e import (
    SUPPLIER,
    World,
    advisory_for,
    sealed_manifest,  # noqa: F401  (fixture)
    second_tenant,
    signed_feed,
)

live_api = fx.live_api
ID = "ROBO-SIGNED-9"


@pytest.fixture
def world(live_api, sealed_manifest, tmp_path):  # noqa: F811
    w = World(live_api, sealed_manifest, tmp_path)
    try:
        yield w
    finally:
        w.http.close()


def _cases(w: World, headers=None) -> list:
    return w.ok("GET", "/v1/change/cases", headers)["cases"]


def _refused_without_a_person(w: World, reply) -> None:
    assert reply.status_code == 409, reply.text[:300]
    assert "named person" in json.dumps(reply.json())
    assert _cases(w) == []


def _setup(w: World, tmp_path):
    w.seal_manifest()
    adv = advisory_for(w.manifest, ID)
    return adv, signed_feed(tmp_path, adv, w.supplier_key)


def test_pinned_valid_opens_without_a_person(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()
    out = w.assess_signed(text, ID).json()
    assert out["opened"] and out["advisory_trust"]["trust_basis"] == "pinned_key_policy"
    assert out["feed_trust"]["policy_satisfied"] is True


def test_tampered_feed_needs_a_named_person(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()
    record = json.loads(text.splitlines()[0])
    record["advisory"]["remedy"] = "Flash http://evil.example/fw.bin."
    bad = json.dumps(record)
    _refused_without_a_person(w, w.assess_signed(bad, ID))
    # a named person may still open it, and the case says nothing vouched for it
    out = w.assess_signed(bad, ID, actor=PERSON).json()
    assert out["opened"] and out["advisory_trust"]["trust_basis"] == "none"
    assert out["advisory_trust"]["automated_consequences_permitted"] is False
    assert out["case"]["provenance"]["advisory_trust"] != "pinned_key_policy"


def test_unpinned_signer_needs_a_named_person(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)          # valid signature, key never pinned
    _refused_without_a_person(w, w.assess_signed(text, ID))
    out = w.assess_signed(text, ID, actor=PERSON).json()
    assert out["advisory_trust"]["trust_basis"] == "none"
    assert out["advisory_trust"]["inspect_only"] is True


def test_a_candidate_key_is_not_a_pin(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    reply = w.assess_signed(text, ID, candidate_public_key_pem=w.supplier_key.verifying.pem())
    _refused_without_a_person(w, reply)


def test_wrong_supplier_needs_a_named_person(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()
    assert SUPPLIER != "someone-else"
    _refused_without_a_person(w, w.assess_signed(text, ID, expect_supplier="someone-else"))


def test_advisory_id_not_in_feed_is_404_and_opens_nothing(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()
    reply = w.assess_signed(text, "NOT-IN-THE-FEED")
    assert reply.status_code == 404
    assert reply.json()["detail"]["error"] == "advisory_not_in_feed"
    assert _cases(w) == []


def test_unreadable_feed_is_refused_and_opens_nothing(world):
    w = world
    w.seal_manifest()
    reply = w.assess_signed("this is not a feed", ID)
    assert reply.status_code == 422
    assert _cases(w) == []


def test_second_tenant_cannot_use_the_first_tenants_pins(world, live_api, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()                                    # tenant A pins; B does not
    _, b_key, _ = second_tenant(live_api)
    sealed = w.call("POST", "/v1/machinery/manifest", b_key,
                    {"manifest": w.manifest, "actor": "b.keller"})
    assert sealed.status_code in (200, 201), sealed.text[:200]
    reply = w.assess_signed(text, ID, headers=b_key)
    assert reply.status_code == 409, reply.text[:300]
    assert _cases(w, b_key) == []
    assert _cases(w) == []


def test_the_signed_route_is_gated_401_and_402(world, live_api, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()
    _, r_key = live_api.account("romeo2@golden.example", "register")
    assert w.assess_signed(text, ID, headers={}).status_code == 401
    assert w.assess_signed(text, ID, headers={"X-API-Key": "asr_not_a_key"}).status_code == 401
    denied = w.assess_signed(text, ID, headers=r_key)
    assert denied.status_code == 402
    assert _cases(w) == []


def test_redelivery_is_idempotent_and_writes_nothing_new(world, tmp_path):
    w = world
    _, text = _setup(w, tmp_path)
    w.pin_supplier()
    first = w.assess_signed(text, ID).json()
    before = w.ok("GET", "/v1/change/cases")
    again = w.assess_signed(text, ID).json()
    assert again["case"]["case_id"] == first["case"]["case_id"]
    assert w.ok("GET", "/v1/change/cases") == before
    assert first["case"]["status"] != "closed"


def test_a_withdrawn_advisory_is_not_a_standing_advisory(world, tmp_path):
    from assurance.supplier import AdvisoryFeed, withdraw

    from .test_golden_path_advisory_to_passport_e2e import IDENTITY

    w = world
    w.seal_manifest()
    adv = advisory_for(w.manifest, ID)
    feed = AdvisoryFeed(tmp_path / "w.jsonl")
    from assurance.supplier import publish
    publish(adv, IDENTITY, w.supplier_key, feed)
    withdraw(ID, "issued against the wrong firmware", IDENTITY, w.supplier_key, feed)
    w.pin_supplier()
    reply = w.assess_signed(feed.path.read_text(encoding="utf-8"), ID)
    assert reply.status_code == 404
    assert _cases(w) == []


def test_a_manual_override_is_not_a_pin(world, tmp_path):
    """An override is a person's attributed act on ONE advisory; it does not let this route
    open a case with no person, because the basis is not the pinned key policy."""
    w = world
    _, text = _setup(w, tmp_path)
    over = w.call("POST", "/v1/supplier/trust/override", w.decider, {
        "feed": text, "advisory_id": ID, "actor": PERSON,
        "reason": "read against the supplier's own page"})
    assert over.status_code in (200, 201), over.text[:300]
    reply = w.assess_signed(text, ID)
    assert reply.status_code == 409, reply.text[:300]
    assert _cases(w) == []
