"""Hosted exports: the skeleton stays inside the account, the anchor is the account's own.

Real accounts, real per-account ledgers and the real counter-signing route; the
verifier is the public ``POST /v1/evidence/verify`` with the signer's public key
in the header, as a third party would use it.
"""

from __future__ import annotations

import importlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps

from .test_assurance_change import item, manifest
from .test_assurance_export_completeness import _rebuild_without

ACTOR = {"identifier": "m.braun", "role": "Head of Engineering"}
VERIFY = "/v1/evidence/verify"


@pytest.fixture()
def api(tmp_path, monkeypatch):
    from assurance.attest import SigningKey

    key_path = tmp_path / "secrets" / "service.pem"
    SigningKey.generate().save(key_path)
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "operator.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(key_path))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    for cache in (deps._register_for, deps._accounts_for, deps._tenant_register_for):
        cache.cache_clear()
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as client:
        yield client
    for cache in (deps._register_for, deps._accounts_for, deps._tenant_register_for):
        cache.cache_clear()


def _account(email):
    store = deps.get_accounts()
    account = store.upsert_account(email=email, tier="cell")
    return account, {"X-API-Key": store.issue_key(account.id)}


def _signal(client, headers, case, text="Integrator observed exploitation"):
    r = client.post(f"/v1/cases/{case}/signal", headers=headers, json={
        "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
        "description": text, "reference": "T-1", "actor": ACTOR})
    assert r.status_code == 201, r.text


def _awareness(client, headers, case):
    r = client.post(f"/v1/cases/{case}/awareness", headers=headers, json={
        "established_at": "2026-09-19T06:30:00Z",
        "assessment_started_at": "2026-09-18T22:05:00Z",
        "assessment_completed_at": "2026-09-19T06:30:00Z",
        "track": "actively_exploited_vulnerability",
        "reasoning": "SIEM export shows a shell spawned from the service port",
        "actor": ACTOR})
    assert r.status_code == 201, r.text


def _counter_sign(client, headers):
    head = client.get("/v1/ledger/verify", headers=headers).json()["attestation"]
    r = client.post("/v1/ledger/attest", headers=headers, json={
        "ledger_length": head["length"], "head_seq": head["head_seq"],
        "head_link_hash": head["head_link_hash"]})
    assert r.status_code == 200, r.text
    return r.json()["attestation"]


def _service_key_header(client):
    pem = client.get("/v1/ledger/attest/key").json()["public_key_pem"]
    return " ".join(pem.split())


def _check(client, bundle, key_header=None):
    headers = {"Content-Type": "application/json"}
    if key_header:
        headers["X-Issuer-Public-Key"] = key_header
    r = client.post(VERIFY, content=json.dumps(bundle), headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture()
def tenants(api):
    """A: C1 (seq 1, 3), C2 (seq 2, 4 after the signature). B: its own, secret case."""
    a, ha = _account("a@example.de")
    b, hb = _account("b@example.de")
    _signal(api, hb, "B-SECRET-CASE", text="B-ONLY-TEXT-77c1")
    _signal(api, ha, "C1")
    _signal(api, ha, "C2")
    _awareness(api, ha, "C1")
    anchor = _counter_sign(api, ha)
    _awareness(api, ha, "C2")
    return api, (a, ha), (b, hb), anchor


class TestTheSkeletonStaysInsideTheAccount:
    def test_a_tenants_export_shows_only_its_own_ledger(self, tenants):
        api, (_, ha), (_, hb), _ = tenants
        mine = api.get("/v1/cases/C1/export", headers=ha).json()
        assert [s["seq"] for s in mine["skeleton"]] == [2, 4]
        text = json.dumps(mine)
        assert "B-SECRET-CASE" not in text and "B-ONLY-TEXT-77c1" not in text
        theirs = api.get("/v1/cases/B-SECRET-CASE/export", headers=hb).json()
        assert theirs["skeleton"] == [] and theirs["skeleton_truncated"] is False
        theirs_text = json.dumps(theirs)
        assert '"C1"' not in theirs_text and '"C2"' not in theirs_text

    def test_a_tenants_export_carries_only_its_own_attestation(self, tenants):
        api, (_, ha), (_, hb), anchor = tenants
        assert api.get("/v1/cases/C1/export", headers=ha).json()["anchor"] == anchor
        assert "anchor" not in api.get("/v1/cases/B-SECRET-CASE/export", headers=hb).json()

    def test_the_skeleton_holds_no_evidence_or_actor(self, tenants):
        api, (_, ha), _, _ = tenants
        skeleton = api.get("/v1/cases/C1/export", headers=ha).json()["skeleton"]
        assert all(set(s) == {"seq", "at", "kind", "subject", "content_hash",
                              "prev_hash", "link_hash"} for s in skeleton)
        assert "m.braun" not in json.dumps(skeleton)


class TestTheAnchorEndToEnd:
    def test_the_export_is_anchored_under_the_published_key(self, tenants):
        api, (_, ha), _, anchor = tenants
        bundle = api.get("/v1/cases/C1/export", headers=ha).json()
        assert bundle["anchor"]["head_seq"] == 3
        got = _check(api, bundle, _service_key_header(api))
        assert got["ok"] and got["completeness"] == "anchored"
        assert got["anchor"]["records_after_anchor"] == 1
        assert any("signed anchor" in v for v in got["verified"])
        assert any("covered by no signature" in n for n in got["not_checked"])
        assert any("also holds the signing key" in a for a in got["assumptions"])

    def test_without_the_key_the_answer_says_completeness_was_not_checked(self, tenants):
        api, (_, ha), _, _ = tenants
        got = _check(api, api.get("/v1/cases/C1/export", headers=ha).json())
        assert got["ok"] and got["completeness"] == "not_checked"
        assert got["not_checked"][0].startswith("COMPLETENESS NOT CHECKED")
        assert "COMPLETENESS WAS NOT CHECKED" in got["summary"]

    def test_a_rebuilt_bundle_is_inconsistent_with_the_key_and_loud_without(self, tenants):
        api, (_, ha), _, _ = tenants
        bundle = _rebuild_without(api.get("/v1/cases/C1/export", headers=ha).json(), {1})
        keyed = _check(api, bundle, _service_key_header(api))
        assert not keyed["ok"] and keyed["outcome"] == "inconsistent"
        assert any("anchor" in p for p in keyed["problems"])
        plain = _check(api, bundle)
        assert plain["ok"] and plain["not_checked"][0].startswith("COMPLETENESS NOT CHECKED")

    def test_a_foreign_public_key_does_not_anchor_anything(self, tenants):
        from assurance.attest import SigningKey

        api, (_, ha), _, _ = tenants
        other = " ".join(SigningKey.generate().verifying.pem().split())
        got = _check(api, api.get("/v1/cases/C1/export", headers=ha).json(), other)
        assert not got["ok"] and got["completeness"] == "failed"

    def test_anchor_false_exports_without_one_and_a_keyed_check_then_refuses(self, tenants):
        api, (_, ha), _, _ = tenants
        bundle = api.get("/v1/cases/C1/export?anchor=false", headers=ha).json()
        assert "anchor" not in bundle
        got = _check(api, bundle, _service_key_header(api))
        assert not got["ok"] and any("no signed anchor" in p for p in got["problems"])

    def test_a_rewound_ledger_refuses_to_export_under_its_own_attestation(self, tenants):
        api, (account, ha), _, _ = tenants
        path = deps.tenant_ledger_path(account.id)
        db = sqlite3.connect(path)
        db.execute("DELETE FROM chain WHERE seq > 2")
        db.commit()
        db.close()
        r = api.get("/v1/cases/C1/export", headers=ha)
        assert r.status_code == 409
        detail = r.json()["detail"]
        assert detail["error"] == "anchor_contradicts_ledger"
        assert "removed after" in detail["finding"] and "anchor=false" in detail["remedy"]
        assert api.get("/v1/cases/C1/export?anchor=false", headers=ha).status_code == 200

    def test_the_change_case_export_is_skeletoned_and_anchored_too(self, api):
        _, headers = _account("c@example.de")
        opened = api.post("/v1/change/assess/drift", headers=headers, json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(item(content_hash="d" * 64), manifest_id="NOW").to_dict(),
        })
        case_id = opened.json()["case"]["case_id"]
        _counter_sign(api, headers)
        bundle = api.get(f"/v1/change/cases/{case_id}/export", headers=headers).json()
        assert "skeleton" in bundle and bundle["anchor"]["sequence"] == 1
        got = _check(api, bundle, _service_key_header(api))
        assert got["ok"] and got["completeness"] == "anchored", got["problems"]
        assert "anchor" not in api.get(
            f"/v1/change/cases/{case_id}/export?anchor=false", headers=headers).json()


def test_the_attestation_route_no_longer_says_the_ledger_never_leaves_the_customer():
    from assurance.api import attest_routes

    doc = attest_routes.__doc__
    assert "never leaves the customer's premises" not in doc
    assert "hosted per-account ledger is different" in doc
    assert "keeps their own copy" in doc
