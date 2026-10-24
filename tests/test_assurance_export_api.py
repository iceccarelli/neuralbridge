"""Hosted exports: the skeleton is opt-in and stays inside the account; the anchor is
the account's own and only ever a server-read attestation.

Real accounts, real per-account ledgers and the real counter-signing route; the
verifier is the public ``POST /v1/evidence/verify`` with the signer's public key
in the header, as a third party would use it.
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
from types import SimpleNamespace

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


def _read_sign(account):
    """What the operator's `assurance attest sign` does to a hosted ledger: the
    service reads the account's own chain and signs what it saw (read_from_ledger)."""
    from assurance.api import attest_routes
    from assurance.attest import SigningKey, attest
    from assurance.evidence import EvidenceLedger

    ledger = EvidenceLedger(deps.tenant_ledger_path(account.id))
    log = attest_routes._log_for(SimpleNamespace(subject=account.id))
    key = SigningKey.load(os.environ["ASSURANCE_ATTEST_KEY"])
    return attest(ledger, key, log).to_dict()


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
    anchor = _read_sign(a)
    _awareness(api, ha, "C2")
    return api, (a, ha), (b, hb), anchor


class TestTheSkeletonIsOptInAndStaysInsideTheAccount:
    def test_the_default_case_export_names_no_other_subject(self, tenants):
        """C2 is another case of the same account; its id must not ride along in C1's file."""
        api, (_, ha), (_, hb), _ = tenants
        for path in ("/v1/cases/C1/export", "/v1/cases/C1/export?skeleton=false"):
            mine = api.get(path, headers=ha).json()
            assert "skeleton" not in mine and "skeleton_truncated" not in mine
            text = json.dumps(mine)
            assert "C2" not in text and "B-SECRET-CASE" not in text
        theirs = json.dumps(api.get("/v1/cases/B-SECRET-CASE/export", headers=hb).json())
        assert "C1" not in theirs and "C2" not in theirs

    def test_asking_for_the_skeleton_shows_only_this_accounts_other_entries(self, tenants):
        api, (_, ha), (_, hb), _ = tenants
        mine = api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json()
        assert [s["seq"] for s in mine["skeleton"]] == [2, 4]
        assert any(s["subject"] == "C2" for s in mine["skeleton"])  # the disclosure
        text = json.dumps(mine)
        assert "B-SECRET-CASE" not in text and "B-ONLY-TEXT-77c1" not in text
        theirs = api.get("/v1/cases/B-SECRET-CASE/export?skeleton=true", headers=hb).json()
        assert theirs["skeleton"] == [] and theirs["skeleton_truncated"] is False
        assert '"C1"' not in json.dumps(theirs) and '"C2"' not in json.dumps(theirs)

    def test_the_skeleton_holds_no_evidence_or_actor(self, tenants):
        api, (_, ha), _, _ = tenants
        skeleton = api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json()["skeleton"]
        assert all(set(s) == {"seq", "at", "kind", "subject", "content_hash",
                              "prev_hash", "link_hash"} for s in skeleton)
        assert "m.braun" not in json.dumps(skeleton)

    def test_the_default_export_says_so_when_checked(self, tenants):
        api, (_, ha), _, _ = tenants
        got = _check(api, api.get("/v1/cases/C1/export", headers=ha).json())
        assert got["ok"] and got["completeness"] == "not_checked"
        assert "skeleton" in " ".join(got["not_checked"][:2])
        keyed = _check(api, api.get("/v1/cases/C1/export", headers=ha).json(),
                       _service_key_header(api))
        # a genuine export is not "tampered": it is "not established", with the remedy
        assert not keyed["ok"] and keyed["outcome"] == "not_established"
        assert keyed["problems"] == [] and any("skeleton" in u for u in keyed["unestablished"])


class TestTheAnchorEndToEnd:
    def test_the_export_is_partly_anchored_under_the_published_key(self, tenants):
        api, (_, ha), _, anchor = tenants
        bundle = api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json()
        assert bundle["anchor"] == anchor and bundle["anchor"]["head_seq"] == 3
        got = _check(api, bundle, _service_key_header(api))
        assert got["ok"] and got["completeness"] == "anchored_partial", got["problems"]
        assert got["anchor"]["records_after_anchor"] == 1
        assert any("signed anchor" in v for v in got["verified"])
        assert any("covered by no signature" in n for n in got["not_checked"])
        assert any("also holds the signing key" in a for a in got["assumptions"])
        assert "1 record(s)" in got["summary"] and "no signature" in got["summary"]
        assert "agrees with a signed head" not in got["summary"]

    def test_signing_the_last_record_makes_it_fully_anchored(self, tenants):
        api, (account, ha), _, _ = tenants
        _read_sign(account)
        got = _check(api, api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json(),
                     _service_key_header(api))
        assert got["ok"] and got["completeness"] == "anchored"
        assert got["anchor"]["records_after_anchor"] == 0

    def test_without_the_key_the_answer_says_completeness_was_not_checked(self, tenants):
        api, (_, ha), _, _ = tenants
        got = _check(api, api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json())
        assert got["ok"] and got["completeness"] == "not_checked"
        assert got["not_checked"][0].startswith("COMPLETENESS NOT CHECKED")
        assert "COMPLETENESS WAS NOT CHECKED" in got["summary"]

    def test_a_rebuilt_bundle_is_inconsistent_with_the_key_and_loud_without(self, tenants):
        api, (_, ha), _, _ = tenants
        bundle = _rebuild_without(
            api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json(), {1})
        keyed = _check(api, bundle, _service_key_header(api))
        assert not keyed["ok"] and keyed["outcome"] == "inconsistent"
        assert any("anchor" in p for p in keyed["problems"])
        plain = _check(api, bundle)
        assert plain["ok"] and plain["not_checked"][0].startswith("COMPLETENESS NOT CHECKED")

    def test_a_foreign_public_key_does_not_anchor_anything(self, tenants):
        from assurance.attest import SigningKey

        api, (_, ha), _, _ = tenants
        other = " ".join(SigningKey.generate().verifying.pem().split())
        got = _check(api, api.get("/v1/cases/C1/export?skeleton=true", headers=ha).json(),
                     other)
        assert not got["ok"] and got["completeness"] == "failed"

    def test_anchor_false_exports_without_one_and_a_keyed_check_then_refuses(self, tenants):
        api, (_, ha), _, _ = tenants
        bundle = api.get("/v1/cases/C1/export?anchor=false&skeleton=true", headers=ha).json()
        assert "anchor" not in bundle
        got = _check(api, bundle, _service_key_header(api))
        assert not got["ok"] and got["outcome"] == "not_established"
        assert any("no signed anchor" in u for u in got["unestablished"])

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

    def test_the_change_case_export_is_anchored_and_opt_in_skeletoned_too(self, api):
        account, headers = _account("c@example.de")
        opened = api.post("/v1/change/assess/drift", headers=headers, json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(item(content_hash="d" * 64), manifest_id="NOW").to_dict(),
        })
        case_id = opened.json()["case"]["case_id"]
        _read_sign(account)
        plain = api.get(f"/v1/change/cases/{case_id}/export", headers=headers).json()
        assert "skeleton" not in plain and plain["anchor"]["sequence"] == 1
        bundle = api.get(f"/v1/change/cases/{case_id}/export?skeleton=true",
                         headers=headers).json()
        assert "skeleton" in bundle
        got = _check(api, bundle, _service_key_header(api))
        assert got["ok"] and got["completeness"] == "anchored", got["problems"]
        assert "anchor" not in api.get(
            f"/v1/change/cases/{case_id}/export?anchor=false", headers=headers).json()


class TestOnlyServerReadAttestationsAreEmbedded:
    """POST /v1/ledger/attest signs numbers the CUSTOMER declared (their own,
    customer-held ledger). They say nothing about the hosted ledger, so they must not
    become the anchor of a hosted export -- else one wrong declaration 409s every
    case export for good (the log is append-only)."""

    def _declare(self, api, headers, **head):
        r = api.post("/v1/ledger/attest", headers=headers, json=head)
        assert r.status_code == 200, r.text
        return r.json()["attestation"]

    def test_a_declared_head_that_matches_nothing_does_not_break_case_exports(self, api):
        account, headers = _account("d@example.de")
        _signal(api, headers, "D1")
        declared = self._declare(api, headers, ledger_length=99, head_seq=99,
                                 head_link_hash="ab" * 32)
        assert declared["basis"] == "declared_by_holder"
        r = api.get("/v1/cases/D1/export", headers=headers)
        assert r.status_code == 200, r.text
        assert "anchor" not in r.json()

    def test_the_same_for_the_change_case_export(self, api):
        account, headers = _account("e@example.de")
        opened = api.post("/v1/change/assess/drift", headers=headers, json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(item(content_hash="d" * 64), manifest_id="NOW").to_dict(),
        })
        case_id = opened.json()["case"]["case_id"]
        self._declare(api, headers, ledger_length=99, head_seq=99, head_link_hash="ab" * 32)
        r = api.get(f"/v1/change/cases/{case_id}/export", headers=headers)
        assert r.status_code == 200 and "anchor" not in r.json()

    def test_a_read_attestation_is_embedded_even_when_a_newer_declared_one_exists(self, api):
        account, headers = _account("f@example.de")
        _signal(api, headers, "F1")
        read = _read_sign(account)
        self._declare(api, headers, ledger_length=99, head_seq=99, head_link_hash="cd" * 32)
        r = api.get("/v1/cases/F1/export", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["anchor"]["sequence"] == read["sequence"]
        assert r.json()["anchor"]["basis"] == "read_from_ledger"

    def test_a_read_attestation_that_contradicts_the_ledger_is_still_a_409(self, api):
        account, headers = _account("g@example.de")
        _signal(api, headers, "G1")
        _signal(api, headers, "G2")
        _read_sign(account)
        db = sqlite3.connect(deps.tenant_ledger_path(account.id))
        db.execute("DELETE FROM chain WHERE seq > 1")
        db.commit()
        db.close()
        r = api.get("/v1/cases/G1/export", headers=headers)
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "anchor_contradicts_ledger"


class TestAZeroLengthAttestationAnchorsNothing:
    def test_a_service_signed_empty_head_cannot_anchor_an_invented_ledger(self, api, tmp_path):
        """Anyone with the attest entitlement can have the service sign an empty head.
        Attached to a ledger they made up, it must not read as 'anchored'."""
        from assurance.core import Actor, Evidence, Origin
        from assurance.evidence import EvidenceLedger

        _, headers = _account("h@example.de")
        r = api.post("/v1/ledger/attest", headers=headers, json={
            "ledger_length": 0, "head_seq": 0, "head_link_hash": "0" * 64})
        assert r.status_code == 200, r.text
        empty_head = r.json()["attestation"]

        invented = EvidenceLedger(tmp_path / "invented.db")
        for i in range(3):
            invented.append(Evidence(
                kind="t.record", body={"n": i}, actor=Actor("a.person", "engineer"),
                origin=Origin("unit-test")).seal(), subject="FORGED")
        bundle = invented.export()
        bundle["anchor"] = empty_head
        got = _check(api, bundle, _service_key_header(api))
        assert not got["ok"] and got["completeness"] == "not_checked"
        assert got["anchor"] is None
        assert got["outcome"] == "not_established"
        assert any("covers no record" in u for u in got["unestablished"])
        assert "agrees with a signed head" not in got["summary"]


def test_the_attestation_route_no_longer_says_the_ledger_never_leaves_the_customer():
    from assurance.api import attest_routes

    doc = attest_routes.__doc__
    assert "never leaves the customer's premises" not in doc
    assert "hosted per-account ledger is different" in doc
    assert "keeps their own copy" in doc


@pytest.mark.asyncio
async def test_the_mcp_export_tool_asks_for_a_skeleton_only_when_told_to(monkeypatch):
    """An agent must not disclose the account's other cases by default."""
    server = pytest.importorskip("assurance.mcp.server")
    seen = []

    async def record(method, path, **kwargs):
        seen.append((method, path, kwargs.get("params")))
        return {"status": 200, "body": {}}

    monkeypatch.setattr(server, "_call", record)
    await server.change_export("CASE-1")
    await server.change_export("CASE-1", skeleton=True)
    assert seen == [("GET", "/v1/change/cases/CASE-1/export", None),
                    ("GET", "/v1/change/cases/CASE-1/export", {"skeleton": "true"})]
