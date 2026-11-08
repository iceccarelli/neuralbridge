"""The ingest routes: who may call them, what they refuse, and that they use the domain functions.

401 with no or an invalid key; 402 for an authenticated account whose plan does not include
machine verification (and for a lapsed one); 403 where a role applies (the review). Entitlements are
read on every request; one account never sees another's drafts or advisories.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.ingest import sbom_store

from .ingest_support import FW_SHA, approve, csaf_doc, raw, sbom_doc

OPERATOR_KEY = "operator-key-ingest-0123456789abcdef0123456789"
ROUTES = [
    ("POST", "/v1/ingest/sbom"), ("GET", "/v1/ingest/sbom"),
    ("GET", "/v1/ingest/sbom/sbom-" + "0" * 32),
    ("POST", "/v1/ingest/sbom/sbom-" + "0" * 32 + "/review"),
    ("POST", "/v1/ingest/csaf"), ("GET", "/v1/ingest/csaf"),
    ("GET", "/v1/ingest/csaf/csaf-" + "0" * 32),
    ("GET", "/v1/ingest/csaf/csaf-" + "0" * 32 + "/impact"),
]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY", "ASSURANCE_TRUST_FLY_PROXY"):
        monkeypatch.delenv(name, raising=False)

    def clear() -> None:
        deps._register_for.cache_clear()
        deps._tenant_register_for.cache_clear()
        deps._accounts_for.cache_clear()

    clear()
    yield tmp_path
    clear()


@pytest.fixture()
def client(env):
    app = importlib.import_module("assurance.api.service").create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def store(client):
    return deps.get_accounts()


def account(store, tier: str, email: str, status: str = "active"):
    acct = store.upsert_account(email=email, tier=tier, status=status,
                                stripe_customer_id=f"cus_{email}")
    return acct, {"X-API-Key": store.issue_key(acct.id)}


@pytest.fixture()
def cell(store):
    return account(store, "cell", "ingest-cell@example.de")


def body(doc: Any, **extra: Any) -> dict[str, Any]:
    return {"document": raw(doc).decode(), "source_name": "synthetic.json", **extra}


def decider(store, acct, name="Maria Rossi") -> dict[str, str]:
    _, key = store.create_operator(acct.id, name, "decider")
    return {"X-API-Key": key}


def pending_draft(client, headers) -> str:
    r = client.post("/v1/ingest/sbom", headers=headers, json=body(sbom_doc()))
    assert r.status_code == 200, r.text
    return r.json()["draft_id"]


def review_body(client, headers, draft_id, **identity: str) -> dict[str, Any]:
    tpl = client.get(f"/v1/ingest/sbom/{draft_id}", headers=headers).json()["review_template"]
    req = approve(tpl, **identity)
    return {k: v for k, v in req.items() if k not in ("draft_id", "instructions")}


# =============================================================================================
class TestWhoMayCall:
    @pytest.mark.parametrize("method,path", ROUTES)
    def test_no_key_is_401_and_a_bad_key_is_401(self, client, method, path):
        assert client.request(method, path, json={}).status_code == 401
        assert client.request(method, path, json={},
                              headers={"X-API-Key": "nb_not_a_key"}).status_code == 401

    @pytest.mark.parametrize("method,path", ROUTES)
    def test_an_authenticated_account_without_the_entitlement_is_402(self, client, store, method,
                                                                    path):
        _, headers = account(store, "free", "ingest-free@example.de")
        r = client.request(method, path, json={}, headers=headers)
        assert r.status_code == 402, r.text
        assert "machine_verification" in json.dumps(r.json())

    @pytest.mark.parametrize("method,path", ROUTES)
    def test_a_lapsed_account_is_402_on_every_route(self, client, store, method, path):
        _, headers = account(store, "cell", "ingest-lapsed@example.de", status="cancelled")
        assert client.request(method, path, json={}, headers=headers).status_code == 402

    def test_entitlements_are_read_on_every_request(self, client, store):
        acct, headers = account(store, "cell", "ingest-live@example.de")
        assert client.get("/v1/ingest/sbom", headers=headers).status_code == 200
        store.upsert_account(email="ingest-live@example.de", tier="free", status="active",
                             account_id=acct.id, event_created=9_000_000)
        assert client.get("/v1/ingest/sbom", headers=headers).status_code == 402

    def test_the_review_is_403_for_an_account_key_and_a_contributor_but_not_a_decider(
            self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        payload = review_body(client, headers, draft_id)
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=headers, json=payload)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "operator_required"
        _, ckey = store.create_operator(acct.id, "Pat Contributor", "contributor")
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review",
                        headers={"X-API-Key": ckey}, json=payload)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "decider_role_required"
        assert client.get("/v1/ingest/sbom", headers=headers).json()["drafts"][0][
            "review_state"] == "pending_review"

    def test_an_operator_cannot_review_as_somebody_else(self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        payload = review_body(client, headers, draft_id) | {"actor": "Somebody Else"}
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=decider(store, acct),
                        json=payload)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "actor_mismatch"

    def test_the_operators_shared_ledger_is_not_a_tenants(self, client, store, cell):
        _, headers = cell
        pending_draft(client, headers)
        other = account(store, "cell", "ingest-other@example.de")[1]
        assert client.get("/v1/ingest/sbom", headers=other).json()["drafts"] == []
        assert client.get("/v1/ingest/sbom", headers={"X-API-Key": OPERATOR_KEY}
                          ).json()["drafts"] == []


# =============================================================================================
class TestTheSbomRoutes:
    def test_import_records_a_draft_and_the_same_bytes_again_are_already_imported(self, client,
                                                                                 cell):
        _, headers = cell
        r = client.post("/v1/ingest/sbom", headers=headers, json=body(sbom_doc()))
        assert r.status_code == 200
        out = r.json()
        assert out["status"] == "imported" and out["review_state"] == "pending_review"
        assert out["source"]["sha256"] == hashlib.sha256(raw(sbom_doc())).hexdigest()
        assert out["source"]["name_as_supplied"] == "synthetic.json"
        again = client.post("/v1/ingest/sbom", headers=headers, json=body(sbom_doc())).json()
        assert again["status"] == "already_imported" and again["draft_id"] == out["draft_id"]

    def test_the_draft_has_no_serial_and_nothing_safety_relevant(self, client, cell):
        _, headers = cell
        draft_id = pending_draft(client, headers)
        shown = client.get(f"/v1/ingest/sbom/{draft_id}", headers=headers).json()
        assert shown["draft"]["proposed_identity"]["serial"] == []
        assert {c["safety_relevance"] for c in shown["draft"]["components"]} == {"not_assessed"}
        assert shown["review_template"]["components"][0]["include"] is None

    def test_a_dry_run_records_nothing(self, client, cell):
        _, headers = cell
        r = client.post("/v1/ingest/sbom", headers=headers, json=body(sbom_doc(), dry_run=True))
        assert r.status_code == 200 and r.json()["status"] == "dry_run"
        assert client.get("/v1/ingest/sbom", headers=headers).json()["drafts"] == []

    def test_a_stated_sha256_is_checked_against_the_bytes_received(self, client, cell):
        _, headers = cell
        good = hashlib.sha256(raw(sbom_doc())).hexdigest()
        assert client.post("/v1/ingest/sbom", headers=headers,
                           json=body(sbom_doc(), source_sha256=good)).status_code == 200
        r = client.post("/v1/ingest/sbom", headers=headers,
                        json=body(sbom_doc(), source_sha256="0" * 64, dry_run=True))
        assert r.status_code == 422 and r.json()["detail"]["error"] == "source_hash_mismatch"

    def test_an_invalid_sbom_is_422_with_the_rules_it_breaks(self, client, cell):
        _, headers = cell
        doc = sbom_doc()
        doc["components"][0]["bom-ref"] = doc["components"][1]["bom-ref"]
        r = client.post("/v1/ingest/sbom", headers=headers, json=body(doc))
        detail = r.json()["detail"]
        assert r.status_code == 422 and detail["error"] == "invalid_sbom"
        assert any(v.startswith("SBOM-R11") for v in detail["violations"])

    @pytest.mark.parametrize("version,code", [("1.3", "unsupported_spec_version"),
                                              ("1.7", "unsupported_spec_version")])
    def test_an_unsupported_version_is_named(self, client, cell, version, code):
        doc = sbom_doc()
        doc["specVersion"] = version
        r = client.post("/v1/ingest/sbom", headers=cell[1], json=body(doc))
        assert r.status_code == 422 and r.json()["detail"]["error"] == code

    def test_hostile_documents_are_422_not_a_500(self, client, cell):
        _, headers = cell
        for text in ("[" * 4000 + "]" * 4000, "{not json", "   ", '{"a": NaN}',
                     '{"a": 1, "a": 2}', "\u0000"):
            r = client.post("/v1/ingest/sbom", headers=headers, json={"document": text})
            assert r.status_code in (400, 422), (text[:20], r.status_code, r.text[:200])

    def test_a_lone_surrogate_in_the_text_is_422_not_a_500(self, client, cell):
        r = client.post("/v1/ingest/sbom", headers=cell[1],
                        content=b'{"document": "\\ud800"}',
                        )
        assert r.status_code == 422

    def test_a_body_over_the_request_cap_is_413(self, client, cell):
        r = client.post("/v1/ingest/sbom", headers=cell[1],
                        content=b'{"document": "' + b"x" * (1024 * 1024 + 10) + b'"}')
        assert r.status_code == 413

    def test_an_unknown_field_is_refused(self, client, cell):
        r = client.post("/v1/ingest/sbom", headers=cell[1],
                        json=body(sbom_doc()) | {"auto_approve": True})
        assert r.status_code == 422

    def test_an_actor_name_cannot_imitate_the_servers_attribution_grammar(self, client, cell):
        r = client.post("/v1/ingest/sbom", headers=cell[1],
                        json=body(sbom_doc()) | {"actor": "x; operator=op_1 (decider)"})
        assert r.status_code == 422 and r.json()["detail"]["error"] == "invalid_actor"

    def test_an_unknown_draft_is_404(self, client, cell):
        r = client.get("/v1/ingest/sbom/sbom-" + "0" * 32, headers=cell[1])
        assert r.status_code == 404 and r.json()["detail"]["error"] == "draft_not_found"

    def test_the_review_enrols_through_the_front_door_and_is_once(self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        payload = review_body(client, headers, draft_id)
        who = decider(store, acct)
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=who, json=payload)
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["status"] == "approved" and out["machine"] == "DemoCo/AR-7#DEMO-0001"
        assert out["enrolment"]["status"] == "enrolled" and out["tier_ceiling"] == "profile"
        fleet = client.get("/v1/fleet/machines", headers=headers).json()
        assert [m["machine"] for m in fleet["machines"]] == ["DemoCo/AR-7#DEMO-0001"]
        again = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=who, json=payload)
        assert again.status_code == 409 and again.json()["detail"]["error"] == "already_reviewed"
        shown = client.get(f"/v1/ingest/sbom/{draft_id}", headers=headers).json()
        assert shown["review_state"] == "approved_and_enrolled"
        assert shown["review"]["reviewer"]["identifier"] == "Maria Rossi"
        assert "attribution=authenticated_operator" in shown["review"]["reviewer_attribution"]
        assert "=" not in shown["review"]["reviewer"]["role"]

    def test_a_review_that_defaults_something_is_422_with_violations(self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        payload = review_body(client, headers, draft_id, serial="n/a")
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=decider(store, acct),
                        json=payload)
        detail = r.json()["detail"]
        assert r.status_code == 422 and detail["error"] == "invalid_review"
        assert any("serial" in v for v in detail["violations"])
        assert client.get("/v1/fleet/machines", headers=headers).json()["machines"] == []

    def test_enrolments_refusal_is_409_and_the_draft_stays_pending(self, client, store, cell):
        acct, headers = cell
        first = pending_draft(client, headers)
        who = decider(store, acct)
        assert client.post(f"/v1/ingest/sbom/{first}/review", headers=who,
                           json=review_body(client, headers, first)).status_code == 200
        other = sbom_doc()
        other["components"][0]["version"] = "3.9.0"
        draft2 = client.post("/v1/ingest/sbom", headers=headers, json=body(other)).json()["draft_id"]
        r = client.post(f"/v1/ingest/sbom/{draft2}/review", headers=who,
                        json=review_body(client, headers, draft2))
        assert r.status_code == 409 and r.json()["detail"]["error"] == "configuration_differs"
        assert client.get(f"/v1/ingest/sbom/{draft2}", headers=headers).json()[
            "review_state"] == "pending_review"

    def test_the_review_body_needs_a_decision_and_a_reason(self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=decider(store, acct),
                        json={})
        assert r.status_code == 422

    def test_a_rejection_through_the_api(self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        r = client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=decider(store, acct),
                        json={"decision": "reject", "reason": "wrong product"})
        assert r.status_code == 200 and r.json()["status"] == "rejected"


# =============================================================================================
class TestTheCsafRoutes:
    def test_import_list_show_and_impact(self, client, store, cell):
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=decider(store, acct),
                    json=review_body(client, headers, draft_id))
        r = client.post("/v1/ingest/csaf", headers=headers, json=body(csaf_doc()))
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["status"] == "imported" and out["trust"] == "unsigned_inspect_only"
        assert out["publisher"]["name"].startswith("ControlCo")
        assert out["tracking"]["version"] == "2"
        ref = out["advisory_ref"]
        listed = client.get("/v1/ingest/csaf", headers=headers).json()["advisories"]
        assert [a["advisory_ref"] for a in listed] == [ref]
        shown = client.get(f"/v1/ingest/csaf/{ref}", headers=headers).json()
        assert shown["record"]["source"]["sha256"] == hashlib.sha256(raw(csaf_doc())).hexdigest()
        impact = client.get(f"/v1/ingest/csaf/{ref}/impact", headers=headers).json()
        assert impact["counts"]["affected"] == 1 and impact["machines_affected"] == [
            "DemoCo/AR-7#DEMO-0001"]
        machine = impact["machines"][0]
        assert machine["state"] == "affected"
        assert {i["item_name"]: i["state"] for i in machine["items"]} == {
            "Safety controller firmware": "affected", "libmotion": "unknown"}
        assert impact["provenance"]["automated_consequences_permitted"] is False

    def test_an_invalid_csaf_is_422_with_the_rules_it_breaks(self, client, cell):
        doc = csaf_doc()
        doc["document"]["csaf_version"] = "2.1"
        r = client.post("/v1/ingest/csaf", headers=cell[1], json=body(doc))
        detail = r.json()["detail"]
        assert r.status_code == 422 and detail["error"] == "invalid_csaf"
        assert any(v.startswith("CSAF-R02") for v in detail["violations"])

    def test_a_draft_document_is_refused_unless_allowed(self, client, cell):
        doc = csaf_doc()
        doc["document"]["tracking"]["status"] = "draft"
        r = client.post("/v1/ingest/csaf", headers=cell[1], json=body(doc))
        assert r.status_code == 422 and r.json()["detail"]["error"] == "document_not_final"
        ok = client.post("/v1/ingest/csaf", headers=cell[1], json=body(doc, allow_draft=True))
        assert ok.status_code == 200 and ok.json()["partial"] is True

    def test_a_dry_run_records_nothing(self, client, cell):
        r = client.post("/v1/ingest/csaf", headers=cell[1], json=body(csaf_doc(), dry_run=True))
        assert r.json()["status"] == "dry_run"
        assert client.get("/v1/ingest/csaf", headers=cell[1]).json()["advisories"] == []

    def test_an_unknown_ref_is_404_on_show_and_impact(self, client, cell):
        for suffix in ("", "/impact"):
            r = client.get(f"/v1/ingest/csaf/csaf-{'0' * 32}{suffix}", headers=cell[1])
            assert r.status_code == 404 and r.json()["detail"]["error"] == "advisory_not_found"

    def test_another_accounts_advisory_is_not_found(self, client, store, cell):
        ref = client.post("/v1/ingest/csaf", headers=cell[1], json=body(csaf_doc())).json()[
            "advisory_ref"]
        other = account(store, "cell", "ingest-other2@example.de")[1]
        assert client.get(f"/v1/ingest/csaf/{ref}", headers=other).status_code == 404

    def test_the_import_opens_no_case_and_changes_no_fleet(self, client, cell):
        client.post("/v1/ingest/csaf", headers=cell[1], json=body(csaf_doc()))
        assert client.get("/v1/change/cases", headers=cell[1]).json()["summary"]["open"] == 0
        assert client.get("/v1/fleet/machines", headers=cell[1]).json()["machines"] == []

    def test_the_hash_read_off_the_unit_is_the_only_hash_compared(self, client, store, cell):
        # the SBOM's SHA-256 is declared; the label decides, and the result says so
        acct, headers = cell
        draft_id = pending_draft(client, headers)
        client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=decider(store, acct),
                    json=review_body(client, headers, draft_id))
        ref = client.post("/v1/ingest/csaf", headers=headers, json=body(csaf_doc())).json()[
            "advisory_ref"]
        item = client.get(f"/v1/ingest/csaf/{ref}/impact", headers=headers).json()[
            "machines"][0]["items"][0]
        assert FW_SHA == "fe21623f37fada0422f8405c6f920036a8bdd84af16ece4f71dad17d6ec19f69"
        assert "label decided" in item["item_hash_basis"]
        assert sbom_store.REVIEW_KIND == "ingest.sbom_review"
