"""The HTTP register, driven through a real client.

These are the tests that matter commercially: an integrator's first contact
with this product is the API, and the behaviours asserted here are the ones
that distinguish it from a spreadsheet — the awareness record, the two
different final-report clocks, validation before submission, and a chain that
refuses to export when it does not verify.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from assurance.api.routes import GLOSSARY_VERSION

ACTOR = {"identifier": "m.braun", "role": "Entwicklungsleitung"}
AWARE = "2026-09-19T06:30:00Z"
KEY = "test-key-do-not-ship"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", KEY)
    from assurance.api import deps

    deps._register_for.cache_clear()
    app_module = importlib.import_module("assurance.api.service")
    with TestClient(app_module.create_app()) as test_client:
        test_client.headers.update({"X-API-Key": KEY})
        yield test_client


def _signal(client, case="C1", **over):
    body = {
        "received_at": "2026-09-18T21:40:00Z",
        "channel": "customer_or_integrator",
        "description": "Integrator observed exploitation on a live line",
        "reference": "TICKET-8812",
        "actor": ACTOR,
    }
    body.update(over)
    return client.post(f"/v1/cases/{case}/signal", json=body)


def _awareness(client, case="C1", **over):
    body = {
        "established_at": AWARE,
        "assessment_started_at": "2026-09-18T22:05:00Z",
        "assessment_completed_at": AWARE,
        "track": "actively_exploited_vulnerability",
        "reasoning": "SIEM export shows a shell spawned from the service port",
        "actor": ACTOR,
    }
    body.update(over)
    return client.post(f"/v1/cases/{case}/awareness", json=body)


def _triage(client, case="C1", **over):
    body = {
        "answers": {
            "is_our_product_with_digital_elements_on_the_eu_market": "yes",
            "reliable_evidence_of_malicious_exploitation": "yes",
            "exploited_in_our_product_not_merely_in_a_component": "yes",
            "awareness_of_active_exploitation_on_or_after_2026_09_11": "yes",
        },
        "actor": ACTOR,
    }
    body.update(over)
    return client.post(f"/v1/cases/{case}/triage", json=body)


def _payload(**over):
    payload = {
        "notification_type": "Vulnerability",
        "title": "Unauthenticated command injection on the service port",
        "summary": "Reachable on FW 2.1.0-2.4.6.",
        "product_name": "SK-4200 Palletising Cell",
        "product_version": "FW 2.1.0-2.4.6",
        "member_states_available": ["DE", "AT", "NL"],
        "awareness_datetime": AWARE,
    }
    payload.update(over)
    return payload


class TestAuthentication:
    def test_register_routes_require_a_key(self, client):
        client.headers.pop("X-API-Key")
        assert client.get("/v1/cases").status_code == 401

    def test_a_wrong_key_is_rejected(self, client):
        client.headers["X-API-Key"] = "not-the-key"
        assert client.get("/v1/cases").status_code == 401

    def test_healthz_is_public(self, client):
        client.headers.pop("X-API-Key")
        assert client.get("/healthz").status_code == 200

    def test_unconfigured_service_refuses_to_serve_the_register(self, tmp_path, monkeypatch):
        # An unauthenticated register is worse than no register: it produces
        # confident artifacts anyone could have written.
        monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "x.db"))
        monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
        monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
        from assurance.api import deps

        deps._register_for.cache_clear()
        app_module = importlib.import_module("assurance.api.service")
        with TestClient(app_module.create_app()) as unconfigured:
            response = unconfigured.get("/v1/cases")
            assert response.status_code == 503
            assert "ASSURANCE_API_KEYS" in response.json()["detail"]
            health = unconfigured.get("/healthz").json()
            assert health["status"] == "degraded"
            assert health["auth_mode"] == "unconfigured"


class TestLifecycle:
    def test_signal_starts_no_clock(self, client):
        response = _signal(client)
        assert response.status_code == 201
        body = response.json()
        assert body["kind"] == "art14.signal"
        assert body["ledger_seq"] == 1
        assert any("no deadline is running" in item for item in body["outstanding"])

    def test_awareness_starts_both_24_and_72_hour_clocks(self, client):
        _signal(client)
        assert _awareness(client).status_code == 201
        case = client.get("/v1/cases/C1").json()
        due = {d["stage"]: d["due_at"] for d in case["deadlines"]["deadlines"]}
        assert due["early_warning"] == "2026-09-20T06:30:00Z"   # Art. 14(2)(a)
        assert due["notification"] == "2026-09-22T06:30:00Z"    # Art. 14(2)(b)

    def test_awareness_without_a_signal_is_refused_with_the_reason(self, client):
        response = _awareness(client)
        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "case_state"
        assert "no signal" in response.json()["detail"]["detail"]

    def test_awareness_without_reasoning_is_rejected_by_the_schema(self, client):
        _signal(client)
        assert _awareness(client, reasoning="").status_code == 422

    def test_awareness_cannot_be_moved_silently(self, client):
        _signal(client)
        _awareness(client)
        response = _awareness(client)
        assert response.status_code == 409
        assert "already has an awareness record" in response.json()["detail"]["detail"]

    def test_triage_returns_the_decision_and_its_authority(self, client):
        _signal(client)
        _awareness(client)
        body = _triage(client).json()
        assert body["triage"]["status"] == "reportable"

    def test_non_reportable_ground_needing_a_trigger_is_refused_without_one(self, client):
        _signal(client)
        _awareness(client)
        response = _triage(
            client,
            answers={
                "is_our_product_with_digital_elements_on_the_eu_market": "yes",
                "reliable_evidence_of_malicious_exploitation": "no",
            },
        )
        assert response.status_code == 422
        assert "reopen trigger is required" in response.json()["detail"]["detail"]

    def test_non_reportable_with_a_trigger_records_the_ground(self, client):
        _signal(client)
        _awareness(client)
        response = _triage(
            client,
            answers={
                "is_our_product_with_digital_elements_on_the_eu_market": "yes",
                "reliable_evidence_of_malicious_exploitation": "no",
            },
            reopen_trigger="any customer report of exploitation",
        )
        assert response.status_code == 201
        triage = response.json()["triage"]
        assert triage["ground"] == "no_reliable_evidence_of_malicious_exploitation"
        assert "Art. 3(42)" in triage["authority"]

    def test_final_filing_before_its_clock_starts_is_refused(self, client):
        _signal(client)
        _awareness(client)
        _triage(client)
        response = client.post(
            "/v1/cases/C1/filings",
            json={
                "stage": "final",
                "submitted_at": "2026-09-25T09:00:00Z",
                "payload": {},
                "actor": ACTOR,
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "clock_not_started"
        assert "mitigating measure" in response.json()["detail"]["detail"]

    def test_a_mitigating_measure_starts_the_14_day_clock(self, client):
        _signal(client)
        _awareness(client)
        _triage(client)
        response = client.post(
            "/v1/cases/C1/measure",
            json={
                "available_at": "2026-09-30T16:00:00Z",
                "description": "Documented workaround published",
                "actor": ACTOR,
            },
        )
        assert response.status_code == 201
        case = client.get("/v1/cases/C1").json()
        final = [d for d in case["deadlines"]["deadlines"] if d["stage"] == "final"][0]
        assert final["due_at"] == "2026-10-14T16:00:00Z"  # Art. 14(2)(c)

    def test_incident_final_clock_runs_from_the_72_hour_submission(self, client):
        _signal(client, case="I1")
        _awareness(client, case="I1", track="severe_incident")
        client.post(
            "/v1/cases/I1/triage",
            json={
                "answers": {
                    "is_our_product_with_digital_elements_on_the_eu_market": "yes",
                    "incident_affects_security_of_the_product": "yes",
                    "affects_sensitive_or_important_data_or_functions": "yes",
                },
                "actor": ACTOR,
            },
        )
        client.post(
            "/v1/cases/I1/filings",
            json={
                "stage": "notification",
                "submitted_at": "2026-09-21T09:00:00Z",
                "payload": {
                    "notification_type": "Incident",
                    "title": "t",
                    "summary": "s",
                    "product_name": "p",
                    "product_version": "v",
                    "member_states_available": ["DE"],
                    "suspected_unlawful_or_malicious": "Yes",
                    "awareness_datetime": AWARE,
                    "incident_general_information": "general information",
                    "incident_occurred_datetime": "2026-09-18T00:00:00Z",
                    "initial_assessment": "initial assessment",
                },
                "actor": ACTOR,
            },
        )
        case = client.get("/v1/cases/I1").json()
        final = [d for d in case["deadlines"]["deadlines"] if d["stage"] == "final"][0]
        assert final["due_at"] == "2026-10-21T09:00:00Z"  # Art. 14(4)(c), one calendar month
        assert "submission" in final["runs_from_fact"]

    def test_unknown_case_is_a_404(self, client):
        assert client.get("/v1/cases/nope").status_code == 404


class TestFilings:
    def test_a_valid_early_warning_is_submittable(self, client):
        _signal(client)
        _awareness(client)
        _triage(client)
        response = client.post(
            "/v1/cases/C1/filings",
            json={
                "stage": "early_warning",
                "submitted_at": "2026-09-19T11:15:00Z",
                "payload": _payload(),
                "platform_reference": "SRP-2026-000123",
                "actor": ACTOR,
            },
        )
        assert response.status_code == 201
        assert response.headers["X-Assurance-Submittable"] == "true"
        assert response.json()["validation"]["submittable"] is True

    def test_an_incomplete_filing_is_recorded_and_flagged_not_refused(self, client):
        # A manufacturer who already submitted something incomplete needs that
        # in the record, not a 400.
        _signal(client)
        _awareness(client)
        _triage(client)
        response = client.post(
            "/v1/cases/C1/filings",
            json={
                "stage": "early_warning",
                "submitted_at": "2026-09-19T11:15:00Z",
                "payload": _payload(member_states_available=["DE", "CH"]),
                "actor": ACTOR,
            },
        )
        assert response.status_code == 201
        assert response.headers["X-Assurance-Submittable"] == "false"
        issues = response.json()["validation"]["issues"]
        assert any("not EU Member States" in i["message"] for i in issues)


class TestSpecification:
    def test_field_spec_is_served_per_track_and_stage(self, client):
        fields = client.get(
            "/v1/spec/fields",
            params={"track": "actively_exploited_vulnerability", "stage": "early_warning"},
        ).json()
        numbers = {f["number"] for f in fields}
        assert "v26" in numbers and "i31" not in numbers
        gap = next(f for f in fields if f["number"] == "v26")
        assert gap["platform_gap"]

    def test_an_unknown_stage_is_rejected(self, client):
        assert (
            client.get(
                "/v1/spec/fields",
                params={"track": "severe_incident", "stage": "nonsense"},
            ).status_code
            == 422
        )

    def test_validation_needs_no_case(self, client):
        response = client.post(
            "/v1/spec/validate",
            json={
                "track": "actively_exploited_vulnerability",
                "stage": "early_warning",
                "payload": _payload(),
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["submittable"] is True
        assert body["glossary_version"] == GLOSSARY_VERSION
        assert body["checks_skipped"]

    def test_over_length_field_blocks_submission(self, client):
        body = client.post(
            "/v1/spec/validate",
            json={
                "track": "actively_exploited_vulnerability",
                "stage": "early_warning",
                "payload": _payload(malicious_actor="x" * 140),
            },
        ).json()
        assert body["submittable"] is False
        assert any(i["field_number"] == "v27" for i in body["issues"])


class TestEvidence:
    def test_export_is_a_verified_bundle(self, client):
        _signal(client)
        _awareness(client)
        bundle = client.get("/v1/cases/C1/export").json()
        assert bundle["chain_verified"] is True
        assert len(bundle["entries"]) == 2
        assert bundle["attestation"]["head_seq"] == 2

    def test_chain_verification_is_exposed(self, client):
        _signal(client)
        body = client.get("/v1/ledger/verify").json()
        assert body["verified"] is True
        assert len(body["attestation"]["head_link_hash"]) == 64
        assert "outside this service" in body["note"]

    def test_register_report_declares_its_own_limits(self, client):
        _signal(client)
        _awareness(client)
        report = client.get("/v1/register").json()
        assert report["legacy_products_in_scope"] is True
        assert report["legacy_basis"] == "Art. 69(3)"
        assert any("non-binding" in c for c in report["checks_skipped"])

    def test_breaches_are_listed(self, client):
        # Anchored on 11 September 2026, the first day Article 14 applied, so
        # the 24-hour deadline is permanently in the past.
        _signal(client, case="OLD", received_at="2026-09-11T00:00:00Z")
        _awareness(
            client,
            case="OLD",
            established_at="2026-09-11T02:00:00Z",
            assessment_started_at="2026-09-11T00:10:00Z",
            assessment_completed_at="2026-09-11T02:00:00Z",
        )
        _triage(client, case="OLD")
        breaches = client.get("/v1/register/breaches").json()
        assert breaches
        assert breaches[0]["case_id"] == "OLD"
        assert breaches[0]["status"] == "overdue_unfiled"


class TestServiceMetadata:
    def test_healthz_reports_what_is_true(self, client):
        body = client.get("/healthz").json()
        assert body["status"] == "ok"
        assert body["auth_mode"] == "api_key"
        assert body["chain_verified"] is True
        assert body["applicable_since"] == "2026-09-11"

    def test_openapi_is_served(self, client):
        schema = client.get("/openapi.json").json()
        assert "/v1/cases/{case_id}/awareness" in schema["paths"]
