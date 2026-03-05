"""
Tests for NeuralBridge FastAPI Management API.

Verifies health endpoints, adapter CRUD, connection management,
and compliance endpoints.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestHealthEndpoints:
    """Tests for /api/v1/health, /api/v1/health/ready, /api/v1/health/live."""

    def test_health_check(self, api_client: TestClient):
        response = api_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_readiness_probe(self, api_client: TestClient):
        response = api_client.get("/api/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ready", "degraded")

    def test_liveness_probe(self, api_client: TestClient):
        response = api_client.get("/api/v1/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_metrics_endpoint(self, api_client: TestClient):
        response = api_client.get("/api/v1/metrics")
        assert response.status_code == 200


class TestAdapterEndpoints:
    """Tests for /api/v1/adapters/* endpoints."""

    def test_list_adapters(self, api_client: TestClient):
        response = api_client.get("/api/v1/adapters")
        assert response.status_code == 200
        data = response.json()
        assert "adapters" in data
        assert "total" in data


class TestConnectionEndpoints:
    """Tests for /api/v1/connections/* endpoints."""

    def test_list_connections(self, api_client: TestClient):
        response = api_client.get("/api/v1/connections")
        assert response.status_code == 200
        data = response.json()
        assert "connections" in data

    def test_create_connection(self, api_client: TestClient, sample_connection_payload: dict):
        response = api_client.post("/api/v1/connections", json=sample_connection_payload)
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["name"] == sample_connection_payload["name"]

    def test_create_and_get_connection(self, api_client: TestClient, sample_connection_payload: dict):
        create_resp = api_client.post("/api/v1/connections", json=sample_connection_payload)
        conn_id = create_resp.json()["id"]
        get_resp = api_client.get(f"/api/v1/connections/{conn_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == conn_id

    def test_delete_connection(self, api_client: TestClient, sample_connection_payload: dict):
        create_resp = api_client.post("/api/v1/connections", json=sample_connection_payload)
        conn_id = create_resp.json()["id"]
        del_resp = api_client.delete(f"/api/v1/connections/{conn_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "deleted"

    def test_get_nonexistent_connection(self, api_client: TestClient):
        response = api_client.get("/api/v1/connections/nonexistent-id")
        assert response.status_code == 404


class TestComplianceEndpoints:
    """Tests for /api/v1/compliance/* endpoints."""

    def test_compliance_status(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/status")
        assert response.status_code == 200
        data = response.json()
        assert "overall_status" in data
        assert "cra_deadline" in data
        assert data["cra_deadline"] == "2026-09-11"

    def test_cra_report(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/cra-report")
        assert response.status_code == 200
        data = response.json()
        assert data["report_type"] == "CRA Vulnerability Report"

    def test_sbom_generation(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/sbom")
        assert response.status_code == 200
        data = response.json()
        assert data["bomFormat"] == "CycloneDX"

    def test_gdpr_register(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/gdpr")
        assert response.status_code == 200
        data = response.json()
        assert "gdpr_article_30_register" in data
