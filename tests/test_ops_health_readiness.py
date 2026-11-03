"""/livez is liveness, /healthz is readiness; a broken environment is never a silent 200.

Temp directories and TestClient only.
"""

from __future__ import annotations

import importlib
import os

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.attest import SigningKey

OPERATOR_KEY = "operator-key-ops-health"
_ENV_NAMES = (
    "ASSURANCE_ALLOW_UNAUTHENTICATED", "ASSURANCE_TENANT_LEDGERS", "ASSURANCE_ATTEST_KEY",
    "ASSURANCE_ATTEST_KEY_PEM", "ASSURANCE_ATTEST_PASSPHRASE", "ASSURANCE_ATTEST_LOGS",
)


def _clear():
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    for name in _ENV_NAMES:
        if name != "ASSURANCE_ATTEST_LOGS":
            monkeypatch.delenv(name, raising=False)
    _clear()
    yield tmp_path
    _clear()


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app(), raise_server_exceptions=False) as c:
        yield c


def _pem(key: SigningKey) -> str:
    return key.private.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode()


class TestLivezAndHealthz:
    def test_livez_answers_with_no_dependencies(self, env, monkeypatch):
        # Everything /healthz depends on is broken; the process still answers.
        blocker = env / "blocker"
        blocker.write_text("a file, not a directory")
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(blocker / "accounts.db"))
        monkeypatch.setenv("ASSURANCE_LEDGER", str(blocker / "ledger.db"))
        _clear()
        service = importlib.import_module("assurance.api.service")
        with TestClient(service.create_app(), raise_server_exceptions=False) as c:
            live = c.get("/livez")
            assert live.status_code == 200 and live.json() == {"status": "alive"}
            assert c.get("/healthz").status_code == 503

    def test_a_working_deployment_is_ready(self, client):
        resp = client.get("/healthz")
        body = resp.json()
        assert resp.status_code == 200 and body["status"] == "ok"
        assert body["ledger_ok"] is True and body["accounts_ok"] is True
        assert body["storage_ok"] is True
        assert body["attestation_key"] == "not_configured"

    def test_an_unusable_accounts_path_is_a_structured_503_not_a_500(self, env, monkeypatch):
        blocker = env / "blocker"
        blocker.write_text("a file, not a directory")
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(blocker / "accounts.db"))
        _clear()
        service = importlib.import_module("assurance.api.service")
        with TestClient(service.create_app(), raise_server_exceptions=False) as c:
            resp = c.get("/healthz")
        body = resp.json()
        assert resp.status_code == 503
        assert body["status"] == "unavailable" and body["accounts_ok"] is False
        assert body["accounts_error"] and "accounts database" in " ".join(body["problems"])
        assert body["storage_ok"] is False
        assert str(env) not in resp.text

    def test_an_unwritable_tenant_directory_is_not_ready(self, env, monkeypatch):
        blocker = env / "blocker"
        blocker.write_text("x")
        monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(blocker / "tenants"))
        _clear()
        service = importlib.import_module("assurance.api.service")
        with TestClient(service.create_app(), raise_server_exceptions=False) as c:
            resp = c.get("/healthz")
        assert resp.status_code == 503 and resp.json()["storage_ok"] is False
        assert "ASSURANCE_TENANT_LEDGERS" in " ".join(resp.json()["storage_problems"])
        assert str(env) not in resp.text

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
    def test_a_read_only_data_directory_is_not_ready(self, env, monkeypatch):
        locked = env / "locked"
        locked.mkdir()
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(locked / "accounts.db"))
        locked.chmod(0o500)
        _clear()
        try:
            service = importlib.import_module("assurance.api.service")
            with TestClient(service.create_app(), raise_server_exceptions=False) as c:
                assert c.get("/healthz").status_code == 503
        finally:
            locked.chmod(0o700)


class TestAttestationKeyIsVisibleNotFatal:
    def test_not_configured_is_shown_and_does_not_fail_readiness(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["attestation_key"] == "not_configured"
        assert resp.json()["status"] == "ok"
        # ... and the product is honest about it where it matters
        assert client.get("/v1/ledger/attest/key",
                          headers={"X-API-Key": OPERATOR_KEY}).status_code == 503

    def test_a_good_key_is_configured(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY_PEM", _pem(SigningKey.generate()))
        body = client.get("/healthz").json()
        assert body["attestation_key"] == "configured" and body["status"] == "ok"

    def test_a_bad_pem_is_unusable_and_degrades_without_failing(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY_PEM",
                           "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----")
        resp = client.get("/healthz")
        body = resp.json()
        assert resp.status_code == 200
        assert body["attestation_key"] == "unusable" and body["status"] == "degraded"
        assert any("attestation key is unusable" in w for w in body["warnings"])

    def test_a_key_file_with_unsafe_custody_is_reported_unsafe(self, env, client, monkeypatch):
        key_dir = env / "keys"
        key_dir.mkdir(mode=0o700)
        path = key_dir / "k"
        path.write_text(_pem(SigningKey.generate()))
        path.chmod(0o644)               # group/world readable: not safe to sign with
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(path))
        body = client.get("/healthz").json()
        assert body["attestation_key"] == "unsafe" and body["status"] == "degraded"
        assert str(env) not in str(body)

    def test_no_secret_material_is_in_the_body(self, client, monkeypatch):
        pem = _pem(SigningKey.generate())
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY_PEM", pem)
        text = client.get("/healthz").text
        assert "PRIVATE KEY" not in text and pem.splitlines()[1] not in text
