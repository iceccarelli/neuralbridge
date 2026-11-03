"""Start-up refuses open mode off loopback, and operator keys shorter than 32 characters."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps, service

GOOD_KEY = "k" * 32


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    for name in ("ASSURANCE_API_KEYS", "ASSURANCE_ALLOW_UNAUTHENTICATED", "ASSURANCE_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))


def test_no_configuration_at_all_is_allowed_to_start():
    deps.validate_startup_config()          # unconfigured: register routes answer 503, as before


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "[::1]", "localhost", "127.0.0.2"])
def test_open_mode_is_allowed_on_loopback(monkeypatch, host):
    monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.setenv("ASSURANCE_HOST", host)
    deps.validate_startup_config()


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "203.0.113.7", "example.com",
                                  "not an address", "127.0.0.1.evil.example"])
def test_open_mode_is_refused_off_loopback(monkeypatch, host):
    monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.setenv("ASSURANCE_HOST", host)
    with pytest.raises(deps.StartupConfigError, match="non-loopback"):
        deps.validate_startup_config()


def test_open_mode_is_refused_when_the_host_cannot_be_determined(monkeypatch):
    monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
    with pytest.raises(deps.StartupConfigError, match="cannot be determined"):
        deps.validate_startup_config()
    monkeypatch.setenv("ASSURANCE_HOST", "   ")
    with pytest.raises(deps.StartupConfigError, match="cannot be determined"):
        deps.validate_startup_config()


def test_only_the_exact_value_one_turns_open_mode_on(monkeypatch):
    monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "true")
    monkeypatch.setenv("ASSURANCE_HOST", "0.0.0.0")
    deps.validate_startup_config()          # not open mode (auth_mode() agrees: see below)
    assert deps.auth_mode() == "unconfigured"


def test_a_short_operator_key_is_refused_and_never_echoed(monkeypatch):
    secret = "short-secret-key"
    monkeypatch.setenv("ASSURANCE_API_KEYS", f"{GOOD_KEY},{secret}")
    with pytest.raises(deps.StartupConfigError) as exc:
        deps.validate_startup_config()
    text = str(exc.value)
    assert "operator key #2" in text and "16 characters" in text and "minimum is 32" in text
    assert secret not in text and GOOD_KEY not in text


def test_a_key_of_exactly_the_minimum_length_is_accepted(monkeypatch):
    monkeypatch.setenv("ASSURANCE_API_KEYS", "a" * 32)
    deps.validate_startup_config()
    monkeypatch.setenv("ASSURANCE_API_KEYS", "a" * 31)
    with pytest.raises(deps.StartupConfigError):
        deps.validate_startup_config()


def test_the_running_app_refuses_to_start_on_an_unsafe_configuration(monkeypatch):
    """The wiring: ``uvicorn assurance.api.service:app`` runs the lifespan, so it fails to start."""
    monkeypatch.setenv("ASSURANCE_API_KEYS", "too-short")
    with pytest.raises(deps.StartupConfigError), TestClient(service.create_app()):
        pass
    monkeypatch.setenv("ASSURANCE_API_KEYS", GOOD_KEY)
    with TestClient(service.create_app()) as client:
        assert client.get("/v1/plans").status_code == 200
    monkeypatch.delenv("ASSURANCE_API_KEYS")
    monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.setenv("ASSURANCE_HOST", "0.0.0.0")
    with pytest.raises(deps.StartupConfigError), TestClient(service.create_app()):
        pass
