"""Production browser access for the separate NeuralBridge platform API.

The website calls this API directly from /ai. Production CORS must permit only the
configured site origins; a missing allow-list must never become a wildcard.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from neuralbridge.config import Environment, Settings
from neuralbridge.main import create_app

_SECRET = "NB_platform_test_secret_2026_CorsSafety!xY7"
_JWT = "NB_platform_test_jwt_2026_CorsSafety!xY7"


def production_settings(origins: str) -> Settings:
    return Settings(
        env=Environment.PRODUCTION,
        debug=False,
        secret_key=_SECRET,
        jwt_secret_key=_JWT,
        cors_allowed_origins=origins,
    )


def preflight(settings: Settings, origin: str):
    client = TestClient(create_app(settings))
    return client.options(
        "/api/v1/ai/plan",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "content-type,x-api-key,x-nb-actor,x-nb-session"
            ),
        },
    )


def test_production_preflight_allows_configured_site_origins_and_credentials():
    settings = production_settings(
        "https://neuralbridge.io, https://www.neuralbridge.io"
    )
    for origin in ("https://neuralbridge.io", "https://www.neuralbridge.io"):
        response = preflight(settings, origin)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
        assert response.headers["access-control-allow-credentials"] == "true"
        assert "x-api-key" in response.headers["access-control-allow-headers"].lower()


def test_production_preflight_rejects_unlisted_origins():
    response = preflight(
        production_settings("https://neuralbridge.io,https://www.neuralbridge.io"),
        "https://attacker.example",
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    "origins",
    [
        "",
        "*",
        "https://neuralbridge.io/console",
        "http://attacker.example",
        "https://user:password@neuralbridge.io",
        "javascript://neuralbridge.io",
    ],
)
def test_production_refuses_missing_or_non_origin_cors_configuration(origins: str):
    with pytest.raises(ValueError, match="cors_allowed_origins"):
        create_app(production_settings(origins))


def test_debug_mode_keeps_the_local_development_cors_shortcut():
    settings = Settings(
        env=Environment.DEVELOPMENT,
        debug=True,
        secret_key=_SECRET,
        jwt_secret_key=_JWT,
        cors_allowed_origins="",
    )
    response = preflight(settings, "http://localhost:3000")
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
