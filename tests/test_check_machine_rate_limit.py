"""POST /v1/check/machine is anonymous and unmetered; it must be rate limited per client address (429), and the limit is operator-tunable."""

from __future__ import annotations

from fastapi.testclient import TestClient

from assurance.api.service import create_app


def test_the_anonymous_unmetered_check_is_rate_limited(monkeypatch):
    monkeypatch.setenv("ASSURANCE_RATE_CHECK_MACHINE", "2")
    client = TestClient(create_app())
    codes = [client.post("/v1/check/machine", json={}).status_code for _ in range(4)]
    assert codes[:2] == [422, 422]          # real validation answers while under the limit
    assert codes[2:] == [429, 429]
    refused = client.post("/v1/check/machine", json={})
    assert refused.headers.get("retry-after")


def test_zero_turns_the_limit_off(monkeypatch):
    monkeypatch.setenv("ASSURANCE_RATE_CHECK_MACHINE", "0")
    client = TestClient(create_app())
    assert {client.post("/v1/check/machine", json={}).status_code for _ in range(5)} == {422}
