"""A browser can only read a non-safelisted response header if CORS exposes it.

app/lib/assuranceApi.ts reads ``retry-after`` cross-origin, and the metering
headers (``X-Assurance-Quota-*``) are for the browser client too; without
``Access-Control-Expose-Headers`` they are invisible to it however correct the
server is. curl and pytest cannot show this, only a real cross-origin browser.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps

ORIGIN = "https://neuralbridge.io"
API_DIR = Path(__file__).resolve().parents[1] / "src" / "assurance" / "api"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


def exposed(client) -> set[str]:
    response = client.get("/v1/plans", headers={"Origin": ORIGIN})
    raw = response.headers.get("access-control-expose-headers", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def test_retry_after_and_the_quota_headers_are_exposed_to_the_browser(client):
    names = exposed(client)
    assert {"retry-after", "x-assurance-tier", "x-assurance-quota-limit",
            "x-assurance-quota-remaining", "x-assurance-usage-event",
            "x-assurance-billable-units"} <= names


def test_no_wildcard_is_used(client):
    assert "*" not in exposed(client)


def test_every_x_assurance_header_the_api_sets_is_exposed(client):
    """A new response header added to a route must be added to the list too."""
    emitted = set()
    for path in API_DIR.glob("*.py"):
        emitted |= {m.lower() for m in re.findall(r"X-Assurance-[A-Za-z-]+", path.read_text("utf-8"))}
    assert emitted, "scan found no X-Assurance-* headers; the pattern is stale"
    assert emitted <= exposed(client), sorted(emitted - exposed(client))
