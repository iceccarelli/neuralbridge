"""GET /v1/supplier/feed/{id} (anonymous) validates the id before touching the filesystem (#87)."""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_SUPPLIER_FEEDS", str(tmp_path / "supplier-feeds"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_do_not_ship")
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    (tmp_path / "supplier-feeds").mkdir()
    (tmp_path / "secret.jsonl").write_text("SECRET")
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app(), raise_server_exceptions=False) as c:
        yield c, tmp_path


@pytest.mark.parametrize("n", [129, 250, 255, 256, 600, 5000])
def test_overlong_id_is_a_4xx_not_a_500(client, n):
    c, _ = client
    r = c.get(f"/v1/supplier/feed/{'a' * n}")
    assert 400 <= r.status_code < 500
    assert r.json()["detail"]["error"] == "invalid_feed_id"


@pytest.mark.parametrize("raw", ["..%2f..%2fsecret", "%2e%2e%2fsecret", "a%00b", "a%5cb", "..",
                                 "a%2fb", "%2e", "a%20b", "a%0ab", "%C3%A4", "x:y"])
def test_traversal_and_odd_ids_stay_4xx_and_leak_nothing(client, raw):
    c, _ = client
    r = c.get(f"/v1/supplier/feed/{raw}")
    assert 400 <= r.status_code < 500 and "SECRET" not in r.text


def test_a_valid_id_still_serves_and_a_missing_one_is_404(client):
    c, tmp = client
    (tmp / "supplier-feeds" / "acc_1.jsonl").write_text('{"a":1}\n')
    ok = c.get("/v1/supplier/feed/acc_1")
    assert ok.status_code == 200 and ok.text == '{"a":1}\n'
    assert c.get("/v1/supplier/feed/acc_2").status_code == 404
    assert c.get(f"/v1/supplier/feed/{'a' * 128}").status_code == 404
