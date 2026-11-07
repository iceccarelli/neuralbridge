"""A 422 must not echo the request back.

pydantic puts the offending ``input`` in every validation error. FastAPI returned it
verbatim, so an authenticated caller posting a ~10 MB array to ``/v1/machine/verify``
received a ~40 MB 422 after ~11 s of server work -- a response amplified four times and
paid for with the process's CPU. The handler keeps what a client needs to fix its request
(``loc``, ``msg``, ``type``), drops the echoed ``input``/``ctx``, and caps how many errors
(and how long each ``msg``/``loc``) are returned.
"""

from __future__ import annotations

import json

from assurance.api.deps import MAX_VALIDATION_ERRORS

from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store

client, store = _client, _store


def _post(client, headers, raw: bytes):
    return client.post("/v1/machine/verify", content=raw,
                       headers={**headers, "content-type": "application/json"})


def test_422_does_not_echo_a_large_input(client, store):
    headers = keyed(store, "cell")
    raw = b'{"a":[' + b"1," * 1_000_000 + b"1]}"  # ~2 MB, envelope/trace missing, extra key
    r = _post(client, headers, raw)
    assert r.status_code == 422
    assert len(r.content) < 4_000, f"{len(r.content)} bytes echoed for a {len(raw)}-byte request"
    errors = r.json()["detail"]
    assert errors and all({"loc", "msg", "type"} <= set(e) for e in errors)
    assert all("input" not in e and "ctx" not in e for e in errors)
    assert {tuple(e["loc"]) for e in errors} >= {("body", "envelope"), ("body", "trace")}


def test_422_error_count_and_text_are_capped(client, store):
    headers = keyed(store, "cell")
    obj = {f"k{i}": 1 for i in range(500)}  # 500 forbidden extra keys -> 500 raw errors
    r = _post(client, headers, json.dumps(obj).encode())
    assert r.status_code == 422
    body = r.json()
    assert len(body["detail"]) <= MAX_VALIDATION_ERRORS
    assert body["errors_omitted"] >= 500 - MAX_VALIDATION_ERRORS
    assert len(r.content) < 20_000


def test_long_loc_and_msg_are_truncated(client, store):
    headers = keyed(store, "cell")
    key = "x" * 100_000
    r = _post(client, headers, json.dumps({key: 1}).encode())
    assert r.status_code == 422
    assert len(r.content) < 4_000


def test_small_422_keeps_its_contract(client, store):
    headers = keyed(store, "cell")
    r = client.post("/v1/machine/verify", json={"envelope": {}}, headers=headers)
    assert r.status_code == 422
    body = r.json()
    assert "errors_omitted" not in body
    e = next(e for e in body["detail"] if e["loc"] == ["body", "trace"])
    assert e["type"] == "missing" and e["msg"]
