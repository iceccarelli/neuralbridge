"""The JSON depth cap could be walked around three ways; each was an anonymous or cheap 500.

* a UTF-16 / UTF-32 body: the cap reads bytes, an escaped quote misaligns its tokenizer on
  two-byte characters, and ``json.loads(bytes)`` detects the encoding and recurses anyway;
* a body that is not labelled JSON, with an ``Idempotency-Key``: the request fingerprint
  parsed it regardless and caught only ``ValueError``;
* ``/v1/machine/verify`` (32 MiB allowance, too large to scan on the event loop): a deep
  body from an authenticated caller reached the parser unchecked.
"""

from __future__ import annotations

import importlib
import json
import logging

import pytest
from fastapi.testclient import TestClient

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    checkout_event,
    collect_key,
    send,
)

DEEP = 3000
#: the body from the review: an escaped quote first, then nesting the byte tokenizer misses
HIDDEN = '["\\"",' + "[" * DEEP + "]" * DEEP + ',"x"]'


@pytest.fixture()
def quiet_client(billing_env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app(), raise_server_exceptions=False) as c:
        yield c


def _clean(r, caplog):
    assert "RecursionError" not in caplog.text and "Traceback" not in caplog.text
    assert "traceback" not in r.text.lower()


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_a_utf16_or_utf32_body_cannot_hide_its_nesting(quiet_client, caplog, encoding):
    with caplog.at_level(logging.DEBUG):
        r = quiet_client.post("/v1/spec/validate", content=HIDDEN.encode(encoding),
                              headers={"content-type": "application/json"})
    assert 400 <= r.status_code < 500, (encoding, r.status_code, r.text[:80])
    _clean(r, caplog)


def test_a_utf8_body_with_a_byte_order_mark_is_still_read(quiet_client):
    body = b"\xef\xbb\xbf" + json.dumps({"track": "x", "stage": "y", "payload": {}}).encode()
    r = quiet_client.post("/v1/spec/validate", content=body,
                          headers={"content-type": "application/json"})
    assert r.status_code == 422 and "utf" not in r.text.lower()   # a schema error, not encoding


def test_a_non_ascii_utf8_body_is_still_read(quiet_client):
    body = json.dumps({"track": "x", "stage": "y", "payload": {"title": "Stoßdämpfer ✓"}},
                      ensure_ascii=False).encode("utf-8")
    r = quiet_client.post("/v1/spec/validate", content=body,
                          headers={"content-type": "application/json"})
    assert r.status_code == 422 and "utf" not in r.text.lower()


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", ""])
def test_a_deep_body_with_an_idempotency_key_and_no_json_type_is_not_a_500(
        quiet_client, caplog, content_type):
    headers = {"Idempotency-Key": "abc12345"}
    if content_type:
        headers["content-type"] = content_type
    with caplog.at_level(logging.DEBUG):
        r = quiet_client.post("/v1/spec/validate", content=b"[" * 200_000, headers=headers)
    assert r.status_code < 500, (r.status_code, r.text[:80])
    _clean(r, caplog)


def test_a_deep_body_to_machine_verify_from_an_authenticated_caller_is_not_a_500(
        quiet_client, caplog):
    assert send(quiet_client, checkout_event("cs_1", "cus_1", "sub_1", "cell", T)).status_code == 200
    key = collect_key(quiet_client, "cs_1")
    with caplog.at_level(logging.DEBUG):
        r = quiet_client.post("/v1/machine/verify", content=("[" * DEEP + "]" * DEEP).encode(),
                              headers={"content-type": "application/json", "X-API-Key": key})
        shallow = quiet_client.post("/v1/machine/verify", content=b"[[]]",
                                    headers={"content-type": "application/json",
                                             "X-API-Key": key})
    assert r.status_code == shallow.status_code == 422, (r.status_code, shallow.status_code)
    assert "nest" in r.text.lower()
    _clean(r, caplog)


def test_a_deep_body_to_the_evidence_verifier_is_still_analysed_not_refused(quiet_client):
    """The anonymous evidence verifier analyses hostile nesting on purpose (older tests)."""
    r = quiet_client.post("/v1/evidence/verify", content=("[" * DEEP + "]" * DEEP).encode(),
                          headers={"content-type": "application/json"})
    assert "json_too_deeply_nested" not in r.text and r.status_code < 500


@pytest.mark.parametrize("field", ["envelope", "trace"])
def test_a_deep_object_inside_a_well_formed_trace_request_is_a_422_too(quiet_client, caplog, field):
    assert send(quiet_client, checkout_event("cs_1", "cus_1", "sub_1", "cell", T)).status_code == 200
    key = collect_key(quiet_client, "cs_1")
    deep = '{"a":' * DEEP + "1" + "}" * DEEP
    other = '{"samples": []}' if field == "envelope" else "{}"
    partner = "trace" if field == "envelope" else "envelope"
    body = f'{{"{field}": {deep}, "{partner}": {other}}}'
    with caplog.at_level(logging.DEBUG):
        r = quiet_client.post("/v1/machine/verify", content=body.encode(),
                              headers={"content-type": "application/json", "X-API-Key": key})
    assert r.status_code == 422 and "nest" in r.text.lower(), (r.status_code, r.text[:100])
    _clean(r, caplog)
