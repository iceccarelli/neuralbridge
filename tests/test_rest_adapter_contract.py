"""REST adapter contract tests against a deterministic LOCAL fixture service.

LOCAL integration evidence only. ``tests/rest_fixture_server.py`` models behaviours real APIs
have (auth schemes, 401/403/404/429 with Retry-After, 5xx, slow and trickling responses,
truncated / oversized / chunked / gzip bodies, redirects, cursor pagination, TLS with a
locally generated self-signed certificate). That the adapter does the right thing against that
model is what is proved here. It is NOT third-party production validation: no vendor API, no
real certificate chain, no real rate-limit policy, no DNS is involved.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from neuralbridge.adapters.apis.rest import RestApiAdapter
from neuralbridge.adapters.base import AdapterResponse

from .rest_fixture_server import (
    API_KEY,
    BASIC,
    BEARER,
    PAGE_SIZE,
    TOTAL_ITEMS,
    FixtureService,
    make_self_signed,
)


@pytest.fixture
def fx():
    service = FixtureService()
    yield service
    service.close()


def make(fx_or_url, **config) -> RestApiAdapter:
    url = fx_or_url if isinstance(fx_or_url, str) else fx_or_url.url
    cfg = {"base_url": url, "allow_private_network": True, "timeout": 5}
    cfg.update(config)
    adapter = RestApiAdapter(cfg)
    adapter.sleeps = []  # type: ignore[attr-defined]

    async def record_sleep(seconds: float) -> None:  # no real waiting, but exactly what would have been waited
        adapter.sleeps.append(round(seconds, 3))  # type: ignore[attr-defined]

    adapter._sleep = record_sleep  # type: ignore[assignment]
    return adapter


async def go(adapter: RestApiAdapter, operation: str, endpoint: str = "/echo", **params) -> AdapterResponse:
    try:
        return await adapter.execute(operation, {"endpoint": endpoint, **params})
    finally:
        await adapter.disconnect()


def run(adapter, operation, endpoint="/echo", **params) -> AdapterResponse:
    return asyncio.run(go(adapter, operation, endpoint, **params))


# ───────────────────────────── auth schemes ─────────────────────────────


class TestAuthSchemes:
    def test_bearer(self, fx) -> None:
        ok = run(make(fx, auth_type="bearer", credentials={"token": BEARER}), "get", "/auth/bearer")
        assert ok.success and ok.data["body"] == {"authenticated": True}
        bad = run(make(fx, auth_type="bearer", credentials={"token": "wrong"}), "get", "/auth/bearer")
        assert not bad.success and bad.data["status_code"] == 401 and bad.error.startswith("http_error")

    def test_basic(self, fx) -> None:
        creds = {"username": BASIC[0], "password": BASIC[1]}
        assert run(make(fx, auth_type="basic", credentials=creds), "get", "/auth/basic").success
        wrong = run(make(fx, auth_type="basic", credentials={**creds, "password": "nope"}), "get", "/auth/basic")
        assert wrong.data["status_code"] == 401

    def test_api_key_in_a_custom_header(self, fx) -> None:
        cfg = {"auth_type": "api_key", "api_key_header": "X-Custom-Key", "credentials": {"api_key": API_KEY}}
        ok = run(make(fx, **cfg), "get", "/auth/api-key", query_params={"header": "X-Custom-Key"})
        assert ok.success
        assert run(make(fx, auth_type="api_key", credentials={"api_key": "no"}), "get", "/auth/api-key").data[
            "status_code"] == 401

    def test_authenticated_but_forbidden_is_403_not_401(self, fx) -> None:
        r = run(make(fx, auth_type="bearer", credentials={"token": "scope-denied"}), "get", "/auth/bearer")
        assert not r.success and r.data["status_code"] == 403

    def test_secrets_the_server_echoes_back_are_redacted(self, fx) -> None:
        r = run(make(fx, auth_type="bearer", credentials={"token": BEARER}), "get", "/reflect")
        assert r.success and BEARER not in str(r.data) and "[REDACTED]" in r.data["body"]["authorization"]
        b = run(make(fx, auth_type="basic", credentials={"username": BASIC[0], "password": BASIC[1]}), "get", "/reflect")
        assert BASIC[1] not in str(b.data)
        k = run(make(fx, auth_type="api_key", credentials={"api_key": API_KEY}), "get", "/reflect")
        assert API_KEY not in str(k.data)


# ───────────────────────────── status codes ─────────────────────────────


class TestStatusCodes:
    @pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504])
    def test_every_non_2xx_is_a_failure_with_the_status_and_a_bounded_body(self, fx, code: int) -> None:
        r = run(make(fx), "get", f"/status/{code}")
        assert r.success is False and r.error.startswith("http_error")
        assert r.data["status_code"] == code and len(r.data["body"]) <= 2048
        assert fx.state.count("/status/") == 1, "no retry unless configured"

    def test_429_exposes_retry_after_to_the_caller(self, fx) -> None:
        r = run(make(fx), "get", "/status/429", query_params={"retry_after": "7"})
        assert r.data["status_code"] == 429 and r.data["headers"]["retry-after"] == "7"

    def test_204_no_content_is_success_with_an_empty_body(self, fx) -> None:
        r = run(make(fx), "get", "/no-content")
        assert r.success and r.data["status_code"] == 204 and r.data["body"] == ""

    def test_json_content_type_with_invalid_json_is_returned_as_text(self, fx) -> None:
        r = run(make(fx), "get", "/bad-json")
        assert r.success and r.data["body"] == "{not json"

    def test_declared_charset_is_honoured(self, fx) -> None:
        assert run(make(fx), "get", "/latin1").data["body"] == "café"

    def test_methods_carry_their_bodies(self, fx) -> None:
        for method in ("post", "put", "patch"):
            r = run(make(fx), method, "/echo", json_body={"n": 1})
            assert r.success and r.data["body"]["method"] == method.upper() and r.data["body"]["body"] == {"n": 1}
        assert run(make(fx), "delete", "/echo").data["body"]["method"] == "DELETE"
        head = run(make(fx), "head", "/echo")
        assert head.success and head.data["body"] == ""


# ───────────────────────────── slow, truncated, oversized, chunked, gzip ─────────────────────────────


class TestBodiesAndTiming:
    def test_a_slow_response_times_out_instead_of_hanging(self, fx) -> None:
        started = time.monotonic()
        r = run(make(fx, timeout=0.5), "get", "/slow", query_params={"delay": "5"})
        assert r.success is False and r.error.startswith("timeout") and time.monotonic() - started < 3

    def test_a_trickling_body_hits_the_overall_deadline(self, fx) -> None:
        started = time.monotonic()
        r = run(make(fx, timeout=0.6), "get", "/trickle", query_params={"n": "200", "interval": "0.2"})
        assert r.success is False and r.error.startswith("timeout") and time.monotonic() - started < 3

    def test_a_body_shorter_than_declared_is_a_failure_not_a_success(self, fx) -> None:
        r = run(make(fx), "get", "/truncated")
        assert r.success is False and r.error.startswith("connection_failed")

    def test_oversized_with_content_length_is_refused_without_reading_it(self, fx) -> None:
        r = run(make(fx, max_response_bytes=100_000), "get", "/big", query_params={"bytes": "2000000"})
        assert not r.success and r.error.startswith("response_too_large") and r.data["truncated"] is True
        assert len(r.data["body"]) <= 2048

    def test_oversized_chunked_without_content_length_is_cut_off(self, fx) -> None:
        r = run(make(fx, max_response_bytes=100_000), "get", "/big-chunked", query_params={"bytes": "2000000"})
        assert not r.success and r.error.startswith("response_too_large")

    def test_a_body_under_the_cap_is_complete(self, fx) -> None:
        r = run(make(fx, max_response_bytes=100_000), "get", "/big", query_params={"bytes": "50000"})
        assert r.success and len(r.data["body"]) == 50_000

    def test_small_chunked_responses_are_reassembled(self, fx) -> None:
        r = run(make(fx), "get", "/chunked")
        assert r.success and r.data["body"] == {"chunked": True, "n": 3}

    def test_gzip_is_decoded(self, fx) -> None:
        r = run(make(fx), "get", "/gzip")
        assert r.success and r.data["body"]["compressed"] is True

    def test_a_gzip_bomb_is_bounded_by_the_decoded_size(self, fx) -> None:
        started = time.monotonic()
        r = run(make(fx, max_response_bytes=1_000_000), "get", "/gzip-bomb", query_params={"bytes": "50000000"})
        assert not r.success and r.error.startswith("response_too_large")
        assert len(r.data["body"]) <= 2048 and time.monotonic() - started < 5


# ───────────────────────────── redirects ─────────────────────────────


class TestRedirects:
    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    def test_same_origin_get_redirects_are_followed(self, fx, code: int) -> None:
        r = run(make(fx), "get", "/redirect", query_params={"code": str(code), "to": "/echo?hop=1"})
        assert r.success and r.data["body"]["path"] == "/echo" and r.data["body"]["query"] == {"hop": "1"}

    def test_another_origin_is_never_followed_and_gets_no_credentials(self, fx) -> None:
        r = run(make(fx, auth_type="bearer", credentials={"token": BEARER}), "get", "/redirect-other-origin")
        assert not r.success and r.error.startswith("redirect_refused")
        assert fx.other_state.requests == [], "the credential was sent to a different origin"

    def test_a_post_redirect_is_not_followed(self, fx) -> None:
        r = run(make(fx), "post", "/redirect", json_body={"a": 1}, query_params={"code": "307"})
        assert not r.success and r.error.startswith("redirect_refused")
        assert fx.state.count("/echo") == 0

    def test_a_redirect_loop_is_bounded(self, fx) -> None:
        r = run(make(fx), "get", "/loop")
        assert not r.success and r.error.startswith("redirect_refused") and fx.state.count("/loop") == 4


# ───────────────────────────── pagination-style JSON ─────────────────────────────


class TestPagination:
    def test_cursor_pagination_is_caller_driven_and_complete(self, fx) -> None:
        async def walk() -> tuple[list[int], int, dict]:
            adapter = make(fx)
            items, cursor, pages, first_headers = [], None, 0, {}
            try:
                while True:
                    params = {"cursor": str(cursor)} if cursor is not None else {}
                    r = await adapter.execute("get", {"endpoint": "/pages", "query_params": params})
                    assert r.success
                    pages += 1
                    first_headers = first_headers or r.data["headers"]
                    items += r.data["body"]["items"]
                    cursor = r.data["body"]["next_cursor"]
                    if cursor is None:
                        return items, pages, first_headers
            finally:
                await adapter.disconnect()

        items, pages, first_headers = asyncio.run(walk())
        assert items == list(range(TOTAL_ITEMS)) and pages == -(-TOTAL_ITEMS // PAGE_SIZE)
        # the headers pagination APIs actually use are passed through
        assert 'rel="next"' in first_headers["link"] and first_headers["x-total-count"] == str(TOTAL_ITEMS)


# ───────────────────────────── TLS (locally generated certificates) ─────────────────────────────


@pytest.fixture
def tls(tmp_path):
    cert, key = make_self_signed(tmp_path)
    service = FixtureService(tls=(cert, key))
    yield service, cert, tmp_path
    service.close()


class TestTls:
    def test_an_untrusted_self_signed_certificate_is_refused_by_default_and_no_request_is_sent(self, tls) -> None:
        service, _cert, _ = tls
        r = run(make(service, auth_type="bearer", credentials={"token": BEARER}), "get", "/echo")
        assert r.success is False and r.error.startswith("connection_failed")
        assert service.state.requests == [], "a request (and its credential) went out over an unverified channel"

    def test_verify_ssl_true_explicitly_is_the_same(self, tls) -> None:
        service, _cert, _ = tls
        assert not run(make(service, verify_ssl=True), "get", "/echo").success

    def test_a_certificate_failure_is_not_retried(self, tls) -> None:
        service, _cert, _ = tls
        adapter = make(service, retry={"max_attempts": 4, "backoff_base": 0.1})
        r = run(adapter, "get", "/echo")
        assert not r.success and r.error.startswith("connection_failed")
        assert adapter.sleeps == [] and "attempts" not in r.data

    def test_verify_ssl_false_accepts_the_self_signed_certificate(self, tls) -> None:
        service, _cert, _ = tls
        r = run(make(service, verify_ssl=False), "get", "/echo")
        assert r.success and r.data["body"]["path"] == "/echo"
        assert service.state.count("/echo") == 1

    def test_a_pinned_ca_certificate_verifies_the_server(self, tls) -> None:
        service, cert, _ = tls
        r = run(make(service, ca_cert_path=str(cert)), "get", "/echo")
        assert r.success and r.data["body"]["path"] == "/echo"

    def test_a_pinned_ca_does_not_excuse_a_hostname_mismatch(self, tmp_path) -> None:
        cert, key = make_self_signed(tmp_path, ips=("192.0.2.77",), dns=("elsewhere.example",), common_name="wrong")
        service = FixtureService(tls=(cert, key))
        try:
            r = run(make(service, ca_cert_path=str(cert)), "get", "/echo")
            assert not r.success and r.error.startswith("connection_failed")
            assert service.state.requests == []
        finally:
            service.close()

    def test_a_different_ca_is_not_trusted(self, tls, tmp_path) -> None:
        service, _cert, _ = tls
        other, _ = make_self_signed(tmp_path, common_name="someone-else")
        assert not run(make(service, ca_cert_path=str(other)), "get", "/echo").success

    def test_a_missing_or_garbage_ca_file_fails_at_connect_with_a_clear_message(self, tls, tmp_path) -> None:
        service, _cert, _ = tls
        junk = tmp_path / "junk.pem"
        junk.write_text("not a certificate")
        for path in (str(tmp_path / "absent.pem"), str(junk)):
            adapter = make(service, ca_cert_path=path)
            outcome = asyncio.run(adapter.connect())
            assert outcome.success is False and "ca_cert_path" in outcome.error

    def test_verify_ssl_false_together_with_a_pinned_ca_is_rejected_as_contradictory(self, tls) -> None:
        service, cert, _ = tls
        outcome = asyncio.run(make(service, verify_ssl=False, ca_cert_path=str(cert)).connect())
        assert outcome.success is False and "verify_ssl" in outcome.error


# ───────────────────────────── documented retry semantics ─────────────────────────────


RETRY = {"max_attempts": 3, "backoff_base": 0.1, "backoff_jitter": 0}


class TestRetrySemantics:
    def test_off_by_default_exactly_one_request(self, fx) -> None:
        r = run(make(fx), "get", "/flaky", query_params={"key": "d", "fail": "5"})
        assert not r.success and fx.state.count("/flaky") == 1

    def test_a_transient_failure_is_retried_and_succeeds(self, fx) -> None:
        adapter = make(fx, retry=RETRY)
        r = run(adapter, "get", "/flaky", query_params={"key": "a", "fail": "2"})
        assert r.success and r.data["body"]["attempt"] == 3 and r.metadata["attempts"] == 3
        assert fx.state.count("/flaky") == 3 and adapter.sleeps == [0.1, 0.2]  # exponential, no jitter

    def test_retries_are_bounded(self, fx) -> None:
        r = run(make(fx, retry=RETRY), "get", "/flaky", query_params={"key": "b", "fail": "99"})
        assert not r.success and r.error.startswith("http_error")
        assert fx.state.count("/flaky") == 3 and r.data["attempts"] == 3

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    def test_the_default_retryable_statuses(self, fx, status: int) -> None:
        r = run(make(fx, retry=RETRY), "get", "/flaky", query_params={"key": f"s{status}", "fail": "1", "status": str(status)})
        assert r.success and r.metadata["attempts"] == 2

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
    def test_client_errors_are_never_retried(self, fx, status: int) -> None:
        r = run(make(fx, retry=RETRY), "get", "/flaky", query_params={"key": f"c{status}", "fail": "9", "status": str(status)})
        assert not r.success and fx.state.count("/flaky") == 1

    @pytest.mark.parametrize("method", ["post", "patch"])
    def test_non_idempotent_methods_are_never_retried(self, fx, method: str) -> None:
        r = run(make(fx, retry=RETRY), method, "/flaky", json_body={"x": 1}, query_params={"key": method, "fail": "9"})
        assert not r.success and fx.state.count("/flaky") == 1

    def test_put_and_delete_retry_only_when_the_operator_opts_in(self, fx) -> None:
        for method in ("put", "delete"):
            r = run(make(fx, retry=RETRY), method, "/flaky", query_params={"key": f"n{method}", "fail": "1"})
            assert not r.success, f"{method} retried without opt-in"
            r = run(make(fx, retry={**RETRY, "methods": ["get", "head", "put", "delete"]}), method, "/flaky",
                    query_params={"key": f"y{method}", "fail": "1"})
            assert r.success and r.metadata["attempts"] == 2

    def test_post_cannot_be_enabled_for_retry(self, fx) -> None:
        outcome = asyncio.run(make(fx, retry={**RETRY, "methods": ["get", "post"]}).connect())
        assert outcome.success is False and "idempotent" in outcome.error

    def test_out_of_range_retry_settings_are_rejected(self, fx) -> None:
        for bad in ({"max_attempts": 50}, {"max_attempts": 0}, {"retry_on_status": [404]}, {"backoff_base": -1},
                    {"max_retry_after": 100000}):
            outcome = asyncio.run(make(fx, retry={**RETRY, **bad}).connect())
            assert outcome.success is False, bad

    def test_retry_after_seconds_is_honoured(self, fx) -> None:
        adapter = make(fx, retry=RETRY, timeout=30)
        r = run(adapter, "get", "/flaky", query_params={"key": "ra", "fail": "1", "status": "429", "retry_after": "4"})
        assert r.success and adapter.sleeps == [4.0]

    def test_retry_after_http_date_is_honoured(self, fx) -> None:
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        when = format_datetime(datetime.now(UTC) + timedelta(seconds=6), usegmt=True)
        adapter = make(fx, retry=RETRY, timeout=30)
        r = run(adapter, "get", "/flaky", query_params={"key": "rd", "fail": "1", "status": "503", "retry_after": when})
        assert r.success and 4.0 <= adapter.sleeps[0] <= 6.5

    def test_a_retry_after_beyond_the_cap_is_not_waited_for(self, fx) -> None:
        adapter = make(fx, retry={**RETRY, "max_retry_after": 5})
        r = run(adapter, "get", "/flaky", query_params={"key": "big", "fail": "9", "status": "429", "retry_after": "120"})
        assert not r.success and fx.state.count("/flaky") == 1 and adapter.sleeps == []
        assert r.data["retry"] == "retry_after_exceeds_cap" and r.data["headers"]["retry-after"] == "120"

    def test_the_overall_deadline_bounds_retrying(self, fx) -> None:
        adapter = make(fx, timeout=2, retry={**RETRY, "max_retry_after": 30})
        r = run(adapter, "get", "/flaky", query_params={"key": "dl", "fail": "9", "status": "503", "retry_after": "10"})
        assert not r.success and r.data["retry"] == "retry_budget_exhausted" and fx.state.count("/flaky") == 1

    def test_connection_failures_are_retried_for_idempotent_methods_only(self) -> None:
        dead = "http://127.0.0.1:1"  # nothing listens
        adapter = make(dead, retry=RETRY)
        r = run(adapter, "get")
        assert not r.success and r.error.startswith("connection_failed") and r.data["attempts"] == 3
        assert len(adapter.sleeps) == 2
        post = make(dead, retry=RETRY)
        r2 = run(post, "post", json_body={})
        assert r2.data.get("attempts", 1) == 1 and post.sleeps == []

    def test_a_retried_failure_still_carries_no_secret(self, fx) -> None:
        r = run(make(fx, retry=RETRY, auth_type="bearer", credentials={"token": BEARER}), "get", "/flaky",
                query_params={"key": "sec", "fail": "99"})
        assert BEARER not in str(r.data) and BEARER not in str(r.error)
