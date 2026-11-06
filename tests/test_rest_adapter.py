"""The REST adapter makes real, bounded HTTP requests (and says so when it cannot).

Every test talks to a real HTTP server started on a free loopback port by this file (``http.server``), so what is
proved is the adapter's behaviour on the wire: the request that arrives, the status that comes back, the limits.
It does not prove anything about any third-party API, TLS certificate handling, or DNS-rebinding resistance.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import structlog

from neuralbridge.adapters.apis.rest import RestApiAdapter
from neuralbridge.adapters.base import AdapterResponse

TOKEN = "tok-SECRET-9f3a1c"
PASSWORD = "pw-SECRET-7d2e"
API_KEY = "key-SECRET-4b8c"


class _Handler(BaseHTTPRequestHandler):
    seen: list[dict] = []
    other_port = 0

    def log_message(self, *a):  # keep test output quiet
        pass

    def _reply(self, status, body=b"", ctype="application/json", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        type(self).seen.append(
            {"method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": raw}
        )
        path = self.path.split("?")[0]
        if path == "/ok":
            self._reply(200, json.dumps({"hello": "world", "method": self.command,
                                         "received": json.loads(raw) if raw else None}).encode())
        elif path == "/text":
            self._reply(200, b"plain words", "text/plain")
        elif path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            self._reply(code, json.dumps({"detail": "x" * 5000}).encode())
        elif path == "/slow":
            time.sleep(1.5)
            self._reply(200, b"{}")
        elif path == "/big":
            self._reply(200, b"A" * (3 * 1024 * 1024), "application/octet-stream")
        elif path == "/reflect":  # a server that echoes the credential it was sent
            self._reply(401, json.dumps({"you_sent": self.headers.get("Authorization")}).encode())
        elif path == "/redirect-same":
            self._reply(302, b"", extra={"Location": "/ok"})
        elif path == "/redirect-other":
            self._reply(302, b"", extra={"Location": f"http://localhost:{type(self).other_port}/ok"})
        elif path == "/redirect-loop":
            self._reply(302, b"", extra={"Location": "/redirect-loop"})
        else:
            self._reply(404, b'{"detail":"nope"}')

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle  # noqa: N815


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return server


@pytest.fixture()
def server():
    handler = type("H", (_Handler,), {"seen": [], "other_port": 0})
    other_handler = type("O", (_Handler,), {"seen": [], "other_port": 0})
    main, other = _serve(handler), _serve(other_handler)
    handler.other_port = other.server_address[1]
    try:
        yield {
            "url": f"http://127.0.0.1:{main.server_address[1]}",
            "seen": handler.seen,
            "other_seen": other_handler.seen,
        }
    finally:
        main.shutdown()
        other.shutdown()
        main.server_close()
        other.server_close()


def _adapter(server, **config) -> RestApiAdapter:
    cfg = {"base_url": server["url"], "allow_private_network": True, "timeout": 5}
    cfg.update(config)
    return RestApiAdapter(cfg)


async def _run(adapter: RestApiAdapter, operation: str, **params) -> AdapterResponse:
    try:
        return await adapter.execute(operation, params)
    finally:
        await adapter.disconnect()


# ── real requests, honest results ───────────────────────────────────────────────────────────────────────────────


def test_class_is_declared_real():
    assert RestApiAdapter.backend == "real"


@pytest.mark.parametrize("op", ["get", "delete", "head"])
def test_bodyless_methods_reach_the_server(server, op):
    result = asyncio.run(_run(_adapter(server), op, endpoint="/ok", query_params={"q": "1"}))
    assert result.success and result.data["status_code"] == 200
    assert [(r["method"], r["path"]) for r in server["seen"]] == [(op.upper(), "/ok?q=1")]


@pytest.mark.parametrize("op", ["post", "put", "patch"])
def test_body_methods_send_the_json_body(server, op):
    result = asyncio.run(_run(_adapter(server), op, endpoint="/ok", json_body={"a": 1}))
    assert result.success and result.data["body"]["received"] == {"a": 1}
    assert server["seen"][0]["method"] == op.upper()
    assert json.loads(server["seen"][0]["body"]) == {"a": 1}


def test_success_returns_the_servers_json_not_canned_data(server):
    result = asyncio.run(_run(_adapter(server), "get", endpoint="/ok"))
    assert result.data["body"] == {"hello": "world", "method": "GET", "received": None}
    assert "mock" not in json.dumps(result.to_dict()).lower()


def test_non_json_body_comes_back_as_text(server):
    result = asyncio.run(_run(_adapter(server), "get", endpoint="/text"))
    assert result.success and result.data["body"] == "plain words"


@pytest.mark.parametrize("code", [400, 401, 404, 500, 503])
def test_error_statuses_are_failures_with_a_truncated_body(server, code):
    result = asyncio.run(_run(_adapter(server), "get", endpoint=f"/status/{code}"))
    assert result.success is False
    assert result.error.startswith("http_error") and str(code) in result.error
    assert result.data["status_code"] == code
    assert 0 < len(result.data["body"]) <= 2048 and result.data["truncated"] is True


def test_unreachable_server_is_a_structured_failure_not_an_exception(server):
    adapter = RestApiAdapter({"base_url": "http://127.0.0.1:1", "allow_private_network": True, "timeout": 2})
    result = asyncio.run(_run(adapter, "get", endpoint="/ok"))
    assert result.success is False and result.error.startswith("connection_failed")


def test_timeout_is_enforced_and_reported(server):
    start = time.monotonic()
    result = asyncio.run(_run(_adapter(server, timeout=0.3), "get", endpoint="/slow"))
    assert time.monotonic() - start < 1.2
    assert result.success is False and result.error.startswith("timeout")


def test_oversized_response_is_cut_off_and_not_success(server):
    result = asyncio.run(_run(_adapter(server, max_response_bytes=10_000), "get", endpoint="/big"))
    assert result.success is False and result.error.startswith("response_too_large")
    assert result.data["truncated"] is True and len(result.data["body"]) <= 2048


def test_response_under_the_cap_is_not_truncated(server):
    result = asyncio.run(_run(_adapter(server, max_response_bytes=4 * 1024 * 1024), "get", endpoint="/big"))
    assert result.success and len(result.data["body"]) == 3 * 1024 * 1024


def test_unknown_operation_is_rejected_before_any_request(server):
    with pytest.raises(ValueError):
        asyncio.run(_run(_adapter(server), "trace", endpoint="/ok"))
    assert server["seen"] == []


def test_missing_endpoint_is_a_structured_failure(server):
    result = asyncio.run(_run(_adapter(server), "get"))
    assert result.success is False and result.error.startswith("invalid_request")
    assert server["seen"] == []


# ── redirects ───────────────────────────────────────────────────────────────────────────────────────────────────


def test_same_origin_redirect_is_followed_for_get(server):
    result = asyncio.run(_run(_adapter(server), "get", endpoint="/redirect-same"))
    assert result.success and result.data["body"]["hello"] == "world"
    assert [r["path"] for r in server["seen"]] == ["/redirect-same", "/ok"]


def test_redirect_to_another_host_is_refused_and_never_requested(server):
    adapter = _adapter(server, auth_type="bearer", credentials={"token": TOKEN})
    result = asyncio.run(_run(adapter, "get", endpoint="/redirect-other"))
    assert result.success is False and result.error.startswith("redirect_refused")
    assert result.data["status_code"] == 302
    assert server["other_seen"] == []  # the second server never saw a request (so never saw the token)


def test_post_redirects_are_not_followed(server):
    result = asyncio.run(_run(_adapter(server), "post", endpoint="/redirect-same", json_body={}))
    assert result.success is False and result.error.startswith("redirect_refused")
    assert [r["path"] for r in server["seen"]] == ["/redirect-same"]


def test_redirect_loop_is_bounded(server):
    result = asyncio.run(_run(_adapter(server), "get", endpoint="/redirect-loop"))
    assert result.success is False and "more than 3 redirects" in result.error
    assert len(server["seen"]) == 4


# ── SSRF ────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_loopback_is_refused_by_default_and_nothing_is_sent(server):
    adapter = RestApiAdapter({"base_url": server["url"], "timeout": 5})  # no allow_private_network
    result = asyncio.run(_run(adapter, "get", endpoint="/ok"))
    assert result.success is False and result.error.startswith("blocked_destination")
    assert server["seen"] == []


@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "10.0.0.5", "192.168.1.1", "172.16.0.9", "[::1]", "[fd00:ec2::254]", "0.0.0.0",
     "[::ffff:127.0.0.1]", "localhost"],
)
def test_private_metadata_and_mapped_addresses_are_refused(host):
    adapter = RestApiAdapter({"base_url": f"http://{host}:9", "timeout": 2})
    result = asyncio.run(_run(adapter, "get", endpoint="/latest/meta-data"))
    assert result.success is False and result.error.startswith("blocked_destination")


def test_allowed_hosts_restricts_even_with_private_opt_in(server):
    with pytest.raises(ValueError):
        asyncio.run(_adapter(server, allowed_hosts=["api.example.com"])._do_connect())
    ok = _adapter(server, allowed_hosts=["127.0.0.1"])
    assert asyncio.run(_run(ok, "get", endpoint="/ok")).success


@pytest.mark.parametrize(
    "endpoint",
    ["http://evil.example/x", "//evil.example/x", "https://127.0.0.1/x", "/a/../../etc", "\\\\evil\\x", "x@evil.example/y"],
)
def test_endpoint_cannot_leave_the_base_url(server, endpoint):
    result = asyncio.run(_run(_adapter(server), "get", endpoint=endpoint))
    assert result.success is False and result.error.startswith("invalid_endpoint")
    assert server["seen"] == []


@pytest.mark.parametrize("base", ["ftp://example.com", "file:///etc/passwd", "example.com", "http://user:pw@example.com"])
def test_only_http_s_and_no_embedded_credentials(base):
    response = asyncio.run(RestApiAdapter({"base_url": base}).connect())
    assert response.success is False


# ── authentication ──────────────────────────────────────────────────────────────────────────────────────────────


def test_bearer_header_is_actually_sent(server):
    adapter = _adapter(server, auth_type="bearer", credentials={"token": TOKEN})
    assert asyncio.run(_run(adapter, "get", endpoint="/ok")).success
    assert server["seen"][0]["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_basic_header_is_actually_sent(server):
    adapter = _adapter(server, auth_type="basic", credentials={"username": "alice", "password": PASSWORD})
    assert asyncio.run(_run(adapter, "get", endpoint="/ok")).success
    sent = server["seen"][0]["headers"]["Authorization"]
    assert sent == "Basic " + base64.b64encode(f"alice:{PASSWORD}".encode()).decode()


def test_api_key_header_is_actually_sent(server):
    adapter = _adapter(server, auth_type="api_key", api_key_header="X-Token", credentials={"api_key": API_KEY})
    assert asyncio.run(_run(adapter, "get", endpoint="/ok")).success
    assert server["seen"][0]["headers"]["X-Token"] == API_KEY
    assert "Authorization" not in server["seen"][0]["headers"]


def test_credentials_can_come_from_the_environment(server, monkeypatch):
    monkeypatch.setenv("TEST_REST_TOKEN", TOKEN)
    adapter = _adapter(server, auth_type="bearer", credentials_env={"token": "TEST_REST_TOKEN"})
    assert asyncio.run(_run(adapter, "get", endpoint="/ok")).success
    assert server["seen"][0]["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_no_auth_sends_no_authorization_and_never_the_old_mock_token(server):
    assert asyncio.run(_run(_adapter(server), "get", endpoint="/ok")).success
    assert "Authorization" not in server["seen"][0]["headers"]
    assert asyncio.run(_run(_adapter(server, auth_type="bearer", credentials={"token": TOKEN}), "get", endpoint="/ok")).success
    assert "MOCK_TOKEN" not in json.dumps(server["seen"], default=str)


@pytest.mark.parametrize("auth_type", ["bearer", "basic", "api_key"])
def test_missing_credentials_fail_at_connect_not_with_a_default(server, auth_type):
    response = asyncio.run(_adapter(server, auth_type=auth_type).connect())
    assert response.success is False and "needs credentials" in response.error


def test_unknown_auth_type_is_refused(server):
    assert asyncio.run(_adapter(server, auth_type="digest").connect()).success is False


def test_configured_headers_are_sent_and_the_config_is_not_mutated(server):
    headers = {"Accept": "application/json", "X-Trace": "t1"}
    adapter = _adapter(server, headers=headers, auth_type="bearer", credentials={"token": TOKEN})
    asyncio.run(_run(adapter, "get", endpoint="/ok"))
    assert server["seen"][0]["headers"]["X-Trace"] == "t1"
    assert headers == {"Accept": "application/json", "X-Trace": "t1"}
    assert "Authorization" not in adapter.config["headers"]


# ── secrets never leak ──────────────────────────────────────────────────────────────────────────────────────────


def test_credentials_are_absent_from_logs_errors_and_returned_data(server, caplog):
    secrets = (TOKEN, PASSWORD, API_KEY)
    caplog.set_level("DEBUG")
    with structlog.testing.capture_logs() as logs:
        for cfg in (
            {"auth_type": "bearer", "credentials": {"token": TOKEN}},
            {"auth_type": "basic", "credentials": {"username": "alice", "password": PASSWORD}},
            {"auth_type": "api_key", "credentials": {"api_key": API_KEY}},
        ):
            results = [
                asyncio.run(_run(_adapter(server, **cfg), "get", endpoint=ep))
                for ep in ("/ok", "/reflect", "/status/500", "/redirect-other", "/missing")
            ]
            results.append(asyncio.run(_run(_adapter(server, **cfg, timeout=0.2), "get", endpoint="/slow")))
            blocked = RestApiAdapter({**{"base_url": server["url"]}, **cfg})
            results.append(asyncio.run(_run(blocked, "get", endpoint="/ok")))  # SSRF refusal path
            for r in results:
                blob = json.dumps(r.to_dict(), default=str)
                assert not any(s in blob for s in secrets), blob
        # ... including a failed connect (bad config) and the reflected-credential response redacted
        failed = asyncio.run(RestApiAdapter({"base_url": "ftp://x", "auth_type": "bearer",
                                             "credentials": {"token": TOKEN}}).connect())
        assert TOKEN not in json.dumps(failed.to_dict(), default=str)
    reflected = asyncio.run(_run(_adapter(server, auth_type="bearer", credentials={"token": TOKEN}), "get", endpoint="/reflect"))
    assert "[REDACTED]" in reflected.data["body"] and TOKEN not in reflected.data["body"]
    everything = json.dumps(logs, default=str) + caplog.text
    assert not any(s in everything for s in secrets)
    assert any(entry.get("event") == "rest_request" for entry in logs)  # the logging we checked did happen


def test_validate_credentials(server):
    ok = _adapter(server, auth_type="bearer", credentials={"token": TOKEN}, validate_path="/ok")
    result = asyncio.run(_validate(ok))
    assert result.success and result.data["status"] == "ok"
    rejected = _adapter(server, auth_type="bearer", credentials={"token": TOKEN}, validate_path="/status/401")
    result = asyncio.run(_validate(rejected))
    assert result.success is False and "401" in result.error and TOKEN not in result.error
    unknown = _adapter(server, validate_path="/status/404")
    result = asyncio.run(_validate(unknown))
    assert result.success and result.data["status"] == "unchecked"  # reachable, nothing confirmed
    down = RestApiAdapter({"base_url": "http://127.0.0.1:1", "allow_private_network": True, "timeout": 1})
    assert asyncio.run(_validate(down)).success is False


async def _validate(adapter: RestApiAdapter) -> AdapterResponse:
    try:
        await adapter.connect()
        return await adapter.validate_credentials()
    finally:
        await adapter.disconnect()
