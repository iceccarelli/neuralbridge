"""Supplier feed fetching under the outbound policy (issue #86).

Every network test talks to a loopback listener started here that records what it receives.
Nothing contacts the internet: public-looking names are resolved by an injected resolver and
never connected to (a MockTransport stands in for the wire where a connection would be made).
"""

from __future__ import annotations

import gzip
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from assurance.supplier import cli as supplier_cli
from assurance.supplier.netpolicy import FetchRefusedError, address_problem, safe_fetch, url_problem
from assurance.supplier.publish import FeedFetchError, PublishError, fetch_feed

FEED = '{"format": "x"}\n'


@contextmanager
def serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


@contextmanager
def listener(reply):
    """Loopback HTTP server; ``reply(handler) -> (status, body, headers)``."""
    seen: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append({"path": self.path,
                         "headers": {k.lower(): v for k, v in self.headers.items()}})
            status, body, headers = reply(self)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            if "content-length" not in {k.lower() for k in headers}:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *a):
            pass

    with serve(H) as port:
        yield port, seen


def ok(body=FEED.encode(), headers=None):
    return lambda h: (200, body, headers or {})


# ----------------------------------------------------------------------------- address policy
@pytest.mark.parametrize("addr", [
    "127.0.0.1", "::1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254",
    "169.254.1.1", "fd00:ec2::254", "fe80::1", "fc00::1", "0.0.0.0", "::", "224.0.0.1",
    "ff02::1", "100.64.0.1", "100.100.100.200", "192.0.0.192", "240.0.0.1", "255.255.255.255",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1",
    "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "198.18.0.1", "192.0.2.1",
])
def test_non_public_addresses_are_refused(addr):
    assert address_problem(addr) is not None


@pytest.mark.parametrize("addr", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_pass(addr):
    assert address_problem(addr) is None


def test_loopback_allowance_does_not_cover_private_or_mapped_private():
    assert address_problem("127.0.0.1", allow_loopback=True) is None
    assert address_problem("::1", allow_loopback=True) is None
    assert address_problem("::ffff:127.0.0.1", allow_loopback=True) is None
    for a in ("10.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "fd00:ec2::254"):
        assert address_problem(a, allow_loopback=True) is not None


@pytest.mark.parametrize("url,reason", [
    ("ftp://example.com/x", "bad_scheme"), ("file:///etc/passwd", "bad_scheme"),
    ("//host/x", "bad_scheme"), ("", "bad_scheme"),
    ("http://example.com/x", "plain_http"), ("http://127.0.0.2/x", "plain_http"),
    ("https://u:p@example.com/x", "credentials_in_url"),
    ("https://u@example.com/x", "credentials_in_url"),
    ("https://example.com/x?a=1", "query_in_url"), ("https://example.com/x#f", "query_in_url"),
    ("https://example.com:99999/x", "bad_url"), ("https://[::1/x", "bad_url"),
    ("https://example.com/a b", "bad_url"),
])
def test_url_shape_refusals(url, reason):
    assert url_problem(url)[0] == reason


@pytest.mark.parametrize("url", ["https://example.com/v1/supplier/feed/acc_1",
                                 "http://localhost:8000/v1/x", "http://127.0.0.1/x",
                                 "http://[::1]:8000/x"])
def test_url_shape_accepts(url):
    assert url_problem(url) is None


# ----------------------------------------------------------------------------- fetch behaviour
def test_loopback_http_fetch_works_and_sends_no_credentials():
    with listener(ok()) as (port, seen):
        assert fetch_feed(f"http://127.0.0.1:{port}/v1/supplier/feed/acc_1") == FEED
    assert len(seen) == 1
    assert "authorization" not in seen[0]["headers"] and "x-api-key" not in seen[0]["headers"]


def test_credentials_in_url_are_refused_before_any_connection():
    with listener(ok()) as (port, seen), pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://user:pw@127.0.0.1:{port}/x")
    assert e.value.reason == "credentials_in_url" and seen == []
    assert "pw" not in str(e.value)


def test_plain_http_to_non_loopback_is_refused_and_nothing_is_sent():
    with listener(ok()) as (port, seen), pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.2:{port}/x")
    assert e.value.reason == "plain_http" and seen == []


@pytest.mark.parametrize("ip", ["10.1.2.3", "169.254.169.254", "fd00:ec2::254", "::ffff:10.0.0.1",
                                "127.0.0.1", "::1", "0.0.0.0"])
def test_hostname_resolving_to_a_blocked_address_is_refused(ip):
    calls = []

    def resolver(host, port):
        calls.append(host)
        return [ip]

    with pytest.raises(FeedFetchError) as e:
        fetch_feed("https://feeds.vendor.example/v1/supplier/feed/a", _resolver=resolver)
    assert e.value.reason == "blocked_address" and calls == ["feeds.vendor.example"]


def test_one_blocked_answer_among_public_ones_refuses_the_whole_name():
    with pytest.raises(FeedFetchError) as e:
        fetch_feed("https://feeds.vendor.example/x",
                   _resolver=lambda h, p: ["93.184.216.34", "10.0.0.9"])
    assert e.value.reason == "blocked_address"


def test_https_to_a_name_that_resolves_to_loopback_is_refused_even_with_a_listener():
    with listener(ok()) as (port, seen), pytest.raises(FeedFetchError):
        fetch_feed(f"https://localhost:{port}/x", _resolver=lambda h, p: ["127.0.0.1"])
    assert seen == []


def test_literal_ip_hosts_are_checked_without_dns():
    def boom(h, p):
        raise AssertionError("no DNS for a literal")

    with pytest.raises(FeedFetchError) as e:
        fetch_feed("https://10.0.0.1/x", _resolver=boom)
    assert e.value.reason == "blocked_address"
    with pytest.raises(FeedFetchError):
        fetch_feed("https://[::ffff:169.254.169.254]/x", _resolver=boom)


def test_connection_is_pinned_to_the_validated_address_and_keeps_host():
    calls = []

    def resolver(host, port):
        calls.append(host)
        return ["127.0.0.1"]   # a second lookup would be free to answer differently

    with listener(ok()) as (port, seen):
        assert fetch_feed(f"http://localhost:{port}/v1/x", _resolver=resolver) == FEED
    assert calls == ["localhost"], "the name was resolved more than once"
    assert seen[0]["headers"]["host"] == f"localhost:{port}"


def test_https_request_is_pinned_with_sni_and_host_of_the_original_name():
    captured = {}

    def handler(request: httpx.Request):
        captured.update(host=request.url.host, port=request.url.port,
                        hdr=request.headers["host"],
                        sni=request.extensions.get("sni_hostname"))
        return httpx.Response(200, stream=httpx.ByteStream(FEED.encode()))

    text = fetch_feed("https://feeds.vendor.example/v1/supplier/feed/a",
                      _resolver=lambda h, p: ["93.184.216.34"],
                      _transport=httpx.MockTransport(handler))
    assert text == FEED
    assert captured == {"host": "93.184.216.34", "port": None, "hdr": "feeds.vendor.example",
                        "sni": "feeds.vendor.example"}


def test_ipv6_https_is_pinned_in_brackets():
    seen = {}

    def handler(request):
        seen["u"] = str(request.url)
        return httpx.Response(200, stream=httpx.ByteStream(b"x"))

    fetch_feed("https://v6.vendor.example/f", _resolver=lambda h, p: ["2606:4700:4700::1111"],
               _transport=httpx.MockTransport(handler))
    assert seen["u"].startswith("https://[2606:4700:4700::1111]/")


def test_redirect_is_never_followed():
    with listener(ok(b"secret")) as (tport, target):
        def redirect(h):
            return 302, b"", {"Location": f"http://127.0.0.1:{tport}/hit"}

        with listener(redirect) as (port, seen), pytest.raises(FeedFetchError) as e:
            fetch_feed(f"http://127.0.0.1:{port}/x")
    assert e.value.reason == "redirect_refused" and len(seen) == 1 and target == []


@pytest.mark.parametrize("status", [301, 307, 404, 500])
def test_non_200_is_could_not_check(status):
    with listener(lambda h: (status, b"", {})) as (port, _), pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x")
    assert e.value.reason in ("redirect_refused", "http_status")
    assert "not as an empty feed" in str(e.value)


def test_declared_content_length_over_cap_is_refused_early():
    with listener(lambda h: (200, b"", {"Content-Length": str(10**9)})) as (port, _), \
            pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x", max_bytes=1024)
    assert e.value.reason == "too_large"


def test_streamed_body_without_length_is_cut_at_the_cap():
    class Big(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()   # no Content-Length: the body runs until close
            try:
                for _ in range(1000):
                    self.wfile.write(b"x" * 4096)
            except OSError:
                pass

        def log_message(self, *a):
            pass

    with serve(Big) as port, pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x", max_bytes=16 * 1024)
    assert e.value.reason == "too_large"


def test_gzip_bomb_is_refused_not_expanded():
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024), 9)
    assert len(bomb) < 1024 * 1024
    with listener(ok(bomb, {"Content-Encoding": "gzip"})) as (port, _), \
            pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x", max_bytes=1024 * 1024)
    assert e.value.reason == "too_large"


def test_small_gzip_feed_is_decoded():
    with listener(ok(gzip.compress(FEED.encode()), {"Content-Encoding": "gzip"})) as (port, _):
        assert fetch_feed(f"http://127.0.0.1:{port}/x") == FEED


@pytest.mark.parametrize("enc", ["br", "zstd", "compress"])
def test_unsupported_content_encoding_is_refused(enc):
    with listener(ok(b"zz", {"Content-Encoding": enc})) as (port, _), \
            pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x")
    assert e.value.reason == "bad_encoding"


def test_corrupt_and_truncated_gzip_are_refused():
    good = gzip.compress(b"a" * 5000)
    for body in (b"not gzip at all", good[: len(good) // 2]):
        with listener(ok(body, {"Content-Encoding": "gzip"})) as (port, _), \
                pytest.raises(FeedFetchError) as e:
            fetch_feed(f"http://127.0.0.1:{port}/x")
        assert e.value.reason in ("bad_encoding", "truncated", "network_error")


def test_slow_server_times_out_as_could_not_check():
    def slow(h):
        time.sleep(2)
        return 200, b"late", {}

    t0 = time.monotonic()
    with listener(slow) as (port, _), pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x", timeout=0.4)
    assert e.value.reason == "timeout" and time.monotonic() - t0 < 5


def test_non_utf8_body_is_could_not_check():
    with listener(ok(b"\xff\xfe\x00bad")) as (port, _), pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x")
    assert e.value.reason == "not_utf8"


def test_connection_refused_is_could_not_check():
    with listener(ok()) as (port, _):
        pass   # closed again: nothing listens here
    with pytest.raises(FeedFetchError) as e:
        fetch_feed(f"http://127.0.0.1:{port}/x", timeout=1)
    assert e.value.reason == "connect_failed"


def test_dns_failure_is_could_not_check():
    def nxdomain(h, p):
        raise FetchRefusedError("dns_failed", "nope")

    with pytest.raises(FeedFetchError) as e:
        fetch_feed("https://nx.vendor.example/x", _resolver=nxdomain)
    assert e.value.reason == "dns_failed"
    with pytest.raises(FeedFetchError) as e:
        fetch_feed("https://nx.vendor.example/x", _resolver=lambda h, p: [])
    assert e.value.reason == "dns_failed"


def test_feed_fetch_error_is_a_publish_error_and_structured():
    assert issubclass(FeedFetchError, PublishError)
    with pytest.raises(PublishError) as e:
        fetch_feed("ftp://x/y")
    assert e.value.reason == "bad_scheme"


def test_policy_cannot_be_disabled_by_environment(monkeypatch):
    for name in ("ASSURANCE_ALLOW_PRIVATE_FETCH", "NEURALBRIDGE_ALLOW_PRIVATE"):
        monkeypatch.setenv(name, "1")
    for name in ("NO_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    with pytest.raises(FetchRefusedError) as e:
        safe_fetch("https://h.vendor.example/x", _resolver=lambda h, p: ["10.0.0.1"])
    assert e.value.reason == "blocked_address"


# ----------------------------------------------------------------------------- CLI guarantees
def test_cli_fetch_refusal_writes_nothing_and_keeps_an_existing_file(tmp_path, capsys):
    out = tmp_path / "feed.jsonl"
    out.write_text("GOOD\n")
    with listener(ok()) as (port, seen):
        rc = supplier_cli.main(["fetch", f"http://u:p@127.0.0.1:{port}/x", "--out", str(out)])
    assert rc == 1 and seen == [] and out.read_text() == "GOOD\n"
    err = capsys.readouterr().err
    assert "credentials_in_url" in err and ":p@" not in err
    fresh = tmp_path / "new.jsonl"
    rc = supplier_cli.main(["fetch", "http://10.0.0.1/x", "--out", str(fresh)])
    assert rc == 1 and not fresh.exists()
