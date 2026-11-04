"""Red-team regressions for the supplier outbound fetch policy (workstream K).

Only loopback listeners started here are ever dialled; every other address is a string handed to a
stub. A test that could reach a non-loopback address patches ``socket.create_connection`` to fail.
"""

from __future__ import annotations

import gzip
import socket
import threading
import time
from contextlib import contextmanager

import httpx
import pytest

from assurance.supplier import netpolicy
from assurance.supplier.netpolicy import FetchRefusedError, safe_fetch, url_problem
from assurance.supplier.publish import FeedFetchError, fetch_feed

H = b"HTTP/1.1 200 OK\r\n"
TOTAL = 2.0


@contextmanager
def raw_server(handler):
    """Loopback TCP server; ``handler(conn)`` runs per connection in its own thread."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()
    conns: list[socket.socket] = []

    def run():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conns.append(c)
            threading.Thread(target=handler, args=(c,), daemon=True).start()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        for c in conns:
            try:
                c.close()
            except OSError:
                pass
        srv.close()
        th.join(2)


def read_request(c):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = c.recv(4096)
        if not d:
            break
        buf += d
    return buf


def drip(c, data, gap=0.4):
    for b in data:
        try:
            c.sendall(bytes([b]))
        except OSError:
            return
        time.sleep(gap)


def fetch_threads():
    return [t for t in threading.enumerate() if t.name == "supplier-fetch" and t.is_alive()]


def timed(port, **kw):
    t0 = time.monotonic()
    with pytest.raises(FetchRefusedError) as ei:
        safe_fetch(f"http://127.0.0.1:{port}/f", timeout=1, total_timeout=TOTAL,
                   max_bytes=10**6, **kw)
    return ei.value, time.monotonic() - t0


def h_header_drip(c):
    read_request(c)
    drip(c, H + b"X-A: " + b"a" * 400)


def h_body_drip(c):
    read_request(c)
    c.sendall(H + b"Content-Length: 900\r\n\r\n")
    drip(c, b"a" * 900)


def h_silent(c):
    read_request(c)
    time.sleep(30)


def h_never_reads(c):
    time.sleep(30)


def h_headers_then_stall(c):
    read_request(c)
    c.sendall(H + b"Content-Length: 900\r\n\r\nabc")
    time.sleep(30)


@pytest.mark.parametrize("handler", [h_header_drip, h_body_drip, h_silent, h_never_reads,
                                     h_headers_then_stall])
def test_total_deadline_is_hard_for_every_stall_shape(handler):
    with raw_server(handler) as port:
        err, took = timed(port)
    assert err.reason == "timeout"
    assert took < TOTAL + 2, took
    assert fetch_threads() == []


def test_total_deadline_through_fetch_feed():
    with raw_server(h_body_drip) as port:
        t0 = time.monotonic()
        with pytest.raises(FeedFetchError) as ei:
            fetch_feed(f"http://127.0.0.1:{port}/f", timeout=1, total_timeout=TOTAL)
    assert ei.value.reason == "timeout"
    assert time.monotonic() - t0 < TOTAL + 2
    assert fetch_threads() == []


def test_success_path_is_fast_and_leaves_no_thread():
    def ok(c):
        read_request(c)
        c.sendall(H + b"Content-Length: 5\r\nConnection: close\r\n\r\nhello")
        c.close()

    with raw_server(ok) as port:
        t0 = time.monotonic()
        assert safe_fetch(f"http://127.0.0.1:{port}/f", timeout=2, total_timeout=10) == b"hello"
    assert time.monotonic() - t0 < 1.5
    assert fetch_threads() == []


def test_deadline_wrapper_cuts_a_stalled_fake_transport():
    """Even a transport that blocks without any socket is bounded by the watchdog."""
    release = threading.Event()

    def handler(request):
        release.wait(5)
        return httpx.Response(200, content=b"late")

    t0 = time.monotonic()
    try:
        with pytest.raises(FetchRefusedError) as ei:
            safe_fetch("https://feed.example/f", timeout=1, total_timeout=1,
                       _resolver=lambda h, p: ["93.184.216.34"],
                       _transport=httpx.MockTransport(handler))
        assert ei.value.reason == "timeout"
        assert time.monotonic() - t0 < 1 + 2 + 1
    finally:
        release.set()


# ---------------------------------------------------------------------------------------------
# 2. resolver exceptions and hostname shape


def test_resolver_unicode_error_is_dns_failed_not_a_traceback():
    def boom(h, p):
        raise UnicodeError("label empty or too long")

    with pytest.raises(FetchRefusedError) as ei:
        safe_fetch("https://feed.example/f", _resolver=boom)
    assert ei.value.reason == "dns_failed"


def test_system_resolver_maps_any_exception_to_dns_failed(monkeypatch):
    def boom(*a, **k):
        raise UnicodeError("label empty or too long")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(FetchRefusedError) as ei:
        netpolicy._system_resolver("feed.example", 443, timeout=2)
    assert ei.value.reason == "dns_failed"


@pytest.mark.parametrize("host", [
    "a" * 70 + ".com", "a..com", ".a.com", ("a" * 60 + ".") * 5 + "com",
    "ｆｅｅｄ.example", "fée.example", "a.com..",
])
def test_hostname_shape_is_refused_without_resolving(host, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: pytest.fail("shape-invalid names must not be resolved"))
    problem = url_problem(f"https://{host}/")
    assert problem is not None and problem[0] == "bad_url"
    with pytest.raises(FetchRefusedError) as ei:
        safe_fetch(f"https://{host}/")
    assert ei.value.reason == "bad_url"


@pytest.mark.parametrize("host", ["feed.example", "feed.example.", "a-b.c1.example", "localhost"])
def test_ordinary_hostnames_keep_their_shape(host):
    assert url_problem(f"https://{host}/") is None


# ---------------------------------------------------------------------------------------------
# 3. dev-loopback http: every answer must be loopback, and only validated addresses are dialled


def test_loopback_http_refuses_a_name_with_any_public_answer(monkeypatch):
    def no_dial(address, *a, **k):
        pytest.fail(f"dialled {address!r}")

    monkeypatch.setattr(socket, "create_connection", no_dial)
    for answers in (["127.0.0.1", "8.8.8.8"], ["8.8.8.8", "127.0.0.1"], ["127.0.0.1", "::ffff:8.8.8.8"]):
        with pytest.raises(FetchRefusedError) as ei:
            safe_fetch("http://localhost:1/", timeout=1, _resolver=lambda h, p, a=answers: a)
        assert ei.value.reason == "blocked_address"


def test_backend_dials_only_the_validated_address(monkeypatch):
    import httpcore

    def no_dial(address, *a, **k):
        pytest.fail(f"dialled {address!r}")

    monkeypatch.setattr(socket, "create_connection", no_dial)
    backend = netpolicy._make_backend(httpcore, netpolicy._Deadline(5), "127.0.0.1")
    with pytest.raises(FetchRefusedError) as ei:
        backend.connect_tcp("8.8.8.8", 80, timeout=1)
    assert ei.value.reason == "blocked_address"
    with pytest.raises(FetchRefusedError):
        backend.connect_unix_socket("x.sock")


def test_loopback_only_answers_still_work():
    def ok(c):
        read_request(c)
        c.sendall(H + b"Content-Length: 2\r\nConnection: close\r\n\r\nok")
        c.close()

    with raw_server(ok) as port:
        got = safe_fetch(f"http://localhost:{port}/f", timeout=2,
                         _resolver=lambda h, p: ["127.0.0.1"])
    assert got == b"ok"


# ---------------------------------------------------------------------------------------------
# 4. gzip members, Content-Length digits


def test_multi_member_gzip_is_refused_not_truncated():
    body = gzip.compress(b"hi") + gzip.compress(b"A" * 10**5)

    def serve(c):
        read_request(c)
        c.sendall(H + b"Content-Encoding: gzip\r\nConnection: close\r\n\r\n" + body)
        c.close()

    with raw_server(serve) as port, pytest.raises(FetchRefusedError) as ei:
        safe_fetch(f"http://127.0.0.1:{port}/f", timeout=2, max_bytes=10**6)
    assert ei.value.reason == "bad_encoding"


def test_decoder_refuses_trailing_bytes_split_across_feeds():
    d = netpolicy._BoundedDecoder("gzip", 10**6)
    blob = gzip.compress(b"hi")
    assert d.feed(blob) == b"hi"
    with pytest.raises(FetchRefusedError) as ei:
        d.feed(gzip.compress(b"more"))
    assert ei.value.reason == "bad_encoding"


def test_single_member_gzip_still_decodes():
    def serve(c):
        read_request(c)
        c.sendall(H + b"Content-Encoding: gzip\r\nConnection: close\r\n\r\n" + gzip.compress(b"hi"))
        c.close()

    with raw_server(serve) as port:
        assert safe_fetch(f"http://127.0.0.1:{port}/f", timeout=2) == b"hi"


@pytest.mark.parametrize("declared", ["²", "٣", "9" * 5000])
def test_non_ascii_or_absurd_content_length_never_raises_valueerror(declared):
    def handler(request):
        return httpx.Response(200, headers=[("content-length", declared)], content=b"")

    try:
        safe_fetch("https://feed.example/f", timeout=1, _resolver=lambda h, p: ["93.184.216.34"],
                   _transport=httpx.MockTransport(handler))
    except FetchRefusedError as exc:
        assert exc.reason in {"network_error", "too_large"}


def test_environment_cannot_redirect_or_break_the_default_transport(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(k, "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/nonexistent")

    def ok(c):
        read_request(c)
        c.sendall(H + b"Content-Length: 2\r\nConnection: close\r\n\r\nok")
        c.close()

    with raw_server(ok) as port:
        assert safe_fetch(f"http://127.0.0.1:{port}/f", timeout=2) == b"ok"
