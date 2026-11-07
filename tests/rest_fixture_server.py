"""A deterministic LOCAL HTTP(S) service that models how real REST APIs misbehave.

LOCAL integration evidence only. This is a fixture written for these tests, started per
test on a free loopback port. It shows the adapter handles each behaviour *as modelled
here*; it is not third-party production validation and says nothing about any real vendor's
API, its rate-limit policy, its TLS chains or its DNS.

Endpoints (``?`` parameters in brackets):

``/echo``                  JSON of the request as received (method, path, query, headers, body)
``/status/<code>``         that status with a small JSON body  [retry_after=<seconds|http-date>]
``/flaky``                 fails the first ``fail`` calls per ``key`` with ``status`` (default 503),
                           then 200  [key, fail, status, retry_after]
``/slow``                  sleeps ``delay`` seconds, then 200
``/trickle``               ``n`` body chunks, ``interval`` seconds apart (never finishes in time)
``/truncated``             declares Content-Length 1000, sends 10 bytes, closes the socket
``/big``                   ``bytes`` bytes with a Content-Length
``/big-chunked``           ``bytes`` bytes, chunked, no Content-Length
``/chunked``               a small chunked JSON body
``/gzip``                  gzip-encoded JSON
``/gzip-bomb``             gzip of ``bytes`` zero bytes (tiny on the wire, huge decoded)
``/redirect``              ``code`` (302) to ``to`` (/echo)
``/loop``                  redirects to itself
``/pages``                 cursor pagination: ``cursor`` -> {items, next_cursor}; also a ``Link`` header
``/auth/bearer|basic|api-key``  200 only with the right credential, else 401 + WWW-Authenticate;
                           403 for a valid-looking but unauthorised "scope=denied" token
``/reflect``               echoes the Authorization / X-API-Key it received, in the body
``/no-content``            204
``/bad-json``              application/json with a body that is not JSON
``/latin1``                text/plain; charset=iso-8859-1
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import ipaddress
import json
import ssl
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BEARER = "fixture-bearer-TOKEN-5521"
BASIC = ("fixture-user", "fixture-pw-SECRET-8841")
API_KEY = "fixture-apikey-SECRET-3307"
TOTAL_ITEMS = 7
PAGE_SIZE = 3


@dataclass
class State:
    requests: list[dict] = field(default_factory=list)
    flaky: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    lock: threading.Lock = field(default_factory=threading.Lock)

    def count(self, path_prefix: str = "") -> int:
        return sum(1 for r in self.requests if r["path"].startswith(path_prefix))


def _handler_for(state: State, other_port: int):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        # -- plumbing ------------------------------------------------
        def _send(self, status, body=b"", ctype="application/json", extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD" and status not in (204, 304):
                self.wfile.write(body)

        def _json(self, status, obj, extra=None):
            self._send(status, json.dumps(obj).encode(), extra=extra)

        def _chunked(self, parts, ctype="application/json"):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in parts:
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        # -- dispatch -------------------------------------------------
        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            split = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(split.query).items()}
            path = split.path
            with state.lock:
                state.requests.append({
                    "method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": raw,
                })
            try:
                self._route(path, q, raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _route(self, path, q, raw):  # noqa: C901 - a flat route table
            retry_hdr = {"Retry-After": q["retry_after"]} if "retry_after" in q else {}
            if path == "/echo":
                self._json(200, {"method": self.command, "path": path, "query": q,
                                 "headers": dict(self.headers.items()),
                                 "body": json.loads(raw) if raw else None})
            elif path.startswith("/status/"):
                code = int(path.rsplit("/", 1)[1])
                self._json(code, {"detail": "status " + str(code), "pad": "x" * 4000}, extra=retry_hdr)
            elif path == "/flaky":
                key = q.get("key", "k")
                with state.lock:
                    state.flaky[key] += 1
                    n = state.flaky[key]
                if n <= int(q.get("fail", "1")):
                    self._json(int(q.get("status", "503")), {"attempt": n, "detail": "try again"}, extra=retry_hdr)
                else:
                    self._json(200, {"attempt": n, "ok": True, "method": self.command})
            elif path == "/slow":
                time.sleep(float(q.get("delay", "2")))
                self._json(200, {"slow": True})
            elif path == "/trickle":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(int(q.get("n", "50"))))
                self.end_headers()
                for _ in range(int(q.get("n", "50"))):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(float(q.get("interval", "0.2")))
            elif path == "/truncated":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "1000")
                self.end_headers()
                self.wfile.write(b'{"part": 1')
                self.wfile.flush()
                self.close_connection = True
                self.connection.shutdown(2)
            elif path == "/big":
                self._send(200, b"A" * int(q.get("bytes", "2000000")), "application/octet-stream")
            elif path == "/big-chunked":
                total, piece = int(q.get("bytes", "2000000")), 64 * 1024
                self._chunked((b"A" * min(piece, total - i) for i in range(0, total, piece)), "application/octet-stream")
            elif path == "/chunked":
                self._chunked([b'{"chun', b'ked": ', b'true, "n": 3}'])
            elif path == "/gzip":
                body = gzip.compress(json.dumps({"compressed": True, "pad": "y" * 500}).encode())
                self._send(200, body, extra={"Content-Encoding": "gzip"})
            elif path == "/gzip-bomb":
                body = gzip.compress(b"\0" * int(q.get("bytes", "20000000")))
                self._send(200, body, "application/octet-stream", extra={"Content-Encoding": "gzip"})
            elif path == "/redirect":
                self._send(int(q.get("code", "302")), b"", extra={"Location": q.get("to", "/echo")})
            elif path == "/redirect-other-origin":
                self._send(302, b"", extra={"Location": f"http://127.0.0.1:{other_port}/echo"})
            elif path == "/loop":
                self._send(302, b"", extra={"Location": "/loop"})
            elif path == "/pages":
                start = int(q.get("cursor", "0"))
                items = list(range(start, min(start + PAGE_SIZE, TOTAL_ITEMS)))
                nxt = start + PAGE_SIZE if start + PAGE_SIZE < TOTAL_ITEMS else None
                extra = {"Link": f'</pages?cursor={nxt}>; rel="next"', "X-Total-Count": str(TOTAL_ITEMS)} if nxt else {
                    "X-Total-Count": str(TOTAL_ITEMS)}
                self._json(200, {"items": items, "next_cursor": nxt}, extra=extra)
            elif path == "/auth/bearer":
                token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
                self._auth(token == BEARER, token.endswith("denied"))
            elif path == "/auth/basic":
                got = self.headers.get("Authorization") or ""
                want = "Basic " + base64.b64encode(f"{BASIC[0]}:{BASIC[1]}".encode()).decode()
                self._auth(got == want, False)
            elif path == "/auth/api-key":
                self._auth(self.headers.get(q.get("header", "X-API-Key")) == API_KEY, False)
            elif path == "/reflect":
                self._json(200, {"authorization": self.headers.get("Authorization"),
                                 "x_api_key": self.headers.get("X-API-Key")})
            elif path == "/no-content":
                self._send(204)
            elif path == "/bad-json":
                self._send(200, b"{not json", "application/json")
            elif path == "/latin1":
                self._send(200, "café".encode("latin-1"), "text/plain; charset=iso-8859-1")
            else:
                self._json(404, {"detail": "no such fixture endpoint"})

        def _auth(self, ok: bool, forbidden: bool):
            if ok:
                self._json(200, {"authenticated": True})
            elif forbidden:
                self._json(403, {"detail": "authenticated but not allowed"})
            else:
                self._json(401, {"detail": "credentials required"}, extra={"WWW-Authenticate": 'Bearer realm="fixture"'})

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle  # noqa: N815

    return Handler


class FixtureService:
    """Two servers (the second is the "other origin" for redirect tests); optionally TLS."""

    def __init__(self, tls: tuple[Path, Path] | None = None) -> None:
        self.state = State()
        self.other_state = State()
        self._tls = tls
        self._servers: list[ThreadingHTTPServer] = []
        other = self._start(self.other_state, 0)
        self.other_port = other.server_address[1]
        main = self._start(self.state, self.other_port)
        self.port = main.server_address[1]
        self.scheme = "https" if tls else "http"
        self.url = f"{self.scheme}://127.0.0.1:{self.port}"

    def _start(self, state: State, other_port: int) -> ThreadingHTTPServer:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(state, other_port))
        server.daemon_threads = True
        if self._tls is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(self._tls[0]), str(self._tls[1]))
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self._servers.append(server)
        return server

    def close(self) -> None:
        for s in self._servers:
            s.shutdown()
            s.server_close()


def make_self_signed(directory: Path, *, ips=("127.0.0.1",), dns=("localhost",), common_name="fixture.local"):
    """A self-signed certificate generated locally (never reused, never trusted by the system):
    returns ``(cert_pem_path, key_pem_path)``. SANs cover the loopback IP so hostname checks pass
    when the certificate itself is trusted."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)
    sans = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{common_name}.crt", directory / f"{common_name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path
