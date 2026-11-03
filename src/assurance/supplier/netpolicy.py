"""The outbound network policy for fetching a hosted supplier feed.

A feed URL is attacker-influenceable text (a ticket, a pasted link, a ``Location`` header). The
fetch therefore runs under one explicit policy, and anything it refuses is *could not check*,
never *the supplier published nothing*:

* **Scheme and shape**: https, or plain http only to ``localhost`` / ``127.0.0.1`` / ``::1`` (the
  rule in ``core/api_url.py``). No credentials, query or fragment.
* **Destination**: the hostname is resolved here and EVERY address must be globally routable.
  Loopback (except the dev-loopback http case above), private, link-local, reserved, multicast,
  unspecified, CGNAT, IPv4-mapped / 6to4 / NAT64 forms of those, and cloud-metadata addresses are
  refused.
* **DNS rebinding**: the connection is made to the address that was validated, not to a second
  lookup. The request keeps ``Host`` and, for https, TLS SNI and certificate verification against
  the original hostname.
* **No redirects**: a 3xx is a refusal. A hosted feed has no reason to move; following a hop
  would mean re-validating a destination chosen by the server.
* **Bounded**: connect/read timeouts, a total deadline, a byte cap checked against
  ``Content-Length`` and while streaming, and a decompression cap (gzip/deflate only, decoded
  incrementally; the output is never allowed past the cap).

There is no environment variable and no argument that relaxes the policy. ``_resolver`` and
``_transport`` exist so tests can supply a name server and a fake wire; they are still subject to
every check above.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
import zlib
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from ..core.api_url import LOOPBACK_HOSTS
from ..core.errors import AssuranceError

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_TOTAL_TIMEOUT",
    "FetchRefusedError",
    "Resolver",
    "address_problem",
    "safe_fetch",
    "url_problem",
]

DEFAULT_MAX_BYTES = 16 * 1024 * 1024  # the hosted feed's own size bound (MAX_FEED_BYTES)
DEFAULT_TOTAL_TIMEOUT = 30.0

Resolver = Callable[[str, int], Sequence[str]]


class FetchRefusedError(AssuranceError):
    """The fetch did not happen or did not complete. ``reason`` is a stable machine code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


# Never routable for a supplier feed, whatever Python's flags say about them.
_METADATA = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254", "169.254.170.2", "169.254.169.123", "100.100.100.200",
    "192.0.0.192", "fd00:ec2::254", "fd20:ce::254"))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIXTOFOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def address_problem(address: str, *, allow_loopback: bool = False) -> str | None:
    """Why a connection to ``address`` is refused, or ``None``. Pure; opens nothing."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return f"{address!r} is not an IP address"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _TEREDO:
            return f"{ip} is a Teredo tunnel address"
        embedded = _embedded_v4(ip)
        if embedded is not None:
            inner = address_problem(str(embedded), allow_loopback=allow_loopback)
            return f"{ip} embeds {embedded}: {inner}" if inner else None
    if ip in _METADATA:
        return f"{ip} is a cloud metadata address"
    if ip.is_loopback:
        return None if allow_loopback else f"{ip} is a loopback address"
    if ip.is_unspecified:
        return f"{ip} is the unspecified address"
    if ip.is_multicast:
        return f"{ip} is a multicast address"
    if ip.is_link_local:
        return f"{ip} is a link-local address"
    if ip.is_private or ip.is_reserved or not ip.is_global:
        return f"{ip} is a private, reserved or otherwise non-public address"
    return None


def _host_shape_problem(host: str) -> str | None:
    """Why ``host`` cannot be a DNS name (pure). IP literals are judged elsewhere."""
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if not host.isascii():
        return ("the feed URL host contains non-ASCII characters; give the ASCII (punycode) "
                "form of the name.")
    name = host[:-1] if host.endswith(".") else host
    if not name or len(name) > 253:
        return "the feed URL host is empty or longer than 253 characters."
    for label in name.split("."):
        if not label or len(label) > 63:
            return "the feed URL host has an empty label or a label longer than 63 characters."
    return None


def url_problem(url: str) -> tuple[str, str] | None:
    """(reason, detail) if ``url`` may not be fetched at all, judged on its text alone."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return "bad_url", "the feed URL is not a valid URL."
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "bad_scheme", "the feed URL is not an http(s) URL with a host. `fetch` downloads a hosted feed; a feed already on disk needs no downloading."
    if url != url.strip() or any(c in url for c in "\r\n\t\x00 "):
        return "bad_url", "the feed URL contains whitespace or control characters."
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return "credentials_in_url", "the feed URL must not contain credentials."
    if parts.query or parts.fragment:
        return "query_in_url", "the feed URL must not carry a query or fragment."
    if port == 0:
        return "bad_url", "the feed URL names port 0."
    shape = _host_shape_problem(parts.hostname)
    if shape:
        return "bad_url", shape
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        return ("plain_http", "plain http is accepted only for localhost, 127.0.0.1 and ::1; "
                              "use https.")
    return None


def _system_resolver(host: str, port: int, *, timeout: float) -> list[str]:
    """getaddrinfo with a deadline (it has none of its own)."""
    box: dict[str, object] = {}

    def work() -> None:
        try:
            box["ok"] = [ai[4][0] for ai in
                         socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        except Exception as exc:  # OSError, but also idna UnicodeError for malformed names
            box["err"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise FetchRefusedError("dns_timeout", f"resolving {host!r} took longer than {timeout:g}s.")
    if "err" in box or "ok" not in box:
        raise FetchRefusedError("dns_failed", f"could not resolve {host!r}.")
    return list(box["ok"])  # type: ignore[arg-type]


class _BoundedDecoder:
    """Incremental gzip/deflate decode whose output can never pass ``cap``."""

    def __init__(self, encoding: str, cap: int) -> None:
        wbits = zlib.MAX_WBITS | 16 if encoding in ("gzip", "x-gzip") else zlib.MAX_WBITS
        self._d = zlib.decompressobj(wbits)
        self._cap = cap
        self._produced = 0

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        try:
            while data:
                chunk = self._d.decompress(data, self._cap - self._produced + 1)
                self._produced += len(chunk)
                if self._produced > self._cap:
                    raise FetchRefusedError(
                        "too_large", f"the decompressed feed exceeds {self._cap} bytes.")
                out += chunk
                data = self._d.unconsumed_tail
                if not chunk and data:  # no progress: corrupt stream
                    break
        except zlib.error as exc:
            raise FetchRefusedError("bad_encoding", "the response body is not valid compressed "
                                               "data.") from exc
        if self._d.eof and self._d.unused_data:
            # A second gzip member (or junk) after the first stream ended: silently dropping it
            # would let one body mean different things to different readers.
            raise FetchRefusedError("bad_encoding", "the compressed response has data after the "
                                               "end of its stream (a second member or trailing "
                                               "bytes).")
        return bytes(out)

    def finish(self) -> None:
        if not self._d.eof:
            raise FetchRefusedError("truncated", "the compressed response ended early.")


class _Deadline:
    """One monotonic wall-clock deadline plus the live sockets the watchdog may cut."""

    def __init__(self, total: float) -> None:
        self.at = time.monotonic() + total
        self._lock = threading.Lock()
        self._fds: set[int] = set()

    def remaining(self) -> float:
        return self.at - time.monotonic()

    def check(self) -> float:
        left = self.remaining()
        if left <= 0:
            raise FetchRefusedError("timeout", "the feed download exceeded its total time limit.")
        return left

    def add(self, sock: socket.socket | None) -> int | None:
        fd = sock.fileno() if sock is not None else -1
        if fd < 0:
            return None
        with self._lock:
            self._fds.add(fd)
        return fd

    def drop(self, fd: int | None) -> None:
        if fd is not None:
            with self._lock:
                self._fds.discard(fd)

    def kill(self) -> None:
        """Shut down every live socket so a blocked recv/handshake in the worker returns."""
        with self._lock:
            for fd in list(self._fds):
                try:
                    s = socket.socket(fileno=os.dup(fd))
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    finally:
                        s.close()
                except OSError:
                    pass


def _make_backend(httpcore, deadline: _Deadline, allowed: str):
    """A network backend that dials only ``allowed`` and never outlives ``deadline``."""
    base = httpcore.SyncBackend()
    want = ipaddress.ip_address(allowed.split("%", 1)[0])

    class Guarded(httpcore.NetworkStream):
        def __init__(self, inner, fd) -> None:
            self._inner = inner
            self._fd = fd

        def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
            left = deadline.check()
            return self._inner.read(min(max_bytes, 16384),
                                    left if timeout is None else min(timeout, left))

        def write(self, buffer: bytes, timeout: float | None = None) -> None:
            left = deadline.check()
            self._inner.write(buffer, left if timeout is None else min(timeout, left))

        def close(self) -> None:
            deadline.drop(self._fd)
            self._inner.close()

        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            left = deadline.check()
            tls = self._inner.start_tls(ssl_context, server_hostname,
                                        left if timeout is None else min(timeout, left))
            return Guarded(tls, self._fd)

        def get_extra_info(self, info: str):
            return self._inner.get_extra_info(info)

    class Backend(httpcore.NetworkBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            try:
                ok = ipaddress.ip_address(host.split("%", 1)[0]) == want
            except ValueError:
                ok = False
            if not ok:  # defence in depth: only the address that passed validation is dialled
                raise FetchRefusedError(
                    "blocked_address", f"refusing to dial {host!r}: it is not the validated address.")
            left = deadline.check()
            inner = base.connect_tcp(host, port, left if timeout is None else min(timeout, left),
                                     local_address, socket_options)
            return Guarded(inner, deadline.add(inner.get_extra_info("socket")))

        def connect_unix_socket(self, *a, **k):
            raise FetchRefusedError("blocked_address", "unix sockets are never dialled.")

        def sleep(self, seconds: float) -> None:
            base.sleep(seconds)

    return Backend()


def _is_loopback(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def safe_fetch(
    url: str,
    *,
    timeout: float = 10.0,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    _resolver: Resolver | None = None,
    _transport: object | None = None,
) -> bytes:
    """GET ``url`` under the policy above and return the (decoded) body bytes.

    Raises :class:`FetchRefusedError` for every refusal or failure; nothing is written anywhere.
    ``total_timeout`` is a hard wall-clock bound over DNS, connect, TLS, headers and body: the
    request runs in a worker thread, every socket read is clamped to the time left, and when the
    deadline passes the watchdog cuts the sockets and the call raises ``timeout``.
    """
    import httpx

    deadline = _Deadline(total_timeout)
    problem = url_problem(url)
    if problem:
        raise FetchRefusedError(*problem)
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    dev_loopback = parts.scheme == "http" and host in LOOPBACK_HOSTS

    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if is_literal:
        addresses = [host]
    else:
        try:
            if _resolver is not None:
                answers = _resolver(host, port)
            else:
                answers = _system_resolver(
                    host, port, timeout=max(0.001, min(timeout, 10.0, deadline.remaining())))
            addresses = list(dict.fromkeys(answers))
        except FetchRefusedError:
            raise
        except Exception as exc:  # a resolver must fail closed, never escape as a traceback
            raise FetchRefusedError(
                "dns_failed", f"could not resolve {host!r} ({type(exc).__name__}).") from exc
    if not addresses:
        raise FetchRefusedError("dns_failed", f"{host!r} resolved to no address.")
    deadline.check()
    for address in addresses:  # all of them: one bad answer among good ones is a refusal
        why = address_problem(address, allow_loopback=dev_loopback)
        if not why and dev_loopback and not _is_loopback(address):
            why = f"{address} is not a loopback address (dev http is loopback-only)"
        if why:
            raise FetchRefusedError("blocked_address", f"refusing to connect for {host!r}: {why}.")

    box: dict[str, object] = {}

    def work() -> None:
        last: FetchRefusedError | None = None
        try:
            for address in addresses:
                try:
                    box["ok"] = _get_pinned(httpx, parts, host, port, address, is_literal, timeout,
                                            deadline, max_bytes, _transport)
                    return
                except _ConnectFailedError as exc:
                    last = FetchRefusedError("connect_failed", str(exc))
            box["err"] = last
        except BaseException as exc:  # noqa: BLE001 - carried to the caller's thread
            box["err"] = exc

    t = threading.Thread(target=work, name="supplier-fetch", daemon=True)
    t.start()
    t.join(max(0.0, deadline.remaining()))
    if t.is_alive():
        deadline.kill()
        t.join(2.0)
        raise FetchRefusedError("timeout", "the feed download exceeded its total time limit.")
    err = box.get("err")
    if err is not None:
        raise err  # type: ignore[misc]
    if "ok" not in box:
        raise FetchRefusedError("network_error", f"could not read from {host}.")
    return box["ok"]  # type: ignore[return-value]


class _ConnectFailedError(Exception):
    pass


def _get_pinned(httpx, parts, host, port, address, is_literal, timeout, deadline, max_bytes,
                transport) -> bytes:
    import httpcore

    ip = ipaddress.ip_address(address.split("%", 1)[0])
    shown = f"[{ip}]" if ip.version == 6 else str(ip)
    pinned = f"{parts.scheme}://{shown}:{port}{parts.path or '/'}"
    headers = {"Host": parts.netloc, "Accept-Encoding": "gzip, deflate",
               "Accept": "application/x-ndjson, application/json, text/plain"}
    extensions = {"sni_hostname": host} if (parts.scheme == "https" and not is_literal) else {}
    tmo = httpx.Timeout(timeout, connect=min(timeout, 10.0))
    if transport is None:
        transport = httpx.HTTPTransport(trust_env=False)
        pool = getattr(transport, "_pool", None)
        if pool is None or not hasattr(pool, "_network_backend"):
            raise FetchRefusedError("network_error", "the HTTP client does not expose its network "
                                    "backend; refusing to fetch without deadline enforcement.")
        pool._network_backend = _make_backend(httpcore, deadline, str(ip))
    try:
        with httpx.Client(transport=transport, timeout=tmo, follow_redirects=False,
                          trust_env=False) as client, \
                client.stream("GET", pinned, headers=headers, extensions=extensions) as resp:
            if 300 <= resp.status_code < 400:
                raise FetchRefusedError("redirect_refused",
                                   f"{host} answered HTTP {resp.status_code} (a redirect). "
                                   "Redirects are not followed.")
            if resp.status_code != 200:
                raise FetchRefusedError("http_status", f"{host} answered HTTP {resp.status_code}.")
            declared = resp.headers.get("content-length", "")
            if declared.isascii() and declared.isdigit() and int(declared) > max_bytes:
                raise FetchRefusedError("too_large", f"the response declares {declared} bytes; "
                                                f"the limit is {max_bytes}.")
            encoding = resp.headers.get("content-encoding", "identity").strip().lower()
            if encoding in ("", "identity"):
                decoder = None
            elif encoding in ("gzip", "x-gzip", "deflate"):
                decoder = _BoundedDecoder(encoding, max_bytes)
            else:
                raise FetchRefusedError("bad_encoding",
                                   f"unsupported Content-Encoding {encoding!r}.")
            raw_total = 0
            body = bytearray()
            for chunk in resp.iter_raw():  # no chunk size: yield what arrived, do not buffer
                deadline.check()
                raw_total += len(chunk)
                if raw_total > max_bytes:
                    raise FetchRefusedError("too_large", f"the response exceeds {max_bytes} bytes.")
                body += decoder.feed(chunk) if decoder else chunk
                if len(body) > max_bytes:
                    raise FetchRefusedError("too_large", f"the response exceeds {max_bytes} bytes.")
            deadline.check()
            if decoder:
                decoder.finish()
            return bytes(body)
    except FetchRefusedError:
        raise
    except httpx.ConnectError as exc:
        raise _ConnectFailedError(f"could not connect to {host}:{port} ({type(exc).__name__}).") \
            from exc
    except httpx.TimeoutException as exc:
        raise FetchRefusedError("timeout", f"{host} timed out ({type(exc).__name__}).") from exc
    except (httpx.HTTPError, OSError, ValueError) as exc:
        raise FetchRefusedError("network_error",
                           f"could not read from {host} ({type(exc).__name__}).") from exc
