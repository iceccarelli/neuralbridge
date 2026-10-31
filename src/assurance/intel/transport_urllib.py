"""The one real transport: stdlib ``urllib``, used only by ``intel refresh --live``.

This module is on the pinned list of modules allowed to import a network client
(``tests/test_interfaces_offline.py``). It is imported lazily, never by the offline verbs, so
the offline kit still opens no socket.

What it enforces, at the network boundary, before and during every request:

* ``https`` only, no userinfo, port 443 only, and the host must be **exactly** one of the
  allowed hosts (the three fixed source hosts by default; a CSAF vendor host only if the
  operator names it);
* a redirect is followed only to the **same** host over https, at most :data:`MAX_REDIRECTS`
  times; any other target raises :class:`RedirectRefused`;
* the body is read in chunks and stops at ``max_bytes`` (``ResponseTooLarge``); gzip is not
  requested, so the cap is on the bytes that matter;
* 429 and 5xx (and connection failures) are retried with exponential backoff, honouring
  ``Retry-After`` (seconds or HTTP-date). A ``Retry-After`` longer than ``max_wait`` is not
  waited out: the last response is returned so the caller records it;
* headers are never logged or put in an exception message.
"""

from __future__ import annotations

import email.utils
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from assurance.intel.sources import DEFAULT_HOSTS
from assurance.intel.transport import (
    HostNotAllowed,
    RedirectRefused,
    ResponseTooLarge,
    TransportError,
)

__all__ = ["MAX_REDIRECTS", "RETRY_STATUSES", "UrllibTransport", "check_url", "parse_retry_after"]

log = logging.getLogger("assurance.intel")

MAX_REDIRECTS = 3
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_CHUNK = 64 * 1024
USER_AGENT = "assurance-intel/1 (+public-source reader; offline-first)"


def check_url(url: str, allowed_hosts: Iterable[str]) -> str:
    """Return the host if ``url`` is an allowed https URL, else raise :class:`HostNotAllowed`."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise HostNotAllowed("the URL cannot be parsed") from exc
    if parts.scheme != "https":
        raise HostNotAllowed("only https URLs may be fetched")
    if parts.username is not None or parts.password is not None:
        raise HostNotAllowed("a URL with credentials is refused")
    if port not in (None, 443):
        raise HostNotAllowed("only port 443 may be fetched")
    host = (parts.hostname or "").lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise HostNotAllowed(f"host {host!r} is not on the allow-list")
    return host


def parse_retry_after(value: str | None, *, now: Callable[[], float] = time.time
                      ) -> float | None:
    """Seconds to wait from a ``Retry-After`` header, or ``None`` if absent or unusable."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, when.timestamp() - now())


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        self._allowed = allowed_hosts

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> Any:
        origin = (urllib.parse.urlsplit(req.full_url).hostname or "").lower()
        target = check_url_or_refuse(newurl, self._allowed)
        if target != origin:
            raise RedirectRefused(f"redirect to another host ({target}) refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url_or_refuse(url: str, allowed: Iterable[str]) -> str:
    try:
        return check_url(url, allowed)
    except HostNotAllowed as exc:
        raise RedirectRefused(f"redirect refused: {exc}") from exc


class UrllibTransport:
    """``Transport`` over ``urllib``. Construct once; ``get`` is safe to call repeatedly."""

    def __init__(self, *, allowed_hosts: Iterable[str] = DEFAULT_HOSTS,
                 max_bytes: int = 16 * 1024 * 1024, retries: int = 3, backoff: float = 1.0,
                 max_wait: float = 60.0, sleep: Callable[[float], None] = time.sleep,
                 opener: Any = None) -> None:
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.max_bytes = max_bytes
        self.retries = retries
        self.backoff = backoff
        self.max_wait = max_wait
        self._sleep = sleep
        self._opener = opener or urllib.request.build_opener(
            _SameHostRedirect(self.allowed_hosts))

    def __repr__(self) -> str:
        return f"UrllibTransport(hosts={sorted(self.allowed_hosts)!r})"

    def get(self, url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        check_url(url, self.allowed_hosts)
        wire = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity", **dict(headers)}
        attempt = 0
        while True:
            status, body, retry_after, failure = self._once(url, wire, timeout)
            if failure is None and status not in RETRY_STATUSES:
                return status, body
            if attempt >= self.retries:
                if failure is not None:
                    raise TransportError(f"request failed after {attempt + 1} attempts: "
                                         f"{failure}")
                return status, body
            delay = self.backoff * (2 ** attempt)
            if retry_after is not None:
                if retry_after > self.max_wait:
                    return status, body           # told to wait longer than we will
                delay = retry_after
            log.info("intel: retry %d for status %s in %.1fs", attempt + 1,
                     status if failure is None else "error", delay)
            self._sleep(min(delay, self.max_wait))
            attempt += 1

    def _once(self, url: str, headers: dict[str, str], timeout: float
              ) -> tuple[int, bytes, float | None, str | None]:
        request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310
        try:
            response = self._opener.open(request, timeout=timeout)
        except RedirectRefused:
            raise
        except urllib.error.HTTPError as exc:
            try:
                if 300 <= exc.code < 400:
                    raise RedirectRefused(f"redirect (status {exc.code}) was not followed")
                return (exc.code, self._read(exc, exc.code),
                        parse_retry_after(exc.headers.get("Retry-After")), None)
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, RedirectRefused):
                raise exc.reason from None
            return 0, b"", None, f"{type(exc.reason).__name__}"
        except (TimeoutError, OSError) as exc:
            return 0, b"", None, type(exc).__name__
        with response:
            status = int(getattr(response, "status", 200))
            return status, self._read(response, status), None, None

    def _read(self, response: Any, status: int) -> bytes:
        declared = response.headers.get("Content-Length") if response.headers else None
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            raise ResponseTooLarge(f"Content-Length {declared} exceeds {self.max_bytes}",
                                   status=status, partial=b"")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(_CHUNK, self.max_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > self.max_bytes:
                raise ResponseTooLarge(f"body exceeded {self.max_bytes} bytes", status=status,
                                       partial=b"".join(chunks))
