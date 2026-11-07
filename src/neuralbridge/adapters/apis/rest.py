"""
NeuralBridge Adapter: REST API (generic, real, bounded)

Description
-----------
Sends real HTTP requests through ``httpx``. Nothing here answers from canned
data: a result either comes from the server that was contacted, or it is a
structured failure. A non-2xx status is never reported as success.

Operations: ``get``, ``post``, ``put``, ``patch``, ``delete``, ``head``.
Parameters: ``endpoint`` (path relative to ``base_url``; absolute URLs are
refused), ``query_params``, ``json_body``.

Result: an :class:`AdapterResponse`.

* success -> ``success=True``,  ``data = {status_code, headers, body, truncated: False}``
* failure -> ``success=False``, ``error`` starts with a short code (``http_error``, ``timeout``,
  ``response_too_large``, ``redirect_refused``, ``blocked_destination``, ``connection_failed``,
  ``invalid_endpoint``, ...) and ``data`` carries ``error`` (the code) plus ``status_code`` and a
  truncated ``body`` where a response exists. Network and policy failures are returned, not raised.

Configuration (YAML)
--------------------
.. code-block:: yaml

    adapters:
      - name: my_rest_api
        type: rest
        config:
          base_url: "https://api.example.com/v1"
          headers: {Accept: "application/json"}
          auth_type: bearer            # none | bearer | basic | api_key
          credentials_env: {token: MY_API_TOKEN}   # or credentials: {token: ...}
          allowed_hosts: ["api.example.com"]       # optional exact-host allow-list
          timeout: 30                  # overall seconds per request, retries included (max 120)
          verify_ssl: true             # false disables certificate checks (logged); see ca_cert_path
          ca_cert_path: /etc/acme/ca.pem   # optional: trust ONLY this CA bundle (system store not used)
          retry_count: 2               # connection-establishment retries only (max 5; default 0)
          retry:                       # request retries; OFF unless max_attempts > 1 (see below)
            max_attempts: 3            # total tries including the first (1-5)
            methods: [get, head]       # idempotent only; add put / delete to opt in; never post / patch
            retry_on_status: [429, 500, 502, 503, 504]
            backoff_base: 0.2          # seconds; doubles each retry (exponential)
            backoff_max: 5
            backoff_jitter: 0.25       # adds up to 25% random delay
            max_retry_after: 30        # a longer Retry-After is not waited for
          max_response_bytes: 1048576  # hard limit 16 MiB
          allow_private_network: false # opt in for tests / local services only

Credentials
-----------
Supplied in the adapter config, like every other adapter (``password`` for
PostgreSQL): ``credentials`` (``token`` | ``username`` + ``password`` |
``api_key``) or, preferred, ``credentials_env`` naming environment variables.
They are only ever placed in the outgoing request header. They are not logged,
not copied into errors, and any occurrence in a returned body or header is
replaced with ``[REDACTED]``.

Security boundaries
-------------------
* Only ``http`` / ``https``; no credentials embedded in the URL.
* Destinations resolving to private, loopback, link-local (incl. the cloud
  metadata address), multicast, reserved or unspecified addresses are refused
  unless ``allow_private_network`` is true. ``allowed_hosts``, if set, further
  restricts the host (exact match).
* Redirects are never followed to another origin, and only for GET/HEAD
  (each hop re-validated, at most 3).
* ``trust_env`` is off by default so ambient proxies cannot bypass the checks.
* Response bodies are read as a stream and cut off at ``max_response_bytes``;
  the whole request has a wall-clock deadline.

Retry semantics (``retry``; off by default, bounded, documented)
-----------------------------------------------------------------
* A request is retried only if its method is in ``retry.methods``. The default is ``get`` and
  ``head``; ``put`` and ``delete`` are idempotent by definition (RFC 9110) but a server may still
  have side effects, so they are an explicit opt-in. ``post`` and ``patch`` can never be enabled
  (rejected at connect): a retried POST can create the thing twice.
* Retried: a response whose status is in ``retry_on_status`` (default 429/500/502/503/504; only 408,
  425, 429 and 5xx may be listed) and a transport failure (connection refused / reset, incomplete
  body). Never retried: any other status (4xx in particular), policy refusals (blocked destination,
  redirect refused, oversized body), TLS verification failures, and the overall deadline.
* Bounded three ways: at most ``max_attempts`` (hard maximum 5); a ``Retry-After`` (seconds or an
  HTTP date) larger than ``max_retry_after`` is not waited for — the failure is returned with
  ``data.retry = "retry_after_exceeds_cap"``; and the wait must fit in what is left of ``timeout``,
  otherwise ``data.retry = "retry_budget_exhausted"``. The ``timeout`` covers all attempts.
* Wait before retry n = max(min(backoff_max, backoff_base * 2**(n-1)) + jitter, Retry-After).
* The result reports ``metadata.attempts`` on success and ``data.attempts`` on a failure that was
  retried. ``retry_count`` (connection establishment inside the transport) is separate and unchanged.

Evidence: ``tests/test_rest_adapter.py`` and ``tests/test_rest_adapter_contract.py`` run the adapter
against deterministic fixture servers started on loopback by the tests (auth schemes, 401/403/404/429
+ Retry-After, 5xx, slow / truncated / oversized / chunked / gzip bodies, redirects, pagination, TLS
with a locally generated self-signed certificate). That is LOCAL integration evidence; it is not
validation against any third-party API.

Known limit: the address check resolves the host immediately before connecting; a
hostile DNS server that changes its answer between the check and the connection
(rebinding) is not defended against. Use ``allowed_hosts`` with trusted DNS.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import random
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)

DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 120.0
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
HARD_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RETRIES = 5
MAX_REDIRECTS = 3
ERROR_BODY_CHARS = 2048
_BODY_METHODS = {"post", "put", "patch"}
_PASS_HEADERS = (
    "content-type", "content-length", "etag", "last-modified", "retry-after", "x-request-id",
    # what REST pagination and rate-limiting actually use
    "link", "x-total-count", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
)
MAX_ATTEMPTS = 5
MAX_RETRY_AFTER_CAP = 300.0
_RETRYABLE_METHODS = ("get", "head", "put", "delete")
_RETRY_STATUS_OK = (408, 425, 429)
_AUTH_TYPES = ("none", "bearer", "basic", "api_key")


@dataclass(frozen=True)
class RetryPolicy:
    """Parsed ``retry`` config. ``max_attempts == 1`` means no retry."""

    max_attempts: int = 1
    methods: tuple[str, ...] = ("get", "head")
    statuses: frozenset[int] = field(default_factory=lambda: frozenset({429, 500, 502, 503, 504}))
    backoff_base: float = 0.2
    backoff_max: float = 5.0
    jitter: float = 0.25
    max_retry_after: float = 30.0

    @classmethod
    def from_config(cls, raw: Any) -> RetryPolicy:
        if raw in (None, {}):
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("retry must be an object")
        try:
            attempts = int(raw.get("max_attempts", 1))
            base = float(raw.get("backoff_base", 0.2))
            cap = float(raw.get("backoff_max", 5.0))
            jitter = float(raw.get("backoff_jitter", 0.25))
            max_after = float(raw.get("max_retry_after", 30.0))
        except (TypeError, ValueError) as exc:
            raise ValueError("retry settings must be numbers") from exc
        if not 1 <= attempts <= MAX_ATTEMPTS:
            raise ValueError(f"retry.max_attempts must be between 1 and {MAX_ATTEMPTS}")
        if not (0 <= base <= 30 and base <= cap <= 60):
            raise ValueError("retry.backoff_base must be 0-30 and retry.backoff_max between it and 60 seconds")
        if not 0 <= jitter <= 1:
            raise ValueError("retry.backoff_jitter must be between 0 and 1")
        if not 0 <= max_after <= MAX_RETRY_AFTER_CAP:
            raise ValueError(f"retry.max_retry_after must be between 0 and {MAX_RETRY_AFTER_CAP:g} seconds")
        methods = tuple(str(m).lower() for m in raw.get("methods", ("get", "head")))
        for m in methods:
            if m in ("post", "patch"):
                raise ValueError(f"retry.methods: {m.upper()} is not idempotent and can never be retried")
            if m not in _RETRYABLE_METHODS:
                raise ValueError(f"retry.methods: unknown method '{m}'")
        statuses = frozenset(int(c) for c in raw.get("retry_on_status", (429, 500, 502, 503, 504)))
        for code in statuses:
            if not (code in _RETRY_STATUS_OK or 500 <= code <= 599):
                raise ValueError(f"retry.retry_on_status: {code} is not a retryable status")
        return cls(attempts, methods, statuses, base, cap, jitter, max_after)


def _caused_by_tls(exc: BaseException) -> bool:
    """Is a TLS failure (bad certificate, handshake) anywhere in this exception's cause chain?"""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, ssl.SSLError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _retry_after_seconds(value: str | None) -> float | None:
    """``Retry-After`` as seconds from now: delta-seconds or an HTTP date. ``None`` if absent/unparseable."""
    if not value:
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    return max(0.0, seconds) if seconds == seconds else None  # NaN guard


class _RefusedError(Exception):
    """A request the adapter will not send (policy). ``code`` is returned to the caller; ``detail`` has no secrets."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Only a globally routable unicast address may be dialled.

    ``is_private`` alone misses shared address space 100.64.0.0/10 (carrier-grade NAT, which holds a
    cloud metadata address, 100.100.100.200), benchmarking 198.18.0.0/15, IETF 192.0.0.0/24 and
    others; ``not is_global`` covers all of them. IPv4 embedded in IPv4-mapped, 6to4 and NAT64
    addresses is judged as the IPv4 address it reaches.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip.teredo is not None:
            return True  # a tunnel whose far end we cannot see
    return ip.is_multicast or ip.is_unspecified or not ip.is_global


async def _resolve(host: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos]


class RestApiAdapter(BaseAdapter):
    """A generic, bounded adapter for RESTful HTTP APIs."""

    adapter_type: str = "rest"
    category: str = "apis"
    description: str = "Generic REST adapter: real, bounded HTTP requests with SSRF and size limits."
    version: str = "0.2.0"
    #: Exercised by tests/test_rest_adapter.py and tests/test_rest_adapter_contract.py against deterministic
    #: LOCAL fixture servers (including TLS with a locally generated certificate); no third-party service.
    backend: str = "real"
    supported_operations: list[str] = ["get", "post", "put", "patch", "delete", "head"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._auth_headers: dict[str, str] = {}
        self._secrets: list[str] = []
        self._policy = RetryPolicy()
        self._sleep = asyncio.sleep  # replaceable in tests; production waits for real

    # ── configuration helpers ────────────────────────────────

    def _cred(self, key: str) -> str | None:
        env_map = self.config.get("credentials_env") or {}
        if env_map.get(key):
            value = os.environ.get(str(env_map[key]))
            if value:
                return value
        value = (self.config.get("credentials") or {}).get(key)
        return str(value) if value else None

    def _build_auth(self) -> tuple[dict[str, str], list[str]]:
        auth_type = self.config.get("auth_type", "none")
        if auth_type not in _AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {list(_AUTH_TYPES)}")
        if auth_type == "none":
            return {}, []
        if auth_type == "bearer":
            token = self._cred("token")
            if not token:
                raise ValueError("auth_type 'bearer' needs credentials.token (or credentials_env.token)")
            return {"Authorization": f"Bearer {token}"}, [token]
        if auth_type == "basic":
            user, pw = self._cred("username"), self._cred("password")
            if not user or not pw:
                raise ValueError("auth_type 'basic' needs credentials.username and credentials.password")
            raw = base64.b64encode(f"{user}:{pw}".encode()).decode()
            return {"Authorization": f"Basic {raw}"}, [pw, raw]
        key = self._cred("api_key")
        if not key:
            raise ValueError("auth_type 'api_key' needs credentials.api_key (or credentials_env.api_key)")
        header = str(self.config.get("api_key_header", "X-API-Key"))
        return {header: key}, [key]

    def _timeout(self) -> float:
        try:
            value = float(self.config.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout must be a number of seconds") from exc
        if value <= 0:
            raise ValueError("timeout must be positive")
        return min(value, MAX_TIMEOUT)

    def _max_bytes(self) -> int:
        try:
            value = int(self.config.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES))
        except (TypeError, ValueError) as exc:
            raise ValueError("max_response_bytes must be an integer") from exc
        if value <= 0:
            raise ValueError("max_response_bytes must be positive")
        return min(value, HARD_MAX_RESPONSE_BYTES)

    def _allowed_hosts(self) -> set[str]:
        return {str(h).lower() for h in (self.config.get("allowed_hosts") or [])}

    def _verify(self, host: str) -> bool | ssl.SSLContext:
        """TLS verification: on by default; ``ca_cert_path`` pins trust to one CA file (hostname still
        checked); ``verify_ssl: false`` turns it off, loudly."""
        ca_path = self.config.get("ca_cert_path")
        disabled = self.config.get("verify_ssl", True) is False
        if ca_path:
            if disabled:
                raise ValueError("ca_cert_path and verify_ssl=false contradict each other")
            try:
                return ssl.create_default_context(cafile=str(ca_path))
            except (OSError, ssl.SSLError) as exc:
                raise ValueError(f"ca_cert_path: cannot load a CA certificate from the configured file ({type(exc).__name__})") from exc
        if disabled:
            logger.warning("rest_tls_verification_disabled", host=host)
            return False
        return True

    # ── lifecycle ────────────────────────────────────────────

    async def _do_connect(self) -> None:
        if self._client and not self._client.is_closed:
            return
        base_url = str(self.config.get("base_url") or "")
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base_url must be an absolute http(s) URL")
        if parts.username or parts.password:
            raise ValueError("base_url must not embed credentials; use credentials/credentials_env")
        allowed = self._allowed_hosts()
        if allowed and parts.hostname.lower() not in allowed:
            raise ValueError("base_url host is not in allowed_hosts")
        retries = max(0, min(int(self.config.get("retry_count", 0) or 0), MAX_RETRIES))
        timeout = self._timeout()
        self._max_bytes()
        self._auth_headers, self._secrets = self._build_auth()
        headers = {str(k): str(v) for k, v in (self.config.get("headers") or {}).items()}
        self._policy = RetryPolicy.from_config(self.config.get("retry"))
        verify = self._verify(parts.hostname)
        # verify goes on the transport: httpx ignores client-level verify when a transport is supplied.
        transport = httpx.AsyncHTTPTransport(retries=retries, verify=verify)
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            headers=headers,
            timeout=httpx.Timeout(timeout),
            transport=transport,
            follow_redirects=False,
            trust_env=self.config.get("trust_env") is True,
        )
        logger.info("rest_client_created", host=parts.hostname)

    async def _do_disconnect(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    # ── request pipeline ─────────────────────────────────────

    @staticmethod
    def _relative(endpoint: Any) -> str:
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("Missing required parameter: endpoint")
        path_part = endpoint.split("?")[0]
        if "://" in endpoint or endpoint.startswith("//") or "\\" in endpoint or "@" in path_part:
            raise _RefusedError("invalid_endpoint", "endpoint must be a path relative to base_url")
        if ".." in path_part.split("/"):
            raise _RefusedError("invalid_endpoint", "endpoint must not contain '..' segments")
        return endpoint.lstrip("/")

    async def _check_destination(self, url: httpx.URL) -> None:
        if url.scheme not in ("http", "https"):
            raise _RefusedError("blocked_destination", "only http and https are allowed")
        host = url.host
        allowed = self._allowed_hosts()
        if allowed and host.lower() not in allowed:
            raise _RefusedError("blocked_destination", f"host '{host}' is not in allowed_hosts")
        if self.config.get("allow_private_network") is True:
            return
        port = url.port or (443 if url.scheme == "https" else 80)
        try:
            addresses = await _resolve(host, port)
        except OSError as exc:
            raise _RefusedError("connection_failed", f"cannot resolve host '{host}'") from exc
        for ip in addresses:
            if _ip_is_blocked(ip):
                raise _RefusedError(
                    "blocked_destination",
                    f"host '{host}' resolves to a private, loopback, link-local or reserved address; "
                    "set allow_private_network only for local use",
                )

    def _redact(self, text: str) -> str:
        for secret in self._secrets:
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return text

    def _fail(self, code: str, detail: str, **data: Any) -> AdapterResponse:
        return AdapterResponse(success=False, error=f"{code}: {self._redact(detail)}", data={"error": code, **data})

    async def _send(self, method: str, endpoint: Any, params: dict[str, Any]) -> AdapterResponse:
        deadline = self._timeout()
        started = time.monotonic()
        policy = self._policy
        allowed = policy.max_attempts if method in policy.methods else 1
        attempt = 0
        try:
            async with asyncio.timeout(deadline):
                while True:
                    attempt += 1
                    result, transient = await self._attempt(method, endpoint, params, deadline)
                    if result.success:
                        result.metadata["attempts"] = attempt
                        return result
                    if attempt > 1:
                        result.data = {**(result.data or {}), "attempts": attempt}
                    if not transient or attempt >= allowed:
                        return result
                    delay = self._retry_delay(attempt, result)
                    if delay is None:
                        result.data = {**(result.data or {}), "retry": "retry_after_exceeds_cap"}
                        return result
                    if delay >= deadline - (time.monotonic() - started):
                        result.data = {**(result.data or {}), "retry": "retry_budget_exhausted"}
                        return result
                    logger.info("rest_retry", method=method, attempt=attempt, delay=round(delay, 3),
                                status=(result.data or {}).get("status_code"))
                    await self._sleep(delay)
        except TimeoutError:
            return self._fail("timeout", f"no complete response within {deadline:g}s",
                              **({"attempts": attempt} if attempt > 1 else {}))

    def _retry_delay(self, attempt: int, result: AdapterResponse) -> float | None:
        """Seconds to wait before the next attempt, or ``None`` if the server asked for longer than we allow."""
        policy = self._policy
        backoff = min(policy.backoff_max, policy.backoff_base * (2 ** (attempt - 1)))
        backoff += random.uniform(0, policy.jitter * backoff)  # noqa: S311 - jitter, not security
        asked = _retry_after_seconds(((result.data or {}).get("headers") or {}).get("retry-after"))
        if asked is None:
            return backoff
        if asked > policy.max_retry_after:
            return None
        return max(backoff, asked)

    async def _attempt(
        self, method: str, endpoint: Any, params: dict[str, Any], deadline: float
    ) -> tuple[AdapterResponse, bool]:
        """One try. Returns the response and whether the failure is transient (worth retrying)."""
        try:
            result = await self._send_inner(method, endpoint, params, self._max_bytes())
        except _RefusedError as exc:
            return self._fail(exc.code, exc.detail), False
        except httpx.ConnectTimeout:
            return self._fail("timeout", f"no connection within {deadline:g}s"), True
        except httpx.TimeoutException:
            return self._fail("timeout", f"no response within {deadline:g}s"), False
        except httpx.HTTPError as exc:
            # Class name only: httpx messages can include the URL (and so a query-string secret).
            tls_failure = _caused_by_tls(exc)
            return self._fail("connection_failed", type(exc).__name__), not tls_failure
        transient = (
            not result.success
            and (result.data or {}).get("error") == "http_error"
            and (result.data or {}).get("status_code") in self._policy.statuses
        )
        return result, transient

    async def _send_inner(
        self, method: str, endpoint: Any, params: dict[str, Any], max_bytes: int
    ) -> AdapterResponse:
        client = self._client
        assert client is not None
        url = client.base_url.join(self._relative(endpoint))
        base = client.base_url
        if (url.scheme, url.host, url.port) != (base.scheme, base.host, base.port):
            raise _RefusedError("blocked_destination", "request left the configured base_url origin")
        kwargs: dict[str, Any] = {"headers": self._auth_headers}
        if params.get("query_params"):
            kwargs["params"] = params["query_params"]
        if method in _BODY_METHODS and params.get("json_body") is not None:
            kwargs["json"] = params["json_body"]
        for hop in range(MAX_REDIRECTS + 1):
            await self._check_destination(url)
            request = client.build_request(method.upper(), url, **kwargs)
            logger.info("rest_request", method=method, host=url.host, path=url.path, hop=hop)
            response = await client.send(request, stream=True, follow_redirects=False)
            try:
                if not response.is_redirect:
                    return await self._read(response, max_bytes)
                status = response.status_code
                location = response.headers.get("location")
                if not location:
                    return self._fail("redirect_refused", "redirect without Location", status_code=status)
                target = url.join(location)
                if (target.scheme, target.host, target.port) != (url.scheme, url.host, url.port):
                    return self._fail(
                        "redirect_refused",
                        f"redirect to a different origin ({target.scheme}://{target.host}) was not followed",
                        status_code=status,
                    )
                if method not in ("get", "head"):
                    return self._fail(
                        "redirect_refused", f"{method.upper()} redirect was not followed", status_code=status
                    )
                url = target
                kwargs.pop("params", None)  # the Location already carries its query
            finally:
                await response.aclose()
        return self._fail("redirect_refused", f"more than {MAX_REDIRECTS} redirects")

    async def _read(self, response: httpx.Response, max_bytes: int) -> AdapterResponse:
        status = response.status_code
        headers = {k: self._redact(response.headers[k]) for k in _PASS_HEADERS if k in response.headers}
        declared = response.headers.get("content-length", "")
        truncated = declared.isdigit() and int(declared) > max_bytes
        buf = bytearray()
        if not truncated:
            async for chunk in response.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    truncated = True
                    break
        text = self._redact(bytes(buf[:max_bytes]).decode(response.encoding or "utf-8", errors="replace"))
        if truncated:
            return self._fail(
                "response_too_large",
                f"response exceeded max_response_bytes={max_bytes}; the rest was not read",
                status_code=status, headers=headers, body=text[:ERROR_BODY_CHARS], truncated=True,
            )
        if not 200 <= status < 300:
            return self._fail(
                "http_error", f"HTTP {status}", status_code=status, headers=headers,
                body=text[:ERROR_BODY_CHARS], truncated=len(text) > ERROR_BODY_CHARS,
            )
        body: Any = text
        if "json" in response.headers.get("content-type", "").lower() and text:
            try:
                body = json.loads(text)
            except ValueError:
                body = text
        return AdapterResponse(
            success=True,
            data={"status_code": status, "headers": headers, "body": body, "truncated": False},
            metadata={"status_code": status},
        )

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """Probe ``validate_path`` (default ``/``): 2xx ok, 401/403 raise, any other status is ``unchecked``."""
        if not self._client:
            raise ConnectionError("Adapter is not connected. Cannot validate credentials.")
        path = str(self.config.get("validate_path", "/"))
        result = await self._send("head", path, {})
        if (result.data or {}).get("status_code") == 405:
            result = await self._send("get", path, {})
        data = result.data or {}
        status = data.get("status_code")
        if result.success:
            return {
                "status": "ok" if self._auth_headers else "reachable",
                "http_status": status,
                "message": "Request accepted." if self._auth_headers else "Reachable; no credentials configured.",
            }
        if status in (401, 403):
            raise ValueError(f"Credentials rejected by the server (HTTP {status})")
        if status is None:
            raise ConnectionError(result.error or "request failed")
        return {
            "status": "unchecked",
            "http_status": status,
            "message": f"Server answered HTTP {status}; credentials could not be confirmed.",
        }

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> Any:
        if not self._client:
            raise ConnectionError("HTTP client is not initialized. Please connect first.")
        if operation not in self.supported_operations:
            raise ValueError(f"Unsupported operation: {operation}")
        try:
            return await self._send(operation, params.get("endpoint"), params)
        except ValueError as exc:
            return self._fail("invalid_request", str(exc))

    def _get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "format": "uri", "description": "Absolute http(s) base URL."},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "auth_type": {"type": "string", "enum": list(_AUTH_TYPES), "default": "none"},
                "api_key_header": {"type": "string", "default": "X-API-Key"},
                "credentials": {"type": "object", "description": "token | username+password | api_key"},
                "credentials_env": {"type": "object", "description": "Same keys, naming environment variables."},
                "allowed_hosts": {"type": "array", "items": {"type": "string"}},
                "allow_private_network": {"type": "boolean", "default": False},
                "timeout": {"type": "number", "default": DEFAULT_TIMEOUT, "minimum": 1, "maximum": MAX_TIMEOUT},
                "verify_ssl": {"type": "boolean", "default": True},
                "ca_cert_path": {"type": "string", "description": "PEM file; trust only this CA (hostname still checked)."},
                "retry": {
                    "type": "object",
                    "description": "Request retries; off unless max_attempts > 1. Idempotent methods only.",
                    "properties": {
                        "max_attempts": {"type": "integer", "default": 1, "minimum": 1, "maximum": MAX_ATTEMPTS},
                        "methods": {"type": "array", "items": {"enum": list(_RETRYABLE_METHODS)}, "default": ["get", "head"]},
                        "retry_on_status": {"type": "array", "items": {"type": "integer"}},
                        "backoff_base": {"type": "number", "default": 0.2},
                        "backoff_max": {"type": "number", "default": 5},
                        "backoff_jitter": {"type": "number", "default": 0.25},
                        "max_retry_after": {"type": "number", "default": 30, "maximum": MAX_RETRY_AFTER_CAP},
                    },
                },
                "retry_count": {"type": "integer", "default": 0, "minimum": 0, "maximum": MAX_RETRIES},
                "max_response_bytes": {
                    "type": "integer", "default": DEFAULT_MAX_RESPONSE_BYTES, "maximum": HARD_MAX_RESPONSE_BYTES,
                },
                "validate_path": {"type": "string", "default": "/"},
            },
            "required": ["base_url"],
        }
