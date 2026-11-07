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
          timeout: 30                  # overall seconds per request (max 120)
          verify_ssl: true
          retry_count: 2               # connection-establishment retries only (max 5; default 0)
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
import socket
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
_PASS_HEADERS = ("content-type", "content-length", "etag", "last-modified", "retry-after", "x-request-id")
_AUTH_TYPES = ("none", "bearer", "basic", "api_key")


class _RefusedError(Exception):
    """A request the adapter will not send (policy). ``code`` is returned to the caller; ``detail`` has no secrets."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


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
    #: Exercised by tests/test_rest_adapter.py against a real local HTTP server (not a third-party service).
    backend: str = "real"
    supported_operations: list[str] = ["get", "post", "put", "patch", "delete", "head"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._auth_headers: dict[str, str] = {}
        self._secrets: list[str] = []

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
        verify = self.config.get("verify_ssl", True) is not False
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
        try:
            async with asyncio.timeout(deadline):
                return await self._send_inner(method, endpoint, params, self._max_bytes())
        except TimeoutError:
            return self._fail("timeout", f"no complete response within {deadline:g}s")
        except _RefusedError as exc:
            return self._fail(exc.code, exc.detail)
        except httpx.TimeoutException:
            return self._fail("timeout", f"no response within {deadline:g}s")
        except httpx.HTTPError as exc:
            # Class name only: httpx messages can include the URL (and so a query-string secret).
            return self._fail("connection_failed", type(exc).__name__)

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
                "retry_count": {"type": "integer", "default": 0, "minimum": 0, "maximum": MAX_RETRIES},
                "max_response_bytes": {
                    "type": "integer", "default": DEFAULT_MAX_RESPONSE_BYTES, "maximum": HARD_MAX_RESPONSE_BYTES,
                },
                "validate_path": {"type": "string", "default": "/"},
            },
            "required": ["base_url"],
        }
