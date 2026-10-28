"""Responses that must not be stored by a browser, a proxy or a CDN.

A plaintext API key is shown once; an export is a customer's evidence. A shared cache that
keeps either is a second copy nobody manages. ``Cache-Control: no-store`` (and ``Pragma:
no-cache`` for old intermediaries) is set here, in one place, rather than route by route:
a new export route that forgets would otherwise be cacheable without anyone noticing, and
``tests/test_assurance_ops_hardening.py`` fails if a route with ``export`` in its path is
not covered by :func:`is_no_store`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

__all__ = ["NoStoreMiddleware", "is_no_store"]

#: (method, path) pairs that mint or hand over a plaintext key.
_KEY_ROUTES = frozenset({
    ("POST", "/v1/keys"), ("POST", "/v1/operators"), ("GET", "/v1/checkout/complete"),
})
_REPORTS = frozenset({("GET", "/v1/fleet/report")})


def is_no_store(method: str, path: str) -> bool:
    """Whether the response to ``method path`` carries a key or an export."""
    path = path.rstrip("/") or "/"
    return ((method, path) in _KEY_ROUTES or (method, path) in _REPORTS
            or path.endswith("/export"))


class NoStoreMiddleware:
    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or not is_no_store(
                str(scope.get("method", "")), str(scope.get("path", ""))):
            await self.app(scope, receive, send)
            return

        async def send_no_store(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"cache-control", b"pragma")]
                headers += [(b"cache-control", b"no-store"), (b"pragma", b"no-cache")]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_no_store)
