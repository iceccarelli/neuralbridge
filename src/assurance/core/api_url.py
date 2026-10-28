"""The one rule for where an API key may be sent.

Shared by ``assurance watch push`` and the MCP relay: https, except plain http to loopback;
no credentials, query or fragment in the URL. Pure string handling, no network client, so
both callers can import it without pulling in anything that opens a socket.
"""

from __future__ import annotations

from urllib.parse import urlsplit

__all__ = ["LOOPBACK_HOSTS", "api_url_problem"]

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def api_url_problem(api_url: str) -> str | None:
    """Why a key must not be sent to ``api_url``, or ``None`` if the URL is acceptable."""
    parts = urlsplit(api_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "--api-url must be an http(s) URL, e.g. https://api.example.com"
    if parts.username or parts.password:
        return ("--api-url must not contain credentials. The key comes from "
                "an environment variable.")
    if parts.query or parts.fragment:
        return "--api-url must be a base URL without a query or fragment."
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        return ("refusing to send a key over plain http to a non-loopback host. Use "
                "https (plain http is accepted only for localhost).")
    return None
