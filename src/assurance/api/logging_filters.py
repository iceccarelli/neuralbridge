"""Keep capabilities out of the access log.

``GET /v1/checkout/complete?session_id=cs_...`` is how a browser returning from Stripe
collects its one-time API key: whoever holds that ``session_id`` can claim the key until it
expires (24 hours) or is claimed. The key itself is never logged, but uvicorn's access log
writes the request line, query string included, and logs are shipped and retained by other
systems. The value is replaced before it is formatted.
"""

from __future__ import annotations

import logging
import re

__all__ = ["REDACTED_PARAMS", "RedactQueryFilter", "install"]

#: Query parameters whose value is a bearer capability or a secret.
REDACTED_PARAMS = ("session_id", "api_key", "key", "token", "secret")

_REDACTED = frozenset(REDACTED_PARAMS)
_QUERY = re.compile(r"\?[^\s\"'#]*")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")


def _unquote_plus(text: str) -> str:
    """Percent-decoding of a parameter name, as a query parser does it (no urllib: this module
    must not look like a network client to the import scan)."""
    return _PERCENT.sub(lambda m: chr(int(m.group(1), 16)), text.replace("+", " "))


def _name(raw: str) -> str:
    """A parameter name as the application reads it: percent-decoded (to a fixed point, so a
    name encoded twice is still caught), and lower-cased."""
    for _ in range(4):
        decoded = _unquote_plus(raw)
        if decoded == raw:
            break
        raw = decoded
    return raw.lower()


def _scrub_query(match: re.Match[str]) -> str:
    query = match.group(0)[1:]
    parts = []
    for pair in query.split("&"):
        name, sep, _value = pair.partition("=")
        parts.append(f"{name}=[redacted]" if sep and _name(name) in _REDACTED else pair)
    return "?" + "&".join(parts)


def _scrub(value: object) -> object:
    if not isinstance(value, str):
        return value
    return _QUERY.sub(_scrub_query, value)


class RedactQueryFilter(logging.Filter):
    """Rewrites the query-string values above in a log record's message and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(_scrub(a) for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: _scrub(v) for k, v in record.args.items()}
        record.msg = _scrub(record.msg)
        return True


def install() -> None:
    """Attach the filter to uvicorn's access logger (once). uvicorn configures its loggers
    before it imports the application, and keeps the filters already on them."""
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactQueryFilter) for f in logger.filters):
        logger.addFilter(RedactQueryFilter())
