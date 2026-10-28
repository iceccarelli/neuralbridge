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
_PATTERN = re.compile(
    r"([?&](?:" + "|".join(REDACTED_PARAMS) + r")=)[^&\s\"']*", re.IGNORECASE)


def _scrub(value: object) -> object:
    return _PATTERN.sub(r"\1[redacted]", value) if isinstance(value, str) else value


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
