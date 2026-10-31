"""The network seam: a one-method Protocol and the errors a transport may raise.

Nothing here imports a network client. Parsing, storage and the CLI's offline verbs depend
only on this module, so the whole package can be used (and tested) without a socket. The one
real implementation is :mod:`assurance.intel.transport_urllib`, imported only by
``refresh --live``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

__all__ = ["HostNotAllowed", "RedirectRefused", "ResponseTooLarge", "Transport",
           "TransportError"]


class TransportError(Exception):
    """A request that produced no usable response. The message never carries a header."""


class HostNotAllowed(TransportError):  # noqa: N818
    """The URL is not https, or its host is not on the exact-host allow-list."""


class RedirectRefused(TransportError):  # noqa: N818
    """The server redirected somewhere this transport will not follow."""


class ResponseTooLarge(TransportError):  # noqa: N818
    """The body exceeded the size cap. ``partial`` is only what was read before stopping."""

    def __init__(self, message: str, *, status: int, partial: bytes) -> None:
        super().__init__(message)
        self.status = status
        self.partial = partial


class Transport(Protocol):
    """``get(url, headers, timeout) -> (http status, raw body bytes)``.

    A non-2xx status is returned, not raised: the caller records it. Raise
    :class:`TransportError` only when there is no response to record.
    """

    def get(self, url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        ...
