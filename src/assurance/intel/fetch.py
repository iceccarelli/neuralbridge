"""Turn "some bytes arrived" into exactly one recorded observation.

Every path ends in :meth:`IntelStore.append`: a good feed, a malformed one, a non-200, an
oversized body and a transport failure each leave one row with the sha256 of what was seen.
A rejected observation changes nothing else (no blob, no baseline). No network client is
imported here; the transport is injected.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from assurance.core.identity import utc_now
from assurance.intel.parsers import PARSER_VERSION, FeedRejected, parser_for
from assurance.intel.sources import SOURCES, Source, resolve_source
from assurance.intel.store import IntelStore, Observation
from assurance.intel.transport import (
    HostNotAllowed,
    RedirectRefused,
    ResponseTooLarge,
    Transport,
    TransportError,
)

__all__ = ["RequestHeaders", "build_headers", "fetch", "ingest_bytes", "ingest_file"]

log = logging.getLogger("assurance.intel")

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SENSITIVE = {"apikey", "authorization", "x-api-key"}


class RequestHeaders(dict):
    """Request headers whose ``repr`` redacts credentials. Values are never printed."""

    def __repr__(self) -> str:
        shown = {k: ("<redacted>" if k.lower() in _SENSITIVE else v) for k, v in self.items()}
        return f"RequestHeaders({shown!r})"

    __str__ = __repr__


def build_headers(source: Source, *, api_key_env: str | None = None,
                  environ: Mapping[str, str] | None = None) -> RequestHeaders:
    """Headers for a request. ``api_key_env`` is the *name* of an environment variable.

    The NVD key, when that variable is set and non-empty, goes in the ``apiKey`` header and
    nowhere else: not in the URL, the observation, the log or any message.
    """
    headers = RequestHeaders({"Accept": "application/json"})
    if api_key_env:
        if not _ENV_NAME.match(api_key_env):
            raise ValueError("the api-key option takes the NAME of an environment variable")
        if source.id != "nvd_cve_api":
            raise ValueError(f"{source.id} takes no API key")
        value = (os.environ if environ is None else environ).get(api_key_env, "")
        if value:
            headers["apiKey"] = value
    return headers


def ingest_bytes(
    store: IntelStore, source_id: str, raw: bytes, *, url: str, locator: str, via: str,
    http_status: int | None, retrieved_at: datetime | None = None, max_bytes: int | None = None,
    reason_prefix: str = "", provenance: dict[str, Any] | None = None,
) -> Observation:
    """Parse ``raw`` and record the outcome, accepted or rejected."""
    source = SOURCES[source_id]
    cap = max_bytes or source.max_bytes
    sha = hashlib.sha256(raw).hexdigest()
    when = retrieved_at or utc_now()
    try:
        parsed = parser_for(source_id)(raw, cap)
    except FeedRejected as exc:
        log.info("intel: %s rejected (%s)", source_id, str(exc).split(":", 1)[0])
        return store.append(
            source=source_id, url=url, locator=locator, via=via, retrieved_at=when,
            http_status=http_status, byte_length=len(raw), sha256=sha,
            parser_version=PARSER_VERSION, parse_result="malformed",
            reason=reason_prefix + str(exc), provenance=provenance)
    obs = store.append(
        source=source_id, url=url, locator=locator, via=via, retrieved_at=when,
        http_status=http_status, byte_length=len(raw), sha256=sha,
        parser_version=PARSER_VERSION, parse_result="ok", reason="", raw=raw, parsed=parsed,
        provenance=provenance)
    log.info("intel: %s %s seq=%d", source_id, obs.disposition, obs.seq)
    return obs


def ingest_file(store: IntelStore, source_id: str, path: str | Path, *,
                retrieved_at: datetime | None = None, url: str | None = None) -> Observation:
    """Record a local file as an observation of ``source_id``. Opens no socket.

    The series URL is the source's canonical URL (a file of the KEV catalogue is the next
    observation of the KEV catalogue); ``locator`` records where the bytes really came from.
    """
    source = SOURCES[source_id]
    p = Path(path)
    if not p.is_file():
        raise TransportError(f"{p} is not a regular file")
    with p.open("rb") as handle:
        raw = handle.read(source.max_bytes + 1)
    return ingest_bytes(store, source_id, raw, url=url or source.url or f"file:{p.name}",
                        locator=f"file:{p.name}", via="file", http_status=None,
                        retrieved_at=retrieved_at)


def fetch(
    store: IntelStore, source: str, url: str, transport: Transport, *,
    headers: Mapping[str, str] | None = None, timeout: float = 30.0,
    max_bytes: int | None = None, clock: Callable[[], datetime] = utc_now,
    provenance: dict[str, Any] | None = None,
) -> Observation:
    """One GET through the injected transport, recorded whatever happens."""
    src = resolve_source(source)
    if src.url and not url.startswith(src.url):
        raise ValueError(f"{url!r} is not a {src.id} URL")
    when = clock()
    try:
        status, raw = transport.get(url, headers or {}, timeout)
    except ResponseTooLarge as exc:
        return _rejected(store, src, url, when, exc.status, exc.partial,
                         f"oversized: the body exceeded the size cap ({exc}); the sha256 "
                         "covers only the bytes read before stopping", provenance)
    except TransportError as exc:
        # A refused host/redirect is a verdict; any other transport failure is transient.
        return _rejected(store, src, url, when, 0, b"", f"transport_error: {exc}",
                         _settle(provenance, permanent=isinstance(
                             exc, (HostNotAllowed, RedirectRefused))))
    if status != 200:
        permanent = 400 <= status < 500 and status != 429
        return _rejected(store, src, url, when, status, raw, f"http_status: {status}",
                         _settle(provenance, permanent=permanent))
    return ingest_bytes(store, src.id, raw, url=url, locator=url, via="network",
                        http_status=status, retrieved_at=when, max_bytes=max_bytes,
                        provenance=provenance)


def _settle(provenance: dict[str, Any] | None, *, permanent: bool) -> dict[str, Any] | None:
    return None if provenance is None else {**provenance, "settled": permanent}


def _rejected(store: IntelStore, src: Source, url: str, when: datetime, status: int,
              raw: bytes, reason: str, provenance: dict[str, Any] | None = None
              ) -> Observation:
    return store.append(
        source=src.id, url=url, locator=url, via="network", retrieved_at=when,
        http_status=status, byte_length=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        parser_version=PARSER_VERSION, parse_result="malformed", reason=reason,
        provenance=provenance)
