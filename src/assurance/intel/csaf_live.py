"""Live CSAF 2.0 refresh from an operator-named provider (``intel refresh --source csaf``).

A CSAF provider is vendor-specific, so nothing is defaulted: the operator names the host(s)
with ``--allow-host`` and every URL touched, including the ``directory_url`` a provider's own
metadata announces, must be on that exact list before a request is made. A vendor advisory
describes a *product*; it does not say what any customer has installed, and a document that
is fetched is still only an unsigned, inspect-only import.

Two modes
---------
``--url U`` (repeatable)
    each URL is one CSAF document. Fetched through the existing seam, one observation each.

``--provider-metadata-url U``
    ``provider-metadata.json`` (CSAF 2.0 section 7.1.4/7.1.5) -> the first ``distributions[]``
    ``directory_url`` on an allowed host -> ``changes.csv`` (section 7.1.12: path and last-change
    time per document) or, when the provider has none, ``index.txt`` (paths only, so no
    incremental cursor: every listed document is a candidate). A provider that announces only
    a TLP:WHITE ROLIE feed (``distributions[].rolie.feeds[]``, RFC 8322 JSON; found live:
    Siemens ProductCERT) is read from that feed: ``entry[].content.src`` and ``updated``.

Incremental, truncation-safe
----------------------------
There is no stored cursor to corrupt. A listed document is skipped when this store already
holds a *settled* observation of its URL whose recorded ``listed_at`` is not older than the
listing's. So a first run capped by ``--max-documents`` simply leaves the rest for the next
run, newest first, and says how many ("N more not fetched"); it never silently truncates. A
transient failure (transport error, 429, 5xx) is not settled and is retried next run; a
malformed or oversized document is settled until the provider lists it again as changed.

Bounds: ``max_documents`` fetches, ``max_total_bytes`` across everything fetched (checked
before each request, so the overshoot is at most one document), a per-document byte cap, and
a stop on 429/503 (the provider asked us to slow down; the rest is reported as not fetched).
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.intel.fetch import RequestHeaders, build_headers, fetch
from assurance.intel.parsers import INTERIM_REFUSAL
from assurance.intel.sources import SOURCES
from assurance.intel.store import IntelStore, Observation
from assurance.intel.transport import Transport, TransportError

__all__ = ["CsafRefusal", "CsafRunReport", "DEFAULT_MAX_DOCUMENTS", "DEFAULT_MAX_TOTAL_BYTES",
           "normalise_allow_hosts", "refresh_documents", "refresh_provider"]

DEFAULT_MAX_DOCUMENTS = 50
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_ROLIE_BYTES = 8 * 1024 * 1024
MAX_INDEX_ROWS = 200_000
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*\.json$")
_STOP_STATUSES = (429, 503)


class CsafRefusal(Exception):  # noqa: N818 - the verdict: this run cannot start or continue
    """A usage or safety refusal. The message never carries a URL query, header or secret."""


@dataclass
class CsafRunReport:
    provider: str
    listed: int = 0
    up_to_date: int = 0
    skipped_rows: int = 0
    refused: list[str] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    not_fetched: int = 0
    stopped: str = ""
    index_kind: str = ""
    index_status: dict[str, Any] = field(default_factory=dict)
    bytes_fetched: int = 0

    @property
    def rejected(self) -> int:
        return sum(o.disposition == "rejected" for o in self.observations) + len(self.refused)

    @property
    def interim_refused(self) -> int:
        """Documents refused only because their tracking status was interim."""
        return sum(o.disposition == "rejected" and o.reason == INTERIM_REFUSAL
                   for o in self.observations)

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(("first", "changed", "unchanged", "rejected"), 0)
        for o in self.observations:
            out[o.disposition] += 1
        return out


# --------------------------------------------------------------------------- safety checks
def normalise_allow_hosts(hosts: Iterable[str]) -> frozenset[str]:
    """Exact lower-case DNS names only. No scheme, port, path, wildcard or empty entry."""
    out = set()
    for raw in hosts:
        h = (raw or "").strip().lower()
        if not _HOST.match(h):
            raise CsafRefusal("--allow-host takes a bare host name such as "
                              "cert.example.com (no scheme, port, path or wildcard)")
        out.add(h)
    if not out:
        raise CsafRefusal("--allow-host is required for csaf: a CSAF provider is "
                          "vendor-specific, so the operator must name the host")
    return frozenset(out)


def _safe_label(url: str) -> str:
    """host + path only: what may be printed or logged about a URL.

    Plain string handling on purpose: this module imports no URL library (the pinned list of
    network-importing modules stays as it is); the real parsing is ``check_url``'s.
    """
    rest = url.split("://", 1)[-1].split("#", 1)[0].split("?", 1)[0]
    host, _, path = rest.partition("/")
    return f"{host.rpartition('@')[2]}/{path}"[:200]


def _check(url: str, allowed: frozenset[str]) -> str:
    """The host if ``url`` is an acceptable CSAF URL; raises CsafRefusal otherwise."""
    from assurance.intel.transport import HostNotAllowed
    from assurance.intel.transport_urllib import check_url

    if "?" in url or "#" in url:
        raise CsafRefusal(f"{_safe_label(url)}: a URL with a query or fragment is refused "
                          "(credentials must never travel in a URL)")
    try:
        return check_url(url, allowed)
    except HostNotAllowed as exc:
        raise CsafRefusal(f"{_safe_label(url)}: {exc}; name the host with --allow-host "
                          "only if you trust this provider") from exc


def _provider_key(url: str) -> str:
    return url


# --------------------------------------------------------------------------- single documents
def refresh_documents(
    store: IntelStore, urls: list[str], transport: Transport, *, allowed_hosts: Iterable[str],
    timeout: float = 30.0, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    clock: Callable[[], datetime] = utc_now, allow_interim: bool = False,
) -> CsafRunReport:
    """Fetch named CSAF document URLs; one observation each.

    ``allow_interim`` is the operator's explicit option: ``interim`` documents are imported
    (still unsigned, inspect-only); ``draft`` and every other refusal are unchanged.
    """
    allowed = normalise_allow_hosts(allowed_hosts)
    if not urls:
        raise CsafRefusal("give at least one --url or a --provider-metadata-url")
    hosts = [_check(u, allowed) for u in urls]   # all-or-nothing: refuse before any request
    report = CsafRunReport(provider="direct", listed=len(urls))
    headers = build_headers(SOURCES["csaf"])
    for i, u in enumerate(urls):
        if report.bytes_fetched >= max_total_bytes:
            report.not_fetched = len(urls) - i
            report.stopped = "total byte cap reached"
            break
        obs = fetch(store, "csaf", u, transport, headers=headers, timeout=timeout, clock=clock,
                    provenance={"provider": f"direct:{hosts[i]}", "listed_at": "",
                                "mode": "direct-url"}, allow_interim=allow_interim)
        report.observations.append(obs)
        report.bytes_fetched += obs.byte_length
        if obs.http_status in _STOP_STATUSES:
            report.not_fetched = len(urls) - i - 1
            report.stopped = f"provider answered {obs.http_status}"
            break
    return report


# --------------------------------------------------------------------------- provider mode
@dataclass(frozen=True)
class _Entry:
    path: str
    url: str
    listed_at: str      # normalised UTC, or "" when the provider lists no time


def _get(transport: Transport, url: str, headers: RequestHeaders, timeout: float,
         cap: int, what: str, report: CsafRunReport) -> bytes:
    try:
        status, body = transport.get(url, headers, timeout)
    except TransportError as exc:
        raise CsafRefusal(f"{what} ({_safe_label(url)}) could not be fetched: {exc}") from exc
    report.bytes_fetched += len(body)
    report.index_status[what] = {"url": _safe_label(url), "http_status": status,
                                 "bytes": len(body)}
    if status != 200:
        raise CsafRefusal(f"{what} ({_safe_label(url)}) answered HTTP {status}")
    if len(body) > cap:
        raise CsafRefusal(f"{what} ({_safe_label(url)}) is {len(body)} bytes, over the "
                          f"{cap}-byte cap")
    return body


def _directory_urls(meta_raw: bytes, allowed: frozenset[str]
                    ) -> tuple[list[str], list[str], dict[str, str]]:
    """(directory urls, ROLIE feed urls, publisher info) the metadata announces on allowed hosts.

    Some providers (found live: Siemens ProductCERT) publish ROLIE feeds only and no
    ``directory_url``; both are read, directories first.
    """
    try:
        meta = json.loads(meta_raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CsafRefusal("provider-metadata.json is not valid UTF-8 JSON") from exc
    if not isinstance(meta, dict) or not isinstance(meta.get("distributions"), list):
        raise CsafRefusal("provider-metadata.json has no distributions[] list")
    if meta.get("metadata_version", "2.0") != "2.0":
        raise CsafRefusal("provider-metadata.json is not metadata_version 2.0")
    pub = meta.get("publisher") if isinstance(meta.get("publisher"), dict) else {}
    info = {k: str(pub.get(k, ""))[:200] for k in ("name", "namespace", "category")}
    dirs: list[str] = []
    refused: list[str] = []
    feeds: list[str] = []
    for d in meta["distributions"]:
        if not isinstance(d, dict):
            continue
        candidates: list[tuple[str, list[str]]] = []
        if isinstance(d.get("directory_url"), str):
            candidates.append((d["directory_url"], dirs))
        rolie = d.get("rolie")
        for f in (rolie.get("feeds") if isinstance(rolie, dict)
                  and isinstance(rolie.get("feeds"), list) else []):
            # Only TLP:WHITE (public) feeds; a feed with another label is not for this reader.
            if (isinstance(f, dict) and isinstance(f.get("url"), str)
                    and str(f.get("tlp_label", "WHITE")).upper() == "WHITE"):
                candidates.append((f["url"], feeds))
        for url, bucket in candidates:
            try:
                _check(url, allowed)
            except CsafRefusal as exc:
                refused.append(str(exc))
                continue
            bucket.append(url.rstrip("/") if bucket is dirs else url)
    if not dirs and not feeds:
        hint = refused[0] if refused else "it announces no directory_url or WHITE ROLIE feed"
        raise CsafRefusal(f"no usable directory_url or ROLIE feed in the provider metadata: "
                          f"{hint}")
    return dirs, feeds, info


def _rolie_entries(body: bytes, report: CsafRunReport, allowed: frozenset[str]
                   ) -> list[_Entry]:
    """Entries of a ROLIE JSON feed (RFC 8322 section 5): ``content.src`` and ``updated``."""
    try:
        feed = json.loads(body.decode("utf-8-sig")).get("feed")
        rows = feed["entry"]
        if not isinstance(rows, list):
            raise TypeError
    except (UnicodeDecodeError, ValueError, AttributeError, KeyError, TypeError) as exc:
        raise CsafRefusal("the ROLIE feed is not a JSON feed with an entry list") from exc
    seen: dict[str, _Entry] = {}
    for n, row in enumerate(rows):
        if n >= MAX_INDEX_ROWS:
            report.stopped = "ROLIE feed longer than the row limit; the rest is ignored"
            break
        try:
            src = row["content"]["src"]
            stamp = format_utc(parse_utc(row["updated"]))
            ok = (isinstance(src, str) and len(src) <= 300 and src.startswith("https://")
                  and src.endswith(".json") and "?" not in src and "#" not in src)
        except (KeyError, TypeError, ValueError, AttributeError):
            ok, src, stamp = False, "", ""
        if not ok:
            report.skipped_rows += 1                # unusable link or time: counted, not guessed
            continue
        try:
            _check(src, allowed)
        except CsafRefusal:
            report.refused.append(_safe_label(src))
            continue
        old = seen.get(src)
        if old is None or stamp > old.listed_at:
            seen[src] = _Entry(src.rsplit("/", 1)[-1], src, stamp)
    by_path = sorted(seen.values(), key=lambda e: e.path)
    return sorted(by_path, key=lambda e: e.listed_at, reverse=True)


def _entries(directory: str, body: bytes, kind: str, report: CsafRunReport,
             allowed: frozenset[str]) -> list[_Entry]:
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsafRefusal(f"{kind} is not UTF-8") from exc
    seen: dict[str, _Entry] = {}
    rows = (csv.reader(io.StringIO(text)) if kind == "changes.csv"
            else ([ln.strip()] for ln in text.splitlines()))
    for n, row in enumerate(rows):
        if n >= MAX_INDEX_ROWS:
            report.stopped = f"{kind} longer than {MAX_INDEX_ROWS} rows; the rest is ignored"
            break
        if not row or not "".join(row).strip():
            continue
        path = row[0].strip()
        stamp = ""
        if kind == "changes.csv":
            try:
                stamp = format_utc(parse_utc(row[1])) if len(row) >= 2 else ""
            except ValueError:
                stamp = ""
            if not stamp:
                report.skipped_rows += 1        # no usable time: counted, never guessed
                continue
        if not _PATH.match(path) or len(path) > 200:
            report.skipped_rows += 1
            continue
        url = f"{directory}/{path}"
        try:
            _check(url, allowed)
        except CsafRefusal:
            report.refused.append(_safe_label(url))
            continue
        old = seen.get(path)
        if old is None or stamp > old.listed_at:
            seen[path] = _Entry(path, url, stamp)
    if kind == "changes.csv":                   # newest change first, ties by path
        by_path = sorted(seen.values(), key=lambda e: e.path)
        return sorted(by_path, key=lambda e: e.listed_at, reverse=True)
    return sorted(seen.values(), key=lambda e: e.path)


def refresh_provider(
    store: IntelStore, metadata_url: str, transport: Transport, *,
    allowed_hosts: Iterable[str], max_documents: int = DEFAULT_MAX_DOCUMENTS,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES, timeout: float = 30.0,
    max_document_bytes: int | None = None, clock: Callable[[], datetime] = utc_now,
    allow_interim: bool = False,
) -> CsafRunReport:
    """Fetch only the documents of one provider that are new or changed since the last run."""
    allowed = normalise_allow_hosts(allowed_hosts)
    if max_documents < 1:
        raise CsafRefusal("--max-documents must be at least 1")
    _check(metadata_url, allowed)
    provider = _provider_key(metadata_url)
    report = CsafRunReport(provider=_safe_label(provider))
    headers = build_headers(SOURCES["csaf"])

    meta_raw = _get(transport, metadata_url, headers, timeout, MAX_METADATA_BYTES,
                    "provider-metadata.json", report)
    directories, feeds, publisher = _directory_urls(meta_raw, allowed)

    entries: list[_Entry] = []
    directory = ""
    last_error = ""
    for directory in directories:
        for kind in ("changes.csv", "index.txt"):
            try:
                body = _get(transport, f"{directory}/{kind}", headers, timeout,
                            MAX_INDEX_BYTES, kind, report)
            except CsafRefusal as exc:
                last_error = str(exc)
                continue
            report.index_kind = kind
            entries = _entries(directory, body, kind, report, allowed)
            break
        if report.index_kind:
            break
    if not report.index_kind:
        for directory in feeds:
            try:
                body = _get(transport, directory, headers, timeout, MAX_ROLIE_BYTES,
                            "rolie-feed", report)
                entries = _rolie_entries(body, report, allowed)
            except CsafRefusal as exc:
                last_error = str(exc)
                continue
            report.index_kind = "rolie"
            break
    if not report.index_kind:
        raise CsafRefusal(f"no changes.csv, index.txt or ROLIE feed could be read: "
                          f"{last_error}")
    report.listed = len(entries)

    done = store.settled_listings(provider, allow_interim=allow_interim)
    pending = []
    for e in entries:
        have = done.get(e.url)
        if have is not None and e.listed_at and have >= e.listed_at:
            report.up_to_date += 1
        else:
            pending.append(e)

    cap = max_document_bytes or SOURCES["csaf"].max_bytes
    for i, e in enumerate(pending):
        if i >= max_documents:
            report.not_fetched = len(pending) - i
            report.stopped = report.stopped or "max-documents reached"
            break
        if report.bytes_fetched >= max_total_bytes:
            report.not_fetched = len(pending) - i
            report.stopped = "total byte cap reached"
            break
        obs = fetch(store, "csaf", e.url, transport, headers=headers, timeout=timeout,
                    max_bytes=cap, clock=clock,
                    provenance={"provider": provider, "listed_at": e.listed_at,
                                "mode": "provider-metadata", "directory": _safe_label(directory),
                                "publisher": publisher}, allow_interim=allow_interim)
        report.observations.append(obs)
        report.bytes_fetched += obs.byte_length
        if obs.http_status in _STOP_STATUSES:
            report.not_fetched = len(pending) - i - 1
            report.stopped = f"provider answered {obs.http_status}; stopped"
            break
    return report
