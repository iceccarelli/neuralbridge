"""Strict parsers for the four feeds. Pure: bytes in, a :class:`ParsedFeed` or a rejection.

A feed that is not exactly the documented shape is **rejected whole**, never half-read: a
catalogue whose ``count`` disagrees with its entries is truncated or altered, and reading the
part that parsed would make the missing part look like "not listed". Rejection reasons start
with a stable code (``empty``, ``oversized``, ``not_utf8``, ``truncated``, ``bad_json``,
``wrong_shape``, ``truncated_or_altered``, ``duplicate_record``) so callers can count them.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from assurance.fleet.advisory import AdvisoryError
from assurance.fleet.csaf import advisory_from_csaf
from assurance.intel.sources import CVE_ID

__all__ = ["PARSER_VERSION", "FeedRejected", "ParsedFeed", "digest_record", "parse_csaf",
           "parse_epss", "parse_kev", "parse_nvd", "parser_for"]

PARSER_VERSION = "assurance-intel-parse/1"


class FeedRejected(Exception):  # noqa: N818 - reads as the verdict it is
    """The bytes are not an acceptable feed. ``str(exc)`` is the recorded reason."""


@dataclass(frozen=True)
class ParsedFeed:
    source: str
    #: record id -> the record as published.
    records: dict[str, Any]
    #: record id -> digest of the record, used to say what changed between two observations.
    digests: dict[str, str]
    #: The publisher's own stamp (catalogue release, score date, response timestamp).
    feed_stamp: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def digest_record(record: Any) -> str:
    text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def load_json(raw: bytes, max_bytes: int) -> Any:
    if len(raw) > max_bytes:
        raise FeedRejected(f"oversized: {len(raw)} bytes exceeds the {max_bytes}-byte cap")
    if not raw.strip():
        raise FeedRejected("empty: the response body is empty")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FeedRejected(f"not_utf8: {exc.reason}") from exc
    try:
        return json.loads(text, parse_constant=_refuse_constant)
    except RecursionError as exc:
        raise FeedRejected("bad_json: nested too deeply") from exc
    except ValueError as exc:
        stripped = text.rstrip()
        pos = getattr(exc, "pos", None)
        if not stripped.endswith(("}", "]")) or (pos is not None and pos >= len(stripped)):
            raise FeedRejected("truncated: the document ends before it is complete") from exc
        raise FeedRejected(f"bad_json: {exc}") from exc


def _shape(ok: bool, detail: str) -> None:
    if not ok:
        raise FeedRejected(f"wrong_shape: {detail}")


def _build(source: str, pairs: list[tuple[str, Any]], stamp: str, meta: dict[str, Any]
           ) -> ParsedFeed:
    records: dict[str, Any] = {}
    for rid, rec in pairs:
        if rid in records:
            raise FeedRejected(f"duplicate_record: {rid} appears twice, so the feed is "
                               "ambiguous")
        records[rid] = rec
    return ParsedFeed(source, records, {k: digest_record(v) for k, v in records.items()},
                      stamp, meta)


def _is_date(value: Any) -> bool:
    try:
        date.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    return True


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# --------------------------------------------------------------------------- CISA KEV
def parse_kev(raw: bytes, max_bytes: int) -> ParsedFeed:
    doc = load_json(raw, max_bytes)
    _shape(isinstance(doc, dict), "the KEV catalogue must be a JSON object")
    vulns = doc.get("vulnerabilities")
    _shape(isinstance(vulns, list), "no 'vulnerabilities' list")
    _shape(isinstance(doc.get("catalogVersion"), str) and doc["catalogVersion"] != "",
           "no 'catalogVersion'")
    count = doc.get("count")
    _shape(_is_int(count), "no integer 'count'")
    if count != len(vulns):
        raise FeedRejected(f"truncated_or_altered: count says {count} but {len(vulns)} "
                           "entries are present")
    pairs: list[tuple[str, Any]] = []
    for i, entry in enumerate(vulns):
        _shape(isinstance(entry, dict), f"entry {i} is not an object")
        cve = entry.get("cveID")
        _shape(isinstance(cve, str) and bool(CVE_ID.match(cve)), f"entry {i} has no valid cveID")
        for key in ("vendorProject", "product", "dateAdded"):
            _shape(isinstance(entry.get(key), str) and entry[key] != "",
                   f"{cve} lacks '{key}'")
        _shape(_is_date(entry["dateAdded"]), f"{cve} dateAdded is not a date")
        pairs.append((cve, entry))
    stamp = doc.get("dateReleased") if isinstance(doc.get("dateReleased"), str) else ""
    return _build("cisa_kev", pairs, stamp or doc["catalogVersion"],
                  {"catalogVersion": doc["catalogVersion"], "title": str(doc.get("title", ""))})


# --------------------------------------------------------------------------- NVD CVE API 2.0
def parse_nvd(raw: bytes, max_bytes: int) -> ParsedFeed:
    doc = load_json(raw, max_bytes)
    _shape(isinstance(doc, dict), "the NVD response must be a JSON object")
    _shape(doc.get("version") == "2.0", "'version' is not '2.0'; another schema is not guessed at")
    vulns = doc.get("vulnerabilities")
    _shape(isinstance(vulns, list), "no 'vulnerabilities' list")
    total = doc.get("totalResults")
    _shape(_is_int(total), "no integer 'totalResults'")
    start, per_page = doc.get("startIndex", 0), doc.get("resultsPerPage", len(vulns))
    _shape(_is_int(start) and _is_int(per_page), "paging fields are not integers")
    if len(vulns) > total or (start == 0 and len(vulns) < total and len(vulns) < per_page):
        raise FeedRejected(f"truncated_or_altered: totalResults says {total} but "
                           f"{len(vulns)} records are present")
    pairs: list[tuple[str, Any]] = []
    for i, item in enumerate(vulns):
        cve = item.get("cve") if isinstance(item, dict) else None
        _shape(isinstance(cve, dict), f"item {i} has no 'cve' object")
        cid = cve.get("id")
        _shape(isinstance(cid, str) and bool(CVE_ID.match(cid)), f"item {i} has no valid cve.id")
        for key in ("configurations", "descriptions"):
            _shape(isinstance(cve.get(key, []), list), f"{cid} '{key}' is not a list")
        _shape(isinstance(cve.get("metrics", {}), dict), f"{cid} 'metrics' is not an object")
        pairs.append((cid, cve))
    stamp = doc.get("timestamp") if isinstance(doc.get("timestamp"), str) else ""
    return _build("nvd_cve_api", pairs, stamp,
                  {"totalResults": total, "complete_page": len(vulns) == total})


# --------------------------------------------------------------------------- FIRST EPSS
def _score(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise FeedRejected(f"wrong_shape: {value!r} is not a number") from exc
    if not 0.0 <= number <= 1.0:        # also false for NaN
        raise FeedRejected(f"wrong_shape: {value!r} is outside 0..1")
    return number


def parse_epss(raw: bytes, max_bytes: int) -> ParsedFeed:
    doc = load_json(raw, max_bytes)
    _shape(isinstance(doc, dict), "the EPSS response must be a JSON object")
    _shape(doc.get("status") == "OK", "'status' is not 'OK'")
    data = doc.get("data")
    _shape(isinstance(data, list), "no 'data' list")
    total = doc.get("total")
    _shape(_is_int(total), "no integer 'total'")
    limit = doc.get("limit", len(data))
    _shape(_is_int(limit), "'limit' is not an integer")
    if len(data) > total or (len(data) < total and len(data) < limit):
        raise FeedRejected(f"truncated_or_altered: total says {total} but {len(data)} rows "
                           "are present")
    pairs: list[tuple[str, Any]] = []
    for i, row in enumerate(data):
        _shape(isinstance(row, dict), f"row {i} is not an object")
        cve = row.get("cve")
        _shape(isinstance(cve, str) and bool(CVE_ID.match(cve)), f"row {i} has no valid cve")
        _shape(_is_date(row.get("date")), f"{cve} has no score date")
        pairs.append((cve, {"cve": cve, "epss": _score(row.get("epss")),
                            "percentile": _score(row.get("percentile")), "date": row["date"]}))
    dates = sorted({r["date"] for _, r in pairs})
    return _build("first_epss", pairs, dates[-1] if dates else "",
                  {"total": total, "incomplete_page": len(data) < total})


# --------------------------------------------------------------------------- CSAF
def parse_csaf(raw: bytes, max_bytes: int) -> ParsedFeed:
    """Accept a document only if the repo's own CSAF importer accepts it (final status)."""
    doc = load_json(raw, max_bytes)
    _shape(isinstance(doc, dict), "a CSAF document must be a JSON object")
    try:
        advisory_from_csaf(doc)
    except AdvisoryError as exc:
        raise FeedRejected(f"wrong_shape: the CSAF importer refused it: {exc}") from exc
    head = doc["document"]["tracking"]
    cves = sorted({v["cve"].strip() for v in (doc.get("vulnerabilities") or [])
                   if isinstance(v, dict) and isinstance(v.get("cve"), str)
                   and CVE_ID.match(v["cve"].strip())})
    rid = str(head["id"]).strip()
    tracking = {k: str(head.get(k, ""))[:200] for k in
                ("id", "version", "initial_release_date", "current_release_date", "status")}
    return ParsedFeed("csaf", {rid: doc}, {rid: digest_record(doc)},
                      str(head.get("current_release_date", "")),
                      {"cves": cves, "tracking": tracking})


def parser_for(source_id: str) -> Callable[[bytes, int], ParsedFeed]:
    return {"cisa_kev": parse_kev, "nvd_cve_api": parse_nvd, "first_epss": parse_epss,
            "csaf": parse_csaf}[source_id]
