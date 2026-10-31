"""Public-source vulnerability intelligence over HTTP: four READ-ONLY routes.

``GET /v1/intel/history``                 the append-only observation history
``GET /v1/intel/observations/{seq}``      one observation, in full
``GET /v1/intel/cve/{cve_id}``            what every recorded source says about one CVE
``GET /v1/intel/candidates``              advisories the model can represent, and what it cannot

What the store is
-----------------
The observation store (:mod:`assurance.intel.store`) is **operator-owned, shared, public
data**: KEV, NVD, EPSS and CSAF files somebody recorded, each with its provenance. It is not
tenant evidence and lives in no tenant ledger. Its path is the server setting
``ASSURANCE_INTEL_STORE``; the operator fills it with the CLI (``assurance intel ingest`` /
``refresh --live``). **No route here writes it, and none fetches anything**: fetching and
recording are an operator act, so there is no ingest or refresh over HTTP, and these routes
open the file read-only (``mode=ro``), never creating it and never running its schema.

What a reader may and may not conclude
--------------------------------------
* A missing or unreadable store is **503** (``no_intel_store_configured`` /
  ``intel_store_unreadable``), exactly as the attestation key route answers an unconfigured
  key. It is never an empty list: "no store" is not "nothing known".
* A CVE no recorded source mentions is ``summary.status == "unknown"``: not clear, not safe.
  Absence from KEV is ``not_listed_in_kev`` with its ``not_established`` note, and ``unchecked``
  when no KEV catalogue was ever recorded. A missing EPSS score is ``unavailable``, never 0.0.
* Every statement carries its citation (observation seq, source, URL, retrieved_at, sha256,
  feed stamp), and every response names the parser version of each observation it used.
* Nothing here matches a version range or says a machine is or is not affected.

Gating is the :data:`~assurance.api.deps.Machine` dependency, the same as the fleet, watch and
change routes this data feeds (Cell): 401 with no or an invalid key, 402 when authenticated but
unentitled, read on every request. No plan flag is added for it.
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status

from assurance.api.deps import Machine
from assurance.core.errors import AssuranceError
from assurance.intel.sources import SOURCE_ALIASES, SOURCES, resolve_source
from assurance.intel.store import _APP_ID, IntelStore, IntelStoreError, Observation
from assurance.intel.view import EPSS_UNAVAILABLE_NOTE, KEV_NOT_ESTABLISHED, build_report

__all__ = ["INTEL_STORE_ENV", "intel_router", "intel_store_path"]

INTEL_STORE_ENV = "ASSURANCE_INTEL_STORE"

intel_router = APIRouter(prefix="/v1/intel", tags=["intel"], dependencies=[Machine])

#: Canonical form only: upper-case, ASCII digits, no whitespace. A lower-case or padded id is
#: refused (422) instead of silently normalised into a lookup the caller did not ask for.
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
#: A SQLite rowid; 18 digits stays inside a signed 64-bit integer.
_SEQ = re.compile(r"[1-9][0-9]{0,17}")
MAX_LIMIT = 1_000
DEFAULT_LIMIT = 200

_R401 = {"description": "No API key, or one that is not valid (`WWW-Authenticate: ApiKey`)."}
_R402 = {"description": "Authenticated, but the plan does not include this "
                        "(`plan_does_not_include_machine_verification`; the body names the plan)."}
_R503 = {"description": "`no_intel_store_configured` or `intel_store_unreadable`: the operator's "
                        "observation store is not available. This is not an empty answer; "
                        "nothing is known from this service until it is."}
_GATED: dict[int | str, dict[str, Any]] = {401: _R401, 402: _R402, 503: _R503}

_STORE_NOTE = ("The observation store is operator-owned, shared public data (KEV, NVD, EPSS, "
               "CSAF files an operator recorded). It is not your evidence, this route never "
               "writes it, and nothing here fetches from the network.")
_SOURCE_NOTE = ("An observation is an UNSIGNED public feed as recorded: its sha256 shows which "
                "bytes were recorded, not that the named source published them.")
_RANGES_NOTE = ("Version ranges are not matched and no range arithmetic is done: this says what "
                "sources recorded about a CVE id, never that a machine is or is not affected.")
_UNKNOWN_NOTE = ("A CVE no recorded source mentions is unknown, not clear: it may be too new, "
                 "outside the recorded NVD/EPSS/CSAF scope, or simply never asked about.")


# --------------------------------------------------------------------------- the store
def intel_store_path() -> str:
    """The configured observation store path, or ``""`` when the operator set none."""
    return os.environ.get(INTEL_STORE_ENV, "").strip()


class _ReadOnlyIntelStore(IntelStore):
    """An :class:`IntelStore` that cannot write and cannot create.

    ``IntelStore.__init__`` creates the file and runs the schema in a write transaction, which a
    read route must never do (and which would turn an unconfigured path into an empty store that
    reads as "nothing known"). This subclass opens SQLite with ``mode=ro`` and ``query_only`` and
    refuses ``append``, so the only operations the report builder can reach are reads.
    """

    def __init__(self, path: str | Path) -> None:       # noqa: D107 - deliberately not super()
        import threading

        self.path = Path(path)
        self._lock = threading.Lock()
        if not self.path.is_file():
            raise IntelStoreError("the configured intel store file does not exist")
        with self._read() as db:
            app_id = db.execute("PRAGMA application_id").fetchone()[0]
            if app_id != _APP_ID:
                raise IntelStoreError("the configured file is not an intel observation store")
            db.execute("SELECT seq FROM observations LIMIT 1").fetchall()
            db.execute("SELECT sha256 FROM blobs LIMIT 1").fetchall()

    def _connect(self, create: bool = False) -> sqlite3.Connection:
        if create:
            raise IntelStoreError("this store is read-only")
        db = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0,
                             isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        return db

    def append(self, *args: Any, **kwargs: Any) -> Observation:
        raise IntelStoreError("this store is read-only")


def _unavailable(error: str, detail: str, remedy: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"error": error, "detail": detail, "remedy": remedy,
                "not_established": "No store means nothing is known from this service. It is "
                                   "not an empty history and it is not 'no vulnerabilities'."})


def _open_store() -> IntelStore:
    path = intel_store_path()
    if not path:
        raise _unavailable(
            "no_intel_store_configured", f"{INTEL_STORE_ENV} is not set.",
            f"The operator sets {INTEL_STORE_ENV} to an observation store built with "
            "`assurance intel ingest` / `assurance intel refresh --live`. This service never "
            "fetches or records feeds over HTTP.")
    try:
        return _ReadOnlyIntelStore(path)
    except (IntelStoreError, sqlite3.Error, OSError) as exc:
        # The reason class only; the server's path is the operator's, not the caller's.
        reason = str(exc) if isinstance(exc, IntelStoreError) else \
            "the file could not be opened as an SQLite database"
        raise _unavailable(
            "intel_store_unreadable", reason,
            f"The operator should check the file {INTEL_STORE_ENV} names (`assurance intel "
            "history --store <file>`). Nothing was read.") from exc


def _read_failed(exc: Exception) -> HTTPException:
    return _unavailable("intel_store_unreadable",
                        "the store could not be read part-way: " + type(exc).__name__,
                        "The operator should check the store file. Nothing was returned.")


# --------------------------------------------------------------------------- shaping
def _observation(o: Observation, *, full: bool = False) -> dict[str, Any]:
    """An observation with its provenance. History lists only the diff totals."""
    row = o.to_dict()
    if not full and row["diff"] is not None:
        row["diff"] = {k: v for k, v in row["diff"].items() if k.endswith("_total")
                       or k == "truncated"}
    row["accepted"] = o.accepted
    return row


def _observation_notes(o: Observation) -> list[str]:
    notes = [_SOURCE_NOTE]
    if o.via == "file":
        notes.append("Recorded from a file the operator supplied: `url` is the source it "
                     "claims to come from, not a fetch this service made.")
    if o.disposition == "rejected":
        notes.append("Rejected: no payload was stored and the series baseline did not move. "
                     "A rejection says nothing about what the source contains.")
    if o.disposition == "unchanged":
        notes.append("Byte-identical to the previous accepted observation of this series: a "
                     "re-observation, not a new event.")
    return notes


def _sources_consulted(store: IntelStore) -> dict[str, Any]:
    """The newest accepted observation of each series, with the fields a reader must cite.

    Also names every source with NO accepted observation, so an absent source reads as absent
    rather than as a quiet source.
    """
    latest = store.latest_accepted()
    seen = {o.source for o in latest}
    return {
        "observations": [
            {"seq": o.seq, "source": o.source, "url": o.url, "retrieved_at": o.retrieved_at,
             "sha256": o.sha256, "parser_version": o.parser_version,
             "feed_stamp": o.feed_stamp, "disposition": o.disposition} for o in latest],
        "sources_without_an_accepted_observation": sorted(set(SOURCES) - seen),
    }


def _scope() -> dict[str, Any]:
    return {"scope": "operator_owned_shared_public_data", "tenant_evidence": False,
            "writes": False, "note": _STORE_NOTE}


def _http_422(error: str, detail: str) -> HTTPException:
    return HTTPException(status_code=422,
                         detail={"error": error, "detail": detail})


def _source_filter(source: str) -> str | None:
    if not source:
        return None
    if source not in SOURCE_ALIASES and source not in SOURCES:
        raise _http_422("invalid_source",
                        f"unknown source; known: {', '.join(sorted(SOURCE_ALIASES))}")
    return resolve_source(source).id


# --------------------------------------------------------------------------- routes
@intel_router.get(
    "/history", responses=_GATED,
    summary="Intel observation history, oldest first (read-only, operator-owned public data)")
def intel_history(
    source: str = "",
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    after_seq: Annotated[int, Query(ge=0, le=10**18)] = 0,
) -> dict[str, Any]:
    """Every recorded observation: accepted, unchanged and rejected alike.

    Page with ``after_seq`` (the last ``seq`` you have). ``status`` is ``empty`` when the store
    exists but nothing was recorded, which means nothing is known, not that nothing exists.
    """
    wanted = _source_filter(source)
    store = _open_store()
    try:
        rows = store.observations(source=wanted, after_seq=after_seq, limit=limit + 1)
    except (sqlite3.Error, AssuranceError) as exc:
        raise _read_failed(exc) from exc
    page, more = rows[:limit], len(rows) > limit
    body: dict[str, Any] = {
        "status": "ok" if page else "empty", "store": _scope(),
        "source": wanted, "after_seq": after_seq, "limit": limit,
        "observations": [_observation(o) for o in page],
        "has_more": more, "next_after_seq": page[-1].seq if more else None,
        "not_established": [_SOURCE_NOTE],
    }
    if not page:
        body["note"] = ("No observation matches. If the store was just created or the filter is "
                        "narrow, that means nothing is recorded, not that nothing is known "
                        "to exist.")
    return body


@intel_router.get(
    "/observations/{seq}",
    responses={**_GATED, 404: {"description": "`observation_not_found`."},
               422: {"description": "`invalid_observation_seq`: not a positive integer."}},
    summary="One intel observation in full, with its provenance")
def intel_observation(seq: str) -> dict[str, Any]:
    if not _SEQ.fullmatch(seq):
        raise _http_422("invalid_observation_seq",
                        "an observation sequence is a positive integer; nothing was read")
    store = _open_store()
    try:
        obs = store.get(int(seq))
    except IntelStoreError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={
            "error": "observation_not_found",
            "detail": "no observation has this sequence in the store"}) from exc
    except (sqlite3.Error, AssuranceError) as exc:
        raise _read_failed(exc) from exc
    return {"status": "ok", "store": _scope(), "observation": _observation(obs, full=True),
            "not_established": _observation_notes(obs)}


@intel_router.get(
    "/cve/{cve_id}",
    responses={**_GATED, 422: {"description": "`invalid_cve_id`: not `CVE-YYYY-NNNN+`."}},
    summary="What every recorded public source says about one CVE (KEV, EPSS, NVD, conflicts)")
def intel_cve(cve_id: str) -> dict[str, Any]:
    """KEV ``listed`` / ``not_listed_in_kev`` / ``unchecked``; EPSS ``available`` (with its score
    date) / ``unavailable``; NVD ``present`` / ``rejected`` / ``unknown``; NVD-versus-vendor
    conflicts. ``summary.status`` is ``unknown`` when no recorded source mentions the CVE.
    """
    if not _CVE_ID.fullmatch(cve_id):
        raise _http_422("invalid_cve_id",
                        "a CVE id looks like CVE-2026-12345 (upper case, ASCII digits); "
                        "nothing was read")
    store = _open_store()
    try:
        report = build_report(store, cve_ids=[cve_id])
        sources = _sources_consulted(store)
    except (sqlite3.Error, AssuranceError) as exc:
        raise _read_failed(exc) from exc
    e = report.enrichments[0].to_dict()
    mentioned = (e["kev"]["status"] == "listed" or e["epss"]["status"] == "available"
                 or e["nvd"]["status"] != "unknown" or bool(e["csaf_advisories"])
                 or bool(e["conflicts"]))
    notes = [_RANGES_NOTE, _SOURCE_NOTE]
    if e["kev"]["status"] != "listed":
        notes.append(KEV_NOT_ESTABLISHED if e["kev"]["status"] == "not_listed_in_kev"
                     else "No KEV catalogue has been recorded, so KEV was not checked.")
    if e["epss"]["status"] == "unavailable":
        notes.append(EPSS_UNAVAILABLE_NOTE)
    if not mentioned:
        notes.append(_UNKNOWN_NOTE)
    return {
        "status": "ok", "store": _scope(), **e,
        "summary": {"status": "recorded" if mentioned else "unknown",
                    "reason": ("at least one recorded source mentions this CVE" if mentioned
                               else "no recorded source mentions this CVE; unknown, not clear")},
        "sources_consulted": sources, "unreadable_observations": list(report.unreadable),
        "not_established": notes,
    }


@intel_router.get(
    "/candidates", responses=_GATED,
    summary="Advisory candidates the model can represent, and what it cannot (read-only)")
def intel_candidates() -> dict[str, Any]:
    """Unsigned, inspect-only advisory candidates built from the recorded CSAF and NVD
    observations, plus every statement a source made that the advisory model cannot hold
    (``not_representable``: bounded version ranges and similar, as text) and NVD-versus-vendor
    conflicts. KEV carries no versions and never yields a candidate. Candidates are drafts for a
    person to read; severity defaults to ``safety_relevant`` and nothing is matched here.
    """
    store = _open_store()
    try:
        report = build_report(store)
        sources = _sources_consulted(store)
    except (sqlite3.Error, AssuranceError) as exc:
        raise _read_failed(exc) from exc
    candidates = [c.to_dict() for c in report.candidates]
    not_rep: list[dict[str, Any]] = [
        {"cve_id": e.cve_id, "statements": list(e.not_representable)}
        for e in report.enrichments if e.not_representable]
    not_rep += [{"advisory_id": c.advisory.advisory_id, "source": c.source,
                 "statements": list(c.not_representable)}
                for c in report.candidates if c.source == "csaf" and c.not_representable]
    notes = [_RANGES_NOTE, _SOURCE_NOTE,
             "Candidates are unsigned and inspect-only; a person decides whether any becomes an "
             "advisory a machine is assessed against."]
    has_input = any(o["source"] in ("nvd_cve_api", "csaf") for o in sources["observations"])
    if not candidates:
        notes.append("No candidate is NOT 'no advisory exists': " + (
            "no NVD or CSAF observation has been recorded." if not has_input else
            "the recorded NVD/CSAF observations yielded no representable advisory."))
    return {
        "status": "ok" if sources["observations"] else "empty", "store": _scope(),
        "candidates": candidates, "not_representable": not_rep,
        "conflicts": list(report.conflicts), "enrichment_count": len(report.enrichments),
        "unreadable_observations": list(report.unreadable),
        "sources_consulted": sources, "not_established": notes,
    }
