"""The append-only observation history.

Storage choice: a **per-purpose SQLite file**, not entries in an ``EvidenceLedger``.
The ledger is the tenant's hash-chained record of *their* evidence, one writer, and
"shared ledger is operator-only". Public-feed observations are not tenant evidence: they are
high-volume, re-observed on every refresh (mostly byte-identical), and would bloat and entangle
a chain whose job is attestable history. They do need the ledger's *discipline*, which is
copied here: every write is one ``BEGIN IMMEDIATE`` transaction spanning "what is the latest
accepted observation of this series" and the insert, so two concurrent refreshes of identical
bytes produce one ``first`` and one ``unchanged``, never two ``first``. Append-only is enforced
by triggers that abort any UPDATE or DELETE, not just by convention. There is no hash chain: this
file is a cache of public facts with provenance, not an attestation, and says so.

Dispositions
------------
``first``      the first accepted bytes of this (source, url) series.
``changed``    accepted bytes that differ from the latest accepted observation; ``diff`` lists
               the added / removed / modified record ids.
``unchanged``  byte-identical (same sha256) to the latest accepted observation; recorded as a
               re-observation, and never a downstream event.
``unchanged`` is also how a conditional GET answered ``304 Not Modified`` is recorded: the
               row carries ``http_status`` 304, the stored sha256 and a reason beginning
               ``not_modified``, so the time of the check is on file (honest freshness) without
               a second copy of the bytes. A 304 with no usable stored body is ``rejected``.
``rejected``   the response could not be accepted (transport failure, non-200, oversized,
               malformed). Recorded with its sha256 and reason; no payload is stored and the
               series baseline is untouched.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc
from assurance.core.sqlite import enable_wal
from assurance.intel.parsers import ParsedFeed

__all__ = ["DISPOSITIONS", "SCHEMA_VERSION", "IntelStore", "IntelStoreError", "ListingState",
           "NOT_MODIFIED", "Observation", "ReadOnlyIntelStore", "Validators", "clean_validators"]

SCHEMA_VERSION = 1
DISPOSITIONS = ("first", "changed", "unchanged", "rejected")
#: Longest id list kept per side of a diff; the totals are always exact.
MAX_DIFF_IDS = 5_000

#: Reason prefixes of a conditional-GET 304 (accepted / not usable).
NOT_MODIFIED = "not_modified"
_NOT_MODIFIED_UNUSABLE = "not_modified_unusable"
_MAX_VALIDATOR = 512

_APP_ID = 0x494E544C     # "INTL": refuse to treat some other SQLite file as this store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS blobs (
    sha256       TEXT PRIMARY KEY,
    body         BLOB NOT NULL,
    digests_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    source         TEXT NOT NULL,
    url            TEXT NOT NULL,
    locator        TEXT NOT NULL,
    via            TEXT NOT NULL CHECK (via IN ('network','file')),
    retrieved_at   TEXT NOT NULL,
    http_status    INTEGER,
    byte_length    INTEGER NOT NULL,
    sha256         TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    parse_result   TEXT NOT NULL CHECK (parse_result IN ('ok','malformed')),
    reason         TEXT NOT NULL,
    disposition    TEXT NOT NULL CHECK (disposition IN ('first','changed','unchanged','rejected')),
    record_count   INTEGER NOT NULL,
    feed_stamp     TEXT NOT NULL,
    diff_json      TEXT
);
CREATE INDEX IF NOT EXISTS obs_series ON observations (source, url, seq);
CREATE TABLE IF NOT EXISTS provenance (
    seq       INTEGER PRIMARY KEY REFERENCES observations(seq),
    provider  TEXT NOT NULL,
    listed_at TEXT NOT NULL,
    settled   INTEGER NOT NULL CHECK (settled IN (0,1)),
    meta_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS provenance_provider ON provenance (provider, seq);
CREATE TABLE IF NOT EXISTS validators (
    seq           INTEGER PRIMARY KEY REFERENCES observations(seq),
    etag          TEXT NOT NULL,
    last_modified TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS listings (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL,
    retrieved_at  TEXT NOT NULL,
    http_status   INTEGER NOT NULL,
    outcome       TEXT NOT NULL CHECK (outcome IN ('fetched','not_modified')),
    sha256        TEXT NOT NULL,
    byte_length   INTEGER NOT NULL,
    etag          TEXT NOT NULL,
    last_modified TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS listings_url ON listings (url, seq);
CREATE TRIGGER IF NOT EXISTS validators_no_update BEFORE UPDATE ON validators
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS validators_no_delete BEFORE DELETE ON validators
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS listings_no_update BEFORE UPDATE ON listings
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS listings_no_delete BEFORE DELETE ON listings
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_no_update BEFORE UPDATE ON provenance
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_no_delete BEFORE DELETE ON provenance
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS blobs_no_update BEFORE UPDATE ON blobs
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS blobs_no_delete BEFORE DELETE ON blobs
  BEGIN SELECT RAISE(ABORT, 'intel observations are append-only'); END;
"""


class IntelStoreError(AssuranceError):
    """The file is not an intel store, or a row cannot be found."""


@dataclass(frozen=True)
class Validators:
    """HTTP cache validators the server gave for one body. Either part may be empty."""

    etag: str = ""
    last_modified: str = ""

    def __bool__(self) -> bool:
        return bool(self.etag or self.last_modified)

    def request_headers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.etag:
            out["If-None-Match"] = self.etag
        if self.last_modified:
            out["If-Modified-Since"] = self.last_modified
        return out


def _clean_value(value: object, *, http_date: bool) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > _MAX_VALIDATOR or any(not 0x20 <= ord(c) < 0x7F for c in value):
        return ""        # empty, oversized, or carrying a control / non-ASCII character
    if http_date:
        # IMF-fixdate only (RFC 9110). Not email.utils: on Python 3.11 it imports ``socket``, and
        # this module is on the offline path, which must import no network client. An obsolete
        # date form is dropped, so that series is simply fetched in full.
        try:
            datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=UTC)
        except ValueError:
            return ""
    return value


def clean_validators(headers: Mapping[str, str] | None) -> Validators:
    """Validators from response headers (any case). Anything unsafe to echo back is dropped."""
    lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
    return Validators(_clean_value(lowered.get("etag"), http_date=False),
                      _clean_value(lowered.get("last-modified"), http_date=True))


@dataclass(frozen=True)
class ListingState:
    """The last stored copy of a listing resource (provider metadata, index, ROLIE feed)."""

    sha256: str
    body: bytes
    validators: Validators


@dataclass(frozen=True)
class Observation:
    seq: int
    source: str
    url: str
    locator: str
    via: str
    retrieved_at: str
    http_status: int | None
    byte_length: int
    sha256: str
    parser_version: str
    parse_result: str
    reason: str
    disposition: str
    record_count: int
    feed_stamp: str
    diff: dict[str, Any] | None

    @property
    def accepted(self) -> bool:
        return self.parse_result == "ok" and self.disposition != "rejected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "source": self.source, "url": self.url, "locator": self.locator,
            "via": self.via, "retrieved_at": self.retrieved_at, "http_status": self.http_status,
            "byte_length": self.byte_length, "sha256": self.sha256,
            "parser_version": self.parser_version, "parse_result": self.parse_result,
            "reason": self.reason, "disposition": self.disposition,
            "record_count": self.record_count, "feed_stamp": self.feed_stamp, "diff": self.diff,
        }

    def citation(self, record_id: str = "") -> dict[str, Any]:
        return {"observation_seq": self.seq, "source": self.source, "url": self.url,
                "retrieved_at": self.retrieved_at, "sha256": self.sha256,
                "record_id": record_id, "feed_stamp": self.feed_stamp}


def _insert_provenance(db: sqlite3.Connection, seq: int | None, provenance: dict[str, Any],
                       meta: dict[str, Any]) -> None:
    db.execute(
        "INSERT INTO provenance (seq,provider,listed_at,settled,meta_json) VALUES (?,?,?,?,?)",
        (seq, provenance["provider"], provenance.get("listed_at", ""),
         1 if provenance.get("settled", True) else 0, json.dumps(meta, sort_keys=True)))


def _rehashed(raw: object, sha256: str) -> bytes | None:
    """``raw`` as bytes if it is a blob that hashes to ``sha256``, else None."""
    if not isinstance(raw, (bytes, memoryview)):
        return None
    body = bytes(raw)
    return body if hashlib.sha256(body).hexdigest() == sha256 else None


def _blob_ok(db: sqlite3.Connection, sha256: str) -> bool:
    row = db.execute("SELECT body FROM blobs WHERE sha256=?", (sha256,)).fetchone()
    return row is not None and _rehashed(row["body"], sha256) is not None


def _validators_of(db: sqlite3.Connection, seq: int) -> Validators | None:
    row = db.execute("SELECT etag, last_modified FROM validators WHERE seq=?", (seq,)).fetchone()
    return Validators(row["etag"], row["last_modified"]) if row else None


def _not_modified_problem(db: sqlite3.Connection, prev: sqlite3.Row | None,
                          sent: Validators) -> str:
    """Why a 304 cannot be taken as "unchanged", or "" when it can."""
    if prev is None:
        return "no accepted observation of this series is stored"
    if not _blob_ok(db, prev["sha256"]):
        return "the stored body is missing or no longer matches its sha256"
    if _validators_of(db, prev["seq"]) != sent:
        return "the validators sent are not those recorded for the stored body"
    return ""


def _row_to_observation(row: sqlite3.Row) -> Observation:
    return Observation(
        seq=row["seq"], source=row["source"], url=row["url"], locator=row["locator"],
        via=row["via"], retrieved_at=row["retrieved_at"], http_status=row["http_status"],
        byte_length=row["byte_length"], sha256=row["sha256"],
        parser_version=row["parser_version"], parse_result=row["parse_result"],
        reason=row["reason"], disposition=row["disposition"],
        record_count=row["record_count"], feed_stamp=row["feed_stamp"],
        diff=json.loads(row["diff_json"]) if row["diff_json"] else None)


def _diff(old: dict[str, str], new: dict[str, str]) -> dict[str, Any]:
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    modified = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    out: dict[str, Any] = {"added_total": len(added), "removed_total": len(removed),
                           "modified_total": len(modified),
                           "added": added[:MAX_DIFF_IDS], "removed": removed[:MAX_DIFF_IDS],
                           "modified": modified[:MAX_DIFF_IDS]}
    out["truncated"] = max(len(added), len(removed), len(modified)) > MAX_DIFF_IDS
    return out


class IntelStore:
    """One SQLite file of observations. Open it from any number of threads or processes."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._refuse_if_foreign_before_writing()
        with self._write_txn(create=True) as db:
            current = db.execute("PRAGMA application_id").fetchone()[0]
            has_tables = db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            if current not in (0, _APP_ID) or (current == 0 and has_tables):
                raise IntelStoreError(f"{self.path} is not an intel observation store.")
            for statement in _split(_SCHEMA):
                db.execute(statement)
            db.execute(f"PRAGMA application_id={_APP_ID}")

    def _refuse_if_foreign_before_writing(self) -> None:
        """Decide "this is somebody else's database" WITHOUT writing to the file.

        ``_connect`` switches the journal mode to WAL (header bytes 18-19, a ``-wal``/``-shm``
        pair), which is a write. A file this code then refuses must be byte-for-byte what it
        was, so the check that can refuse runs first, on the raw header and, for an unset
        application id, a table count over an ``immutable`` read-only handle (no lock file, no
        ``-shm``, nothing created). A missing or empty file is new and proceeds. The same checks
        run again inside the write transaction (a race, or an uncheckpointed WAL).
        """
        try:
            if not self.path.is_file():
                return
            size = self.path.stat().st_size
        except OSError:
            return          # let the normal open report it
        if size == 0:
            return
        what = str(self.path)
        if size < 100:      # shorter than a SQLite header: SQLite itself would call it "empty"
            raise IntelStoreError(f"{what} is not an intel observation store.")
        # SQLite reads the header; no plain descriptor is opened on the file (closing one would
        # release the locks SQLite holds for another thread in this process; see
        # ``core.sqlite.copy_files_apart``). ``immutable`` locks nothing and creates nothing.
        try:
            db = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro&immutable=1",
                                 uri=True, timeout=5.0)
            try:
                current = db.execute("PRAGMA application_id").fetchone()[0]
                tables = db.execute(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            finally:
                db.close()
        except sqlite3.Error:
            raise IntelStoreError(f"{what} is not an intel observation store.") from None
        if current not in (0, _APP_ID) or (current == 0 and tables):
            raise IntelStoreError(f"{what} is not an intel observation store.")

    @classmethod
    def open_existing(cls, path: str | Path, *, label: str | None = None) -> IntelStore:
        """Open an EXISTING store for reading only. Never creates, never writes.

        A mistyped ``--store`` must not turn into a fresh empty store that then reads as
        "nothing known". Missing, empty or foreign files are refused with
        :class:`IntelStoreError`. ``label`` replaces the path in messages (the HTTP routes
        must not echo the server's path).
        """
        return ReadOnlyIntelStore(path, label=label)

    # -- plumbing ---------------------------------------------------------
    def _connect(self, create: bool = False) -> sqlite3.Connection:
        if not create and not self.path.exists():
            raise IntelStoreError(f"{self.path} does not exist.")
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        enable_wal(db)
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _write_txn(self, create: bool = False) -> Iterator[sqlite3.Connection]:
        with self._lock:
            db = self._connect(create)
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
            finally:
                db.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    # -- writing ----------------------------------------------------------
    def append(
        self, *, source: str, url: str, locator: str, via: str, retrieved_at: datetime,
        http_status: int | None, byte_length: int, sha256: str, parser_version: str,
        parse_result: str, reason: str, raw: bytes | None = None,
        parsed: ParsedFeed | None = None, provenance: dict[str, Any] | None = None,
        validators: Validators | None = None,
    ) -> Observation:
        """Record one observation. Decides the disposition inside the write transaction.

        ``provenance`` (CSAF provider fetches only) is stored beside the observation in the
        same transaction: ``provider``, ``listed_at`` (when the provider's index said the
        document last changed), ``settled`` (False for a transient failure that must be
        retried) and any other keys as ``meta``. For an accepted CSAF document the document's
        own tracking block (id, version, release dates) is added from the parsed feed.
        """
        accepted = parse_result == "ok"
        if accepted and (raw is None or parsed is None):
            raise ValueError("an accepted observation needs its raw bytes and parsed feed")
        with self._write_txn() as db:
            disposition, diff, count, stamp = "rejected", None, 0, ""
            if accepted:
                assert raw is not None and parsed is not None
                count, stamp = len(parsed.records), parsed.feed_stamp
                prev = db.execute(
                    "SELECT o.sha256, b.digests_json FROM observations o "
                    "JOIN blobs b ON b.sha256 = o.sha256 "
                    "WHERE o.source=? AND o.url=? AND o.parse_result='ok' "
                    "ORDER BY o.seq DESC LIMIT 1", (source, url)).fetchone()
                if prev is None:
                    disposition = "first"
                elif prev["sha256"] == sha256:
                    disposition = "unchanged"
                else:
                    disposition = "changed"
                    diff = _diff(json.loads(prev["digests_json"]), parsed.digests)
                db.execute("INSERT OR IGNORE INTO blobs (sha256, body, digests_json) "
                           "VALUES (?,?,?)",
                           (sha256, raw, json.dumps(parsed.digests, sort_keys=True)))
            cur = db.execute(
                "INSERT INTO observations (source,url,locator,via,retrieved_at,http_status,"
                "byte_length,sha256,parser_version,parse_result,reason,disposition,"
                "record_count,feed_stamp,diff_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (source, url, locator, via, format_utc(retrieved_at), http_status, byte_length,
                 sha256, parser_version, parse_result, reason, disposition, count, stamp,
                 json.dumps(diff, sort_keys=True) if diff is not None else None))
            if accepted and validators:
                db.execute("INSERT INTO validators (seq,etag,last_modified) VALUES (?,?,?)",
                           (cur.lastrowid, validators.etag, validators.last_modified))
            if provenance is not None:
                meta = {k: v for k, v in provenance.items()
                        if k not in ("provider", "listed_at", "settled")}
                if parsed is not None and accepted and parsed.meta.get("tracking"):
                    meta["tracking"] = parsed.meta["tracking"]
                _insert_provenance(db, cur.lastrowid, provenance, meta)
            row = db.execute("SELECT * FROM observations WHERE seq=?",
                             (cur.lastrowid,)).fetchone()
            return _row_to_observation(row)

    def append_not_modified(
        self, *, source: str, url: str, locator: str, retrieved_at: datetime,
        sent: Validators, received: Validators | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> Observation:
        """Record a conditional GET answered ``304 Not Modified``. Nothing is re-downloaded.

        Inside one write transaction: take the newest accepted observation of the series,
        re-hash its stored blob, and require that the validators we sent are the ones recorded
        for it. Then, and only then, append an ``unchanged`` row (``http_status`` 304, the stored
        sha256 and counts) so the time of the check is on file. If there is no accepted
        observation, no blob, a blob that no longer hashes to its recorded sha256, or the sent
        validators are not the recorded ones, the answer is UNKNOWN, not "unchanged": a
        ``rejected`` row (``http_status`` 304, empty body) is appended and the baseline is
        untouched. ``received`` are validators the 304 itself carried; otherwise ``sent`` carry
        forward.
        """
        insert = (
            "INSERT INTO observations (source,url,locator,via,retrieved_at,http_status,"
            "byte_length,sha256,parser_version,parse_result,reason,disposition,"
            "record_count,feed_stamp,diff_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        with self._write_txn() as db:
            prev = db.execute(
                "SELECT * FROM observations WHERE source=? AND url=? AND parse_result='ok' "
                "AND disposition != 'rejected' ORDER BY seq DESC LIMIT 1",
                (source, url)).fetchone()
            problem = _not_modified_problem(db, prev, sent)
            meta = {k: v for k, v in (provenance or {}).items()
                    if k not in ("provider", "listed_at", "settled")}
            if problem or prev is None:
                reason = f"{_NOT_MODIFIED_UNUSABLE}: {problem}; the answer is unknown"
                cur = db.execute(insert, (
                    source, url, locator, "network", format_utc(retrieved_at), 304, 0,
                    hashlib.sha256(b"").hexdigest(), prev["parser_version"] if prev else "",
                    "malformed", reason, "rejected", 0, "", None))
                if provenance is not None:
                    _insert_provenance(db, cur.lastrowid, {**provenance, "settled": False}, meta)
            else:
                cur = db.execute(insert, (
                    source, url, locator, "network", format_utc(retrieved_at), 304,
                    prev["byte_length"], prev["sha256"], prev["parser_version"], "ok",
                    f"{NOT_MODIFIED}: the server confirmed the stored copy "
                    f"(observation {prev['seq']}) is current; nothing was downloaded",
                    "unchanged", prev["record_count"], prev["feed_stamp"], None))
                keep = received if received else sent
                if keep:
                    db.execute("INSERT INTO validators (seq,etag,last_modified) VALUES (?,?,?)",
                               (cur.lastrowid, keep.etag, keep.last_modified))
                if provenance is not None:
                    old = db.execute("SELECT meta_json FROM provenance WHERE seq=?",
                                     (prev["seq"],)).fetchone()
                    tracking = json.loads(old["meta_json"]).get("tracking") if old else None
                    if tracking:
                        meta["tracking"] = tracking
                    _insert_provenance(db, cur.lastrowid, provenance, meta)
            row = db.execute("SELECT * FROM observations WHERE seq=?",
                             (cur.lastrowid,)).fetchone()
            return _row_to_observation(row)

    def validators_for(self, source: str, url: str) -> Validators | None:
        """Validators to send for the series, or None (send nothing, download in full).

        They are those recorded with the newest accepted observation, and only while that
        observation's stored blob still re-hashes to its recorded sha256: a damaged or edited
        blob makes its validators worthless, so they are dropped, never trusted.
        """
        with self._read() as db:
            try:
                prev = db.execute(
                    "SELECT * FROM observations WHERE source=? AND url=? AND "
                    "parse_result='ok' AND disposition != 'rejected' "
                    "ORDER BY seq DESC LIMIT 1", (source, url)).fetchone()
                if prev is None:
                    return None
                got = _validators_of(db, prev["seq"])
                return got if got and _blob_ok(db, prev["sha256"]) else None
            except sqlite3.OperationalError:
                return None     # a store from before validators existed

    # -- listing resources (provider metadata, changes.csv, index.txt, ROLIE feed) ---------
    def listing_state(self, url: str) -> ListingState | None:
        """The newest stored copy of a listing resource, if its blob still re-hashes."""
        with self._read() as db:
            try:
                row = db.execute("SELECT * FROM listings WHERE url=? ORDER BY seq DESC LIMIT 1",
                                 (url,)).fetchone()
            except sqlite3.OperationalError:
                return None
            if row is None:
                return None
            blob = db.execute("SELECT body FROM blobs WHERE sha256=?",
                              (row["sha256"],)).fetchone()
        body = _rehashed(blob["body"] if blob else None, row["sha256"])
        if body is None:
            return None
        return ListingState(row["sha256"], body, Validators(row["etag"], row["last_modified"]))

    def record_listing(self, url: str, *, retrieved_at: datetime, raw: bytes,
                       validators: Validators) -> None:
        """Keep a listing resource fetched in full (HTTP 200) so a later 304 can be honoured."""
        sha = hashlib.sha256(raw).hexdigest()
        with self._write_txn() as db:
            db.execute("INSERT OR IGNORE INTO blobs (sha256, body, digests_json) "
                       "VALUES (?,?,?)", (sha, raw, "{}"))
            db.execute(
                "INSERT INTO listings (url,retrieved_at,http_status,outcome,sha256,byte_length,"
                "etag,last_modified) VALUES (?,?,?,?,?,?,?,?)",
                (url, format_utc(retrieved_at), 200, "fetched", sha, len(raw),
                 validators.etag, validators.last_modified))

    def record_listing_not_modified(self, url: str, *, retrieved_at: datetime, sent: Validators,
                                    received: Validators | None = None) -> bytes:
        """Honour a 304 for a listing: return the stored body, after re-hashing it.

        Raises :class:`IntelStoreError` (the answer is unknown) when there is no stored copy,
        it no longer hashes to its sha256, or ``sent`` are not the validators recorded with it.
        """
        with self._write_txn() as db:
            row = db.execute("SELECT * FROM listings WHERE url=? ORDER BY seq DESC LIMIT 1",
                             (url,)).fetchone()
            if row is None:
                raise IntelStoreError("304 for a resource with no stored copy")
            blob = db.execute("SELECT body FROM blobs WHERE sha256=?",
                              (row["sha256"],)).fetchone()
            body = _rehashed(blob["body"] if blob else None, row["sha256"])
            if body is None:
                raise IntelStoreError("304, but the stored copy no longer matches its sha256")
            if Validators(row["etag"], row["last_modified"]) != sent:
                raise IntelStoreError("304, but the validators sent are not the recorded ones")
            keep = received if received else sent
            db.execute(
                "INSERT INTO listings (url,retrieved_at,http_status,outcome,sha256,byte_length,"
                "etag,last_modified) VALUES (?,?,?,?,?,?,?,?)",
                (url, format_utc(retrieved_at), 304, "not_modified", row["sha256"],
                 row["byte_length"], keep.etag, keep.last_modified))
            return body

    # -- reading ----------------------------------------------------------
    def observations(self, *, source: str | None = None, after_seq: int = 0,
                     limit: int | None = None) -> list[Observation]:
        sql, args = "SELECT * FROM observations WHERE seq > ?", [after_seq]
        if source:
            sql += " AND source = ?"
            args.append(source)
        sql += " ORDER BY seq"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(limit)
        with self._read() as db:
            return [_row_to_observation(r) for r in db.execute(sql, args)]

    def provenance(self, seq: int) -> dict[str, Any] | None:
        """Provider provenance of one observation, or None (also for a store without it)."""
        with self._read() as db:
            try:
                row = db.execute("SELECT * FROM provenance WHERE seq=?", (seq,)).fetchone()
            except sqlite3.OperationalError:
                return None
        if row is None:
            return None
        return {"provider": row["provider"], "listed_at": row["listed_at"],
                "settled": bool(row["settled"]), **json.loads(row["meta_json"])}

    def settled_listings(self, provider: str, *, allow_interim: bool = False
                         ) -> dict[str, str]:
        """url -> newest ``listed_at`` already settled (accepted or rejected for good).

        This is the incremental cursor: a document whose listing is not newer than this has
        been dealt with. A transient failure is not settled, so it is tried again. With
        ``allow_interim`` a document that was refused only for being interim is not settled:
        the operator has now asked for those.
        """
        with self._read() as db:
            try:
                rows = db.execute(
                    "SELECT o.url AS url, p.listed_at AS listed_at, p.meta_json AS meta "
                    "FROM provenance p "
                    "JOIN observations o ON o.seq = p.seq "
                    "WHERE p.provider=? AND p.settled=1 AND p.listed_at != ''",
                    (provider,)).fetchall()
            except sqlite3.OperationalError:
                return {}
        out: dict[str, str] = {}
        for r in rows:
            if allow_interim and json.loads(r["meta"]).get("interim_refused"):
                continue
            if r["url"] not in out or r["listed_at"] > out[r["url"]]:
                out[r["url"]] = r["listed_at"]
        return out

    def get(self, seq: int) -> Observation:
        with self._read() as db:
            row = db.execute("SELECT * FROM observations WHERE seq=?", (seq,)).fetchone()
        if row is None:
            raise IntelStoreError(f"no observation {seq}")
        return _row_to_observation(row)

    def raw_row(self, seq: int) -> tuple[Any, ...]:
        """The stored row as plain values, for byte-identity checks."""
        with self._read() as db:
            row = db.execute("SELECT * FROM observations WHERE seq=?", (seq,)).fetchone()
        return tuple(row) if row else ()

    def body(self, sha256: str) -> bytes | None:
        """The stored payload for ``sha256``, or None if it is absent OR does not hash to it.

        A blob is looked up by the hash recorded when it was observed. Re-hashing on every read
        means bit-rot or an edit that still parses (a changed digit inside valid JSON) is
        treated as an unreadable payload, never as the observation that was recorded.
        """
        with self._read() as db:
            row = db.execute("SELECT body FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        # A payload rewritten as TEXT/INTEGER/NULL is unreadable, not a crash.
        return _rehashed(row["body"], sha256) if row else None

    def latest_accepted(self, source: str | None = None) -> list[Observation]:
        """The newest accepted observation of each (source, url) series, oldest first."""
        sql = ("SELECT * FROM observations WHERE seq IN (SELECT max(seq) FROM observations "
               "WHERE parse_result='ok'" + (" AND source=?" if source else "")
               + " GROUP BY source, url) ORDER BY seq")
        with self._read() as db:
            return [_row_to_observation(r) for r in db.execute(sql, [source] if source else [])]

    def downstream_events(self, after_seq: int = 0) -> list[Observation]:
        """What a downstream consumer should act on: accepted ``first``/``changed`` only.

        ``unchanged`` re-observations and rejections are history, never events, so a refresh
        that learned nothing cannot raise a duplicate.
        """
        return [o for o in self.observations(after_seq=after_seq)
                if o.disposition in ("first", "changed")]


class ReadOnlyIntelStore(IntelStore):
    """An :class:`IntelStore` that cannot write and cannot create.

    ``IntelStore.__init__`` creates the file and runs the schema in a write transaction, which a
    read path must never do. This opens SQLite with ``mode=ro`` and ``query_only`` and refuses
    ``append``, so the only operations reachable are reads.
    """

    def __init__(self, path: str | Path, *, label: str | None = None) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        what = label or str(self.path)
        if not self.path.is_file():
            raise IntelStoreError(
                f"{what} does not exist. Nothing was read, and no store was created.")
        try:
            with self._read() as db:
                app_id = db.execute("PRAGMA application_id").fetchone()[0]
                if app_id != _APP_ID:
                    raise IntelStoreError(f"{what} is not an intel observation store.")
                db.execute("SELECT seq FROM observations LIMIT 1").fetchall()
                db.execute("SELECT sha256 FROM blobs LIMIT 1").fetchall()
        except sqlite3.Error as exc:
            raise IntelStoreError(
                f"{what} could not be opened as an intel observation store "
                f"({type(exc).__name__}).") from exc

    def _connect(self, create: bool = False) -> sqlite3.Connection:
        if create:
            raise IntelStoreError("this store is read-only")
        # A WAL-mode file opened ``mode=ro`` still gets a ``-shm`` / ``-wal`` pair created beside
        # it: a read verb writing into the store's directory. With neither sidecar there is no
        # open writer (a writer holds both until the last connection closes), so the file is
        # quiescent and ``immutable=1`` reads it with no locking and creates nothing. With a
        # sidecar present a writer may be live: ``mode=ro`` then uses the existing files and
        # creates none. (A writer that opens in the instant between the check and the read is
        # the one case ``immutable`` could misread; the next read sees it.)
        resolved = self.path.resolve()
        quiescent = not any(resolved.with_name(resolved.name + sfx).exists()
                            for sfx in ("-wal", "-shm", "-journal"))
        mode = "mode=ro&immutable=1" if quiescent else "mode=ro"
        db = sqlite3.connect(f"{resolved.as_uri()}?{mode}", uri=True, timeout=5.0,
                             isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        return db

    def append(self, *args: Any, **kwargs: Any) -> Observation:
        raise IntelStoreError("this store is read-only")


def _split(script: str) -> Sequence[str]:
    """Split the schema into statements (triggers contain a ';' inside BEGIN ... END)."""
    out, buf = [], []
    for line in script.strip().splitlines():
        buf.append(line)
        joined = "\n".join(buf).strip()
        in_trigger = joined.upper().startswith("CREATE TRIGGER")
        if (in_trigger and joined.upper().endswith("END;")) or (
                not in_trigger and joined.endswith(";")):
            out.append(joined.rstrip(";"))
            buf = []
    return out
