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
``rejected``   the response could not be accepted (transport failure, non-200, oversized,
               malformed). Recorded with its sha256 and reason; no payload is stored and the
               series baseline is untouched.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc
from assurance.core.sqlite import enable_wal
from assurance.intel.parsers import ParsedFeed

__all__ = ["DISPOSITIONS", "SCHEMA_VERSION", "IntelStore", "IntelStoreError", "Observation"]

SCHEMA_VERSION = 1
DISPOSITIONS = ("first", "changed", "unchanged", "rejected")
#: Longest id list kept per side of a diff; the totals are always exact.
MAX_DIFF_IDS = 5_000

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
        with self._write_txn(create=True) as db:
            current = db.execute("PRAGMA application_id").fetchone()[0]
            has_tables = db.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            if current not in (0, _APP_ID) or (current == 0 and has_tables):
                raise IntelStoreError(f"{self.path} is not an intel observation store.")
            for statement in _split(_SCHEMA):
                db.execute(statement)
            db.execute(f"PRAGMA application_id={_APP_ID}")

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
        parsed: ParsedFeed | None = None,
    ) -> Observation:
        """Record one observation. Decides the disposition inside the write transaction."""
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
            row = db.execute("SELECT * FROM observations WHERE seq=?",
                             (cur.lastrowid,)).fetchone()
            return _row_to_observation(row)

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
        with self._read() as db:
            row = db.execute("SELECT body FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        return bytes(row["body"]) if row else None

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
