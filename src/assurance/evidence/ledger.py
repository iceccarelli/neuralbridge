"""The tamper-evident evidence ledger.

Append-only, hash-chained, and durable. Every record carries the hash of the
record before it, so removing or editing anything in the middle breaks every
link after it and :meth:`verify_chain` says exactly where.

Three defects seen in the wild are designed out here rather than documented:

1. **Chain forking under concurrency.** Reading the tail and appending in two
   statements lets two writers read the same predecessor and fork the chain
   into two records with the same ``prev_hash``. Every append here happens
   inside one ``BEGIN IMMEDIATE`` transaction that spans the read and the
   write, so the second writer waits and chains onto the first.

2. **Per-process chains.** An in-memory store behind four worker processes
   keeps four independent chains from genesis, each internally consistent and
   collectively meaningless. The chain lives in one SQLite file.

3. **Verification that is never called.** ``verify_chain`` is not decoration:
   :meth:`export` runs it and refuses to emit a bundle that does not verify,
   because an export is precisely the moment someone is about to rely on it.

What this is not: a defence against an administrator with write access to the
database and time. A self-recomputable chain detects accident and casual
tampering. Detecting a determined insider needs a signature over the head with
a key the insider does not hold, or an external anchor — see
:meth:`head_attestation`, which produces the value to sign or publish.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.errors import LedgerIntegrityError
from ..core.evidence import Evidence
from ..core.identity import content_hash_of, format_utc, utc_now

__all__ = ["GENESIS", "LEDGER_SCHEMA_VERSION", "EvidenceLedger", "LedgerEntry"]

LEDGER_SCHEMA_VERSION = 1

#: ``prev_hash`` of the first record. A fixed, published constant so that an
#: empty chain and a truncated chain are distinguishable.
GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chain (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    kind          TEXT NOT NULL,
    subject       TEXT NOT NULL DEFAULT '',
    content_hash  TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    link_hash     TEXT NOT NULL UNIQUE,
    actor         TEXT NOT NULL,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chain_by_subject ON chain (subject, seq);
CREATE INDEX IF NOT EXISTS chain_by_kind    ON chain (kind, seq);
CREATE INDEX IF NOT EXISTS chain_by_content ON chain (content_hash);
"""


@dataclass(frozen=True)
class LedgerEntry:
    """One link in the chain."""

    seq: int
    at: str
    kind: str
    subject: str
    content_hash: str
    prev_hash: str
    link_hash: str
    actor: str
    payload: dict[str, Any]

    def expected_link_hash(self) -> str:
        """Recompute this link's hash from its own content.

        The link hash binds the record's content to its position, so neither
        can be changed without detection.
        """
        return content_hash_of(
            {
                "seq": self.seq,
                "at": self.at,
                "kind": self.kind,
                "subject": self.subject,
                "content_hash": self.content_hash,
                "prev_hash": self.prev_hash,
            }
        )

    def evidence(self) -> Evidence:
        return Evidence.from_dict(self.payload)


class EvidenceLedger:
    """Durable, append-only, hash-chained store of evidence objects."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.executescript(_SCHEMA)
            row = db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(LEDGER_SCHEMA_VERSION),),
                )
            elif int(row[0]) != LEDGER_SCHEMA_VERSION:
                raise LedgerIntegrityError(
                    f"{self.path} was written by ledger schema {row[0]}, this build speaks "
                    f"{LEDGER_SCHEMA_VERSION}. Refusing rather than guessing."
                )

    # -- plumbing ---------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def _write_txn(self) -> Iterator[sqlite3.Connection]:
        """One transaction spanning the tail read and the append.

        ``BEGIN IMMEDIATE`` takes the write lock up front, so a concurrent
        writer blocks here instead of reading the same predecessor and forking
        the chain.
        """
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
            finally:
                db.close()

    # -- writing ----------------------------------------------------------
    def append(self, evidence: Evidence, subject: str = "") -> LedgerEntry:
        """Append a sealed evidence object and return its link.

        The object must already be sealed. Sealing on the caller's behalf would
        mean this ledger could record content the caller never saw.
        """
        if not evidence.is_sealed:
            raise LedgerIntegrityError(
                f"{evidence.kind} evidence is unsealed; seal() it before appending so the "
                "hash recorded is the hash the caller computed."
            )
        if not evidence.verify():
            raise LedgerIntegrityError(
                f"{evidence.kind} evidence {evidence.content_hash[:12]} does not match its "
                "own content — it was mutated after sealing."
            )

        payload = json.dumps(evidence.to_dict(), sort_keys=True, separators=(",", ":"))
        at = format_utc(utc_now())

        with self._write_txn() as db:
            tail = db.execute("SELECT seq, link_hash FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = tail["link_hash"] if tail else GENESIS
            seq = (tail["seq"] + 1) if tail else 1
            link_hash = content_hash_of(
                {
                    "seq": seq,
                    "at": at,
                    "kind": evidence.kind,
                    "subject": subject,
                    "content_hash": evidence.content_hash,
                    "prev_hash": prev_hash,
                }
            )
            db.execute(
                "INSERT INTO chain (seq, at, kind, subject, content_hash, prev_hash, "
                "link_hash, actor, payload) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    seq,
                    at,
                    evidence.kind,
                    subject,
                    evidence.content_hash,
                    prev_hash,
                    link_hash,
                    evidence.actor.identifier,
                    payload,
                ),
            )
        return LedgerEntry(
            seq=seq,
            at=at,
            kind=evidence.kind,
            subject=subject,
            content_hash=evidence.content_hash,
            prev_hash=prev_hash,
            link_hash=link_hash,
            actor=evidence.actor.identifier,
            payload=json.loads(payload),
        )

    # -- reading ----------------------------------------------------------
    def _row_to_entry(self, row: sqlite3.Row) -> LedgerEntry:
        return LedgerEntry(
            seq=row["seq"],
            at=row["at"],
            kind=row["kind"],
            subject=row["subject"],
            content_hash=row["content_hash"],
            prev_hash=row["prev_hash"],
            link_hash=row["link_hash"],
            actor=row["actor"],
            payload=json.loads(row["payload"]),
        )

    def entries(self, *, subject: str | None = None, kind: str | None = None) -> list[LedgerEntry]:
        sql = "SELECT * FROM chain"
        clauses, args = [], []
        if subject is not None:
            clauses.append("subject = ?")
            args.append(subject)
        if kind is not None:
            clauses.append("kind = ?")
            args.append(kind)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        db = self._connect()
        try:
            return [self._row_to_entry(r) for r in db.execute(sql, args)]
        finally:
            db.close()

    def get(self, content_hash: str) -> LedgerEntry | None:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT * FROM chain WHERE content_hash = ? ORDER BY seq LIMIT 1", (content_hash,)
            ).fetchone()
            return self._row_to_entry(row) if row else None
        finally:
            db.close()

    def __len__(self) -> int:
        db = self._connect()
        try:
            return int(db.execute("SELECT COUNT(*) FROM chain").fetchone()[0])
        finally:
            db.close()

    # -- integrity --------------------------------------------------------
    def verify_chain(self) -> tuple[bool, list[str]]:
        """Walk the chain and report every break.

        Returns ``(ok, problems)``. Problems name the sequence number, because
        "the ledger is broken" is not an actionable statement.
        """
        problems: list[str] = []
        prev = GENESIS
        expected_seq = 1
        for entry in self.entries():
            if entry.seq != expected_seq:
                problems.append(
                    f"seq {entry.seq}: gap in the chain, expected {expected_seq} "
                    "— a record was removed"
                )
                expected_seq = entry.seq
            if entry.prev_hash != prev:
                problems.append(
                    f"seq {entry.seq}: prev_hash {entry.prev_hash[:12]} does not match the "
                    f"preceding link {prev[:12]} — the chain was re-ordered or spliced"
                )
            if entry.link_hash != entry.expected_link_hash():
                problems.append(
                    f"seq {entry.seq}: link_hash does not match its own content "
                    "— the record was edited in place"
                )
            try:
                if not entry.evidence().verify():
                    problems.append(
                        f"seq {entry.seq}: payload does not match content_hash "
                        f"{entry.content_hash[:12]} — the evidence body was edited"
                    )
            except Exception as exc:
                problems.append(f"seq {entry.seq}: payload is unreadable ({exc})")
            prev = entry.link_hash
            expected_seq += 1
        return (not problems, problems)

    def head_attestation(self) -> dict[str, Any]:
        """The value to sign or publish so the chain cannot be silently rewound.

        Signing this with a key held outside the system, or publishing it where
        it cannot be retracted, is what turns tamper-*evidence* into tamper-
        *proof*. This function does not sign; producing and protecting the key
        is an operational decision that must not be made implicitly by a
        library.
        """
        entries = self.entries()
        head = entries[-1] if entries else None
        return {
            "ledger_schema_version": LEDGER_SCHEMA_VERSION,
            "length": len(entries),
            "head_seq": head.seq if head else 0,
            "head_link_hash": head.link_hash if head else GENESIS,
            "attested_at": format_utc(utc_now()),
        }

    def export(self, *, subject: str | None = None) -> dict[str, Any]:
        """Export a verifiable bundle, refusing if the chain does not verify.

        An export is the moment the records leave the system and start being
        relied upon, so it is the right moment to fail loudly.
        """
        ok, problems = self.verify_chain()
        if not ok:
            raise LedgerIntegrityError(
                "refusing to export a ledger that does not verify:\n  "
                + "\n  ".join(problems)
            )
        entries = self.entries(subject=subject)
        return {
            "ledger_schema_version": LEDGER_SCHEMA_VERSION,
            "exported_at": format_utc(utc_now()),
            "subject": subject or "",
            "chain_verified": True,
            "attestation": self.head_attestation(),
            "entries": [
                {
                    "seq": e.seq,
                    "at": e.at,
                    "kind": e.kind,
                    "subject": e.subject,
                    "content_hash": e.content_hash,
                    "prev_hash": e.prev_hash,
                    "link_hash": e.link_hash,
                    "actor": e.actor,
                    "evidence": e.payload,
                }
                for e in entries
            ],
        }
