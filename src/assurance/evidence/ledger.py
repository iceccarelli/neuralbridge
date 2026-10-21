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
from ..core.sqlite import enable_wal, retry_locked
from . import chain_cache

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
        # sqlite3's context manager commits or rolls back; it does NOT close.
        # Closing is explicit here because a ledger is constructed once per
        # request in a served deployment, and a leaked handle per construction
        # exhausts the file table under load.
        db = self._connect()
        try:
            # Several first opens can race (a new tenant's first parallel
            # requests). The schema script is idempotent and takes no write lock
            # on an existing file. The version row is READ first: a plain open of
            # an existing ledger must not queue behind a writer. Only when it is
            # missing is it written, with INSERT OR IGNORE so the loser of a race
            # reads the winner's row. Busy errors wait (boundedly); they are not
            # failures.
            retry_locked(lambda: db.executescript(_SCHEMA), db=db)
            row = db.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                retry_locked(lambda: db.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(LEDGER_SCHEMA_VERSION),),
                ), db=db)
                row = db.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if int(row[0]) != LEDGER_SCHEMA_VERSION:
                raise LedgerIntegrityError(
                    f"{self.path} was written by ledger schema {row[0]}, this build speaks "
                    f"{LEDGER_SCHEMA_VERSION}. Refusing rather than guessing."
                )
        finally:
            db.close()

    # -- plumbing ---------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        enable_wal(db)
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
    @staticmethod
    def _check_entry(entry: LedgerEntry, prev: str, expected_seq: int) -> list[str]:
        """Everything wrong with one record, given the link and sequence it must follow."""
        problems: list[str] = []
        if entry.seq != expected_seq:
            problems.append(
                f"seq {entry.seq}: gap in the chain, expected {expected_seq} "
                "— a record was removed"
            )
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
        return problems

    def verify_full(self) -> tuple[list[str], int, str]:
        """Walk the whole chain: ``(problems, head_seq, head_link_hash)``.

        The head is the last record the walk itself read, so a record appended
        while it ran is not claimed as verified.
        """
        problems: list[str] = []
        prev, expected_seq = GENESIS, 1
        head_seq = 0
        try:
            entries = self.entries()
        except sqlite3.DatabaseError as exc:
            if isinstance(exc, sqlite3.OperationalError):
                raise  # busy/locked/unreadable path: transient or environmental, not a finding
            # The file opens but its pages are damaged (SQLITE_CORRUPT / NOTADB). A
            # verifier that crashes on the very thing it exists to find is no verifier.
            return ([f"the ledger's storage is damaged and cannot be read ({exc}) "
                     "— restore from a backup and run "
                     "`python -m assurance.evidence.restore_check verify`"], 0, GENESIS)
        for entry in entries:
            problems.extend(self._check_entry(entry, prev, expected_seq))
            expected_seq = entry.seq + 1
            prev, head_seq = entry.link_hash, entry.seq
        return problems, head_seq, prev

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Walk the chain and report every break.

        Returns ``(ok, problems)``. Problems name the sequence number, because
        "the ledger is broken" is not an actionable statement.

        Always a full walk. It also settles what :meth:`verify_cached` believes:
        a clean walk becomes the new verified head, a failing one forgets it, so a
        cache can never hold a pass that a full walk has since contradicted.
        """
        problems, head_seq, head_link = self.verify_full()
        key = chain_cache.identity(self.path)
        if problems:
            chain_cache.drop(key)
        else:
            chain_cache.remember(key, head_seq, head_link, chain_cache.now())
        return (not problems, problems)

    def _verify_since(self, seq: int, link_hash: str) -> tuple[list[str], int, str]:
        """Check the remembered head and everything appended after it, in one snapshot."""
        db = self._connect()
        try:
            db.execute("BEGIN")
            problems: list[str] = []
            head_seq, head_link = seq, link_hash
            if seq > 0:
                row = db.execute("SELECT * FROM chain WHERE seq = ?", (seq,)).fetchone()
                if row is None:
                    return ([f"seq {seq}: the record that was the verified head is gone "
                             "— the chain was truncated, or the ledger was replaced"],
                            seq, link_hash)
                head = self._row_to_entry(row)
                if head.link_hash != link_hash:
                    problems.append(
                        f"seq {seq}: the record at the verified head has changed "
                        f"({head.link_hash[:12]} where {link_hash[:12]} was verified) "
                        "— the chain was rewound and rewritten, or the ledger was replaced")
                problems.extend(self._check_entry(head, head.prev_hash, seq))
                if problems:
                    return problems, seq, link_hash
            prev, expected = link_hash, seq + 1
            for row in db.execute("SELECT * FROM chain WHERE seq > ? ORDER BY seq", (seq,)):
                entry = self._row_to_entry(row)
                problems.extend(self._check_entry(entry, prev, expected))
                expected = entry.seq + 1
                prev, head_seq, head_link = entry.link_hash, entry.seq, entry.link_hash
            return problems, head_seq, head_link
        finally:
            db.close()

    def verify_cached(self) -> tuple[bool, list[str]]:
        """Does the chain still verify, at O(new records) cost? ``(ok, problems)``.

        A full walk the first time in this process, whenever the last full walk
        is older than ``ASSURANCE_CHAIN_RECHECK_SECONDS`` (default 60; ``0`` =
        always), and whenever the file is not the one last verified. Otherwise the
        remembered head is re-read and re-checked and every record appended since is
        verified completely. An edit to an *old* record is therefore seen by the
        next full walk, not by every call; see :mod:`assurance.evidence.chain_cache`
        for the trade-off and what still needs a signed head attestation.
        """
        key = chain_cache.identity(self.path)
        known = chain_cache.lookup(key)
        now = chain_cache.now()
        interval = chain_cache.recheck_seconds()
        if known is None or interval <= 0 or now - known.full_pass_at >= interval:
            problems, head_seq, head_link = self.verify_full()
            started = now
        else:
            problems, head_seq, head_link = self._verify_since(known.seq, known.link_hash)
            started = known.full_pass_at
        if problems:
            chain_cache.drop(key)
            return False, problems
        chain_cache.remember(key, head_seq, head_link, started)
        return True, []

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

    def snapshot_to(self, destination: str | Path) -> Path:
        """Copy the whole ledger to ``destination``, WAL and all.

        A plain file copy of a WAL-mode database copies the main file and
        leaves the write-ahead log behind, so the copy can be missing its most
        recent records — or, on a freshly written ledger, every record and even
        the schema. Anything that duplicates a ledger (a backup, a test, an
        export to hand to an auditor) must come through here.
        """
        dest = Path(destination)
        dest.parent.mkdir(parents=True, exist_ok=True)
        source = self._connect()
        try:
            target = sqlite3.connect(dest)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        return dest

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
