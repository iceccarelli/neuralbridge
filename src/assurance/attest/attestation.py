"""Signed head attestations: making a rewind undeniable.

The ledger's own integrity check answers "has this chain been edited?". It
cannot answer "has this chain been *shortened*?", because a chain rebuilt from
genesis with the inconvenient records left out verifies perfectly. Every
hash-chained audit log has this hole, and most products that sell one do not
say so.

The hole closes when a value that depends on the whole history leaves the
building periodically and is signed by a key the holder of the database does
not have. Then a rewind is not a matter of opinion: here is a signature, made
at a stated time, over a head that the present ledger cannot produce.

Three refusals carry the weight, and each one is a finding rather than an
error:

* **A ledger that does not verify is never attested.** A signature over a
  broken chain converts a detected problem into a signed assertion that
  everything is fine.
* **A ledger shorter than the last attestation is refused.** That refusal *is*
  the rewind detector. It is the reason to run this at all.
* **A ledger that has changed an already-attested link is refused.** Same
  length, different history — a fork. Detected by re-reading the exact
  sequence numbers previously signed for.

Attestations live *outside* the ledger, in an append-only JSONL log. Sealing an
attestation into the ledger it attests would change the head it had just
attested, which is either a lie or an infinite regress. The log is also the
thing worth copying off the machine — it is small, it is text, and it is the
only part of this system that a rewind cannot reach.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..core.errors import AssuranceError
from ..core.identity import content_hash_of, format_utc, parse_utc, utc_now
from ..core.text import neutralise
from ..evidence.ledger import GENESIS, EvidenceLedger
from ..evidence.verify_export import DuplicateKeyError, loads_no_duplicate_keys
from .keys import SigningKey, VerifyingKey

__all__ = [
    "ATTESTATION_FORMAT",
    "ATTESTATION_FORMAT_BOUND",
    "KNOWN_ATTESTATION_FORMATS",
    "LOCK_TIMEOUT_SECONDS",
    "NO_EXPECTATION_NOTE",
    "AttestationBasis",
    "AttestationBusyError",
    "AttestationError",
    "AttestationLog",
    "AttestationLogDamagedError",
    "AttestationTornTailError",
    "HeadAttestation",
    "LedgerHead",
    "LogVerdict",
    "attest",
    "describe_anchor",
    "head_of",
    "select_anchor",
    "verify_log",
]

#: Written into every attestation so a future reader knows what the bytes under
#: the signature were. Changing what is signed without changing this would make
#: old signatures unverifiable for a reason nobody could diagnose.
ATTESTATION_FORMAT = "assurance.head-attestation.v1"
#: The format of a head that is signed together with the identity of the ledger (and,
#: optionally, the tenant) it describes. A verifier that only knows ``v1`` reports ``v2`` as an
#: unknown format rather than checking a signature over bytes it cannot recompute.
ATTESTATION_FORMAT_BOUND = "assurance.head-attestation.v2"
KNOWN_ATTESTATION_FORMATS = (ATTESTATION_FORMAT, ATTESTATION_FORMAT_BOUND)


#: How long a writer waits for the log's lock before giving up. Signing one head is
#: milliseconds of work, so ten seconds is "something is wrong or very busy", not
#: "queue politely": past it the caller gets a typed busy error (HTTP 503 with
#: ``Retry-After``) instead of a request that holds a worker thread indefinitely.
LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_POLL_SECONDS = 0.02


class AttestationError(AssuranceError):
    """An attestation cannot be made, or a log does not hold up."""


class AttestationLogDamagedError(AttestationError):
    """The log file itself cannot be read as a log: a fault to repair, not a finding.

    Distinct from a refusal (a rewind, a fork), which is the *answer* this system
    exists to give. A damaged file says nothing about the ledger; it says the
    file needs a person.
    """


class AttestationTornTailError(AttestationLogDamagedError):
    """The log ends in an unterminated line that is not a record.

    Either a write is in flight or a crash cut one off, and a reader cannot tell
    which. For *listing* the log that is a warning; for *choosing the anchor of an
    export* it is damage, because the missing line may have been the newest signed
    record, and the record before it would then be a stale anchor with no sign of
    the gap. Subclassing the damaged-log error keeps every caller that already treats
    that as a fault correct.
    """


class AttestationBusyError(AssuranceError):
    """The log's lock was not free within the deadline. Retry; nothing was written.

    Deliberately not an :class:`AttestationError`: it is not a finding about any
    ledger, and a caller that treats every ``AttestationError`` as "refused" must
    not mislabel contention as one.
    """

    retry_after_seconds = 2


class AttestationBasis(StrEnum):
    """How the signer came to know the head it signed.

    The distinction is the whole difference between two products. When the
    signer read the ledger itself, the signature says the chain verified and
    every previously attested position still resolved the same way. When the
    holder *told* the signer what the head was, the signature says only that
    this value was presented at this time — which is still enough to make a
    later rewind contradict a signed statement, and is emphatically not enough
    to say the records behind it were ever coherent.

    Recording which one happened, inside the signed bytes, is what stops the
    weaker statement from being read later as the stronger one.
    """

    READ_FROM_LEDGER = "read_from_ledger"
    DECLARED_BY_HOLDER = "declared_by_holder"


@dataclass(frozen=True)
class LedgerHead:
    """The three numbers that identify a ledger's state, and where they came from."""

    length: int
    head_seq: int
    head_link_hash: str
    basis: AttestationBasis = AttestationBasis.DECLARED_BY_HOLDER
    #: The lineage id of the ledger this head was read from (``READ_FROM_LEDGER``), or ""
    #: when the ledger has none (opened read-only, never minted) or the head was merely
    #: declared. "" is signed as an *unbound* attestation, never as one for "any ledger".
    ledger_id: str = ""

    def __post_init__(self) -> None:
        if self.length < 0 or self.head_seq < 0:
            raise AttestationError("a ledger cannot have a negative length or head.")
        if self.length == 0:
            if self.head_seq != 0 or self.head_link_hash != GENESIS:
                raise AttestationError(
                    "an empty ledger has head seq 0 and the genesis link hash; "
                    f"this one claims seq {self.head_seq}."
                )
        elif self.head_seq < 1:
            raise AttestationError(
                f"a ledger of {self.length} record(s) cannot have head seq "
                f"{self.head_seq}."
            )
        if len(self.head_link_hash) != 64 or not all(
            c in "0123456789abcdef" for c in self.head_link_hash
        ):
            raise AttestationError(
                f"{self.head_link_hash!r} is not a SHA-256 link hash. Refusing to "
                "sign a value that cannot have come from a ledger."
            )


def head_of(ledger: EvidenceLedger) -> LedgerHead:
    """Read the head of *ledger*, refusing if the chain does not verify.

    A signature over a broken chain converts a detected break into a signed
    statement that all is well, so the verification is not optional here.
    """
    ok, problems = ledger.verify_chain()
    if not ok:
        raise AttestationError(
            "refusing to attest a ledger that does not verify. A signature here "
            "would turn a detected break into a signed statement that all is "
            "well:\n  " + "\n  ".join(problems)
        )
    entries = ledger.entries()
    head = entries[-1] if entries else None
    return LedgerHead(
        length=len(entries),
        head_seq=head.seq if head else 0,
        head_link_hash=head.link_hash if head else GENESIS,
        basis=AttestationBasis.READ_FROM_LEDGER,
        ledger_id=ledger.ledger_id() or "",
    )


_REQUIRED_FIELDS = ("format", "sequence", "ledger_length", "head_seq", "head_link_hash", "basis",
                    "attested_at", "key_fingerprint", "previous")
_INT_FIELDS = ("sequence", "ledger_length", "head_seq")
_STR_FIELDS = ("format", "head_link_hash", "attested_at", "key_fingerprint", "previous")


def _exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class HeadAttestation:
    """One signed statement about the state of a ledger at a moment.

    The signature covers :meth:`signed_payload` — everything here except the
    signature itself. That includes ``previous``, which chains the attestation
    log the same way the ledger chains its records, so an attestation cannot be
    quietly dropped from the middle of the log either.
    """

    format: str
    sequence: int
    ledger_length: int
    head_seq: int
    head_link_hash: str
    basis: AttestationBasis
    attested_at: str
    key_fingerprint: str
    previous: str
    note: str = ""
    signature: str = ""
    #: Inside the signed bytes of a ``v2`` attestation; "" for ``v1`` (unbound).
    ledger_id: str = ""
    tenant: str = ""

    @property
    def binding(self) -> str:
        """``"bound"`` when the signature covers a ledger id, else ``"unbound"``."""
        return "bound" if (self.format == ATTESTATION_FORMAT_BOUND and self.ledger_id) else "unbound"

    # -- bytes under the signature ---------------------------------------
    def _body(self) -> dict[str, Any]:
        body = self._v1_body()
        if self.format == ATTESTATION_FORMAT_BOUND:
            # Only a v2 record signs these, so every v1 signature still recomputes. Stripping
            # them from a v2 record changes the bytes (and the format string is signed too),
            # so a bound head cannot be downgraded to an unbound one that still verifies.
            body["ledger_id"] = self.ledger_id
            body["tenant"] = self.tenant
        return body

    def _v1_body(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "sequence": self.sequence,
            "ledger_length": self.ledger_length,
            "head_seq": self.head_seq,
            "head_link_hash": self.head_link_hash,
            "basis": self.basis.value,
            "attested_at": self.attested_at,
            "key_fingerprint": self.key_fingerprint,
            "previous": self.previous,
            "note": self.note,
        }

    def signed_payload(self) -> bytes:
        """Exactly the bytes the signature is over. Canonical, so portable."""
        from ..core.identity import canonical_json

        return canonical_json(self._body()).encode("utf-8")

    def content_hash(self) -> str:
        """Names this attestation. What the *next* attestation points back to."""
        return content_hash_of(self._body())

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, reject_unknown: bool = False) -> HeadAttestation:
        """Read one record, exactly: every field has the type the signer wrote.

        A number is a whole number (not ``"11"``, not ``11.9``, not ``true``) and the rest is
        text; ``int()`` and ``str()`` used to coerce them, so one record read as two different
        things to two parsers. Absent ``note`` / ``signature`` default as before. With
        ``reject_unknown`` a field the signer never writes is refused, not dropped: a bundle's
        embedded anchor is a signed statement and nothing unsigned may ride beside it.
        """
        missing = [k for k in _REQUIRED_FIELDS if k not in data]
        if missing:
            raise AttestationError(
                "attestation record is missing " + ", ".join(missing)
                + " — it was not written by this system, or it was edited."
            )
        bound = data["format"] == ATTESTATION_FORMAT_BOUND
        wrong = [k for k in _INT_FIELDS if not _exact_int(data[k])]
        wrong += [k for k in (*_STR_FIELDS, "basis") if not isinstance(data[k], str)]
        wrong += [k for k in ("note", "signature", *(("ledger_id", "tenant") if bound else ()))
                  if k in data and not isinstance(data[k], str)]
        if wrong:
            raise AttestationError(
                "attestation record has the wrong type for " + ", ".join(wrong)
                + " (whole numbers and text only) — it was not written by this system, or it "
                "was edited.")
        if reject_unknown:
            allowed = {*_REQUIRED_FIELDS, "note", "signature",
                       *(("ledger_id", "tenant") if bound else ())}
            extra = sorted(str(k)[:40] for k in data if k not in allowed)
            if extra:
                raise AttestationError(
                    "attestation record carries field(s) the signer never writes: "
                    + ", ".join(neutralise(k) for k in extra[:5])
                    + " — unsigned content beside a signed statement is refused.")
        try:
            return cls(
                format=data["format"],
                sequence=data["sequence"],
                ledger_length=data["ledger_length"],
                head_seq=data["head_seq"],
                head_link_hash=data["head_link_hash"],
                basis=AttestationBasis(data["basis"]),
                attested_at=data["attested_at"],
                key_fingerprint=data["key_fingerprint"],
                previous=data["previous"],
                note=data.get("note", ""),
                signature=data.get("signature", ""),
                # Only a v2 record signs these. On a v1 record they are unsigned text someone
                # added, so they are dropped rather than believed.
                ledger_id=data.get("ledger_id", "") if bound else "",
                tenant=data.get("tenant", "") if bound else "",
            )
        except OverflowError as exc:  # pragma: no cover - whole numbers cannot overflow
            raise AttestationError(
                "attestation record holds a number that is not a whole number "
                f"({exc}) — it was not written by this system, or it was edited."
            ) from exc

    def signature_bytes(self) -> bytes:
        try:
            return base64.b64decode(self.signature.encode("ascii"), validate=True)
        except Exception as exc:  # noqa: BLE001 - any decode failure is the same finding
            raise AttestationError(
                f"attestation {self.sequence} carries a signature that is not base64 "
                f"({exc}). Treat the log as damaged, not as unsigned."
            ) from exc

    def verified_by(self, key: VerifyingKey) -> bool:
        if not self.signature:
            return False
        return key.verify(self.signed_payload(), self.signature_bytes())

    @property
    def note_is_tenant_supplied(self) -> bool:
        """True when ``note`` is text the *requester* typed, not the key holder.

        A ``declared_by_holder`` attestation is made for somebody who handed the
        signer three numbers and a note; the signature covers the note because it
        covers everything, which does not make it the key holder's statement. The
        basis is inside the signed bytes, so this cannot be lifted off one record
        and put on another. Derived rather than stored: the signed format is
        unchanged, so every existing attestation and every verifier still works.
        """
        return bool(self.note) and self.basis is AttestationBasis.DECLARED_BY_HOLDER


def select_anchor(
    records: Sequence[HeadAttestation], *, accept_declared: bool = False,
) -> HeadAttestation | None:
    """The one rule for which attestation an export embeds as its ``anchor``.

    Used by the API (and so the MCP tool that calls it) and by every CLI export,
    so the same log can never anchor one export to a different record depending on
    which door it came through.

    The newest ``read_from_ledger`` record wins: the signer read the chain and saw
    it verify. A ``declared_by_holder`` record is three numbers somebody typed
    about a ledger the signer never saw; it describes the *holder's* ledger, not
    necessarily the one being exported, so it is never chosen unless
    ``accept_declared`` says a person pointed at this log on purpose (the offline
    CLI's ``--attestations``). Even then a declared head over zero records anchors
    nothing and is refused rather than embedded as if it did.
    """
    for record in reversed(records):
        if record.basis is AttestationBasis.READ_FROM_LEDGER:
            return record
    if not accept_declared:
        return None
    for record in reversed(records):
        if record.head_seq == 0:
            raise AttestationError(
                f"attestation {record.sequence} was declared by the holder over zero "
                "records. It anchors nothing: an export cannot show that no record "
                "was removed up to a head that covers none."
            )
        return record
    return None


def describe_anchor(anchor: dict[str, Any] | HeadAttestation) -> str:
    """One line for the CLI to say what an embedded anchor is, and is not."""
    data = anchor.to_dict() if isinstance(anchor, HeadAttestation) else anchor
    where = f"attestation {data['sequence']} (seq {data['head_seq']})"
    if data.get("basis") == AttestationBasis.DECLARED_BY_HOLDER.value:
        return (
            f"anchor is {where}, declared by the holder: the signer was told this head "
            "and it was not read from the ledger, so it is not a check that the chain "
            "verified. Records after it are covered by no signature"
        )
    return f"anchored to {where}; records after it are covered by no signature"


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(log: AttestationLog) -> threading.Lock:
    """One in-process lock per *real* file, however its path was spelled."""
    key = os.path.realpath(log.path)
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


class AttestationLog:
    """An append-only JSONL file of attestations, one per line.

    Deliberately not a database. It must be copyable by somebody who does not
    have this software installed, readable by somebody who does not trust it,
    and small enough to paste into an email to an auditor.

    ``label`` is how this log is named in error text. It defaults to the path,
    which is right for a CLI that was handed the path; a server passes a label so
    that no message it sends to a client contains a filesystem path.
    """

    def __init__(self, path: str | Path, *, label: str | None = None) -> None:
        self.path = Path(path)
        self.label = label or str(path)

    # -- reading -----------------------------------------------------------
    def read(self) -> list[HeadAttestation]:
        """Every record. Takes no lock, so it never waits and never blocks a writer.

        A writer appends one line at a time, so a reader that races it can see the
        file end part-way through a line. That last, unterminated, unparseable line
        is ignored here (see :meth:`has_torn_tail`): it is either an append still in
        flight or the debris of a crash, and in neither case was a signed record
        ever handed to anybody. A damaged line *anywhere else* is an error.
        """
        return self.scan()[0]

    def has_torn_tail(self) -> bool:
        """True when the file ends in an unterminated line that is not a record."""
        return self.scan()[1]

    def scan(self) -> tuple[list[HeadAttestation], bool]:
        """``(records, torn_tail)``: every readable record, and whether the file ends
        in an unterminated line that is not one."""
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return [], False
        *lines, tail = raw.split(b"\n")      # tail is b"" when the file ends in a newline
        out: list[HeadAttestation] = []
        for number, line in enumerate(lines, start=1):
            if line.strip():
                out.append(self._parse(line, number))
        torn = False
        if tail.strip():
            try:
                out.append(self._parse(tail, len(lines) + 1))
            except AttestationLogDamagedError:
                torn = True
        return out, torn

    def _parse(self, line: bytes, number: int) -> HeadAttestation:
        try:
            data = loads_no_duplicate_keys(line.decode("utf-8"))
        except (ValueError, RecursionError) as exc:
            what = ("repeats a member name" if isinstance(exc, DuplicateKeyError)
                    else "is not JSON")
            raise AttestationLogDamagedError(
                f"{self.label} line {number} {what} ({neutralise(exc)}). A damaged "
                "attestation log is a finding: it is the one file a rewind "
                "cannot reach, so damage to it is worth explaining."
            ) from exc
        if not isinstance(data, dict):
            raise AttestationLogDamagedError(
                f"{self.label} line {number} is not an attestation record.")
        try:
            return HeadAttestation.from_dict(data)
        except (AttestationError, ValueError, TypeError) as exc:
            raise AttestationLogDamagedError(
                f"{self.label} line {number} is not a readable attestation: {exc}"
            ) from exc

    def _read_for_append(self) -> list[HeadAttestation]:
        """The records, for a caller about to append: a torn tail is refused.

        Appending after an unterminated line would glue the new record onto the
        debris and turn a recoverable tail into a damaged middle. The file is
        evidence; it is left exactly as found for a person to repair.
        """
        records, torn = self.scan()
        if torn:
            raise AttestationTornTailError(
                f"{self.label} ends in an unterminated line (a write that did not "
                "finish). Nothing was appended: doing so would merge the new record "
                "into the damaged one. Preserve the file as it is and have the "
                "operator repair it."
            )
        return records

    def _read_for_anchor(self) -> list[HeadAttestation]:
        """The records, for a caller choosing the anchor of an export: a torn tail
        is damage, not something to read around.

        :meth:`read` drops an unterminated unparseable last line because, for listing
        the log, that is the honest thing (and :meth:`scan` says it happened). An export
        is different: the dropped line may be the newest signed attestation, and the
        record before it would then be embedded as the anchor with no sign of the gap,
        which is exactly the silently-unanchored export the registry says never
        happens. A ledger rewound after the lost record was signed would then export
        cleanly. The file is left as found.
        """
        records, torn = self.scan()
        if torn:
            raise AttestationTornTailError(
                f"{self.label} ends in an unterminated line (a write that did not "
                "finish, or one still in flight). The newest attestation may be the "
                "one that was cut off, so no earlier record is chosen as the anchor "
                "in its place. Preserve the file as it is and have the operator "
                "repair it."
            )
        return records

    def last(self) -> HeadAttestation | None:
        records = self.read()
        return records[-1] if records else None

    def require_last(self) -> HeadAttestation:
        """The newest record of *any* basis, for a caller that *asked* for one.

        A missing or empty log is an error here, not "no anchor". This is **not** the
        rule for which record anchors an export: that is :meth:`require_anchor`,
        which every export path shares.
        """
        if not self.path.exists():
            raise AttestationError(
                f"{self.label} does not exist. Nothing was read, and no attestation "
                "was invented.")
        latest = self.last()
        if latest is None:
            raise AttestationError(f"{self.label} holds no attestations.")
        return latest

    def anchor(self, *, accept_declared: bool = False) -> HeadAttestation | None:
        """The record an export would embed (:func:`select_anchor`), or ``None``.

        Raises :class:`AttestationTornTailError` when the log ends in an unterminated
        line: see :meth:`_read_for_anchor`.
        """
        return select_anchor(self._read_for_anchor(), accept_declared=accept_declared)

    def require_anchor(self) -> HeadAttestation:
        """The record an offline export embeds because a person named this log.

        The operator's explicit ``--attestations`` choice allows a record the holder
        declared when the log holds nothing the signer read itself; the embedded
        anchor carries its ``basis`` and the CLI says so. A missing or empty log is
        an error: an export told to use a log must not quietly carry on without one.
        """
        if not self.path.exists():
            raise AttestationError(
                f"{self.label} does not exist. Nothing was read, and no attestation "
                "was invented.")
        records = self._read_for_anchor()
        if not records:
            raise AttestationError(f"{self.label} holds no attestations.")
        chosen = select_anchor(records, accept_declared=True)
        if chosen is None:  # pragma: no cover - records is non-empty, so one basis matched
            raise AttestationError(f"{self.label} holds no usable attestation.")
        return chosen

    # -- writing -----------------------------------------------------------
    def lock_path(self) -> Path:
        """The sidecar file ``flock`` is taken on: beside the *real* file.

        Keyed by the resolved path, like the in-process lock, so a symlinked
        directory or a symlinked file cannot give two processes two locks over one
        log.
        """
        return Path(os.path.realpath(self.path) + ".lock")

    @contextmanager
    def locked(self, timeout: float | None = None) -> Iterator[None]:
        """Serialise read-decide-append across threads and processes.

        ``attest`` derives the next sequence and ``previous`` hash from the last
        record, so two writers that read the same tail would sign two records
        with the same sequence: a forked log that ``verify_log`` rightly refuses
        but that has already handed a signed record to somebody. One in-process
        lock per real path plus ``flock`` on a sidecar file covers both.

        Waiting is bounded: ``LOCK_NB`` polling against a deadline
        (:data:`LOCK_TIMEOUT_SECONDS` unless *timeout* is given), then
        :class:`AttestationBusyError`. A process that holds the sidecar lock and
        never lets go must cost a request ten seconds, not a worker for ever.
        """
        budget = max(LOCK_TIMEOUT_SECONDS if timeout is None else timeout, 0.0)
        deadline = time.monotonic() + budget
        thread_lock = _thread_lock_for(self)
        if not thread_lock.acquire(timeout=budget):
            raise self._busy(budget)
        try:
            try:
                import fcntl
            except ImportError:  # pragma: no cover - not POSIX: one process only
                yield
                return
            sidecar = self.lock_path()
            sidecar.parent.mkdir(parents=True, exist_ok=True)
            with open(sidecar, "a+") as handle:
                while True:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise self._busy(budget) from None
                        time.sleep(_LOCK_POLL_SECONDS)
                try:
                    yield
                finally:
                    fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            thread_lock.release()

    def _busy(self, waited: float) -> AttestationBusyError:
        return AttestationBusyError(
            f"{self.label} is being written by another request (waited {waited:g}s). "
            "Nothing was signed or appended; retry shortly.")

    def append(self, attestation: HeadAttestation) -> HeadAttestation:
        """Append one record. Call inside :meth:`locked` when the record's
        sequence was derived from a prior :meth:`read`.

        The file must end in a newline or the new record would be glued onto the last
        line and turn it into an unreadable middle. If the last line is a complete,
        parseable record that merely lost its newline, the newline is written first (a
        repair that changes no signed byte). If it is not a record (a torn write) the
        append is refused with :class:`AttestationTornTailError` and the file is left
        exactly as found.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(attestation.to_dict(), sort_keys=True, separators=(",", ":"))
        with self.path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            lead = b""
            if size:
                handle.seek(size - 1)
                if handle.read(1) != b"\n":
                    handle.seek(0)
                    *lines, tail = handle.read().split(b"\n")
                    try:
                        self._parse(tail, len(lines) + 1)
                    except AttestationLogDamagedError as exc:
                        raise AttestationTornTailError(
                            f"{self.label} ends in an unterminated line that is not a "
                            "record. Nothing was appended: doing so would merge the new "
                            "record into the damaged one. Preserve the file as it is "
                            "and have the operator repair it."
                        ) from exc
                    lead = b"\n"
            handle.write(lead + line.encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return attestation

    def __len__(self) -> int:
        return len(self.read())


def attest(
    source: EvidenceLedger | LedgerHead,
    key: SigningKey,
    log: AttestationLog,
    *,
    note: str = "",
    rotating: bool = False,
    now: datetime | None = None,
    tenant: str = "",
) -> HeadAttestation:
    """Sign a ledger head, refusing every case that would lie.

    A head read from a ledger that has a lineage id is signed **together with that id** (and
    *tenant*, if given): format ``v2``. A ledger without one is signed as before (``v1``,
    *unbound*) and every verdict says so. A log is one ledger's: signing a head of ledger B into
    a log that holds heads bound to ledger A is refused, and so is appending an unbound head to
    a log of bound ones (that would be a downgrade).

    *source* is either a ledger, which is read and verified here, or a
    :class:`LedgerHead` somebody else has declared — the counter-signature
    case, where the signer never sees the records and says so in the signed
    bytes. Returns the attestation, already appended to *log*.

    Raises :class:`AttestationError` — and the message is the finding — when
    the chain does not verify, when the ledger is shorter than it was at the
    last attestation, when an already-attested link has changed, or when a
    different key is being used without ``rotating=True``.

    The length, head and fork comparisons are made **only against earlier records
    of the same basis**. A ``read_from_ledger`` record describes the ledger this
    process read; a ``declared_by_holder`` record describes whatever ledger the
    caller said they held. One log may hold both (a hosted account's log does), and
    comparing a head with a record about a different ledger is not a rewind
    detector: it tells a customer their records were removed because the service's
    own ledger was longer, and lets one inflated number stop the other kind of
    signing for good. The key check and the ``previous`` hash chain still span the
    whole file.

    The ledger is read inside the lock, deliberately: a snapshot taken before it
    could be older than a head appended meanwhile and be refused as a "rewind", and
    the head would be older than the ``attested_at`` that is signed beside it. The
    API path declares a head and reads no ledger, so it holds the lock only for the
    small log.

    Raises :class:`AttestationLogDamagedError` (an :class:`AttestationError` that is
    a fault, not a finding) when the log cannot be read, and
    :class:`AttestationBusyError` when its lock is not free within
    :data:`LOCK_TIMEOUT_SECONDS`.
    """
    with log.locked():
        head: LedgerHead
        by_seq: dict[int, str] | None
        if isinstance(source, EvidenceLedger):
            head = head_of(source)
            by_seq = {e.seq: e.link_hash for e in source.entries()}
        else:
            head = source
            by_seq = None

        history = log._read_for_append()
        previous = history[-1] if history else None
        bound_ids = {r.ledger_id for r in history if r.binding == "bound"}
        if head.ledger_id and bound_ids and head.ledger_id not in bound_ids:
            raise AttestationError(
                f"refusing to attest: this log holds heads bound to ledger "
                f"{', '.join(sorted(neutralise(i[:12]) for i in bound_ids))}, and this head was read from "
                f"ledger {head.ledger_id[:12]}. A log belongs to one ledger; signing another "
                "ledger's head into it is a cross-ledger substitution."
            )
        if not head.ledger_id and bound_ids and head.basis is AttestationBasis.READ_FROM_LEDGER:
            raise AttestationError(
                "refusing to attest: this ledger has no lineage id, but the log holds heads "
                "bound to a ledger id. An unbound head in a bound log would be a downgrade."
            )
        tenants = {r.tenant for r in history if r.tenant}
        if tenant and tenants and tenant not in tenants:
            raise AttestationError(
                f"refusing to attest: this log is for tenant "
                f"{', '.join(sorted(neutralise(t) for t in tenants))}, "
                f"not {tenant}.")
        same_basis = [r for r in history if r.basis is head.basis]
        prior = same_basis[-1] if same_basis else None

        if prior is not None:
            if head.length < prior.ledger_length:
                raise AttestationError(
                    f"refusing to attest: the ledger holds {head.length} record(s), but "
                    f"attestation {prior.sequence} signed for {prior.ledger_length} "
                    f"at {neutralise(prior.attested_at)}. An append-only ledger does not get "
                    "shorter. Records were removed after they were attested — this is "
                    "the event this whole mechanism exists to catch. Preserve the "
                    "database and the attestation log as they are."
                )
            if head.head_seq < prior.head_seq:
                raise AttestationError(
                    f"refusing to attest: head seq {head.head_seq} is behind the "
                    f"{prior.head_seq} signed at {neutralise(prior.attested_at)}."
                )
            for earlier in same_basis:
                if earlier.head_seq == 0:
                    continue
                if by_seq is not None:
                    current = by_seq.get(earlier.head_seq)
                    if current is None:
                        raise AttestationError(
                            f"refusing to attest: seq {earlier.head_seq} was attested at "
                            f"{neutralise(earlier.attested_at)} and is no longer in the ledger."
                        )
                elif earlier.head_seq == head.head_seq:
                    current = head.head_link_hash
                else:
                    continue
                if current != earlier.head_link_hash:
                    raise AttestationError(
                        f"refusing to attest: seq {earlier.head_seq} now links as "
                        f"{neutralise(current[:12])} but was attested as "
                        f"{neutralise(earlier.head_link_hash[:12])} at "
                        f"{neutralise(earlier.attested_at)}. The "
                        "chain was rebuilt — same position, different history. This is "
                        "a fork, not a gap, and it will not show up in verify_chain."
                    )
        if previous is not None:
            if previous.key_fingerprint != key.fingerprint and not rotating:
                raise AttestationError(
                    f"refusing to attest: this log was signed by key "
                    f"{neutralise(previous.key_fingerprint)} and the key offered is "
                    f"{key.fingerprint}. If this is a deliberate rotation, say so "
                    "explicitly; otherwise somebody is continuing your attestation log "
                    "with a key of their own, which is exactly what a rewind looks "
                    "like when nobody checks the fingerprint."
                )

        bound = bool(head.ledger_id or tenant)
        attestation = HeadAttestation(
            format=ATTESTATION_FORMAT_BOUND if bound else ATTESTATION_FORMAT,
            ledger_id=head.ledger_id,
            tenant=tenant,
            sequence=(previous.sequence + 1) if previous else 1,
            ledger_length=head.length,
            head_seq=head.head_seq,
            head_link_hash=head.head_link_hash,
            basis=head.basis,
            attested_at=format_utc(now if now is not None else utc_now()),
            key_fingerprint=key.fingerprint,
            previous=previous.content_hash() if previous else "",
            note=note,
        )
        signed = replace(
            attestation,
            signature=base64.b64encode(key.sign(attestation.signed_payload())).decode("ascii"),
        )
        return log.append(signed)


@dataclass(frozen=True)
class LogVerdict:
    """What a verifier can say about an attestation log, and what it cannot."""

    ok: bool
    checked: int
    problems: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    key_fingerprint: str = ""
    latest: HeadAttestation | None = None
    #: Every non-empty note, with whose words it is. A note on a counter-signature is
    #: the requester's free text (``note_is_tenant_supplied``), signed along with the
    #: head; it is not a statement by the key holder about the ledger.
    notes: list[dict[str, Any]] = field(default_factory=list)
    #: ``"bound"`` (every attestation signs a ledger id), ``"unbound"`` (none does: a v1
    #: record, which says nothing about WHICH ledger it describes) or ``"mixed"``.
    binding: str = "unbound"
    #: Sequences of attestations that are not bound to any ledger.
    unbound: list[int] = field(default_factory=list)
    #: True only when a ledger id (from *ledger* or ``expect_ledger_id``) was available and
    #: every attestation was bound to exactly that id (and nothing else was wrong).
    bound_to_this_ledger: bool = False

    def summary(self) -> str:
        if self.checked == 0:
            return "no attestations to check"
        if self.ok:
            weak = "" if self.binding == "bound" else (
                f"; {len(self.unbound)} UNBOUND (not tied to any ledger id)")
            return (
                f"{self.checked} attestation(s) verify against key "
                f"{self.key_fingerprint}{weak}"
            )
        return f"{len(self.problems)} problem(s) across {self.checked} attestation(s)"


#: Said on every verification that was given no expectation about the newest attestation.
NO_EXPECTATION_NOTE = (
    "Cannot detect a withheld newer attestation or a rollback: a ledger truncated to an "
    "older signed head, with the attestation log cut back to match, verifies. Keep the "
    "newest attestation's sequence and head from your last check and pass them next time "
    "(--min-sequence N --expect-head HASH); a log whose newest head is older than that "
    "then fails as a rollback or a withheld newer attestation.")


def _expectation_problems(
    records: Sequence[HeadAttestation], *, min_sequence: int | None = None,
    expect_head: str | None = None, max_age: timedelta | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Problems with the log's NEWEST attestation measured against what the caller expects.

    ``min_sequence`` is the newest attestation sequence the caller remembers from an earlier
    check; ``expect_head`` is that attestation's ``head_link_hash`` (full, or a prefix of at
    least 12 hex characters). The log must be at least that new and must still contain
    that head. A log that is shorter or older than this is a rollback or a withheld newer
    attestation: the signatures on what remains are all genuine, which is why nothing but
    the caller's own memory can catch it. ``max_age`` bounds the age of the newest one.
    """
    problems: list[str] = []
    newest = records[-1] if records else None
    if min_sequence is not None:
        if isinstance(min_sequence, bool) or not isinstance(min_sequence, int) or min_sequence < 1:
            raise ValueError("min_sequence must be a whole number of at least 1.")
        if newest is None or newest.sequence < min_sequence:
            have = f"attestation {newest.sequence}" if newest else "no attestation"
            problems.append(
                f"rollback or withheld newer attestation: the log's newest is {have}, but "
                f"attestation {min_sequence} was seen before. A newer attestation was "
                "removed from this log, or this is an older copy of it.")
    if expect_head is not None:
        want = str(expect_head).strip().lower()
        if len(want) < 12 or any(c not in "0123456789abcdef" for c in want):
            raise ValueError("expect_head must be a hex head link hash (12 or more characters).")
        found = [r for r in records if r.head_link_hash.startswith(want)]
        if not found:
            problems.append(
                f"rollback or withheld newer attestation: no attestation in the log has head "
                f"{want[:12]}, the newest head you remembered. The log is older than your "
                "last check, was rewritten, or belongs to a different ledger.")
    if max_age is not None:
        if newest is None:
            problems.append("no attestation, so its age cannot be within the limit")
        else:
            moment = now if now is not None else utc_now()
            age = moment - parse_utc(newest.attested_at)
            if age > max_age:
                problems.append(
                    f"the newest attestation ({newest.sequence}, {newest.attested_at}) is "
                    f"{age.total_seconds() / 3600:.1f} h old, over the allowed "
                    f"{max_age.total_seconds() / 3600:g} h: signing has stopped, or a newer "
                    "attestation is being withheld")
    return problems


def _binding_problems(
    records: Sequence[HeadAttestation], ledger_id: str | None, *, require_bound: bool = False,
    expect_tenant: str | None = None,
) -> tuple[list[str], list[str], bool]:
    """``(problems, skipped, bound_to_this_ledger)`` for who the records say they describe.

    A bound record whose id differs from *ledger_id* is a head from another ledger (cross-tenant
    replay or head substitution): a problem. A bound record when *ledger_id* is unknown cannot be
    shown to belong here: a problem. An unbound record is never a problem on its own, but it is
    never counted as verified for this ledger either: it is listed in ``skipped``.
    """
    problems: list[str] = []
    skipped: list[str] = []
    for r in records:
        where = f"attestation {r.sequence}"
        if expect_tenant is not None and r.tenant != expect_tenant:
            problems.append(
                f"{where}: signed for tenant {r.tenant or '(none)'}, expected {expect_tenant} "
                "— a head from another tenant's log, or one that was never bound to a tenant")
        if r.binding != "bound":
            continue
        if not ledger_id:
            problems.append(
                f"{where}: signed for ledger {r.ledger_id[:12]}, but no ledger id is available "
                "to compare it with (the ledger has none, or none was given), so it cannot be "
                "shown to describe this ledger")
        elif r.ledger_id != ledger_id:
            problems.append(
                f"{where}: signed for ledger {r.ledger_id[:12]}, this is ledger "
                f"{ledger_id[:12]} — a head from a different ledger (cross-tenant replay or head "
                "substitution)")
    unbound = [r.sequence for r in records if r.binding != "bound"]
    if require_bound:
        problems.extend(
            f"attestation {n}: unbound (a v1 record) but a bound head was required"
            for n in unbound)
    elif unbound:
        skipped.append(
            "Attestation(s) " + ", ".join(str(n) for n in unbound)
            + " are UNBOUND: their signature covers no ledger id, so they show that a head "
            "with these numbers was signed, not that it was this ledger's. A signed head from "
            "another tenant's ledger with the same numbers would verify the same way.")
    ok_here = bool(records) and bool(ledger_id) and not problems and not unbound
    return problems, skipped, ok_here


def check_log_against_ledger(
    records: Sequence[HeadAttestation],
    ledger: EvidenceLedger,
    *,
    basis: AttestationBasis | None = None,
    chain: bool = True,
    min_sequence: int | None = None,
    expect_head: str | None = None,
    require_bound: bool = False,
    expect_tenant: str | None = None,
) -> tuple[list[str], list[str]]:
    """Whether *ledger* still holds every head the log attests. ``(problems, skipped)``.

    The ledger half of :func:`verify_log`, usable where no verifying key is at hand (a
    restore check holds the files, not the service's key). It compares only what each
    record states (length, head sequence, head link hash), so on its own it finds a
    rewind or a loss but does not authenticate the log: that is ``verify_log``'s
    signature check. ``chain=False`` skips re-verifying the ledger's own hash chain
    for a caller that has just done it. ``min_sequence`` / ``expect_head`` are the newest
    attestation sequence / head link hash the caller remembers (see
    :func:`_expectation_problems`): without one, a ledger rolled back to an older signed
    head with the log cut to match passes, and the result says so in ``skipped``.
    """
    problems: list[str] = []
    skipped: list[str] = []
    problems.extend(_expectation_problems(
        records, min_sequence=min_sequence, expect_head=expect_head))
    if min_sequence is None and expect_head is None:
        skipped.append(NO_EXPECTATION_NOTE)
    bind_problems, bind_skipped, _ = _binding_problems(
        records, ledger.ledger_id(), require_bound=require_bound, expect_tenant=expect_tenant)
    problems.extend(bind_problems)
    skipped.extend(bind_skipped)
    if chain:
        chain_ok, chain_problems = ledger.verify_chain()
        if not chain_ok:
            problems.extend(f"ledger: {p}" for p in chain_problems)
    entries = ledger.entries()
    by_seq = {e.seq: e.link_hash for e in entries}
    length = len(entries)
    bases = {r.basis for r in records}
    target = basis if basis is not None else (
        next(iter(bases)) if len(bases) == 1 else AttestationBasis.READ_FROM_LEDGER)
    joined = [r for r in records if r.basis is target]
    left_out = [r.sequence for r in records if r.basis is not target]
    if left_out:
        skipped.append(
            "Attestation(s) " + ", ".join(str(n) for n in left_out)
            + f" were not checked against this ledger: their basis is not "
            f"{target.value}, so they describe a different ledger (the one the "
            "holder declared). Pass the other basis to check those instead."
        )
    for record in joined:
        where = f"attestation {record.sequence}"
        if length < record.ledger_length:
            problems.append(
                f"{where}: signed for {record.ledger_length} records at "
                f"{record.attested_at}; the ledger now holds {length}. "
                f"{record.ledger_length - length} record(s) were removed after "
                "being attested."
            )
        if record.head_seq == 0:
            continue
        current = by_seq.get(record.head_seq)
        if current is None:
            problems.append(
                f"{where}: seq {record.head_seq} was attested at "
                f"{record.attested_at} and is absent from the ledger"
            )
        elif current != record.head_link_hash:
            problems.append(
                f"{where}: seq {record.head_seq} links as {current[:12]} but was "
                f"attested as {record.head_link_hash[:12]} — the history at that "
                "position was rewritten"
            )
    skipped.append(
        "Records appended after the latest attestation are covered by no "
        "signature. Everything from seq "
        f"{(joined[-1].head_seq + 1) if joined else 1} onward rests on the "
        "chain alone."
    )
    return [neutralise(p) for p in problems], [neutralise(x) for x in skipped]


def verify_log(
    attestations: Iterable[HeadAttestation],
    key: VerifyingKey,
    *,
    ledger: EvidenceLedger | None = None,
    basis: AttestationBasis | None = None,
    min_sequence: int | None = None,
    expect_head: str | None = None,
    max_age: timedelta | None = None,
    now: datetime | None = None,
    expect_ledger_id: str | None = None,
    expect_tenant: str | None = None,
    require_bound: bool = False,
) -> LogVerdict:
    """Check an attestation log, and optionally check a ledger against it.

    Without a ledger this establishes only that the log is internally sound and
    was signed by the holder of *key*: signatures valid, sequence unbroken,
    each record naming its predecessor, lengths never decreasing. That is worth
    something on its own, and it is not the same as the ledger being intact, so
    the omission is named in ``checks_skipped`` rather than left for the reader
    to infer.

    With a ledger, the question that matters gets asked: does the ledger in
    front of us still contain every head that was signed for? Only the records
    that describe *that* ledger are joined to it: those whose basis is *basis*, or,
    when none is given, the log's only basis, or ``read_from_ledger`` when the log
    mixes both (a hosted account's does). A ``declared_by_holder`` record describes
    the holder's own ledger; against the hosted one it would read as thousands of
    removed records. The ones left out are named in ``checks_skipped``.

    Length and head are compared only between records of the same basis, for the
    same reason.

    **Rollback.** Everything above is relative to the log in hand. An operator with write
    access to the ledger who truncates it to an older signed head and cuts the log to
    match leaves a pair that verifies. Only the verifier's memory closes that:
    **Which ledger.** A ``v2`` attestation signs the ledger's lineage id (and tenant, if any). With
    *ledger*, or *expect_ledger_id* when only the id is known, a bound attestation for a different
    ledger is a problem (a head signed for tenant A's ledger replayed as tenant B's). A ``v1``
    attestation is **unbound**: it still verifies as before, but ``binding``/``unbound`` on the
    verdict and a ``checks_skipped`` entry say it is not tied to any ledger, and
    ``bound_to_this_ledger`` stays False. ``require_bound=True`` turns an unbound record into a
    problem.

    ``min_sequence`` (the newest attestation sequence seen at the last check) and
    ``expect_head`` (its head link hash) fail the verdict with a "rollback or withheld newer
    attestation" problem when the log's newest head is older; ``max_age`` fails a log whose
    newest attestation is too old. With neither expectation the limitation is listed in
    ``checks_skipped``.
    """
    records = list(attestations)
    problems: list[str] = []
    skipped: list[str] = []
    if not records:
        # A log that is missing, emptied or never written vouches for nothing. Reading it
        # as "no problems" would let whoever removes the log also remove the evidence that
        # the ledger was rolled back.
        problems.append(
            "the log holds no attestations, so nothing about the ledger was established "
            "(a deleted or emptied log is indistinguishable from one that was never written)"
        )

    expected_sequence = 1
    previous: HeadAttestation | None = None
    fingerprints: set[str] = set()
    last_of_basis: dict[AttestationBasis, HeadAttestation] = {}

    for record in records:
        where = f"attestation {record.sequence}"
        if record.format not in KNOWN_ATTESTATION_FORMATS:
            problems.append(
                f"{where}: format is {record.format!r}, this build verifies "
                f"{' and '.join(KNOWN_ATTESTATION_FORMATS)} — the signed bytes may not be what "
                "is recomputed here, so a failure below would be uninformative"
            )
        if record.sequence != expected_sequence:
            problems.append(
                f"{where}: out of order, expected {expected_sequence} — an "
                "attestation was removed from the log or the file was reordered"
            )
            expected_sequence = record.sequence
        expected_previous = previous.content_hash() if previous else ""
        if record.previous != expected_previous:
            problems.append(
                f"{where}: names predecessor {record.previous[:12] or '(none)'} but "
                f"follows {expected_previous[:12] or '(none)'} — the log was spliced"
            )
        earlier_same_basis = last_of_basis.get(record.basis)
        if earlier_same_basis is not None and (
                record.ledger_length < earlier_same_basis.ledger_length):
            problems.append(
                f"{where}: signs for {record.ledger_length} records where "
                f"attestation {earlier_same_basis.sequence} signed for "
                f"{earlier_same_basis.ledger_length}. The ledger was shortened between "
                "the two, and both statements are signed."
            )
        if not record.verified_by(key):
            problems.append(
                f"{where}: signature does not verify against key {key.fingerprint} "
                "— either it was signed by a different key, or the record was "
                "edited after signing"
            )
        fingerprints.add(record.key_fingerprint)
        previous = record
        last_of_basis[record.basis] = record
        expected_sequence += 1

    notes = [
        {"sequence": r.sequence, "note": r.note,
         "note_is_tenant_supplied": r.note_is_tenant_supplied}
        for r in records if r.note
    ]
    requester_notes = [n["sequence"] for n in notes if n["note_is_tenant_supplied"]]
    if requester_notes:
        skipped.append(
            "Attestation(s) " + ", ".join(str(n) for n in requester_notes)
            + " carry a note. On a counter-signature the note is the requester's free "
            "text: the signature covers it because it covers every field, but it is "
            "not a statement by the key holder about the ledger."
        )

    declared = [r.sequence for r in records
                if r.basis is AttestationBasis.DECLARED_BY_HOLDER]
    if declared:
        skipped.append(
            "Attestation(s) "
            + ", ".join(str(n) for n in declared)
            + " were counter-signatures: the signer was handed a head value and "
            "never saw the ledger. They fix what was claimed and when, so a later "
            "rewind contradicts a signed statement. They do not say the chain "
            "verified at the time of signing."
        )

    if len(fingerprints) > 1:
        problems.append(
            "the log names more than one signing key ("
            + ", ".join(sorted(fingerprints))
            + "). A rotation is legitimate but must be verified against each key "
            "over its own span; this check used one."
        )

    problems.extend(_expectation_problems(
        records, min_sequence=min_sequence, expect_head=expect_head, max_age=max_age, now=now))
    if min_sequence is None and expect_head is None:
        skipped.append(NO_EXPECTATION_NOTE)

    bound_here = False
    if ledger is None:
        b_problems, b_skipped, bound_here = _binding_problems(
            records, expect_ledger_id, require_bound=require_bound, expect_tenant=expect_tenant)
        if expect_ledger_id is None:
            # No id to compare with: nothing was checked, and a bound record must not read as if
            # it had been. Only the unbound note and tenant/require_bound findings stand.
            b_problems = [p for p in b_problems if "no ledger id is available" not in p]
            bound_here = False
        problems.extend(b_problems)
        skipped.extend(b_skipped)
        skipped.append(
            "The ledger itself was not examined. This says the attestations are "
            "genuine and consistent with each other; it does not say the ledger "
            "still holds the records they were made over."
        )
    else:
        ledger_problems, ledger_skipped = check_log_against_ledger(
            records, ledger, basis=basis, require_bound=require_bound,
            expect_tenant=expect_tenant)
        _, _, bound_here = _binding_problems(
            records, ledger.ledger_id(), require_bound=require_bound,
            expect_tenant=expect_tenant)
        if expect_ledger_id is not None and ledger.ledger_id() != expect_ledger_id:
            problems.append(
                f"the ledger's id is {(ledger.ledger_id() or '(none)')[:12]}, not the expected "
                f"{expect_ledger_id[:12]}")
        problems.extend(ledger_problems)
        skipped.extend(x for x in ledger_skipped if x != NO_EXPECTATION_NOTE)

    skipped.append(
        "Whether this public key belongs to whom you think it does was not "
        "checked. A signature is only worth the provenance of the key: obtain "
        f"fingerprint {key.fingerprint} by some route other than the one these "
        "attestations arrived on."
    )

    unbound_seqs = [r.sequence for r in records if r.binding != "bound"]
    return LogVerdict(
        ok=not problems,
        checked=len(records),
        # Fingerprints, times and ids in these lines came out of the log: shown, never obeyed.
        problems=[neutralise(p) for p in problems],
        checks_skipped=[neutralise(x) for x in skipped],
        key_fingerprint=key.fingerprint,
        latest=records[-1] if records else None,
        notes=notes,
        binding=("bound" if records and not unbound_seqs else
                 "mixed" if len(unbound_seqs) < len(records) else "unbound"),
        unbound=unbound_seqs,
        bound_to_this_ledger=bound_here and not problems,
    )
