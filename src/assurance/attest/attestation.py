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
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..core.errors import AssuranceError
from ..core.identity import content_hash_of, format_utc, utc_now
from ..evidence.ledger import GENESIS, EvidenceLedger
from .keys import SigningKey, VerifyingKey

__all__ = [
    "ATTESTATION_FORMAT",
    "AttestationBasis",
    "AttestationError",
    "AttestationLog",
    "HeadAttestation",
    "LedgerHead",
    "LogVerdict",
    "attest",
    "head_of",
    "verify_log",
]

#: Written into every attestation so a future reader knows what the bytes under
#: the signature were. Changing what is signed without changing this would make
#: old signatures unverifiable for a reason nobody could diagnose.
ATTESTATION_FORMAT = "assurance.head-attestation.v1"


class AttestationError(AssuranceError):
    """An attestation cannot be made, or a log does not hold up."""


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
    )


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

    # -- bytes under the signature ---------------------------------------
    def _body(self) -> dict[str, Any]:
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
    def from_dict(cls, data: dict[str, Any]) -> HeadAttestation:
        missing = [
            k
            for k in (
                "format",
                "sequence",
                "ledger_length",
                "head_seq",
                "head_link_hash",
                "basis",
                "attested_at",
                "key_fingerprint",
                "previous",
            )
            if k not in data
        ]
        if missing:
            raise AttestationError(
                "attestation record is missing " + ", ".join(missing)
                + " — it was not written by this system, or it was edited."
            )
        return cls(
            format=str(data["format"]),
            sequence=int(data["sequence"]),
            ledger_length=int(data["ledger_length"]),
            head_seq=int(data["head_seq"]),
            head_link_hash=str(data["head_link_hash"]),
            basis=AttestationBasis(str(data["basis"])),
            attested_at=str(data["attested_at"]),
            key_fingerprint=str(data["key_fingerprint"]),
            previous=str(data["previous"]),
            note=str(data.get("note", "")),
            signature=str(data.get("signature", "")),
        )

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


class AttestationLog:
    """An append-only JSONL file of attestations, one per line.

    Deliberately not a database. It must be copyable by somebody who does not
    have this software installed, readable by somebody who does not trust it,
    and small enough to paste into an email to an auditor.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read(self) -> list[HeadAttestation]:
        if not self.path.exists():
            return []
        out: list[HeadAttestation] = []
        for number, line in enumerate(self.path.read_text("utf-8").splitlines(), start=1):
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise AttestationError(
                    f"{self.path} line {number} is not JSON ({exc}). A damaged "
                    "attestation log is a finding: it is the one file a rewind "
                    "cannot reach, so damage to it is worth explaining."
                ) from exc
            out.append(HeadAttestation.from_dict(data))
        return out

    def last(self) -> HeadAttestation | None:
        records = self.read()
        return records[-1] if records else None

    def append(self, attestation: HeadAttestation) -> HeadAttestation:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(attestation.to_dict(), sort_keys=True, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
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
) -> HeadAttestation:
    """Sign a ledger head, refusing every case that would lie.

    *source* is either a ledger, which is read and verified here, or a
    :class:`LedgerHead` somebody else has declared — the counter-signature
    case, where the signer never sees the records and says so in the signed
    bytes. Returns the attestation, already appended to *log*.

    Raises :class:`AttestationError` — and the message is the finding — when
    the chain does not verify, when the ledger is shorter than it was at the
    last attestation, when an already-attested link has changed, or when a
    different key is being used without ``rotating=True``.
    """
    head: LedgerHead
    by_seq: dict[int, str] | None
    if isinstance(source, EvidenceLedger):
        head = head_of(source)
        by_seq = {e.seq: e.link_hash for e in source.entries()}
    else:
        head = source
        by_seq = None

    history = log.read()
    previous = history[-1] if history else None

    if previous is not None:
        if head.length < previous.ledger_length:
            raise AttestationError(
                f"refusing to attest: the ledger holds {head.length} record(s), but "
                f"attestation {previous.sequence} signed for {previous.ledger_length} "
                f"at {previous.attested_at}. An append-only ledger does not get "
                "shorter. Records were removed after they were attested — this is "
                "the event this whole mechanism exists to catch. Preserve the "
                "database and the attestation log as they are."
            )
        if head.head_seq < previous.head_seq:
            raise AttestationError(
                f"refusing to attest: head seq {head.head_seq} is behind the "
                f"{previous.head_seq} signed at {previous.attested_at}."
            )
        for earlier in history:
            if earlier.head_seq == 0:
                continue
            if by_seq is not None:
                current = by_seq.get(earlier.head_seq)
                if current is None:
                    raise AttestationError(
                        f"refusing to attest: seq {earlier.head_seq} was attested at "
                        f"{earlier.attested_at} and is no longer in the ledger."
                    )
            elif earlier.head_seq == head.head_seq:
                current = head.head_link_hash
            else:
                continue
            if current != earlier.head_link_hash:
                raise AttestationError(
                    f"refusing to attest: seq {earlier.head_seq} now links as "
                    f"{current[:12]} but was attested as "
                    f"{earlier.head_link_hash[:12]} at {earlier.attested_at}. The "
                    "chain was rebuilt — same position, different history. This is "
                    "a fork, not a gap, and it will not show up in verify_chain."
                )
        if previous.key_fingerprint != key.fingerprint and not rotating:
            raise AttestationError(
                f"refusing to attest: this log was signed by key "
                f"{previous.key_fingerprint} and the key offered is "
                f"{key.fingerprint}. If this is a deliberate rotation, say so "
                "explicitly; otherwise somebody is continuing your attestation log "
                "with a key of their own, which is exactly what a rewind looks "
                "like when nobody checks the fingerprint."
            )

    attestation = HeadAttestation(
        format=ATTESTATION_FORMAT,
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

    def summary(self) -> str:
        if self.checked == 0:
            return "no attestations to check"
        if self.ok:
            return (
                f"{self.checked} attestation(s) verify against key "
                f"{self.key_fingerprint}"
            )
        return f"{len(self.problems)} problem(s) across {self.checked} attestation(s)"


def verify_log(
    attestations: Iterable[HeadAttestation],
    key: VerifyingKey,
    *,
    ledger: EvidenceLedger | None = None,
) -> LogVerdict:
    """Check an attestation log, and optionally check a ledger against it.

    Without a ledger this establishes only that the log is internally sound and
    was signed by the holder of *key*: signatures valid, sequence unbroken,
    each record naming its predecessor, lengths never decreasing. That is worth
    something on its own, and it is not the same as the ledger being intact, so
    the omission is named in ``checks_skipped`` rather than left for the reader
    to infer.

    With a ledger, the question that matters gets asked: does the ledger in
    front of us still contain every head that was signed for?
    """
    records = list(attestations)
    problems: list[str] = []
    skipped: list[str] = []

    expected_sequence = 1
    previous: HeadAttestation | None = None
    fingerprints: set[str] = set()

    for record in records:
        where = f"attestation {record.sequence}"
        if record.format != ATTESTATION_FORMAT:
            problems.append(
                f"{where}: format is {record.format!r}, this build verifies "
                f"{ATTESTATION_FORMAT!r} — the signed bytes may not be what is "
                "recomputed here, so a failure below would be uninformative"
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
        if previous is not None and record.ledger_length < previous.ledger_length:
            problems.append(
                f"{where}: signs for {record.ledger_length} records where "
                f"attestation {previous.sequence} signed for "
                f"{previous.ledger_length}. The ledger was shortened between the "
                "two, and both statements are signed."
            )
        if not record.verified_by(key):
            problems.append(
                f"{where}: signature does not verify against key {key.fingerprint} "
                "— either it was signed by a different key, or the record was "
                "edited after signing"
            )
        fingerprints.add(record.key_fingerprint)
        previous = record
        expected_sequence += 1

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

    if ledger is None:
        skipped.append(
            "The ledger itself was not examined. This says the attestations are "
            "genuine and consistent with each other; it does not say the ledger "
            "still holds the records they were made over."
        )
    else:
        chain_ok, chain_problems = ledger.verify_chain()
        if not chain_ok:
            problems.extend(f"ledger: {p}" for p in chain_problems)
        entries = ledger.entries()
        by_seq = {e.seq: e.link_hash for e in entries}
        length = len(entries)
        for record in records:
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
            f"{(records[-1].head_seq + 1) if records else 1} onward rests on the "
            "chain alone."
        )

    skipped.append(
        "Whether this public key belongs to whom you think it does was not "
        "checked. A signature is only worth the provenance of the key: obtain "
        f"fingerprint {key.fingerprint} by some route other than the one these "
        "attestations arrived on."
    )

    return LogVerdict(
        ok=not problems,
        checked=len(records),
        problems=problems,
        checks_skipped=skipped,
        key_fingerprint=key.fingerprint,
        latest=records[-1] if records else None,
    )
