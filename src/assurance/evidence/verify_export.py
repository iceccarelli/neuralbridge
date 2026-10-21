"""Check an exported evidence bundle without the service that produced it.

``EvidenceLedger.export`` refuses to emit a bundle whose chain does not verify,
but a bundle is read by people who were never in the room: an auditor, an
insurer, a notified body. They need to check it with nothing but the file and
this module, so this reads no ledger, opens no network connection and needs no
account.

What a pass establishes, and what it cannot:

* every entry's evidence body still hashes to the recorded ``content_hash``,
  and the entry carries nothing the seal does not cover;
* every entry's ``link_hash`` still matches its own sequence number, time,
  kind, subject, content hash and ``prev_hash``;
* where entries are consecutive, each one chains to the one before it;
* for a whole-ledger bundle: it starts at genesis, has no gaps, and ends at the
  head the bundle's own attestation names.

It does **not** establish that the bundle is the ledger the operator holds. An
operator who controls the whole file can rebuild a consistent chain. Closing
that needs a signature over the head made by a key the operator does not hold
(``assurance attest verify``), and every result says so.

``verified`` lists only facts for checks that ran and found nothing wrong;
``checks_skipped`` lists every limit; ``assumptions`` lists what a pass still
takes on trust. ``ok`` means "none of the checks that ran found a problem" and
nothing more.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assurance.evidence.ledger import GENESIS, LEDGER_SCHEMA_VERSION, LedgerEntry

__all__ = ["ASSUMPTIONS", "ExportVerification", "verify_export", "verify_export_file"]

_ENTRY_FIELDS = ("seq", "at", "kind", "subject", "content_hash", "prev_hash",
                 "link_hash", "actor", "evidence")
_STR_FIELDS = ("at", "kind", "subject", "content_hash", "prev_hash", "link_hash",
               "actor")

#: What a pass takes on trust, whatever the file says. Printed with every result.
ASSUMPTIONS = (
    "Names in the `actor` fields are whatever the writer declared. Nothing here "
    "checks who a person is.",
    "Timestamps are whatever the writer's clock said. Nothing here shows the "
    "clock was right.",
)


@dataclass(frozen=True)
class ExportVerification:
    """The outcome of checking one bundle. ``ok`` is only the checks that ran."""

    ok: bool
    entries: int
    scope: str
    problems: tuple[str, ...] = ()
    checks_skipped: tuple[str, ...] = field(default_factory=tuple)
    #: Plain-language facts, each for a check that ran and found nothing wrong.
    verified: tuple[str, ...] = field(default_factory=tuple)
    #: What a pass still takes on trust.
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    #: The last entry's position, for comparing with a signed head attestation.
    #: ``None`` unless the bundle verified and holds the whole ledger.
    head: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "entries": self.entries, "scope": self.scope,
                "problems": list(self.problems),
                "checks_skipped": list(self.checks_skipped),
                "verified": list(self.verified),
                "assumptions": list(self.assumptions),
                "head": self.head}

    def text(self) -> str:
        head = "VERIFIED" if self.ok else "DOES NOT VERIFY"
        lines = [f"{head} — {self.entries} entries, scope: {self.scope}"]
        lines += [f"  CHECKED  {v}" for v in self.verified]
        lines += [f"  PROBLEM  {p}" for p in self.problems]
        lines += [f"  ASSUMED  {a}" for a in self.assumptions]
        lines += [f"  NOT CHECKED  {c}" for c in self.checks_skipped]
        return "\n".join(lines)


def _exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def verify_export(bundle: Any) -> ExportVerification:
    """Verify an exported bundle. Never raises on a malformed one: it reports."""
    problems: list[str] = []
    # Which check each problem belongs to, so a fact is claimed only for a check
    # that found nothing.
    failed: set[str] = set()

    def bad(check: str, message: str) -> None:
        failed.add(check)
        problems.append(message)

    skipped: list[str] = [
        "this checks the bundle's internal consistency, not that it matches the "
        "ledger its operator holds. For that, check a signed head attestation "
        "(`assurance attest verify`).",
        "`exported_at`, each evidence object's own `recorded_at` and the "
        "attestation's `attested_at` are not covered by any hash in the bundle; "
        "the ledger's per-entry `at` is.",
    ]
    if not isinstance(bundle, dict) or not isinstance(bundle.get("entries"), list):
        return ExportVerification(False, 0, "unknown",
                                  ("not an evidence bundle: no `entries` list",),
                                  tuple(skipped), (), ASSUMPTIONS)

    subject = bundle.get("subject", "")
    if not isinstance(subject, str):
        bad("subject", "the bundle's `subject` is not text")
        subject = ""
    whole = subject == ""
    scope = "whole ledger" if whole else f"subject {subject!r}"

    if bundle.get("chain_verified") is not True:
        bad("claim", "the bundle does not claim chain_verified=true; the "
                     "exporter only emits verified chains")

    version = bundle.get("ledger_schema_version")
    if not _exact_int(version) or version != LEDGER_SCHEMA_VERSION:
        # The link-hash recipe belongs to a schema version; a file in another one
        # may be recomputed wrongly, so a link finding below could be uninformative.
        bad("format", f"unsupported ledger format {version!r}: this verifier "
                      f"checks ledger_schema_version {LEDGER_SCHEMA_VERSION}, so "
                      "the hashes below may not be the ones the writer made")

    entries: list[LedgerEntry] = []
    for index, raw in enumerate(bundle["entries"]):
        if not isinstance(raw, dict) or any(k not in raw for k in _ENTRY_FIELDS):
            bad("shape", f"entry {index}: missing required field(s)")
            continue
        if (not _exact_int(raw["seq"]) or raw["seq"] < 1
                or any(not isinstance(raw[k], str) for k in _STR_FIELDS)
                or not isinstance(raw["evidence"], dict)):
            bad("shape", f"entry {index}: a field has the wrong type")
            continue
        entries.append(LedgerEntry(
            seq=raw["seq"], at=raw["at"], kind=raw["kind"],
            subject=raw["subject"], content_hash=raw["content_hash"],
            prev_hash=raw["prev_hash"], link_hash=raw["link_hash"],
            actor=raw["actor"], payload=raw["evidence"]))

    prev: LedgerEntry | None = None
    consecutive = 0
    for entry in entries:
        label = f"seq {entry.seq}"
        if entry.link_hash != entry.expected_link_hash():
            bad("link", f"{label}: link_hash does not match its own content "
                        "— the record was edited in place")
        try:
            ev = entry.evidence()
            if not ev.verify():
                bad("evidence", f"{label}: evidence body does not match its hash "
                                "— the evidence was edited")
            elif ev.content_hash != entry.content_hash or ev.kind != entry.kind:
                bad("identity", f"{label}: the entry names different evidence "
                                "than it contains")
            elif entry.actor != ev.actor.identifier:
                # The actor column sits outside the link hash, so it can be
                # rewritten without breaking the chain; it must agree with the
                # sealed evidence it summarises.
                bad("actor", f"{label}: the recorded actor {entry.actor!r} is "
                             f"not the evidence's actor {ev.actor.identifier!r}")
            elif ev.to_dict() != entry.payload:
                # The seal covers the fields the evidence model reads. Anything
                # else in the object (an added key, a non-canonical form) rides
                # along unauthenticated.
                bad("sealed", f"{label}: the evidence object carries content the "
                              "seal does not cover (an extra or non-canonical field)")
        except Exception as exc:  # noqa: BLE001 - report, never crash on input
            bad("evidence", f"{label}: evidence is unreadable ({type(exc).__name__})")
        if not whole and entry.subject != subject:
            bad("subject", f"{label}: belongs to subject {entry.subject!r}, not "
                           f"the bundle's {subject!r}")
        if prev is not None:
            if entry.seq <= prev.seq:
                bad("order", f"{label}: out of order after seq {prev.seq}")
            elif entry.seq == prev.seq + 1:
                consecutive += 1
                if entry.prev_hash != prev.link_hash:
                    bad("chain", f"{label}: prev_hash does not match the preceding "
                                 "link — the chain was re-ordered or spliced")
            elif whole:
                bad("gap", f"{label}: gap after seq {prev.seq} — a record "
                           "was removed")
        prev = entry

    head: dict[str, Any] | None = None
    if whole:
        if entries and entries[0].seq != 1:
            bad("start", "a whole-ledger bundle must start at seq 1")
        if entries and entries[0].seq == 1 and entries[0].prev_hash != GENESIS:
            bad("start", "seq 1 does not chain to genesis")
        att = bundle.get("attestation")
        if isinstance(att, dict):
            # Checked even for an empty bundle: "no entries" is a claim too,
            # and an attestation naming N > 0 records contradicts it.
            head_seq = entries[-1].seq if entries else 0
            head_link = entries[-1].link_hash if entries else GENESIS
            if att.get("head_link_hash") != head_link or att.get("head_seq") != head_seq \
                    or att.get("length") != len(entries):
                bad("head", "the bundle's attestation names a different head "
                            "than its last entry — records were cut from the end")
            head = {"seq": head_seq, "link_hash": head_link, "length": len(entries)}
        else:
            bad("head", "a whole-ledger bundle must carry its head attestation")
    else:
        if not entries and not problems:
            # What exporting a subject that does not exist produces. It is
            # well-formed and consistent, and it establishes nothing: calling it
            # VERIFIED would let an empty file stand in for a record.
            problems.append(f"the bundle holds no entries for subject {subject!r}: "
                            "there is nothing to verify (the subject may not exist)")
        skipped.append(
            "this bundle holds one subject's entries only, so the links to entries "
            "of other subjects, the start of the chain and the ledger head were "
            "not checked; nothing here shows that no other entry exists for it.")
        skipped.append(
            "the bundle's ledger-wide attestation, if any, was not compared with "
            "these entries.")
    if not entries:
        skipped.append("the bundle holds no entries, so no record was available "
                       "to check.")

    n = len(entries)
    verified: list[str] = []
    if not problems:
        if entries:
            verified.append(f"all {n} entries have every required field, with the "
                            "expected types")
            verified.append(f"each entry's evidence still hashes to the content "
                            f"hash recorded for it ({n} of {n}), and carries no "
                            "field outside that seal")
            verified.append("each entry's recorded kind and content hash are the "
                            "ones its evidence contains")
            verified.append("each entry's actor column equals the actor sealed "
                            "inside its evidence")
            verified.append("each entry's link hash matches its own sequence "
                            "number, time, kind, subject, content hash and "
                            "previous hash")
            verified.append("sequence numbers are strictly increasing"
                            + (f"; {consecutive} consecutive pair(s) each name the "
                               "entry before them as their predecessor"
                               if consecutive else ""))
        if whole and entries:
            verified.append("the chain starts at sequence 1 and chains to the "
                            "genesis value, with no gaps")
            verified.append(f"the last entry (seq {entries[-1].seq}) is the head "
                            "the bundle's own attestation names")
        elif whole:
            verified.append("the bundle holds no entries and its attestation "
                            "names an empty ledger")
        elif entries:
            verified.append(f"every entry belongs to subject {subject!r}")
        verified.append(f"the bundle declares ledger format {LEDGER_SCHEMA_VERSION}, "
                        "the one this verifier implements")
    elif entries and "shape" not in failed:
        # A bad file is still worth triaging: name the checks that ran clean.
        if "evidence" not in failed:
            verified.append("each entry's evidence still hashes to the content "
                            "hash recorded for it")
        if not ({"link", "format"} & failed):
            verified.append("each entry's link hash matches its own content")

    ok = not problems
    return ExportVerification(
        ok, n, scope, tuple(problems), tuple(skipped), tuple(verified),
        ASSUMPTIONS, head if ok and whole else None)


def verify_export_file(path: str | Path) -> ExportVerification:
    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ExportVerification(False, 0, "unknown",
                                  (f"cannot read the bundle: {type(exc).__name__}",),
                                  ())
    return verify_export(bundle)
