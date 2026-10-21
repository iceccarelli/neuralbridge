"""Check an exported evidence bundle without the service that produced it.

``EvidenceLedger.export`` refuses to emit a bundle whose chain does not verify,
but a bundle is read by people who were never in the room: an auditor, an
insurer, a notified body. They need to check it with nothing but the file and
this module, so this reads no ledger, opens no network connection and needs no
account.

What a pass establishes, and what it cannot:

* every entry's evidence body still hashes to the recorded ``content_hash``;
* every entry's ``link_hash`` still matches its own sequence number, time,
  kind, subject, content hash and ``prev_hash``;
* where entries are consecutive, each one chains to the one before it;
* for a whole-ledger bundle: it starts at genesis, has no gaps, and ends at the
  head the bundle's own attestation names.

It does **not** establish that the bundle is the ledger the operator holds. An
operator who controls the whole file can rebuild a consistent chain. Closing
that needs a signature over the head made by a key the operator does not hold
(``assurance attest verify``), and every result says so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assurance.evidence.ledger import GENESIS, LedgerEntry

__all__ = ["ExportVerification", "verify_export", "verify_export_file"]

_ENTRY_FIELDS = ("seq", "at", "kind", "subject", "content_hash", "prev_hash",
                 "link_hash", "actor", "evidence")


@dataclass(frozen=True)
class ExportVerification:
    """The outcome of checking one bundle. ``ok`` is only the checks that ran."""

    ok: bool
    entries: int
    scope: str
    problems: tuple[str, ...] = ()
    checks_skipped: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "entries": self.entries, "scope": self.scope,
                "problems": list(self.problems),
                "checks_skipped": list(self.checks_skipped)}

    def text(self) -> str:
        head = "VERIFIED" if self.ok else "DOES NOT VERIFY"
        lines = [f"{head} — {self.entries} entries, scope: {self.scope}"]
        lines += [f"  PROBLEM  {p}" for p in self.problems]
        lines += [f"  NOT CHECKED  {c}" for c in self.checks_skipped]
        return "\n".join(lines)


def verify_export(bundle: Any) -> ExportVerification:
    """Verify an exported bundle. Never raises on a malformed one: it reports."""
    problems: list[str] = []
    skipped: list[str] = [
        "this checks the bundle's internal consistency, not that it matches the "
        "ledger its operator holds. For that, check a signed head attestation "
        "(`assurance attest verify`).",
    ]
    if not isinstance(bundle, dict) or not isinstance(bundle.get("entries"), list):
        return ExportVerification(False, 0, "unknown",
                                  ("not an evidence bundle: no `entries` list",),
                                  tuple(skipped))

    subject = str(bundle.get("subject", ""))
    whole = subject == ""
    scope = "whole ledger" if whole else f"subject {subject!r}"

    if bundle.get("chain_verified") is not True:
        problems.append("the bundle does not claim chain_verified=true; the "
                        "exporter only emits verified chains")

    entries: list[LedgerEntry] = []
    for index, raw in enumerate(bundle["entries"]):
        if not isinstance(raw, dict) or any(k not in raw for k in _ENTRY_FIELDS):
            problems.append(f"entry {index}: missing required field(s)")
            continue
        try:
            entries.append(LedgerEntry(
                seq=int(raw["seq"]), at=str(raw["at"]), kind=str(raw["kind"]),
                subject=str(raw["subject"]), content_hash=str(raw["content_hash"]),
                prev_hash=str(raw["prev_hash"]), link_hash=str(raw["link_hash"]),
                actor=str(raw["actor"]), payload=dict(raw["evidence"])))
        except (TypeError, ValueError):
            problems.append(f"entry {index}: malformed")

    prev: LedgerEntry | None = None
    for entry in entries:
        label = f"seq {entry.seq}"
        if entry.link_hash != entry.expected_link_hash():
            problems.append(f"{label}: link_hash does not match its own content "
                            "— the record was edited in place")
        try:
            ev = entry.evidence()
            if not ev.verify():
                problems.append(f"{label}: evidence body does not match its hash "
                                "— the evidence was edited")
            elif ev.content_hash != entry.content_hash or ev.kind != entry.kind:
                problems.append(f"{label}: the entry names different evidence "
                                "than it contains")
        except Exception as exc:  # noqa: BLE001 - report, never crash on input
            problems.append(f"{label}: evidence is unreadable ({type(exc).__name__})")
        if not whole and entry.subject != subject:
            problems.append(f"{label}: belongs to subject {entry.subject!r}, not "
                            f"the bundle's {subject!r}")
        if prev is not None:
            if entry.seq <= prev.seq:
                problems.append(f"{label}: out of order after seq {prev.seq}")
            elif entry.seq == prev.seq + 1 and entry.prev_hash != prev.link_hash:
                problems.append(f"{label}: prev_hash does not match the preceding "
                                "link — the chain was re-ordered or spliced")
            elif entry.seq > prev.seq + 1 and whole:
                problems.append(f"{label}: gap after seq {prev.seq} — a record "
                                "was removed")
        prev = entry

    if whole:
        if entries and entries[0].seq != 1:
            problems.append("a whole-ledger bundle must start at seq 1")
        if entries and entries[0].seq == 1 and entries[0].prev_hash != GENESIS:
            problems.append("seq 1 does not chain to genesis")
        att = bundle.get("attestation")
        if isinstance(att, dict) and entries:
            last = entries[-1]
            if att.get("head_link_hash") != last.link_hash or att.get("head_seq") != last.seq \
                    or att.get("length") != len(entries):
                problems.append("the bundle's attestation names a different head "
                                "than its last entry — records were cut from the end")
        elif entries:
            problems.append("a whole-ledger bundle must carry its head attestation")
    else:
        skipped.append(
            "this bundle holds one subject's entries only, so the links to entries "
            "of other subjects, the start of the chain and the ledger head were "
            "not checked; nothing here shows that no other entry exists for it.")

    return ExportVerification(not problems, len(entries), scope, tuple(problems),
                              tuple(skipped))


def verify_export_file(path: str | Path) -> ExportVerification:
    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ExportVerification(False, 0, "unknown",
                                  (f"cannot read the bundle: {type(exc).__name__}",),
                                  ())
    return verify_export(bundle)
