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
  head the bundle's own attestation names (that attestation is the exporter's
  own unsigned statement and is **not** an anchor);
* for a subject bundle that carries its ``skeleton`` of the ledger's other
  entries (opt-in at export: it names every other subject's id, kind and time):
  the subject's entries and the skeleton chain together from genesis with nothing
  missing, so a record removed from inside the chain is a gap, and the bundle's own
  unsigned head agrees with where that chain ends.

None of that shows the bundle is **complete**. Anyone who controls the file can
rebuild a consistent chain with entries left out (the hashes are unkeyed) or cut
the end off. Completeness is only checked against a **signed anchor**: a head
attestation (``assurance attest sign``) whose signature verifies under a public
key the *caller* obtained elsewhere (``trusted_key``; never read from the bundle).
With one, a bundle shorter than the signed length, or whose link at the signed
sequence differs, is rejected; so is a record dated after the moment the head was
signed (a signature cannot cover a record that did not exist yet). Without an
anchor, ``completeness`` is ``not_checked`` and says so in words; a pass is never a
bare pass. Supplying a trusted key asks for the check, so a bundle that then cannot
be shown complete is not ``ok`` -- but that is "could not be established"
(``unestablished``), which is not the same finding as "this file was tampered with"
(``problems``).

``completeness`` has five values and ``ok`` is none of them:

* ``anchored``: a signed anchor **the signer read from the ledger**
  (``read_from_ledger``) covering at least one record agrees with the bundle, and it
  signs the bundle's last record;
* ``anchored_partial``: the same, but ``records_after_anchor`` records follow the
  signed head and no signature covers them (a cut of those is not detected);
* ``declared_head``: the only signed head that agrees with the bundle was
  ``declared_by_holder``: the signer was TOLD three numbers and never read the chain.
  Anyone entitled to ask a hosted service to counter-sign can have a head they invented
  signed, so it shows a number was presented at a time, not that this is the ledger or
  that it is complete. It is never ``anchored``;
* ``not_checked``: nothing could be checked against, or the only anchor signs an
  empty ledger (it covers no record, so it shows nothing was kept or removed);
* ``failed``: an anchor was checked and the bundle does not match it.

What an anchor does not cover: records after it; and, when the party holding the
ledger also holds the signing key (a hosted account ledger), anything that party
could re-sign. The anchor protects against that party only if the verifier kept
a signed record of its own (``anchors=``).

The seal hashes every number as ``round(float(v), 6)``. So an integer beyond 2^53,
or a fraction finer than 6 decimal places, hashes the same as its neighbour: an edit
to it changes nothing the seal or the chain can see. Such a number is reported
(``unestablished``, "a number the seal cannot distinguish"), and ``Evidence.seal``
refuses to make new ones. Hash semantics are unchanged, so existing seals still verify.

``verified`` lists only facts for checks that ran and found nothing wrong;
``checks_skipped`` lists every limit; ``assumptions`` lists what a pass still
takes on trust. ``ok`` means "no inconsistency was found in the checks that ran and
nothing asked for was left undone" and nothing more: read ``completeness`` beside it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from assurance.core.evidence import indistinguishable_numbers
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import GENESIS, LEDGER_SCHEMA_VERSION, LedgerEntry

if TYPE_CHECKING:  # the Ed25519 dependency is only needed when a key is supplied
    from assurance.attest.keys import VerifyingKey

__all__ = ["ANCHORED", "ANCHORED_PARTIAL", "ANCHOR_CLOCK_SKEW_SECONDS", "ASSUMPTIONS",
           "DECLARED_HEAD", "FAILED", "MAX_PROBLEMS", "NOT_CHECKED",
           "ExportVerification", "verify_export", "verify_export_file"]

#: ``ExportVerification.completeness``: is it shown that nothing was removed?
ANCHORED = "anchored"        # a signed anchor, under a trusted key, covers the whole chain
#: A signed anchor agrees with the chain but records follow it that no signature covers.
ANCHORED_PARTIAL = "anchored_partial"
#: A signed head agrees with the bundle, but the signer was only TOLD it
#: (``declared_by_holder``) and never read the chain. Not an anchor.
DECLARED_HEAD = "declared_head"
NOT_CHECKED = "not_checked"  # nothing was available to check it against
FAILED = "failed"            # an anchor was checked and the bundle does not match it

#: How far after a head's ``attested_at`` a record it covers may be dated. A record
#: the signer saw cannot be newer than the signature; this allows only for the clock
#: of whoever wrote the ledger differing slightly from the signer's (both are
#: truncated to the second). A forger gains at most this much.
ANCHOR_CLOCK_SKEW_SECONDS = 60

#: Problems listed in a result. A hostile file can make every one of millions of
#: entries a finding; the answer must stay readable and small, so past this the
#: rest are counted, not listed.
MAX_PROBLEMS = 50

_TOP_LEVEL_FIELDS = frozenset({"ledger_schema_version", "exported_at", "subject",
                               "chain_verified", "attestation", "entries", "anchor",
                               "skeleton", "skeleton_truncated"})
_ATTESTATION_FIELDS = frozenset({"ledger_schema_version", "length", "head_seq",
                                 "head_link_hash", "attested_at"})

_ENTRY_FIELDS = ("seq", "at", "kind", "subject", "content_hash", "prev_hash",
                 "link_hash", "actor", "evidence")
_STR_FIELDS = ("at", "kind", "subject", "content_hash", "prev_hash", "link_hash",
               "actor")
_SKELETON_FIELDS = ("seq", "at", "kind", "subject", "content_hash", "prev_hash",
                    "link_hash")
_SKELETON_STR_FIELDS = _SKELETON_FIELDS[1:]

#: What a pass takes on trust, whatever the file says. Printed with every result.
ASSUMPTIONS = (
    "Names in the `actor` fields are whatever the writer declared. Nothing here "
    "checks who a person is.",
    "Timestamps are whatever the writer's clock said. Nothing here shows the "
    "clock was right.",
)

_KEY_PROVENANCE = (
    "The trusted public key is the signer's because you say so: nothing here can "
    "tell. Obtain it, and read its fingerprint, by a route the ledger's "
    "administrator does not control; a key that arrived with the bundle proves "
    "nothing.")
_SAME_PARTY = (
    "A signature shows what the key holder signed, not who else could sign. If the "
    "party that holds this ledger also holds the signing key (a hosted account "
    "ledger), it could sign a shorter ledger and embed that: the anchor guards "
    "against that party only if you kept a signed record of your own from earlier "
    "and pass it as well (`--attestations`).")


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
    #: Is it shown that no entry was removed? ``anchored`` only when a signed
    #: anchor (covering at least one record) under a trusted key agreed with a
    #: complete chain and signs its last record; ``anchored_partial`` when records
    #: follow the signed head; ``not_checked`` otherwise; ``failed`` when an anchor
    #: was checked and the bundle did not match.
    completeness: str = NOT_CHECKED
    #: The signed anchor completeness rests on: ``anchored``, partial or ``declared_head``.
    anchor: dict[str, Any] | None = None
    #: Things that could not be established although nothing was found wrong: a
    #: completeness check that was asked for (a key was supplied) and could not be
    #: completed, or a number the seal cannot distinguish. Not tampering, not a pass:
    #: ``ok`` is false while any is open. Kept apart from ``problems`` so a genuine
    #: file is never reported as one that "is not what the exporter wrote".
    unestablished: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "entries": self.entries, "scope": self.scope,
                "problems": list(self.problems),
                "unestablished": list(self.unestablished),
                "checks_skipped": list(self.checks_skipped),
                "verified": list(self.verified),
                "assumptions": list(self.assumptions),
                "head": self.head,
                "completeness": self.completeness,
                "anchor": self.anchor}

    def text(self) -> str:
        if self.problems:
            head = "DOES NOT VERIFY"
        elif not self.ok:
            head = ("NOT ESTABLISHED (no inconsistency found, but a check that was "
                    "asked for could not be completed)")
        elif self.completeness == ANCHORED:
            head = "VERIFIED — anchored to a signed head"
        elif self.completeness == ANCHORED_PARTIAL and self.anchor:
            after = self.anchor["records_after_anchor"]
            head = (f"CONSISTENT, SIGNED ONLY UP TO seq {self.anchor['head_seq']} — "
                    f"{after} record(s) after it are covered by no signature")
        elif self.completeness == DECLARED_HEAD:
            head = ("CONSISTENT, HEAD ONLY DECLARED — the signer was told the head "
                    "and never read the chain; completeness NOT shown")
        else:
            head = "VERIFIED (internal consistency only; completeness NOT CHECKED)"
        lines = [f"{head} — {self.entries} entries, scope: {self.scope}"]
        lines += [f"  CHECKED  {v}" for v in self.verified]
        lines += [f"  PROBLEM  {p}" for p in self.problems]
        lines += [f"  NOT ESTABLISHED  {u}" for u in self.unestablished]
        lines += [f"  ASSUMED  {a}" for a in self.assumptions]
        lines += [f"  NOT CHECKED  {c}" for c in self.checks_skipped]
        return "\n".join(lines)


def _exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _short(link: Any) -> str:
    return str(link)[:12]


def verify_export(
    bundle: Any, *, trusted_key: VerifyingKey | None = None,
    anchors: Sequence[Mapping[str, Any] | Any] = (),
) -> ExportVerification:
    """Verify an exported bundle. Never raises on a malformed one: it reports.

    ``trusted_key`` is an Ed25519 public key the caller obtained **outside** the
    bundle. With it the bundle's embedded ``anchor`` (and any ``anchors`` the
    caller holds, e.g. from their own copy of an attestation log) are verified and
    the bundle is checked against them; a bundle that carries none, or cannot be
    shown complete, is then reported as a problem rather than a pass. Without it
    completeness is reported ``not_checked``.
    """
    problems: list[str] = []
    unestablished: list[str] = []
    total = 0
    open_total = 0
    # Which check each problem belongs to, so a fact is claimed only for a check
    # that found nothing.
    failed: set[str] = set()
    # seq -> the `at` the bundle gives it (entries and skeleton), for the signed-head clock.
    times: dict[int, str] = {}

    def bad(check: str, message: str) -> None:
        nonlocal total
        failed.add(check)
        total += 1
        if len(problems) < MAX_PROBLEMS:
            problems.append(message)

    def cannot(message: str) -> None:
        """Something asked for could not be established. Not a finding of tampering."""
        nonlocal open_total
        open_total += 1
        if len(unestablished) < MAX_PROBLEMS:
            unestablished.append(message)

    skipped: list[str] = [
        "`exported_at`, each evidence object's own `recorded_at` and the unsigned "
        "`attestation`'s `attested_at` are not covered by any hash in the bundle; "
        "the ledger's per-entry `at` is (and so is a signed anchor's).",
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

    extra_top = sorted(k for k in bundle if k not in _TOP_LEVEL_FIELDS)
    if extra_top:
        bad("extra", f"the bundle carries top-level field(s) the exporter does not "
                     f"write: {', '.join(extra_top[:5])}")

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
        extra = sorted(k for k in raw if k not in _ENTRY_FIELDS)
        if extra:
            bad("extra", f"entry {index}: carries field(s) outside the seal and the "
                         f"link hash: {', '.join(extra[:5])}")
        times.setdefault(raw["seq"], raw["at"])
        entries.append(LedgerEntry(
            seq=raw["seq"], at=raw["at"], kind=raw["kind"],
            subject=raw["subject"], content_hash=raw["content_hash"],
            prev_hash=raw["prev_hash"], link_hash=raw["link_hash"],
            actor=raw["actor"], payload=raw["evidence"]))

    prev: LedgerEntry | None = None
    consecutive = 0
    numbers_flagged = 0
    for entry in entries:
        label = f"seq {entry.seq}"
        try:
            link_ok = entry.link_hash == entry.expected_link_hash()
        except Exception:  # noqa: BLE001 - e.g. an integer too large to hash
            link_ok = False
        if not link_ok:
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
        flagged = indistinguishable_numbers(entry.payload)
        if flagged:
            numbers_flagged += 1
            cannot(f"{label}: {'; '.join(flagged[:3])}"
                   + (f"; and {len(flagged) - 3} more" if len(flagged) > 3 else "")
                   + ". The seal cannot distinguish a number like that from its "
                     "neighbour, so an edit to it would not change any hash: this "
                     "entry cannot be shown unedited.")
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

    # What the chain looks like end to end, when the bundle lets that be known:
    # ``links`` maps every seq 1..N to its recorded link hash, set only when the
    # whole chain is present, contiguous and linked. ``why_unknown`` says why not.
    links: dict[int, str] | None = None
    why_unknown = ""
    skeleton_used = False
    head_agrees: int | None = None
    head: dict[str, Any] | None = None
    if whole:
        for key in ("skeleton", "skeleton_truncated"):
            if key in bundle:
                bad("extra", f"a whole-ledger bundle carries `{key}`, which only a "
                             "subject bundle has")
        if entries and entries[0].seq != 1:
            bad("start", "a whole-ledger bundle must start at seq 1")
        if entries and entries[0].seq == 1 and entries[0].prev_hash != GENESIS:
            bad("start", "seq 1 does not chain to genesis")
        att = bundle.get("attestation")
        if isinstance(att, dict):
            extra_att = sorted(k for k in att if k not in _ATTESTATION_FIELDS)
            if extra_att:
                bad("extra", "the bundle's attestation carries field(s) the exporter "
                             f"does not write: {', '.join(extra_att[:5])}")
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
        if not ({"shape", "link", "order", "gap", "chain", "start"} & failed):
            links = {e.seq: e.link_hash for e in entries}
        else:
            why_unknown = ("the bundle's own chain is not intact (see the problems), "
                           "so there is no complete chain to compare with an anchor")
    else:
        if not entries and total == 0:
            # What exporting a subject that does not exist produces. It is
            # well-formed and consistent, and it establishes nothing: calling it
            # VERIFIED would let an empty file stand in for a record.
            bad("empty", f"the bundle holds no entries for subject {subject!r}: "
                         "there is nothing to verify (the subject may not exist)")
        links, why_unknown, skeleton_used = _merge_skeleton(
            bundle, entries, subject, bad, failed, times)
        if links is not None and isinstance(bundle.get("attestation"), dict):
            # The chain's end is now known, so the exporter's own head claim can be
            # held against it, as a whole-ledger bundle's is. Still unsigned.
            att = bundle["attestation"]
            end = max(links) if links else 0
            end_link = links[end] if links else GENESIS
            extra_att = sorted(k for k in att if k not in _ATTESTATION_FIELDS)
            if extra_att:
                bad("extra", "the bundle's attestation carries field(s) the exporter "
                             f"does not write: {', '.join(extra_att[:5])}")
            if att.get("head_link_hash") != end_link or att.get("head_seq") != end \
                    or att.get("length") != end:
                bad("head", "the bundle's attestation names a different head than "
                            f"the end of its chain (seq {end}) — records were cut "
                            "from the end")
            else:
                head_agrees = end
        if "attestation" in bundle and not skeleton_used:
            skipped.append(
                "the bundle's ledger-wide attestation, if any, was not compared with "
                "these entries.")
    if not entries:
        skipped.append("the bundle holds no entries, so no record was available "
                       "to check.")

    # -- completeness: only ever against a signed anchor, under a key the caller holds
    known = {e.seq: e.link_hash for e in entries}
    chain_len = max(links) if links else 0
    completeness, anchor_info, anchor_facts, anchor_assumptions = _check_anchors(
        bundle, anchors, trusted_key, links, known, chain_len, why_unknown, bad, cannot,
        skipped, times)

    anchored = completeness in (ANCHORED, ANCHORED_PARTIAL)
    if whole:
        skipped.insert(0, "this checks the bundle's internal consistency, not that it "
                          "matches the ledger its operator holds. Its tail is checked "
                          "only against its own unsigned `attestation`, which the "
                          "exporter wrote and anyone who rewrites the file can "
                          "rewrite: that is not an anchor." if not anchored
                       else "this checks the bundle against a signed head, not that it "
                            "matches the ledger its operator holds today.")
    else:
        if skeleton_used:
            skipped.insert(0, "this bundle holds one subject's evidence only; the "
                              "ledger's other entries appear as a skeleton (position "
                              "and hashes, no body), so what they record was not "
                              "checked.")
        else:
            skipped.insert(0, "this bundle holds one subject's entries only, with no "
                              "skeleton of the rest of the ledger: the links to other "
                              "subjects' entries, the start of the chain and the "
                              "ledger head were not checked, and nothing here shows "
                              "that no other entry exists for it.")

    # The completeness statement leads: it is the first thing a reader must not miss.
    skipped.sort(key=lambda line: not line.startswith("COMPLETENESS NOT CHECKED"))

    n = len(entries)
    verified: list[str] = []
    if total == 0:
        if entries:
            verified.append(f"all {n} entries have every required field, with the "
                            "expected types")
            verified.append(
                f"each entry's evidence still hashes to the content hash recorded "
                f"for it ({n} of {n}), and every field in it is one the seal covers, "
                "to the seal's own precision (it hashes numbers to 6 decimal places, "
                "and an integer beyond 2^53 loses precision)"
                + ("; no entry here holds a number whose edit that would hide"
                   if not numbers_flagged else
                   "; some entries DO hold such numbers (see the findings below)"))
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
            verified.append(f"the bundle's own unsigned attestation agrees with its "
                            f"last entry (seq {entries[-1].seq}); that is the "
                            "exporter agreeing with itself, not an anchor")
        elif whole:
            verified.append("the bundle holds no entries and its own unsigned "
                            "attestation names an empty ledger")
        elif entries:
            verified.append(f"every entry belongs to subject {subject!r}")
            if skeleton_used and links is not None:
                verified.append(
                    f"the subject's entries and the skeleton of the ledger's other "
                    f"entries chain together from genesis through seq {chain_len} "
                    "with nothing missing, each skeleton link matching its own "
                    "content")
                if head_agrees is not None:
                    verified.append(
                        f"the bundle's own unsigned attestation agrees with where "
                        f"that chain ends (seq {head_agrees}); that is the exporter "
                        "agreeing with itself, not an anchor")
        verified.append(f"the bundle declares ledger format {LEDGER_SCHEMA_VERSION}, "
                        "the one this verifier implements")
        verified.extend(anchor_facts)
    elif entries and "shape" not in failed:
        # A bad file is still worth triaging: name the checks that ran clean.
        if "evidence" not in failed:
            verified.append("each entry's evidence still hashes to the content "
                            "hash recorded for it")
        if not ({"link", "format"} & failed):
            verified.append("each entry's link hash matches its own content")

    if total > len(problems):
        problems.append(f"… and {total - len(problems)} more problem(s) not listed")
    if open_total > len(unestablished):
        unestablished.append(f"… and {open_total - len(unestablished)} more not listed")
    ok = total == 0 and open_total == 0
    if total and completeness in (ANCHORED, ANCHORED_PARTIAL, DECLARED_HEAD):
        completeness = NOT_CHECKED  # a bundle with problems is not shown complete
        anchor_info = None
    return ExportVerification(
        ok, n, scope, tuple(problems), tuple(skipped), tuple(verified),
        (*ASSUMPTIONS, *anchor_assumptions), head if total == 0 and whole else None,
        completeness, anchor_info if total == 0 else None, tuple(unestablished))


def _merge_skeleton(
    bundle: dict[str, Any], entries: list[LedgerEntry], subject: str,
    bad: Any, failed: set[str], times: dict[int, str],
) -> tuple[dict[int, str] | None, str, bool]:
    """Chain a subject bundle's entries with its skeleton of everything else.

    Returns ``(links, why_unknown, skeleton_used)``. ``links`` maps seq 1..N to the
    recorded link hash when the merged chain is whole and linked; ``None`` otherwise.
    """
    truncated = bundle.get("skeleton_truncated", False)
    raw = bundle.get("skeleton")
    if not isinstance(truncated, bool):
        bad("skeleton", "`skeleton_truncated` is not true or false")
        truncated = False
    if truncated:
        if raw:
            bad("skeleton", "the bundle says its skeleton was omitted for size yet "
                            "carries entries in it")
        return (None, "the exporter left out the skeleton of the ledger's other "
                      "entries because there are too many of them (`skeleton_truncated`), "
                      "so removed entries of this subject cannot be seen", False)
    if raw is None:
        return (None, "the bundle carries no skeleton of the ledger's other entries "
                      "(it is opt-in at export, because it discloses the id, kind and time of the "
                      "ledger's other subjects; or it was removed), so removed entries of "
                      "this subject cannot be seen. Ask the exporter for one if that "
                      "disclosure is acceptable (`?skeleton=true`, `--skeleton`)", False)
    if not isinstance(raw, list):
        bad("skeleton", "`skeleton` is not a list")
        return None, "the skeleton is not readable", False

    skeleton: list[LedgerEntry] = []
    for index, item in enumerate(raw):
        if (not isinstance(item, dict) or set(item) != set(_SKELETON_FIELDS)
                or not _exact_int(item["seq"]) or item["seq"] < 1
                or any(not isinstance(item[k], str) for k in _SKELETON_STR_FIELDS)):
            bad("skeleton", f"skeleton item {index}: it must hold exactly "
                            f"{', '.join(_SKELETON_FIELDS)}, with the expected types "
                            "(a skeleton carries no evidence body)")
            continue
        times.setdefault(item["seq"], item["at"])
        skeleton.append(LedgerEntry(
            seq=item["seq"], at=item["at"], kind=item["kind"], subject=item["subject"],
            content_hash=item["content_hash"], prev_hash=item["prev_hash"],
            link_hash=item["link_hash"], actor="", payload={}))

    by_seq: dict[int, tuple[LedgerEntry, bool]] = {}
    for e in entries:
        by_seq.setdefault(e.seq, (e, True))
    for s in skeleton:
        label = f"skeleton seq {s.seq}"
        try:
            link_ok = s.link_hash == s.expected_link_hash()
        except Exception:  # noqa: BLE001
            link_ok = False
        if not link_ok:
            bad("link", f"{label}: link_hash does not match its own content "
                        "— the record was edited in place")
        if s.subject == subject:
            bad("skeleton", f"{label} belongs to the bundle's own subject but carries "
                            "no evidence — the evidence was stripped")
        if s.seq in by_seq:
            bad("skeleton", f"{label} is also listed as an entry — one record twice")
        else:
            by_seq[s.seq] = (s, False)

    intact = not ({"shape", "skeleton", "link", "order", "chain", "extra"} & failed)
    expected, prev_link, prev_is_entry = 1, GENESIS, False
    for seq in sorted(by_seq):
        e, is_entry = by_seq[seq]
        if seq != expected:
            intact = False
            bad("gap", f"seq {expected}"
                       + (f"–{seq - 1}" if seq - 1 > expected else "")
                       + " appear in neither the entries nor the skeleton — "
                         "a record was removed")
        elif e.prev_hash != prev_link and not (is_entry and prev_is_entry):
            intact = False
            bad("chain", f"seq {seq}: prev_hash does not match the preceding link "
                         "— the chain was re-ordered, spliced or rebuilt")
        prev_link, prev_is_entry, expected = e.link_hash, is_entry, seq + 1
    if not intact:
        return None, "the bundle's chain is not intact (see the problems)", True
    return {seq: pair[0].link_hash for seq, pair in by_seq.items()}, "", True


def _dated_after(att: Any, times: dict[int, str]) -> str:
    """Why a record the signed head covers cannot be under it, or ``""``.

    A signer who read the ledger saw every record up to the head at ``attested_at``; a
    signer who was told the head signed it then. Either way a record dated later than
    that did not exist when the head was signed, so a bundle that holds one under the
    head was back-dated, rebuilt or belongs to another ledger. A time that is not a
    timestamp cannot be compared, so it cannot be allowed through either.
    """
    try:
        limit = parse_utc(att.attested_at) + timedelta(seconds=ANCHOR_CLOCK_SKEW_SECONDS)
    except (ValueError, TypeError, OverflowError):
        return f"its signing time {att.attested_at!r} is not a timestamp"
    late: list[int] = []
    unreadable: list[int] = []
    for seq in sorted(times):
        if seq > att.head_seq:
            continue
        try:
            if parse_utc(times[seq]) > limit:
                late.append(seq)
        except (ValueError, TypeError, OverflowError):
            unreadable.append(seq)
    if unreadable:
        return (f"the time recorded for seq {unreadable[0]} ({times[unreadable[0]]!r}) "
                "is not a timestamp, so it cannot be shown to precede the signature")
    if late:
        first = late[0]
        more = f" (and {len(late) - 1} more)" if len(late) > 1 else ""
        return (f"seq {first} is dated {times[first]}{more}, after the head was signed "
                f"({att.attested_at}); a signature cannot cover a record that did not "
                "exist yet, so these entries were back-dated, rebuilt, or belong to "
                "another ledger")
    return ""


def _check_anchors(
    bundle: dict[str, Any], external: Sequence[Any], key: VerifyingKey | None,
    links: dict[int, str] | None, known: dict[int, str], chain_len: int,
    why_unknown: str, bad: Any, cannot: Any, skipped: list[str], times: dict[int, str],
) -> tuple[str, dict[str, Any] | None, list[str], list[str]]:
    """Judge completeness. Returns ``(completeness, anchor, facts, assumptions)``.

    Every anchor is checked only under *key*, which the caller obtained elsewhere.
    Without a key nothing is judged and the reason is stated. ``bad`` records a
    finding (the file contradicts a signed statement); ``cannot`` records that
    completeness was asked for and could not be established.
    """
    raws: list[tuple[str, Any]] = []
    if bundle.get("anchor") is not None:
        raws.append(("the bundle's anchor", bundle["anchor"]))
    for index, item in enumerate(external, start=1):
        raws.append((f"supplied attestation {index}", item))

    why = (f"Why there is no complete chain to compare with: {why_unknown}."
           if why_unknown else "")
    if key is None:
        if raws:
            skipped.insert(0, (
                "COMPLETENESS NOT CHECKED: a signed anchor was supplied or embedded, "
                "but no trusted public key was, so its signature was not checked and "
                "nothing was compared with it. Supply the signer's public key from a "
                "channel other than this bundle. Without it a bundle that was cut "
                "short, or rebuilt without some entries, cannot be told from a "
                "complete one."))
        else:
            skipped.insert(0, (
                "COMPLETENESS NOT CHECKED: nothing in this bundle is signed, so "
                "nothing shows that no entry was cut from the end or removed. A "
                "bundle can be shortened and its unsigned `attestation` rewritten to "
                "match. Export with a signed head attestation (`--attestations`) and "
                "check it with the signer's public key (`--public-key`)."))
        if why:
            skipped.insert(1, why)
        return NOT_CHECKED, None, [], []

    if not raws:
        cannot("Completeness could not be established: a trusted public key was "
               "supplied, which asks for it to be checked, but this bundle carries no "
               "signed anchor and none was supplied. Nothing shows it is complete (an "
               "anchor may have been removed from the file, or the export was made "
               "without one).")
        return NOT_CHECKED, None, [], []

    from assurance.attest.attestation import (  # lazy: needs `cryptography`
        ATTESTATION_FORMAT,
        AttestationBasis,
        AttestationError,
        HeadAttestation,
    )

    passed: list[Any] = []
    failures = 0

    def reject(message: str) -> None:
        nonlocal failures
        failures += 1
        bad("anchor", message)

    for label, raw in raws:
        try:
            data = raw.to_dict() if hasattr(raw, "to_dict") else raw
            if not isinstance(data, Mapping):
                raise AttestationError("not an object")
            att = HeadAttestation.from_dict(dict(data))
        except (AttestationError, ValueError, TypeError, KeyError, OverflowError) as exc:
            # OverflowError: `int(1e999)` / `int(inf)` on a number the file chose.
            reject(f"{label} is not a readable head attestation ({exc})")
            continue
        if att.format != ATTESTATION_FORMAT:
            reject(f"{label}: format {att.format!r} is not {ATTESTATION_FORMAT!r}; "
                   "its signature cannot be checked here")
            continue
        if att.key_fingerprint != key.fingerprint:
            reject(f"{label} was signed by key {att.key_fingerprint}, not the "
                   f"trusted key {key.fingerprint} — a foreign anchor anchors "
                   "nothing")
            continue
        try:
            signature_ok = att.verified_by(key)
        except AttestationError:
            signature_ok = False
        if not signature_ok:
            reject(f"{label}: the signature does not verify against the trusted "
                   f"key {key.fingerprint} — the anchor was edited or forged")
            continue
        # The signature is genuine. Now: does this bundle agree with what was signed?
        where = (f"{label} (attestation {att.sequence}, {att.basis.value}, signed "
                 f"{att.attested_at}, for {att.ledger_length} record(s) up to seq "
                 f"{att.head_seq})")
        late = _dated_after(att, times)
        if late:
            reject(f"{where}: {late}")
            continue
        if links is None:
            # No complete chain to hold it against; still, a link we do hold must agree.
            seen = known.get(att.head_seq)
            if seen is not None and seen != att.head_link_hash:
                reject(f"{where}: seq {att.head_seq} links as {_short(seen)} in "
                       f"this bundle but was signed as "
                       f"{_short(att.head_link_hash)} — the history was rewritten")
            continue
        if chain_len < att.ledger_length or chain_len < att.head_seq:
            reject(f"{where}: this bundle's chain ends at seq {chain_len} — "
                   f"{max(att.ledger_length, att.head_seq) - chain_len} signed "
                   "record(s) were cut from the end (or the anchor belongs to "
                   "another ledger)")
            continue
        if att.head_seq > 0 and links.get(att.head_seq) != att.head_link_hash:
            reject(f"{where}: seq {att.head_seq} links as "
                   f"{_short(links.get(att.head_seq, ''))} in this bundle but "
                   f"was signed as {_short(att.head_link_hash)} — the history at "
                   "that position was removed from or rewritten")
            continue
        passed.append(att)

    if failures:
        return FAILED, None, [], []  # each failure was reported where it was found
    if not passed:
        # Every anchor was genuine and none contradicted the bundle, but there was no
        # complete chain to hold them against: asked for, and not established.
        cannot("Completeness could not be established although a trusted key was "
               f"supplied: {why_unknown}.")
        return NOT_CHECKED, None, [], []

    # Only a head the signer READ from the ledger can anchor a bundle. One the signer
    # was merely told is a number presented at a time -- any paid account can have the
    # one service key sign a head it invented -- so it can say "declared", never
    # "anchored".
    covering = [a for a in passed if a.head_seq >= 1 and a.ledger_length >= 1]
    read = [a for a in covering if a.basis is AttestationBasis.READ_FROM_LEDGER]
    declared = [a for a in covering if a.basis is AttestationBasis.DECLARED_BY_HOLDER]
    if not covering:
        # Genuine, and it contradicts nothing -- because it says nothing. A signed
        # empty head can be had by anyone entitled to attest (it is three numbers),
        # and attached to a ledger they invented it would read as a signed record.
        reason = ("the strongest signed anchor signs an empty ledger (0 records), so "
                  "it covers no record in this bundle and shows nothing was kept or "
                  "removed")
        cannot(f"Completeness could not be established: {reason}.")
        skipped.insert(0, f"COMPLETENESS NOT CHECKED: {reason}. Only an anchor over "
                          "at least one record can anchor a bundle.")
        return NOT_CHECKED, None, [], []
    best = max(read or declared, key=lambda a: (a.head_seq, a.sequence))
    after = chain_len - best.head_seq
    info = {
        "sequence": best.sequence, "key_fingerprint": best.key_fingerprint,
        "attested_at": best.attested_at, "basis": best.basis.value,
        "ledger_length": best.ledger_length, "head_seq": best.head_seq,
        "head_link_hash": best.head_link_hash, "records_after_anchor": after,
    }
    assumptions = [_KEY_PROVENANCE, _SAME_PARTY]
    if not read:
        facts = [
            f"{len(passed)} signed attestation(s) verify against the public key you "
            f"supplied (fingerprint {key.fingerprint})",
            f"the bundle's chain runs to seq {chain_len}, at least the "
            f"{best.ledger_length} record(s) the signer was told of, and its link at "
            f"seq {best.head_seq} ({_short(best.head_link_hash)}) is the head the "
            "signer was told, with no record under it dated after it was signed — "
            "so the bundle does not contradict what was declared",
        ]
        skipped.insert(0, (
            "COMPLETENESS NOT CHECKED: the only signed head that agrees with this "
            "bundle was declared to the signer (basis declared_by_holder), who was "
            "handed three numbers and never read the chain. That is not an anchor: "
            "anyone entitled to ask a hosted service to counter-sign can have a head "
            "they invented signed. Completeness needs a head the signer read from "
            "the ledger (`assurance attest sign`)."))
        assumptions.append(
            f"Attestation {best.sequence} is a counter-signature: the signer was "
            "handed the head values and did not read the chain. It fixes what was "
            "declared and when; it does not say the chain verified at the time, that "
            "this is the ledger the head belongs to, or that nothing is missing.")
        return DECLARED_HEAD, info, facts, assumptions
    facts = [
        f"{len(passed)} signed anchor(s) verify against the public key you supplied "
        f"(fingerprint {key.fingerprint})",
        f"the bundle's chain runs to seq {chain_len}, at least the "
        f"{best.ledger_length} record(s) signed for, and its link at seq "
        f"{best.head_seq} ({_short(best.head_link_hash)}) is the signed head — so "
        f"nothing up to seq {best.head_seq} was removed or rewritten",
        f"the signer read that head from the ledger (basis {best.basis.value}), and no "
        "record under it is dated after it was signed",
    ]
    skipped.insert(0, (
        f"{after} record(s) after the anchor (seq {best.head_seq + 1}"
        f"–{chain_len}) are covered by no signature: a cut of those is not "
        "detected." if after else
        f"the anchor signs the bundle's last record (seq {chain_len}); anything "
        "appended since is covered by no signature."))
    return (ANCHORED_PARTIAL if after else ANCHORED), info, facts, assumptions


def verify_export_file(
    path: str | Path, *, trusted_key: VerifyingKey | None = None,
    anchors: Sequence[Any] = (),
) -> ExportVerification:
    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ExportVerification(False, 0, "unknown",
                                  (f"cannot read the bundle: {type(exc).__name__}",),
                                  ())
    return verify_export(bundle, trusted_key=trusted_key, anchors=anchors)
