#!/usr/bin/env python3
# ruff: noqa: T201  (a command-line tool: printing is its output)
"""Check a NeuralBridge evidence export with this one file. No NeuralBridge code, no network.

    python verify_export_standalone.py BUNDLE.json
    python verify_export_standalone.py BUNDLE.json --public-key SIGNER.pub   # also check completeness

Written to be read: an auditor, insurer or notified body should be able to follow every check in
ten minutes and decide whether they trust *this file* instead of trusting the product that made the
export. It uses only the Python standard library. Checking a signed anchor (``--public-key``) needs
the ``cryptography`` package for Ed25519; without it that one check is reported as not done.

Exit codes
    0  every check below passed, a signed head the signer read from the ledger covers EVERY record,
       and nothing was left unestablished
    1  the file contradicts itself or a signed statement: it was edited, rebuilt or cut
    2  not a readable export
    3  nothing is wrong that this file can see, but something could not be established
       (completeness not checked, or the export is outside what this file understands)

What a pass shows, and does not
    * every evidence body still hashes to the content hash recorded for it;
    * every link hash matches its own sequence number, time, kind, subject, content hash and
      predecessor, so an edit in place is detected;
    * the chain starts at genesis, has no gap, and each entry names its predecessor;
    * the exporter's own (unsigned) head record agrees with the last entry;
    * with a trusted public key: a head signed by that key is contained in this chain, so the
      export was not cut short or rebuilt without records that existed when it was signed. (The
      product's verifier also rejects records dated after the signing time; for a whole-ledger
      export that is implied by the link comparison, because changing a date changes every later
      link, so this file does not repeat it.)
    It does NOT show the records are true, who a named person is, that a clock was right, or that
    nothing happened that nobody recorded. Without ``--public-key`` it cannot show the export is
    complete: anyone holding the file can rebuild a consistent chain with entries left out.

Scope: whole-ledger exports of ledger schema 1 only. A subject-only export, a skeleton, or any
field this file does not know is exit 3, never a pass. This file is deliberately stricter and
smaller than the product's own verifier; the independent test suite checks that it never passes
anything that verifier rejects.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys

LEDGER_SCHEMA_VERSION = 1
GENESIS = "0" * 64
HASH_PRECISION = 6
FLOAT_NOISE_TOLERANCE = 1e-9
SEAL_EXACT_INT = 2**53
CANONICAL_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ATTESTATION_FORMAT = "assurance.head-attestation.v1"
MAX_LISTED = 25

TOP_FIELDS = {"ledger_schema_version", "exported_at", "subject", "chain_verified", "attestation",
              "entries", "anchor"}
ENTRY_FIELDS = {"seq", "at", "kind", "subject", "content_hash", "prev_hash", "link_hash",
                "actor", "evidence"}
EVIDENCE_FIELDS = {"schema_version", "kind", "body", "actor", "origin", "validation_state",
                   "confidence", "checks_skipped", "relations", "recorded_at", "content_hash"}
HEAD_FIELDS = {"ledger_schema_version", "length", "head_seq", "head_link_hash", "attested_at"}
VALIDATION_STATES = {"unverified", "verified", "refuted", "indeterminate", "superseded"}
CONFIDENCES = {"none", "low", "medium", "high", "established"}
BASES = {"read_from_ledger", "declared_by_holder"}


# --- the product's hashing recipe, restated -------------------------------------------------
def _round(value):
    """Every number is hashed as round(float(v), 6); -0 is 0. (So 1 and 1.0 hash alike.)"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        rounded = round(float(value), HASH_PRECISION)
        return 0.0 if rounded == 0 else rounded
    if isinstance(value, dict):
        return {k: _round(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_round(v) for v in value]
    return value


def content_hash(payload) -> str:
    text = json.dumps(_round(payload), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ambiguous_numbers(value) -> list[str]:
    """Numbers the hash cannot tell from a neighbour: an edit to one would change no hash."""
    found, stack = [], [("", value)]
    while stack and len(found) < MAX_LISTED:
        path, node = stack.pop()
        if isinstance(node, bool):
            continue
        if isinstance(node, int):
            if abs(node) > SEAL_EXACT_INT:
                found.append(f"{path or '(root)'}: integer beyond 2^53")
        elif isinstance(node, float):
            if not math.isfinite(node) or abs(node - round(node, HASH_PRECISION)) > max(
                    FLOAT_NOISE_TOLERANCE, 4 * math.ulp(node)):
                found.append(f"{path or '(root)'}: number finer than {HASH_PRECISION} places")
        elif isinstance(node, dict):
            stack.extend((f"{path}.{k}", v) for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((f"{path}[{i}]", v) for i, v in enumerate(node))
    return found


def exact_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class Findings:
    def __init__(self) -> None:
        self.wrong: list[str] = []
        self.unestablished: list[str] = []
        self.checked: list[str] = []
        self.assumed: list[str] = []

    def bad(self, message: str) -> None:
        self.wrong.append(message)

    def cannot(self, message: str) -> None:
        self.unestablished.append(message)


def strict_json_loads(text: str):
    """Plain JSON only: NaN/Infinity are not JSON and are refused."""
    def refuse(token):
        raise ValueError(f"{token} is not valid JSON")
    return json.loads(text, parse_constant=refuse)


# --- the checks -----------------------------------------------------------------------------
def check_entry_shape(raw, index, f: Findings):
    if not isinstance(raw, dict) or set(raw) != ENTRY_FIELDS:
        f.bad(f"entry {index}: fields are not exactly {sorted(ENTRY_FIELDS)}")
        return False
    if not exact_int(raw["seq"]) or raw["seq"] < 1 or not isinstance(raw["evidence"], dict) \
            or any(not isinstance(raw[k], str) for k in
                   ("at", "kind", "subject", "content_hash", "prev_hash", "link_hash", "actor")):
        f.bad(f"entry {index}: a field has the wrong type")
        return False
    return True


def check_evidence(entry, f: Findings):
    seq, ev = entry["seq"], entry["evidence"]
    label = f"seq {seq}"
    if set(ev) != EVIDENCE_FIELDS:
        f.bad(f"{label}: evidence fields are not exactly the ones the seal covers")
        return
    actor, origin = ev["actor"], ev["origin"]
    if not (isinstance(actor, dict) and set(actor) == {"identifier", "role", "kind"}
            and all(isinstance(v, str) for v in actor.values())) \
            or not (isinstance(origin, dict) and set(origin) == {"system", "reference", "method"}
                    and all(isinstance(v, str) for v in origin.values())) \
            or not isinstance(ev["body"], dict) or not isinstance(ev["schema_version"], str) \
            or not isinstance(ev["kind"], str) \
            or not isinstance(ev["recorded_at"], str) \
            or not CANONICAL_TIME.match(ev["recorded_at"]) \
            or ev["validation_state"] not in VALIDATION_STATES \
            or ev["confidence"] not in CONFIDENCES \
            or not isinstance(ev["checks_skipped"], list) \
            or any(not isinstance(s, str) for s in ev["checks_skipped"]) \
            or not isinstance(ev["relations"], list) \
            or any(not (isinstance(r, dict) and set(r) == {"relation", "content_hash", "note"}
                        and all(isinstance(v, str) for v in r.values())) for r in ev["relations"]):
        f.bad(f"{label}: evidence is not in the exact form the seal covers")
        return
    hashed = {k: v for k, v in ev.items() if k not in ("recorded_at", "content_hash")}
    if content_hash(hashed) != ev["content_hash"]:
        f.bad(f"{label}: evidence body does not match its hash - the evidence was edited")
    elif ev["content_hash"] != entry["content_hash"] or ev["kind"] != entry["kind"]:
        f.bad(f"{label}: the entry names different evidence than it contains")
    elif actor["identifier"] != entry["actor"]:
        f.bad(f"{label}: the actor column is not the actor sealed inside the evidence")
    flagged = ambiguous_numbers(ev)
    if flagged:
        f.cannot(f"{label}: holds a number the seal cannot protect ({flagged[0]}); an edit to it "
                 "would change no hash, so this entry cannot be shown unedited")


def check_link(entry, f: Findings):
    link = content_hash({"seq": entry["seq"], "at": entry["at"], "kind": entry["kind"],
                         "subject": entry["subject"], "content_hash": entry["content_hash"],
                         "prev_hash": entry["prev_hash"]})
    if link != entry["link_hash"]:
        f.bad(f"seq {entry['seq']}: link_hash does not match its own content - edited in place")


def check_chain(entries, f: Findings):
    for i, entry in enumerate(entries):
        if i == 0:
            if entry["seq"] != 1:
                f.bad("a whole-ledger export must start at seq 1")
            elif entry["prev_hash"] != GENESIS:
                f.bad("seq 1 does not chain to genesis")
            continue
        before = entries[i - 1]
        if entry["seq"] <= before["seq"]:
            f.bad(f"seq {entry['seq']}: out of order after seq {before['seq']}")
        elif entry["seq"] != before["seq"] + 1:
            f.bad(f"seq {entry['seq']}: gap after seq {before['seq']} - a record was removed")
        elif entry["prev_hash"] != before["link_hash"]:
            f.bad(f"seq {entry['seq']}: prev_hash is not the preceding link - re-ordered or spliced")
        if entry["subject"] is None:
            f.bad(f"seq {entry['seq']}: no subject")


def check_head(bundle, entries, f: Findings):
    att = bundle.get("attestation")
    head_seq = entries[-1]["seq"] if entries else 0
    head_link = entries[-1]["link_hash"] if entries else GENESIS
    if not isinstance(att, dict):
        f.bad("a whole-ledger export must carry its head record")
        return
    if set(att) != HEAD_FIELDS:
        f.bad("the head record carries fields the exporter does not write, or lacks some")
    if att.get("head_link_hash") != head_link or att.get("head_seq") != head_seq \
            or att.get("length") != len(entries):
        f.bad("the export's head record names a different head than its last entry - records "
              "were cut from the end")


def check_anchor(bundle, entries, key_path: str, f: Findings):
    """Completeness: a head signed by a key the caller obtained elsewhere lies inside this chain."""
    anchor = bundle.get("anchor")
    if anchor is None:
        f.cannot("completeness could not be established: a public key was supplied, which asks for "
                 "it, but the export carries no signed anchor (it may have been removed)")
        return
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        f.cannot("the `cryptography` package is not installed, so the signature was not checked")
        return
    try:
        with open(key_path, "rb") as handle:
            public = serialization.load_pem_public_key(handle.read())
        if not isinstance(public, ed25519.Ed25519PublicKey):
            raise ValueError("not an Ed25519 key")
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except (OSError, ValueError) as exc:
        f.cannot(f"the public key could not be read ({exc.__class__.__name__}); completeness not checked")
        return
    fingerprint = hashlib.sha256(raw).hexdigest()[:16]
    need = ("format", "sequence", "ledger_length", "head_seq", "head_link_hash", "basis",
            "attested_at", "key_fingerprint", "previous", "signature")
    if not isinstance(anchor, dict) or any(k not in anchor for k in need) \
            or anchor["format"] != ATTESTATION_FORMAT or anchor["basis"] not in BASES \
            or any(not exact_int(anchor[k]) for k in ("sequence", "ledger_length", "head_seq")) \
            or any(not isinstance(anchor[k], str) for k in
                   ("head_link_hash", "attested_at", "key_fingerprint", "previous", "signature")):
        f.bad("the anchor is not a readable head attestation")
        return
    if anchor["key_fingerprint"] != fingerprint:
        f.bad(f"the anchor was signed by key {anchor['key_fingerprint']}, not the trusted key "
              f"{fingerprint} - a foreign anchor anchors nothing")
        return
    body = {k: anchor[k] for k in ("format", "sequence", "ledger_length", "head_seq",
                                   "head_link_hash", "basis", "attested_at", "key_fingerprint",
                                   "previous")}
    body["note"] = anchor.get("note", "") if isinstance(anchor.get("note", ""), str) else None
    if body["note"] is None:
        f.bad("the anchor's note is not text")
        return
    message = json.dumps(_round(body), sort_keys=True, separators=(",", ":"),
                         default=str).encode("utf-8")
    try:
        public.verify(base64.b64decode(anchor["signature"].encode("ascii"), validate=True), message)
    except (InvalidSignature, ValueError):
        f.bad("the anchor's signature does not verify against the trusted key - edited or forged")
        return
    chain_len = entries[-1]["seq"] if entries else 0
    links = {e["seq"]: e["link_hash"] for e in entries}
    if chain_len < anchor["ledger_length"] or chain_len < anchor["head_seq"]:
        f.bad(f"the chain ends at seq {chain_len} but {max(anchor['ledger_length'], anchor['head_seq'])}"
              " were signed for - records were cut from the end (or this is another ledger)")
    elif anchor["head_seq"] > 0 and links.get(anchor["head_seq"]) != anchor["head_link_hash"]:
        f.bad(f"the link at seq {anchor['head_seq']} is not the one that was signed - the history "
              "there was removed or rewritten")
    elif anchor["head_seq"] < 1 or anchor["ledger_length"] < 1:
        f.cannot("the signed anchor covers no records, so it shows nothing was kept or removed")
    elif anchor["basis"] != "read_from_ledger":
        f.cannot("the only matching signed head was declared to the signer (basis "
                 "declared_by_holder); the signer never read the chain, so this is not an anchor")
    else:
        after = chain_len - anchor["head_seq"]
        if after:
            f.cannot(f"{after} record(s) after the signed head (seq {anchor['head_seq']}) are covered "
                     "by no signature: they are consistent with the chain and nothing more, and an "
                     "unsigned tail is exactly what a forger can invent")
        if not f.wrong:
            f.checked.append(f"a head signed by key {fingerprint} (read from the ledger, seq "
                             f"{anchor['head_seq']}) lies inside this chain, which runs to seq "
                             f"{chain_len}")
        f.assumed += [
            "The public key must come from a channel the ledger's administrator does not control; a "
            "key that arrived with the export proves nothing.",
            "A hosted-ledger operator who also holds the signing key can sign a shorter or invented "
            "ledger: a signature fixes what was signed and when, by whom, and not that it was true.",
        ]


def verify(bundle, public_key_path: str | None = None) -> Findings:
    f = Findings()
    if not isinstance(bundle, dict) or not isinstance(bundle.get("entries"), list):
        f.bad("not a ledger export: no `entries` list")
        return f
    unknown = sorted(set(bundle) - TOP_FIELDS - {"skeleton", "skeleton_truncated"})
    if unknown:
        f.bad(f"top-level field(s) the exporter does not write: {', '.join(unknown[:5])} - this "
              "file did not come from the exporter as it is")
    if {"skeleton", "skeleton_truncated"} & set(bundle):
        f.cannot("a subject export with a skeleton; this file checks whole-ledger exports")
    if bundle.get("subject", "") != "":
        f.cannot("a subject-only export; this file checks whole-ledger exports")
    if bundle.get("chain_verified") is not True:
        f.bad("the export does not claim chain_verified=true")
    if bundle.get("ledger_schema_version") != LEDGER_SCHEMA_VERSION \
            or not exact_int(bundle.get("ledger_schema_version")):
        f.cannot(f"ledger_schema_version {bundle.get('ledger_schema_version')!r}: this file "
                 f"implements {LEDGER_SCHEMA_VERSION} only")
        return f
    entries = []
    for index, raw in enumerate(bundle["entries"]):
        if check_entry_shape(raw, index, f):
            entries.append(raw)
    if f.wrong:
        return f
    for entry in entries:
        try:
            check_evidence(entry, f)
            check_link(entry, f)
        except (ValueError, OverflowError, RecursionError, TypeError):
            f.bad(f"seq {entry['seq']}: the entry cannot be examined (a number or nesting depth "
                  "no hash can carry) - the file is not an intact export")
    check_chain(entries, f)
    check_head(bundle, entries, f)
    if not f.wrong:
        f.checked += [
            f"{len(entries)} entries have the exact fields and types the seal covers",
            "each evidence body still hashes to its recorded content hash",
            "each link hash matches its own content",
            "the chain starts at genesis, has no gap, and each entry names its predecessor",
            "the export's unsigned head record agrees with its last entry (the exporter agreeing "
            "with itself, not an anchor)",
        ]
    if public_key_path is not None:
        check_anchor(bundle, entries, public_key_path, f)
    else:
        f.cannot("COMPLETENESS NOT CHECKED: without a trusted public key, nothing shows no entry was "
                 "cut from the end or removed; the file's own head record can be rewritten to match")
    return f


def clean(text) -> str:
    """Text that came from the file may hold newlines or terminal escapes that fake or erase
    output lines; show them escaped, never raw."""
    return str(text).encode("unicode_escape").decode("ascii")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check a NeuralBridge evidence export with this one file.")
    ap.add_argument("bundle")
    ap.add_argument("--public-key", help="the signer's PUBLIC key (PEM), obtained other than from the "
                                         "export, to check completeness against a signed anchor")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        with open(args.bundle, encoding="utf-8") as handle:
            bundle = strict_json_loads(handle.read())
    except (OSError, ValueError, RecursionError) as exc:
        print(f"cannot read {args.bundle}: {exc.__class__.__name__}", file=sys.stderr)
        return 2
    try:
        f = verify(bundle, args.public_key)
    except Exception as exc:  # noqa: BLE001 - a hostile file must be a refusal, not a traceback
        if args.json:
            print(json.dumps({"exit": 2, "wrong": [], "unestablished": [], "checked": [],
                              "assumed": [], "error": exc.__class__.__name__}))
        else:
            print(f"DOES NOT VERIFY - could not examine the file ({exc.__class__.__name__})")
        return 2
    code = 1 if f.wrong else 3 if f.unestablished else 0
    if args.json:
        print(json.dumps({"exit": code, "wrong": f.wrong, "unestablished": f.unestablished,
                          "checked": f.checked, "assumed": f.assumed}, indent=2))
    else:
        head = {0: "VERIFIED", 1: "DOES NOT VERIFY", 3: "NOT ESTABLISHED"}[code]
        listed = bundle.get("entries") if isinstance(bundle, dict) else None
        print(f"{head} - {len(listed) if isinstance(listed, list) else 0} entries")
        for line in f.wrong[:MAX_LISTED]:
            print(f"  PROBLEM  {clean(line)}")
        for line in f.unestablished[:MAX_LISTED]:
            print(f"  NOT ESTABLISHED  {clean(line)}")
        for line in f.checked:
            print(f"  checked  {clean(line)}")
        for line in f.assumed:
            print(f"  ASSUMED  {clean(line)}")
        print("  ASSUMED  Names in `actor` fields are whatever the writer declared; timestamps are "
              "whatever the writer's clock said; nothing here shows the records are true.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
