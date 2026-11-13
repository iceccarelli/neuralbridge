#!/usr/bin/env python3
# ruff: noqa: T201  (a command-line tool: printing is its output)
"""Check a NeuralBridge evidence export with this one file. No NeuralBridge code, no network.

    python verify_export_standalone.py BUNDLE.json
    python verify_export_standalone.py BUNDLE.json --public-key SIGNER.pub   # also check completeness
    python verify_export_standalone.py BUNDLE.json --keyset KEYS.json        # several keys, with history
    python verify_export_standalone.py BUNDLE.json --public-key SIGNER.pub --attestations MY-COPY.jsonl
    python verify_export_standalone.py BUNDLE.json --public-key SIGNER.pub --expect-fingerprint FP
        --min-sequence N --expect-head HASH --min-length N --max-age HOURS

Written to be read: an auditor, insurer or notified body should be able to follow every check in
ten minutes and decide whether they trust *this file* instead of trusting the product that made the
export. It uses only the Python standard library. Checking a signed anchor (``--public-key``) needs
the ``cryptography`` package for Ed25519; without it that one check is reported as not done.

Exit codes
    0  every check below passed, a signed head the signer read from the ledger covers EVERY record,
       and nothing was left unestablished
    1  the file contradicts itself or a signed statement: it was edited, rebuilt or cut
    2  not a readable export (or an unreadable keyset / attestation log)
    3  nothing is wrong that this file can see, but something could not be established
       (completeness not checked, a subject-only export, or an anchor from a key not in your keyset)

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

A signed head does not show the export is the NEWEST: one cut back to an older signed head is
genuine and consistent. Only what you remember from your last check can show it, so a passing
result prints ``KEEP FOR YOUR NEXT CHECK`` and the next check passes it back (``--min-sequence``,
``--expect-head``, ``--min-length``, ``--max-age``). ``--expect-fingerprint`` is the fingerprint of
the signing key you wrote down elsewhere: a different public key is exit 1. A fingerprint is 16 hex
characters, 64 bits: it catches a swapped key, and is a weaker defence against a ground-out one.

Keys. ONE ``--public-key``: an anchor signed by any other key is a foreign anchor (exit 1). Several
``--public-key`` or a ``--keyset`` (a public-key-only JSON file, ``assurance.attest.keyset.v1``, with
a status and dates per key): the key is chosen by the fingerprint the anchor names; a revoked key,
or a date outside a retired key's window, is exit 1; a fingerprint not in your keyset is exit 3.

Scope: ledger schema 1 only. A subject-only export is checked entry by entry (hash, link, subject,
order) but can never be shown complete by this file, whatever a skeleton says: that is exit 3, never
a pass (use the product's verifier to merge a skeleton). Any field this file does not know is wrong
or exit 3, never a pass. This file is deliberately stricter and smaller than the product's own
verifier; the independent test suite checks that it never passes anything that verifier rejects.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys
from datetime import UTC, datetime, timedelta

LEDGER_SCHEMA_VERSION = 1
GENESIS = "0" * 64
HASH_PRECISION = 6
FLOAT_NOISE_TOLERANCE = 1e-9
SEAL_EXACT_INT = 2**53
CANONICAL_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ATTESTATION_FORMAT = "assurance.head-attestation.v1"
#: v2 signs the ledger's lineage id and tenant as well (an export bundle names no ledger id, so a
#: bound anchor cannot be matched to the bundle's ledger here; that is said, not assumed).
ATTESTATION_FORMAT_BOUND = "assurance.head-attestation.v2"
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


class InputError(Exception):
    """A key, keyset or attestation log that cannot be used: exit 2, nothing is judged."""


def _refuse_duplicates(pairs):
    """A JSON object that repeats a name reads as one value here and another in other parsers."""
    seen = {}
    for name, value in pairs:
        if name in seen:
            raise ValueError(f"a JSON object repeats the name {clean(name[:40])!r}")
        seen[name] = value
    return seen


def strict_json_loads(text: str):
    """Plain JSON only: NaN/Infinity are not JSON and are refused, and so is a repeated name."""
    def refuse(token):
        raise ValueError(f"{token} is not valid JSON")
    return json.loads(text, parse_constant=refuse, object_pairs_hook=_refuse_duplicates)


def parse_time(text):
    """A canonical UTC time (YYYY-MM-DDTHH:MM:SSZ) as an aware datetime, else None."""
    if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", text):
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


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


# --- keys: one key, several keys, or a keyset with history -----------------------------------
KEYSET_FORMAT = "assurance.attest.keyset.v1"
KEY_STATUSES = ("active", "retired", "revoked")
EPOCH = "1970-01-01T00:00:00Z"
FINGERPRINT_BITS_NOTE = (
    "A key fingerprint is 16 hex characters: 64 bits of SHA-256 over the raw public key. That catches a "
    "swapped or mistyped key; it is a weaker defence against someone who deliberately grinds out a key "
    "with a chosen fingerprint, which is expensive but not impossible. Where the stakes justify it, "
    "compare the whole public key file as well.")


def _crypto():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return InvalidSignature, serialization, ed25519


def load_public_key(pem: bytes):
    """``(public key object, fingerprint)`` for an Ed25519 PEM public key, else ValueError."""
    _, serialization, ed25519 = _crypto()
    if pem.count(b"-----BEGIN ") != 1 or pem.count(b"-----END ") != 1 or not re.fullmatch(
            rb"\s*-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----\s*", pem, re.DOTALL):
        raise ValueError("a public key must be exactly one PEM block with nothing before or after it")
    public = serialization.load_pem_public_key(pem)
    if not isinstance(public, ed25519.Ed25519PublicKey):
        raise ValueError("not an Ed25519 key")
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return public, hashlib.sha256(raw).hexdigest()[:16]


def _private_material(text: str) -> bool:
    upper = text.upper()
    return "PRIVATE KEY" in upper or "OPENSSH PRIVATE" in upper


def _all_strings(node) -> str:
    out, stack = [], [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for k, v in item.items():
                out.append(str(k))
                stack.append(v)
        elif isinstance(item, list):
            stack.extend(item)
    return "\n".join(out)


def load_keyset(path: str) -> dict:
    """``fingerprint -> entry`` from an assurance.attest.keyset.v1 file; InputError on anything else."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(256 * 1024 + 1)
    except OSError as exc:
        raise InputError(f"the keyset file cannot be read ({exc.__class__.__name__})") from None
    if len(data) > 256 * 1024:
        raise InputError("the keyset file is too large to be a list of public keys")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("the keyset file is not UTF-8 text") from None
    if _private_material(text):
        raise InputError("the keyset file holds private key material; it is a place for PUBLIC keys only "
                         "and is refused whole (if that key was ever real, treat it as burned)")
    try:
        doc = strict_json_loads(text)
    except (ValueError, RecursionError) as exc:
        raise InputError(f"the keyset file is not valid JSON ({clean(exc)})") from None
    if _private_material(_all_strings(doc)):
        raise InputError("the keyset file holds private key material; it is refused whole")
    if not isinstance(doc, dict) or doc.get("format") != KEYSET_FORMAT:
        raise InputError(f"unsupported keyset: this file reads {KEYSET_FORMAT} only")
    if set(doc) != {"format", "keys"}:
        raise InputError("the keyset carries field(s) it does not define")
    keys = doc["keys"]
    if not isinstance(keys, list) or not keys or len(keys) > 64:
        raise InputError("`keys` must be a list of between 1 and 64 keys")
    entries = {}
    for number, raw in enumerate(keys, start=1):
        where = f"key {number}"
        required = {"fingerprint", "public_key_pem", "status", "effective_from"}
        if not isinstance(raw, dict) or not required <= set(raw) \
                or set(raw) - required - {"effective_until", "label"}:
            raise InputError(f"{where}: not exactly the fields a keyset key has")
        if any(not isinstance(raw[k], str) for k in ("fingerprint", "public_key_pem", "status")):
            raise InputError(f"{where}: fingerprint, public_key_pem and status must be text")
        if not re.fullmatch(r"[0-9a-f]{16}", raw["fingerprint"]) or raw["status"] not in KEY_STATUSES:
            raise InputError(f"{where}: bad fingerprint or status")
        try:
            public, fingerprint = load_public_key(raw["public_key_pem"].encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise InputError(f"{where}: the public key cannot be read ({exc.__class__.__name__})") from None
        if fingerprint != raw["fingerprint"]:
            raise InputError(f"{where}: the fingerprint {raw['fingerprint']} is not the key's ({fingerprint})")
        start = parse_time(raw["effective_from"])
        until = parse_time(raw["effective_until"]) if "effective_until" in raw else None
        if start is None or ("effective_until" in raw and until is None):
            raise InputError(f"{where}: times are written YYYY-MM-DDTHH:MM:SSZ")
        if until is not None and until <= start:
            raise InputError(f"{where}: effective_until is not after effective_from")
        if (raw["status"] == "retired" and until is None) or (raw["status"] == "active" and until is not None):
            raise InputError(f"{where}: a retired key needs effective_until and an active key has none")
        if not isinstance(raw.get("label", ""), str) or len(raw.get("label", "")) > 120:
            raise InputError(f"{where}: label must be short text")
        if fingerprint in entries:
            raise InputError(f"key {fingerprint} is given twice")
        entries[fingerprint] = {"public": public, "status": raw["status"], "start": start, "until": until,
                                "from_text": raw["effective_from"], "until_text": raw.get("effective_until")}
    return entries


class Trust:
    """The keys the caller trusts. ``single`` keeps the one-key meaning: any other signer is foreign."""

    def __init__(self, entries: dict, single: bool) -> None:
        self.entries, self.single = entries, single

    @property
    def fingerprints(self):
        return sorted(self.entries)

    def judge(self, fingerprint: str, attested_at) -> str:
        """"" if an anchor signed at *attested_at* may be checked under that key, else why not."""
        entry = self.entries[fingerprint]
        if entry["status"] == "revoked":
            return (f"signed by key {fingerprint}, which your keyset marks REVOKED: nothing it signed is "
                    "trusted, whatever date the anchor carries")
        when = parse_time(attested_at)
        if when is None:
            return (f"its signing time is not a YYYY-MM-DDTHH:MM:SSZ time, so it cannot be placed in the "
                    f"window of key {fingerprint}")
        if when < entry["start"]:
            return f"dated {attested_at}, before key {fingerprint} was in force (from {entry['from_text']})"
        if entry["until"] is not None and when > entry["until"]:
            return (f"dated {attested_at}, after key {fingerprint} was {entry['status']} (until "
                    f"{entry['until_text']}): a retired key signing later is a leak, a back-dated record, "
                    "or a wrong date in your keyset")
        return ""


def build_trust(public_paths, keyset_path, f: Findings):
    """A Trust, or None (with a finding) when Ed25519 support or a --public-key file is missing."""
    try:
        _crypto()
    except ImportError:
        f.cannot("the `cryptography` package is not installed, so the signature was not checked")
        return None
    entries = {}
    for path in public_paths:
        try:
            with open(path, "rb") as handle:
                public, fingerprint = load_public_key(handle.read())
        except (OSError, ValueError) as exc:
            f.cannot(f"the public key could not be read ({exc.__class__.__name__}); completeness not checked")
            return None
        if fingerprint in entries:
            raise InputError(f"key {fingerprint} is given twice")
        entries[fingerprint] = {"public": public, "status": "active", "start": parse_time(EPOCH),
                                "until": None, "from_text": EPOCH, "until_text": None}
    if keyset_path:
        for fingerprint, entry in load_keyset(keyset_path).items():
            if fingerprint in entries:
                raise InputError(f"key {fingerprint} is given twice")
            entries[fingerprint] = entry
    return Trust(entries, single=len(public_paths) == 1 and not keyset_path)


# --- anchors ---------------------------------------------------------------------------------
ANCHOR_REQUIRED = ("format", "sequence", "ledger_length", "head_seq", "head_link_hash", "basis",
                   "attested_at", "key_fingerprint", "previous")


def parse_anchor(anchor, strict_extra: bool):
    """The anchor as an exact-typed dict, or None. A field of another type is refused, not coerced; with
    *strict_extra* a field the signer never writes is refused too (an unsigned rider on a signed
    statement)."""
    if not isinstance(anchor, dict) or any(k not in anchor for k in ANCHOR_REQUIRED):
        return None
    if anchor["format"] not in (ATTESTATION_FORMAT, ATTESTATION_FORMAT_BOUND) \
            or anchor["basis"] not in BASES \
            or any(not exact_int(anchor[k]) for k in ("sequence", "ledger_length", "head_seq")) \
            or any(not isinstance(anchor[k], str) for k in
                   ("head_link_hash", "attested_at", "key_fingerprint", "previous")):
        return None
    bound = anchor["format"] == ATTESTATION_FORMAT_BOUND
    allowed = {*ANCHOR_REQUIRED, "note", "signature"} | ({"ledger_id", "tenant"} if bound else set())
    if any(not isinstance(anchor[k], str) for k in ("note", "signature", "ledger_id", "tenant")
           if k in anchor and (k in allowed)) or (strict_extra and set(anchor) - allowed):
        return None
    if bound and not (isinstance(anchor.get("ledger_id"), str) and isinstance(anchor.get("tenant"), str)):
        return None
    if "signature" not in anchor:
        return None
    return {k: anchor[k] for k in anchor if k in allowed}


def anchor_signature_ok(anchor: dict, public) -> bool:
    invalid_signature = _crypto()[0]
    body = {k: anchor[k] for k in ANCHOR_REQUIRED}
    if anchor["format"] == ATTESTATION_FORMAT_BOUND:
        body["ledger_id"], body["tenant"] = anchor["ledger_id"], anchor["tenant"]
    body["note"] = anchor.get("note", "")
    message = json.dumps(_round(body), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    try:
        public.verify(base64.b64decode(anchor["signature"].encode("ascii"), validate=True), message)
    except (invalid_signature, ValueError):
        return False
    return True


def read_attestation_log(path: str) -> dict:
    """The record an offline check takes from the caller's own log: the newest the signer READ from the
    ledger, else the newest declared one (never one over zero records). InputError when the log is
    missing, empty, damaged anywhere, or ends in an unfinished line."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise InputError(f"the attestation log cannot be read ({exc.__class__.__name__})") from None
    *lines, tail = raw.split(b"\n")
    if tail.strip():
        raise InputError("the attestation log ends in an unfinished line; the newest attestation may be "
                         "the one that was cut off, so no earlier record is used in its place")
    records = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = strict_json_loads(line.decode("utf-8"))
        except (ValueError, RecursionError):
            raise InputError(f"the attestation log is damaged at line {number}") from None
        parsed = parse_anchor(row, strict_extra=False)
        if parsed is None:
            raise InputError(f"the attestation log line {number} is not a readable attestation")
        records.append(parsed)
    if not records:
        raise InputError("the attestation log holds no attestations")
    for record in reversed(records):
        if record["basis"] == "read_from_ledger":
            return record
    newest = records[-1]
    if newest["head_seq"] == 0:
        raise InputError(f"attestation {newest['sequence']} was declared over zero records; it anchors nothing")
    return newest


def check_anchors(candidates, trust: Trust, entries, whole: bool, expect: dict, f: Findings):
    """Completeness: heads signed by keys the caller obtained elsewhere, held against this chain."""
    chain_len = entries[-1]["seq"] if entries else 0
    links = {e["seq"]: e["link_hash"] for e in entries}
    chain_known = whole and not f.wrong
    passed, deferred = [], 0
    for label, raw, strict in candidates:
        anchor = parse_anchor(raw, strict)
        if anchor is None:
            f.bad(f"{label} is not a readable head attestation (exact types, and no field the signer "
                  "never writes)")
            continue
        fingerprint = anchor["key_fingerprint"]
        if trust.single:
            (only,) = trust.fingerprints
            if fingerprint != only:
                f.bad(f"{label} was signed by key {fingerprint}, not the trusted key {only} - a foreign "
                      "anchor anchors nothing")
                continue
        else:
            if fingerprint not in trust.entries:
                deferred += 1
                f.cannot(f"{label} was signed by key {fingerprint}, which is not in your keyset "
                         f"({', '.join(trust.fingerprints)}). It may be genuine and from a key you hold no "
                         "record of (an earlier key era), or a forgery: nothing here can tell, so it "
                         "anchors nothing")
                continue
            if expect["fingerprints"] and fingerprint not in expect["fingerprints"]:
                f.bad(f"{label} was signed by key {fingerprint}, which is not one you expected "
                      f"({', '.join(expect['fingerprints'])})")
                continue
            why = trust.judge(fingerprint, anchor["attested_at"])
            if why:
                f.bad(f"{label}: {why}")
                continue
        if not anchor_signature_ok(anchor, trust.entries[fingerprint]["public"]):
            f.bad(f"{label}: the anchor's signature does not verify against the trusted key - edited or "
                  "forged")
            continue
        if anchor["format"] == ATTESTATION_FORMAT_BOUND:
            f.assumed.append(f"{label} is bound to ledger {anchor['ledger_id'][:12]}, but an export bundle names "
                             "no ledger id, so whether this bundle came from that ledger was NOT checked")
        else:
            f.assumed.append(f"{label} is UNBOUND (a v1 attestation): its signature covers no ledger id, so it is "
                             "not shown to describe the ledger this bundle came from")
        if not chain_known:
            seen = links.get(anchor["head_seq"])
            if seen is not None and seen != anchor["head_link_hash"]:
                f.bad(f"{label}: the link at seq {anchor['head_seq']} is not the one that was signed - the "
                      "history there was rewritten")
            continue
        if chain_len < anchor["ledger_length"] or chain_len < anchor["head_seq"]:
            f.bad(f"{label}: the chain ends at seq {chain_len} but {max(anchor['ledger_length'], anchor['head_seq'])}"
                  " were signed for - records were cut from the end (or this is another ledger)")
        elif anchor["head_seq"] > 0 and links.get(anchor["head_seq"]) != anchor["head_link_hash"]:
            f.bad(f"{label}: the link at seq {anchor['head_seq']} is not the one that was signed - the history "
                  "there was removed or rewritten")
        else:
            passed.append(anchor)
    if f.wrong:
        return None
    if not passed:
        if not deferred:
            f.cannot("completeness could not be established although a key was supplied: "
                     + ("this export has no complete chain to hold a signed head against (a subject-only "
                        "export, or a chain that is not intact)" if not chain_known else "no signed anchor "
                        "was usable"))
        return None
    covering = [a for a in passed if a["head_seq"] >= 1 and a["ledger_length"] >= 1]
    if not covering:
        f.cannot("the signed anchor covers no records, so it shows nothing was kept or removed")
        return None
    read = [a for a in covering if a["basis"] == "read_from_ledger"]
    best = max(read or covering, key=lambda a: (a["head_seq"], a["sequence"]))
    violations = hold_expectations(expect, best, links, chain_len, f)
    if violations:
        for message in violations:
            f.bad(message)
        return None
    if not read:
        f.cannot("the only matching signed head was declared to the signer (basis declared_by_holder); the "
                 "signer never read the chain, so this is not an anchor")
        return best
    after = chain_len - best["head_seq"]
    if after:
        f.cannot(f"{after} record(s) after the signed head (seq {best['head_seq']}) are covered by no "
                 "signature: they are consistent with the chain and nothing more, and an unsigned tail is "
                 "exactly what a forger can invent")
    signers = sorted({a["key_fingerprint"] for a in passed})
    f.checked.append(f"a head signed by key {', '.join(signers)} (read from the ledger, attestation "
                     f"{best['sequence']}, seq {best['head_seq']}, signed {best['attested_at']}) lies inside "
                     f"this chain, which runs to seq {chain_len}")
    f.checked += expectation_facts(expect, best, chain_len)
    f.remember = {"min_sequence": best["sequence"], "expect_head": best["head_link_hash"],
                  "min_length": chain_len}
    f.assumed += [
        "The public key must come from a channel the ledger's administrator does not control; a "
        "key that arrived with the export proves nothing.",
        "A hosted-ledger operator who also holds the signing key (the same party that holds the ledger) can "
        "sign a shorter or invented ledger: a signature fixes what was signed and when, by whom, and not "
        "that it was true. Keep a signed record of your own from earlier and pass it with --attestations.",
        FINGERPRINT_BITS_NOTE,
    ]
    if not trust.single:
        f.assumed.append("The keyset file is the trust anchor here: its statuses and dates are whatever its "
                         "author wrote, and an anchor's date is the signer's own claim.")
    return best


def hold_expectations(expect: dict, best: dict, links: dict, chain_len: int, f: Findings) -> list:
    out = []
    seen = f"attestation {best['sequence']} (seq {best['head_seq']}, signed {best['attested_at']})"
    if expect["min_sequence"] is not None and best["sequence"] < expect["min_sequence"]:
        out.append(f"rollback or withheld newer anchor: the newest signed head this export rests on is {seen}, but "
                   f"you saw attestation {expect['min_sequence']} before "
                   f"({expect['min_sequence'] - best['sequence']} newer attestation(s) than this export carries). "
                   "The export was cut back to an older signed head, or its newer anchor was removed.")
    complete = bool(links) and sorted(links) == list(range(1, chain_len + 1)) and not f.wrong
    if expect["expect_head"] is not None:
        if not complete:
            f.cannot("The head you remembered could not be looked for: this export has no complete chain to look in.")
        elif not any(h.startswith(expect["expect_head"]) for h in links.values()):
            out.append(f"rollback: the head you remembered ({expect['expect_head'][:12]}) is not in this export's "
                       f"chain, which ends at seq {chain_len}. Records were removed from the end of the export, "
                       "or it is another ledger's.")
    if expect["min_length"] is not None:
        if not complete:
            f.cannot("The ledger length you remembered could not be compared: this export has no complete chain.")
        elif chain_len < expect["min_length"]:
            out.append(f"{expect['min_length'] - chain_len} record(s) removed: you saw a ledger of at least "
                       f"{expect['min_length']} record(s) and this export's chain ends at seq {chain_len}.")
    if expect["max_age"] is not None:
        signed = parse_time(best["attested_at"])
        age = None if signed is None else expect["now"] - signed
        if age is None or age > expect["max_age"] or age < -timedelta(minutes=5):
            how = ("its signing time is not a timestamp" if age is None else
                   f"it was signed in the future ({-age.total_seconds() / 3600:.1f} h ahead of now), "
                   "which no honest signer or clock produces" if age < -timedelta(minutes=5) else
                   f"it is {age.total_seconds() / 3600:.1f} h old, over the allowed "
                   f"{expect['max_age'].total_seconds() / 3600:g} h")
            out.append(f"the newest signed head ({seen}) is too old: {how}. Signing has stopped, or a newer "
                       "anchor is being withheld.")
    return out


def expectation_facts(expect: dict, best: dict, chain_len: int) -> list:
    facts = []
    if expect["min_sequence"] is not None:
        facts.append(f"the newest signed head here is attestation {best['sequence']}, at least the "
                     f"attestation {expect['min_sequence']} you remembered")
    if expect["expect_head"] is not None:
        facts.append(f"the head you remembered ({expect['expect_head'][:12]}) is in this export's chain")
    if expect["min_length"] is not None:
        facts.append(f"the export's chain runs to seq {chain_len}, at least the {expect['min_length']} "
                     "record(s) you remembered")
    if expect["max_age"] is not None:
        facts.append(f"the newest signed head was signed within the last "
                     f"{expect['max_age'].total_seconds() / 3600:g} h")
    return facts


NO_SKELETON = ("the export carries no skeleton of the ledger's other entries (it is opt-in at export, because it "
               "discloses the id, kind and time of the ledger's other subjects; or it was removed), so removed "
               "entries of this subject cannot be seen. Ask the exporter for one if that disclosure is "
               "acceptable (`?skeleton=true`, `--skeleton`)")


def verify(bundle, public_key_path=None, *, public_keys=(), keyset=None, attestations=None,
           expect=None) -> Findings:
    """Check *bundle*. ``public_key_path`` is the old single-key spelling of ``public_keys``."""
    f = Findings()
    f.remember = None
    keys = list(public_keys) + ([public_key_path] if public_key_path else [])
    expect = expect or {}
    expect = {"min_sequence": None, "expect_head": None, "min_length": None, "max_age": None,
              "fingerprints": (), "now": datetime.now(UTC), **expect}
    if not isinstance(bundle, dict) or not isinstance(bundle.get("entries"), list):
        f.bad("not a ledger export: no `entries` list")
        return f
    unknown = sorted(set(bundle) - TOP_FIELDS - {"skeleton", "skeleton_truncated"})
    if unknown:
        f.bad(f"top-level field(s) the exporter does not write: {', '.join(unknown[:5])} - this "
              "file did not come from the exporter as it is")
    subject = bundle.get("subject", "")
    if not isinstance(subject, str):
        f.bad("the export's `subject` is not text")
        subject = ""
    whole = subject == ""
    if whole and {"skeleton", "skeleton_truncated"} & set(bundle):
        f.bad("a whole-ledger export carries `skeleton`, which only a subject export has")
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
    if whole:
        check_chain(entries, f)
        check_head(bundle, entries, f)
    else:
        check_subject_entries(entries, subject, f)
        if not entries:
            f.bad(f"the export holds no entries for subject {clean(subject)!r}: there is nothing to verify "
                  "(the subject may not exist)")
        if "skeleton" in bundle and bundle.get("skeleton_truncated") is not True:
            f.cannot("a subject export with a skeleton: this file does not merge a skeleton, so it cannot show "
                     "the chain whole; check it with the product's `assurance evidence verify`")
        else:
            f.cannot(NO_SKELETON if "skeleton" not in bundle else
                     "the exporter left out the skeleton because there are too many other entries "
                     "(`skeleton_truncated`), so removed entries of this subject cannot be seen")
    if not f.wrong:
        f.checked += [
            f"{len(entries)} entries have the exact fields and types the seal covers",
            "each evidence body still hashes to its recorded content hash",
            "each link hash matches its own content",
        ]
        if whole:
            f.checked += [
                "the chain starts at genesis, has no gap, and each entry names its predecessor",
                "the export's unsigned head record agrees with its last entry (the exporter agreeing "
                "with itself, not an anchor)",
            ]
        else:
            f.checked += [f"every entry belongs to subject {clean(subject)!r}, in order, and each consecutive "
                          "pair names its predecessor (nothing is said about entries between or beyond)"]
    asked = bool(keys or keyset)
    if not asked:
        if any(expect[k] is not None for k in ("min_sequence", "expect_head", "min_length", "max_age")) \
                or expect["fingerprints"]:
            f.cannot("A remembered head, sequence, length, age or key fingerprint was given and was NOT checked: "
                     "no trusted public key was supplied")
        f.cannot("COMPLETENESS NOT CHECKED: without a trusted public key, nothing shows no entry was "
                 "cut from the end or removed; the file's own head record can be rewritten to match")
        return f
    trust = build_trust(keys, keyset, f)
    if trust is None:
        return f
    if expect["fingerprints"]:
        absent = [fp for fp in expect["fingerprints"] if fp not in trust.entries]
        if absent:
            f.bad("the key(s) supplied do not include the fingerprint you expected "
                  f"({', '.join(absent)}); they are {', '.join(trust.fingerprints)}. This is not the key you "
                  "were given, or it was swapped for another; nothing signed by it is to be trusted.")
        if trust.single and len(expect["fingerprints"]) > 1:
            pass          # the loop above already reported every expected key the one supplied is not
    candidates = []
    if bundle.get("anchor") is not None:
        candidates.append(("the export's anchor", bundle["anchor"], True))
    elif attestations is None:
        f.cannot("completeness could not be established: a public key was supplied, which asks for it, but "
                 "the export carries no signed anchor (it may have been removed)")
    if attestations is not None:
        candidates.append(("the supplied attestation", attestations, False))
    if candidates:
        check_anchors(candidates, trust, entries, whole, expect, f)
    if f.wrong:
        f.checked = [c for c in f.checked if "signed by key" not in c]
    return f


def check_subject_entries(entries, subject, f: Findings):
    """What a subject-only export can show about itself, without the rest of the ledger."""
    for i, entry in enumerate(entries):
        if entry["subject"] != subject:
            f.bad(f"seq {entry['seq']}: belongs to subject {clean(entry['subject'])!r}, not the export's "
                  f"{clean(subject)!r}")
        if i == 0:
            continue
        before = entries[i - 1]
        if entry["seq"] <= before["seq"]:
            f.bad(f"seq {entry['seq']}: out of order after seq {before['seq']}")
        elif entry["seq"] == before["seq"] + 1 and entry["prev_hash"] != before["link_hash"]:
            f.bad(f"seq {entry['seq']}: prev_hash is not the preceding link - re-ordered or spliced")


def clean(text) -> str:
    """Text that came from the file may hold newlines or terminal escapes that fake or erase
    output lines; show them escaped, never raw."""
    return str(text).encode("unicode_escape").decode("ascii")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check a NeuralBridge evidence export with this one file.")
    ap.add_argument("bundle")
    ap.add_argument("--public-key", action="append", default=None,
                    help="the signer's PUBLIC key (PEM), obtained other than from the export, to check "
                         "completeness against a signed anchor. Repeat it to recognise several keys")
    ap.add_argument("--keyset", help="your key history (assurance.attest.keyset.v1); asks for completeness")
    ap.add_argument("--attestations", help="your own copy of the signed attestation log (JSONL)")
    ap.add_argument("--min-sequence", type=int, help="the newest attestation sequence you saw last time")
    ap.add_argument("--expect-head", help="the head link hash (12+ hex) of that attestation")
    ap.add_argument("--min-length", type=int, help="the number of records the ledger had last time")
    ap.add_argument("--max-age", type=float, help="the signed head may be at most this many hours old")
    ap.add_argument("--expect-fingerprint", action="append", default=None,
                    help="the signing key's 16-hex fingerprint, written down elsewhere (repeatable)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    asked = bool(args.public_key or args.keyset)
    if (args.attestations or args.min_sequence is not None or args.expect_head or args.min_length is not None
            or args.max_age is not None or args.expect_fingerprint) and not asked:
        ap.error("--attestations and the remembered values need --public-key or --keyset: a signature can only "
                 "be checked against a key you obtained yourself")
    hexchars = set("0123456789abcdef")
    expect = {"min_sequence": args.min_sequence, "min_length": args.min_length}
    for name in ("min_sequence", "min_length"):
        if expect[name] is not None and expect[name] < 1:
            ap.error(f"--{name.replace('_', '-')} must be at least 1")
    if args.expect_head is not None:
        head = args.expect_head.strip().lower()
        if not 12 <= len(head) <= 64 or not set(head) <= hexchars:
            ap.error("--expect-head must be a hex head link hash (12 to 64 characters)")
        expect["expect_head"] = head
    if args.max_age is not None:
        if not math.isfinite(args.max_age) or args.max_age <= 0 or args.max_age > 1e9:
            ap.error("--max-age must be a positive number of hours")
        expect["max_age"] = timedelta(hours=args.max_age)
    if args.expect_fingerprint:
        fps = [x.strip().lower() for x in args.expect_fingerprint]
        if any(len(x) != 16 or not set(x) <= hexchars for x in fps):
            ap.error("--expect-fingerprint is 16 hex characters (what `attest keygen` prints)")
        expect["fingerprints"] = tuple(dict.fromkeys(fps))
    try:
        with open(args.bundle, encoding="utf-8") as handle:
            bundle = strict_json_loads(handle.read())
    except (OSError, ValueError, RecursionError) as exc:
        reason = clean(exc) if "repeats the name" in str(exc) else exc.__class__.__name__
        print(f"cannot read {args.bundle}: {reason}", file=sys.stderr)
        return 2
    try:
        record = read_attestation_log(args.attestations) if args.attestations else None
        f = verify(bundle, public_keys=args.public_key or [], keyset=args.keyset, attestations=record,
                   expect=expect)
    except InputError as exc:
        print(f"cannot use the key material or log you named: {clean(exc)}. Nothing was checked against it.",
              file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a hostile file must be a refusal, not a traceback
        if args.json:
            print(json.dumps({"exit": 2, "wrong": [], "unestablished": [], "checked": [],
                              "assumed": [], "error": exc.__class__.__name__}))
        else:
            print(f"DOES NOT VERIFY - could not examine the file ({exc.__class__.__name__})")
        return 2
    code = 1 if f.wrong else 3 if f.unestablished else 0
    keep = f.remember if code == 0 or (code == 3 and f.remember and not f.wrong) else None
    if args.json:
        print(json.dumps({"exit": code, "wrong": f.wrong, "unestablished": f.unestablished,
                          "checked": f.checked, "assumed": f.assumed,
                          "remember_for_next_check": keep}, indent=2))
    else:
        head = {0: "VERIFIED", 1: "DOES NOT VERIFY", 3: "NOT ESTABLISHED"}[code]
        listed = bundle.get("entries") if isinstance(bundle, dict) else None
        print(f"{head} - {len(listed) if isinstance(listed, list) else 0} entries")
        if keep:
            print("  KEEP FOR YOUR NEXT CHECK  (so an export cut back to an older signed head is caught)  "
                  f"--min-sequence {keep['min_sequence']} --expect-head {keep['expect_head']} "
                  f"--min-length {keep['min_length']}")
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
