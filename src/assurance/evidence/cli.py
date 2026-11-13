"""``assurance evidence`` — check an exported evidence bundle offline.

    verify <bundle.json> [--public-key KEY.pub [--attestations LOG]] [--json]
           [--min-sequence N --expect-head HASH --min-length N --max-age HOURS]
           [--expect-fingerprint FP]
        exit 0 verified (with --public-key: anchored to a head the signer read from
        the ledger, and every remembered value met), 1 does not verify, 2 unreadable,
        3 no inconsistency found but not established

The exit codes keep "the evidence is wrong" (1) apart from "I could not look" (2) and
from "nothing wrong was found, and completeness is still not shown" (3). With
``--public-key`` you asked for completeness, so only ``anchored`` is a pass: a signed
head that stops short of the last record, one the signer was merely told
(``declared_head``), or no complete chain to hold it against are exit 3. Without a key
exit 0 means internal consistency only, and the output says completeness was not
checked.

Without ``--public-key`` the check is internal consistency only and the output
says, in words, that **completeness was not checked**: a bundle cut short, or
rebuilt without some entries, looks the same. With the signer's public key (from a
channel other than the bundle) the bundle's embedded signed anchor is verified and
the bundle must agree with it; one that contradicts it is exit 1. If records
follow the signed head the headline says how many no signature covers (it is never
"anchored"), a head the signer was only told (``declared_by_holder``) is reported as
declared and is never "anchored", an anchor that signs an empty ledger anchors nothing,
and a one-case export made without the opt-in skeleton cannot be shown complete (that
is "not established", exit 3, and the output says how to ask for the skeleton).
``--attestations LOG`` adds the verifier's *own* copy of the signed attestations,
which is the only thing that guards against a party that holds both the ledger and
the signing key.

A signed anchor does not show the bundle is the NEWEST: a bundle cut back to any older
signed head is genuine, consistent and anchored. Only what you remember from your last
check can show it, so a passing result prints a ``KEEP FOR YOUR NEXT CHECK`` line and the
next check passes it back (``--min-sequence N --expect-head HASH --min-length N``, and
``--max-age HOURS`` for how old the signed head may be). A bundle that breaks one is
exit 1, with how many attestations or records are missing. ``--expect-fingerprint FP``
(the signing key's fingerprint, written down from another source) makes a swapped public
key exit 1 instead of passing. All of these need ``--public-key``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.text import neutralise
from assurance.evidence.verify_export import (
    ANCHORED,
    Expectations,
    ExportVerification,
    verify_export_file,
)

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assurance evidence", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify an exported bundle, offline")
    v.add_argument("bundle")
    v.add_argument("--json", action="store_true")
    v.add_argument("--keyset", type=Path, default=None, metavar="FILE",
                   help="your key history (assurance.attest.keyset.v1; `attest keyset add`): "
                        "the key that checks an anchor is the one whose fingerprint it names, "
                        "within that key's window. A revoked key, or an anchor dated outside a "
                        "retired key's window, is exit 1; a fingerprint not in the file is "
                        "exit 3 (not established), never a pass. Like --public-key it asks "
                        "for completeness")
    v.add_argument("--public-key", type=Path, action="append", default=None, metavar="KEY.pub",
                   help="the signer's Ed25519 PUBLIC key, obtained somewhere other than "
                        "the bundle. Turns on the completeness check against the "
                        "bundle's signed anchor; then only a head the signer READ "
                        "from the ledger and that covers the last record is exit "
                        "0 (anything less is exit 3). ONE key: an anchor from any other key "
                        "is a foreign anchor, exit 1. Repeat it (or use --keyset) to "
                        "recognise several keys: an anchor from an unlisted key is then exit 3.")
    v.add_argument("--attestations", type=Path, default=None, metavar="LOG",
                   help="your own copy of the signed attestation log "
                        "(`assurance attest sign`); the newest record the signer READ from a ledger "
                        "(else the newest declared one) is checked against the bundle as well. "
                        "Needs --public-key.")
    v.add_argument("--min-sequence", type=int, default=None, metavar="N",
                   help="the newest attestation sequence you saw at your LAST check (printed "
                        "under KEEP FOR YOUR NEXT CHECK). A bundle whose signed head is older "
                        "is a rollback: exit 1. Needs --public-key")
    v.add_argument("--expect-head", default=None, metavar="HASH",
                   help="the head link hash of that attestation (12+ hex characters). A bundle "
                        "whose chain no longer contains it is a rollback: exit 1")
    v.add_argument("--min-length", type=int, default=None, metavar="N",
                   help="the number of records the ledger had at your last check; a shorter "
                        "bundle fails and the answer says how many were removed")
    v.add_argument("--max-age", type=float, default=None, metavar="HOURS",
                   help="fail unless the signed head the bundle rests on was signed within "
                        "this many hours")
    v.add_argument("--expect-fingerprint", action="append", default=None, metavar="FP",
                   help="the signing key's 16-hex fingerprint, written down from a source "
                        "other than the bundle (repeat for several). A different public key "
                        "is exit 1: this is the check that catches a substituted key. Needs "
                        "--public-key")
    return parser


def _expectations(parser: argparse.ArgumentParser, args: argparse.Namespace) -> dict[str, Any]:
    """The remembered values as ``verify_export`` keywords; a usage error if they are nonsense."""
    max_age = None
    if args.max_age is not None:
        if not math.isfinite(args.max_age) or args.max_age <= 0:
            parser.error("--max-age must be a positive number of hours")
        try:
            max_age = timedelta(hours=args.max_age)
        except OverflowError:
            parser.error("--max-age is too large")
    given: dict[str, Any] = {
        "min_sequence": args.min_sequence, "expect_head": args.expect_head,
        "min_length": args.min_length, "max_age": max_age,
        "expect_fingerprints": args.expect_fingerprint}
    try:
        Expectations.checked(**given)
    except ValueError as exc:
        parser.error(str(exc))
    return given


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.attestations and not (args.public_key or args.keyset):
        parser.error("--attestations needs --public-key or --keyset: a signature can only be "
                     "checked against a key you obtained yourself")
    expectations = _expectations(parser, args)
    asked = bool(args.public_key or args.keyset)
    if any(v is not None for v in expectations.values()) and not asked:
        parser.error("--min-sequence, --expect-head, --min-length, --max-age and "
                     "--expect-fingerprint need --public-key or --keyset: they are held "
                     "against a signed anchor, which only a key you obtained yourself can "
                     "check")
    trusted = None
    keyset = None
    anchors: list[object] = []
    if asked:
        try:
            from assurance.attest.attestation import AttestationLog
            from assurance.attest.keys import VerifyingKey
            from assurance.attest.keyset import Keyset

            keys = [VerifyingKey.from_file(p) for p in (args.public_key or [])]
            if args.keyset:
                keyset = Keyset.load(args.keyset)
                if keys:
                    keyset = keyset.merged_with(Keyset.from_keys(keys))
            elif len(keys) == 1:
                trusted = keys[0]
            else:
                keyset = Keyset.from_keys(keys)
            if args.attestations:
                anchors.append(AttestationLog(args.attestations).require_anchor())
        except (ImportError, AssuranceError, OSError, ValueError) as exc:
            # Could not look: a missing key or log is never a quiet unanchored pass.
            print(f"error: {neutralise(exc, multiline=True)}", file=sys.stderr)
            return 2

    result: ExportVerification = verify_export_file(
        args.bundle, trusted_key=trusted, keyset=keyset, anchors=anchors, **expectations)
    unreadable = result.scope == "unknown"
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.text())
    if unreadable:
        return 2
    if result.problems or (not result.ok and not result.unestablished):
        return 1
    if not result.ok:
        return 3  # nothing wrong was found, but something asked for is not established
    if asked and result.completeness != ANCHORED:
        return 3  # a key asks for completeness: partial, declared and unchecked are not a pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
