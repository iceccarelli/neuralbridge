"""``assurance evidence`` — check an exported evidence bundle offline.

    verify <bundle.json> [--public-key KEY.pub [--attestations LOG]] [--json]
        exit 0 verified (with --public-key: anchored to a head the signer read from
        the ledger), 1 does not verify, 2 unreadable, 3 no inconsistency found but
        not established

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
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.evidence.verify_export import ANCHORED, ExportVerification, verify_export_file

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assurance evidence", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify an exported bundle, offline")
    v.add_argument("bundle")
    v.add_argument("--json", action="store_true")
    v.add_argument("--public-key", type=Path, default=None, metavar="KEY.pub",
                   help="the signer's Ed25519 PUBLIC key, obtained somewhere other than "
                        "the bundle. Turns on the completeness check against the "
                        "bundle's signed anchor; then only a head the signer READ "
                        "from the ledger and that covers the last record is exit "
                        "0 (anything less is exit 3).")
    v.add_argument("--attestations", type=Path, default=None, metavar="LOG",
                   help="your own copy of the signed attestation log "
                        "(`assurance attest sign`); the newest record the signer READ from a ledger "
                        "(else the newest declared one) is checked against the bundle as well. "
                        "Needs --public-key.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.attestations and not args.public_key:
        parser.error("--attestations needs --public-key: a signature can only be "
                     "checked against a key you obtained yourself")
    trusted = None
    anchors: list[object] = []
    if args.public_key:
        try:
            from assurance.attest.attestation import AttestationLog
            from assurance.attest.keys import VerifyingKey

            trusted = VerifyingKey.from_file(args.public_key)
            if args.attestations:
                anchors.append(AttestationLog(args.attestations).require_anchor())
        except (ImportError, AssuranceError, OSError, ValueError) as exc:
            # Could not look: a missing key or log is never a quiet unanchored pass.
            print(f"error: {exc}", file=sys.stderr)
            return 2

    result: ExportVerification = verify_export_file(
        args.bundle, trusted_key=trusted, anchors=anchors)
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
    if trusted is not None and result.completeness != ANCHORED:
        return 3  # a key asks for completeness: partial, declared and unchecked are not a pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
