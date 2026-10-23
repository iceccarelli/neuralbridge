"""``assurance evidence`` — check an exported evidence bundle offline.

    verify <bundle.json> [--public-key KEY.pub [--attestations LOG]] [--json]
                                    exit 0 verified, 1 does not verify, 2 unreadable

The exit codes keep "the evidence is wrong" (1) apart from "I could not look" (2).

Without ``--public-key`` the check is internal consistency only and the output
says, in words, that **completeness was not checked**: a bundle cut short, or
rebuilt without some entries, looks the same. With the signer's public key (from a
channel other than the bundle) the bundle's embedded signed anchor is verified and
the bundle must agree with it; a bundle that cannot be shown to is exit 1.
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
from assurance.evidence.verify_export import ExportVerification, verify_export_file

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="assurance evidence", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify an exported bundle, offline")
    v.add_argument("bundle")
    v.add_argument("--json", action="store_true")
    v.add_argument("--public-key", type=Path, default=None, metavar="KEY.pub",
                   help="the signer's Ed25519 PUBLIC key, obtained somewhere other than "
                        "the bundle. Turns on the completeness check against the "
                        "bundle's signed anchor.")
    v.add_argument("--attestations", type=Path, default=None, metavar="LOG",
                   help="your own copy of the signed attestation log "
                        "(`assurance attest sign`); its newest record is checked "
                        "against the bundle as well. Needs --public-key.")
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
                anchors.append(AttestationLog(args.attestations).require_last())
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
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
