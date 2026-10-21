"""``assurance evidence`` — check an exported evidence bundle offline.

    verify <bundle.json> [--json]   exit 0 verified, 1 does not verify, 2 unreadable

The exit codes keep "the evidence is wrong" (1) apart from "I could not look" (2).
"""

from __future__ import annotations

import argparse
import json
import sys

from assurance.evidence.verify_export import verify_export_file

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="assurance evidence", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify an exported bundle, offline")
    v.add_argument("bundle")
    v.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = verify_export_file(args.bundle)
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
