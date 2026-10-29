"""``assurance value report`` — your own assurance position, from your own ledger.

Exit codes: 0 the position was computed and no work is outstanding; 1 outstanding
work or unknowns exist; 2 the ledger's chain does not verify or the input is bad.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.value.position import assess_position, render_text

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance value", description=__doc__)
    verbs = p.add_subparsers(dest="verb", required=True)
    r = verbs.add_parser("report", help="derive the assurance position from a ledger")
    r.add_argument("--ledger", required=True, type=Path)
    r.add_argument("--now", default="", help="ISO time to measure freshness against")
    r.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not args.ledger.exists():
            print(f"{args.ledger} does not exist.", file=sys.stderr)
            return 2
        result = assess_position(EvidenceLedger(args.ledger),
                                 now=parse_utc(args.now) if args.now else None)
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else render_text(result))
    if not result["ledger"]["chain_verified"]:
        return 2
    return 1 if result["next_work"] or result["totals"]["machines_without_a_manifest"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
