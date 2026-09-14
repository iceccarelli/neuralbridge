"""``assurance bridge`` — the advisory becomes a regulatory intake.

    art14   draft a CRA Article 14 intake from an advisory and your fleet

Article 14(2)(a) gives a manufacturer 24 hours to file an early warning naming
the Member States the product was made available in. That list is an inventory
question, and 24 hours is not long enough to answer it from a standing start.

    assurance bridge art14 advisory.json --ledger register.db \\
      --received-by a.integrator --open

Exits non-zero when the Member State list cannot be completed from the fleet —
because a filing with a wrong field 5 is worse than a late one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.bridge.art14 import draft_from_advisory, open_case
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.security.art14.engine import Art14Register

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance bridge",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    a = verbs.add_parser("art14", help="draft an Article 14 intake from an advisory")
    a.add_argument("advisory", type=Path)
    a.add_argument("--ledger", required=True, type=Path,
                   help="the fleet ledger the affected machines live in")
    a.add_argument("--received-by", required=True,
                   help="who received the advisory; the interval from here to "
                        "awareness is evidence")
    a.add_argument("--case-id", default="")
    a.add_argument("--product-name", default="",
                   help="the product as placed on the market, if it is not "
                        "'<manufacturer> <model>'")
    a.add_argument("--open", action="store_true",
                   help="record the intake in the Article 14 register")
    a.add_argument("--register", type=Path, default=None,
                   help="register ledger for --open; defaults to --ledger")
    a.add_argument("--actor", default="",
                   help="who is recording it; defaults to --received-by")
    a.add_argument("--out", type=Path, default=None)
    a.add_argument("--json", action="store_true")

    return p


def _cmd_art14(args: argparse.Namespace) -> int:
    advisory = ComponentAdvisory.from_json(args.advisory)
    fleet = Fleet.from_ledger(EvidenceLedger(args.ledger))
    impact = assess_impact(advisory, fleet)
    draft = draft_from_advisory(
        advisory, impact, fleet, case_id=args.case_id,
        received_by=args.received_by, product_name=args.product_name,
    )

    opened = ""
    if args.open:
        register = Art14Register(EvidenceLedger(args.register or args.ledger))
        actor = Actor(identifier=args.actor or args.received_by,
                      role="product security", kind="person")
        case_id, sealed = open_case(register, draft, actor)
        opened = f"{case_id}: {len(sealed)} record(s) sealed"

    if args.out:
        Path(args.out).write_text(
            json.dumps(draft.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    if args.json:
        payload = draft.to_dict()
        payload["opened"] = opened
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(draft.summary())
        if draft.checks_skipped:
            print("\n  not checked:")
            for c in draft.checks_skipped:
                print(f"    - {c}")
        if args.out:
            print(f"\n  draft written to {args.out}")
        if opened:
            print(f"  opened {opened}")
            print("  The register will refuse a filing until somebody records a "
                  "track and an awareness timestamp. That is the point.")
        if not draft.can_complete_field_5:
            print("\n  FIELD 5 CANNOT BE COMPLETED from the fleet. Record the "
                  "country against every affected machine, or establish the "
                  "territories another way before filing.")

    return 0 if draft.can_complete_field_5 else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"art14": _cmd_art14}[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
