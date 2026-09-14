"""``assurance fleet`` — every machine at once, and what an advisory means for them.

    list        every machine in the ledger, worst coverage first
    advisory    fan a component advisory out across the fleet
    declare     bind a Declaration of Conformity to the configuration in front of you
    declaration check a declaration against what the machine runs today

``advisory`` and ``declaration`` exit non-zero on a finding, so both belong in
whatever runs when a supplier bulletin lands or before a machine ships.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory
from assurance.fleet.declaration import (
    DeclarationOfConformity,
    check_declaration,
)
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord, assess_coverage

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance fleet",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    ls = verbs.add_parser("list", help="every machine, worst coverage first")
    ls.add_argument("--ledger", required=True, type=Path)
    ls.add_argument("--json", action="store_true")

    ad = verbs.add_parser("advisory", help="which machines does this advisory touch")
    ad.add_argument("advisory", type=Path)
    ad.add_argument("--ledger", required=True, type=Path)
    ad.add_argument("--json", action="store_true")

    dc = verbs.add_parser("declare",
                          help="bind a declaration to a manifest's configuration")
    dc.add_argument("manifest", type=Path)
    dc.add_argument("--doc-id", required=True)
    dc.add_argument("--issued-by", required=True)
    dc.add_argument("--legislation", required=True, action="append",
                    help="repeatable, e.g. --legislation 'Regulation (EU) 2023/1230'")
    dc.add_argument("--standard", action="append", default=[])
    dc.add_argument("--notified-body", default="")
    dc.add_argument("--notified-body-number", default="")
    dc.add_argument("--signatory", default="")
    dc.add_argument("--place", default="")
    dc.add_argument("--issued-at", default="",
                    help="ISO timestamp; defaults to now")
    dc.add_argument("--out", type=Path, default=None)

    ck = verbs.add_parser("declaration",
                          help="does the declaration still describe the machine")
    ck.add_argument("declaration", type=Path)
    ck.add_argument("--manifest", required=True, type=Path)
    ck.add_argument("--ledger", type=Path, default=None,
                    help="also assess whether the safety evidence still stands")
    ck.add_argument("--json", action="store_true")

    return p


def _cmd_list(args: argparse.Namespace) -> int:
    fleet = Fleet.from_ledger(EvidenceLedger(args.ledger))
    if args.json:
        print(json.dumps(fleet.to_dict(), indent=2))
    else:
        print(fleet.table())
    return 0 if not fleet.with_gaps() else 1


def _cmd_advisory(args: argparse.Namespace) -> int:
    advisory = ComponentAdvisory.from_json(args.advisory)
    fleet = Fleet.from_ledger(EvidenceLedger(args.ledger))
    report = assess_impact(advisory, fleet)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
        if report.checks_skipped:
            print("\n  not checked:")
            for c in report.checks_skipped:
                print(f"    - {c}")
    return 0 if report.verdict == "clear" else 1


def _cmd_declare(args: argparse.Namespace) -> int:
    manifest = SafetyManifest.from_json(args.manifest)
    issued = parse_utc(args.issued_at) if args.issued_at else utc_now()
    declaration = DeclarationOfConformity.bind(
        manifest, doc_id=args.doc_id, issued_by=args.issued_by, issued_at=issued,
        legislation=tuple(args.legislation), standards=tuple(args.standard),
        notified_body=args.notified_body,
        notified_body_number=args.notified_body_number,
        signatory=args.signatory, place=args.place,
    )
    payload = json.dumps(declaration.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"declaration {declaration.doc_id} written to {args.out}")
        print(f"  machine        {declaration.machine_key}")
        print(f"  configuration  {declaration.configuration_hash[:16]}")
        print(f"  identity       {declaration.content_hash()[:16]}")
        print("  This declaration is now checkable: any later manifest of this "
              "machine either matches that configuration or does not.")
    else:
        print(payload, end="")
    return 0


def _cmd_declaration(args: argparse.Namespace) -> int:
    declaration = DeclarationOfConformity.from_json(args.declaration)
    manifest = SafetyManifest.from_json(args.manifest)

    coverage = None
    if args.ledger:
        ledger = EvidenceLedger(args.ledger)
        key = manifest.machine.key
        coverage = assess_coverage(
            manifest,
            VerificationRecord.from_ledger(ledger, subject=key),
            interventions_from_ledger(ledger, key),
        )

    status = check_declaration(declaration, manifest, coverage)
    if args.json:
        print(json.dumps(status.to_dict(), indent=2))
    else:
        print(status.summary())
        if status.checks_skipped:
            print("\n  not checked:")
            for c in status.checks_skipped:
                print(f"    - {c}")
        if coverage is None:
            print("\n  Supply --ledger to check the evidence as well as the "
                  "configuration.")
    return 0 if status.is_sound else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "list": _cmd_list,
        "advisory": _cmd_advisory,
        "declare": _cmd_declare,
        "declaration": _cmd_declaration,
    }
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
