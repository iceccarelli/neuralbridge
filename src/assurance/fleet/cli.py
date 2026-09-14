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
    ad.add_argument("advisory", type=Path, nargs="?", default=None,
                    help="an advisory as JSON. Prefer --feed, which is signed")
    ad.add_argument("--feed", type=Path, default=None,
                    help="a signed supplier feed; every standing advisory in it "
                         "is fanned out")
    ad.add_argument("--supplier-key", type=Path, default=None,
                    help="the supplier's public key, obtained by a route that is "
                         "not this feed")
    ad.add_argument("--expect-supplier", default="")
    ad.add_argument("--unsigned-anyway", action="store_true",
                    help="act on an unverified advisory. Recorded in the output; "
                         "you are choosing to modify a safety system on the word "
                         "of an unauthenticated file")
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


#: Said once, loudly, wherever an unverified advisory is acted on. The point of
#: this whole mechanism is that a forged advisory is a physical safety attack:
#: it induces somebody to modify the safety system of a machine people stand
#: next to. A tool that treats signed and unsigned as equivalent has not closed
#: anything.
_UNSIGNED_WARNING = (
    "This advisory is not signed, or its signature was not checked. It arrived "
    "as a file. Acting on it means changing a safety system on the authority of "
    "something anyone could have written — which is the attack this mechanism "
    "exists to prevent. Ask the supplier to publish a signed feed; it costs them "
    "one command."
)


def _advisories_from_feed(args: argparse.Namespace) -> tuple[list, list[str]]:
    """Every standing advisory in a feed, refusing the feed if it does not hold up."""
    from assurance.attest.keys import VerifyingKey
    from assurance.supplier.publish import AdvisoryFeed, verify_feed

    records = AdvisoryFeed(args.feed).read()
    if not records:
        raise AssuranceError(f"{args.feed} holds no records.")

    if args.supplier_key is None:
        if not args.unsigned_anyway:
            raise AssuranceError(
                f"{args.feed} was not checked against a key. Pass --supplier-key "
                "with the public key you obtained from the supplier by some route "
                "other than this feed, or --unsigned-anyway if you accept that "
                "you are acting on an unauthenticated file."
            )
        return ([r.component() for r in records if not r.is_withdrawal],
                [_UNSIGNED_WARNING])

    verdict = verify_feed(records, VerifyingKey.from_file(args.supplier_key),
                          expect_supplier=args.expect_supplier)
    if not verdict.ok and not args.unsigned_anyway:
        raise AssuranceError(
            f"refusing to act on {args.feed}:\n  "
            + "\n  ".join(verdict.problems)
            + "\n\nA change to a safety system driven by an advisory that does "
              "not verify is exactly what signing is for. Use --unsigned-anyway "
              "only if you have decided, deliberately, to proceed."
        )
    notes = list(verdict.checks_skipped)
    if not verdict.ok:
        notes.insert(0, "PROCEEDED ON A FEED THAT DOES NOT VERIFY: "
                        + "; ".join(verdict.problems))
    return ([r.component() for r in verdict.live], notes)


def _cmd_advisory(args: argparse.Namespace) -> int:
    if args.feed and args.advisory:
        print("error: give an advisory file or --feed, not both.", file=sys.stderr)
        return 2
    if not args.feed and not args.advisory:
        print("error: give an advisory file or --feed.", file=sys.stderr)
        return 2

    if args.feed:
        advisories, notes = _advisories_from_feed(args)
    else:
        advisories = [ComponentAdvisory.from_json(args.advisory)]
        notes = [_UNSIGNED_WARNING]

    fleet = Fleet.from_ledger(EvidenceLedger(args.ledger))
    reports = [assess_impact(a, fleet) for a in advisories]

    if args.json:
        print(json.dumps({
            "advisories": [r.to_dict() for r in reports],
            "provenance_notes": notes,
        }, indent=2))
    else:
        for advisory, report in zip(advisories, reports, strict=True):
            print(f"{advisory.advisory_id} — {advisory.title}")
            print(report.summary())
            if report.checks_skipped:
                print("\n  not checked:")
                for c in report.checks_skipped:
                    print(f"    - {c}")
            print()
        print("  provenance:")
        for note in notes:
            print(f"    - {note}")
    return 0 if all(r.verdict == "clear" for r in reports) else 1


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
