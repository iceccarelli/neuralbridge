"""``assurance machinery`` — the machine's software identity and its change history.

    record-manifest   seal what is on the machine today
    record-change     seal an intervention in safety-relevant software
    diff              compare a baseline manifest against what was found
    coverage          which safety functions still have valid evidence
    passport          seal and export the machine's whole evidence position
    check             re-verify a passport somebody else produced

``coverage`` exits non-zero when any declared safety function is not currently
covered, which makes it a gate rather than a report.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.divergence import compare
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import (
    build_passport,
    interventions_from_ledger,
    record_divergence,
    record_intervention,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import VerificationRecord, assess_coverage

__all__ = ["build_parser", "main"]


def _actor(args: argparse.Namespace) -> Actor:
    return Actor(identifier=args.actor, role=getattr(args, "role", ""), kind="person")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance machinery",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    rm = verbs.add_parser("record-manifest", help="seal a safety software manifest")
    rm.add_argument("manifest", type=Path)
    rm.add_argument("--ledger", required=True, type=Path)
    rm.add_argument("--actor", default="")
    rm.add_argument("--role", default="")

    rc = verbs.add_parser("record-change", help="seal an intervention record")
    rc.add_argument("intervention", type=Path)
    rc.add_argument("--ledger", required=True, type=Path)
    rc.add_argument("--actor", default="")
    rc.add_argument("--role", default="")

    df = verbs.add_parser("diff", help="compare a baseline manifest against an observed one")
    df.add_argument("--baseline", required=True, type=Path)
    df.add_argument("--observed", required=True, type=Path)
    df.add_argument("--ledger", type=Path, default=None,
                    help="seal the divergence report into this ledger")
    df.add_argument("--actor", default="")
    df.add_argument("--role", default="")
    df.add_argument("--json", action="store_true")

    cv = verbs.add_parser("coverage", help="which safety functions still have evidence")
    cv.add_argument("manifest", type=Path)
    cv.add_argument("--ledger", required=True, type=Path)
    cv.add_argument("--json", action="store_true")

    pp = verbs.add_parser("passport", help="seal and export the machine's position")
    pp.add_argument("manifest", type=Path)
    pp.add_argument("--ledger", required=True, type=Path)
    pp.add_argument("--actor", required=True)
    pp.add_argument("--role", default="verification engineer")
    pp.add_argument("--out", type=Path, default=None)
    pp.add_argument("--no-seal", action="store_true",
                    help="assemble without appending to the ledger")
    pp.add_argument("--json", action="store_true")

    ck = verbs.add_parser("check", help="re-verify a passport you did not produce")
    ck.add_argument("passport", type=Path)
    ck.add_argument("--ledger", type=Path, default=None)
    ck.add_argument("--json", action="store_true")

    return p


def _cmd_record_manifest(args: argparse.Namespace) -> int:
    manifest = SafetyManifest.from_json(args.manifest)
    ledger = EvidenceLedger(args.ledger)
    actor = _actor(args) if args.actor else None
    evidence = record_manifest(ledger, manifest, actor=actor)
    print(f"sealed {evidence.content_hash[:16]} as entry {len(ledger)}")
    print(f"  machine       {manifest.machine.key}")
    print(f"  source        {manifest.source.value}")
    print(f"  items         {len(manifest.items)} "
          f"({len(manifest.uncomparable_items)} carry no hash)")
    print(f"  configuration {manifest.configuration_hash()[:16]}")
    print(f"  tier ceiling  {manifest.tier_ceiling.value}")
    for f in manifest.undemonstrable_functions:
        print(f"  !! {f.function_id} declares no verification check")
    return 0


def _cmd_record_change(args: argparse.Namespace) -> int:
    intervention = Intervention.from_json(args.intervention)
    ledger = EvidenceLedger(args.ledger)
    actor = _actor(args) if args.actor else None
    evidence = record_intervention(ledger, intervention, actor=actor)
    print(intervention.summary())
    print(f"    sealed {evidence.content_hash[:16]} as entry {len(ledger)}")
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    baseline = SafetyManifest.from_json(args.baseline)
    observed = SafetyManifest.from_json(args.observed)
    divergence = compare(baseline, observed)

    if args.ledger:
        if not args.actor:
            print("error: --actor is required to seal a divergence report",
                  file=sys.stderr)
            return 2
        record_divergence(EvidenceLedger(args.ledger), divergence, actor=_actor(args))

    if args.json:
        print(json.dumps(divergence.to_dict(), indent=2))
    else:
        print(divergence.summary())
        if divergence.checks_skipped:
            print("\n  not checked:")
            for c in divergence.checks_skipped:
                print(f"    - {c}")
    return 0 if divergence.verdict == "matches" else 1


def _cmd_coverage(args: argparse.Namespace) -> int:
    manifest = SafetyManifest.from_json(args.manifest)
    ledger = EvidenceLedger(args.ledger)
    key = manifest.machine.key
    report = assess_coverage(
        manifest,
        VerificationRecord.from_ledger(ledger, subject=key),
        interventions_from_ledger(ledger, key),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
        if report.checks_skipped:
            print("\n  not checked:")
            for c in report.checks_skipped:
                print(f"    - {c}")
    return 0 if report.verdict == "covered" else 1


def _cmd_passport(args: argparse.Namespace) -> int:
    manifest = SafetyManifest.from_json(args.manifest)
    ledger = EvidenceLedger(args.ledger)
    passport = build_passport(ledger, manifest, actor=_actor(args),
                              seal=not args.no_seal)
    if args.out:
        passport.write(args.out)
    if args.json:
        print(json.dumps(passport.to_dict(), indent=2, sort_keys=True))
    else:
        print(passport.summary())
        if passport.coverage.checks_skipped:
            print("\n  not checked:")
            for c in passport.coverage.checks_skipped:
                print(f"    - {c}")
        if args.out:
            print(f"\n  passport written to {args.out}")
    return 0 if passport.verdict == "covered" else 1


def _cmd_check(args: argparse.Namespace) -> int:
    ledger = EvidenceLedger(args.ledger) if args.ledger else None
    ok, problems = verify_passport(args.passport, ledger=ledger)
    if args.json:
        print(json.dumps({"ok": ok, "problems": problems}, indent=2))
    else:
        print(f"{args.passport}: {'OK' if ok else 'REJECTED'}")
        for p in problems:
            print(f"  - {p}")
        if ok and ledger is None:
            print("  Supply --ledger to check the records it names, not just the seal.")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "record-manifest": _cmd_record_manifest,
        "record-change": _cmd_record_change,
        "diff": _cmd_diff,
        "coverage": _cmd_coverage,
        "passport": _cmd_passport,
        "check": _cmd_check,
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
