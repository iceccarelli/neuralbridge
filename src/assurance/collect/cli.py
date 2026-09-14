"""``assurance collect`` — turn a folder of vendor exports into a sealed manifest.

    check-plan   read a plan and say what it would and would not catch
    probe        two exports of an unchanged machine: which rules report noise
    run          collect one machine, and optionally seal it into the ledger

The intended order is exactly that. Write the plan once for a machine type,
probe it until it says STABLE, then run it for every unit — and never the other
way round, because a plan that has not been probed produces drift reports that
are mostly noise and a customer who stops reading them.

``probe`` exits non-zero while any rule is volatile, so it belongs in whatever
reviews a change to a plan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.collect.collector import collect
from assurance.collect.plan import CollectionPlan
from assurance.collect.volatility import probe
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.manifest import ManifestSource
from assurance.machinery.record import record_manifest

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance collect",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    cp = verbs.add_parser("check-plan", help="what would this plan catch, and miss")
    cp.add_argument("plan", type=Path)
    cp.add_argument("--json", action="store_true")

    pr = verbs.add_parser("probe", help="which rules report the export's own noise")
    pr.add_argument("plan", type=Path)
    pr.add_argument("--first", required=True, type=Path,
                    help="folder of the first export")
    pr.add_argument("--second", required=True, type=Path,
                    help="folder of a second export of the SAME unchanged machine")
    pr.add_argument("--json", action="store_true")

    rn = verbs.add_parser("run", help="collect one machine")
    rn.add_argument("plan", type=Path)
    rn.add_argument("--root", required=True, type=Path,
                    help="folder holding this machine's exports")
    rn.add_argument("--serial", required=True)
    rn.add_argument("--actor", required=True)
    rn.add_argument("--role", default="safety engineer")
    rn.add_argument("--site", default="")
    rn.add_argument("--country", default="",
                    help="ISO 3166-1 alpha-2 of the territory this unit was made "
                         "available in. CRA Article 14(2)(a) asks for it, and 24 "
                         "hours is not long enough to find out.")
    rn.add_argument("--year", default="")
    rn.add_argument("--manifest-id", default="")
    rn.add_argument("--taken-at", default="", help="ISO timestamp; defaults to now")
    rn.add_argument("--as-declared", action="store_true",
                    help="this is a baseline built from a release, not a machine")
    rn.add_argument("--out", type=Path, default=None)
    rn.add_argument("--ledger", type=Path, default=None,
                    help="seal the manifest into this evidence ledger")
    rn.add_argument("--json", action="store_true")

    return p


def _cmd_check_plan(args: argparse.Namespace) -> int:
    plan = CollectionPlan.from_json(args.plan)
    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
        return 0
    print(f"{plan.plan_id} — {plan.manufacturer} {plan.model}  "
          f"({plan.content_hash()[:12]})")
    print(f"  {len(plan.items)} item(s), {len(plan.functions)} safety function(s)")
    for item in plan.items:
        fns = ", ".join(item.implements) or "—"
        req = "" if item.required else "  (optional)"
        print(f"  {item.item_id:<14} {item.rule.kind.value:<16} {item.source}{req}")
        print(f"                 implements {fns}   version from "
              f"{item.version.kind}")
        if item.rule.note:
            print(f"                 excludes: {item.rule.note}")
    if plan.unmapped_items:
        print()
        print("  items credited to no safety function — a change to these will show "
              "as drift and invalidate no verification:")
        for item in plan.unmapped_items:
            print(f"    - {item.item_id}")
    if plan.undemonstrable_functions:
        print()
        print("  safety functions with no verification check — nothing can ever "
              "demonstrate these:")
        for fn in plan.undemonstrable_functions:
            print(f"    - {fn.function_id}  {fn.description}")
    raw = [i for i in plan.items if i.rule.kind.value == "raw"]
    if raw:
        print()
        print("  items hashed raw. Correct for an opaque firmware image; wrong for "
              "any export that stamps itself. Probe before you trust them:")
        for item in raw:
            print(f"    - {item.item_id}  {item.source}")
    return 0


def _cmd_probe(args: argparse.Namespace) -> int:
    plan = CollectionPlan.from_json(args.plan)
    report = probe(plan, args.first, args.second)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
        if report.checks_skipped:
            print("\n  not checked:")
            for c in report.checks_skipped:
                print(f"    - {c}")
    return 0 if report.verdict == "stable" else 1


def _cmd_run(args: argparse.Namespace) -> int:
    plan = CollectionPlan.from_json(args.plan)
    result = collect(
        plan, args.root, serial=args.serial,
        taken_by=Actor(identifier=args.actor, role=args.role, kind="person"),
        site=args.site, country=args.country, year=args.year,
        manifest_id=args.manifest_id,
        source=ManifestSource.AS_DECLARED if args.as_declared
        else ManifestSource.AS_FOUND,
        taken_at=parse_utc(args.taken_at) if args.taken_at else None,
    )

    if args.out:
        Path(args.out).write_text(
            json.dumps(result.manifest.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    sealed = ""
    if args.ledger:
        ledger = EvidenceLedger(args.ledger)
        evidence = record_manifest(ledger, result.manifest)
        sealed = f"{evidence.content_hash[:16]} as entry {len(ledger)}"

    if args.json:
        payload = result.to_dict()
        payload["sealed"] = sealed
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(result.summary())
        if args.out:
            print(f"\n  manifest written to {args.out}")
        if sealed:
            print(f"  sealed {sealed}")
        if not result.complete:
            print("\n  This collection is INCOMPLETE. The missing items are absent "
                  "from the manifest, so nothing derived from it says anything "
                  "about them.")
    return 0 if result.complete else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "check-plan": _cmd_check_plan,
        "probe": _cmd_probe,
        "run": _cmd_run,
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
