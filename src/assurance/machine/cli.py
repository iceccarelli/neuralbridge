"""``assurance machine`` — verify a run, seal a bundle, re-check somebody else's.

Three verbs, and the third is the one that sells the first two.

``separation``
    Print S(t0) term by term for a declared envelope at a given speed. This is
    the thirty-second demonstration: an integrator reads their own light-curtain
    distance off the wall and compares it to the number that comes out.

``verify``
    Compare a trace against an envelope and seal the result into the ledger.
    Exits non-zero on a violation, so it belongs in a commissioning pipeline.

``check``
    Re-verify a bundle somebody else produced. Exits non-zero if the bundle was
    edited, if its verdict disagrees with its own checks, or if re-running the
    engine on the named inputs does not reproduce it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle, verify_bundle
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.ssm import separation_required
from assurance.machine.trace import Trace
from assurance.machine.verify import Verdict

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance machine",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    sep = verbs.add_parser(
        "separation", help="print the protective separation distance, term by term")
    sep.add_argument("--envelope", required=True, type=Path)
    sep.add_argument("--speed", required=True, type=float,
                     help="TCP speed in mm/s")
    sep.add_argument("--human-speed", type=float, default=None,
                     help="closing speed in mm/s; omit to use the declared figure")
    sep.add_argument("--json", action="store_true")

    ver = verbs.add_parser("verify", help="verify a trace against an envelope")
    ver.add_argument("--envelope", required=True, type=Path)
    ver.add_argument("--trace", required=True, type=Path)
    ver.add_argument("--limits", type=Path, default=None,
                     help="body-region limits table for a power-and-force claim")
    ver.add_argument("--actor", required=True,
                     help="who is signing this verification, e.g. 'v.grimaldi'")
    ver.add_argument("--role", default="verification engineer")
    ver.add_argument("--ledger", type=Path, default=None,
                     help="append the sealed bundle to this evidence ledger")
    ver.add_argument("--out", type=Path, default=None, help="write the bundle here")
    ver.add_argument("--json", action="store_true")

    chk = verbs.add_parser("check", help="re-verify a bundle you did not produce")
    chk.add_argument("bundle", type=Path)
    chk.add_argument("--envelope", type=Path, default=None)
    chk.add_argument("--trace", type=Path, default=None)
    chk.add_argument("--json", action="store_true")

    return p


def _cmd_separation(args: argparse.Namespace) -> int:
    envelope = SafetyEnvelope.from_json(args.envelope)
    b = separation_required(envelope, robot_speed_mm_s=args.speed,
                            human_speed_mm_s=args.human_speed)
    if args.json:
        print(json.dumps(b.to_dict(), indent=2))
        return 0
    print(f"{envelope.product} {envelope.product_version}  "
          f"envelope {envelope.content_hash()[:12]}")
    print(f"  TCP speed          {args.speed:.0f} mm/s")
    print(f"  human closing      {b.human_speed_mm_s:.0f} mm/s ({b.human_speed_source})")
    print()
    print(f"  Sh human travel    {b.human_travel_mm:8.0f} mm")
    print(f"  Sr robot reaction  {b.robot_reaction_travel_mm:8.0f} mm")
    print(f"  Ss robot stopping  {b.robot_stopping_travel_mm:8.0f} mm  "
          f"({b.stopping_basis})")
    print(f"  C  intrusion       {b.intrusion_mm:8.0f} mm")
    print(f"  Zd human uncert.   {b.human_uncertainty_mm:8.0f} mm")
    print(f"  Zr robot uncert.   {b.robot_uncertainty_mm:8.0f} mm")
    print(f"  {'-' * 32}")
    print(f"  S  required        {b.total_mm:8.0f} mm")
    if b.rests_on_extrapolation:
        print()
        print("  Ss is extrapolated: this speed is above the one the stopping")
        print(f"  distance was measured at "
              f"({envelope.stop.measured_at_speed_mm_s:.0f} mm/s). The number above "
              "is a model.")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    envelope = SafetyEnvelope.from_json(args.envelope)
    trace = Trace.from_json(args.trace)
    limits = LimitsTable.from_json(args.limits) if args.limits else None
    ledger = EvidenceLedger(args.ledger) if args.ledger else None

    bundle = build_bundle(
        envelope, trace,
        actor=Actor(identifier=args.actor, role=args.role, kind="person"),
        limits=limits, ledger=ledger,
    )
    if args.out:
        bundle.write(args.out)

    if args.json:
        print(json.dumps(bundle.to_dict(), indent=2, sort_keys=True))
    else:
        print(bundle.summary())
        if bundle.result.checks_skipped:
            print("\n  not checked:")
            for c in bundle.result.checks_skipped:
                print(f"    - {c}")
        if args.out:
            print(f"\n  bundle written to {args.out}")
        if ledger:
            print(f"  sealed into {args.ledger} at entry {len(ledger)}")

    return 0 if bundle.verdict is Verdict.PASS else 1


def _cmd_check(args: argparse.Namespace) -> int:
    envelope = SafetyEnvelope.from_json(args.envelope) if args.envelope else None
    trace = Trace.from_json(args.trace) if args.trace else None
    ok, problems = verify_bundle(args.bundle, envelope=envelope, trace=trace)
    if args.json:
        print(json.dumps({"ok": ok, "problems": problems}, indent=2))
    else:
        print(f"{args.bundle}: {'OK' if ok else 'REJECTED'}")
        for p in problems:
            print(f"  - {p}")
        if ok and envelope is None:
            print("  Supply --envelope and --trace to check the claim, not just the seal.")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "separation": _cmd_separation,
        "verify": _cmd_verify,
        "check": _cmd_check,
    }
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except AssuranceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
