"""``assurance change`` — the Active Assurance Cases queue, from the command line.

    assess-drift      turn a manifest divergence into a case (or update one)
    assess-advisory    turn a fleet impact report into a case (or update one)
    list               the queue: every open case, what it needs, who owns it
    show               one case, in full — the detail page
    claim              take ownership; OPEN -> IN_REVIEW
    advance            move to the next stop the case's own required work names
    reverify           supply fresh verification evidence; may reach READY_TO_CLOSE
    decide             the human decision: close, reject, or defer

Exit codes: 0 fine, 1 a case needs attention (list/show only), 2 the command
could not run — the same convention every other domain in this CLI uses.

Nothing here invents a fact. ``assess-drift`` and ``assess-advisory`` read the
exact objects :mod:`assurance.machinery.divergence` and
:mod:`assurance.fleet.impact` already produce; run those first (or use
``assurance machinery diff`` / ``assurance fleet advisory``) and feed their
JSON in here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.change.model import CaseStatus
from assurance.change.service import (
    CaseTransitionError,
    advance,
    assess_advisory,
    assess_drift,
    claim,
    decide,
    reverify,
)
from assurance.change.store import CaseStore
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.divergence import compare
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord

__all__ = ["build_parser", "main"]


def _actor(name: str, role: str) -> Actor:
    return Actor(identifier=name or "operator", role=role, kind="person" if name else "automation")


def _store(path: Path) -> CaseStore:
    return CaseStore(EvidenceLedger(path))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance change", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    verbs = p.add_subparsers(dest="command", required=True)

    def ledger_arg(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--ledger", required=True, type=Path)

    ad = verbs.add_parser("assess-drift", help="turn a manifest divergence into a case")
    ledger_arg(ad)
    ad.add_argument("--baseline", required=True, type=Path)
    ad.add_argument("--observed", required=True, type=Path)
    ad.add_argument("--actor", default="")

    aa = verbs.add_parser("assess-advisory", help="turn a fleet impact report into a case")
    ledger_arg(aa)
    aa.add_argument("--advisory", required=True, type=Path)
    aa.add_argument("--actor", default="")

    ls = verbs.add_parser("list", help="the Active Assurance Cases queue")
    ledger_arg(ls)
    ls.add_argument("--status", default="")
    ls.add_argument("--json", action="store_true")

    sh = verbs.add_parser("show", help="one case in full")
    ledger_arg(sh)
    sh.add_argument("case_id")
    sh.add_argument("--json", action="store_true")

    cl = verbs.add_parser("claim", help="OPEN -> IN_REVIEW")
    ledger_arg(cl)
    cl.add_argument("case_id")
    cl.add_argument("--owner", required=True)
    cl.add_argument("--actor", default="")

    av = verbs.add_parser("advance", help="move to the next required stop")
    ledger_arg(av)
    av.add_argument("case_id")
    av.add_argument("--actor", default="")

    rv = verbs.add_parser("reverify", help="supply fresh verification evidence")
    ledger_arg(rv)
    rv.add_argument("case_id")
    rv.add_argument("--manifest", required=True, type=Path,
                     help="the current manifest, JSON")
    rv.add_argument("--verification-hash", required=True,
                     help="content hash of the sealed verification bundle "
                          "already in the ledger")
    rv.add_argument("--actor", default="")

    dc = verbs.add_parser("decide", help="close, reject or defer")
    ledger_arg(dc)
    dc.add_argument("case_id")
    dc.add_argument("--disposition", required=True, choices=("closed", "rejected", "deferred"))
    dc.add_argument("--reason", required=True)
    dc.add_argument("--actor", default="")

    return p


def _manifest(path: Path) -> SafetyManifest:
    return SafetyManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _cmd_assess_drift(args: argparse.Namespace) -> int:
    baseline = _manifest(args.baseline)
    observed = _manifest(args.observed)
    ledger = EvidenceLedger(args.ledger)
    divergence = compare(baseline, observed)
    verifications = VerificationRecord.from_ledger(ledger, subject=observed.machine.key)
    interventions = interventions_from_ledger(ledger, observed.machine.key)
    case = assess_drift(_store(args.ledger), divergence, observed, verifications,
                        interventions, actor=_actor(args.actor, "watch"))
    if case is None:
        print(f"{divergence.verdict}: no safety-relevant change, no case opened.")
        return 0
    print(f"case {case.case_id}  [{case.status.value.upper()}]  "
          f"{len(case.affected_functions)} function(s) affected")
    return 0


def _cmd_assess_advisory(args: argparse.Namespace) -> int:
    from assurance.fleet.advisory import ComponentAdvisory

    raw = json.loads(args.advisory.read_text(encoding="utf-8"))
    if "advisory" in raw and "signature" in raw:
        raise AssuranceError(
            "this looks like a signed feed record, not a raw advisory. Verify "
            "it with `assurance supplier verify` first, then pass the "
            "`advisory` field's contents.")
    advisory = ComponentAdvisory.from_dict(raw)
    ledger = EvidenceLedger(args.ledger)
    fleet = Fleet.from_ledger(ledger)
    report = assess_impact(advisory, fleet)
    case = assess_advisory(_store(args.ledger), report, actor=_actor(args.actor, "fleet"))
    if case is None:
        print(f"{report.verdict}: this advisory touches no machine in this fleet.")
        return 0
    print(f"case {case.case_id}  [{case.status.value.upper()}]  "
          f"{len(case.machines)} machine(s) affected")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    status = CaseStatus(args.status) if args.status else None
    cases = _store(args.ledger).list(status=status)
    if args.json:
        print(json.dumps([c.to_dict() for c in cases], indent=2))
        return 1 if any(c.is_open for c in cases) else 0

    open_cases = [c for c in cases if c.is_open]
    safety = [c for c in open_cases if c.change_severity == "safety_relevant"]
    awaiting_reverif = [c for c in open_cases if c.status is CaseStatus.AWAITING_REVERIFICATION]
    degraded = [c for c in open_cases if not c.machines]
    ready = [c for c in open_cases if c.status is CaseStatus.READY_TO_CLOSE]
    print(f"{len(open_cases)} open  {len(safety)} safety-relevant  "
          f"{len(awaiting_reverif)} awaiting re-verification  "
          f"{len(degraded)} degraded  {len(ready)} ready for human closure")
    print()
    header = (f"{'CASE':<20} {'MACHINE':<22} {'STATUS':<24} {'OWNER':<16} "
             f"{'AGE':<5} NEXT ACTION")
    print(header)
    for c in sorted(open_cases, key=lambda c: (-c.age_days, c.case_id)):
        row = c.row()
        machine = row["machines"][0] if row["machines"] else "—"
        print(f"{c.case_id:<20} {machine:<22} {c.status.value:<24} "
              f"{c.owner or '—':<16} {row['age_days']:<5} {row['next_action']}")
    return 1 if open_cases else 0


def _cmd_show(args: argparse.Namespace) -> int:
    case = _store(args.ledger).get(args.case_id)
    if case is None:
        print(f"no case {args.case_id!r}.", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(case.to_dict(), indent=2))
    else:
        print(case.summary())
    return 1 if case.is_open else 0


def _cmd_claim(args: argparse.Namespace) -> int:
    case = claim(_store(args.ledger), args.case_id, owner=args.owner,
                actor=_actor(args.actor, "reviewer"))
    print(f"{case.case_id}: {case.status.value}, owner {case.owner}")
    return 0


def _cmd_advance(args: argparse.Namespace) -> int:
    case = advance(_store(args.ledger), args.case_id, actor=_actor(args.actor, "reviewer"))
    print(f"{case.case_id}: {case.status.value}")
    print(f"  {case.next_action()}")
    return 0


def _cmd_reverify(args: argparse.Namespace) -> int:
    manifest = _manifest(args.manifest)
    ledger = EvidenceLedger(args.ledger)
    verifications = VerificationRecord.from_ledger(ledger, subject=manifest.machine.key)
    interventions: list[Intervention] = interventions_from_ledger(ledger, manifest.machine.key)
    case = reverify(_store(args.ledger), args.case_id, manifest, verifications, interventions,
                    verification_content_hash=args.verification_hash,
                    actor=_actor(args.actor, "verification engineer"))
    print(f"{case.case_id}: {case.status.value}")
    if case.required_reverifications:
        print(f"  still outstanding: {', '.join(case.required_reverifications)}")
    return 0


def _cmd_decide(args: argparse.Namespace) -> int:
    case = decide(_store(args.ledger), args.case_id, disposition=args.disposition,
                 reason=args.reason, actor=_actor(args.actor, "reviewer"))
    print(f"{case.case_id}: {case.status.value} by {case.decision_by}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "assess-drift": _cmd_assess_drift, "assess-advisory": _cmd_assess_advisory,
        "list": _cmd_list, "show": _cmd_show, "claim": _cmd_claim,
        "advance": _cmd_advance, "reverify": _cmd_reverify, "decide": _cmd_decide,
    }
    try:
        return handlers[args.command](args)
    except CaseTransitionError as exc:
        print(f"finding: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
