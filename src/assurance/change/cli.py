"""``assurance change`` — the Active Assurance Cases queue, from the command line.

    assess-drift      turn a manifest divergence into a case (or update one)
    assess-advisory    turn a fleet impact report into a case (or update one)
    assess-intervention  did a recorded intervention invalidate evidence? open a case
    list               the queue: every open case, what it needs, who owns it
    show               one case, in full — the detail page
    claim              take ownership; OPEN -> IN_REVIEW
    advance            move to the next stop the case's own required work names
    reverify           supply fresh verification evidence; may reach READY_TO_CLOSE
    resolve-decision   a named person answers one of a case's open questions
    waive-reverification  a named person closes one entry without evidence, on the record
    decide             the human decision: close, reject, or defer
    resume             a named person takes a deferred case back up
    replay             rebuild a case from the ledger alone and check every step
    export             write the case's verifiable evidence bundle (check it with
                       ``assurance evidence verify``)

A person is someone named with ``--actor``; a command with no ``--actor`` runs
as automation, and automation can claim, advance and reverify but cannot
decide, resume or resolve. ``assurance watch run`` already opens and updates
cases itself; these commands are for the people who work them.

Exit codes: 0 fine, 1 a case needs attention (list/show only) or a transition
was refused, 2 the command could not run — which includes a case id the ledger
does not hold, on every verb (the HTTP API answers 404 for the same id), and
3 a re-verification was recorded but cleared nothing (``reverify`` only): the
submission is evidence and is sealed, the case still awaits re-verification, and
the printed ``blocked:`` reason says why. 3 is the code ``assurance evidence
verify`` uses for "nothing wrong was found, but something asked for is not
established", so a script reading ``$?`` cannot take an uncleared case for a
cleared one. Otherwise the same convention every other domain in this CLI uses.

``list`` prints the work queue — open cases, and a count of deferred ones — and
exits 1 while any case is open. ``list --json`` prints the document
``GET /v1/change/cases`` returns (``cases`` and ``summary``), every case or those
with ``--status``.

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

from assurance.change.model import CaseStatus, queue_summary
from assurance.change.replay import reconstruct_case
from assurance.change.service import (
    CaseNotFoundError,
    CaseTransitionError,
    advance,
    assess_advisory,
    assess_drift,
    assess_recorded_intervention,
    blocked_reason,
    claim,
    decide,
    resolve_decision,
    resume,
    reverify,
    waive_reverification,
)
from assurance.change.store import CASE_KINDS, CaseConflictError, CaseStore, ChainBrokenError
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

__all__ = ["EXIT_NOT_CLEARED", "build_parser", "main"]

#: ``reverify`` sealed the submission and the case still has required entries.
EXIT_NOT_CLEARED = 3


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

    ai = verbs.add_parser("assess-intervention",
                          help="did a recorded intervention invalidate evidence?")
    ledger_arg(ai)
    ai.add_argument("--manifest", required=True, type=Path,
                    help="the machine's current manifest, JSON")
    ai.add_argument("--intervention-id", required=True,
                    help="an intervention already sealed in the ledger")
    ai.add_argument("--actor", default="")

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

    rd = verbs.add_parser("resolve-decision",
                          help="answer one of a case's open human decisions")
    ledger_arg(rd)
    rd.add_argument("case_id")
    rd.add_argument("--number", required=True, type=int,
                    help="which open decision, counting from 1 as `show` lists them")
    rd.add_argument("--resolution", required=True)
    rd.add_argument("--actor", default="")

    wv = verbs.add_parser("waive-reverification",
                          help="close one re-verification entry WITHOUT evidence (a person, with a reason)")
    ledger_arg(wv)
    wv.add_argument("case_id")
    wv.add_argument("--entry", required=True,
                    help="the entry as `show` lists it (machine/function for an advisory case)")
    wv.add_argument("--reason", required=True)
    wv.add_argument("--actor", default="")

    rs = verbs.add_parser("resume", help="DEFERRED -> IN_REVIEW; a person, with a reason")
    ledger_arg(rs)
    rs.add_argument("case_id")
    rs.add_argument("--reason", required=True)
    rs.add_argument("--actor", default="")

    rp = verbs.add_parser("replay",
                          help="rebuild a case from the ledger alone and check each step")
    ledger_arg(rp)
    rp.add_argument("case_id")
    rp.add_argument("--json", action="store_true")

    ex = verbs.add_parser("export",
                          help="write one case's verifiable evidence bundle")
    ledger_arg(ex)
    ex.add_argument("case_id")
    ex.add_argument("--out", type=Path, default=None,
                    help="write the bundle here (default: print it)")
    ex.add_argument("--attestations", type=Path, default=None, metavar="LOG",
                    help="embed a signed head attestation from this log "
                         "(`assurance attest sign`) as the bundle's anchor, so a "
                         "verifier with the signer's public key can show nothing "
                         "was removed up to it. The newest one the signer READ from "
                         "a ledger is used; a head only DECLARED by a holder is used "
                         "when there is nothing else, and is labelled as declared. "
                         "Refuses if it contradicts the ledger.")
    ex.add_argument("--skeleton", action="store_true",
                    help="also list the id, kind and time of every OTHER entry in the "
                         "ledger (no evidence), so a verifier can see a removed entry "
                         "and check completeness. Off by default: it tells whoever "
                         "receives the file what else the ledger holds.")

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


def _cmd_assess_intervention(args: argparse.Namespace) -> int:
    manifest = _manifest(args.manifest)
    chosen, case = assess_recorded_intervention(
        _store(args.ledger), manifest, args.intervention_id,
        actor=_actor(args.actor, "watch"))
    if case is None:
        print(f"{chosen.intervention_id} invalidated no verified function: "
              "no case opened.")
        return 0
    print(f"case {case.case_id}  [{case.status.value.upper()}]  "
          f"{len(case.affected_functions)} function(s) affected")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    status = CaseStatus(args.status) if args.status else None
    store = _store(args.ledger)
    store.require_intact()
    cases = store.list(status=status)
    summary = queue_summary(cases)
    open_cases = [c for c in cases if c.is_open]
    if args.json:
        # The document GET /v1/change/cases returns.
        print(json.dumps({"cases": [c.row() for c in cases], "summary": summary}, indent=2))
        return 1 if open_cases else 0

    print(f"{summary['open']} open  {summary['safety_relevant']} safety-relevant  "
          f"{summary['awaiting_reverification']} awaiting re-verification  "
          f"{summary['degraded']} degraded  {summary['ready_to_close']} ready for human "
          f"closure  {summary['deferred']} deferred (not closed)")
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
    store = _store(args.ledger)
    store.require_intact()
    case = store.get(args.case_id)
    if case is None:
        raise CaseNotFoundError(args.case_id)
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
        reason = blocked_reason(case)
        if reason is not None:
            print(f"  blocked: {reason['code']}")
            print(f"  {reason['message']}")
    # Accepted and sealed, but the case still waits: not success. See the module
    # docstring for why this is 3 and not the 1 of a refused transition.
    return EXIT_NOT_CLEARED if case.required_reverifications else 0


def _cmd_resolve_decision(args: argparse.Namespace) -> int:
    store = _store(args.ledger)
    case = store.get(args.case_id)
    if case is None:
        raise CaseNotFoundError(args.case_id)
    if not 1 <= args.number <= len(case.human_decisions_required):
        raise CaseTransitionError(
            f"{args.case_id} has {len(case.human_decisions_required)} open human "
            f"decision(s); --number {args.number} is not one of them.")
    updated = resolve_decision(
        store, args.case_id, decision=case.human_decisions_required[args.number - 1],
        resolution=args.resolution, actor=_actor(args.actor, "reviewer"))
    print(f"{updated.case_id}: {len(updated.human_decisions_required)} decision(s) still open")
    return 0


def _cmd_waive(args: argparse.Namespace) -> int:
    case = waive_reverification(_store(args.ledger), args.case_id, entry=args.entry,
                                reason=args.reason, actor=_actor(args.actor, "reviewer"))
    print(f"{case.case_id}: {len(case.required_reverifications)} re-verification(s) still outstanding")
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    case = resume(_store(args.ledger), args.case_id, reason=args.reason,
                  actor=_actor(args.actor, "reviewer"))
    print(f"{case.case_id}: {case.status.value}, owner {case.owner}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    replay = reconstruct_case(EvidenceLedger.open_existing(args.ledger), args.case_id)
    if replay.entries == 0:
        raise CaseNotFoundError(args.case_id)
    if args.json:
        print(json.dumps(replay.to_dict(), indent=2))
    else:
        print(replay.summary())
    return 0 if replay.ok else 1


def _cmd_export(args: argparse.Namespace) -> int:
    # The ledger refuses to export a chain that does not verify (a
    # LedgerIntegrityError, an AssuranceError: exit 2, nothing written).
    anchor = None
    if args.attestations:
        # Signing needs the Ed25519 dependency; exporting without an anchor does not.
        from assurance.attest.attestation import AttestationLog
        anchor = AttestationLog(args.attestations).require_anchor().to_dict()
    bundle = EvidenceLedger.open_existing(args.ledger).export(
        subject=args.case_id, anchor=anchor, skeleton=args.skeleton)
    if not any(e["kind"] in CASE_KINDS for e in bundle["entries"]):
        raise CaseNotFoundError(args.case_id)
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"exported {len(bundle['entries'])} record(s) of {args.case_id} to {args.out}")
        if anchor:
            from assurance.attest.attestation import describe_anchor
            print(f"  {describe_anchor(anchor)}")
            print(f"  check it, offline: assurance evidence verify {args.out} "
                  "--public-key <signer.pub>")
        else:
            print(f"  check it anywhere, offline: assurance evidence verify {args.out}")
            print("  not anchored: nothing in this file shows nothing was removed. "
                  "Export with --attestations <log> and verify with --public-key.")
        if not args.skeleton:
            print("  no skeleton: a removed entry of this case cannot be seen and "
                  "completeness cannot be checked. --skeleton adds one, and tells "
                  "whoever receives the file the id, kind and time of every other "
                  "entry in the ledger.")
    else:
        print(text)
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
        "assess-intervention": _cmd_assess_intervention,
        "list": _cmd_list, "show": _cmd_show, "claim": _cmd_claim,
        "advance": _cmd_advance, "reverify": _cmd_reverify, "decide": _cmd_decide,
        "resolve-decision": _cmd_resolve_decision, "resume": _cmd_resume,
        "waive-reverification": _cmd_waive,
        "replay": _cmd_replay, "export": _cmd_export,
    }
    try:
        return handlers[args.command](args)
    except CaseNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ChainBrokenError as exc:
        # First and loud, and nothing is printed to stdout: a pipe that reads the
        # queue gets an empty queue and a non-zero exit, never a stale one.
        print(f"THE LEDGER CHAIN DOES NOT VERIFY — {exc}", file=sys.stderr)
        return 2
    except (CaseTransitionError, CaseConflictError) as exc:
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
