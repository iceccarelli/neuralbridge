"""``assurance check`` — the Machine Assurance Check: what does this change mean for this machine?

    services       the service catalogue, machine-readable (GET /v1/check/services)
    machine        one manifest, one advisory, no ledger (POST /v1/check/machine)
    fleet-machine  an enrolled machine against its own ledger history, and the fleet
                   fan-out when an advisory is given (POST /v1/check/fleet-machine)

These call the same functions as the API routes and the MCP tools, and ``--json`` prints the
API's response body. Nothing here writes: no ledger is created (``fleet-machine`` opens one
that must already exist) and nothing is sealed. Inputs are JSON files, or ``-`` for standard
input (one of them).

Exit codes: 0 the check found nothing (``no_impact_found`` or ``verified``); 1 a finding (the
change matches, or the machine's evidence needs re-verification, is insufficient or needs a
person); 2 could not run or could not vouch (an unreadable input, a machine that is not
enrolled, a ledger whose chain does not verify and in which nothing was found); 3 INCOMPLETE,
not a pass (``cannot_determine``: the advisory is a partial translation or there is nothing to
read; ``verified_at_community``: every function is current but on evidence below
``validated``).

The free check cannot say whether standing safety evidence is still valid; the "not
established" list printed with every result says what else the answer does not cover.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from assurance.check.inputs import InputError, one_stdin, read_json_object
from assurance.check.pipeline import (
    AssuranceVerdict,
    CheckError,
    MachineAssuranceCheck,
    run_ad_hoc_check,
    run_enrolled_check,
)
from assurance.core.errors import AssuranceError
from assurance.core.text import neutralise
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory
from assurance.machinery.manifest import SafetyManifest

__all__ = ["build_parser", "exit_code_for", "main"]

_CLEAR = (AssuranceVerdict.NO_IMPACT_FOUND, AssuranceVerdict.VERIFIED)
_INCOMPLETE = (AssuranceVerdict.CANNOT_DETERMINE, AssuranceVerdict.VERIFIED_AT_COMMUNITY)


def exit_code_for(result: MachineAssuranceCheck) -> int:
    """0 clear, 3 incomplete (never a pass), 1 anything that needs action."""
    if result.incomplete and result.verdict in _CLEAR:
        return 3
    if result.verdict in _CLEAR:
        return 0
    if result.verdict in _INCOMPLETE:
        return 3
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance check", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    verbs = p.add_subparsers(dest="command", required=True)

    sv = verbs.add_parser("services", help="what can be executed for a machine right now")
    sv.add_argument("--json", action="store_true")

    mc = verbs.add_parser("machine", help="one manifest, one advisory, no ledger, no account")
    mc.add_argument("manifest", help="the machine's safety manifest as JSON, or - for stdin")
    mc.add_argument("--advisory", required=True,
                    help="the advisory or change being checked as JSON, or - for stdin")
    mc.add_argument("--json", action="store_true")

    fm = verbs.add_parser(
        "fleet-machine", help="an enrolled machine, against its own ledger history")
    fm.add_argument("--ledger", required=True, type=Path,
                    help="the ledger the machine is enrolled in; it must already exist")
    fm.add_argument("--machine-key", required=True,
                    help="the ledger subject, e.g. 'Grimaldi/AR-7#0412'")
    fm.add_argument("--advisory", default=None,
                    help="optional; when given, also fanned out across every other enrolled "
                         "machine. JSON, or - for stdin")
    fm.add_argument("--recorder-trust", type=Path, default=None,
                    help="your own recorder trust list. Without it the verification tier "
                         "sealed with each record is believed, as for the other offline "
                         "readers of your own ledger; the hosted API applies its server's "
                         "list, or none")
    fm.add_argument("--json", action="store_true")
    return p


def _manifest(doc: dict[str, Any]) -> SafetyManifest:
    try:
        return SafetyManifest.from_dict(doc)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise InputError(f"the manifest is not a valid safety manifest: {exc}") from exc


def _advisory(doc: dict[str, Any]) -> ComponentAdvisory:
    try:
        return ComponentAdvisory.from_dict(doc)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise InputError(f"the advisory is not a valid advisory: {exc}") from exc


def _print_json(doc: Any) -> None:
    print(json.dumps(doc, indent=2, sort_keys=True))


def _print_human(result: MachineAssuranceCheck) -> None:
    doc = result.to_dict()
    print(f"{neutralise(result.machine_key)}: {result.verdict.value}")
    cfg = doc["configuration"]
    print(f"  enrolled            {'yes' if result.enrolled else 'no (no ledger was read)'}")
    print(f"  advisory evaluated  {'yes' if result.advisory_evaluated else 'no'}")
    print(f"  configuration       {cfg['status']}")
    for m in result.matches:
        flag = "  (needs a person)" if m.get("needs_a_human") else ""
        print(f"  match {neutralise(m['item_id'])} {neutralise(m['item_name'])} "
              f"{neutralise(m['item_version'])}: {m['basis']}{flag}")
    ev = doc["evidence"]
    if result.enrolled:
        print(f"  evidence            valid {ev['valid']}, valid below validated "
              f"{ev['valid_below_validated']}, stale {ev['stale']}, insufficient "
              f"{ev['insufficient']}, cannot determine {ev['cannot_determine']}")
        for function_id in result.required_actions:
            print(f"  re-verify           {neutralise(function_id)}")
    if doc["fleet"]:
        print(f"  fleet               {doc['fleet']['machines_affected']} of "
              f"{doc['fleet']['machines_analyzed']} enrolled machine(s) affected")
    if result.human_review_required:
        print("  a person must review this: a match rests on a label that contradicts the "
              "artefact, or a basis that cannot settle it.")
    nxt = doc["commercial_next_action"]
    print(f"  next                {nxt['action']}" + (f" ({nxt['endpoint']})"
                                                       if nxt["endpoint"] else ""))
    print("\n  not established:")
    for skipped in result.checks_skipped:
        print(f"    - {neutralise(skipped)}")
    if result.verdict not in _CLEAR:
        return
    print("\n  A clear result is not a statement that the machine is safe: it is the answer "
          "to the question above, from the inputs given.")


def _emit(result: MachineAssuranceCheck, as_json: bool) -> None:
    if as_json:
        _print_json(result.to_dict())
    else:
        _print_human(result)


def _cmd_services(args: argparse.Namespace) -> int:
    from assurance.check.services import service_catalogue

    catalogue = service_catalogue()
    if args.json:
        _print_json(catalogue)
        return 0
    print("verdicts (worst first): " + ", ".join(catalogue["verdicts"]))
    for svc in catalogue["services"]:
        plan = svc["required_plan"] or "no plan"
        print(f"\n{svc['service_id']}  ({svc['free_or_paid']}, {plan}, {svc['price']})")
        print(f"  {svc['human_name']}: {svc['description']}")
        print(f"  endpoint        {svc['endpoint']}")
        print(f"  evidence output {svc['evidence_output']}")
    print("\n  Offline, the same checks are `assurance check machine` and "
          "`assurance check fleet-machine`.")
    return 0


def _cmd_machine(args: argparse.Namespace) -> int:
    one_stdin(manifest=args.manifest, advisory=args.advisory)
    manifest = _manifest(read_json_object(args.manifest, "manifest"))
    advisory = _advisory(read_json_object(args.advisory, "advisory"))
    result = run_ad_hoc_check(manifest, advisory)
    _emit(result, args.json)
    return exit_code_for(result)


def _cmd_fleet_machine(args: argparse.Namespace) -> int:
    from assurance.machine.recorder_attestation import RecorderTrust

    advisory = (_advisory(read_json_object(args.advisory, "advisory"))
                if args.advisory is not None else None)
    trust = RecorderTrust.from_json(args.recorder_trust) if args.recorder_trust else None
    ledger = EvidenceLedger.open_existing(args.ledger)
    result = run_enrolled_check(ledger, args.machine_key, advisory, recorder_trust=trust)
    _emit(result, args.json)
    code = exit_code_for(result)
    if code != 1 and not ledger.verify_chain()[0]:
        # A broken chain can hide a record, never invent a match: a finding stands, but
        # nothing may be cleared (or called incomplete) from a store that does not verify.
        print("THE LEDGER CHAIN DOES NOT VERIFY: nothing here is cleared.", file=sys.stderr)
        return 2
    return code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"services": _cmd_services, "machine": _cmd_machine,
                "fleet-machine": _cmd_fleet_machine}
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {neutralise(exc)}", file=sys.stderr)
        return 2
    except (CheckError, AssuranceError, ValueError, OSError) as exc:
        print(f"error: {neutralise(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
