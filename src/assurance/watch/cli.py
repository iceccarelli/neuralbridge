"""``assurance watch`` — keep looking, and say only what is new.

    run     one pass over every target: collect, compare, seal what moved
    status  what the last run found, without looking again
    push    OPT-IN: report the latest run to your own hosted ledger
    open-case  a NAMED PERSON opens a case from a public-intel finding (never decides)

``run`` and ``status`` never touch the network. ``push`` is the one command here
that can, only when you give it an explicit ``--api-url`` and the name of an
environment variable holding your key, and it lives in its own module
(``assurance.watch.push``) which nothing else imports. ``--dry-run`` shows
exactly what would be sent and sends nothing.

``run`` exits 0 when the fleet is quiet, 1 when something changed since the
last pass, and 2 when the watch could not see part of the fleet — because
"I could not look" and "nothing moved" must never share an exit code.

``--now ISO8601Z`` (on ``run`` and ``status``) sets the clock for ASSESSMENT ONLY:
staleness and age checks, and the run record's assessed-at. It is refused (exit 2)
unless ``run`` is also ``--dry-run``: a run that seals records must use the real clock,
or it could write forged history. ``open-case`` has no ``--now``: it writes a case.

Put it on a timer:

    0 6 * * 1  assurance watch run watch.json --ledger register.db || mail -s ...
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.core.text import neutralise
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.config import WatchConfig
from assurance.watch.intel_source import StoreAges, store_ages
from assurance.watch.runner import last_run, run_watch

__all__ = ["build_parser", "main"]


class _Parser(argparse.ArgumentParser):
    """An argument parser that never echoes a value back in an error.

    ``watch push`` takes the NAME of an environment variable, never a key. An
    operator who types ``--key asr_...`` anyway must be told no, not shown their
    key again in a terminal, a CI log or a screenshot: argparse's own errors
    quote the offending arguments, so they are replaced here.
    """

    def error(self, message: str) -> NoReturn:  # type: ignore[override]
        if message.startswith("unrecognized arguments"):
            message = ("unrecognized arguments (not echoed: `watch push` never "
                       "accepts a key on the command line; use --key-env NAME)")
        message = re.sub(r"(invalid .* value): .*$", r"\1", message)
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def _iso_z(text: str) -> datetime:
    """``--now``: an explicit UTC instant, ``YYYY-MM-DDTHH:MM:SSZ`` (a zone is never guessed)."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z", text or ""):
        raise argparse.ArgumentTypeError(
            "--now must be an ISO 8601 UTC instant ending in Z, e.g. 2026-11-01T06:30:00Z")
    try:
        return parse_utc(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--now is not a valid instant: {exc}") from None


_NOW_HELP = ("ISO 8601 UTC instant (e.g. 2026-11-01T06:30:00Z) used as the clock for "
             "ASSESSMENT ONLY (staleness / age checks and the assessed-at).")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="assurance watch",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    verbs = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    r = verbs.add_parser("run", help="one pass over every target")
    r.add_argument("config", type=Path)
    r.add_argument("--ledger", required=True, type=Path)
    r.add_argument("--dry-run", action="store_true",
                   help="look and report without sealing anything")
    r.add_argument("--out", type=Path, default=None)
    r.add_argument("--json", action="store_true")
    r.add_argument("--now", type=_iso_z, default=None, metavar="ISO8601Z",
                   help=_NOW_HELP + " REFUSED unless --dry-run is also given: a run that "
                        "seals records must use the real clock.")

    s = verbs.add_parser("status", help="what the last run found")
    s.add_argument("config", type=Path)
    s.add_argument("--ledger", required=True, type=Path)
    s.add_argument("--json", action="store_true")
    s.add_argument("--now", type=_iso_z, default=None, metavar="ISO8601Z",
                   help=_NOW_HELP + " Read-only: nothing is written.")

    h = verbs.add_parser(
        "push", allow_abbrev=False, help="OPT-IN: report the latest sealed run to your hosted ledger",
        description="Report what the latest sealed run saw to your own hosted "
                    "ledger. Sends the SafetyManifest, the observation status and "
                    "the run summary — never a raw file. Exit 0 reported, 1 "
                    "refused or partial, 2 could not run (safe to run again).")
    h.add_argument("config", type=Path)
    h.add_argument("--ledger", required=True, type=Path)
    h.add_argument("--api-url", required=True,
                   help="the hosted API base URL, e.g. https://api.example.com")
    h.add_argument("--key-env", required=True, metavar="ENVVAR",
                   help="NAME of the environment variable holding your API key "
                        "(the key is never accepted on the command line)")
    h.add_argument("--dry-run", action="store_true",
                   help="print exactly what would be sent; open no connection")
    h.add_argument("--timeout", type=float, default=30.0)
    h.add_argument("--retries", type=int, default=2,
                   help="retries after a timeout or 5xx (the report is idempotent)")
    h.add_argument("--retry-wait", type=float, default=1.0)
    h.add_argument("--max-body-bytes", type=int, default=900_000,
                   help="split the report into requests no larger than this")

    o = verbs.add_parser(
        "open-case", allow_abbrev=False,
        help="a named person opens a case from a public-intel finding",
        description="Re-derive an intel finding from the watch's local intel store and open "
                    "a case for it in the ledger, as a NAMED PERSON. Reads the store from "
                    "disk (no network). Refuses an automation/service/empty name, an id "
                    "that is not a current finding, and a CSAF-derived candidate without "
                    "--accept-unsigned and --reason. Never closes, decides or waives "
                    "anything. Exit 0 opened or already open, 1 refused (reason printed), "
                    "2 usage or I/O. Re-running writes nothing new.")
    o.add_argument("--config", required=True, type=Path)
    o.add_argument("--ledger", required=True, type=Path)
    o.add_argument("--advisory-id", required=True)
    o.add_argument("--actor", required=True, help="the person's name")
    o.add_argument("--role", required=True, help="the person's role, as free text")
    o.add_argument("--accept-unsigned", action="store_true",
                   help="a CSAF-derived candidate is unsigned: the person accepts that")
    o.add_argument("--reason", default="",
                   help="what you checked, against what (required with --accept-unsigned)")
    o.add_argument("--json", action="store_true")

    return p


def _exit_code(verdict: str) -> int:
    return {"quiet": 0, "findings": 1, "degraded": 2}[verdict]


def _cmd_run(args: argparse.Namespace) -> int:
    if args.now is not None and not args.dry_run:
        # Checked before anything is opened, so a refusal writes nothing at all.
        print("error: --now sets the assessment clock and is accepted only with --dry-run. "
              "A run that seals records must use the real clock; otherwise it could write "
              "history that never happened. Nothing was run and nothing was written.",
              file=sys.stderr)
        return 2
    config = WatchConfig.from_json(args.config)
    ledger = EvidenceLedger(args.ledger)
    run = run_watch(config, ledger, seal=not args.dry_run, now=args.now)

    if args.out:
        Path(args.out).write_text(
            json.dumps(run.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    if args.json:
        print(json.dumps(run.to_dict(), indent=2, sort_keys=True))
    else:
        print(run.summary())

        adv = run.advisories
        if adv.feeds:
            print(f"\n  suppliers: {adv.summary()}")
            # Stop-use first and alone. An advisory the supplier marked stop_use
            # against a machine that matched is not one line among forty; it is
            # the reason this ran.
            for finding in adv.stop_use:
                print(f"\n  ** STOP USE ** {neutralise(finding.advisory_id)} "
                      f"({neutralise(finding.supplier_id)}) — {neutralise(finding.title)}")
                print(f"       machines: {neutralise(', '.join(finding.machines))}")
                if finding.remedy:
                    print(f"       remedy:   {neutralise(finding.remedy)}")
                if finding.reference:
                    print(f"       source:   {neutralise(finding.reference)}")
            for finding in adv.new:
                if finding.stops_use:
                    continue
                print(f"    new        {neutralise(finding.advisory_id):<16} "
                      f"[{finding.impact}] {neutralise(finding.title[:48])}")
                if finding.machines:
                    print(f"               {neutralise(', '.join(finding.machines))}")
            for finding in adv.withdrawn:
                print(f"    WITHDRAWN  {neutralise(finding.advisory_id):<16} "
                      f"{neutralise(finding.title[:48])}")
                print(f"               reason: {neutralise(finding.withdrawal_reason)}")
                print("               You were told about this one. If somebody "
                      "changed a machine because")
                print("               of it, that change now rests on a "
                      "retracted advisory.")
            fil = run.filings
            if fil.enabled and fil.prompts:
                print(f"\n  Article 14: {fil.summary()}")
                # Escalations first. An advisory received and never assessed is
                # the finding; the draft is merely the help.
                for prompt in fil.escalating:
                    print(f"\n  ** UNASSESSED {prompt.hours_since_receipt:.0f}h ** "
                          f"{prompt.advisory_id}")
                    print("       Art. 14(2)(a) runs 24 hours from AWARENESS, not "
                          "from receipt — but")
                    print("       C(2026) 5252 Annex §214 requires the initial "
                          "assessment to be prompt,")
                    print(f"       and this has been outstanding since "
                          f"{prompt.received_at}.")
                    if prompt.draft:
                        print(f"       draft: {len(prompt.draft.machines)} machine(s), "
                              f"Member States "
                              f"{', '.join(prompt.draft.member_states) or '—'}")
                for prompt in fil.drafted:
                    draft = prompt.draft
                    print(f"    drafted    {prompt.advisory_id}  "
                          f"received {prompt.received_at}")
                    if draft is not None:
                        # Confirmed and unconfirmed are printed separately and
                        # always. "0 machines" on its own reads as "you are
                        # fine"; it usually means the supplier published no
                        # hashes, which is the opposite of fine.
                        print(f"               {len(draft.machines)} confirmed "
                              f"affected (matched by hash)")
                        if draft.machines_needing_a_human:
                            print(f"               {len(draft.machines_needing_a_human)}"
                                  " machine(s) in NEITHER column — a person has "
                                  "to look:")
                            for key in draft.machines_needing_a_human:
                                print(f"                 {key}")
                        print(f"               field 5: "
                              f"{', '.join(draft.member_states) or 'CANNOT BE COMPLETED'}")
                        if draft.machines_without_country:
                            print(f"               !! "
                                  f"{len(draft.machines_without_country)} affected "
                                  "machine(s) have no country recorded")
                        print("               still to be decided by a person:")
                        for decision in draft.decisions_required:
                            print(f"                 - {decision}")
                for prompt in fil.unassessed:
                    if prompt.is_escalating:
                        continue
                    print(f"    unassessed {prompt.advisory_id}  "
                          f"{prompt.hours_since_receipt:.1f}h since receipt")

            for feed in adv.degraded:
                print(f"    !! {feed.supplier_id}: {feed.status} — {feed.detail}")
                for problem in feed.problems:
                    print(f"       {problem}")

        if run.sealed:
            print(f"\n  sealed: {', '.join(run.sealed)}")
        elif not args.dry_run:
            print("\n  nothing sealed beyond the observations: nothing moved.")
        if args.dry_run:
            print("\n  DRY RUN — nothing was sealed, so the next real run will "
                  "report these same findings as new.")
        if run.checks_skipped:
            print("\n  not checked:")
            for c in run.checks_skipped:
                print(f"    - {c}")
    return _exit_code(run.verdict)


def _cmd_status(args: argparse.Namespace) -> int:
    config = WatchConfig.from_json(args.config)
    body = last_run(EvidenceLedger.open_existing(args.ledger), config.watch_id)
    if body is None:
        print(f"{config.watch_id}: this watch has never run against this ledger.",
              file=sys.stderr)
        return 2
    code = _exit_code(str(body.get("verdict", "degraded")))
    clock = args.now or utc_now()
    ages = [store_ages(sub, clock) for sub in config.intel]
    if any(not a.ok for a in ages):
        code = 2          # only ever ADDS the intel condition, and only when one is subscribed
    if args.json:
        doc = dict(body)
        if ages:
            doc["intel_staleness"] = {
                "assessed_at": format_utc(clock), "ok": all(a.ok for a in ages),
                "subscriptions": [a.to_dict() for a in ages]}
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        print(f"{config.watch_id} — last run {body.get('started_at')} — "
              f"{str(body.get('verdict', '')).upper()}")
        for o in body.get("outcomes", []):
            print(f"  {o.get('status', ''):<14} {o.get('serial', '')}  "
                  f"{o.get('detail', '')}")
        if body.get("stale_observations"):
            print("  not looked at recently enough: "
                  + ", ".join(body["stale_observations"]))
        for a in ages:
            _print_ages(a, clock)
    return code


def _print_ages(a: StoreAges, clock: datetime) -> None:
    print(f"  intel {neutralise(a.supplier_id)} — assessed at {format_utc(clock)}")
    if a.problem:
        print(f"    !! {a.problem_status}: {neutralise(a.problem)}")
        return
    if not a.checked:
        print("    age not checked (no max_age_hours is set on this subscription)")
        return
    for src in a.ages:
        if src.age_hours is not None and src.state in ("fresh", "stale"):
            age = f"{src.age_hours:.1f} h"
        else:
            age = "n/a"
        verdict = {"fresh": "fresh", "stale": "STALE", "never_observed": "NEVER OBSERVED",
                   "unreadable": "UNREADABLE (retrieval time)",
                   "future": "UNREADABLE (retrieved after the clock)"}[src.state]
        print(f"    {src.source:<5} newest accepted: {src.retrieved_at or 'none':<20} "
              f"age {age:>8} / limit {src.limit_hours:g} h — {verdict}")


def _cmd_open_case(args: argparse.Namespace) -> int:
    from assurance.change.service import CaseTransitionError
    from assurance.watch.open_case import (
        NEXT_STEPS,
        NOT_ESTABLISHED,
        OpenCaseRefusedError,
        open_case,
    )

    config = WatchConfig.from_json(args.config)
    ledger = EvidenceLedger.open_existing(args.ledger)
    try:
        res = open_case(config, ledger, args.advisory_id, actor_name=args.actor,
                        role=args.role, accept_unsigned=args.accept_unsigned,
                        reason=args.reason)
    except (OpenCaseRefusedError, CaseTransitionError) as exc:
        print(f"refused: {neutralise(str(exc))}", file=sys.stderr)
        return 1
    # A warning, not a refusal: a person may knowingly open a case from older data.
    for warning in res.intel_age_warnings:
        print(f"warning: {neutralise(warning)}", file=sys.stderr)
    if args.json:
        print(json.dumps({
            "case_id": res.case_id, "outcome": res.outcome, "status": res.status,
            "trust_state": res.trust_state, "recorded_trust": res.recorded_trust,
            "machines": list(res.machines), "accepted_by": res.accepted_by,
            "not_established": list(NOT_ESTABLISHED), "next_steps": list(NEXT_STEPS),
            "intel_age_warnings": list(res.intel_age_warnings)},
            indent=2, sort_keys=True))
        return 0
    verb = "opened" if res.outcome == "opened" else "already open (nothing written)"
    print(f"case {res.case_id}: {verb}, status {res.status}")
    print(f"  advisory:    {neutralise(args.advisory_id)}")
    print(f"  machines:    {neutralise(', '.join(res.machines))}")
    print(f"  accepted by: {neutralise(res.accepted_by)}")
    print(f"  trust state: {res.trust_state}"
          + (f" (case records: {neutralise(res.recorded_trust)})"
             if res.recorded_trust != res.trust_state else ""))
    print("  NOT established:")
    for line in NOT_ESTABLISHED:
        print(f"    - {line}")
    print("  next, by a person:")
    for line in NEXT_STEPS:
        print(f"    - {line.replace('CASE_ID', res.case_id).replace('LEDGER', str(args.ledger))}")
    return 0


def _cmd_push(args: argparse.Namespace) -> int:
    # Imported here and nowhere else: `watch run` and the kit never load it.
    from assurance.watch.push import main_push

    return main_push(args)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"run": _cmd_run, "status": _cmd_status, "push": _cmd_push,
                "open-case": _cmd_open_case}
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
