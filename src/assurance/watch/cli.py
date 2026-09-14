"""``assurance watch`` — keep looking, and say only what is new.

    run     one pass over every target: collect, compare, seal what moved
    status  what the last run found, without looking again

``run`` exits 0 when the fleet is quiet, 1 when something changed since the
last pass, and 2 when the watch could not see part of the fleet — because
"I could not look" and "nothing moved" must never share an exit code.

Put it on a timer:

    0 6 * * 1  assurance watch run watch.json --ledger register.db || mail -s ...
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.config import WatchConfig
from assurance.watch.runner import last_run, run_watch

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance watch",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    r = verbs.add_parser("run", help="one pass over every target")
    r.add_argument("config", type=Path)
    r.add_argument("--ledger", required=True, type=Path)
    r.add_argument("--dry-run", action="store_true",
                   help="look and report without sealing anything")
    r.add_argument("--out", type=Path, default=None)
    r.add_argument("--json", action="store_true")

    s = verbs.add_parser("status", help="what the last run found")
    s.add_argument("config", type=Path)
    s.add_argument("--ledger", required=True, type=Path)
    s.add_argument("--json", action="store_true")

    return p


def _exit_code(verdict: str) -> int:
    return {"quiet": 0, "findings": 1, "degraded": 2}[verdict]


def _cmd_run(args: argparse.Namespace) -> int:
    config = WatchConfig.from_json(args.config)
    ledger = EvidenceLedger(args.ledger)
    run = run_watch(config, ledger, seal=not args.dry_run)

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
                print(f"\n  ** STOP USE ** {finding.advisory_id} "
                      f"({finding.supplier_id}) — {finding.title}")
                print(f"       machines: {', '.join(finding.machines)}")
                if finding.remedy:
                    print(f"       remedy:   {finding.remedy}")
                if finding.reference:
                    print(f"       source:   {finding.reference}")
            for finding in adv.new:
                if finding.stops_use:
                    continue
                print(f"    new        {finding.advisory_id:<16} "
                      f"[{finding.impact}] {finding.title[:48]}")
                if finding.machines:
                    print(f"               {', '.join(finding.machines)}")
            for finding in adv.withdrawn:
                print(f"    WITHDRAWN  {finding.advisory_id:<16} "
                      f"{finding.title[:48]}")
                print(f"               reason: {finding.withdrawal_reason}")
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
    body = last_run(EvidenceLedger(args.ledger), config.watch_id)
    if body is None:
        print(f"{config.watch_id}: this watch has never run against this ledger.",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(body, indent=2, sort_keys=True))
    else:
        print(f"{config.watch_id} — last run {body.get('started_at')} — "
              f"{str(body.get('verdict', '')).upper()}")
        for o in body.get("outcomes", []):
            print(f"  {o.get('status', ''):<14} {o.get('serial', '')}  "
                  f"{o.get('detail', '')}")
        if body.get("stale_observations"):
            print("  not looked at recently enough: "
                  + ", ".join(body["stale_observations"]))
    return _exit_code(str(body.get("verdict", "degraded")))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"run": _cmd_run, "status": _cmd_status}
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
