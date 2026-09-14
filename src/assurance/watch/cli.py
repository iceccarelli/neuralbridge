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
