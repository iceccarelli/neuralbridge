"""``assurance ops``: run the unattended pipeline steps as one auditable cycle.

    cycle   one cycle: intel refresh (only if config live AND --live), watch run, chain verify,
            attest anchor-all (only if a key path is configured), backup + restore_check verify
    status  the last cycle, its age and the human actions it left (stale -> exit 2)
    check   a PREFLIGHT of the config and host (writes nothing; lists what it does not check)

Exit codes. ``cycle``: 0 every step ok or skipped; 1 something is FLAGGED for a person (findings
are not failures); 2 anything degraded or failed, or the cycle could not start (bad config,
another cycle running). ``status``: 0 last cycle ok and fresh; 1 last cycle flagged; 2 stale, no
record, or last cycle degraded. ``check``: 0 usable; 1 a check failed; 2 config unusable.
This tool schedules and installs nothing; a timer calls it. Software here drafts and reports;
opening a case, awareness and closure remain a named person's acts.
"""

# ruff: noqa: T201 - a command line writes to stdout
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.core.text import neutralise
from assurance.ops import record as rec
from assurance.ops.check import run_check
from assurance.ops.config import OpsConfig, load_config

__all__ = ["build_parser", "main"]

EXIT_COULD_NOT_RUN = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance ops", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                allow_abbrev=False)
    verbs = p.add_subparsers(dest="command", required=True)

    c = verbs.add_parser("cycle", help="run one cycle and append its record")
    c.add_argument("--config", required=True, type=Path)
    c.add_argument("--live", action="store_true",
                   help="allow the intel refresh to use the network (also needs 'live': true "
                        "in the config); without it the refresh is skipped as 'not refreshed'")
    c.add_argument("--dry-run", action="store_true",
                   help="print the plan; run nothing, take no lock, write nothing")
    c.add_argument("--json", action="store_true", help="print the cycle record as JSON")

    s = verbs.add_parser("status", help="last cycle, age, outstanding human actions")
    s.add_argument("--config", required=True, type=Path)
    s.add_argument("--json", action="store_true")

    k = verbs.add_parser("check", help="preflight the config and host (writes nothing)")
    k.add_argument("--config", required=True, type=Path)
    k.add_argument("--json", action="store_true")
    return p


# --------------------------------------------------------------------------------------------
def _print_record(doc: dict) -> None:
    print(f"{doc['ops_id']} - cycle {doc['status'].upper()} "
          f"({doc['started_at']} -> {doc['finished_at']}, {doc['duration_s']}s)")
    for s in doc["steps"]:
        code = "-" if s["exit_code"] is None else str(s["exit_code"])
        print(f"  [{s['status']:<8}] {s['name']:<34} exit {code:>2}  {neutralise(s['detail'])}")
    actions = doc.get("human_actions", [])
    if actions:
        print(f"\n  HUMAN ACTIONS REQUIRED ({len(actions)}):")
        for a in actions:
            print(f"    - [{a['step']}] {neutralise(a['action'])}")
    print("\n  " + doc["not_established"])


def _lock(path: Path):
    """An exclusive, non-blocking flock held for the life of the returned file object."""
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _cmd_cycle(args: argparse.Namespace) -> int:
    from assurance.ops.cycle import plan, run_cycle

    cfg = load_config(args.config)
    if os.name != "posix":
        print("error: the cycle lock uses flock and needs a POSIX host. Nothing was run.",
              file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    if args.dry_run:
        steps = plan(cfg, live=args.live)
        if args.json:
            print(json.dumps({"dry_run": True, "ops_id": cfg.ops_id, "steps": steps},
                             indent=2, sort_keys=True))
        else:
            print(f"{cfg.ops_id} - DRY RUN: nothing was run, locked or written")
            for s in steps:
                print(f"  [{s['status']:<8}] {s['name']:<34} {neutralise(s['detail'])}")
                print(f"             {neutralise(s['command'])}")
        return 0
    fd = _lock(cfg.lock)
    if fd is None:
        print("error: cycle already running (the lock is held). Nothing was run and nothing "
              "was written.", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    try:
        doc = run_cycle(cfg, live=args.live)
        rec.append(cfg.record, doc)
    finally:
        os.close(fd)
    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        _print_record(doc)
    return int(doc["exit_code"])


def _actions_by_recency(cycles: list[dict]) -> tuple[list[dict], list[dict]]:
    """``(this cycle's actions, earlier ones not re-raised)``; earlier looks back 30 cycles."""
    last = cycles[-1]
    now = last.get("human_actions", []) if isinstance(last.get("human_actions"), list) else []
    seen = {(a.get("step"), a.get("ref")) for a in now if isinstance(a, dict)}
    earlier: list[dict] = []
    for c in reversed(cycles[-31:-1]):
        for a in c.get("human_actions", []) if isinstance(c.get("human_actions"), list) else []:
            if isinstance(a, dict) and (a.get("step"), a.get("ref")) not in seen:
                seen.add((a.get("step"), a.get("ref")))
                earlier.append({**a, "raised_at": c.get("finished_at", "")})
    return [a for a in now if isinstance(a, dict)], earlier


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    got = rec.read(cfg.record)
    now = utc_now()
    report: dict = {"ops_id": cfg.ops_id, "record": str(cfg.record), "now": format_utc(now),
                    "cycles_recorded": len(got.cycles), "unreadable_lines": got.unreadable_lines,
                    "max_cycle_age_hours": cfg.max_cycle_age_hours}
    if not got.cycles:
        report.update(state="no_record", exit_code=2, last_cycle=None, age_hours=None,
                      actions={"this_cycle": [], "earlier_not_reraised": []})
    else:
        last = got.cycles[-1]
        age = (now - parse_utc(last["finished_at"])) / timedelta(hours=1)
        stale = age > cfg.max_cycle_age_hours
        code = 2 if stale or last["status"] == "degraded" else (
            1 if last["status"] == "flagged" else 0)
        this, earlier = _actions_by_recency(got.cycles)
        report.update(
            state="stale" if stale else last["status"], exit_code=code,
            age_hours=round(age, 2), last_cycle={
                k: last.get(k) for k in ("started_at", "finished_at", "status", "exit_code",
                                         "live_requested")} | {
                "steps": [{k: s.get(k) for k in ("name", "status", "exit_code", "detail")}
                          for s in last.get("steps", []) if isinstance(s, dict)]},
            actions={"this_cycle": this, "earlier_not_reraised": earlier})
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return int(report["exit_code"])
    if report["state"] == "no_record":
        print(f"{cfg.ops_id} - NO CYCLE RECORDED at {cfg.record} (a cycle that never ran is "
              "not a healthy one)")
    else:
        last = report["last_cycle"]
        print(f"{cfg.ops_id} - last cycle {last['status'].upper()} finished "
              f"{last['finished_at']} ({report['age_hours']}h ago; stale after "
              f"{cfg.max_cycle_age_hours:g}h)")
        if report["state"] == "stale":
            print("  STALE: no cycle has finished within the allowed age. A timer that stopped "
                  "looks exactly like a quiet fleet.")
        for s in last["steps"]:
            print(f"  [{s['status']:<8}] {s['name']:<34} {neutralise(s['detail'])}")
        a = report["actions"]
        print(f"\n  human actions raised by the last cycle: {len(a['this_cycle'])}")
        for x in a["this_cycle"]:
            print(f"    - [{x.get('step')}] {neutralise(x.get('action', ''))}")
        if a["earlier_not_reraised"]:
            print(f"  raised by earlier cycles and not raised again: "
                  f"{len(a['earlier_not_reraised'])} (this record cannot show whether a person "
                  "handled them)")
            for x in a["earlier_not_reraised"]:
                print(f"    - {x.get('raised_at')} [{x.get('step')}] "
                      f"{neutralise(x.get('action', ''))}")
    if got.unreadable_lines:
        print(f"  note: {len(got.unreadable_lines)} unreadable line(s) in the record, at line "
              f"{', '.join(map(str, got.unreadable_lines[:10]))}; they were ignored.")
    print("  This record is an unsigned operator log; it does not establish that the data are "
          "sound.")
    return int(report["exit_code"])


def _cmd_check(args: argparse.Namespace) -> int:
    cfg: OpsConfig = load_config(args.config)
    report = run_check(cfg)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"{cfg.ops_id} - preflight {'OK' if report['ok'] else 'FAILED'}")
        for c in report["checks"]:
            print(f"  [{c['status']:<4}] {c['name']}: {neutralise(c['detail'])}")
        print("\n  NOT checked:")
        for item in report["not_checked"]:
            print(f"    - {item}")
        print("\n  " + report["note"])
    return 0 if report["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"cycle": _cmd_cycle, "status": _cmd_status,
                "check": _cmd_check}[args.command](args)
    except (AssuranceError, OSError, ValueError) as exc:
        # A config the loader refused, or a file it could not use: "could not run" (2), with no
        # side effect (the loader runs before the lock, the clock or any write).
        print(f"error: {neutralise(exc)}", file=sys.stderr)
        return EXIT_COULD_NOT_RUN


if __name__ == "__main__":
    raise SystemExit(main())
