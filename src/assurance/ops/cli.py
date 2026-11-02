"""``assurance ops``: run the unattended pipeline steps as one auditable cycle.

    cycle   one cycle: intel refresh (only if config live AND --live), watch run, chain verify,
            attest anchor-all (only if a key path is configured), backup + restore_check verify
    status  the last cycle, its age and the human actions it left (stale -> exit 2)
    check   a PREFLIGHT of the config and host (writes nothing; lists what it does not check)
    notify-test  show (dry) or, with --live, send one clearly labelled TEST webhook to a target

Exit codes. ``cycle``: 0 every step ok or skipped; 1 something is FLAGGED for a person (findings
are not failures); 2 anything degraded or failed, or the cycle could not start (bad config,
another cycle running). ``status``: 0 last cycle ok and fresh; 1 last cycle flagged; 2 stale, no
record, or last cycle degraded. ``check``: 0 usable; 1 a check failed; 2 config unusable.
A failed notification (config ``notify``) is reported in the record and in ``status`` and never
changes the cycle's exit code.
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

    n = verbs.add_parser("notify-test", help="dry-run (default) or --live send of a TEST webhook")
    n.add_argument("--config", required=True, type=Path)
    n.add_argument("--target", required=True, help="the notify[].name to test")
    n.add_argument("--live", action="store_true",
                   help="really POST the test payload (otherwise print what would be sent)")
    n.add_argument("--json", action="store_true")
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
    notes = doc.get("notifications")
    if notes:
        print(f"\n  NOTIFICATIONS ({len(notes)}):")
        for n in notes:
            print("    - " + _note_line(n))
    print("\n  " + doc["not_established"])


def _note_line(n: dict) -> str:
    bits = [f"{neutralise(n.get('target', '?'))}: {n.get('status')}"]
    if n.get("http_status"):
        bits.append(f"http {n['http_status']}")
    if n.get("error_class"):
        bits.append(neutralise(n["error_class"]))
    if n.get("reason"):
        bits.append(neutralise(n["reason"]))
    bits.append(f"attempt {n.get('attempts', 0)}")
    if n.get("retry"):
        bits.append(f"retry of {neutralise(n.get('cycle_id', ''))}")
    if n.get("abandoned"):
        bits.append("ABANDONED")
    return ", ".join(bits)


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
            for t in cfg.notify:
                print(f"  [notify  ] {t.name}: would be told on {'/'.join(t.on)} (host "
                      f"{t.allow_host}); nothing is sent in a dry run")
        return 0
    fd = _lock(cfg.lock)
    if fd is None:
        print("error: cycle already running (the lock is held). Nothing was run and nothing "
              "was written.", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    try:
        doc = run_cycle(cfg, live=args.live)
        _notify(cfg, doc)
        rec.append(cfg.record, doc)
    finally:
        os.close(fd)
    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        _print_record(doc)
    return int(doc["exit_code"])


def _notify(cfg: OpsConfig, doc: dict) -> None:
    """Tell the configured people (and retry what is owed). Adds ``notifications`` to ``doc``.

    Whatever happens here, ``doc['status']`` and ``doc['exit_code']`` are not touched: a failed
    notification is reported, it does not change or hide the cycle result.
    """
    if not cfg.notify and not cfg.outbox.exists():
        return
    from assurance.ops import notify

    try:
        entries = notify.deliver(cfg, doc)
    except Exception as exc:  # noqa: BLE001 - never let the messenger break the record
        entries = [{"target": "*", "cycle_id": "", "status": "failed", "http_status": None,
                    "attempts": 0, "delivery_id": None, "error_class": type(exc).__name__,
                    "retry": False}]
    if cfg.notify or entries:
        doc["notifications"] = entries


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
    from assurance.ops import notify

    box = notify.outbox_state(cfg)
    last_notes = [n for n in (got.cycles[-1].get("notifications") or [])
                  if isinstance(n, dict)] if got.cycles else []
    report["notifications"] = {
        "configured": [t.name for t in cfg.notify],
        "last_cycle_failures": [n for n in last_notes if n.get("status") == "failed"],
        "last_cycle_skipped": [n for n in last_notes if n.get("status") == "skipped"],
        "retry_pending": box["open"], "abandoned": box["abandoned"],
        "note": "A notification failure never changes this exit code. Delivery to a webhook "
                "is not acknowledgement by a person."}
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
    nf = report["notifications"]
    if nf["last_cycle_failures"] or nf["retry_pending"] or nf["abandoned"] \
            or nf["last_cycle_skipped"]:
        print("\n  NOTIFICATIONS (nobody may have been told):")
        for n in nf["last_cycle_failures"] + nf["last_cycle_skipped"]:
            print("    - last cycle: " + _note_line(n))
        for o in nf["retry_pending"]:
            print(f"    - owed, retried next cycle: {neutralise(o['target'])} for "
                  f"{neutralise(o['cycle_id'])} ({o['attempts']}/{notify.MAX_ATTEMPTS} "
                  f"attempts, {neutralise(o.get('error_class') or o.get('http_status') or '?')})")
        for o in nf["abandoned"]:
            print(f"    - ABANDONED after {o['attempts']} attempts: {neutralise(o['target'])} "
                  f"for {neutralise(o['cycle_id'])}: no one was told by this path")
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


def _cmd_notify_test(args: argparse.Namespace) -> int:
    from assurance.ops import notify

    cfg = load_config(args.config)
    target = next((t for t in cfg.notify if t.name == args.target), None)
    if target is None:
        known = ", ".join(t.name for t in cfg.notify) or "none configured"
        print(f"error: no notify target with that name (configured: {known}). Nothing was "
              "sent.", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    if not args.live:
        shown = notify.dry_run_request(cfg, target)
        if args.json:
            print(json.dumps({"dry_run": True, **shown}, indent=2, sort_keys=True))
        else:
            print(f"{cfg.ops_id} - DRY RUN: nothing was sent. A live test would be:")
            print(f"  POST to host {shown['host']}")
            for h in shown["headers"]:
                print(f"  {neutralise(h)}")
            print(f"  body: {shown['body']}")
            print(f"  secret_env set: {shown['secret_env_set']}; headers_env set: "
                  f"{shown['headers_env_set']}")
            print("  Add --live to send it.")
        return 0
    out = notify.send_test(cfg, target)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"{cfg.ops_id} - TEST to {target.name}: {out['status']}" + (
            f" ({out['reason']})" if out.get("reason") else "") + (
            f", http {out['http_status']}" if out.get("http_status") else "") + (
            f", {out['error_class']}" if out.get("error_class") else ""))
        print("  A delivered test shows the receiver answered 2xx. It does not show that anyone "
              "reads it.")
    return {"delivered": 0, "failed": 1}.get(out["status"], EXIT_COULD_NOT_RUN)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"cycle": _cmd_cycle, "status": _cmd_status,
                "check": _cmd_check,
                "notify-test": _cmd_notify_test}[args.command](args)
    except (AssuranceError, OSError, ValueError) as exc:
        # A config the loader refused, or a file it could not use: "could not run" (2), with no
        # side effect (the loader runs before the lock, the clock or any write).
        print(f"error: {neutralise(exc)}", file=sys.stderr)
        return EXIT_COULD_NOT_RUN


if __name__ == "__main__":
    raise SystemExit(main())
