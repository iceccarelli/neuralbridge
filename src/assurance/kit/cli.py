"""``assurance kit`` — enrol a plant's machines without anything leaving it.

    init    write a runnable kit into a folder: config, plan skeleton, README
    run     collect every machine listed, offline, into your own ledger
    check   read a kit and say what it would do, touching nothing

The order is ``init`` once per site, then ``run`` whenever something might have
changed. ``check`` is for the person who has to approve this before it runs on
their network, and it is the first command they will ask for.

Exit codes are the interface:

    0  every machine enrolled, nothing tried to reach the network
    1  a finding — a machine incomplete, a required item missing, or a refused
       connection attempt. The run still produced evidence; read it.
    2  the kit could not run at all.

A refused connection attempt is a 1, not a 2, on purpose. The run is still
valid — nothing got out — but somebody needs to know which line tried.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from assurance.collect.plan import CollectionPlan
from assurance.core.errors import AssuranceError
from assurance.kit.enrol import (
    KitConfig,
    KitError,
    _is_placeholder,
    run_kit,
    starter_config,
)

__all__ = ["build_parser", "main"]

_README = """# Offline enrolment kit — {kit_id}

This folder records what safety-relevant software is on your machines, seals it
into an evidence ledger **that stays on this disk**, and produces a report you
can hand to an auditor, an insurer or a customer.

Nothing is uploaded. Nothing is registered. There is no account and no key.

## Before you run it

1. Open `kit.json` and put your company, site and name in it.
2. For each machine, make a folder under `exports/` named after its serial and
   drop that machine's vendor exports into it — the scanner zone file, the robot
   parameter export, the safety PLC project, the controller firmware. Whatever
   your tools produce. Do not rename them.
3. Open `plans/cell.json` and make the four `source` entries match the file
   names your tools actually produce. That file is the only thing you have to
   edit that needs any thought, and getting it wrong is visible: the run will
   say which items it could not find.

## Run it

    python -m assurance kit run kit.json --out out/

You get, in `out/`:

    report.html                  open this first
    evidence.db                  your ledger. Back it up like a drawing
    run.json                     machine-by-machine, what was recorded
    attestation-request.json     three numbers, if you ever want the head
                                 counter-signed by somebody who is not you

## Before you let it near anything

    python -m assurance kit check kit.json

`check` reads the configuration and prints what the run would touch, without
touching it. The run itself arms a guard over this process's socket layer and
refuses every outbound connection, recording any attempt with the line of code
that made it — and seals that record into your own ledger. So "it does not phone
home" is not a promise in a document; it is a hash in a file you hold.

The guard covers this Python process's socket calls. It does not cover a
subprocess (this kit spawns none), nor a C extension that opens a file
descriptor itself, and it records intent rather than enforcing containment.
Those four sentences are in the evidence record too, because a claim printed
next to its limits is worth more to a reviewer than a broader claim with none.

## What one run of this does not establish

Printed at the end of every run, and in the report. Read it. It is the honest
part, and it is where the remaining work is.
"""

_PLAN = {
    "plan_id": "PLAN-CELL-1",
    "manufacturer": "CHANGE ME",
    "model": "CHANGE ME",
    "procedure": (
        "Export from each vendor tool into this machine's folder under "
        "exports/. Do not rename the files; the plan matches them by name."
    ),
    "functions": [
        {"function_id": "SF-01",
         "description": "Protective separation is maintained in collaborative operation",
         "required_performance": "PL d",
         "verified_by": ["ssm_separation", "stop_characterisation"]},
        {"function_id": "SF-02",
         "description": "Speed is limited in collaborative operation",
         "required_performance": "PL d",
         "verified_by": ["speed_limit"]},
    ],
    "items": [
        {"item_id": "ITM-ZONES", "kind": "safety_configuration",
         "name": "Safety scanner zone set", "source": "scanner-zones.cfg",
         "supplier": "CHANGE ME", "implements": ["SF-01"],
         "modifiable_in_field": True,
         "rule": {"kind": "text_excluding",
                  "patterns": ["^#\\\\s*Exported ", "^#\\\\s*Export sequence no:"],
                  "note": "most scanner tools stamp the time and the operator "
                          "into the header; run `assurance collect probe` to "
                          "find out what yours does."}},
        {"item_id": "ITM-PARAMS", "kind": "parameter_set",
         "name": "Robot safety parameter set", "source": "robot-params.json",
         "supplier": "CHANGE ME", "implements": ["SF-01", "SF-02"],
         "rule": {"kind": "json_excluding",
                  "keys": ["export.timestamp", "export.operator"],
                  "note": "the export block records who exported and when."},
         "version": {"kind": "json", "value": "firmware.version"}},
        {"item_id": "ITM-PLC", "kind": "safety_program",
         "name": "Safety PLC project", "source": "plc-project.zip",
         "supplier": "CHANGE ME", "implements": ["SF-01"],
         "rule": {"kind": "zip_members", "members": ["program/main.st"],
                  "note": "archive member timestamps move on every save."}},
        {"item_id": "ITM-FW", "kind": "firmware",
         "name": "Safety controller firmware", "source": "controller-fw.bin",
         "supplier": "CHANGE ME", "implements": ["SF-01", "SF-02"]},
    ],
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance kit",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    i = verbs.add_parser("init", help="write a runnable kit into a folder")
    i.add_argument("folder", type=Path)
    i.add_argument("--kit-id", default="site-kit")

    r = verbs.add_parser("run", help="enrol every machine, offline")
    r.add_argument("config", type=Path)
    r.add_argument("--out", type=Path, default=Path("out"))
    r.add_argument("--allow-loopback", action="store_true",
                   help="permit connections to this machine only; recorded either way")
    r.add_argument("--json", action="store_true")

    c = verbs.add_parser("check", help="what this kit would do, touching nothing")
    c.add_argument("config", type=Path)
    c.add_argument("--json", action="store_true")

    return p


def _cmd_init(args: argparse.Namespace) -> int:
    folder = Path(args.folder)
    if folder.exists() and any(folder.iterdir()):
        print(f"error: {folder} is not empty. Refusing to write over somebody's "
              "work; pick an empty folder.", file=sys.stderr)
        return 2

    (folder / "plans").mkdir(parents=True, exist_ok=True)
    (folder / "exports" / "CELL-0412").mkdir(parents=True, exist_ok=True)

    config = starter_config(args.kit_id)
    (folder / "kit.json").write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (folder / "plans" / "cell.json").write_text(
        json.dumps(_PLAN, indent=2) + "\n", encoding="utf-8")
    (folder / "README.md").write_text(
        _README.format(kit_id=args.kit_id), encoding="utf-8")
    (folder / "exports" / "CELL-0412" / "PUT-EXPORTS-HERE.txt").write_text(
        "Drop this machine's vendor exports into this folder, then delete this "
        "file.\n\nThe plan in plans/cell.json expects, by name:\n"
        "  scanner-zones.cfg\n  robot-params.json\n  plc-project.zip\n"
        "  controller-fw.bin\n\nIf your tools produce different names, change "
        "the `source` entries in the plan rather than renaming the exports — a "
        "renamed export is one more thing nobody can reproduce later.\n",
        encoding="utf-8")

    print(f"kit written to {folder}")
    print("\n  1. edit kit.json          your company, site, and machines")
    print("  2. edit plans/cell.json   the four source file names")
    print("  3. fill exports/<serial>/ with the vendor exports")
    print(f"\n  then: python -m assurance kit run {folder}/kit.json --out {folder}/out")
    print(f"  first: python -m assurance kit check {folder}/kit.json")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """What a run would read, and whether the files the plan names are there.

    The useful question is not "is the export folder empty" — it is "does every
    item this plan declares actually resolve to a file". An item that does not
    is left out of the manifest entirely, and a manifest silently missing an
    item is the failure mode this whole package exists to prevent. Better to
    find it here, before the engineer walks away thinking they are done.
    """
    config = KitConfig.from_json(args.config)
    rows: list[dict[str, Any]] = []
    problems = 0

    for entry in config.machines:
        plan_path = config.resolve(entry.plan)
        exports = config.resolve(entry.exports)
        row: dict[str, Any] = {
            "serial": entry.serial,
            "plan": str(plan_path),
            "exports": str(exports),
            "ready": False,
            "items": [],
            "problem": "",
        }
        if not plan_path.exists():
            row["problem"] = "plan does not exist"
        elif not exports.is_dir():
            row["problem"] = "export folder does not exist"
        else:
            try:
                plan = CollectionPlan.from_json(plan_path)
            except AssuranceError as exc:
                row["problem"] = f"plan is unusable: {exc}"
            else:
                row["plan_id"] = plan.plan_id
                placeholders = [
                    f"{label}={value!r}"
                    for label, value in (("manufacturer", plan.manufacturer),
                                         ("model", plan.model))
                    if _is_placeholder(value)
                ]
                if placeholders:
                    row["problem"] = (
                        "plan still carries template values: "
                        + ", ".join(placeholders))
                for spec in plan.items:
                    found = sorted(
                        f.name for f in exports.glob(spec.source) if f.is_file())
                    row["items"].append({
                        "item_id": spec.item_id, "source": spec.source,
                        "found": found, "required": spec.required,
                    })
                missing = [i for i in row["items"] if not i["found"]]
                if missing:
                    row["problem"] = "; ".join(filter(None, [
                        row["problem"],
                        f"{len(missing)} of {len(row['items'])} item(s) match no "
                        "file in the export folder"]))
                row["ready"] = not row["problem"]
        if not row["ready"]:
            problems += 1
        rows.append(row)

    if args.json:
        print(json.dumps({"kit_id": config.kit_id, "machines": rows,
                          "problems": problems}, indent=2))
        return 1 if problems else 0

    print(f"{config.kit_id} — {config.organisation}"
          + (f" — {config.site}" if config.site else ""))
    print(f"  prepared by {config.prepared_by}")
    print(f"\n  {len(config.machines)} machine(s):")
    for row in rows:
        print(f"  {' ' if row['ready'] else '!'} {row['serial']}"
              + (f"   [{row['plan_id']}]" if row.get("plan_id") else ""))
        print(f"      plan     {row['plan']}")
        print(f"      exports  {row['exports']}")
        for item in row["items"]:
            mark = "  " if item["found"] else "->"
            detail = ", ".join(item["found"]) if item["found"] else "NO MATCH"
            flag = "" if item["found"] or not item["required"] else "  (required)"
            print(f"      {mark} {item['item_id']:<12} {item['source']:<24} "
                  f"{detail}{flag}")
        if row["problem"]:
            print(f"      ! {row['problem']}")

    print("\n  What a run would touch: only the paths above, for reading, and "
          "the --out folder,")
    print("  for writing. What it would send: nothing. The run arms a guard over "
          "this process's")
    print("  socket layer, refuses every outbound connection, and seals the "
          "result into your")
    print("  own ledger, so the claim is checkable rather than promised.")
    if problems:
        print(f"\n  {problems} machine(s) are not ready. An item that matches no "
              "file is left out of")
        print("  the manifest entirely — fix the `source` entries, or drop the "
              "missing exports in,")
        print("  before you run.")
    return 1 if problems else 0


def _cmd_run(args: argparse.Namespace) -> int:
    config = KitConfig.from_json(args.config)
    run = run_kit(config, args.out, allow_loopback=args.allow_loopback)

    if args.json:
        print(json.dumps(run.to_dict(), indent=2, sort_keys=True))
    else:
        print(run.summary())
        print()
        for m in run.machines:
            print(f"  {m.status:<11} {m.serial:<16} {m.items} item(s)"
                  + (f"   {m.detail}" if m.detail else ""))
            for w in m.warnings:
                print(f"      ! {w}")
        print(f"\n  airgap: {run.airgap.summary()}")
        for attempt in run.airgap.attempts:
            print(f"      ! {attempt.api} -> {attempt.target}  from {attempt.caller}")
        print(f"\n  report   {run.report_path}")
        print(f"  ledger   {run.ledger_path}")
        print(f"  request  {run.attest_request_path}")
        print(f"  head     seq {run.head.get('head_seq')} "
              f"{str(run.head.get('head_link_hash', ''))[:12]} "
              f"over {run.head.get('length')} record(s)")
        print("\n  What this run does not establish:")
        for c in run.checks_skipped:
            print(f"    - {c}")

    if run.verdict == "failed":
        return 2
    return 0 if (run.verdict == "complete" and run.airgap.held) else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"init": _cmd_init, "run": _cmd_run, "check": _cmd_check}
    try:
        return handlers[args.command](args)
    except KitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
