"""``assurance kit`` — enrol a plant's machines without anything leaving it.

    init    write a runnable kit into a folder: config, plan skeleton, README
    run     collect every machine listed, offline, into your own ledger
    check   read a kit and say what it would do, touching nothing

The order is ``init`` once per site, then ``run`` whenever something might have
changed. ``check`` is for the person who has to approve this before it runs on
their network, and it is the first command they will ask for.

Exit codes are the interface:

    0  every machine recorded, nothing tried to reach the network
    1  a finding — a machine incomplete, a required item missing, or a refused
       connection attempt. The run still produced evidence; read it.
    2  the kit could not run at all.

A refused connection attempt is a 1, not a 2, on purpose. The run is still
valid — nothing got out — but somebody needs to know which line tried.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import textwrap
from pathlib import Path
from typing import Any

from assurance.collect.collector import ItemOutcome
from assurance.core.errors import AssuranceError
from assurance.kit.airgap import no_network
from assurance.kit.enrol import (
    KitConfig,
    KitError,
    describe_placeholders,
    find_placeholders,
    inspect_machine,
    run_kit,
    starter_config,
    starter_warnings,
)

__all__ = ["build_parser", "main"]

#: The steps ``kit init`` prints and the kit README lists. One source, so the two
#: cannot disagree about how many things a person has to do.
_STEPS = (
    "Open `kit.json` and put your company (`organisation`), your site and your name "
    "or e-mail (`prepared_by`) in it, and list your machines.",
    "Open `plans/cell.json` and replace every `CHANGE ME`: the machine's `manufacturer` "
    "and `model`, and the `supplier` of each item. Make the four `source` entries match "
    "the file names your tools actually produce. That file is the only one that needs "
    "any thought, and getting it wrong is visible: the run says which items it could "
    "not find.",
    "For each machine, make a folder under `exports/` named after its serial and drop "
    "that machine's vendor exports into it: the scanner zone file, the robot parameter "
    "export, the safety PLC project, the controller firmware. Do not rename them.",
    "Run `python -m assurance kit check kit.json`. It reads each file the plan names the "
    "way the run will, names every placeholder still in your files, every item that "
    "matches no file and every file it cannot read, and writes nothing. Fix what it "
    "names; when it says READY it prints the command to run.",
)


def _steps_text(indent: str, hang: str) -> str:
    return "\n".join(
        textwrap.fill(step, width=78, initial_indent=f"{indent}{n}. ",
                      subsequent_indent=hang)
        for n, step in enumerate(_STEPS, 1))


_README = """# Offline enrolment kit — {kit_id}

This folder records what safety-relevant software is on your machines, seals it
into an evidence ledger **that stays on this disk**, and produces a report you
can hand to an auditor, an insurer or a customer.

Nothing is uploaded. Nothing is registered. There is no account and no key to
run this kit. (Having the ledger head counter-signed is a separate, optional,
hosted step; that one does need an account.)

## Before you run it

{steps}

## Run it

    python -m assurance kit run kit.json --out out/

You get, in `out/`:

    report.html                  open this first
    evidence.db                  your ledger. Back it up like a drawing
    run.json                     machine-by-machine, what was recorded
    attestation-request.json     three numbers, if you ever want the head
                                 counter-signed by somebody who is not you

Files read from an export folder are labelled `supplied_by_vendor` (tier ceiling
`community`): a folder cannot show which machine it came off. If this kit really
runs on the machine itself, pass `--read-from-machine`; that is your assertion,
and it is recorded as such. The headline `COMPLETE` means only that every item the
plan names was found and hashed.

## Before you let it near anything

    python -m assurance kit check kit.json

`check` reads the configuration and every file the plan names, the way the run does, and
prints each item and what the run would touch, without writing anything. The run itself arms a guard over this process's socket layer and
refuses every outbound connection, recording any attempt with the line of code
that made it — and seals that record into your own ledger. So "it does not phone
home" is not a promise in a document; it is a hash in a file you hold.

The guard covers this Python process: its socket calls and name lookups are refused,
and so is creating a process (including through `multiprocessing`). It does not cover
native code that reaches the kernel without Python (a C extension, `ctypes`), a socket
that was already connected before the run began, or a process started some other way,
and it records intent rather than enforcing containment. The operating system is the
real control: run the kit in a network namespace with no interface (`unshare -rn`) or
behind your firewall. These limits are in the evidence record too, because a claim
printed next to its limits is worth more to a reviewer than a broader claim with none.

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
                  "patterns": ["^#\\s*Exported ", "^#\\s*Export sequence no:"],
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
    r.add_argument("--read-from-machine", action="store_true",
                   help="assert that this kit runs ON the machines, so the hashes describe "
                        "the units. Without it every item is labelled supplied_by_vendor "
                        "(community ceiling): a folder of exported files cannot show which "
                        "machine it came from. The assertion is the operator's, it is "
                        "recorded in each manifest and in the report, and the software "
                        "cannot check it")
    r.add_argument("--seal-incomplete", action="store_true",
                   help="seal a machine even when a required item could not be read. The "
                        "manifest then becomes the machine's current one with those items "
                        "absent, and an advisory about them will not match this machine; by "
                        "default an incomplete collection is not sealed (the attempt is "
                        "recorded in the run record, with the missing items)")
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
        _README.format(kit_id=args.kit_id, steps=_steps_text("", "    ")),
        encoding="utf-8")
    (folder / "exports" / "CELL-0412" / "PUT-EXPORTS-HERE.txt").write_text(
        "Drop this machine's vendor exports into this folder, then delete this "
        "file.\n\nThe plan in plans/cell.json expects, by name:\n"
        "  scanner-zones.cfg\n  robot-params.json\n  plc-project.zip\n"
        "  controller-fw.bin\n\nIf your tools produce different names, change "
        "the `source` entries in the plan rather than renaming the exports — a "
        "renamed export is one more thing nobody can reproduce later.\n",
        encoding="utf-8")

    print(f"kit written to {folder}\n")
    print(_steps_text("  ", "     "))
    print(f"\n  check: python -m assurance kit check {folder}/kit.json")
    print(f"  run:   python -m assurance kit run {folder}/kit.json --out {folder}/out")
    return 0


def _check_machine(entry: Any, config: KitConfig, placeholders: list[dict[str, str]]
                   ) -> tuple[dict[str, Any], list[ItemOutcome], dict[str, Any]]:
    """Read one machine exactly as ``run`` would, and say what would go wrong.

    Returns the row, the item outcomes and each item's plan spec (for printing). Nothing is
    sealed or written: this is :func:`~assurance.kit.enrol.inspect_machine`.
    """
    row: dict[str, Any] = {
        "serial": entry.serial,
        "plan": str(config.resolve(entry.plan)),
        "exports": str(config.resolve(entry.exports)),
        "ready": False,
        "items": [],
        "problem": "",
    }
    plan, result, failed = inspect_machine(entry, config)
    problems: list[str] = []
    specs: dict[str, Any] = {}
    outcomes: list[ItemOutcome] = []
    if failed is not None:
        problems.append(failed.detail)
    if plan is not None:
        row["plan_id"] = plan.plan_id
        specs = {i.item_id: i for i in plan.items}
        in_plan = [p for p in placeholders if p["file"] == entry.plan]
        if in_plan:
            problems.append(" ".join(describe_placeholders(in_plan)))
    if result is not None:
        outcomes = list(result.outcomes)
        for o in outcomes:
            spec = specs[o.item_id]
            row["items"].append({
                "item_id": o.item_id, "source": spec.source, "found": list(o.files),
                "required": spec.required, "status": o.status, "digest": o.digest,
                "version": o.version, "warnings": list(o.warnings), "detail": o.detail,
            })
        missing = [o for o in outcomes if o.status == "missing" and o.required]
        unreadable = [o for o in outcomes if o.status == "unreadable"]
        if missing:
            problems.append(f"{len(missing)} of {len(outcomes)} item(s) match no file in the "
                            "export folder")
        if unreadable:
            problems.append(f"{len(unreadable)} of {len(outcomes)} item(s) could not be read "
                            f"({', '.join(o.item_id for o in unreadable)})")
    row["problem"] = "; ".join(filter(None, problems))
    row["ready"] = not row["problem"]
    row["notes"] = list(starter_warnings(entry, config))
    return row, outcomes, specs


def _cmd_check(args: argparse.Namespace) -> int:
    """What a run would read, item by item, and whether it would work. Writes nothing.

    The useful question is not "is the export folder empty" and not "does a glob match" — a
    file that matches and cannot be read (not UTF-8 under a text rule, not a zip, a link out
    of the folder) passed the old check and failed the run. So this makes the same read-only
    :func:`~assurance.collect.collector.collect` call per machine that ``run`` makes, under
    the same socket guard, and reports each item: its digest, its version or that it is
    unknown, its warnings, or why it would fail. It seals nothing and creates nothing.
    """
    placeholders = find_placeholders(args.config)
    try:
        config = KitConfig.from_json(args.config)
    except KitError:
        # Only when the refusal IS kit.json's own template values; any other fault in
        # kit.json is reported as itself.
        if not any(p["file"] == args.config.name for p in placeholders):
            raise
        # Not a crash and not one refusal at a time: everything still to fill in,
        # named once. `check` only reads, and says so.
        if args.json:
            print(json.dumps({"ready": False, "problems": len(placeholders),
                              "machines": [], "placeholders": placeholders}, indent=2))
        else:
            print("not ready, and check only read these files (nothing was run or "
                  "written):", file=sys.stderr)
            for line in describe_placeholders(placeholders):
                print(f"  {line}", file=sys.stderr)
            print("Fill them in, then run check again.", file=sys.stderr)
        return 2
    rows: list[dict[str, Any]] = []
    lines: list[list[ItemOutcome]] = []
    specs_by_row: list[dict[str, Any]] = []
    with no_network() as airgap:
        for entry in config.machines:
            row, outcomes, specs = _check_machine(entry, config, placeholders)
            rows.append(row)
            lines.append(outcomes)
            specs_by_row.append(specs)
    problems = sum(1 for row in rows if not row["ready"]) + (0 if airgap.held else 1)
    run_command = (f"python -m assurance kit run {shlex.quote(str(args.config))} "
                   f"--out {shlex.quote(str(Path(args.config).parent / 'out'))}")

    if args.json:
        print(json.dumps({"kit_id": config.kit_id, "ready": not problems,
                          "machines": rows, "problems": problems,
                          "placeholders": placeholders, "airgap": airgap.to_dict(),
                          "run_command": run_command if not problems else ""}, indent=2))
        return 1 if problems else 0

    print(f"{config.kit_id} — {config.organisation}"
          + (f" — {config.site}" if config.site else ""))
    print(f"  prepared by {config.prepared_by}")
    print(f"\n  {len(config.machines)} machine(s):")
    for row, outcomes, specs in zip(rows, lines, specs_by_row, strict=True):
        print(f"  {' ' if row['ready'] else '!'} {row['serial']}"
              + (f"   [{row['plan_id']}]" if row.get("plan_id") else ""))
        print(f"      plan     {row['plan']}")
        print(f"      exports  {row['exports']}")
        for o in outcomes:
            if o.status == "missing":
                spec = specs[o.item_id]
                flag = "  (required)" if spec.required else "  (optional: not a gap)"
                print(f"      MISS {o.item_id:<12} NO MATCH for {spec.source!r}{flag}")
            else:
                for line in _outcome_lines(o):
                    print(line)
        for note in row["notes"]:
            print(f"      ? {note}")
        if row["problem"]:
            print(f"      ! {row['problem']}")

    print("\n  What a run would touch: only the paths above, for reading, and "
          "the --out folder,")
    print("  for writing. What it would send: nothing. The run arms a guard over "
          "this process's")
    print("  socket layer, refuses every outbound connection, and seals the "
          "result into your")
    print("  own ledger, so the claim is checkable rather than promised.")
    print(f"\n  check read every file above under the same guard and wrote nothing: "
          f"{airgap.summary()}")
    for attempt in airgap.attempts:
        print(f"      ! {attempt.api} -> {attempt.target}  from {attempt.caller}")
    if problems:
        print(f"\n  NOT READY: {problems} problem(s), marked FAIL, MISS or ! above. A machine with "
              "an item that")
        print("  cannot be read is not sealed by `run` (the attempt is recorded, nothing "
              "describes the machine).")
        print("  Fix the export files, the `source` entries and the template values, then "
              "run check again.")
    else:
        warned = sum(1 for outcomes in lines for o in outcomes if o.warnings)
        print("\n  READY: every item of every machine was found and read."
              + (f" {warned} item(s) carry warnings above; read them first." if warned else ""))
        print("  Run it with:")
        print(f"\n    {run_command}")
    return 1 if problems else 0


def _outcome_lines(o: ItemOutcome, indent: str = "      ") -> list[str]:
    """One item as the integrator reads it: result, id, where it came from, why if not."""
    mark = {"collected": "ok  ", "missing": "MISS", "unreadable": "FAIL"}[o.status]
    if o.ok:
        version = f"v{o.version}" if o.version else "version unknown"
        lines = [f"{indent}{mark} {o.item_id:<12} {o.digest[:12]}  {version:<16} "
                 f"{', '.join(o.files)}"]
        if o.detail:
            lines.append(f"{indent}     {o.detail}")
    else:
        lines = [f"{indent}{mark} {o.item_id:<12} {o.detail}"]
    lines.extend(f"{indent}     ! {w}" for w in o.warnings)
    return lines


def _enrol_commands(config: KitConfig, run: Any, read_from_machine: bool) -> list[str]:
    """The commands that turn a recorded machine into an enrolled one.

    The kit seals each machine's manifest into the ledger; it does not enrol it. Enrolment is
    a declaration by a named person (``machinery enrol``), and ``machinery amend-enrolment``
    refuses a machine that has none. Two steps: write the manifest file with the same plan,
    folder and identity the kit used (so the configuration is identical), then enrol it.
    """
    q = shlex.quote
    lines: list[str] = []
    for m in run.recorded:
        entry = next(e for e in config.machines if e.serial == m.serial)
        manifest = f"manifest-{entry.serial}.json"
        lines.append(
            f"python -m assurance collect run {q(str(config.resolve(entry.plan)))} "
            f"--root {q(str(config.resolve(entry.exports)))} --serial {q(entry.serial)} "
            f"--actor {q(config.prepared_by)} --site {q(config.site)} "
            f"--country {q(config.country)} --year {q(entry.year)} --out {q(manifest)}"
            + (" --read-from-machine" if read_from_machine else ""))
        lines.append(
            f"python -m assurance machinery enrol {q(manifest)} "
            f"--ledger {q(run.ledger_path)} --actor {q(config.prepared_by)}")
    return lines


def _cmd_run(args: argparse.Namespace) -> int:
    config = KitConfig.from_json(args.config)
    run = run_kit(config, args.out, allow_loopback=args.allow_loopback,
                  read_from_machine=args.read_from_machine,
                  seal_incomplete=args.seal_incomplete)

    if args.json:
        print(json.dumps(run.to_dict(), indent=2, sort_keys=True))
    else:
        print(run.summary())
        print("  (COMPLETE means only that every item the plan names was found and hashed.)")
        print()
        for m in run.machines:
            count = (f"{m.items} of {len(m.outcomes)} item(s) collected" if m.outcomes
                     else f"{m.items} item(s)")
            print(f"  {m.status:<11} {m.serial:<16} {count}"
                  + (f"   {m.detail}" if m.detail else ""))
            for o in m.outcomes:
                for line in _outcome_lines(o):
                    print(line)
            for w in m.warnings:
                print(f"      ! {w}")
        unsealed = [m.serial for m in run.machines if m.status == "incomplete" and not m.sealed]
        if unsealed:
            print(f"\n  NOT sealed (collection incomplete): {', '.join(unsealed)}. Nothing in "
                  "the ledger describes those machines; the attempt, with the items that "
                  "were not collected, is in the run record and the report. Fix the export "
                  "folder and run again, or pass --seal-incomplete to seal what was read.")
        if run.recorded:
            print("\n  recorded is not enrolled: the manifest is sealed in the ledger, but no "
                  "enrolment\n  has been declared, so `machinery amend-enrolment` will say "
                  "'not enrolled'. To enrol\n  (a named person's declaration; the kit does "
                  "not make it for you), per machine:")
            for line in _enrol_commands(config, run, args.read_from_machine):
                print(f"\n    {line}")
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
