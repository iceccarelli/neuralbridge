#!/usr/bin/env python3
# ruff: noqa: T201, S603  (a command-line demo: it prints, and it runs this package's own CLI)
"""One synthetic machine, one firmware change, evidence before and after, a passport anyone can check.

    python examples/workflow/run.py            # prints each step and what it does NOT prove
    python examples/workflow/run.py --json     # the same, as one JSON document

Everything is invented: the machine (DemoCo/AR-7#DEMO-0001), its firmware hashes, the stop and
calibration figures, the two traces, and the "recorder", whose key is generated fresh on every run
and trusted only by the trust list this script writes. Nothing here describes real equipment, and
a green run shows that the software behaves as documented on this input, not that any machine is
safe or compliant.

It drives the real CLI (``python -m assurance``) in a temporary directory and exits 0 only if every
step gave the documented result: covered, then stale after the intervention, then covered again at
``validated``, then a passport that an outsider's check accepts. Anything else is exit 1.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEY = "DemoCo/AR-7#DEMO-0001"
PRODUCT = "AR-7 Palletising Cell (SYNTHETIC DEMO)"


def cli(work: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "assurance", *args], cwd=work,
                          capture_output=True, text=True, check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true", help="print one JSON report")
    ap.add_argument("--keep", metavar="DIR", help="work in DIR (must be empty) and keep the files")
    args = ap.parse_args()

    steps: list[dict] = []

    def step(name: str, run: subprocess.CompletedProcess, expect: int, shows: str, limits: str
             ) -> None:
        steps.append({"step": name, "exit": run.returncode, "expected_exit": expect,
                      "ok": run.returncode == expect, "shows": shows, "does_not_show": limits,
                      "stderr": run.stderr.strip()[-300:]})

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(args.keep) if args.keep else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        for name in ("envelope", "manifest", "intervention", "trace-before", "trace-after"):
            (work / f"{name}.json").write_text((HERE / f"{name}.json").read_text("utf-8"), "utf-8")
        ledger = "ledger.db"

        step("keygen: a throwaway recorder key", cli(work, "attest", "keygen", "--out", "rec.pem"),
             0, "a fresh Ed25519 key pair for this run", "that any real recorder exists")
        step("trust: the verifier's own list names that key",
             cli(work, "machine", "recorder-trust", "--trust", "trust.json", "--public-key",
                 "rec.pem.pub", "--label", "SYNTHETIC demo recorder", "--provenance", "bench,field"),
             0, "which key this verifier would believe", "that the key belongs to a real recorder")
        step("enrol: declare the machine and seal its baseline manifest",
             cli(work, "machinery", "enrol", "--ledger", ledger, "--actor",
                 "a.integrator", "manifest.json"),
             0, "a hash-chained record of the declared identity, configuration and safety "
             "functions, and a receipt listing what enrolment does not establish",
             "that the declaration is complete or true, that the serial belongs to a physical "
             "unit, or that any function has been verified (all read never_verified)")

        def verify(tag: str, attested_on: str) -> subprocess.CompletedProcess:
            sign = cli(work, "machine", "recorder-sign", "--key", "rec.pem", "--trace",
                       f"trace-{tag}.json", "--product", PRODUCT, "--product-version", "2.4.1",
                       "--machine-serial", "DEMO-0001", "--recorder-id", "SYNTHETIC demo recorder",
                       "--attested-on", attested_on, "--out", f"att-{tag}.json")
            if sign.returncode != 0:
                return sign
            return cli(work, "machine", "verify", "--envelope", "envelope.json", "--trace",
                       f"trace-{tag}.json", "--recorder-attestation", f"att-{tag}.json",
                       "--recorder-trust", "trust.json", "--actor", "v.demo", "--ledger", ledger,
                       "--subject", KEY, "--machine-serial", "DEMO-0001", "--out",
                       f"bundle-{tag}.json")

        step("verify (before the change): the recorded run against the declared envelope",
             verify("before", "2026-03-10"), 0,
             "the run stayed inside the declared limits; a trusted key signed these trace bytes",
             "that the recording is physically true or the envelope figures are right")
        step("coverage: which safety functions the evidence still stands for",
             cli(work, "machinery", "coverage", "--ledger", ledger, "manifest.json"), 0,
             "SF-01 and SF-02 covered at validated", "SF-03-style functions nobody listed")
        step("intervention: seal the firmware update",
             cli(work, "machinery", "record-change", "--ledger", ledger, "--actor", "m.tech",
                 "intervention.json"),
             0, "the update, who did it and which functions it touches",
             "that the update was safe, or that this record is the only change")
        step("coverage after the change: expected GAPS",
             cli(work, "machinery", "coverage", "--ledger", ledger, "manifest.json"), 1,
             "the earlier evidence no longer stands for SF-01 and SF-02",
             "that the machine is unsafe, only that nothing re-verified it")
        step("verify (after the change)", verify("after", "2026-03-15"), 0,
             "a new run, attested, inside the limits", "the same limits of the first run")
        step("coverage after re-verification: covered again",
             cli(work, "machinery", "coverage", "--ledger", ledger, "manifest.json"), 0,
             "both functions current at validated", "compliance with any law or standard")
        step("passport: seal the machine's whole position",
             cli(work, "machinery", "passport", "--ledger", ledger, "--actor", "v.demo",
                 "manifest.json", "--out", "passport.json"),
             0, "one document holding configuration, changes and cover",
             "anything the ledger did not contain")
        step("outsider check of the passport, with the ledger",
             cli(work, "machinery", "check", "--ledger", ledger, "passport.json"), 0,
             "the passport matches the records it names", "who the recorder or filer really is")
        step("outsider check of the verification bundle, own trust list",
             cli(work, "machine", "check", "bundle-after.json", "--envelope", "envelope.json",
                 "--trace", "trace-after.json", "--recorder-trust", "trust.json", "--as-of",
                 "2026-03-16T00:00:00Z"),
             0, "the verification reproduces from the envelope and trace",
             "that the trace came from a real machine")

    passed = all(s["ok"] for s in steps)
    if args.json:
        print(json.dumps({"synthetic": True, "ok": passed, "steps": steps}, indent=2))
    else:
        for s in steps:
            print(f"[{'ok' if s['ok'] else 'FAIL'}] {s['step']}  (exit {s['exit']}, "
                  f"expected {s['expected_exit']})")
            print(f"       shows: {s['shows']}\n       does not show: {s['does_not_show']}")
            if not s["ok"] and s["stderr"]:
                print(f"       stderr: {s['stderr']}")
        print("\nSYNTHETIC DEMONSTRATION — " + ("every step gave the documented result."
              if passed else "a step did not give the documented result."))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
