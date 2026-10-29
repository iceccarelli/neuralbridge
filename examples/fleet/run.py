#!/usr/bin/env python3
# ruff: noqa: T201, S603  (a command-line demo: it prints, and it runs this package's own CLI)
"""Five synthetic machines, five different positions, one ledger, one supplier advisory.

    python examples/fleet/run.py            # each step, and what it does not show
    python examples/fleet/run.py --json     # the same as one JSON document

What a service organisation or a plant manager would look at: which machines the evidence still
stands for, on what tier of evidence, which are stale after a change, which were never verified,
and which an advisory touches. Everything is invented (``DemoCo/AR-7#FLEET-01`` .. ``05``), the
recorder key is generated per run, and the advisory is the shipped example. It reuses the single
machine pack in ``examples/workflow`` for the envelope and the traces.

Machines
    FLEET-01  firmware 3.9.0 (the advisory's fixed release), attested run   -> covered, validated
    FLEET-02  firmware 3.8.2 (affected hash), attested run                  -> covered, validated
    FLEET-03  labelled 3.8.1 (a version the advisory names) but its hash is not one the supplier
              published for it; run only declared by its filer              -> covered at community
    FLEET-04  firmware 3.8.2, attested run, then a recorded firmware update -> stale, nothing re-run
    FLEET-05  firmware 3.8.2, manifest only, never verified                 -> gaps

What the advisory step shows, and the paperwork caveat it prints: every machine here is known only
from a declared baseline, so a match or a clear is "about the paperwork". FLEET-04 still matches
because its update was recorded but no new manifest was taken; FLEET-03 is "contradictory label
versus hash" and needs a person, and is counted neither affected nor clear; nothing is called clear.

Exit 0 only if every step gave the documented result. A green run shows the software behaves as
documented on this input; it says nothing about any real machine, supplier or advisory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE.parent / "workflow"
PRODUCT = "AR-7 Palletising Cell (SYNTHETIC DEMO)"
PERSON = {"identifier": "a.integrator", "role": "safety engineer", "kind": "person"}
FW_AFFECTED_HASH = "a" * 64            # the hash the shipped advisory names
FW_FIXED_HASH = "3" * 64               # the advisory's fixed_hashes

MACHINES = [   # serial, firmware version, firmware hash, how it is verified
    ("FLEET-01", "3.9.0", FW_FIXED_HASH, "attested"),
    ("FLEET-02", "3.8.2", FW_AFFECTED_HASH, "attested"),
    ("FLEET-03", "3.8.1", hashlib.sha256(b"SYNTHETIC fw 3.8.1").hexdigest(), "declared"),
    ("FLEET-04", "3.8.2", FW_AFFECTED_HASH, "attested"),
    ("FLEET-05", "3.8.2", FW_AFFECTED_HASH, "never"),
]


def manifest(serial: str, version: str, fw_hash: str) -> dict:
    return {
        "manifest_id": f"MAN-{serial}", "source": "as_declared",
        "machine": {"manufacturer": "DemoCo", "model": "AR-7", "serial": serial, "year": "2026",
                    "site": "SYNTHETIC demo plant"},
        "taken_at": "2026-03-01T09:00:00Z", "taken_by": PERSON,
        "method": "SYNTHETIC: figures invented for the demonstration", "notes": "Not a real machine.",
        "items": [{"item_id": "ITM-FW", "kind": "firmware", "name": "Safety controller firmware",
                   "version": version, "content_hash": fw_hash, "hash_source": "read_from_machine",
                   "supplier": "ControlCo", "implements": ["SF-01", "SF-02"],
                   "modifiable_in_field": False}],
        "functions": [
            {"function_id": "SF-01", "description": "Protective separation (SSM)",
             "required_performance": "PL d", "verified_by": ["ssm_separation", "stop_characterisation"]},
            {"function_id": "SF-02", "description": "Speed limit in collaborative operation",
             "required_performance": "PL d", "verified_by": ["speed_limit"]}],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep", metavar="DIR", help="work in DIR (must be empty) and keep the files")
    args = ap.parse_args()
    steps: list[dict] = []
    facts: dict = {}

    def cli(work: Path, *a: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "assurance", *a], cwd=work,
                              capture_output=True, text=True, check=False)

    def step(name: str, run: subprocess.CompletedProcess, expect: int, shows: str, limits: str):
        steps.append({"step": name, "exit": run.returncode, "expected_exit": expect,
                      "ok": run.returncode == expect, "shows": shows, "does_not_show": limits,
                      "stderr": run.stderr.strip()[-300:]})

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(args.keep) if args.keep else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        for name in ("envelope", "trace-before"):
            (work / f"{name}.json").write_text((PACK / f"{name}.json").read_text("utf-8"), "utf-8")
        (work / "advisory.json").write_text((HERE / "advisory-CTRL-2026-11.json").read_text("utf-8"),
                                            "utf-8")
        ledger = "fleet.db"
        step("keygen + trust list", cli(work, "attest", "keygen", "--out", "rec.pem"), 0,
             "a throwaway recorder key", "that any real recorder exists")
        step("trust", cli(work, "machine", "recorder-trust", "--trust", "trust.json", "--public-key",
                          "rec.pem.pub", "--label", "SYNTHETIC fleet recorder", "--provenance",
                          "bench,field"), 0, "the verifier's own list names that key",
             "that the key belongs to a real recorder")
        base_trace = json.loads((work / "trace-before.json").read_text("utf-8"))
        for serial, version, fw_hash, how in MACHINES:
            (work / f"manifest-{serial}.json").write_text(
                json.dumps(manifest(serial, version, fw_hash)), "utf-8")
            r = cli(work, "machinery", "record-manifest", "--ledger", ledger, "--actor",
                    "a.integrator", f"manifest-{serial}.json")
            if r.returncode != 0 or how == "never":
                step(f"manifest {serial}", r, 0, "the declared configuration is sealed",
                     "that the declaration is true or complete")
                continue
            trace = dict(base_trace, trace_id=f"RUN-{serial}")
            (work / f"trace-{serial}.json").write_text(json.dumps(trace), "utf-8")
            verify = ["machine", "verify", "--envelope", "envelope.json", "--trace",
                      f"trace-{serial}.json", "--actor", "v.demo", "--ledger", ledger, "--subject",
                      f"DemoCo/AR-7#{serial}", "--machine-serial", serial]
            if how == "attested":
                sign = cli(work, "machine", "recorder-sign", "--key", "rec.pem", "--trace",
                           f"trace-{serial}.json", "--product", PRODUCT, "--product-version",
                           "2.4.1", "--machine-serial", serial, "--recorder-id",
                           "SYNTHETIC fleet recorder", "--attested-on", "2026-03-10", "--out",
                           f"att-{serial}.json")
                if sign.returncode != 0:
                    step(f"sign {serial}", sign, 0, "", "")
                    continue
                verify += ["--recorder-attestation", f"att-{serial}.json", "--recorder-trust",
                           "trust.json"]
            step(f"manifest + verification {serial} ({how})", cli(work, *verify), 0,
                 "the run stayed inside the envelope" + (", attested by a trusted key"
                                                       if how == "attested" else ", declared only"),
                 "that the recording is physically true")
        intervention = {
            "intervention_id": "INT-FLEET-04", "machine_key": "DemoCo/AR-7#FLEET-04",
            "item_id": "ITM-FW", "kind": "update", "occurred_at": "2026-03-14T09:30:00Z",
            "performed_by": {"identifier": "m.tech", "role": "service technician", "kind": "person"},
            "reason": "SYNTHETIC: update to the advisory's fixed release",
            "from_hash": FW_AFFECTED_HASH, "to_hash": FW_FIXED_HASH,
            "affects_functions": ["SF-01", "SF-02"], "authorization": None, "revalidation": None,
            "notes": "Nothing was re-run afterwards."}
        (work / "intervention-04.json").write_text(json.dumps(intervention), "utf-8")
        step("intervention on FLEET-04 (firmware updated, nothing re-run)",
             cli(work, "machinery", "record-change", "--ledger", ledger, "--actor", "m.tech",
                 "intervention-04.json"), 0, "the update is on the record",
             "that the update was safe or is the only change")
        listing = cli(work, "fleet", "list", "--ledger", ledger, "--json")
        step("fleet list: expected GAPS", listing, 1, "which machines the evidence still stands for",
             "machines nobody enrolled")
        try:
            facts["machines"] = {m["machine"].split("#")[1]: {
                "verdict": m["verdict"], "worst": m["worst"], "tier_floor": m["evidence_tier_floor"]}
                for m in json.loads(listing.stdout)["machines"]}
            facts["order"] = [m["machine"].split("#")[1] for m in json.loads(listing.stdout)["machines"]]
        except (ValueError, KeyError):
            facts["machines"] = {}
        adv = cli(work, "fleet", "advisory", "--ledger", ledger, "--unsigned-anyway", "--json",
                  "advisory.json")
        step("fleet advisory CTRL-2026-11: expected a MATCH", adv, 1,
             "which machines declare an affected firmware", "that an unmatched machine is unaffected")
        try:
            body = json.loads(adv.stdout)
            facts["advisory"] = body
        except ValueError:
            facts["advisory"] = {}

    passed = all(s["ok"] for s in steps)
    if args.json:
        print(json.dumps({"synthetic": True, "ok": passed, "steps": steps, "facts": facts}, indent=2))
    else:
        for s in steps:
            print(f"[{'ok' if s['ok'] else 'FAIL'}] {s['step']}  (exit {s['exit']}, expected "
                  f"{s['expected_exit']})")
            if s["shows"]:
                print(f"       shows: {s['shows']}\n       does not show: {s['does_not_show']}")
            if not s["ok"] and s["stderr"]:
                print(f"       stderr: {s['stderr']}")
        for serial, f in facts.get("machines", {}).items():
            print(f"  {serial}: {f['verdict']:<22} worst={f['worst']:<10} tier_floor={f['tier_floor']}")
        print("\nSYNTHETIC DEMONSTRATION — " + ("every step gave the documented result."
              if passed else "a step did not give the documented result."))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
