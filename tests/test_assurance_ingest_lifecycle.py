"""The whole slice, end to end, on SYNTHETIC data, through the real command line.

SBOM import -> draft manifest -> named human review -> machine verification bound to the
configuration hash -> CSAF advisory import -> fleet impact -> a recorded intervention and its case
-> a named human decision -> re-verification -> passport -> independent verification.

Nothing here describes real equipment, a real supplier or a real vulnerability: the machine,
firmware, hashes, envelope, traces and advisory are invented (``examples/``). A green run shows the
software behaves as documented on this input. It shows no machine is safe.

Along the way the states that are not success are asserted to stay apart from it: a draft is not a
manifest, an unreviewed draft enrols nothing, a stale function is not covered, an affected machine
is not a clear, an ``unknown`` result is exit 3 and not 0, a case is not closed before its
re-verification and never without a named person, and a manifest that merely declares a
configuration cannot serve as the look a re-verification needs.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.manifest import (
    HashSource,
    ManifestSource,
    SafetyItem,
    SafetyManifest,
    not_a_look,
)
from assurance.machinery.record import manifests_from_ledger

from .ingest_support import EXAMPLES, FW_SHA, approve
from .interfaces_scenario import cli_env

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "examples" / "workflow"
KEY = "DemoCo/AR-7#DEMO-0001"
UPDATED_FW = "6ffe145cf6db3e43729768c065c3373c08b2c39dd72f15ee8e487aa8c6e5226e"
LIB_LOOKED_AT = "c" * 64          # SYNTHETIC digest of the library image, as a technician read it
LEDGER = "ledger.db"


class Run:
    """One synthetic plant in a temporary folder, driven through ``python -m assurance``."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.steps: list[dict[str, Any]] = []
        self.out: dict[str, Any] = {}

    def cli(self, *argv: Any, expect: int | None = 0, label: str = "") -> subprocess.CompletedProcess:
        done = subprocess.run(  # noqa: S603  (this repository's own CLI)
            [sys.executable, "-m", "assurance", *map(str, argv)], cwd=self.work,
            capture_output=True, text=True, env=cli_env(), check=False)
        self.steps.append({"step": label or " ".join(map(str, argv[:3])), "exit": done.returncode,
                           "expected": expect})
        if expect is not None:
            assert done.returncode == expect, (argv, done.returncode, done.stdout[-600:],
                                               done.stderr[-600:])
        return done

    def json(self, *argv: Any, expect: int | None = 0, label: str = "") -> dict[str, Any]:
        done = self.cli(*argv, "--json", expect=expect, label=label)
        return json.loads(done.stdout)


def _verify(run: Run, tag: str, attested_on: str, config_hash: str, label: str) -> dict[str, Any]:
    run.cli("machine", "recorder-sign", "--key", "rec.pem", "--trace", f"trace-{tag}.json",
            "--product", "AR-7 Palletising Cell (SYNTHETIC DEMO)", "--product-version", "2.4.1",
            "--machine-serial", "DEMO-0001", "--recorder-id", "SYNTHETIC demo recorder",
            "--attested-on", attested_on, "--out", f"att-{tag}.json", label=f"sign {tag}")
    run.cli("machine", "verify", "--envelope", "envelope.json", "--trace", f"trace-{tag}.json",
            "--recorder-attestation", f"att-{tag}.json", "--recorder-trust", "trust.json",
            "--actor", "v.demo", "--ledger", LEDGER, "--subject", KEY, "--machine-serial",
            "DEMO-0001", "--configuration-hash", config_hash, "--out", f"bundle-{tag}.json",
            label=label)
    return json.loads((run.work / f"bundle-{tag}.json").read_text("utf-8"))


@pytest.fixture(scope="module")
def ran(tmp_path_factory) -> Run:
    work = tmp_path_factory.mktemp("ingest-lifecycle")
    run = Run(work)
    for name in ("envelope", "trace-before", "trace-after"):
        (work / f"{name}.json").write_text((WORKFLOW / f"{name}.json").read_text("utf-8"), "utf-8")
    sbom = (EXAMPLES / "synthetic-sbom.cdx.json").read_text("utf-8")
    assert "SYNTHETIC" in sbom and "SYNTHETIC" in (EXAMPLES / "synthetic-advisory.csaf.json"
                                                   ).read_text("utf-8")
    (work / "sbom.json").write_text(sbom, "utf-8")
    (work / "advisory.json").write_text((EXAMPLES / "synthetic-advisory.csaf.json"
                                         ).read_text("utf-8"), "utf-8")

    # 1. SBOM -> a draft; the draft enrols nothing
    run.out["sbom_import"] = run.json("ingest", "sbom-import", "sbom.json", "--ledger", LEDGER,
                                      "--name", "sbom.json", label="sbom import")
    draft_id = run.out["sbom_import"]["draft_id"]
    run.out["fleet_after_draft"] = run.cli("fleet", "list", "--ledger", LEDGER, "--json",
                                           expect=None, label="fleet before review")
    template = json.loads(run.cli("ingest", "sbom-show", draft_id, "--ledger", LEDGER,
                                  "--review-template", label="template").stdout)

    # 2. an automation cannot review; a blank template cannot be approved; a person can
    (work / "review.json").write_text(json.dumps(approve(template)), "utf-8")
    run.out["review_by_bot"] = run.cli("ingest", "sbom-review", draft_id, "review.json",
                                       "--ledger", LEDGER, "--actor", "bot", expect=2,
                                       label="review by automation")
    blank = dict(template, decision="approve", reason="x")
    (work / "blank.json").write_text(json.dumps(blank), "utf-8")
    run.out["review_blank"] = run.cli("ingest", "sbom-review", draft_id, "blank.json",
                                      "--ledger", LEDGER, "--actor", "A. Integrator", expect=2,
                                      label="review of the blank template")
    run.out["review"] = run.json("ingest", "sbom-review", draft_id, "review.json", "--ledger",
                                 LEDGER, "--actor", "A. Integrator", label="review")
    config_hash = run.out["review"]["configuration_hash"]

    ledger = EvidenceLedger.open_existing(work / LEDGER)
    enrolled = manifests_from_ledger(ledger, KEY)[0]
    (work / "manifest.json").write_text(json.dumps(enrolled.to_dict(), indent=2), "utf-8")
    run.out["enrolled"] = enrolled
    fw = next(i for i in enrolled.items if i.name == "Safety controller firmware")

    # 3. a verification bound to the configuration the person reviewed
    run.cli("attest", "keygen", "--out", "rec.pem", label="keygen")
    run.cli("machine", "recorder-trust", "--trust", "trust.json", "--public-key", "rec.pem.pub",
            "--label", "SYNTHETIC demo recorder", "--provenance", "bench,field", label="trust")
    run.out["bundle_before"] = _verify(run, "before", "2026-03-10", config_hash, "verify before")
    run.out["coverage_before"] = run.cli("machinery", "coverage", "--ledger", LEDGER,
                                         "manifest.json", expect=None, label="coverage before")

    # 4. the advisory -> the fleet
    run.out["csaf_import"] = run.json("ingest", "csaf-import", "advisory.json", "--ledger", LEDGER,
                                      "--name", "advisory.json", "--url",
                                      "https://controlco.example/csaf/cc-syn-2026-0001.json",
                                      label="csaf import")
    ref = run.out["csaf_import"]["advisory_ref"]
    run.out["impact_before"] = run.json("ingest", "csaf-impact", ref, "--ledger", LEDGER,
                                        expect=1, label="impact before the update")

    # 5. a person records the update; the evidence goes stale; a case opens
    when = (datetime.now(UTC) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (work / "intervention.json").write_text(json.dumps({
        "intervention_id": "INT-SYN-1", "machine_key": KEY, "item_id": fw.item_id,
        "kind": "update", "occurred_at": when,
        "performed_by": {"identifier": "m.tech", "role": "service technician", "kind": "person"},
        "reason": "SYNTHETIC: update to firmware 3.9.0, named as the fix by CC-SYN-2026-0001",
        "from_hash": fw.content_hash, "to_hash": UPDATED_FW,
        "affects_functions": ["SF-01", "SF-02"], "authorization": None, "revalidation": None,
        "notes": ""}), "utf-8")
    run.cli("machinery", "record-change", "--ledger", LEDGER, "--actor", "m.tech",
            "intervention.json", label="record the update")
    run.out["coverage_stale"] = run.cli("machinery", "coverage", "--ledger", LEDGER, "--json",
                                        "manifest.json", expect=1, label="coverage after the change")
    run.cli("change", "assess-intervention", "--ledger", LEDGER, "--manifest", "manifest.json",
            "--intervention-id", "INT-SYN-1", "--actor", "a.integrator", label="open the case")
    case = run.json("change", "list", "--ledger", LEDGER, expect=1,   # 1: a case needs attention
                    label="queue")["cases"][0]
    case_id = run.out["case_id"] = case["case_id"]
    run.cli("change", "claim", case_id, "--ledger", LEDGER, "--owner", "a.integrator",
            "--actor", "a.integrator", label="claim")
    run.cli("change", "advance", case_id, "--ledger", LEDGER, "--actor", "a.integrator", label="advance")
    run.cli("change", "advance", case_id, "--ledger", LEDGER, "--actor", "a.integrator", label="advance")
    run.out["premature_close"] = run.cli(
        "change", "decide", case_id, "--ledger", LEDGER, "--disposition", "closed", "--reason",
        "SYNTHETIC: closing before any re-verification", "--actor", "v.grimaldi", expect=1,
        label="close before re-verification")

    # 6. a re-verification needs a LOOK at the unit, not the declared baseline
    # The case's trigger is the intervention's occurred_at (`when`, now + 1 s, whole seconds). A look
    # taken in that same second predates the change and the product, rightly, refuses it ("predates
    # this case's trigger"). On a fast runner that happened; wait until the clock is past `when`.
    time.sleep(1.2)
    found = SafetyManifest(
        manifest_id="LOOK-1", machine=enrolled.machine, source=ManifestSource.AS_FOUND,
        taken_at=datetime.now(UTC), taken_by=Actor("m.tech", "service technician", "person"),
        method="SYNTHETIC look", functions=enrolled.functions,
        items=tuple(SafetyItem(
            item_id=i.item_id, kind=i.kind, name=i.name, supplier=i.supplier,
            implements=i.implements, hash_source=HashSource.READ_FROM_MACHINE,
            version="3.9.0" if i.item_id == fw.item_id else i.version,
            content_hash=UPDATED_FW if i.item_id == fw.item_id else LIB_LOOKED_AT)
            for i in enrolled.items))
    (work / "found.json").write_text(json.dumps(found.to_dict(), indent=2), "utf-8")
    time.sleep(1.2)                   # the ledger clock has one-second resolution
    after = json.loads((work / "trace-after.json").read_text("utf-8"))
    after["started_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    (work / "trace-after.json").write_text(json.dumps(after), "utf-8")
    bundle = _verify(run, "after", datetime.now(UTC).strftime("%Y-%m-%d"),
                     found.configuration_hash(), "verify after")
    run.out["bundle_after"] = bundle
    verification = bundle["evidence"]["content_hash"]
    run.out["reverify_declared"] = run.cli(
        "change", "reverify", case_id, "--ledger", LEDGER, "--manifest", "manifest.json",
        "--verification-hash", verification, "--actor", "a.integrator", expect=1,
        label="re-verify against the declared manifest")
    run.cli("machinery", "record-manifest", "--ledger", LEDGER, "--actor", "m.tech",
            "found.json", label="record the look")
    run.cli("change", "reverify", case_id, "--ledger", LEDGER, "--manifest", "found.json",
            "--verification-hash", verification, "--actor", "a.integrator", label="re-verify")

    # 7. only a named person closes; automation cannot
    run.out["close_by_automation"] = run.cli(
        "change", "decide", case_id, "--ledger", LEDGER, "--disposition", "closed", "--reason",
        "SYNTHETIC", expect=None, label="close without a name")
    run.cli("change", "decide", case_id, "--ledger", LEDGER, "--disposition", "closed",
            "--reason", "SYNTHETIC: re-verified on the updated firmware", "--actor", "v.grimaldi",
            label="named decision")
    run.out["impact_after"] = run.json("ingest", "csaf-impact", ref, "--ledger", LEDGER,
                                       expect=3, label="impact after the update")
    run.out["coverage_after"] = run.cli("machinery", "coverage", "--ledger", LEDGER, "found.json",
                                        "--json", label="coverage after")
    run.cli("machinery", "passport", "--ledger", LEDGER, "--actor", "v.demo", "found.json",
            "--out", "passport.json", label="passport")

    # 8. independent verification
    run.cli("machinery", "check", "--ledger", LEDGER, "passport.json", label="check passport")
    run.cli("machine", "check", "bundle-after.json", "--envelope", "envelope.json", "--trace",
            "trace-after.json", "--recorder-trust", "trust.json", "--as-of",
            (datetime.now(UTC) + timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z"),
            label="check bundle")
    run.cli("change", "replay", case_id, "--ledger", LEDGER, label="replay the case")
    run.cli("art14", "--ledger", LEDGER, "verify", label="verify the chain")
    return run


# ---- the slice ---------------------------------------------------------------------------
def test_every_step_gave_the_documented_exit(ran):
    wrong = [s for s in ran.steps if s["expected"] is not None and s["exit"] != s["expected"]]
    assert not wrong, wrong
    assert len(ran.steps) > 30


def test_the_draft_enrolled_nothing_and_says_what_it_does_not_establish(ran):
    receipt = ran.out["sbom_import"]
    assert receipt["status"] == "imported" and receipt["review_state"] == "pending_review"
    assert receipt["source"]["name_as_supplied"] == "sbom.json"
    assert any("NOT ASSESSED" in n for n in receipt["does_not_establish"])
    listed = ran.out["fleet_after_draft"]
    assert listed.returncode == 0 and json.loads(listed.stdout)["machines"] == []


def test_the_review_is_refused_for_automation_and_for_the_blank_template(ran):
    assert "named person" in ran.out["review_by_bot"].stderr
    assert "invalid_review" in ran.out["review_blank"].stderr or "not valid" in \
        ran.out["review_blank"].stderr


def test_the_reviewed_manifest_is_declared_with_the_serial_the_person_typed(ran):
    review = ran.out["review"]
    assert review["status"] == "approved" and review["machine"] == KEY
    assert review["enrolment"]["status"] == "enrolled"
    manifest = ran.out["enrolled"]
    assert manifest.machine.serial == "DEMO-0001" and manifest.source is ManifestSource.AS_DECLARED
    assert {i.hash_source for i in manifest.items} == {HashSource.DECLARED}
    assert {i.name for i in manifest.items} == {"Safety controller firmware", "libmotion"}
    assert next(i for i in manifest.items if i.name == "libmotion").implements == ()
    assert next(i for i in manifest.items if i.name.startswith("Safety")
                ).content_hash == FW_SHA
    assert review["tier_ceiling"] == "profile"


def test_a_manifest_that_only_declares_is_not_a_look_at_the_unit(ran):
    assert "not a record of looking at this machine" in not_a_look(ran.out["enrolled"])
    refused = ran.out["reverify_declared"]
    assert "not a record of looking at this machine" in (refused.stdout + refused.stderr)


def test_the_verification_is_bound_to_the_reviewed_configuration(ran):
    body = ran.out["bundle_before"]["evidence"]["body"]
    assert ran.out["review"]["configuration_hash"] in json.dumps(body)
    assert "COVERED" in ran.out["coverage_before"].stdout


def test_the_advisory_is_recorded_unsigned_with_its_publisher(ran):
    rec = ran.out["csaf_import"]
    assert rec["trust"] == "unsigned_inspect_only" and rec["status"] == "imported"
    assert rec["publisher"]["namespace"] == "https://controlco.example"
    assert rec["tracking"]["id"] == "CC-SYN-2026-0001" and rec["tracking"]["version"] == "2"
    assert rec["source"]["url_as_supplied"].endswith("cc-syn-2026-0001.json")


def test_before_the_update_the_machine_is_affected_and_the_library_is_unknown(ran):
    impact = ran.out["impact_before"]
    assert impact["counts"]["affected"] == 1 and impact["machines_affected"] == [KEY]
    items = {i["item_name"]: (i["state"], i["reason_codes"]) for i in impact["machines"][0]["items"]}
    assert items == {"Safety controller firmware": ("affected", []),
                     "libmotion": ("unknown", ["supplier_differs"])}
    assert any("never observed" in c for c in impact["machines"][0]["caveats"])


def test_the_update_leaves_the_evidence_stale_not_covered(ran):
    stale = json.loads(ran.out["coverage_stale"].stdout)
    assert stale["verdict"] == "gaps"
    assert {f["coverage"] for f in stale["functions"]} == {"stale"}


def test_no_case_closes_before_its_re_verification_and_none_without_a_name(ran):
    assert "not ready_to_close" in ran.out["premature_close"].stdout + ran.out["premature_close"].stderr
    nameless = ran.out["close_by_automation"]
    assert nameless.returncode != 0
    assert "named" in (nameless.stdout + nameless.stderr).lower() or \
        "human" in (nameless.stdout + nameless.stderr).lower()


def test_after_the_update_the_result_is_unknown_and_not_a_clear(ran):
    impact = ran.out["impact_after"]
    assert impact["counts"] == {"affected": 0, "under_investigation": 0, "unknown": 1,
                                "fixed": 0, "not_affected": 0}
    machine = impact["machines"][0]
    assert machine["state"] == "unknown" and machine["reason_codes"] == ["supplier_differs"]
    assert {i["item_name"]: i["state"] for i in machine["items"]} == {
        "Safety controller firmware": "fixed", "libmotion": "unknown"}
    assert impact["complete"] is False
    assert machine["configuration_basis"] == "as_found"


def test_the_case_is_closed_by_a_named_person_and_replays(ran):
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", "change", "show", ran.out["case_id"], "--ledger",
         LEDGER, "--json"], cwd=ran.work, capture_output=True, text=True, env=cli_env(),
        check=False)
    case = json.loads(done.stdout)
    assert case["status"] == "closed"
    assert "v.grimaldi" in json.dumps(case)


def test_the_final_position_is_covered_on_a_look_and_the_passport_checks_out(ran):
    final = json.loads(ran.out["coverage_after"].stdout)
    assert final["verdict"] == "covered"
    assert (ran.work / "passport.json").exists()


def test_an_edited_passport_is_rejected_by_the_independent_check(ran):
    text = (ran.work / "passport.json").read_text("utf-8")
    assert '"covered"' in text
    (ran.work / "passport-edited.json").write_text(text.replace('"covered"', '"gaps"', 1), "utf-8")
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", "machinery", "check", "--ledger", LEDGER,
         "passport-edited.json"], cwd=ran.work, capture_output=True, text=True, env=cli_env(),
        check=False)
    assert done.returncode == 1 and "REJECTED" in done.stdout


def test_the_lifecycle_data_is_synthetic_and_names_no_real_party():
    for path in (EXAMPLES / "synthetic-sbom.cdx.json", EXAMPLES / "synthetic-advisory.csaf.json"):
        text = path.read_text("utf-8")
        assert "SYNTHETIC" in text
        assert "Grimaldi" not in text
