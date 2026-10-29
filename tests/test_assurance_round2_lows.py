"""Round-2 findings that are not about the claim map: passport format, severity, watch, copy.

* LOW 1  a passport sealed at ``covered_at_community`` is a NEWER format: an older verifier says
         "schema is ..., expected ..." (an intelligible refusal), never a tamper-style
         "verdict ... implies covered"; a passport sealed by a135c0e still verifies.
* LOW 2  an unchecked/incomplete function is work to do: with a matching advisory the check
         says ``requires_reverification`` (it did on a135c0e, where these read ``failing``).
* LOW 3  ``watch`` calls a function recovered only when it is current at ``validated`` or
         better; current on declared-provenance evidence is recorded, not recovered.
* LOW 4  no copy promises "valid evidence" for cover that may rest on a declared provenance.
* LOW 6  ``seal:false`` says the tier shown was not compared with the ledger.
* F5     killers for survivors of the round-2 mutation pass.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.check.pipeline import run_enrolled_check
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.machine.bundle import build_bundle, check_bundle_data
from assurance.machinery.record import build_passport, record_manifest, verify_passport
from assurance.watch.runner import run_watch

from .support_recorder import server_trust
from .support_trust_hardening import (
    FW,
    KEY,
    attested_bundle,
    community_bundle,
    legacy_bundle,
    manifest,
    reseal_body,
)
from .support_trust_hardening import (
    ledger as make_ledger,
)
from .test_assurance_coverage_states import AUTO, _man, _seal
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_machine_provenance import ACTOR, envelope, laptop_trace
from .test_assurance_recorder_attestation import envelope as att_envelope
from .test_assurance_recorder_attestation import make_trace
from .test_assurance_watch import T0, reexport
from .test_assurance_watch import config as _config
from .test_assurance_watch import ledger as _watch_ledger
from .test_assurance_watch import work as _work

client, store = _client, _store
work, config = _work, _config
ledger = _watch_ledger

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "passport_a135c0e_covered_at_community.json"


# -- LOW 1 -----------------------------------------------------------------------------------

class TestPassportFormat:
    def test_a_passport_written_by_a135c0e_still_verifies(self):
        ok, problems = verify_passport(FIXTURE)
        assert ok, problems
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert raw["schema"] == "assurance.machinery.passport/1"
        assert raw["evidence"]["body"]["verdict"] == "covered"
        assert raw["evidence"]["body"]["evidence_tier_floor"] == "community"

    def test_a_community_cover_is_sealed_in_the_newer_format(self, tmp_path):
        led = make_ledger(tmp_path)
        record_manifest(led, manifest())
        community_bundle(KEY, file_under=led)
        out = tmp_path / "p.json"
        build_passport(led, manifest(), actor=ACTOR).write(out)
        raw = json.loads(out.read_text(encoding="utf-8"))
        # not the old schema: an older verifier refuses it by name ("schema is ... expected ...")
        # instead of reporting that the verdict "implies covered"
        assert raw["schema"] == "assurance.machinery.passport/2"
        assert raw["evidence"]["body"]["verdict"] == "covered_at_community"
        ok, problems = verify_passport(out)
        assert ok, problems

    def test_the_older_format_is_unchanged_for_covers_it_could_express(self, tmp_path):
        led = make_ledger(tmp_path)
        record_manifest(led, manifest())
        attested_bundle(KEY, file_under=led)
        raw = build_passport(led, manifest(), actor=ACTOR, seal=False).to_dict()
        assert raw["schema"] == "assurance.machinery.passport/1"

        gaps = make_ledger(tmp_path, "g.db")
        record_manifest(gaps, manifest())
        assert build_passport(gaps, manifest(), actor=ACTOR, seal=False).to_dict()["schema"] \
            == "assurance.machinery.passport/1"

    def test_a_newer_verdict_inside_the_older_schema_is_refused(self, tmp_path):
        from assurance.core.evidence import Evidence
        led = make_ledger(tmp_path)
        record_manifest(led, manifest())
        community_bundle(KEY, file_under=led)
        raw = json.loads(json.dumps(build_passport(led, manifest(), actor=ACTOR,
                                                   seal=False).to_dict()))
        raw["schema"] = "assurance.machinery.passport/1"
        raw["evidence"]["body"]["schema"] = "assurance.machinery.passport/1"
        raw["evidence"]["content_hash"] = Evidence.from_dict(raw["evidence"]).compute_hash()
        path = tmp_path / "mixed.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        ok, problems = verify_passport(path)
        assert ok is False and any("passport/2" in p for p in problems)


# -- LOW 2 -----------------------------------------------------------------------------------

def _advisory_for_the_firmware():
    return ComponentAdvisory(
        advisory_id="ADV-1", issued_by="vendor", title="t", summary="s",
        issued_at=datetime(2026, 10, 1, tzinfo=UTC),
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(supplier="x", name="fw", versions=("1",),
                                   content_hashes=(FW,)),),
        reference="https://example.invalid/adv-1")


def test_an_unchecked_function_with_a_matching_advisory_requires_reverification(tmp_path):
    led = make_ledger(tmp_path)
    record_manifest(led, _man())
    _seal(led, AUTO)                  # speed_limit left unchecked: F-STOP unchecked, F-BOTH incomplete
    d = run_enrolled_check(led, KEY, _advisory_for_the_firmware()).to_dict()
    assert d["matches"], "the advisory must match the firmware item"
    by_id = {f["function_id"]: f["coverage"] for f in d["functions"]}
    assert by_id["F-STOP"] == "unchecked" and by_id["F-BOTH"] == "incomplete"
    assert {"F-STOP", "F-BOTH"} <= set(d["required_actions"])
    assert d["verdict"] == "requires_reverification"


def test_a_never_verified_function_is_still_insufficient_not_required_work(tmp_path):
    led = make_ledger(tmp_path)
    record_manifest(led, manifest())
    d = run_enrolled_check(led, KEY, None).to_dict()
    assert d["required_actions"] == [] and d["verdict"] == "insufficient_evidence"


# -- LOW 3 -----------------------------------------------------------------------------------

def _runner_envelope_and_trace():
    from assurance.machine.envelope import (
        FigureBasis,
        SafetyEnvelope,
        SensingUncertainty,
        StopPerformance,
        Workspace,
    )
    from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
    env = SafetyEnvelope(
        envelope_id="E", product="AR-7", product_version="1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.1, 0.25, 120.0, 500.0, FigureBasis("measured", "S1", "2026-01-01")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "C1")),
        intrusion_distance_mm=850.0)
    trace = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="fw",
                  started_at=T0 + timedelta(days=1), sample_rate_hz=50.0,
                  samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=400.0,
                                       mode=OperatingMode.SSM, separation=2200.0)
                                for i in range(10)))
    return env, trace


@pytest.mark.parametrize("attested, recovered", [(False, False), (True, True)])
def test_watch_calls_a_function_recovered_only_at_validated(
        work, config, ledger, attested, recovered):
    from .support_recorder import build_attested_bundle
    run_watch(config, ledger, now=T0)
    env, trace = _runner_envelope_and_trace()
    seal = build_attested_bundle if attested else build_bundle
    seal(env, trace, actor=ACTOR, ledger=ledger, subject="Grimaldi/AR-7#0412")
    reexport(work, "0412")
    reexport(work, "0501")
    run = run_watch(config, ledger, now=T0 + timedelta(days=7))
    o = next(x for x in run.outcomes if x.serial == "0412")
    if recovered:
        assert set(o.recovered) == {"SF-01", "SF-02"} and o.still_uncovered == ()
    else:
        assert o.recovered == ()
        assert set(o.still_uncovered) == {"SF-01", "SF-02"}      # recorded, not recovered
        assert o.newly_uncovered == ()


# -- LOW 4 -----------------------------------------------------------------------------------

@pytest.mark.parametrize("relative", [
    "src/assurance/machinery/cli.py", "src/assurance/machinery/__init__.py",
    "src/assurance/machinery/staleness.py", "src/assurance/report/render.py",
    "src/assurance/api/machinery_routes.py", "src/assurance/api/service.py",
    "app/lib/routes.ts", "app/lib/solutions.ts", "public/openapi.json",
])
def test_no_copy_promises_valid_evidence_for_cover_that_may_be_declared(relative):
    text = (ROOT / relative).read_text(encoding="utf-8")
    assert not re.search(r"(still have|covered by|without) valid evidence", text, re.I), relative


# -- LOW 6 -----------------------------------------------------------------------------------

class TestUnsealedVerify:
    @staticmethod
    def _post(client, headers, seal):
        env, tr = att_envelope(), make_trace()
        from .support_recorder import with_attestation
        body = with_attestation({
            "envelope": env.to_dict(), "trace": tr.hashable_payload(),
            "actor": "a.integrator", "subject": KEY, "seal": seal}, env, tr,
            machine_serial="0001")
        return client.post("/v1/machine/verify", json=body, headers=headers)

    def test_an_unsealed_unit_key_verification_says_the_ledger_was_not_consulted(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        unsealed = self._post(client, h, False).json()
        assert unsealed["sealed"] is False
        assert "not compared with the ledger" in unsealed["unit_binding_note"]
        sealed = self._post(client, h, True).json()
        assert sealed["sealed"] is True and "unit_binding_note" not in sealed


# -- F5 killers ------------------------------------------------------------------------------

class TestKillers:
    def test_a_serial_only_copy_filed_under_another_unit_blocks_nothing(self, tmp_path):
        led = make_ledger(tmp_path)
        record_manifest(led, manifest("Beta", "XY-9", "0002"))
        record_manifest(led, manifest())
        from assurance.machine.recorder_attestation import RecorderTrust  # noqa: F401
        stray, rec = legacy_bundle("0002")
        led.append(stray.evidence, subject="Beta/XY-9#0002")
        sealed, _ = attested_bundle(KEY, rec=rec, file_under=led)
        assert sealed.tier.value == "validated"

    def test_a_community_copy_under_another_enrolled_unit_blocks_nothing(self, tmp_path):
        led = make_ledger(tmp_path)
        record_manifest(led, manifest("Beta", "XY-9", "0002"))
        record_manifest(led, manifest())
        community_bundle("Beta/XY-9#0002", file_under=led)
        sealed, _ = attested_bundle(KEY, file_under=led)
        assert sealed.tier.value == "validated"

    def test_the_community_caveat_is_only_for_community_cover(self, tmp_path):
        text = "only on evidence at tier"
        weak = make_ledger(tmp_path, "w.db")
        record_manifest(weak, manifest())
        community_bundle(KEY, file_under=weak)
        assert any(text in c for c in build_passport(
            weak, manifest(), actor=ACTOR, seal=False).evidence.checks_skipped)
        strong = make_ledger(tmp_path, "s.db")
        record_manifest(strong, manifest())
        attested_bundle(KEY, file_under=strong)
        assert not any(text in c for c in build_passport(
            strong, manifest(), actor=ACTOR, seal=False).evidence.checks_skipped)

    def test_a_zero_function_manifest_reports_no_coverage_assessed(self, client, store):
        from datetime import UTC, datetime

        from assurance.fleet.declaration import DeclarationOfConformity
        man = manifest(functions=False)
        doc = DeclarationOfConformity.bind(
            man, doc_id="D", issued_by="G", issued_at=datetime(2026, 1, 20, tzinfo=UTC),
            legislation=("Regulation (EU) 2023/1230",))
        r = client.post("/v1/fleet/declaration/check", json={
            "declaration": doc.to_dict(), "manifest": man.to_dict(), "with_coverage": True},
            headers=keyed(store, "cell"))
        assert r.json()["coverage_assessed"] is False
        assert r.json()["evidence_assessed"] is False

    @pytest.mark.parametrize("bad", ["Cell@1.0.0", "no-hash-at-all"])
    def test_a_unit_key_with_no_hash_is_rejected_by_the_checker(self, bad):
        bundle = build_bundle(envelope(), laptop_trace(), actor=ACTOR)
        forged = reseal_body(bundle.evidence, unit_key=bad)
        raw = {**bundle.to_dict(), "evidence": forged.to_dict()}
        check = check_bundle_data(raw)
        assert check.ok is False
        assert any("not a unit key" in p for p in check.problems)

    def test_a_unit_key_that_is_not_text_reads_community_by_tier_alone(self, tmp_path):
        from assurance.evidence.ledger import EvidenceLedger
        from assurance.machinery.staleness import VerificationRecord
        bundle, rec = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, unit_key=[KEY])
        led = EvidenceLedger(tmp_path / "x.db")
        led.append(forged, subject=KEY)
        tiers = [r.tier for r in VerificationRecord.from_ledger(
            led, subject=KEY, recorder_trust=rec.trust())]
        assert tiers == ["community"]
