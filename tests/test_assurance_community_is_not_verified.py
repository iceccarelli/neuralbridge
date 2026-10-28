"""Evidence whose provenance the filer merely declared must not read ``verified``/``covered``.

Regression (independent review of a135c0e, finding M1): a function whose cover rests on a
``community`` verification (a trace whose provenance the filer DECLARED; the engine caps it
there) surfaced as ``verified`` in the check pipeline (``_decide_verdict`` took no tier), as
``covered`` in the fleet summary (``registry.py``) and in ``FleetPanel`` ("N with every
declared safety function covered"), carried no tier in the fleet row, and the offline
``machinery coverage`` printed the tier but exited 0.

The states, below ``validated``:

* ``CoverageReport.verdict``  ``covered_at_community``  (not ``covered``)
* check pipeline verdict       ``verified_at_community`` (not ``verified``)
* fleet summary                ``covered`` counts validated-or-better cover only;
                               ``covered_at_community`` counts the rest
* CLI exit codes               0 only for demonstrated cover; 3 for cover at community
                               (1 gaps, 2 could not vouch for the ledger / error)
* declaration check            ``configuration_intact_evidence_below_validated``

``current`` for a function still means "the recorded evidence still stands"; it is not a
claim the behaviour was demonstrated on the machine.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.check.pipeline import run_enrolled_check
from assurance.fleet.cli import main as fleet_cli
from assurance.fleet.declaration import DeclarationOfConformity, check_declaration
from assurance.fleet.registry import Fleet
from assurance.machinery.cli import main as machinery_cli
from assurance.machinery.record import (
    build_passport,
    interventions_from_ledger,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import VerificationRecord, assess_coverage

from .support_recorder import server_trust, with_attestation
from .support_trust_hardening import (
    KEY,
    attested_bundle,
    community_bundle,
    ledger,
    manifest,
)
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_machine_provenance import ACTOR
from .test_assurance_recorder_attestation import envelope as att_envelope
from .test_assurance_recorder_attestation import make_trace

client, store = _client, _store


def _community_ledger(tmp_path):
    led = ledger(tmp_path)
    record_manifest(led, manifest())
    b = community_bundle(KEY, file_under=led)
    assert b.tier.value == "community"
    return led


def _validated_ledger(tmp_path):
    led = ledger(tmp_path)
    record_manifest(led, manifest())
    b, _ = attested_bundle(KEY, file_under=led)
    assert b.tier.value == "validated"
    return led


def _coverage(led):
    return assess_coverage(manifest(), VerificationRecord.from_ledger(led, subject=KEY),
                           interventions_from_ledger(led, KEY))


class TestCoverageVerdict:
    def test_community_cover_is_covered_at_community(self, tmp_path):
        report = _coverage(_community_ledger(tmp_path))
        assert report.verdict == "covered_at_community"
        assert report.to_dict()["verdict"] == "covered_at_community"
        assert report.evidence_tier_floor == "community"
        assert [f.coverage.value for f in report.functions] == ["current"]
        assert report.functions[0].evidence_tier == "community"

    def test_validated_cover_is_covered(self, tmp_path):
        report = _coverage(_validated_ledger(tmp_path))
        assert report.verdict == "covered"
        assert report.evidence_tier_floor == "validated"
        assert report.functions[0].evidence_tier == "validated"

    def test_the_summary_text_does_not_say_covered_for_community(self, tmp_path):
        text = _coverage(_community_ledger(tmp_path)).summary()
        assert text.splitlines()[0].endswith("COVERED_AT_COMMUNITY")

    def test_a_gap_stays_a_gap_whatever_the_tier(self, tmp_path):
        led = ledger(tmp_path)
        record_manifest(led, manifest(checks=("workspace_containment", "speed_limit",
                                              "ssm_separation")))
        community_bundle(KEY, file_under=led)
        report = assess_coverage(
            manifest(checks=("workspace_containment", "speed_limit", "ssm_separation")),
            VerificationRecord.from_ledger(led, subject=KEY), [])
        assert report.verdict == "gaps"


class TestThePassport:
    def test_a_community_passport_says_covered_at_community_and_is_not_verified(
            self, tmp_path):
        led = _community_ledger(tmp_path)
        passport = build_passport(led, manifest(), actor=ACTOR, seal=False)
        assert passport.verdict == "covered_at_community"
        assert passport.evidence.validation_state.value == "indeterminate"
        assert passport.evidence.confidence.value == "low"

    def test_a_sealed_community_passport_checks_out(self, tmp_path):
        led = _community_ledger(tmp_path)
        passport = build_passport(led, manifest(), actor=ACTOR)
        out = tmp_path / "passport.json"
        passport.write(out)
        ok, problems = verify_passport(out, ledger=led)
        assert ok, problems

    def test_a_validated_passport_is_verified_with_high_confidence(self, tmp_path):
        led = _validated_ledger(tmp_path)
        passport = build_passport(led, manifest(), actor=ACTOR, seal=False)
        assert passport.verdict == "covered"
        assert passport.evidence.validation_state.value == "verified"

    def test_a_passport_sealed_before_the_state_existed_still_checks(self, tmp_path):
        """A passport filed by the previous release recorded verdict 'covered' beside a
        community floor and was already INDETERMINATE / low. It is not rejected for that."""
        from assurance.core.evidence import Evidence
        led = _community_ledger(tmp_path)
        passport = build_passport(led, manifest(), actor=ACTOR, seal=False)
        raw = json.loads(json.dumps(passport.to_dict()))
        raw["evidence"]["body"]["verdict"] = "covered"
        raw["coverage"]["verdict"] = "covered"
        raw["evidence"]["content_hash"] = Evidence.from_dict(raw["evidence"]).compute_hash()
        path = tmp_path / "old.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        ok, problems = verify_passport(path)
        assert ok, problems


class TestTheCheckPipeline:
    def test_community_cover_is_verified_at_community(self, tmp_path):
        led = _community_ledger(tmp_path)
        r = run_enrolled_check(led, KEY, None)
        d = r.to_dict()
        assert d["verdict"] == "verified_at_community"
        assert d["verdict"] != "verified"
        assert d["affected"] is False
        assert d["evidence"]["valid"] == 0
        assert d["evidence"]["valid_below_validated"] == 1
        assert d["evidence"]["tier_floor"] == "community"
        assert r.verdict.value == "verified_at_community"

    def test_validated_cover_is_verified(self, tmp_path):
        d = run_enrolled_check(_validated_ledger(tmp_path), KEY, None).to_dict()
        assert d["verdict"] == "verified"
        assert d["evidence"]["valid"] == 1
        assert d["evidence"]["valid_below_validated"] == 0
        assert d["evidence"]["tier_floor"] == "validated"

    def test_the_verdict_ranks_below_verified_and_above_every_finding(self):
        from assurance.check.pipeline import AssuranceVerdict
        v = AssuranceVerdict
        assert v.VERIFIED_AT_COMMUNITY.rank < v.VERIFIED.rank
        assert v.VERIFIED_AT_COMMUNITY.rank > v.NO_IMPACT_FOUND.rank

    def test_an_advisory_that_matches_nothing_is_unaffected_by_the_tier(self, tmp_path):
        from datetime import UTC, datetime

        from assurance.fleet.advisory import (
            AdvisorySeverity,
            AffectedArtefact,
            ComponentAdvisory,
        )
        adv = ComponentAdvisory(
            advisory_id="ADV-1", issued_by="vendor", title="x", summary="x",
            issued_at=datetime(2026, 10, 1, tzinfo=UTC),
            severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(supplier="Nobody", name="nothing-here",
                                       versions=("9.9",)),),
            reference="https://example.invalid/adv-1")
        d = run_enrolled_check(_community_ledger(tmp_path), KEY, adv).to_dict()
        assert d["verdict"] == "no_impact_found"


class TestTheFleet:
    def test_community_cover_is_not_counted_as_covered(self, tmp_path):
        fleet = Fleet.from_ledger(_community_ledger(tmp_path))
        s = fleet.summary().to_dict()
        assert s["covered"] == 0
        assert s["covered_at_community"] == 1
        assert s["with_gaps"] == 0
        assert s["machines"] == s["covered"] + s["covered_at_community"] + s["with_gaps"]
        row = fleet.to_dict()["machines"][0]
        assert row["verdict"] == "covered_at_community"
        assert row["evidence_tier_floor"] == "community"

    def test_validated_cover_is_counted_as_covered(self, tmp_path):
        fleet = Fleet.from_ledger(_validated_ledger(tmp_path))
        s = fleet.summary().to_dict()
        assert (s["covered"], s["covered_at_community"], s["with_gaps"]) == (1, 0, 0)
        assert fleet.to_dict()["machines"][0]["evidence_tier_floor"] == "validated"

    def test_a_machine_with_a_gap_is_a_gap(self, tmp_path):
        led = ledger(tmp_path)
        record_manifest(led, manifest())
        s = Fleet.from_ledger(led).summary().to_dict()
        assert (s["covered"], s["covered_at_community"], s["with_gaps"]) == (0, 0, 1)
        assert Fleet.from_ledger(led).to_dict()["machines"][0]["evidence_tier_floor"] == ""

    def test_the_table_does_not_say_covered_for_community(self, tmp_path):
        table = Fleet.from_ledger(_community_ledger(tmp_path)).table()
        assert "1 covered at community" in table
        assert "0 covered," in table


class TestTheDeclaration:
    def test_community_cover_does_not_describe_the_machine(self, tmp_path):
        man = manifest()
        doc = DeclarationOfConformity.bind(
            man, doc_id="DOC-1", issued_by="G",
            issued_at=datetime(2026, 10, 1, tzinfo=UTC), legislation=("Regulation (EU) 2023/1230",))
        s = check_declaration(doc, man, _coverage(_community_ledger(tmp_path)))
        assert s.verdict.value == "configuration_intact_evidence_below_validated"
        assert s.is_sound is False
        assert s.evidence_assessed is True
        assert s.lapsed_functions == ()
        assert "community" in s.statement

    def test_validated_cover_still_describes_the_machine(self, tmp_path):
        man = manifest()
        doc = DeclarationOfConformity.bind(
            man, doc_id="DOC-1", issued_by="G",
            issued_at=datetime(2026, 10, 1, tzinfo=UTC), legislation=("Regulation (EU) 2023/1230",))
        s = check_declaration(doc, man, _coverage(_validated_ledger(tmp_path)))
        assert s.verdict.value == "describes_the_machine"


class TestTheCliExitCodes:
    def _manifest_file(self, tmp_path: Path) -> Path:
        p = tmp_path / "manifest.json"
        p.write_text(json.dumps(manifest().to_dict()), encoding="utf-8")
        return p

    def _db(self, tmp_path: Path) -> str:
        return str(tmp_path / "ledger.db")

    def test_machinery_coverage_exit_3_for_community(self, tmp_path, capsys):
        _community_ledger(tmp_path)
        rc = machinery_cli(["coverage", str(self._manifest_file(tmp_path)),
                            "--ledger", self._db(tmp_path), "--json"])
        assert json.loads(capsys.readouterr().out)["verdict"] == "covered_at_community"
        assert rc == 3

    def test_machinery_coverage_exit_0_for_validated(self, tmp_path, capsys):
        _validated_ledger(tmp_path)
        rc = machinery_cli(["coverage", str(self._manifest_file(tmp_path)),
                            "--ledger", self._db(tmp_path), "--json"])
        assert json.loads(capsys.readouterr().out)["verdict"] == "covered"
        assert rc == 0

    def test_machinery_coverage_exit_1_for_a_gap(self, tmp_path, capsys):
        led = ledger(tmp_path)
        record_manifest(led, manifest())
        rc = machinery_cli(["coverage", str(self._manifest_file(tmp_path)),
                            "--ledger", self._db(tmp_path), "--json"])
        assert json.loads(capsys.readouterr().out)["verdict"] == "gaps"
        assert rc == 1

    def test_machinery_passport_exit_3_for_community(self, tmp_path, capsys):
        _community_ledger(tmp_path)
        rc = machinery_cli(["passport", str(self._manifest_file(tmp_path)),
                            "--ledger", self._db(tmp_path), "--actor", "a.i",
                            "--no-seal", "--json"])
        assert json.loads(capsys.readouterr().out)["coverage"]["verdict"] \
            == "covered_at_community"
        assert rc == 3

    def test_fleet_list_exit_3_for_community_and_0_for_validated(self, tmp_path, capsys):
        _community_ledger(tmp_path)
        rc = fleet_cli(["list", "--ledger", self._db(tmp_path), "--json"])
        assert json.loads(capsys.readouterr().out)["summary"]["covered_at_community"] == 1
        assert rc == 3
        other = tmp_path / "v"
        other.mkdir()
        _validated_ledger(other)
        rc = fleet_cli(["list", "--ledger", str(other / "ledger.db"), "--json"])
        assert json.loads(capsys.readouterr().out)["summary"]["covered"] == 1
        assert rc == 0

    def test_the_coverage_text_says_covered_at_community(self, tmp_path, capsys):
        _community_ledger(tmp_path)
        machinery_cli(["coverage", str(self._manifest_file(tmp_path)),
                       "--ledger", self._db(tmp_path)])
        assert "COVERED_AT_COMMUNITY" in capsys.readouterr().out.splitlines()[0]


class TestTheHostedApi:
    def _community(self, client, headers):
        env, tr = att_envelope(), make_trace()
        assert client.post("/v1/machinery/manifest", json={"manifest": manifest().to_dict()},
                           headers=headers).status_code == 200
        r = client.post("/v1/machine/verify", json={
            "envelope": env.to_dict(), "trace": tr.hashable_payload(),
            "actor": "a.integrator", "subject": KEY}, headers=headers)
        assert r.status_code == 200 and r.json()["tier"] == "community"

    def _validated(self, client, headers):
        env, tr = att_envelope(), make_trace()
        assert client.post("/v1/machinery/manifest", json={"manifest": manifest().to_dict()},
                           headers=headers).status_code == 200
        r = client.post("/v1/machine/verify", json=with_attestation({
            "envelope": env.to_dict(), "trace": tr.hashable_payload(),
            "actor": "a.integrator", "subject": KEY}, env, tr, machine_serial="0001"),
            headers=headers)
        assert r.status_code == 200 and r.json()["tier"] == "validated"

    def test_every_reader_says_covered_at_community(self, client, store, monkeypatch,
                                                    tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        self._community(client, h)
        cov = client.post("/v1/machinery/coverage", json={"manifest": manifest().to_dict()},
                          headers=h).json()
        assert cov["verdict"] == "covered_at_community"
        assert cov["evidence_tier_floor"] == "community"
        fleet = client.get("/v1/fleet/machines", headers=h).json()
        assert fleet["summary"]["covered"] == 0
        assert fleet["summary"]["covered_at_community"] == 1
        assert fleet["machines"][0]["evidence_tier_floor"] == "community"
        chk = client.post("/v1/check/fleet-machine", json={"machine_key": KEY},
                          headers=h).json()
        assert chk["verdict"] == "verified_at_community"
        assert chk["evidence"]["tier_floor"] == "community"
        pp = client.post("/v1/machinery/passport", json={
            "manifest": manifest().to_dict(), "actor": "a.i", "seal": False},
            headers=h).json()
        assert pp["coverage"]["verdict"] == "covered_at_community"

    def test_control_validated_evidence_reads_covered(self, client, store, monkeypatch,
                                                      tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        self._validated(client, h)
        assert client.post("/v1/machinery/coverage", json={"manifest": manifest().to_dict()},
                           headers=h).json()["verdict"] == "covered"
        s = client.get("/v1/fleet/machines", headers=h).json()["summary"]
        assert (s["covered"], s["covered_at_community"]) == (1, 0)
        assert client.post("/v1/check/fleet-machine", json={"machine_key": KEY},
                           headers=h).json()["verdict"] == "verified"


@pytest.mark.parametrize("tier,expected", [
    ("profile", "covered_at_community"), ("community", "covered_at_community"),
    ("validated", "covered"), ("certified", "covered"),
])
def test_the_verdict_follows_the_tier_floor(tier, expected):
    rec = VerificationRecord(
        content_hash="a" * 64, effective_at=datetime(2026, 9, 14, tzinfo=UTC), ledger_seq=1,
        product="p", product_version="1", verdict="pass", tier=tier,
        checks_verified=("workspace_containment", "speed_limit"), checks_not_verified=())
    assert assess_coverage(manifest(), [rec], []).verdict == expected
