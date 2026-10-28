"""Features that landed separately must still hold together.

The unit-binding / tier-cap work (a bundle is validated only for the unit key it was sealed
for; one recording is one unit's) and the staleness-integrity work (a record the reader cannot
use is a stand-in assumed to have failed; a broken chain is never cover; an unsigned CSAF import
is inspect-only) were written apart and met in one merge. Each test names an interaction and
holds an invariant that neither side's own tests could state alone:

* a damaged or tampered record never reads as covered or current, and never takes the whole
  read down (the claim map walks every bundle, so it must tolerate the row it cannot parse);
* a chain that does not verify is never cover, validated or community, in the fleet, the
  passport and the check;
* the unit-binding tier caps still apply, and an unchecked / incomplete function is still
  work to do, after the merge;
* an unsigned CSAF import is described as such wherever it meets a stale or capped function;
* the fleet read stays linear in connections even when every machine holds a claim.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime

from assurance.check import AssuranceVerdict, run_enrolled_check
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.csaf import advisory_from_csaf
from assurance.fleet.registry import Fleet
from assurance.machine.bundle import BUNDLE_KIND
from assurance.machinery.manifest import SafetyFunction
from assurance.machinery.record import (
    MANIFEST_KIND,
    build_passport,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import (
    Coverage,
    UnitClaims,
    VerificationRecord,
    assess_coverage,
)

from .support_recorder import Recorder
from .support_trust_hardening import (
    KEY,
    attested_bundle,
    community_bundle,
    ledger,
    manifest,
    seal_fleet,
    serial_of,
)
from .test_assurance_machine_provenance import ACTOR, laptop_trace

TECH = Actor("t", "tech")


def _sql(led: EvidenceLedger, sql: str, *args) -> list:
    db = sqlite3.connect(led.path)
    try:
        rows = db.execute(sql, args).fetchall()
        db.commit()
        return rows
    finally:
        db.close()


def _row_seq(led, key: str, kind: str = BUNDLE_KIND) -> int:
    return _sql(led, "select seq from chain where subject=? and kind=?", key, kind)[0][0]


def _break_the_chain(led: EvidenceLedger) -> None:
    """Edit an unrelated record in place: the chain no longer verifies."""
    led.append(Evidence(kind="test.unrelated", body={"x": 1}, actor=TECH,
                        origin=Origin(system="test")).seal(), subject="unrelated")
    seq = led.entries()[-1].seq
    (payload,) = _sql(led, "select payload from chain where seq=?", seq)[0]
    p = json.loads(payload)
    p["body"]["x"] = 2
    _sql(led, "update chain set payload=? where seq=?",
         json.dumps(p, sort_keys=True, separators=(",", ":")), seq)
    assert led.verify_chain()[0] is False


def _validated_unit(tmp_path, key: str = KEY):
    """An enrolled unit whose one function rests on a validated, unit-bound recording."""
    led = ledger(tmp_path)
    serial = serial_of(key)
    record_manifest(led, manifest(serial=serial))
    bundle, rec = attested_bundle(key, file_under=led)
    assert bundle.tier.value == "validated"
    return led, rec


# =====================================================================
# 1. A damaged record for a unit-bound recording
# =====================================================================

class TestADamagedBundleOfAUnitBoundRecording:
    def _fleet_with_one_damaged_bundle(self, tmp_path, how):
        led = ledger(tmp_path)
        rec = seal_fleet(led, 3)
        victim = "Acme/AR-7#00001"
        seq = _row_seq(led, victim)
        if how == "not_json":
            _sql(led, "update chain set payload=? where seq=?", "this is not json", seq)
        else:                      # valid JSON, seal broken
            (payload,) = _sql(led, "select payload from chain where seq=?", seq)[0]
            p = json.loads(payload)
            p["body"]["verdict"] = "pass-edited"
            _sql(led, "update chain set payload=? where seq=?",
                 json.dumps(p, sort_keys=True, separators=(",", ":")), seq)
        return led, rec, victim

    def test_a_non_json_bundle_row_does_not_take_the_claim_map_down(self, tmp_path):
        led, rec, _ = self._fleet_with_one_damaged_bundle(tmp_path, "not_json")
        # the one shared walk over every bundle, and the per-machine read, both survive it
        claims = UnitClaims.build(led, rec.trust())
        assert claims.holder("0" * 64) is None
        fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
        assert len(fleet) == 3

    def test_a_damaged_bundle_is_failing_never_current(self, tmp_path):
        for how in ("not_json", "bad_seal"):
            led, rec, victim = self._fleet_with_one_damaged_bundle(_sub(tmp_path, how), how)
            fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
            hurt = fleet.record(victim)
            (fn,) = hurt.coverage.functions
            assert fn.coverage is Coverage.FAILING, how
            assert "damaged" in fn.detail
            assert hurt.verdict == "gaps"
            # and a damaged record is a stand-in, not a validated claim of anything
            (stand_in,) = hurt.verifications
            assert stand_in.unreadable and stand_in.tier == ""

    def test_the_damage_also_breaks_the_chain_so_no_machine_is_covered(self, tmp_path):
        led, rec, _ = self._fleet_with_one_damaged_bundle(tmp_path, "not_json")
        fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
        assert fleet.chain_verified is False
        summary = fleet.summary()
        assert summary.covered == 0 and summary.covered_at_community == 0
        assert summary.with_gaps == 3

    def test_a_damaged_row_neither_enrols_a_unit_nor_holds_a_recording(self, tmp_path):
        led, rec = _validated_unit(tmp_path)
        trace_hash = led.entries(kind=BUNDLE_KIND)[0].payload["body"]["trace_hash"]
        assert UnitClaims.build(led, rec.trust()).holder(trace_hash) == (
            led.entries(kind=BUNDLE_KIND)[0].seq, KEY)
        _sql(led, "update chain set payload=? where kind=?", "not json", MANIFEST_KIND)
        # the manifest that enrolled the unit is unreadable: it enrols nothing, and the read
        # survives it
        assert UnitClaims.build(led, rec.trust()).holder(trace_hash) is None

    def test_a_damaged_newest_record_ends_a_validated_cover(self, tmp_path):
        """Unit-bound cover is current; a later record the reader cannot use is assumed to
        have failed, and is not 'unchecked' (an unusable record said nothing, it did not
        decline to judge)."""
        led, rec = _validated_unit(tmp_path)
        man = manifest()
        report = assess_coverage(
            man, VerificationRecord.from_ledger(led, subject=KEY, recorder_trust=rec.trust()),
            [])
        assert report.verdict == "covered"
        good = VerificationRecord.from_ledger(led, subject=KEY, recorder_trust=rec.trust())
        filed = good[0].filed_at
        stand_in = VerificationRecord(
            content_hash="d" * 64, effective_at=filed, ledger_seq=good[0].ledger_seq + 1,
            product="", product_version="", verdict="unreadable", tier="",
            checks_verified=(), filed_at=filed.replace(year=filed.year + 1),
            unreadable=True, unreadable_why="the stored payload is not JSON")
        broken = assess_coverage(man, [*good, stand_in], [])
        assert broken.verdict == "gaps"
        (fn,) = broken.functions
        assert fn.coverage is Coverage.FAILING and fn.coverage not in (
            Coverage.UNCHECKED, Coverage.INCOMPLETE)

    def test_an_unchecked_run_is_still_required_work_and_a_damaged_one_is_failing(
            self, tmp_path):
        base = manifest(checks=("speed_limit",))
        man = replace(base, functions=(SafetyFunction(
            "SF-1", "safe stop", verified_by=("speed_limit", "workspace_containment")),))
        filed = datetime(2026, 10, 1, tzinfo=UTC)

        def run(seq, *, verified=(), unchecked=(), unreadable=False):
            return VerificationRecord(
                content_hash=f"{seq:064x}", effective_at=filed, ledger_seq=seq,
                product="AR-7", product_version="1", verdict="unreadable" if unreadable else "x",
                tier="" if unreadable else "validated", checks_verified=tuple(verified),
                checks_not_verified=tuple(unchecked), checks_unchecked=tuple(unchecked),
                filed_at=filed, unreadable=unreadable)

        partial = assess_coverage(man, [run(1, verified=["speed_limit"],
                                            unchecked=["workspace_containment"])], [])
        assert partial.functions[0].coverage is Coverage.INCOMPLETE
        assert partial.verdict == "gaps"
        later = filed.replace(day=2)
        damaged = replace(run(2, unreadable=True), filed_at=later, effective_at=later)
        both = assess_coverage(man, [run(1, verified=["speed_limit"],
                                         unchecked=["workspace_containment"]), damaged], [])
        assert both.functions[0].coverage is Coverage.FAILING


def _sub(tmp_path, name):
    path = tmp_path / name
    path.mkdir()
    return path


# =====================================================================
# 2. A broken chain with unit-bound cover
# =====================================================================

class TestABrokenChainWithUnitBoundCover:
    def test_control_a_whole_chain_passport_is_covered(self, tmp_path):
        led, rec = _validated_unit(tmp_path)
        passport = build_passport(led, manifest(), actor=ACTOR, seal=False,
                                  recorder_trust=rec.trust())
        assert passport.verdict == "covered"
        assert passport.to_dict()["schema"].endswith("/1")
        assert passport.evidence.validation_state.value == "verified"

    def test_the_passport_of_a_broken_chain_is_not_covered_and_says_why(self, tmp_path):
        led, rec = _validated_unit(tmp_path)
        _break_the_chain(led)
        passport = build_passport(led, manifest(), actor=ACTOR, seal=False,
                                  recorder_trust=rec.trust())
        assert passport.coverage.verdict == "covered"        # what the rows alone read
        assert passport.verdict == "ledger_chain_not_verified"
        assert passport.to_dict()["schema"].endswith("/2")
        assert passport.evidence.validation_state.value != "verified"
        assert passport.evidence.confidence.value not in ("high", "established")
        written = passport.write(tmp_path / "p.json")
        ok, problems = verify_passport(written)
        assert not ok and any("chain did not verify" in p for p in problems)

    def test_the_fleet_row_of_a_broken_chain_is_gaps_for_either_kind_of_cover(self, tmp_path):
        led = ledger(tmp_path)
        rec = Recorder()
        # unit 0001 is validated; unit 0002 holds a bundle sealed for another key: capped
        record_manifest(led, manifest(serial="0001"))
        record_manifest(led, manifest(serial="0002"))
        bundle, rec = attested_bundle(KEY, rec=rec, file_under=led)
        capped = community_bundle("Acme/AR-7#0002", file_under=led)
        assert bundle.tier.value == "validated" and capped.tier.value == "community"
        healthy = Fleet.from_ledger(led, recorder_trust=rec.trust())
        assert healthy.record(KEY).verdict == "covered"
        assert healthy.record("Acme/AR-7#0002").verdict == "covered_at_community"
        assert healthy.summary().covered == 1
        assert healthy.summary().covered_at_community == 1
        _break_the_chain(led)
        broken = Fleet.from_ledger(led, recorder_trust=rec.trust())
        assert broken.record(KEY).verdict == "gaps"
        assert broken.record("Acme/AR-7#0002").verdict == "gaps"
        assert {r.machine_key for r in broken.with_gaps()} == {KEY, "Acme/AR-7#0002"}
        assert broken.covered_at_community() == ()
        s = broken.summary()
        assert (s.covered, s.covered_at_community, s.with_gaps) == (0, 0, 2)

    def test_the_check_of_a_broken_chain_is_cannot_determine_not_verified(self, tmp_path):
        led, rec = _validated_unit(tmp_path)
        assert run_enrolled_check(led, KEY, recorder_trust=rec.trust()).verdict is \
            AssuranceVerdict.VERIFIED
        _break_the_chain(led)
        result = run_enrolled_check(led, KEY, recorder_trust=rec.trust())
        assert result.verdict is AssuranceVerdict.CANNOT_DETERMINE

    def test_fleet_list_exits_2_on_a_broken_chain_even_with_only_cover(self, tmp_path, capsys):
        from assurance.fleet.cli import main

        led, rec = _validated_unit(tmp_path)
        assert main(["list", "--ledger", str(led.path)]) in (0, 3)
        _break_the_chain(led)
        capsys.readouterr()
        assert main(["list", "--ledger", str(led.path)]) == 2


# =====================================================================
# 3. The unit-binding caps still apply to the rows the new readers return
# =====================================================================

class TestTheTierCapsSurviveTheNewReader:
    def test_a_bundle_filed_under_another_unit_is_community_with_its_reason(self, tmp_path):
        led = ledger(tmp_path)
        record_manifest(led, manifest(serial="0002"))
        bundle, rec = attested_bundle(KEY)
        led.append(bundle.evidence, subject="Acme/AR-7#0002")
        (rec_,) = VerificationRecord.from_ledger(
            led, subject="Acme/AR-7#0002", recorder_trust=rec.trust())
        assert rec_.tier == "community" and rec_.tier_note
        row = Fleet.from_ledger(led, recorder_trust=rec.trust()).record("Acme/AR-7#0002")
        assert row.verdict == "covered_at_community"
        assert row.to_row()["tier_notes"] == [rec_.tier_note]

    def test_the_second_claimant_of_a_recording_is_capped_with_the_holder_named(
            self, tmp_path):
        led = ledger(tmp_path)
        rec, tr = Recorder(), laptop_trace()
        for serial in ("0001", "0002"):
            record_manifest(led, manifest(serial=serial))
        first, _ = attested_bundle(KEY, rec=rec, trace=tr)
        led.append(first.evidence, subject=KEY)
        second, _ = attested_bundle("Acme/AR-7#0002", rec=rec, trace=tr)
        led.append(second.evidence, subject="Acme/AR-7#0002")
        fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
        assert fleet.record(KEY).verdict == "covered"
        later = fleet.record("Acme/AR-7#0002")
        assert later.verdict == "covered_at_community"
        assert KEY in later.to_row()["tier_notes"][0]

    def test_fleet_reads_stay_linear_in_connections_when_every_machine_holds_a_claim(
            self, tmp_path, monkeypatch):
        machines = 12
        led = ledger(tmp_path)
        rec = seal_fleet(led, machines)
        opened = {"n": 0}
        real = EvidenceLedger._connect

        def counting(self):
            opened["n"] += 1
            return real(self)

        monkeypatch.setattr(EvidenceLedger, "_connect", counting)
        fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
        assert fleet.summary().covered == machines
        assert opened["n"] <= 4 * machines + 10, opened


# =====================================================================
# 4. An unsigned CSAF import against a stale or capped function
# =====================================================================

VENDOR = "ControlCo"


def _csaf(*, partial=False, version="3.8.2", product="Safety controller firmware"):
    tree = [{"category": "product_name", "name": product,
             "branches": [{"category": "product_version", "name": version,
                           "product": {"product_id": "A", "name": f"fw {version}"}}]}]
    affected = ["A", "B"] if partial else ["A"]
    document = {
        "document": {
            "csaf_version": "2.0", "category": "csaf_security_advisory",
            "title": "SYNTHETIC advisory",
            "publisher": {"name": VENDOR, "category": "vendor",
                          "namespace": "https://example.invalid"},
            "tracking": {"id": "CTRL-2026-77", "status": "final", "version": "1",
                         "initial_release_date": "2026-10-01T00:00:00Z",
                         "current_release_date": "2026-10-02T08:30:00Z"},
            "references": [{"category": "self", "url": "https://example.invalid/x"}],
        },
        "product_tree": {"branches": [{"category": "vendor", "name": VENDOR,
                                       "branches": tree}]},
        "vulnerabilities": [{"cve": "CVE-2026-0001",
                             "product_status": {"known_affected": affected}}],
    }
    if partial:
        document["product_tree"]["full_product_names"] = [
            {"product_id": "B", "name": f"{VENDOR} Other 1.0"}]
    return advisory_from_csaf(document).advisory


class TestAnUnsignedCsafImportMeetsStaleAndCappedCover:
    def _enrolled_with_a_stale_function(self, tmp_path):
        from .test_assurance_check import enrol

        led = EvidenceLedger(tmp_path / "check.db")
        enrol(led, "0412", intervene=True)
        return led

    def test_a_matching_import_against_a_stale_function_requires_reverification(
            self, tmp_path):
        led = self._enrolled_with_a_stale_function(tmp_path)
        advisory = _csaf()
        assert advisory.import_record is not None
        result = run_enrolled_check(led, "Grimaldi/AR-7#0412", advisory)
        assert result.verdict is AssuranceVerdict.REQUIRES_REVERIFICATION
        assert result.advisory_import is not None
        assert any("unsigned CSAF import" in c for c in result.checks_skipped)
        assert "SF-01" in result.required_actions

    def test_a_partial_import_with_no_match_is_never_no_impact_on_a_capped_machine(
            self, tmp_path):
        """The machine's evidence is community only (a recording the filer declared); the
        advisory is a partial translation. 'Nothing matched' is neither 'no impact' nor
        'verified'."""
        from .test_assurance_check import enrol

        led = EvidenceLedger(tmp_path / "check.db")
        enrol(led, "0412")          # sealed with a declared (community) provenance
        no_match = _csaf(partial=True, product="Pendant firmware")
        assert no_match.import_record is not None and no_match.import_record.partial
        result = run_enrolled_check(led, "Grimaldi/AR-7#0412", no_match)
        assert result.incomplete is True
        assert result.verdict is AssuranceVerdict.CANNOT_DETERMINE
        assert result.verdict not in (AssuranceVerdict.NO_IMPACT_FOUND,
                                      AssuranceVerdict.VERIFIED,
                                      AssuranceVerdict.VERIFIED_AT_COMMUNITY)

    def test_a_partial_import_on_a_broken_chain_is_cannot_determine(self, tmp_path):
        from .test_assurance_check import enrol

        led = EvidenceLedger(tmp_path / "check.db")
        enrol(led, "0412")
        _break_the_chain(led)
        no_match = _csaf(partial=True, product="Pendant firmware")
        result = run_enrolled_check(led, "Grimaldi/AR-7#0412", no_match)
        assert result.verdict is AssuranceVerdict.CANNOT_DETERMINE
        assert result.incomplete is True
