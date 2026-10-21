"""Matching an advisory to a machine, and joining evidence to changes by date.

Two ways to be wrong, and only one is survivable. An advisory that matches
something it should not costs an engineer ten minutes. An advisory that fails to
match what it should — because the supplier's name arrived in a different
Unicode form, the hash was upper-cased, or one of two entries for the same
component was read first — clears a cell that should have been stopped.
"""

from __future__ import annotations

import itertools
import unicodedata
from datetime import UTC, datetime, timedelta, timezone

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.divergence import compare
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import record_manifest
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

ENG = Actor("a.integrator", "safety engineer")
TECH = Actor("m.tech", "service technician")

AFFECTED = "1" * 64
FIXED = "3" * 64
OTHER = "2" * 64

FUNCS = (
    SafetyFunction("SF-01", "Protective stop", "PL d",
                   verified_by=("ssm_separation", "stop_characterisation")),
    SafetyFunction("SF-02", "Speed limit", "PL d", verified_by=("speed_limit",)),
)


def item(version="3.8.2", content_hash=AFFECTED, source=None,
         supplier="ControlCo", name="Safety controller firmware", **over):
    if source is None:
        source = HashSource.READ_FROM_MACHINE if content_hash else HashSource.DECLARED
    kw = {"item_id": "ITM-FW", "kind": ItemKind.FIRMWARE, "name": name,
          "version": version, "content_hash": content_hash, "hash_source": source,
          "supplier": supplier, "implements": ("SF-01", "SF-02")}
    kw.update(over)
    return SafetyItem(**kw)


def artefact(**over):
    kw = {"supplier": "ControlCo", "name": "Safety controller firmware",
          "versions": ("3.8.2",), "content_hashes": (AFFECTED,)}
    kw.update(over)
    return AffectedArtefact(**kw)


def advisory(*affected, **over):
    kw = {"advisory_id": "A-1", "issued_by": "ControlCo",
          "issued_at": datetime(2026, 9, 12, tzinfo=UTC), "title": "t", "summary": "s",
          "severity": AdvisorySeverity.SAFETY_RELEVANT,
          "affected": affected or (artefact(),),
          "reference": "https://controlco.example/a-1",
          "fixed_versions": ("3.9.0",), "fixed_hashes": (FIXED,)}
    kw.update(over)
    return ComponentAdvisory(**kw)


def basis(adv, it):
    m = match_item(adv, it)
    return m[0] if m else None


# =====================================================================
# the same string in a different form must still match
# =====================================================================

class TestIdentityOfNames:
    def test_composed_and_decomposed_unicode_are_the_same_supplier(self):
        composed = unicodedata.normalize("NFC", "Müller Sicherheit")
        decomposed = unicodedata.normalize("NFD", "Müller Sicherheit")
        assert composed != decomposed
        adv = advisory(artefact(supplier=composed))
        assert basis(adv, item(supplier=decomposed)) is MatchBasis.HASH

    def test_case_folding_is_unicode_aware(self):
        adv = advisory(artefact(supplier="Straße Automation"))
        assert basis(adv, item(supplier="STRASSE AUTOMATION")) is MatchBasis.HASH

    def test_compatibility_forms_are_the_same_supplier(self):
        adv = advisory(artefact(supplier="ControlCo"))
        assert basis(adv, item(supplier="ＣｏｎｔｒｏｌＣｏ")) is MatchBasis.HASH

    @pytest.mark.parametrize("variant", [
        " ControlCo", "ControlCo ", "\tControlCo\n", "Control Co".replace(
            "Control Co", "ControlCo "),
    ])
    def test_surrounding_whitespace_of_any_kind_is_ignored(self, variant):
        assert basis(advisory(), item(supplier=variant)) is MatchBasis.HASH

    def test_runs_of_internal_whitespace_collapse(self):
        adv = advisory(artefact(name="Safety  controller\tfirmware"))
        assert basis(adv, item()) is MatchBasis.HASH

    def test_it_is_still_not_fuzzy(self):
        assert match_item(advisory(), item(supplier="Control Co GmbH")) is None
        assert match_item(advisory(), item(supplier="ControlCo2")) is None
        assert match_item(advisory(), item(name="Safety controller firmware v2")) is None

    def test_a_name_that_differs_only_by_an_invisible_character_is_not_called_equal(self):
        """Zero-width characters are not whitespace; they are a different string."""
        assert match_item(advisory(), item(supplier="Control​Co")) is None


class TestIdentityOfHashes:
    def test_an_uppercase_hash_is_the_same_hash(self):
        assert basis(advisory(), item(content_hash=AFFECTED.upper())) is MatchBasis.HASH
        up = advisory(artefact(content_hashes=("A" * 64,)))
        assert basis(up, item(content_hash="a" * 64)) is MatchBasis.HASH

    def test_surrounding_whitespace_and_an_algorithm_prefix_are_ignored(self):
        assert basis(advisory(), item(content_hash=f" sha256:{AFFECTED}\n")) \
            is MatchBasis.HASH

    def test_a_prefix_of_the_published_hash_is_not_a_match(self):
        """The first twelve characters are for display. Matching on them would let a
        truncated or colliding value stand for the artefact."""
        short = AFFECTED[:12]
        b = basis(advisory(), item(content_hash=short))
        assert b is not MatchBasis.HASH

    def test_a_longer_value_with_the_published_hash_as_prefix_is_not_a_match(self):
        b = basis(advisory(), item(content_hash=AFFECTED + "00"))
        assert b is not MatchBasis.HASH

    def test_a_version_label_is_compared_case_and_space_insensitively(self):
        adv = advisory(artefact(versions=("3.8.2-RC1",), content_hashes=()))
        assert basis(adv, item(version=" 3.8.2-rc1 ", content_hash="")) is MatchBasis.VERSION

    def test_version_matching_is_still_exact_in_substance(self):
        adv = advisory(artefact(versions=("3.8.2",), content_hashes=()))
        for other in ("3.8", "v3.8.2", "3.8.20", "3.8.2.1"):
            assert basis(adv, item(version=other, content_hash="")) \
                is not MatchBasis.VERSION, other


class TestEmptyValuesNeverMatchEverything:
    def test_an_empty_version_in_an_advisory_is_refused(self):
        with pytest.raises(AdvisoryError, match="empty"):
            artefact(versions=("",), content_hashes=())

    def test_a_blank_hash_in_an_advisory_is_refused(self):
        with pytest.raises(AdvisoryError, match="empty"):
            artefact(versions=(), content_hashes=("   ",))

    def test_a_blank_fixed_hash_is_refused(self):
        with pytest.raises(AdvisoryError, match="empty"):
            advisory(fixed_hashes=("",))

    def test_a_blank_fixed_version_is_refused(self):
        with pytest.raises(AdvisoryError, match="empty"):
            advisory(fixed_versions=(" ",))

    def test_an_item_with_no_hash_never_matches_on_hash(self):
        adv = advisory(artefact(versions=(), content_hashes=(AFFECTED,)))
        assert basis(adv, item(content_hash="", version="",
                               source=HashSource.DECLARED)) is MatchBasis.NAME_ONLY

    def test_an_item_with_no_version_never_matches_on_a_label(self):
        adv = advisory(artefact(content_hashes=()))
        assert basis(adv, item(version="", content_hash="")) is MatchBasis.NAME_ONLY


# =====================================================================
# a hash that was not read off this machine says nothing about this machine
# =====================================================================

class TestOnlyAMachineReadHashIsEvidenceAboutTheMachine:
    @pytest.mark.parametrize("source", [HashSource.SUPPLIED_BY_VENDOR,
                                        HashSource.DECLARED])
    def test_a_hash_from_a_vendor_file_is_not_byte_identical_to_anything_on_the_machine(
            self, source):
        b = basis(advisory(), item(source=source))
        assert b is not MatchBasis.HASH
        assert b is MatchBasis.VERSION       # the label still matches

    @pytest.mark.parametrize("source", [HashSource.SUPPLIED_BY_VENDOR,
                                        HashSource.DECLARED])
    def test_a_vendor_hash_cannot_contradict_the_label_either(self, source):
        """Hash mismatch means 'the machine is not running what it says'. A hash the
        machine never produced cannot say that."""
        b = basis(advisory(), item(source=source, content_hash=OTHER))
        assert b is not MatchBasis.HASH_MISMATCH
        assert b is MatchBasis.VERSION

    def test_the_detail_says_why_the_hash_was_set_aside(self):
        m = match_item(advisory(), item(source=HashSource.SUPPLIED_BY_VENDOR))
        assert m is not None
        assert "not read from this machine" in m[1]

    def test_a_machine_read_hash_still_confirms(self):
        assert basis(advisory(), item()) is MatchBasis.HASH


# =====================================================================
# hash_mismatch semantics, and the whole grid
# =====================================================================

class TestAffectedClearOrNeither:
    def test_label_affected_hash_contradicts_published_hash_is_mismatch(self):
        assert basis(advisory(), item(content_hash=OTHER)) is MatchBasis.HASH_MISMATCH

    def test_label_affected_hash_is_a_fixed_hash_is_mismatch_even_with_no_published_hash(
            self):
        """Label says affected, artefact says fixed: contradictory, not 'probably
        affected'. It used to be reported as VERSION when the advisory published no
        affected hashes."""
        adv = advisory(artefact(content_hashes=()))
        assert basis(adv, item(content_hash=FIXED)) is MatchBasis.HASH_MISMATCH

    def test_label_clear_but_hash_affected_is_a_hash_match(self):
        assert basis(advisory(), item(version="9.9.9")) is MatchBasis.HASH

    def test_label_fixed_and_hash_fixed_is_clear(self):
        assert match_item(advisory(), item(version="3.9.0", content_hash=FIXED)) is None

    def test_label_fixed_with_an_unlisted_hash_is_clear_on_the_label(self):
        assert match_item(advisory(), item(version="3.9.0", content_hash=OTHER)) is None

    def test_a_version_both_affected_and_fixed_is_treated_as_affected(self):
        adv = advisory(artefact(content_hashes=()), fixed_versions=("3.8.2",))
        assert basis(adv, item(content_hash="")) is MatchBasis.VERSION

    def test_the_grid_agrees_with_an_independent_table(self):
        versions = {"affected": "3.8.2", "fixed": "3.9.0", "other": "4.1.0", "none": ""}
        hashes = {"affected": AFFECTED, "fixed": FIXED, "other": OTHER, "none": ""}
        for publishes, (v, h) in itertools.product(
                (True, False), itertools.product(versions, hashes)):
            adv = advisory(artefact(content_hashes=(AFFECTED,) if publishes else ()))
            it = item(version=versions[v], content_hash=hashes[h],
                      source=(HashSource.READ_FROM_MACHINE if hashes[h]
                              else HashSource.DECLARED))
            got = basis(adv, it)

            # the expectation, from the module's stated order of evidence
            if h == "affected" and publishes:
                want = MatchBasis.HASH
            elif v == "affected":
                if h != "none" and (publishes or h == "fixed"):
                    want = MatchBasis.HASH_MISMATCH
                else:
                    want = MatchBasis.VERSION
            elif h == "fixed":
                want = None
            elif v in ("fixed", "other"):
                want = None
            else:
                want = MatchBasis.NAME_ONLY
            assert got is want, (publishes, v, h, got, want)


class TestOrderOfAdvisoryEntriesDoesNotChangeTheAnswer:
    def entries(self):
        return (
            artefact(versions=("1.0",), content_hashes=()),
            artefact(versions=("3.8.2",), content_hashes=()),
            artefact(versions=(), content_hashes=(AFFECTED,)),
            artefact(versions=("7.7",), content_hashes=(OTHER,)),
        )

    def test_every_permutation_of_the_entries_gives_the_same_basis(self):
        it = item()
        results = {basis(advisory(*perm), it)
                   for perm in itertools.permutations(self.entries())}
        assert results == {MatchBasis.HASH}

    def test_a_label_only_entry_first_does_not_hide_a_hash_entry(self):
        a = artefact(versions=("3.8.2",), content_hashes=())
        b = artefact(versions=(), content_hashes=(AFFECTED,))
        assert basis(advisory(a, b), item()) is MatchBasis.HASH
        assert basis(advisory(b, a), item()) is MatchBasis.HASH

    def test_a_name_only_entry_first_does_not_hide_a_hash_entry(self):
        """An item with no version recorded: entry one can only say 'possible'."""
        a = artefact(versions=("3.8.2",), content_hashes=())
        b = artefact(versions=(), content_hashes=(AFFECTED,))
        it = item(version="")
        assert basis(advisory(a, b), it) is MatchBasis.HASH
        assert basis(advisory(b, a), it) is MatchBasis.HASH

    def test_the_stronger_basis_wins_in_the_documented_order(self):
        mismatch = artefact(versions=("3.8.2",), content_hashes=(OTHER,))
        version = artefact(versions=("3.8.2",), content_hashes=())
        name = artefact(versions=("1.0",), content_hashes=())
        it = item(content_hash="9" * 64)
        assert basis(advisory(name, version, mismatch), it) is MatchBasis.HASH_MISMATCH
        assert basis(advisory(mismatch, version, name), it) is MatchBasis.HASH_MISMATCH

    def test_one_clear_entry_does_not_clear_a_component_another_entry_matches(self):
        clear = artefact(versions=("1.0",), content_hashes=())
        hit = artefact(versions=("3.8.2",), content_hashes=())
        assert basis(advisory(clear, hit), item(content_hash="")) is MatchBasis.VERSION
        assert basis(advisory(hit, clear), item(content_hash="")) is MatchBasis.VERSION


# =====================================================================
# the fleet: the same item id on two machines is two exposures
# =====================================================================

def manifest(serial, it, site="Plant 2"):
    return SafetyManifest(
        manifest_id=f"MAN-{serial}",
        machine=MachineIdentity("Grimaldi", "AR-7", serial, site=site),
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 9, 1, tzinfo=UTC),
        taken_by=ENG, items=(it,), functions=FUNCS, method="read")


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "f.db")


class TestImpactAcrossMachines:
    def test_the_same_item_id_on_two_machines_is_two_independent_exposures(self, ledger):
        record_manifest(ledger, manifest("0412", item(content_hash=AFFECTED)))
        record_manifest(ledger, manifest("0413", item(version="3.9.0",
                                                      content_hash=FIXED)))
        record_manifest(ledger, manifest("0414", item(content_hash=OTHER)))
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        by_machine = {e.machine_key: e for e in r.exposures}
        assert set(by_machine) == {"Grimaldi/AR-7#0412", "Grimaldi/AR-7#0414"}
        assert by_machine["Grimaldi/AR-7#0412"].basis is MatchBasis.HASH
        assert by_machine["Grimaldi/AR-7#0414"].basis is MatchBasis.HASH_MISMATCH
        assert r.machines_in_fleet == 3

    def test_a_clear_machine_does_not_clear_its_neighbour(self, ledger):
        record_manifest(ledger, manifest("0413", item(version="3.9.0",
                                                      content_hash=FIXED)))
        record_manifest(ledger, manifest("0412", item(content_hash=AFFECTED)))
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.machines_affected == ("Grimaldi/AR-7#0412",)

    def test_a_ledger_chain_that_does_not_verify_is_never_reported_clear(
            self, ledger, monkeypatch):
        record_manifest(ledger, manifest("0620", item(version="3.9.0", content_hash=FIXED)))
        fleet = Fleet.from_ledger(ledger)
        broken = Fleet(records=fleet.records, chain_verified=False,
                       chain_problems=("entry 3 does not chain",))
        r = assess_impact(advisory(), broken)
        assert r.exposures == ()
        assert r.verdict != "clear"
        assert any("DOES NOT VERIFY" in c for c in r.checks_skipped)
        assert "chain" in r.summary().lower()

    def test_an_empty_fleet_says_nothing_was_assessed(self, ledger):
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.machines_in_fleet == 0
        assert any("no machine" in c.lower() and "assessed" in c.lower()
                   for c in r.checks_skipped)


# =====================================================================
# coverage: what counts as a verification of a function
# =====================================================================

def vrec(seq, at, verified, not_verified=(), tier="validated", verdict="pass", **kw):
    return VerificationRecord(
        content_hash=f"{seq:064x}", effective_at=at, ledger_seq=seq, product="AR-7",
        product_version="2.4.1", verdict=verdict, tier=tier,
        checks_verified=tuple(verified), checks_not_verified=tuple(not_verified), **kw)


def man():
    return manifest("0412", item())


def interv(at, **over):
    kw = {"intervention_id": "INT-1", "machine_key": "Grimaldi/AR-7#0412",
          "item_id": "ITM-FW", "kind": InterventionKind.UPDATE, "occurred_at": at,
          "performed_by": TECH, "reason": "update", "from_hash": "a" * 64,
          "to_hash": "d" * 64, "affects_functions": ("SF-01", "SF-02")}
    kw.update(over)
    return Intervention(**kw)


FEB = datetime(2026, 2, 9, tzinfo=UTC)
MAR = datetime(2026, 3, 14, 9, 30, tzinfo=UTC)
APR = datetime(2026, 4, 20, tzinfo=UTC)


def cov(report, fid):
    return next(f for f in report.functions if f.function_id == fid)


class TestAFunctionIsCoveredOnlyByItsWholeSetOfChecks:
    def test_verifying_one_of_two_declared_checks_does_not_cover_the_function(self):
        """SF-01 declares ssm_separation AND stop_characterisation. The old rule
        treated any overlap as cover."""
        v = vrec(1, FEB, verified=("stop_characterisation", "speed_limit"),
                 not_verified=("ssm_separation",), verdict="fail")
        r = assess_coverage(man(), [v], [])
        assert cov(r, "SF-01").coverage is not Coverage.CURRENT
        assert cov(r, "SF-01").coverage is Coverage.FAILING
        assert cov(r, "SF-02").coverage is Coverage.CURRENT

    def test_all_declared_checks_verified_is_cover(self):
        v = vrec(1, FEB, verified=("ssm_separation", "stop_characterisation",
                                   "speed_limit"))
        assert cov(assess_coverage(man(), [v], []), "SF-01").coverage is Coverage.CURRENT

    def test_a_later_failing_run_of_the_same_checks_ends_the_cover(self):
        good = vrec(1, FEB, verified=("ssm_separation", "stop_characterisation",
                                      "speed_limit"))
        bad = vrec(2, APR, verified=("stop_characterisation", "speed_limit"),
                   not_verified=("ssm_separation",), verdict="fail")
        r = assess_coverage(man(), [good, bad], [])
        assert cov(r, "SF-01").coverage is Coverage.FAILING
        assert cov(r, "SF-02").coverage is Coverage.CURRENT

    def test_a_still_later_passing_run_restores_it(self):
        good = vrec(1, FEB, verified=("ssm_separation", "stop_characterisation"))
        bad = vrec(2, MAR, verified=("stop_characterisation",),
                   not_verified=("ssm_separation",), verdict="fail")
        good2 = vrec(3, APR, verified=("ssm_separation", "stop_characterisation"))
        assert cov(assess_coverage(man(), [good, bad, good2], []),
                   "SF-01").coverage is Coverage.CURRENT

    def test_a_function_is_only_as_current_as_the_oldest_run_it_rests_on(self):
        """ssm_separation verified in February, stop_characterisation in April, a
        change in March: the February evidence predates the change, so the function
        is not covered even though the newest run is after it."""
        a = vrec(1, FEB, verified=("ssm_separation",))
        b = vrec(2, APR, verified=("stop_characterisation",))
        r = assess_coverage(man(), [a, b], [interv(MAR)])
        assert cov(r, "SF-01").coverage is Coverage.STALE
        assert cov(r, "SF-01").last_verified_hash == a.content_hash

    def test_two_separate_runs_can_together_cover_a_function(self):
        a = vrec(1, FEB, verified=("ssm_separation",), not_verified=("speed_limit",))
        b = vrec(2, MAR, verified=("stop_characterisation",))
        assert cov(assess_coverage(man(), [a, b], []), "SF-01").coverage \
            is Coverage.CURRENT

    def test_a_check_that_was_not_applicable_in_a_later_run_does_not_undo_cover(self):
        """not_applicable is 'this trace never entered the regime', not a failure.
        The record cannot tell it from a failure, so it must not be able to END
        cover either way: only a violated or unchecked outcome does."""
        a = vrec(1, FEB, verified=("ssm_separation", "stop_characterisation"))
        b = vrec(2, APR, verified=("stop_characterisation",),
                 not_verified=("ssm_separation",),
                 checks_not_applicable=("ssm_separation",), verdict="pass")
        assert cov(assess_coverage(man(), [a, b], []), "SF-01").coverage \
            is Coverage.CURRENT

    def test_a_cover_resting_on_a_simulation_is_labelled_as_such(self):
        v = vrec(1, FEB, verified=("ssm_separation", "stop_characterisation"),
                 tier="community")
        r = assess_coverage(man(), [v], [])
        assert any("simulat" in c.lower() or "community" in c.lower()
                   for c in r.checks_skipped)
        assert "community" in cov(r, "SF-01").detail


class TestDatingTheJoin:
    def test_an_intervention_at_the_very_instant_the_trace_began_is_not_cover(self):
        v = vrec(1, MAR, verified=("ssm_separation", "stop_characterisation"))
        r = assess_coverage(man(), [v], [interv(MAR)])
        assert cov(r, "SF-01").coverage is Coverage.STALE

    def test_one_second_after_the_intervention_is_cover(self):
        v = vrec(1, MAR + timedelta(seconds=1),
                 verified=("ssm_separation", "stop_characterisation"))
        assert cov(assess_coverage(man(), [v], [interv(MAR)]), "SF-01").coverage \
            is Coverage.CURRENT

    def test_a_naive_effective_time_is_refused_not_compared(self):
        with pytest.raises(ValueError, match="timezone"):
            vrec(1, datetime(2026, 2, 9), verified=("ssm_separation",))

    def test_offsets_are_compared_as_instants_not_as_wall_clock(self):
        rome = timezone(timedelta(hours=2))
        # 03:00+02:00 is 01:00Z, which is BEFORE 02:00Z although '03' > '02'.
        change = datetime(2026, 10, 25, 3, 0, tzinfo=rome)
        verified_at = datetime(2026, 10, 25, 2, 0, tzinfo=UTC)
        v = vrec(1, verified_at, verified=("ssm_separation", "stop_characterisation"))
        assert cov(assess_coverage(man(), [v], [interv(change)]), "SF-01").coverage \
            is Coverage.CURRENT

    def test_the_repeated_hour_at_the_end_of_dst_orders_by_instant(self):
        # Europe/Rome 2026-10-25 02:30 happens twice: +02:00 (00:30Z) then +01:00 (01:30Z)
        first = datetime(2026, 10, 25, 0, 30, tzinfo=UTC)    # 02:30+02:00
        second = datetime(2026, 10, 25, 1, 30, tzinfo=UTC)   # 02:30+01:00
        v = vrec(1, second, verified=("ssm_separation", "stop_characterisation"))
        assert cov(assess_coverage(man(), [v], [interv(first)]), "SF-01").coverage \
            is Coverage.CURRENT
        v2 = vrec(2, first, verified=("ssm_separation", "stop_characterisation"))
        assert cov(assess_coverage(man(), [v2], [interv(second)]), "SF-01").coverage \
            is Coverage.STALE

    @pytest.mark.parametrize("year", [1970, 1999, 2099, 9999])
    def test_extreme_dates_do_not_crash_and_are_ordered_correctly(self, year):
        at = datetime(year, 1, 1, tzinfo=UTC)
        v = vrec(1, at, verified=("ssm_separation", "stop_characterisation"))
        r = assess_coverage(man(), [v], [interv(MAR)])
        want = Coverage.CURRENT if at > MAR else Coverage.STALE
        assert cov(r, "SF-01").coverage is want
        r.to_dict()
        r.summary()

    def test_a_trace_dated_after_it_was_filed_cannot_outrun_a_change_filed_before_it(
            self, ledger):
        """From the ledger: a trace that claims to start in 2099 was filed today. An
        intervention recorded before today must not read as older than the trace."""
        from assurance.machine.bundle import build_bundle
        from assurance.machine.envelope import (
            FigureBasis,
            SafetyEnvelope,
            SensingUncertainty,
            StopPerformance,
            Workspace,
        )
        from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
        from assurance.machinery.record import record_intervention

        m = man()
        record_manifest(ledger, m)
        env = SafetyEnvelope(
            envelope_id="E", product="AR-7", product_version="2.4.1",
            workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
            max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
            stop=StopPerformance(0.1, 0.25, 120.0, 500.0, FigureBasis("measured", "S-1")),
            uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "C-3")),
            intrusion_distance_mm=850.0)
        run = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="fw",
                    started_at=datetime(2099, 1, 1, tzinfo=UTC), sample_rate_hz=50.0,
                    samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0),
                                         tcp_speed=400.0, mode=OperatingMode.SSM,
                                         separation=2200.0) for i in range(10)))
        record_intervention(ledger, interv(datetime.now(UTC) - timedelta(days=1)))
        build_bundle(env, run, actor=ENG, ledger=ledger, subject=m.machine.key)
        vfs = VerificationRecord.from_ledger(ledger, subject=m.machine.key)
        assert len(vfs) == 1
        assert vfs[0].effective_at <= datetime.now(UTC) + timedelta(days=1)
        assert vfs[0].date_suspect
        ivs = [interv(datetime.now(UTC) - timedelta(days=1))]
        r = assess_coverage(m, vfs, ivs)
        assert cov(r, "SF-01").coverage is Coverage.STALE
        assert any("filed" in c and "start" in c for c in r.checks_skipped)

    def test_an_unreadable_effective_date_in_a_resealed_record_is_treated_as_unknown(
            self, ledger):
        from assurance.core.evidence import Evidence, Origin
        from assurance.machine.bundle import BUNDLE_KIND

        ev = Evidence(kind=BUNDLE_KIND,
                      body={"trace_started_at": "not a date", "product": "AR-7",
                            "product_version": "2.4.1", "verdict": "pass",
                            "tier": "validated",
                            "checks": [{"name": "ssm_separation", "outcome": "verified"},
                                       {"name": "stop_characterisation",
                                        "outcome": "verified"}]},
                      actor=ENG, origin=Origin(system="x")).seal()
        ledger.append(ev, subject="Grimaldi/AR-7#0412")
        (v,) = VerificationRecord.from_ledger(ledger, subject="Grimaldi/AR-7#0412")
        assert v.date_suspect
        r = assess_coverage(man(), [v], [interv(MAR)])
        assert cov(r, "SF-01").coverage is Coverage.STALE


# =====================================================================
# divergence: 'matches' must mean something was compared
# =====================================================================

def man_with(it, source=ManifestSource.AS_FOUND, serial="0412"):
    return SafetyManifest(
        manifest_id="M", machine=MachineIdentity("Grimaldi", "AR-7", serial),
        source=source, taken_at=datetime(2026, 9, 1, tzinfo=UTC), taken_by=ENG,
        items=(it,), functions=FUNCS, method="read")


class TestMatchesMeansSomethingWasCompared:
    def test_two_hashed_machine_reads_that_agree_match(self):
        d = compare(man_with(item(), ManifestSource.AS_DECLARED), man_with(item()))
        assert d.verdict == "matches"

    def test_an_item_with_no_hash_on_either_side_is_not_called_a_match(self):
        it = item(content_hash="", source=HashSource.DECLARED)
        d = compare(man_with(it, ManifestSource.AS_DECLARED), man_with(it))
        assert d.verdict == "unverifiable"
        assert d.verdict != "matches"
        assert d.uncompared

    def test_one_unhashed_item_among_matching_ones_still_blocks_a_clean_match(self):
        a = SafetyManifest(
            manifest_id="M", machine=MachineIdentity("Grimaldi", "AR-7", "0412"),
            source=ManifestSource.AS_DECLARED, taken_at=datetime(2026, 9, 1, tzinfo=UTC),
            taken_by=ENG, functions=FUNCS, method="r",
            items=(item(), item(item_id="ITM-X", content_hash="",
                                source=HashSource.DECLARED, implements=())))
        b = SafetyManifest(
            manifest_id="M2", machine=a.machine, source=ManifestSource.AS_FOUND,
            taken_at=datetime(2026, 9, 2, tzinfo=UTC), taken_by=ENG, functions=FUNCS,
            method="r", items=a.items)
        assert compare(a, b).verdict == "unverifiable"

    def test_an_observed_hash_that_was_not_read_from_the_machine_is_not_a_match(self):
        obs = item(source=HashSource.SUPPLIED_BY_VENDOR)
        d = compare(man_with(item(), ManifestSource.AS_DECLARED), man_with(obs))
        assert d.verdict == "unverifiable"

    def test_two_declarations_compared_are_not_a_match_about_the_machine(self):
        d = compare(man_with(item(), ManifestSource.AS_DECLARED),
                    man_with(item(), ManifestSource.AS_DECLARED))
        assert d.verdict == "unverifiable"

    def test_a_real_change_still_outranks_unverifiable(self):
        it = item(content_hash="", source=HashSource.DECLARED)
        changed = item(content_hash=OTHER)
        d = compare(man_with(it, ManifestSource.AS_DECLARED), man_with(changed))
        assert d.verdict in ("drifted", "safety_relevant_drift")

    def test_the_cli_exit_code_is_nonzero_for_unverifiable(self, tmp_path):
        from assurance.machinery.cli import main
        it = item(content_hash="", source=HashSource.DECLARED)
        a, b = tmp_path / "a.json", tmp_path / "b.json"
        a.write_text(__import__("json").dumps(
            man_with(it, ManifestSource.AS_DECLARED).to_dict()), encoding="utf-8")
        b.write_text(__import__("json").dumps(man_with(it).to_dict()), encoding="utf-8")
        assert main(["diff", "--baseline", str(a), "--observed", str(b)]) != 0

    def test_it_is_sealed_as_indeterminate_not_verified(self, ledger):
        from assurance.core.evidence import ValidationState
        from assurance.machinery.record import record_divergence
        it = item(content_hash="", source=HashSource.DECLARED)
        d = compare(man_with(it, ManifestSource.AS_DECLARED), man_with(it))
        ev = record_divergence(ledger, d, actor=ENG)
        assert ev.validation_state is ValidationState.INDETERMINATE
