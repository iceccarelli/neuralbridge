"""A verification can state which configuration it was run against (red-team B8, additive).

``VerificationRecord`` had no manifest binding: whether a pass still described the machine was
judged by timestamps alone. A bundle may now carry an OPTIONAL ``configuration_hash``. When it
is present and differs from the manifest being assessed, the verification reads STALE; when it
is absent nothing changes except that the report says, in so many words, that currency is by
time only. Bundles sealed before this field existed are untouched.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle, check_bundle_data
from assurance.machinery.record import interventions_from_ledger, record_manifest
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

from .support_recorder import build_attested_bundle
from .test_assurance_change import (  # noqa: F401  (the autouse clock fixture)
    ENG,
    MACHINE,
    _inputs,
    _pinned_clock,
    item,
    manifest,
)

WHEN = datetime(2026, 2, 9, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "binding.db")


def _seal(ledger, *, configuration_hash=""):
    env, run = _inputs(WHEN)
    extra = {"configuration_hash": configuration_hash} if configuration_hash else {}
    return build_attested_bundle(env, run, actor=ENG, ledger=ledger, subject=MACHINE.key,
                                 **extra)


def _report(ledger, m):
    return assess_coverage(
        m, VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
        interventions_from_ledger(ledger, MACHINE.key))


class TestABoundVerification:
    def test_it_is_current_for_the_configuration_it_names(self, ledger):
        m = manifest()
        record_manifest(ledger, m)
        _seal(ledger, configuration_hash=m.configuration_hash())
        rep = _report(ledger, m)
        assert {f.coverage for f in rep.functions} == {Coverage.CURRENT}
        assert not any("TIME ONLY" in c for c in rep.checks_skipped)

    def test_it_reads_stale_for_another_configuration(self, ledger):
        old = manifest()
        record_manifest(ledger, old)
        _seal(ledger, configuration_hash=old.configuration_hash())
        newer = manifest(item(content_hash="9" * 64), manifest_id="NEWER")
        rep = assess_coverage(
            newer, VerificationRecord.from_ledger(ledger, subject=MACHINE.key), [])
        assert {f.coverage for f in rep.functions} == {Coverage.STALE}
        stale = rep.functions[0]
        assert stale.invalidated_by.startswith("configuration:")
        assert "run it again" in stale.detail

    def test_the_binding_is_read_from_the_sealed_body(self, ledger):
        m = manifest()
        bundle = _seal(ledger, configuration_hash=m.configuration_hash())
        assert bundle.evidence.body["configuration_hash"] == m.configuration_hash()
        (record,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert record.configuration_hash == m.configuration_hash()
        assert record.to_dict()["configuration_hash"] == m.configuration_hash()

    def test_a_replay_of_a_bound_bundle_still_reproduces(self, ledger):
        m = manifest()
        env, run = _inputs(WHEN)
        bundle = build_bundle(env, run, actor=ENG, configuration_hash=m.configuration_hash())
        result = check_bundle_data(bundle.to_dict(), envelope=env, trace=run)
        assert result.ok, result.notes

    @pytest.mark.parametrize("bad", ["abc", "z" * 64, "a" * 63])
    def test_a_malformed_hash_is_refused_not_sealed(self, ledger, bad):
        env, run = _inputs(WHEN)
        with pytest.raises(ValueError, match="configuration_hash"):
            build_bundle(env, run, actor=ENG, ledger=ledger, subject=MACHINE.key,
                         configuration_hash=bad)
        assert len(ledger) == 0


class TestAnUnboundVerificationSaysSo:
    def test_the_body_is_exactly_what_older_builds_sealed(self, ledger):
        bundle = _seal(ledger)
        assert "configuration_hash" not in bundle.evidence.body
        (record,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert record.configuration_hash == ""
        assert "configuration_hash" not in record.to_dict()

    def test_currency_is_by_time_only_and_the_report_says_so(self, ledger):
        m = manifest()
        record_manifest(ledger, m)
        bundle = _seal(ledger)
        rep = _report(ledger, m)
        assert {f.coverage for f in rep.functions} == {Coverage.CURRENT}    # unchanged
        note = next(c for c in rep.checks_skipped if "TIME ONLY" in c)
        assert bundle.content_hash[:12] in note

    def test_no_note_when_nothing_is_current_on_it(self, ledger):
        rep = _report(ledger, manifest())
        assert not any("TIME ONLY" in c for c in rep.checks_skipped)
