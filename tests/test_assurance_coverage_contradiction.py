"""A record that carries a check as both verified and failed is not cover.

Regression: ``latest()`` tested ``checks_verified`` before ``failed_checks``, so a
contradictory record (a check listed twice with different outcomes) read as current.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from assurance.core.evidence import Actor
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _manifest():
    return SafetyManifest(
        manifest_id="m", machine=MachineIdentity("Acme", "AR-7", "0412"),
        source=ManifestSource.AS_FOUND, taken_at=T0, taken_by=Actor("t", "tech"),
        items=(SafetyItem("fw", ItemKind.FIRMWARE, "fw", "1", "a" * 64,
                          HashSource.READ_FROM_MACHINE, implements=("SF-1",)),),
        functions=(SafetyFunction("SF-1", "safe stop", verified_by=("a",)),),
    )


def _record(seq, days, verified=(), not_verified=()):
    return VerificationRecord(
        content_hash=f"{seq:064x}", effective_at=T0 + timedelta(days=days), ledger_seq=seq,
        product="p", product_version="1", verdict="pass", tier="validated",
        checks_verified=tuple(verified), checks_not_verified=tuple(not_verified))


def _coverage(records):
    report = assess_coverage(_manifest(), records, [])
    return {f.function_id: f.coverage for f in report.functions}["SF-1"]


def test_a_contradictory_record_is_failing_not_current():
    assert _coverage([_record(1, 1, verified=("a",), not_verified=("a",))]) is Coverage.FAILING


def test_a_clean_pass_is_still_current():
    assert _coverage([_record(1, 1, verified=("a",))]) is Coverage.CURRENT


def test_a_newer_clean_pass_ends_an_older_contradiction():
    older = _record(1, 1, verified=("a",), not_verified=("a",))
    newer = _record(2, 5, verified=("a",))
    assert _coverage([older, newer]) is Coverage.CURRENT
