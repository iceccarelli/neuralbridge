"""A change record's own date is the filer's word; the ledger's filing time is not.

A verification filed at 08:30 describes the machine until something changes it. An
explicit intervention filed at 09:30 that *claims* it happened last month used to be
compared by that claim, so the change sorted before the verification and the function stayed
``current`` on evidence that predates a recorded change to the firmware. The comparison now
uses the later of the claimed date and the time the ledger filed the record (as the
changes the ledger derives from its own manifests already did); the claimed date stays what
it was shown as.
"""

from __future__ import annotations

from datetime import UTC, datetime

from assurance.machinery.record import (
    interventions_from_ledger,
    record_intervention,
    record_manifest,
)
from assurance.machinery.staleness import Coverage

from .test_assurance_staleness_integrity import (  # noqa: F401  (fixtures)
    KEY,
    clock,
    coverage_of,
    ledger,
    manifest,
    seal,
    update,
)

CLAIMED = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)          # before the verification ran


def _state(ledger, clock):  # noqa: F811
    clock.at(8, 0)
    record_manifest(ledger, manifest())
    clock.at(8, 30)
    seal(ledger, datetime(2026, 10, 1, 8, 10, tzinfo=UTC), expect="pass")


def test_control_before_any_change_the_function_is_current(ledger, clock):  # noqa: F811
    _state(ledger, clock)
    report, _ = coverage_of(ledger)
    assert [f.coverage for f in report.functions] == [Coverage.CURRENT]


def test_a_change_filed_after_the_verification_but_claiming_an_earlier_date_stales_it(
        ledger, clock):  # noqa: F811
    _state(ledger, clock)
    clock.at(9, 30)
    record_intervention(ledger, update(when=CLAIMED))
    report, _ = coverage_of(ledger)
    [fn] = report.functions
    assert fn.coverage is Coverage.STALE and fn.invalidated_by == "INT-1"
    # the claimed date is still what is displayed
    assert fn.invalidated_at.startswith("2026-09-13")


def test_an_honest_change_dated_before_the_verification_and_filed_before_it_does_not(
        ledger, clock):  # noqa: F811
    clock.at(8, 0)
    record_manifest(ledger, manifest())
    record_intervention(ledger, update(when=CLAIMED))
    clock.at(8, 30)
    seal(ledger, datetime(2026, 10, 1, 8, 10, tzinfo=UTC), expect="pass")
    report, _ = coverage_of(ledger)
    assert [f.coverage for f in report.functions] == [Coverage.CURRENT]


def test_a_new_verification_after_the_late_filing_makes_it_current_again(ledger, clock):  # noqa: F811
    _state(ledger, clock)
    clock.at(9, 30)
    record_intervention(ledger, update(when=CLAIMED))
    clock.at(10, 0)
    seal(ledger, datetime(2026, 10, 1, 9, 45, tzinfo=UTC), tid="RUN2", expect="pass")
    report, _ = coverage_of(ledger)
    assert [f.coverage for f in report.functions] == [Coverage.CURRENT]


def test_the_sealed_record_and_what_the_ledger_returns_still_show_the_claimed_date(
        ledger, clock):  # noqa: F811
    _state(ledger, clock)
    clock.at(9, 30)
    record_intervention(ledger, update(when=CLAIMED))
    [recorded] = interventions_from_ledger(ledger, KEY, include_implied=False)
    assert recorded.occurred_at == CLAIMED
    assert recorded.to_dict() == update(when=CLAIMED).to_dict()
