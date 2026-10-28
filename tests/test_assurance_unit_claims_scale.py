"""Reading a fleet costs linear work in its bundles, not machines x bundles x signature checks.

Regression (round-2 review, F1): the one-recording-one-unit scan walked the whole ledger for
every ``VerificationRecord.from_ledger(subject=key)`` that saw a validated record, and for every
bundle re-verified its seal and re-assessed its attestation signature. ``Fleet.from_ledger`` calls
it once per machine, so a fleet read was quadratic (measured: 150 attested machines 0.63 s on
a135c0e, 22 s on 534a189; 300 machines 96 s). Every hosted fleet, check, report and watch read
goes through it.

The bound is stated in COUNTS of the expensive operations (a seal verification, a tier
assessment), not in seconds, so it does not depend on the machine running the test; one generous
wall-clock sanity check sits beside it.
"""

from __future__ import annotations

import time

from assurance.core.evidence import Evidence
from assurance.fleet.registry import Fleet
from assurance.machinery import staleness
from assurance.machinery.staleness import VerificationRecord

from .support_trust_hardening import ledger, seal_fleet


def _count(monkeypatch, led, rec, *, subject: str | None = None) -> dict[str, int]:
    calls = {"tier": 0, "verify": 0}
    real_tier, real_verify = staleness._tier_and_why, Evidence.verify

    def tier(*a, **k):
        calls["tier"] += 1
        return real_tier(*a, **k)

    def verify(self):
        calls["verify"] += 1
        return real_verify(self)

    monkeypatch.setattr(staleness, "_tier_and_why", tier)
    monkeypatch.setattr(Evidence, "verify", verify)
    try:
        if subject is None:
            fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
            assert fleet.summary().covered == len(fleet)      # all validated, none capped
        else:
            (record,) = VerificationRecord.from_ledger(
                led, subject=subject, recorder_trust=rec.trust())
            assert record.tier == "validated"
    finally:
        monkeypatch.undo()
    return calls


def test_a_fleet_read_does_linear_work(tmp_path, monkeypatch):
    small_ledger, big_ledger = ledger(tmp_path, "s.db"), ledger(tmp_path, "b.db")
    small_rec, big_rec = seal_fleet(small_ledger, 10), seal_fleet(big_ledger, 40)
    small = _count(monkeypatch, small_ledger, small_rec)
    big = _count(monkeypatch, big_ledger, big_rec)
    for kind in ("tier", "verify"):
        # 4x the machines may cost at most ~4x (plus slack), never ~16x
        assert big[kind] <= 6 * small[kind], (kind, small, big)
        assert big[kind] <= 12 * 40, (kind, big)


def test_one_machines_read_does_not_verify_the_rest_of_the_fleet(tmp_path, monkeypatch):
    led = ledger(tmp_path)
    rec = seal_fleet(led, 30)
    one = _count(monkeypatch, led, rec, subject="Acme/AR-7#00007")
    # its own seal and tier, and nothing like one verification per bundle in the ledger
    assert one["verify"] <= 6 and one["tier"] <= 6, one


def test_a_hundred_machines_are_read_in_a_generous_time(tmp_path):
    led = ledger(tmp_path)
    rec = seal_fleet(led, 100)
    t0 = time.perf_counter()
    fleet = Fleet.from_ledger(led, recorder_trust=rec.trust())
    elapsed = time.perf_counter() - t0
    assert fleet.summary().covered == 100
    assert elapsed < 15.0, elapsed       # a135c0e: ~0.3 s; the quadratic scan: ~10 s on this box


def test_a_fleet_read_scans_the_bundles_once_not_once_per_machine(tmp_path, monkeypatch):
    """The claim map is shared: the ledger's bundles are listed 2 per machine (its own records)
    plus a constant, not another full listing per machine."""
    from assurance.evidence.ledger import EvidenceLedger
    from assurance.machine.bundle import BUNDLE_KIND

    led = ledger(tmp_path)
    rec = seal_fleet(led, 20)
    real_entries, real_read = EvidenceLedger.entries, EvidenceLedger.read_subject
    seen = {"full": 0}

    def entries(self, *, subject=None, kind=None):
        if kind == BUNDLE_KIND and subject is None:
            seen["full"] += 1
        return real_entries(self, subject=subject, kind=kind)

    def read_subject(self, subject, kind):
        # the damage-tolerant reader the claim map and every per-machine read use
        if kind == BUNDLE_KIND and subject is None:
            seen["full"] += 1
        return real_read(self, subject, kind)

    monkeypatch.setattr(EvidenceLedger, "entries", entries)
    monkeypatch.setattr(EvidenceLedger, "read_subject", read_subject)
    Fleet.from_ledger(led, recorder_trust=rec.trust())
    monkeypatch.undo()
    assert 1 <= seen["full"] <= 2, seen     # the one shared claim map (+ slack), not 20
