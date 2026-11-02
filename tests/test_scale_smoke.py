"""Regression guards against accidental quadratic behaviour in the batch import and fleet reads.

These are NOT performance claims and not capacity statements. They exist because a 500-row
inventory import used to be O(n^2) (the whole ledger chain was verified once per row) and
nothing noticed. The budgets are about 10x what the code took on the machine that wrote them
(see ``deploy/assurance/SCALE.md`` for the measurements), so they fail on a change of order, not
on a slow runner. Synthetic data, a throwaway ledger, no network. Never skipped.

The doubling and slope tests use CPU time (``time.process_time``), not wall time: the ledger
fsyncs every append (synchronous=FULL, deliberately), and that wait is linear in rows and would
hide a quadratic CPU term at these sizes.
"""
from __future__ import annotations

import datetime
import time
from pathlib import Path

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.machinery import inventory as inv
from assurance.machinery.inventory import import_rows

PERSON = Actor("a.integrator", "safety engineer")
FUNCTIONS = (inv.FunctionDecl("SF-01", "Protective stop", "PL d", ("ssm_separation",)),)
SHA = "1" * 64

#: Seconds. About 10x the wall time measured when these were written (see SCALE.md).
BUDGET_IMPORT_200_S = 40.0
BUDGET_FLEET_LIST_200_S = 5.0
#: time(2N) / time(N) for a linear algorithm is about 2; a quadratic one trends to 4.
MAX_DOUBLING_RATIO = 3.5
#: mean per-row CPU of the last quarter of a batch over the first quarter: flat is about 1.
MAX_TAIL_OVER_HEAD = 2.0


def _rows(n: int):
    raw = [{"manufacturer": "Grimaldi", "model": "AR-7", "serial": f"S{i:06d}",
            "site": f"Plant {i % 20}", "owner": "Example GmbH", "year": "2021", "country": "DE",
            "items": [{"name": "Safety controller firmware", "version": "3.8.2", "sha256": SHA,
                       "supplier": "ControlCo", "implements": ["SF-01"]},
                      {"name": "Scanner zones", "version": "r4",
                       "kind": "safety_configuration", "implements": ["SF-01"]}]}
           for i in range(n)]
    return inv.rows_from_api(raw, FUNCTIONS)


def _import(path: Path, n: int, clock=time.perf_counter):
    ledger = EvidenceLedger(path)
    rows = _rows(n)
    t = clock()
    report = import_rows(Path(""), rows, actor=PERSON, source_system="smoke",
                         export_date=datetime.date(2026, 10, 15), file_sha256="b" * 64,
                         functions=FUNCTIONS, channel="api", ledger=ledger)
    return report, clock() - t, ledger


@pytest.fixture(scope="module")
def fleet_200(tmp_path_factory):
    report, seconds, ledger = _import(tmp_path_factory.mktemp("scale") / "l.db", 200)
    return report, seconds, ledger


def test_batch_import_of_200_rows_completes_within_budget(fleet_200):
    report, seconds, ledger = fleet_200
    assert report.counts["enrolled"] == 200 and report.ok
    assert seconds < BUDGET_IMPORT_200_S, f"{seconds:.1f}s for 200 rows"
    assert len(ledger) == 200 * 2 + 1                     # manifest + enrolment each, one record
    assert ledger.verify_chain()[0]


def test_fleet_list_at_200_machines_within_budget(fleet_200):
    ledger = fleet_200[2]
    t = time.perf_counter()
    fleet = Fleet.from_ledger(ledger)
    seconds = time.perf_counter() - t
    assert len(fleet) == 200 and fleet.chain_verified
    assert seconds < BUDGET_FLEET_LIST_200_S, f"{seconds:.1f}s for 200 machines"


def _cpu_best_of_3(tmp_path: Path, n: int) -> float:
    best = float("inf")
    for k in range(3):
        report, seconds, _ = _import(tmp_path / f"d{n}_{k}.db", n, clock=time.process_time)
        assert report.counts["enrolled"] == n
        best = min(best, seconds)
    return best


def test_doubling_the_batch_does_not_quadruple_the_cpu_time(tmp_path):
    """The check asked for. Honest limit: at these sizes the per-row fsync wait is excluded but
    the linear CPU per row (about 8 ms) still dominates, so the per-row full walk this guards
    against (about 0.1 ms per ledger entry) moved this ratio only from about 2.1 to about 3.3 (measured)
    when it was present: under the 3.5 limit. ``test_later_rows_cost...`` below and the
    full-walk count in ``test_assurance_batch_chain.py`` are the guards that fail on that bug."""
    n = 100
    small, large = _cpu_best_of_3(tmp_path, n), _cpu_best_of_3(tmp_path, 2 * n)
    assert small > 0.05, "too small to measure; raise n"
    assert large / small < MAX_DOUBLING_RATIO, (
        f"{n} rows {small:.2f}s CPU, {2 * n} rows {large:.2f}s CPU: ratio "
        f"{large / small:.2f} (linear is about 2, quadratic trends to 4)")


def test_later_rows_cost_about_the_same_as_earlier_rows(tmp_path, monkeypatch):
    """Per-row CPU of the last quarter against the first: the shape a per-row full walk has."""
    real = inv.enrol_machine
    cost: list[float] = []

    def timed(*a, **kw):
        t = time.process_time()
        try:
            return real(*a, **kw)
        finally:
            cost.append(time.process_time() - t)
    monkeypatch.setattr(inv, "enrol_machine", timed)
    n = 240
    best = float("inf")
    for k in range(2):
        cost.clear()
        _import(tmp_path / f"t{k}.db", n)
        q = n // 4
        head, tail = sum(cost[:q]) / q, sum(cost[-q:]) / q
        best = min(best, tail / head)
    assert best < MAX_TAIL_OVER_HEAD, f"last quarter costs {best:.1f}x the first per row"
