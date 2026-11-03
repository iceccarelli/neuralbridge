"""The batch importer verifies the chain twice in full, not once per row.

``enrol_machine`` walks the whole chain before each enrolment. A batch (``machinery
import-inventory``, ``POST /v1/machinery/enrol/batch``) used to pay that per row, which made a
500-row import quadratic. It now holds a :class:`~assurance.machinery.enrol.BatchChain`: one FULL
walk before the first row, a head-plus-appended check before each row, one FULL walk after the
last. These tests pin what must not have changed (same entries, same hashes, same order as the
per-row path), and that the integrity checks still happen and still refuse.

All data is SYNTHETIC.
"""
from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path

import pytest

from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery import inventory as inv
from assurance.machinery.enrol import BatchChain, EnrolmentError, enrol_machine
from assurance.machinery.inventory import LedgerChainUnverifiedError, import_rows

PERSON = Actor("a.integrator", "safety engineer")
FUNCTIONS = (inv.FunctionDecl("SF-01", "Protective stop", "PL d", ("ssm_separation",)),)
SHA = "1" * 64


def _raw(serial: str, **over):
    d = {"manufacturer": "Grimaldi", "model": "AR-7", "serial": serial, "site": "Plant 1",
         "owner": "Example GmbH", "year": "2021", "country": "DE",
         "items": [{"name": "Safety controller firmware", "version": "3.8.2", "sha256": SHA,
                    "supplier": "ControlCo", "implements": ["SF-01"]},
                   {"name": "Scanner zones", "version": "r4", "kind": "safety_configuration",
                    "implements": ["SF-01"]}]}
    d.update(over)
    return d


def _rows(n: int, start: int = 0):
    raw = [_raw(f"S{i:04d}") for i in range(start, start + n)]
    raw.append(_raw("BAD", items=[]))                      # a rejected row in the middle of it
    return inv.rows_from_api(raw, FUNCTIONS)


def _import(ledger: EvidenceLedger, rows, **kw):
    return import_rows(Path(""), rows, actor=PERSON, source_system="bench",
                       export_date=dt.date(2026, 10, 15),
                       file_sha256="a" * 64, functions=FUNCTIONS, channel="api",
                       ledger=ledger, **kw)


def _shape(ledger: EvidenceLedger):
    return [(e.seq, e.kind, e.subject, e.actor, e.content_hash) for e in ledger.entries()]


class _CountWalks:
    """Counts FULL chain walks (``verify_full``) made while it is installed."""

    def __init__(self, monkeypatch):
        self.n = 0
        real = EvidenceLedger.verify_full

        def counting(ledger):
            self.n += 1
            return real(ledger)
        monkeypatch.setattr(EvidenceLedger, "verify_full", counting)


def _tamper_old_record(path: Path) -> None:
    db = sqlite3.connect(path)
    try:
        db.execute("UPDATE chain SET payload = replace(payload, 'Grimaldi', 'Grimaldy') "
                   "WHERE seq = 1")
        db.commit()
    finally:
        db.close()


class TestSameOutcomeAsThePerRowPath:
    def test_entries_hashes_order_and_report_are_identical(self, tmp_path, monkeypatch):
        fast = EvidenceLedger(tmp_path / "fast.db")
        slow = EvidenceLedger(tmp_path / "slow.db")
        fast_report = _import(fast, _rows(25))

        real = inv.enrol_machine

        def per_row(ledger, manifest, **kw):          # the old behaviour: a full walk per row
            kw.pop("batch_chain", None)
            return real(ledger, manifest, **kw)
        monkeypatch.setattr(inv, "enrol_machine", per_row)
        slow_report = _import(slow, _rows(25))

        assert _shape(fast) == _shape(slow) and len(_shape(fast)) == 25 * 2 + 1
        assert fast_report.to_dict() == slow_report.to_dict()
        assert fast_report.counts["enrolled"] == 25 and fast_report.counts["rejected"] == 1
        assert fast.verify_chain()[0] and slow.verify_chain()[0]

    def test_a_second_import_of_the_same_rows_reports_already_enrolled(self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        _import(led, _rows(5))
        before = _shape(led)
        again = _import(led, _rows(5))
        assert again.counts["already_enrolled"] == 5 and again.counts["enrolled"] == 0
        assert _shape(led) == before                         # nothing was written


class TestTheIntegrityCheckStillHappens:
    def test_a_batch_makes_exactly_two_full_walks_however_many_rows(self, tmp_path, monkeypatch):
        led = EvidenceLedger(tmp_path / "l.db")
        walks = _CountWalks(monkeypatch)
        _import(led, _rows(20))
        assert walks.n == 2          # before the first row, and after the batch record

    def test_a_single_enrolment_still_walks_the_whole_chain(self, tmp_path, monkeypatch):
        led = EvidenceLedger(tmp_path / "l.db")
        walks = _CountWalks(monkeypatch)
        enrol_machine(led, _manifest("S1"), actor=PERSON)
        enrol_machine(led, _manifest("S2"), actor=PERSON)
        assert walks.n == 2                                  # one per call, as before

    def test_a_broken_chain_is_refused_before_anything_is_written(self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        _import(led, _rows(3))
        _tamper_old_record(led.path)
        before = len(led)
        with pytest.raises(LedgerChainUnverifiedError, match="nothing was imported"):
            _import(led, _rows(3, start=100))
        assert len(led) == before

    def test_mutation_without_the_upfront_walk_the_closing_walk_still_refuses(
            self, tmp_path, monkeypatch):
        """Skip the first full verify: the closing full verify still refuses the import."""
        led = EvidenceLedger(tmp_path / "l.db")
        _import(led, _rows(3))
        _tamper_old_record(led.path)

        def no_upfront_walk(ledger):
            tail = ledger.entries()[-1]
            return BatchChain(ledger, tail.seq, tail.link_hash)
        monkeypatch.setattr(inv, "_begin", no_upfront_walk)
        with pytest.raises(LedgerChainUnverifiedError, match="after the import"):
            _import(led, _rows(2, start=100))

    def test_mutation_without_the_closing_walk_the_upfront_walk_still_refuses(
            self, tmp_path, monkeypatch):
        led = EvidenceLedger(tmp_path / "l.db")
        _import(led, _rows(3))
        _tamper_old_record(led.path)
        monkeypatch.setattr(BatchChain, "finish", lambda self: [])
        before = len(led)
        with pytest.raises(LedgerChainUnverifiedError, match="nothing was imported"):
            _import(led, _rows(2, start=100))
        assert len(led) == before

    def test_a_record_forged_onto_the_end_during_the_batch_is_seen_by_the_next_row(
            self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        enrol_machine(led, _manifest("S0"), actor=PERSON)
        chain = BatchChain.begin(led)
        chain.check(led)                                     # clean: head unchanged
        db = sqlite3.connect(led.path)
        try:
            tail = db.execute("SELECT seq, link_hash FROM chain ORDER BY seq DESC "
                              "LIMIT 1").fetchone()
            db.execute("INSERT INTO chain (seq, at, kind, subject, content_hash, prev_hash, "
                       "link_hash, actor, payload) VALUES (?,?,?,?,?,?,?,?,?)",
                       (tail[0] + 1, "2026-10-15T00:00:00Z", "x", "", "c" * 64, tail[1],
                        "f" * 64, "mallory", "{}"))
            db.commit()
        finally:
            db.close()
        with pytest.raises(EnrolmentError, match="does not verify"):
            chain.check(led)
        assert chain.finish()

    def test_an_edit_to_the_head_record_is_seen_by_the_next_row(self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        enrol_machine(led, _manifest("S0"), actor=PERSON)
        chain = BatchChain.begin(led)
        db = sqlite3.connect(led.path)
        try:
            db.execute("UPDATE chain SET payload = replace(payload, 'Grimaldi', 'Grimaldy') "
                       "WHERE seq = (SELECT MAX(seq) FROM chain)")
            db.commit()
        finally:
            db.close()
        with pytest.raises(EnrolmentError):
            chain.check(led)

    def test_the_stated_limit_an_old_record_edited_mid_batch_is_seen_at_the_end(self, tmp_path):
        """Documented trade-off: per-row checks start at the batch's head; finish() is full."""
        led = EvidenceLedger(tmp_path / "l.db")
        enrol_machine(led, _manifest("S0"), actor=PERSON)
        enrol_machine(led, _manifest("S1"), actor=PERSON)
        chain = BatchChain.begin(led)
        _tamper_old_record(led.path)
        chain.check(led)                                     # not seen here ...
        assert chain.finish()                                # ... seen by the closing walk

    def test_a_check_belongs_to_one_ledger(self, tmp_path):
        a, b = EvidenceLedger(tmp_path / "a.db"), EvidenceLedger(tmp_path / "b.db")
        chain = BatchChain.begin(a)
        with pytest.raises(EnrolmentError, match="another ledger"):
            enrol_machine(b, _manifest("S1"), actor=PERSON, batch_chain=chain)


class TestLedgerHelpers:
    def test_verify_chain_head_returns_the_head_the_walk_read(self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        for i in range(3):
            led.append(Evidence(kind="t", body={"i": i}, actor=PERSON,
                                origin=Origin("t")).seal())
        problems, seq, link = led.verify_chain_head()
        tail = led.entries()[-1]
        assert problems == [] and seq == tail.seq == 3 and link == tail.link_hash
        assert led.verify_chain() == (True, [])
        assert led.verify_since(seq, link) == ([], seq, link)

    def test_verify_since_verifies_what_was_appended_after_the_head(self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        led.append(Evidence(kind="t", body={"i": 0}, actor=PERSON, origin=Origin("t")).seal())
        _, seq, link = led.verify_chain_head()
        led.append(Evidence(kind="t", body={"i": 1}, actor=PERSON, origin=Origin("t")).seal())
        problems, new_seq, new_link = led.verify_since(seq, link)
        assert problems == [] and new_seq == seq + 1 and new_link != link
        assert led.verify_since(seq + 5, "0" * 64)[0]          # a head that is gone is a finding


class TestSubjectKindQueriesUseTheSubjectIndex:
    """``subject = ? AND kind = ?`` used to be answered from ``chain_by_kind``: one scan of every
    row of that kind per machine, so fleet reads and enrolment were O(machines) per call."""

    def _ledger(self, tmp_path) -> EvidenceLedger:
        led = EvidenceLedger(tmp_path / "l.db")
        for i in range(60):
            led.append(Evidence(kind=("a", "b", "c")[i % 3], body={"i": i}, actor=PERSON,
                                origin=Origin("t")).seal(), subject=f"S{i % 7}")
        return led

    def test_results_are_the_rows_a_plain_filter_gives_in_the_same_order(self, tmp_path):
        led = self._ledger(tmp_path)
        everything = led.entries()
        for subject in ("S0", "S3", "none"):
            for kind in ("a", "b", "zzz"):
                want = [e for e in everything if e.subject == subject and e.kind == kind]
                assert led.entries(subject=subject, kind=kind) == want
                readable, damaged, clock = led.read_subject(subject, kind)
                assert readable == want and damaged == []
                assert set(clock) == {e.seq for e in everything if e.subject == subject}
        assert led.entries(kind="a") == [e for e in everything if e.kind == "a"]
        assert led.entries(subject="S1") == [e for e in everything if e.subject == "S1"]

    def test_the_planner_is_not_sent_to_the_kind_index(self, tmp_path, monkeypatch):
        led = self._ledger(tmp_path)
        seen: list[str] = []
        real = EvidenceLedger._connect

        def traced(self):
            db = real(self)
            db.set_trace_callback(seen.append)
            return db
        monkeypatch.setattr(EvidenceLedger, "_connect", traced)
        led.entries(subject="S1", kind="a")
        led.read_subject("S1", "a")
        led.append(Evidence(kind="x", body={}, actor=PERSON, origin=Origin("t")).seal(),
                   subject="S1", expect_subject_head=0, expect_kinds=("x",))
        monkeypatch.undo()
        both = [q for q in seen if "FROM chain" in q and "subject" in q and "kind" in q]
        assert len(both) == 3, both
        db = sqlite3.connect(led.path)
        try:
            for q in both:
                plan = " ".join(str(r) for r in db.execute("EXPLAIN QUERY PLAN " + q))
                assert "chain_by_subject" in plan and "chain_by_kind" not in plan, (q, plan)
        finally:
            db.close()


def _manifest(serial: str):
    row = inv.canonical_row(_raw(serial), 1, frozenset({"SF-01"}))
    return inv._manifest_for(row, actor=PERSON, source_system="bench",
                             export_date=dt.date(2026, 10, 15), file_sha256="",
                             functions=FUNCTIONS)
