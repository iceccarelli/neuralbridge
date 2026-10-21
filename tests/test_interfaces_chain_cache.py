"""The incremental chain check keeps the guarantee and costs O(new entries).

``CaseStore.require_intact`` runs before every case read and write. A full
``verify_chain`` is ~55 microseconds per record (1 s at 20 000), so the check
remembers the head a full walk verified and checks only the head and what was
appended since. These tests are written against the naive cache (remember "ok"
and trust it): each of them fails on that one.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

from assurance.core.evidence import Actor, Evidence, Origin
from assurance.core.identity import content_hash_of
from assurance.evidence import chain_cache
from assurance.evidence.ledger import GENESIS, EvidenceLedger


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.delenv("ASSURANCE_CHAIN_RECHECK_SECONDS", raising=False)
    chain_cache.reset()
    yield
    chain_cache.reset()


def sealed(n: int = 1) -> Evidence:
    return Evidence(kind="test.bulk", body={"n": n}, actor=Actor("a.tester", "t", kind="person"),
                    origin=Origin(system="test", reference="r", method="m")).seal()


def bulk_ledger(path: Path, n: int) -> EvidenceLedger:
    """A valid ``n``-record chain, built in one transaction (appending is fsync-bound)."""
    ledger = EvidenceLedger(path)
    ev = sealed()
    payload = json.dumps(ev.to_dict(), sort_keys=True, separators=(",", ":"))
    rows, prev = [], GENESIS
    for seq in range(1, n + 1):
        at = "2026-10-21T10:00:00Z"
        subject = f"s{seq % 50}"
        link = content_hash_of({"seq": seq, "at": at, "kind": ev.kind, "subject": subject,
                                "content_hash": ev.content_hash, "prev_hash": prev})
        rows.append((seq, at, ev.kind, subject, ev.content_hash, prev, link,
                     ev.actor.identifier, payload))
        prev = link
    db = sqlite3.connect(path)
    try:
        db.executemany("INSERT INTO chain (seq, at, kind, subject, content_hash, prev_hash, "
                       "link_hash, actor, payload) VALUES (?,?,?,?,?,?,?,?,?)", rows)
        db.commit()
    finally:
        db.close()
    return ledger


def sql(path: Path, statement: str, *args) -> None:
    db = sqlite3.connect(path)
    try:
        db.execute(statement, args)
        db.commit()
    finally:
        db.close()


@pytest.fixture
def ledger(tmp_path):
    return bulk_ledger(tmp_path / "l.db", 300)


def test_an_intact_ledger_passes_and_stays_passing_as_it_grows(ledger):
    assert ledger.verify_cached() == (True, [])
    for i in range(3):
        ledger.append(sealed(i), subject="x")
        assert ledger.verify_cached() == (True, [])
    assert chain_cache.lookup(chain_cache.identity(ledger.path)).seq == 303


class TestWhatTheIncrementalPassMustStillCatch:
    def test_garbage_appended_after_the_head_is_caught_at_once(self, ledger):
        assert ledger.verify_cached()[0]
        sql(ledger.path, "INSERT INTO chain (seq, at, kind, subject, content_hash, prev_hash, "
            "link_hash, actor, payload) VALUES (301, 'x', 'k', 's', 'c', 'p', 'l', 'a', '{}')")
        ok, problems = ledger.verify_cached()
        assert not ok and any("seq 301" in p for p in problems)

    def test_a_well_formed_record_that_does_not_chain_is_caught_at_once(self, ledger):
        assert ledger.verify_cached()[0]
        ev = sealed(9)
        payload = json.dumps(ev.to_dict(), sort_keys=True, separators=(",", ":"))
        link = content_hash_of({"seq": 301, "at": "t", "kind": ev.kind, "subject": "s",
                                "content_hash": ev.content_hash, "prev_hash": "f" * 64})
        sql(ledger.path, "INSERT INTO chain (seq, at, kind, subject, content_hash, prev_hash, "
            "link_hash, actor, payload) VALUES (301, 't', ?, 's', ?, ?, ?, 'a.tester', ?)",
            ev.kind, ev.content_hash, "f" * 64, link, payload)
        ok, problems = ledger.verify_cached()
        assert not ok and any("prev_hash" in p for p in problems)

    def test_an_appended_record_whose_evidence_was_edited_is_caught_at_once(self, ledger):
        assert ledger.verify_cached()[0]
        ledger.append(sealed(5), subject="x")
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":5', '\"n\":6') "
            "WHERE seq = 301")
        # (301 is the entry just appended and not yet seen by a pass)
        ok, problems = ledger.verify_cached()
        assert not ok and any("seq 301" in p for p in problems)

    def test_truncation_is_caught_at_once(self, ledger):
        assert ledger.verify_cached()[0]
        sql(ledger.path, "DELETE FROM chain WHERE seq > 250")
        ok, problems = ledger.verify_cached()
        assert not ok and any("removed" in p or "gone" in p for p in problems)

    def test_truncation_to_nothing_is_caught_at_once(self, ledger):
        assert ledger.verify_cached()[0]
        sql(ledger.path, "DELETE FROM chain")
        assert not ledger.verify_cached()[0]

    def test_a_rewind_and_rewrite_is_caught_at_once(self, ledger):
        """Delete the tail and append different, perfectly valid records until the
        chain is as long as before: the record at the remembered head has changed."""
        assert ledger.verify_cached()[0]
        sql(ledger.path, "DELETE FROM chain WHERE seq > 299")
        ledger.append(sealed(77), subject="rewritten")
        ledger.append(sealed(78), subject="rewritten")
        ok, problems = ledger.verify_cached()
        assert not ok and any("seq 300" in p for p in problems)
        assert ledger.verify_chain()[0]       # a full walk alone would have called it fine

    def test_an_edit_to_the_head_record_is_caught_at_once(self, ledger):
        assert ledger.verify_cached()[0]
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') "
            "WHERE seq = 300")
        assert not ledger.verify_cached()[0]

    def test_swapping_the_file_is_caught(self, ledger, tmp_path):
        assert ledger.verify_cached()[0]
        other = bulk_ledger(tmp_path / "other.db", 300)
        sql(other.path, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') "
            "WHERE seq = 10")
        os.replace(other.path, ledger.path)            # a different inode at the same path
        ok, problems = ledger.verify_cached()
        assert not ok and any("seq 10" in p for p in problems)

    def test_swapping_in_a_valid_ledger_is_judged_on_its_own_not_the_old_ones_cache(
            self, ledger, tmp_path):
        assert ledger.verify_cached()[0]
        shorter = bulk_ledger(tmp_path / "short.db", 40)
        os.replace(shorter.path, ledger.path)
        assert ledger.verify_cached() == (True, [])
        assert chain_cache.lookup(chain_cache.identity(ledger.path)).seq == 40


class TestAnOldEditIsSeenByTheNextFullPass:
    """The stated trade-off: not on every read, but within the recheck interval."""

    def edit_old(self, ledger):
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') "
            "WHERE seq = 100")

    def test_it_is_seen_once_the_interval_has_passed(self, ledger, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(chain_cache, "now", lambda: clock[0])
        assert ledger.verify_cached()[0]
        self.edit_old(ledger)
        clock[0] += 59
        assert ledger.verify_cached()[0], "an incremental pass does not re-read old records"
        clock[0] += 2
        ok, problems = ledger.verify_cached()
        assert not ok and any("seq 100" in p for p in problems)

    def test_an_incremental_pass_does_not_extend_the_life_of_the_full_pass(
            self, ledger, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(chain_cache, "now", lambda: clock[0])
        assert ledger.verify_cached()[0]
        self.edit_old(ledger)
        for _ in range(7):                       # many passes, each inside the interval
            clock[0] += 9
            ledger.append(sealed(), subject="x")
            ledger.verify_cached()
        clock[0] += 9
        assert not ledger.verify_cached()[0]     # 72 s after the full pass

    def test_a_zero_interval_makes_every_check_a_full_walk(self, ledger, monkeypatch):
        monkeypatch.setenv("ASSURANCE_CHAIN_RECHECK_SECONDS", "0")
        assert ledger.verify_cached()[0]
        self.edit_old(ledger)
        assert not ledger.verify_cached()[0]

    def test_an_unreadable_setting_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("ASSURANCE_CHAIN_RECHECK_SECONDS", "soon")
        assert chain_cache.recheck_seconds() == 60.0
        monkeypatch.setenv("ASSURANCE_CHAIN_RECHECK_SECONDS", "-5")
        assert chain_cache.recheck_seconds() == 0.0

    def test_every_full_verify_refreshes_and_a_failing_one_drops_the_cache(self, ledger):
        assert ledger.verify_cached()[0]
        self.edit_old(ledger)
        assert ledger.verify_cached()[0]          # inside the interval: not yet seen
        ok, _ = ledger.verify_chain()             # export / replay / /v1/ledger/verify
        assert not ok
        assert not ledger.verify_cached()[0]      # the cache cannot mask what a full walk showed
        assert chain_cache.lookup(chain_cache.identity(ledger.path)) is None

    def test_a_failing_incremental_pass_drops_the_remembered_head(self, ledger):
        """verify_cached must forget what it had verified when it finds a problem,
        so the next call is a full walk and not a re-check from a head that has
        since been shown to sit on a damaged chain."""
        assert ledger.verify_cached()[0]
        key = chain_cache.identity(ledger.path)
        assert chain_cache.lookup(key) is not None
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') "
            "WHERE seq = 300")
        ok, _ = ledger.verify_cached()           # the head itself: seen by the incremental pass
        assert not ok
        assert chain_cache.lookup(key) is None

    def test_after_a_failure_the_next_check_is_a_full_walk(self, ledger, monkeypatch):
        assert ledger.verify_cached()[0]
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') "
            "WHERE seq = 300")
        assert not ledger.verify_cached()[0]
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":2', '\"n\":1') "
            "WHERE seq = 300")                    # put it back
        walks = []
        real = ledger.verify_full
        monkeypatch.setattr(ledger, "verify_full", lambda: walks.append(1) or real())
        assert ledger.verify_cached() == (True, [])
        assert walks == [1], "with the cache dropped, the check must be a full walk"

    def test_a_failure_is_never_remembered_as_a_pass(self, ledger):
        sql(ledger.path, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') "
            "WHERE seq = 5")
        for _ in range(3):
            assert not ledger.verify_cached()[0]
        assert chain_cache.lookup(chain_cache.identity(ledger.path)) is None


class TestSteadyStateCost:
    def test_an_unchanged_20k_ledger_costs_o_of_new_entries(self, tmp_path):
        ledger = bulk_ledger(tmp_path / "big.db", 20_000)
        t0 = time.perf_counter()
        assert ledger.verify_cached()[0]
        first = time.perf_counter() - t0
        t0 = time.perf_counter()
        assert ledger.verify_chain()[0]
        full = time.perf_counter() - t0

        samples = []
        for _ in range(20):
            t0 = time.perf_counter()
            assert ledger.verify_cached() == (True, [])
            samples.append(time.perf_counter() - t0)
        unchanged = sorted(samples)[len(samples) // 2]

        for i in range(5):
            ledger.append(sealed(i), subject="x")
        t0 = time.perf_counter()
        assert ledger.verify_cached()[0]
        after_five = time.perf_counter() - t0

        sys.stderr.write(
            f"\n20k entries: first (full) {first * 1e3:.0f} ms, verify_chain {full * 1e3:.0f} ms, "
            f"unchanged median {unchanged * 1e3:.2f} ms, after 5 appends "
            f"{after_five * 1e3:.2f} ms\n")
        assert unchanged < 0.050
        assert after_five < 0.050
        assert unchanged < full / 10


def test_concurrent_checks_while_appending_never_fail_or_raise(tmp_path):
    ledger = bulk_ledger(tmp_path / "l.db", 200)
    errors, results = [], []
    stop = threading.Event()

    def checker():
        try:
            while not stop.is_set():
                results.append(ledger.verify_cached())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=checker) for _ in range(6)]
    for t in threads:
        t.start()
    for i in range(15):
        ledger.append(sealed(i), subject="x")
    stop.set()
    for t in threads:
        t.join()
    assert errors == []
    assert results and all(r == (True, []) for r in results)


def test_the_case_store_checks_incrementally(tmp_path, monkeypatch):
    from assurance.change import CaseStore

    ledger = bulk_ledger(tmp_path / "l.db", 100)
    store = CaseStore(ledger)
    full_walks = []
    real = EvidenceLedger.verify_full

    def counting(self):
        full_walks.append(1)
        return real(self)

    monkeypatch.setattr(EvidenceLedger, "verify_full", counting)
    for _ in range(25):
        store.require_intact()
    assert len(full_walks) == 1
    sql(ledger.path, "DELETE FROM chain WHERE seq > 90")
    from assurance.core.errors import LedgerIntegrityError

    with pytest.raises(LedgerIntegrityError):
        store.require_intact()


def test_the_copy_of_a_ledger_does_not_borrow_the_originals_cache(tmp_path):
    ledger = bulk_ledger(tmp_path / "l.db", 100)
    assert ledger.verify_cached()[0]
    copy = tmp_path / "copy.db"
    shutil.copy(ledger.path, copy)
    sql(copy, "UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":2') WHERE seq = 3")
    assert not EvidenceLedger(copy).verify_cached()[0]
