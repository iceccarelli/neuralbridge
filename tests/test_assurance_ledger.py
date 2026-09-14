"""The evidence ledger.

Each test here corresponds to a defect observed in a real audit-log
implementation: a chain that forks under concurrency, a record that can be
edited in place without detection, a chain kept per worker process, and a
verification function that exists but is never called.
"""

from __future__ import annotations

import itertools
import json
import sqlite3
import threading

import pytest

from assurance.core import Actor, Evidence, LedgerIntegrityError, Origin
from assurance.evidence import GENESIS, EvidenceLedger


@pytest.fixture()
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "evidence.db")


def make(value: int, kind: str = "test.record") -> Evidence:
    return Evidence(
        kind=kind,
        body={"value": value},
        actor=Actor("m.braun", "engineer"),
        origin=Origin("unit-test"),
    ).seal()


class TestAppend:
    def test_first_record_chains_from_genesis(self, ledger):
        entry = ledger.append(make(1))
        assert entry.seq == 1
        assert entry.prev_hash == GENESIS

    def test_records_chain_in_order(self, ledger):
        entries = [ledger.append(make(i)) for i in range(5)]
        for earlier, later in itertools.pairwise(entries):
            assert later.prev_hash == earlier.link_hash

    def test_unsealed_evidence_is_refused(self, ledger):
        unsealed = Evidence(
            kind="t", body={}, actor=Actor("m.braun"), origin=Origin("unit-test")
        )
        with pytest.raises(LedgerIntegrityError, match="unsealed"):
            ledger.append(unsealed)

    def test_evidence_mutated_after_sealing_is_refused(self, ledger):
        sealed = make(1)
        forged = Evidence.from_dict({**sealed.to_dict(), "body": {"value": 99}})
        with pytest.raises(LedgerIntegrityError, match="does not match its own content"):
            ledger.append(forged)


class TestConcurrency:
    def test_parallel_writers_do_not_fork_the_chain(self, tmp_path):
        # The classic defect: read the tail, then append, in two statements.
        # Two writers read the same predecessor and produce two records with
        # the same prev_hash, each chain internally consistent and the pair
        # meaningless. Every append here spans one BEGIN IMMEDIATE transaction.
        path = tmp_path / "concurrent.db"
        EvidenceLedger(path)  # create the schema once, up front
        errors: list[Exception] = []
        barrier = threading.Barrier(8)

        def writer(n: int) -> None:
            try:
                own = EvidenceLedger(path)
                barrier.wait()
                for i in range(5):
                    own.append(make(n * 100 + i))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"writers failed: {errors}"
        ledger = EvidenceLedger(path)
        assert len(ledger) == 40
        ok, problems = ledger.verify_chain()
        assert ok, problems

        prev_hashes = [e.prev_hash for e in ledger.entries()]
        assert len(set(prev_hashes)) == len(prev_hashes), "a prev_hash was reused: chain forked"


class TestTamperDetection:
    def _corrupt(self, ledger, sql, args=()):
        db = sqlite3.connect(ledger.path)
        db.execute(sql, args)
        db.commit()
        db.close()

    def test_clean_chain_verifies(self, ledger):
        for i in range(4):
            ledger.append(make(i))
        assert ledger.verify_chain() == (True, [])

    def test_edited_payload_is_detected(self, ledger):
        for i in range(4):
            ledger.append(make(i))
        self._corrupt(
            ledger,
            "UPDATE chain SET payload = replace(payload, '\"value\":2', '\"value\":99') WHERE seq = 3",
        )
        ok, problems = ledger.verify_chain()
        assert not ok
        assert any("seq 3" in p and "evidence body was edited" in p for p in problems)

    def test_removed_record_is_detected(self, ledger):
        for i in range(4):
            ledger.append(make(i))
        self._corrupt(ledger, "DELETE FROM chain WHERE seq = 2")
        ok, problems = ledger.verify_chain()
        assert not ok
        assert any("gap in the chain" in p for p in problems)

    def test_reordered_chain_is_detected(self, ledger):
        for i in range(4):
            ledger.append(make(i))
        self._corrupt(ledger, "UPDATE chain SET prev_hash = ? WHERE seq = 3", (GENESIS,))
        ok, problems = ledger.verify_chain()
        assert not ok
        assert any("re-ordered or spliced" in p for p in problems)

    def test_edited_metadata_is_detected(self, ledger):
        ledger.append(make(1))
        self._corrupt(ledger, "UPDATE chain SET at = '1999-01-01T00:00:00Z' WHERE seq = 1")
        ok, problems = ledger.verify_chain()
        assert not ok
        assert any("edited in place" in p for p in problems)


class TestExport:
    def test_export_verifies_before_emitting(self, ledger):
        # An export is the moment records start being relied upon, so it is the
        # right moment to refuse. A verification function that is never called
        # is decoration.
        for i in range(3):
            ledger.append(make(i))
        db = sqlite3.connect(ledger.path)
        db.execute("DELETE FROM chain WHERE seq = 2")
        db.commit()
        db.close()
        with pytest.raises(LedgerIntegrityError, match="refusing to export"):
            ledger.export()

    def test_export_carries_an_attestation(self, ledger):
        for i in range(3):
            ledger.append(make(i), subject="CASE-1")
        bundle = ledger.export(subject="CASE-1")
        assert bundle["chain_verified"] is True
        assert len(bundle["entries"]) == 3
        assert bundle["attestation"]["head_seq"] == 3
        assert bundle["attestation"]["head_link_hash"] == ledger.entries()[-1].link_hash

    def test_export_round_trips_through_json(self, ledger):
        ledger.append(make(1))
        assert json.loads(json.dumps(ledger.export()))["chain_verified"] is True


class TestQueries:
    def test_filters_by_subject_and_kind(self, ledger):
        ledger.append(make(1, "a"), subject="CASE-1")
        ledger.append(make(2, "b"), subject="CASE-1")
        ledger.append(make(3, "a"), subject="CASE-2")
        assert len(ledger.entries(subject="CASE-1")) == 2
        assert len(ledger.entries(kind="a")) == 2
        assert len(ledger.entries(subject="CASE-1", kind="a")) == 1

    def test_lookup_by_content_hash(self, ledger):
        evidence = make(7)
        ledger.append(evidence)
        found = ledger.get(evidence.content_hash)
        assert found is not None
        assert found.evidence().body["value"] == 7

    def test_head_attestation_of_an_empty_ledger_is_genesis(self, ledger):
        attestation = ledger.head_attestation()
        assert attestation["length"] == 0
        assert attestation["head_link_hash"] == GENESIS


class TestSchemaGuard:
    def test_refuses_a_ledger_written_by_another_schema(self, tmp_path):
        path = tmp_path / "future.db"
        EvidenceLedger(path)
        db = sqlite3.connect(path)
        db.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        db.commit()
        db.close()
        with pytest.raises(LedgerIntegrityError, match="Refusing rather than guessing"):
            EvidenceLedger(path)
