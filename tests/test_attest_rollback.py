"""Rollback: truncating the ledger to an older signed head AND cutting the log to match.

``verify_log`` only asks "does the ledger still hold every head THIS log attests". An operator
with database write access can delete the newest records and the newest attestation lines; what
is left is internally consistent and genuinely signed. Nothing in the pair can show it, so the
verifier must bring an expectation (the newest sequence/head from its last check). These tests
reproduce the attack and pin what the expectation catches and what the output admits.
"""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path

import pytest

from assurance.attest import AttestationLog, SigningKey, attest, verify_log
from assurance.attest.attestation import NO_EXPECTATION_NOTE, check_log_against_ledger
from assurance.attest.cli import main as attest_main
from assurance.core import Actor, Evidence, Origin
from assurance.core.identity import utc_now
from assurance.evidence import EvidenceLedger


def _add(ledger: EvidenceLedger, start: int, stop: int) -> None:
    for n in range(start, stop):
        ledger.append(Evidence(kind="test.record", body={"n": n}, actor=Actor("t"),
                               origin=Origin("pytest")).seal(), subject=f"m{n}")


@pytest.fixture()
def rolled_back(tmp_path):
    """Sign at length 10, grow to 20, sign again, then roll both ledger and log back."""
    key = SigningKey.generate()
    ledger = EvidenceLedger(tmp_path / "l.db")
    log = AttestationLog(tmp_path / "a.jsonl")
    _add(ledger, 0, 10)
    first = attest(ledger, key, log)
    _add(ledger, 10, 20)
    second = attest(ledger, key, log)
    full_log = log.path.read_text()
    db = sqlite3.connect(ledger.path)
    db.execute("DELETE FROM chain WHERE seq > 10")
    db.commit()
    db.close()
    lines = full_log.splitlines(keepends=True)
    log.path.write_text(lines[0])
    return {"key": key, "ledger": ledger, "log": AttestationLog(log.path), "first": first,
            "second": second, "tmp": tmp_path}


class TestTheReproducedRollback:
    def test_without_an_expectation_it_still_passes_and_says_what_it_did_not_establish(
            self, rolled_back):
        records = rolled_back["log"].read()
        verdict = verify_log(records, rolled_back["key"].verifying, ledger=rolled_back["ledger"])
        assert verdict.ok is True                       # the limitation, stated, not hidden
        assert NO_EXPECTATION_NOTE in verdict.checks_skipped
        assert "withheld newer attestation" in NO_EXPECTATION_NOTE
        assert "--min-sequence" in NO_EXPECTATION_NOTE

    def test_min_sequence_catches_it(self, rolled_back):
        verdict = verify_log(rolled_back["log"].read(), rolled_back["key"].verifying,
                             ledger=rolled_back["ledger"],
                             min_sequence=rolled_back["second"].sequence)
        assert verdict.ok is False
        assert any("rollback or withheld newer attestation" in p for p in verdict.problems)
        assert NO_EXPECTATION_NOTE not in verdict.checks_skipped

    def test_expect_head_catches_it_by_full_hash_or_prefix(self, rolled_back):
        head = rolled_back["second"].head_link_hash
        for given in (head, head[:12].upper()):
            verdict = verify_log(rolled_back["log"].read(), rolled_back["key"].verifying,
                                 ledger=rolled_back["ledger"], expect_head=given)
            assert verdict.ok is False
            assert any("rollback or withheld newer attestation" in p for p in verdict.problems)

    def test_check_log_against_ledger_takes_the_same_expectation(self, rolled_back):
        problems, skipped = check_log_against_ledger(
            rolled_back["log"].read(), rolled_back["ledger"],
            min_sequence=rolled_back["second"].sequence)
        assert any("rollback or withheld" in p for p in problems)
        problems, skipped = check_log_against_ledger(
            rolled_back["log"].read(), rolled_back["ledger"])
        assert problems == [] and NO_EXPECTATION_NOTE in skipped


class TestAnExpectationNeverFailsAGoodLog:
    def test_the_current_sequence_and_head_pass(self, tmp_path):
        key = SigningKey.generate()
        ledger = EvidenceLedger(tmp_path / "l.db")
        log = AttestationLog(tmp_path / "a.jsonl")
        _add(ledger, 0, 5)
        attest(ledger, key, log)
        _add(ledger, 5, 8)
        newest = attest(ledger, key, log)
        verdict = verify_log(log.read(), key.verifying, ledger=ledger,
                             min_sequence=newest.sequence, expect_head=newest.head_link_hash)
        assert verdict.ok and NO_EXPECTATION_NOTE not in verdict.checks_skipped
        # an older remembered expectation is satisfied by a newer log
        older = log.read()[0]
        assert verify_log(log.read(), key.verifying, min_sequence=older.sequence,
                          expect_head=older.head_link_hash).ok

    def test_an_expect_head_the_log_never_held_fails(self, tmp_path):
        key = SigningKey.generate()
        ledger = EvidenceLedger(tmp_path / "l.db")
        log = AttestationLog(tmp_path / "a.jsonl")
        _add(ledger, 0, 3)
        attest(ledger, key, log)
        verdict = verify_log(log.read(), key.verifying, expect_head="ab" * 32)
        assert not verdict.ok and "no attestation in the log has head" in verdict.problems[0]

    def test_bad_expectations_are_refused_not_ignored(self, tmp_path):
        key = SigningKey.generate()
        with pytest.raises(ValueError):
            verify_log([], key.verifying, min_sequence=0)
        with pytest.raises(ValueError):
            verify_log([], key.verifying, expect_head="xyz")


class TestMaxAge:
    def test_a_stale_newest_attestation_fails(self, tmp_path):
        key = SigningKey.generate()
        ledger = EvidenceLedger(tmp_path / "l.db")
        log = AttestationLog(tmp_path / "a.jsonl")
        _add(ledger, 0, 3)
        attest(ledger, key, log, now=utc_now() - timedelta(hours=30))
        assert not verify_log(log.read(), key.verifying, max_age=timedelta(hours=24)).ok
        assert verify_log(log.read(), key.verifying, max_age=timedelta(hours=48)).ok


class TestCli:
    def _run(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = attest_main(list(argv))
        return code, out.getvalue()

    def _setup(self, tmp_path: Path):
        keys = tmp_path / "keys"
        keys.mkdir()
        private, public = keys / "k", keys / "k.pub"
        assert self._run("keygen", "--out", str(private), "--public-out", str(public))[0] == 0
        return private, public

    def test_rollback_is_caught_by_the_cli_flags(self, tmp_path):
        private, public = self._setup(tmp_path)
        ledger = EvidenceLedger(tmp_path / "l.db")
        log = tmp_path / "a.jsonl"
        _add(ledger, 0, 10)
        assert self._run("sign", "--ledger", str(ledger.path), "--key", str(private),
                         "--log", str(log))[0] == 0
        _add(ledger, 10, 20)
        assert self._run("sign", "--ledger", str(ledger.path), "--key", str(private),
                         "--log", str(log))[0] == 0
        code, text = self._run("verify", "--log", str(log), "--public-key", str(public),
                               "--ledger", str(ledger.path), "--json")
        assert code == 0
        remember = json.loads(text)["remember_for_next_check"]
        assert remember["min_sequence"] == 2
        newest_head = remember["expect_head"]

        db = sqlite3.connect(ledger.path)
        db.execute("DELETE FROM chain WHERE seq > 10")
        db.commit()
        db.close()
        log.write_text(log.read_text().splitlines(keepends=True)[0])

        base = ["verify", "--log", str(log), "--public-key", str(public),
                "--ledger", str(ledger.path)]
        code, text = self._run(*base)
        assert code == 0 and "withheld newer attestation" in text    # passes, and says so
        code, text = self._run(*base, "--min-sequence", "2")
        assert code == 1 and "rollback or withheld newer attestation" in text
        code, text = self._run(*base, "--expect-head", newest_head)
        assert code == 1 and "rollback or withheld newer attestation" in text

    def test_success_output_tells_the_caller_what_to_keep(self, tmp_path):
        private, public = self._setup(tmp_path)
        ledger = EvidenceLedger(tmp_path / "l.db")
        _add(ledger, 0, 2)
        log = tmp_path / "a.jsonl"
        self._run("sign", "--ledger", str(ledger.path), "--key", str(private), "--log", str(log))
        code, text = self._run("verify", "--log", str(log), "--public-key", str(public))
        assert code == 0 and "--min-sequence 1 --expect-head" in text

    def test_max_age_is_available_on_verify(self, tmp_path):
        private, public = self._setup(tmp_path)
        ledger = EvidenceLedger(tmp_path / "l.db")
        _add(ledger, 0, 2)
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(ledger, SigningKey.load(private), log, now=utc_now() - timedelta(hours=100))
        argv = ["verify", "--log", str(log.path), "--public-key", str(public)]
        assert self._run(*argv)[0] == 0
        code, text = self._run(*argv, "--max-age", "24")
        assert code == 1 and "over the allowed" in text
        assert self._run(*argv, "--max-age", "200")[0] == 0

    def test_bad_flag_values_exit_2(self, tmp_path):
        private, public = self._setup(tmp_path)
        log = tmp_path / "a.jsonl"
        log.write_text("")
        base = ["verify", "--log", str(log), "--public-key", str(public)]
        for extra in (["--min-sequence", "0"], ["--max-age", "0"], ["--max-age", "nan"],
                      ["--expect-head", "zz"]):
            assert self._run(*base, *extra)[0] == 2
