"""A signed anchor does not make a bundle the NEWEST one, and a key does not name itself.

An audit reproduced both against the verifier tooling:

* a bundle cut back to ANY older signed head (the unsigned head rewritten, the older genuine
  anchor embedded) was "VERIFIED - anchored", exit 0, because every signature on it is genuine.
  ``attest verify`` could be told what the verifier remembers (``--min-sequence`` /
  ``--expect-head`` / ``--max-age``); ``evidence verify`` could not;
* a forged shorter ledger, signed with the forger's key and checked with the forger's own public
  key, was "VERIFIED", because nothing compared the key with the fingerprint the verifier had
  been given elsewhere.

Every bundle here comes from the real ledger and the real signer. The forgeries are what someone
holding the whole file can do.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import timedelta

import pytest

from assurance.attest import AttestationLog, SigningKey, attest
from assurance.cli import main as cli_main
from assurance.core import Actor, Evidence, Origin
from assurance.core.identity import parse_utc
from assurance.evidence import EvidenceLedger
from assurance.evidence.verify_export import (
    ANCHORED,
    FAILED,
    FINGERPRINT_BITS_NOTE,
    verify_export,
)


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


def _cut_tail(bundle: dict, keep: int) -> dict:
    """Remove every entry after ``keep`` and rewrite the UNSIGNED head record to match."""
    out = copy.deepcopy(bundle)
    out["entries"] = [e for e in out["entries"] if e["seq"] <= keep]
    last = out["entries"][-1]
    out["attestation"].update(length=len(out["entries"]), head_seq=last["seq"],
                              head_link_hash=last["link_hash"])
    return out


class History:
    """A ledger signed at 11 records (attestation 1), grown to 13, signed again (attestation 2)."""

    def __init__(self, root):
        self.root = root
        self.ledger = EvidenceLedger(root / "ledger.db")
        for i in range(11):
            self.ledger.append(_ev(i), subject=f"CASE-{i % 3}")
        self.key = SigningKey.generate()
        self.log = AttestationLog(root / "attestations.jsonl")
        self.first = attest(self.ledger, self.key, self.log)
        for i in range(11, 13):
            self.ledger.append(_ev(i), subject=f"CASE-{i % 3}")
        self.second = attest(self.ledger, self.key, self.log)
        self.pub = self.write_pub(self.key, "signer.pub")
        self.honest = self.ledger.export(anchor=self.second.to_dict())
        # The attack: drop the last two records, rewrite the unsigned head, embed the OLDER
        # genuine anchor. Every signature on the result is real.
        self.rolled_back = _cut_tail(self.ledger.export(anchor=self.first.to_dict()), 11)

    def write_pub(self, key: SigningKey, name: str):
        path = self.root / name
        path.write_text(key.verifying.pem(), encoding="utf-8")
        return path

    def write(self, bundle: dict, name: str = "bundle.json"):
        path = self.root / name
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return str(path)


@pytest.fixture()
def history(tmp_path):
    return History(tmp_path)


def _verify(*args: str) -> int:
    return cli_main(["evidence", "verify", *args])


class TestARollbackToAnOlderSignedHead:
    def test_without_a_remembered_value_the_rollback_still_reads_as_anchored(self, history, capsys):
        """The hole, kept visible: nothing inside the file can show it. This must not change,
        or every artefact a verifier has ever accepted would verify differently."""
        r = verify_export(history.rolled_back, trusted_key=history.key.verifying)
        assert r.ok and r.completeness == ANCHORED and r.entries == 11
        path = history.write(history.rolled_back)
        assert _verify(path, "--public-key", str(history.pub)) == 0
        out = capsys.readouterr().out
        assert out.startswith("VERIFIED — anchored to a signed head")
        assert "KEEP FOR YOUR NEXT CHECK" in out      # the way to catch it is on the screen

    def test_min_sequence_catches_it_and_counts_the_missing_attestations(self, history, capsys):
        r = verify_export(history.rolled_back, trusted_key=history.key.verifying, min_sequence=2)
        assert not r.ok and r.completeness == FAILED and r.anchor is None
        assert any("attestation 1" in p and "attestation 2" in p
                   and "1 newer attestation(s)" in p for p in r.problems), r.problems
        assert _verify(history.write(history.rolled_back), "--public-key", str(history.pub),
                       "--min-sequence", "2") == 1
        out = capsys.readouterr().out
        assert out.startswith("DOES NOT VERIFY") and "rollback" in out

    @pytest.mark.parametrize("cut", [12, 64])
    def test_expect_head_catches_it_with_a_prefix_or_the_whole_hash(self, history, cut, capsys):
        head = history.second.head_link_hash[:cut]
        r = verify_export(history.rolled_back, trusted_key=history.key.verifying,
                          expect_head=head)
        assert not r.ok and r.completeness == FAILED
        assert any("not in this bundle's chain" in p for p in r.problems), r.problems
        assert _verify(history.write(history.rolled_back), "--public-key", str(history.pub),
                       "--expect-head", head) == 1
        capsys.readouterr()

    def test_min_length_says_how_many_records_were_removed(self, history, capsys):
        r = verify_export(history.rolled_back, trusted_key=history.key.verifying, min_length=13)
        assert not r.ok
        assert any("2 record(s) removed" in p for p in r.problems), r.problems
        assert _verify(history.write(history.rolled_back), "--public-key", str(history.pub),
                       "--min-length", "13") == 1
        assert "2 record(s) removed" in capsys.readouterr().out

    def test_max_age_fails_a_signed_head_that_is_too_old(self, history):
        signed = parse_utc(history.first.attested_at)
        fresh = verify_export(history.rolled_back, trusted_key=history.key.verifying,
                              max_age=timedelta(hours=24), now=signed + timedelta(hours=1))
        assert fresh.ok and fresh.completeness == ANCHORED
        stale = verify_export(history.rolled_back, trusted_key=history.key.verifying,
                              max_age=timedelta(hours=24), now=signed + timedelta(hours=30))
        assert not stale.ok and stale.completeness == FAILED
        assert any("too old" in p and "30.0 h" in p for p in stale.problems), stale.problems

    def test_the_honest_bundle_passes_every_expectation_it_told_the_verifier_to_keep(
            self, history, capsys):
        path = history.write(history.honest)
        assert _verify(path, "--public-key", str(history.pub)) == 0
        out = capsys.readouterr().out
        keep = re.search(r"--min-sequence (\d+) --expect-head ([0-9a-f]{64}) --min-length (\d+)", out)
        assert keep, out
        assert keep.groups() == ("2", history.second.head_link_hash, "13")
        # the headline carries the anchor's sequence, head and age
        first = out.splitlines()[0]
        assert "attestation 2" in first and "seq 13" in first
        assert history.second.head_link_hash[:12] in first and "signed " in first
        assert _verify(path, "--public-key", str(history.pub), "--min-sequence", keep.group(1),
                       "--expect-head", keep.group(2), "--min-length", keep.group(3),
                       "--max-age", "24") == 0
        assert "you remembered" in capsys.readouterr().out

    def test_the_values_to_keep_are_in_the_json(self, history, capsys):
        assert _verify(history.write(history.honest), "--public-key", str(history.pub),
                       "--json") == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["remember_for_next_check"] == {
            "min_sequence": 2, "expect_head": history.second.head_link_hash, "min_length": 13}
        assert doc["anchor"]["sequence"] == 2 and "age" in doc["anchor"]

    def test_nothing_is_kept_for_a_result_that_is_not_anchored(self, history, capsys):
        assert _verify(history.write(history.honest)) == 0       # no key: internal consistency
        assert "KEEP FOR YOUR NEXT CHECK" not in capsys.readouterr().out

    def test_a_head_that_cannot_be_looked_for_is_not_established_never_a_pass(self, history):
        subject = history.ledger.export(subject="CASE-0", anchor=history.second.to_dict())
        r = verify_export(subject, trusted_key=history.key.verifying,
                          expect_head=history.second.head_link_hash)
        assert not r.ok and r.problems == ()
        assert any("remembered" in u for u in r.unestablished), r.unestablished

    def test_remembered_values_without_a_key_are_not_established(self, history):
        r = verify_export(history.honest, min_sequence=2)
        assert not r.ok and r.problems == () and r.completeness != ANCHORED
        assert any("no trusted public key" in u for u in r.unestablished)

    def test_remembered_values_need_a_key_on_the_command_line(self, history):
        path = history.write(history.honest)
        for flag, value in (("--min-sequence", "2"), ("--expect-head", "ab" * 6),
                            ("--min-length", "3"), ("--max-age", "24"),
                            ("--expect-fingerprint", "ab" * 8)):
            with pytest.raises(SystemExit) as exc:
                _verify(path, flag, value)
            assert exc.value.code == 2

    @pytest.mark.parametrize("flag,value", [
        ("--min-sequence", "0"), ("--min-length", "-4"), ("--expect-head", "xyz"),
        ("--expect-head", "abcd"), ("--max-age", "0"), ("--max-age", "nan"),
        ("--expect-fingerprint", "abcd"),
    ])
    def test_nonsense_values_are_a_usage_error_not_a_silent_pass(self, history, flag, value):
        with pytest.raises(SystemExit) as exc:
            _verify(history.write(history.honest), "--public-key", str(history.pub), flag, value)
        assert exc.value.code == 2

    def test_an_expectation_on_a_tampered_bundle_does_not_launder_it(self, history):
        edited = copy.deepcopy(history.honest)
        edited["entries"][2]["evidence"]["body"] = {"n": "edited"}
        r = verify_export(edited, trusted_key=history.key.verifying, min_sequence=1)
        assert not r.ok and r.problems


class TestKeySubstitution:
    @pytest.fixture()
    def forged(self, history, tmp_path):
        """The forger: a shorter ledger of their own, signed with their own key."""
        forger = SigningKey.generate()
        ledger = EvidenceLedger(tmp_path / "forged.db")
        for i in range(5):
            ledger.append(_ev(900 + i), subject="CASE-0")
        log = AttestationLog(tmp_path / "forged.jsonl")
        record = attest(ledger, forger, log)
        return {"key": forger, "pub": history.write_pub(forger, "forger.pub"),
                "bundle": history.write(ledger.export(anchor=record.to_dict()), "forged.json"),
                "log": log}

    def test_a_forgery_checked_with_the_forgers_own_key_passes_without_a_fingerprint(
            self, forged, capsys):
        """The hole: 'VERIFIED' says nothing about WHOSE key. Unchanged without the flag."""
        assert _verify(forged["bundle"], "--public-key", str(forged["pub"])) == 0
        capsys.readouterr()

    def test_expect_fingerprint_makes_the_substituted_key_exit_one(self, history, forged, capsys):
        real = history.key.fingerprint
        assert _verify(forged["bundle"], "--public-key", str(forged["pub"]),
                       "--expect-fingerprint", real) == 1
        out = capsys.readouterr().out
        assert out.startswith("DOES NOT VERIFY")
        assert forged["key"].fingerprint in out and real in out
        assert "swapped" in out

    def test_the_library_reports_it_as_a_problem_and_never_as_anchored(self, history, forged):
        doc = json.loads(open(forged["bundle"]).read())
        r = verify_export(doc, trusted_key=forged["key"].verifying,
                          expect_fingerprints=[history.key.fingerprint])
        assert not r.ok and r.completeness != ANCHORED
        assert any("fingerprint" in p for p in r.problems), r.problems

    def test_the_right_key_with_the_right_fingerprint_passes(self, history, capsys):
        assert _verify(history.write(history.honest), "--public-key", str(history.pub),
                       "--expect-fingerprint", history.key.fingerprint.upper()) == 0
        capsys.readouterr()

    def test_the_output_says_a_fingerprint_is_64_bits(self, history, capsys):
        assert _verify(history.write(history.honest), "--public-key", str(history.pub)) == 0
        out = capsys.readouterr().out
        assert "64 bits" in out and FINGERPRINT_BITS_NOTE in out

    def test_attest_verify_has_the_same_check(self, history, forged, capsys):
        base = ["attest", "verify", "--log", str(forged["log"].path),
                "--public-key", str(forged["pub"])]
        assert cli_main(base) == 0                       # the forgery verifies under its own key
        capsys.readouterr()
        assert cli_main([*base, "--expect-fingerprint", history.key.fingerprint]) == 1
        out = capsys.readouterr().out
        assert "key substitution" in out and "64 bits" in out
        assert cli_main([*base, "--expect-fingerprint", forged["key"].fingerprint]) == 0
        assert "are the ones you expected" in capsys.readouterr().out
        assert cli_main([*base, "--expect-fingerprint", "nonsense"]) == 2
        capsys.readouterr()


class TestAHeadSignedInTheFuture:
    """--max-age bounds how OLD a head is; a head 'signed' in 2099 is -632324 h old and passed."""

    @pytest.fixture()
    def future(self, tmp_path):
        from datetime import UTC, datetime

        led = EvidenceLedger(tmp_path / "f.db")
        for i in range(3):
            led.append(_ev(i), subject="C")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "f.jsonl")
        record = attest(led, key, log, now=datetime(2099, 1, 1, tzinfo=UTC))
        pub = tmp_path / "f.pub"
        pub.write_text(key.verifying.pem(), encoding="utf-8")
        bundle = tmp_path / "f.json"
        bundle.write_text(json.dumps(led.export(anchor=record.to_dict())), encoding="utf-8")
        return {"bundle": str(bundle), "pub": str(pub), "log": str(log.path), "key": key}

    def test_evidence_verify_calls_it_a_finding(self, future, capsys):
        base = ["evidence", "verify", future["bundle"], "--public-key", future["pub"]]
        assert cli_main(base) == 0                                # no bound asked: as before
        capsys.readouterr()
        assert cli_main([*base, "--max-age", "1"]) == 1
        assert "signed in the future" in capsys.readouterr().out

    def test_attest_verify_calls_it_a_finding(self, future, capsys):
        base = ["attest", "verify", "--log", future["log"], "--public-key", future["pub"]]
        assert cli_main(base) == 0
        capsys.readouterr()
        assert cli_main([*base, "--max-age", "1"]) == 1
        assert "signed in the future" in capsys.readouterr().out

    def test_a_few_minutes_of_clock_skew_is_tolerated(self, history):
        signed = parse_utc(history.first.attested_at)
        r = verify_export(history.rolled_back, trusted_key=history.key.verifying,
                          max_age=timedelta(hours=24), now=signed - timedelta(minutes=4))
        assert r.ok
        r = verify_export(history.rolled_back, trusted_key=history.key.verifying,
                          max_age=timedelta(hours=24), now=signed - timedelta(minutes=6))
        assert not r.ok and any("in the future" in p for p in r.problems)
