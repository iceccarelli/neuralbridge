"""The one-file verifier and the product's must say the same thing about the same file.

An audit found the standalone file calling a GENUINE subject export "DOES NOT VERIFY ... a record
was removed" (exit 1) where the product, and the runbook, say exit 3; it also had no
``--attestations``, one key, no keyset, no remembered values and no fingerprint check. Here every
input class is run through BOTH and the exit codes compared. The standalone may be stricter (it
never merges a skeleton, and never exits 0 without a key); it must never be more lenient, and
where the product says 1 or 2 it says the same.
"""
# ruff: noqa: S603  (runs this repository's own shipped script)
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.cli import main as cli_main

from .test_assurance_keyset import Rotation, _t
from .test_assurance_verifier_rollback import History

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_export_standalone.py"
FIXTURES = Path(__file__).parent / "fixtures" / "verifier_trust"
ESC = "\x1b"


def standalone(*args: str) -> tuple[int, str]:
    run = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,
                         timeout=60, check=False)
    return run.returncode, run.stdout + run.stderr


def both(capsys, bundle: str, *flags: str) -> tuple[int, int, str]:
    capsys.readouterr()
    product = cli_main(["evidence", "verify", bundle, *flags])
    capsys.readouterr()
    code, out = standalone(bundle, *flags)
    return product, code, out


@pytest.fixture()
def history(tmp_path):
    return History(tmp_path)


@pytest.fixture()
def rot(tmp_path):
    return Rotation(tmp_path)


class TestSubjectExports:
    def test_a_genuine_subject_export_is_exit_three_never_a_removed_record(
            self, history, capsys):
        bundle = history.write(history.ledger.export(subject="CASE-0",
                                                     anchor=history.second.to_dict()))
        for flags in ((), ("--public-key", str(history.pub))):
            product, code, out = both(capsys, bundle, *flags)
            assert code == 3, out
            assert "a record was removed" not in out and "no skeleton" in out
        assert product == 3

    def test_a_subject_export_with_a_skeleton_is_not_judged_whole_either(self, history, capsys):
        bundle = history.write(history.ledger.export(
            subject="CASE-0", anchor=history.second.to_dict(), skeleton=True))
        product, code, out = both(capsys, bundle, "--public-key", str(history.pub))
        assert code == 3 and "skeleton" in out, out
        assert product in (0, 3)          # the product may merge it; this file must not pass it

    def test_a_tampered_subject_export_is_still_exit_one(self, history, capsys):
        doc = history.ledger.export(subject="CASE-0", anchor=history.second.to_dict())
        doc["entries"][1]["evidence"]["body"] = {"n": "edited"}
        product, code, out = both(capsys, history.write(doc), "--public-key", str(history.pub))
        assert product == 1 and code == 1, out

    def test_an_entry_of_another_subject_and_an_empty_export_are_exit_one(self, history, capsys):
        doc = history.ledger.export(subject="CASE-0", anchor=history.second.to_dict())
        doc["subject"] = "CASE-1"
        assert both(capsys, history.write(doc), "--public-key", str(history.pub))[:2] == (1, 1)
        doc = history.ledger.export(subject="NO-SUCH", anchor=history.second.to_dict())
        assert both(capsys, history.write(doc), "--public-key", str(history.pub))[:2] == (1, 1)

    def test_a_whole_export_carrying_a_skeleton_is_exit_one(self, history, capsys):
        doc = copy.deepcopy(history.honest)
        doc["skeleton"] = []
        assert both(capsys, history.write(doc), "--public-key", str(history.pub))[:2] == (1, 1)


class TestRememberedValues:
    def test_the_rollback_is_exit_one_with_each_value_in_both(self, history, capsys):
        bundle = history.write(history.rolled_back)
        key = ("--public-key", str(history.pub))
        assert both(capsys, bundle, *key)[:2] == (0, 0)             # the hole, in both, unchanged
        for flags in (("--min-sequence", "2"), ("--expect-head", history.second.head_link_hash[:12]),
                      ("--min-length", "13")):
            product, code, out = both(capsys, bundle, *key, *flags)
            assert (product, code) == (1, 1), (flags, out)
        _, code, out = both(capsys, bundle, *key, "--min-length", "13")[0:3]
        assert "2 record(s) removed" in out

    def test_max_age(self, history, capsys):
        product, code, out = both(capsys, history.write(history.rolled_back), "--public-key",
                                  str(history.pub), "--max-age", "0.000001")
        assert (product, code) == (1, 1), out

    def test_the_honest_export_passes_with_exactly_what_it_said_to_keep(self, history, capsys):
        bundle = history.write(history.honest)
        key = ("--public-key", str(history.pub))
        product, code, out = both(capsys, bundle, *key)
        assert (product, code) == (0, 0)
        keep = f"--min-sequence 2 --expect-head {history.second.head_link_hash} --min-length 13"
        assert keep in out
        assert both(capsys, bundle, *key, *keep.split())[:2] == (0, 0)

    def test_values_without_a_key_are_a_usage_error_in_both(self, history, capsys):
        bundle = history.write(history.honest)
        with pytest.raises(SystemExit):
            cli_main(["evidence", "verify", bundle, "--min-sequence", "2"])
        capsys.readouterr()
        assert standalone(bundle, "--min-sequence", "2")[0] == 2

    @pytest.mark.parametrize("flag,value", [("--min-sequence", "0"), ("--expect-head", "xyz"),
                                            ("--max-age", "-1"), ("--expect-fingerprint", "ab")])
    def test_nonsense_is_a_usage_error(self, history, flag, value):
        bundle = history.write(history.honest)
        assert standalone(bundle, "--public-key", str(history.pub), flag, value)[0] == 2

    def test_a_customers_own_attestation_log_catches_a_resigned_cut(self, history, capsys):
        bundle = history.write(history.rolled_back)
        key = ("--public-key", str(history.pub))
        assert both(capsys, bundle, *key, "--attestations", str(history.log.path))[:2] == (1, 1)
        assert standalone(bundle, *key, "--attestations", str(history.root / "nope.jsonl"))[0] == 2
        torn = history.root / "torn.jsonl"
        torn.write_text(history.log.path.read_text() + '{"sequence": 3')
        product, code, _ = both(capsys, history.write(history.honest), *key,
                                "--attestations", str(torn))
        assert (product, code) == (2, 2)


class TestKeys:
    def test_a_substituted_key_is_exit_one_in_both(self, history, tmp_path, capsys):
        from assurance.attest import SigningKey

        other = SigningKey.generate()
        pub = history.write_pub(other, "other.pub")
        bundle = history.write(history.honest)
        product, code, out = both(capsys, bundle, "--public-key", str(pub))
        assert (product, code) == (1, 1) and "foreign anchor" in out
        ok = both(capsys, bundle, "--public-key", str(history.pub), "--expect-fingerprint",
                  history.key.fingerprint)
        assert ok[:2] == (0, 0)
        bad = both(capsys, bundle, "--public-key", str(history.pub), "--expect-fingerprint",
                   other.fingerprint)
        assert bad[:2] == (1, 1)
        assert "64 bits" in standalone(bundle, "--public-key", str(history.pub))[1]

    def test_the_keyset_cases_agree(self, rot, capsys):
        later, earlier = rot.bundle(rot.second), rot.bundle(rot.first, "first.json")
        ks = str(rot.keyset())
        assert both(capsys, later, "--keyset", ks)[:2] == (0, 0)
        assert both(capsys, earlier, "--keyset", ks)[:2] == (3, 3)           # 2 records unsigned
        assert both(capsys, later, "--public-key", str(rot.pub1), "--public-key",
                    str(rot.pub2))[:2] == (0, 0)
        only_one = both(capsys, later, "--public-key", str(rot.pub1))
        assert only_one[:2] == (1, 1) and "foreign anchor" in only_one[2]
        unknown = both(capsys, later, "--keyset", str(_keyset_of(rot, rot.k1)))
        assert unknown[:2] == (3, 3) and "not in your keyset" in unknown[2]
        assert both(capsys, earlier, "--keyset", str(rot.keyset(k1="revoked")))[:2] == (1, 1)
        assert both(capsys, earlier, "--keyset", str(
            rot.keyset(k1_until=_early(rot))))[:2] == (1, 1)
        assert both(capsys, earlier, "--keyset", str(rot.keyset(
            k1_from=_t(rot.t0, hours=1), k1_until=_t(rot.t0, hours=3))))[:2] == (1, 1)
        assert both(capsys, later, "--keyset", ks, "--expect-fingerprint",
                    rot.k1.fingerprint)[:2] == (1, 1)

    def test_a_keyset_that_cannot_be_trusted_is_exit_two_in_both(self, rot, capsys):
        bundle = rot.bundle(rot.second)
        bad = rot.root / "bad.json"
        doc = json.loads(rot.keyset().read_text())
        doc["keys"][0]["label"] = "-----BEGIN PRIVATE KEY-----"
        bad.write_text(json.dumps(doc))
        assert both(capsys, bundle, "--keyset", str(bad))[:2] == (2, 2)
        doc = json.loads(rot.keyset().read_text())
        doc["keys"][0]["fingerprint"] = "0" * 16
        bad.write_text(json.dumps(doc))
        assert both(capsys, bundle, "--keyset", str(bad))[:2] == (2, 2)
        doc = json.loads(rot.keyset().read_text())
        doc["extra"] = 1
        bad.write_text(json.dumps(doc))
        assert both(capsys, bundle, "--keyset", str(bad))[:2] == (2, 2)
        assert both(capsys, bundle, "--keyset", str(rot.keyset()), "--public-key",
                    str(rot.pub2))[:2] == (2, 2)                      # a key given twice


def _early(rot):
    return _t(rot.t0, seconds=1)


def _keyset_of(rot, key):
    path = rot.root / "one.json"
    path.write_text(json.dumps({"format": "assurance.attest.keyset.v1", "keys": [
        rot._entry(key, "active", "2020-01-01T00:00:00Z", None, "")]}))
    return path


class TestHostileInput:
    def test_a_repeated_name_and_wrong_types_and_riders_agree(self, history, capsys):
        text = json.dumps(history.honest)
        decoy = history.root / "decoy.json"
        decoy.write_text('{"entries": [], ' + text[1:])
        assert both(capsys, str(decoy), "--public-key", str(history.pub))[:2] == (2, 2)
        key = ("--public-key", str(history.pub))
        typed = copy.deepcopy(history.honest)
        typed["anchor"]["sequence"] = str(typed["anchor"]["sequence"])
        assert both(capsys, history.write(typed), *key)[:2] == (1, 1)
        rider = copy.deepcopy(history.honest)
        rider["anchor"]["public_key_pem"] = "anything"
        assert both(capsys, history.write(rider), *key)[:2] == (1, 1)

    def test_a_keyset_and_a_log_with_a_repeated_name_are_refused(self, rot, capsys):
        text = rot.keyset().read_text()
        bad = rot.root / "dup.json"
        bad.write_text('{"format": "x", ' + text[1:])
        assert both(capsys, rot.bundle(rot.second), "--keyset", str(bad))[:2] == (2, 2)

    def test_hostile_text_never_reaches_either_output(self, history, capsys):
        doc = copy.deepcopy(history.honest)
        doc["anchor"]["key_fingerprint"] = f"{ESC}[2J\n  CHECKED  fake"
        doc["subject"] = f"{ESC}[31m"
        bundle = history.write(doc)
        capsys.readouterr()
        cli_main(["evidence", "verify", bundle, "--public-key", str(history.pub)])
        assert ESC not in capsys.readouterr().out
        assert ESC not in standalone(bundle, "--public-key", str(history.pub))[1]


class TestPreChangeArtefactsAreJudgedAsBefore:
    @pytest.mark.parametrize("name,code", [("v2.export.json", 0), ("v1.export.json", 0),
                                           ("v2.subject.export.json", 3)])
    def test_with_the_key(self, name, code):
        pub = FIXTURES / ("v1.signer.pub" if name.startswith("v1") else "v2.signer.pub")
        assert standalone(str(FIXTURES / name), "--public-key", str(pub))[0] == code

    def test_without_the_key_nothing_is_a_bare_pass(self):
        assert standalone(str(FIXTURES / "v2.export.json"))[0] == 3


def test_a_head_signed_in_the_future_fails_max_age_in_the_standalone_too(tmp_path, capsys):
    from datetime import UTC, datetime

    from assurance.attest import AttestationLog, SigningKey, attest
    from assurance.evidence import EvidenceLedger

    from .test_assurance_verifier_rollback import _ev

    led = EvidenceLedger(tmp_path / "f.db")
    for i in range(3):
        led.append(_ev(i), subject="C")
    key = SigningKey.generate()
    record = attest(led, key, AttestationLog(tmp_path / "f.jsonl"),
                    now=datetime(2099, 1, 1, tzinfo=UTC))
    pub = tmp_path / "f.pub"
    pub.write_text(key.verifying.pem(), encoding="utf-8")
    bundle = tmp_path / "f.json"
    bundle.write_text(json.dumps(led.export(anchor=record.to_dict())), encoding="utf-8")
    assert standalone(str(bundle), "--public-key", str(pub))[0] == 0
    code, out = standalone(str(bundle), "--public-key", str(pub), "--max-age", "1")
    assert code == 1 and "signed in the future" in out, out


class TestOneKeyBlockAndNothingElse:
    """The PEM loader skipped text before a block and ignored everything after it, so junk or a
    second key appended to a key file loaded the FIRST key without a word."""

    @staticmethod
    def _variants(good: str, other: str) -> dict:
        return {"junk before": "note to self\n" + good, "junk after": good + "trailing words\n",
                "second block": good + other, "second block first": other + good,
                "two begins": good.replace("\n", "\n-----BEGIN PUBLIC KEY-----\n", 1)}

    def test_product_and_standalone_refuse_the_same_files_and_accept_what_the_tools_write(
            self, history, capsys):
        from assurance.attest import SigningKey
        from assurance.attest.keys import SigningKeyError, VerifyingKey

        good = history.key.verifying.pem()
        other = SigningKey.generate().verifying.pem()
        bundle = history.write(history.honest)
        accepted = {"as written": good, "no final newline": good.rstrip("\n"),
                    "blank lines around": "\n\n" + good + "\n\n", "crlf": good.replace("\n", "\r\n")}
        for name, text in accepted.items():
            path = history.root / "ok.pub"
            path.write_text(text, encoding="utf-8", newline="")
            VerifyingKey.from_pem(text)
            assert both(capsys, bundle, "--public-key", str(path))[:2] == (0, 0), name
        for name, text in self._variants(good, other).items():
            path = history.root / "bad.pub"
            path.write_text(text, encoding="utf-8")
            with pytest.raises(SigningKeyError):
                VerifyingKey.from_pem(text)
            product, code, out = both(capsys, bundle, "--public-key", str(path))
            assert product == 2 and code == 3 and "could not be read" in out, (name, product, code)

    def test_a_private_key_file_with_a_second_block_is_refused_and_the_saved_one_loads(
            self, tmp_path):
        import os

        from assurance.attest import SigningKey
        from assurance.attest.keys import SigningKeyError

        directory = tmp_path / "keys"
        directory.mkdir(mode=0o700)
        key = SigningKey.generate()
        saved = key.save(directory / "k.pem")
        text = saved.read_text()
        assert SigningKey.load(saved).fingerprint == key.fingerprint
        for bad in ("junk\n" + text, text + "junk\n", text + SigningKey.generate().save(
                directory / "k2.pem").read_text()):
            with pytest.raises(SigningKeyError):
                SigningKey.from_pem(bad)
        assert os.name == "posix"
