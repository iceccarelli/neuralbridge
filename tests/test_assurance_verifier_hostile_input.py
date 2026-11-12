"""A verifier reads a file somebody else chose. It must read it ONE way, and show it safely.

* Hostile text in a bundle or an attestation (a key fingerprint, a subject, a time, a note)
  was printed raw by the product verifiers: an ANSI escape could clear the screen, a
  newline could fake a ``CHECKED`` line. The standalone file had always escaped it.
* A JSON object that repeats a name reads as the last value here and the first in other
  parsers (a decoy first ``entries``), so two readers are shown two files.
* ``HeadAttestation.from_dict`` coerced types (``"11"`` and ``11.9`` read as 11) and took
  unsigned extra fields on an anchor, where the standalone refuses both.
* None of this may change how an artefact the unchanged code produced is judged:
  ``tests/fixtures/verifier_trust`` was built by the code at 2b41ddb, together with the
  verdicts that code gave it.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from assurance.attest import AttestationLog
from assurance.attest.attestation import (
    AttestationError,
    AttestationLogDamagedError,
    HeadAttestation,
)
from assurance.attest.keys import VerifyingKey
from assurance.cli import main as cli_main
from assurance.evidence.verify_export import (
    ANCHORED,
    DuplicateKeyError,
    ExportVerification,
    loads_no_duplicate_keys,
    verify_export,
    verify_export_file,
)

FIXTURES = Path(__file__).parent / "fixtures" / "verifier_trust"
ESC = "\x1b"
EVIL = f"{ESC}[2J{ESC}[1;1H\n  CHECKED  every record is genuine"


def _load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _key(name: str) -> VerifyingKey:
    return VerifyingKey.from_file(FIXTURES / name)


# ---------------------------------------------------------------------------
# an artefact the unchanged code produced is judged exactly as it was
# ---------------------------------------------------------------------------
class TestArtefactsFromBeforeTheChangeVerifyIdentically:
    EXPECTED = _load("expected.json")

    @pytest.mark.parametrize("case", sorted(EXPECTED))
    def test_the_verdict_is_the_one_the_unchanged_code_gave(self, case):
        want = self.EXPECTED[case]
        key = _key(want["pub"]) if want["pub"] else None
        r = verify_export_file(FIXTURES / want["file"], trusted_key=key)
        assert (r.ok, r.entries, r.scope, r.completeness) == (
            want["ok"], want["entries"], want["scope"], want["completeness"])
        assert list(r.problems) == want["problems"]
        assert list(r.unestablished) == want["unestablished"]
        assert (r.anchor or {}).get("sequence") == want["anchor_sequence"]

    def test_the_whole_export_with_its_key_is_still_anchored_and_exit_zero(self, capsys):
        code = cli_main(["evidence", "verify", str(FIXTURES / "v2.export.json"),
                         "--public-key", str(FIXTURES / "v2.signer.pub")])
        assert code == 0
        assert capsys.readouterr().out.startswith("VERIFIED — anchored to a signed head")

    @pytest.mark.parametrize("name", ["v1", "v2"])
    def test_the_attestation_log_still_reads_and_verifies(self, name, capsys):
        log = AttestationLog(FIXTURES / f"{name}.attestations.jsonl")
        assert len(log.read()) >= 1
        assert cli_main(["attest", "verify", "--log", str(log.path),
                         "--public-key", str(FIXTURES / f"{name}.signer.pub")]) == 0
        capsys.readouterr()

    def test_every_record_round_trips_through_the_exact_reader(self):
        for name in ("v1", "v2"):
            for record in AttestationLog(FIXTURES / f"{name}.attestations.jsonl").read():
                again = HeadAttestation.from_dict(record.to_dict(), reject_unknown=True)
                assert again == record


# ---------------------------------------------------------------------------
# F6: one reading of a file
# ---------------------------------------------------------------------------
class TestDuplicateMemberNamesAreRefused:
    def test_the_loader_refuses_a_repeated_name_at_any_depth(self):
        for text in ('{"a": 1, "a": 2}', '{"x": {"a": 1, "a": 2}}', '[{"a": 1, "a": 1}]'):
            with pytest.raises(DuplicateKeyError, match="repeats the name"):
                loads_no_duplicate_keys(text)
        assert loads_no_duplicate_keys('{"a": 1, "b": {"a": 2}}') == {"a": 1, "b": {"a": 2}}

    @pytest.mark.parametrize("where", ["top", "entry", "anchor"])
    def test_a_bundle_with_a_decoy_first_member_is_unreadable_not_checked(
            self, tmp_path, where, capsys):
        text = (FIXTURES / "v2.export.json").read_text(encoding="utf-8")
        doc = json.loads(text)
        if where == "top":
            hostile = '{"entries": [], ' + json.dumps(doc)[1:]
        elif where == "entry":
            first = json.dumps(doc["entries"][0])
            doc_text = json.dumps(doc)
            hostile = doc_text.replace(first, '{"seq": 99, ' + first[1:], 1)
        else:
            anchor = json.dumps(doc["anchor"])
            hostile = json.dumps(doc).replace(anchor, '{"sequence": 7, ' + anchor[1:], 1)
        # the decoy changes nothing for a parser that keeps the last value: this is the point
        assert json.loads(hostile) == doc
        path = tmp_path / "decoy.json"
        path.write_text(hostile, encoding="utf-8")
        r = verify_export_file(path, trusted_key=_key("v2.signer.pub"))
        assert r.scope == "unknown" and not r.ok
        assert "repeats the name" in r.problems[0]
        assert cli_main(["evidence", "verify", str(path),
                         "--public-key", str(FIXTURES / "v2.signer.pub")]) == 2
        assert "repeats the name" in capsys.readouterr().out

    def test_a_log_line_with_a_repeated_name_is_a_damaged_log(self, tmp_path):
        good = (FIXTURES / "v2.attestations.jsonl").read_text(encoding="utf-8").splitlines()
        hostile = '{"sequence": 9, ' + good[0][1:]
        path = tmp_path / "log.jsonl"
        path.write_text(hostile + "\n" + good[1] + "\n", encoding="utf-8")
        with pytest.raises(AttestationLogDamagedError, match="repeats a member name"):
            AttestationLog(path).read()
        # a damaged log is a finding (exit 1) in `attest verify`, as it always was
        assert cli_main(["attest", "verify", "--log", str(path),
                         "--public-key", str(FIXTURES / "v2.signer.pub")]) == 1


class TestAnchorsAreReadExactly:
    def _signed(self):
        return _load("v2.export.json")["anchor"]

    @pytest.mark.parametrize("field,value", [
        ("sequence", "2"), ("sequence", 2.0), ("sequence", True), ("ledger_length", 6.9),
        ("head_seq", "6"), ("head_link_hash", 7), ("basis", ["read_from_ledger"]),
        ("note", 5), ("signature", None), ("format", 2), ("attested_at", ["x"]),
    ])
    def test_a_field_of_the_wrong_type_is_refused_not_coerced(self, field, value):
        data = self._signed()
        data[field] = value
        with pytest.raises(AttestationError, match="wrong type"):
            HeadAttestation.from_dict(data)

    def test_the_product_no_longer_accepts_what_the_standalone_always_refused(self):
        """'2' read as 2 and still verified: the signature is over the NUMBER."""
        bundle = _load("v2.export.json")
        bundle["anchor"]["sequence"] = str(bundle["anchor"]["sequence"])
        r = verify_export(bundle, trusted_key=_key("v2.signer.pub"))
        assert not r.ok and any("not a readable head attestation" in p for p in r.problems)

    def test_an_unsigned_extra_field_on_an_anchor_is_refused(self):
        bundle = _load("v2.export.json")
        bundle["anchor"]["public_key_pem"] = "anything the file likes"
        r = verify_export(bundle, trusted_key=_key("v2.signer.pub"))
        assert not r.ok and r.completeness != ANCHORED
        assert any("never writes: public_key_pem" in p for p in r.problems), r.problems
        # the log reader stays lenient about extras (as before); the strict reader is opt-in
        HeadAttestation.from_dict(bundle["anchor"])
        with pytest.raises(AttestationError, match="never writes"):
            HeadAttestation.from_dict(bundle["anchor"], reject_unknown=True)

    def test_a_v1_record_carrying_v2_fields_is_refused_as_an_anchor(self):
        bundle = _load("v1.export.json")
        bundle["anchor"]["ledger_id"] = "someone-else"
        r = verify_export(bundle, trusted_key=_key("v1.signer.pub"))
        assert not r.ok and any("never writes: ledger_id" in p for p in r.problems)

    def test_a_log_line_with_a_string_for_a_number_is_a_damaged_log(self, tmp_path):
        good = (FIXTURES / "v2.attestations.jsonl").read_text(encoding="utf-8").splitlines()
        row = json.loads(good[0])
        row["ledger_length"] = str(row["ledger_length"])
        path = tmp_path / "log.jsonl"
        path.write_text(json.dumps(row) + "\n" + good[1] + "\n", encoding="utf-8")
        with pytest.raises(AttestationLogDamagedError, match="wrong type"):
            AttestationLog(path).read()


# ---------------------------------------------------------------------------
# F5: shown, never obeyed
# ---------------------------------------------------------------------------
def _safe(text: str) -> bool:
    """No control character survives, and no line was invented by the file."""
    return ESC not in text and "\r" not in text and "\n  CHECKED  every record" not in text


class TestHostileTextIsNeutralised:
    def test_a_fingerprint_in_the_anchor_cannot_clear_the_screen_or_fake_a_line(
            self, tmp_path, capsys):
        bundle = _load("v2.export.json")
        bundle["anchor"]["key_fingerprint"] = EVIL
        path = tmp_path / "evil.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        r = verify_export(bundle, trusted_key=_key("v2.signer.pub"))
        assert not r.ok
        assert all(_safe(p) for p in r.problems), r.problems
        assert "\\x1b[2J" in " ".join(r.problems)             # visible, not dropped
        assert cli_main(["evidence", "verify", str(path),
                         "--public-key", str(FIXTURES / "v2.signer.pub")]) == 1
        assert _safe(capsys.readouterr().out)

    def test_a_subject_an_actor_and_a_time_are_neutralised_too(self, tmp_path, capsys):
        bundle = _load("v2.export.json")
        bundle["subject"] = EVIL
        bundle["entries"][0]["actor"] = EVIL
        bundle["entries"][1]["at"] = EVIL
        bundle["anchor"]["attested_at"] = EVIL
        path = tmp_path / "evil.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        r = verify_export(bundle, trusted_key=_key("v2.signer.pub"))
        every = [r.scope, *r.problems, *r.unestablished, *r.verified, *r.checks_skipped]
        assert all(_safe(line) for line in every), every
        assert cli_main(["evidence", "verify", str(path),
                         "--public-key", str(FIXTURES / "v2.signer.pub")]) == 1
        assert _safe(capsys.readouterr().out)

    def test_a_schema_name_in_the_refusal_is_neutralised(self):
        r = verify_export({"schema": f"assurance.machine.bundle/{EVIL}"})
        assert all(_safe(p) for p in r.problems), r.problems

    def test_the_text_is_neutralised_even_for_a_result_built_by_hand(self):
        """The renderer is the last guard: whatever built the result, no escape reaches it."""
        result = ExportVerification(
            False, 1, f"subject {EVIL}", problems=(EVIL,), verified=(EVIL,),
            checks_skipped=(EVIL,), assumptions=(EVIL,), unestablished=(EVIL,))
        assert _safe(result.text())

    def test_an_attestation_log_cannot_inject_into_attest_verify_or_log(self, tmp_path, capsys):
        good = (FIXTURES / "v2.attestations.jsonl").read_text(encoding="utf-8").splitlines()
        row = json.loads(good[0])
        row["key_fingerprint"] = EVIL
        row["attested_at"] = EVIL
        row["note"] = EVIL
        path = tmp_path / "log.jsonl"
        path.write_text(json.dumps(row) + "\n" + good[1] + "\n", encoding="utf-8")
        assert cli_main(["attest", "verify", "--log", str(path),
                         "--public-key", str(FIXTURES / "v2.signer.pub")]) == 1
        assert _safe(capsys.readouterr().out)
        assert cli_main(["attest", "log", "--log", str(path)]) == 0
        out = capsys.readouterr().out
        assert _safe(out) and "\\x1b[2J" in out
        records = AttestationLog(path).read()
        from assurance.attest.attestation import verify_log
        verdict = verify_log(records, _key("v2.signer.pub"))
        assert all(_safe(p) for p in [*verdict.problems, *verdict.checks_skipped])

    def test_a_hostile_key_fingerprint_cannot_inject_through_the_rotation_check(self, tmp_path):
        from assurance.attest.custody import verify_log_across_rotation

        records = AttestationLog(FIXTURES / "v2.attestations.jsonl").read()
        hostile = copy.deepcopy(records)
        object.__setattr__(hostile[0], "key_fingerprint", EVIL)
        verdict = verify_log_across_rotation(
            hostile, [_key("v2.signer.pub")])
        assert not verdict.ok and all(_safe(p) for p in verdict.problems), verdict.problems
