"""A bundle can be cut short, or rebuilt without entries, and stay internally consistent.

The audit that motivated this reproduced four silent truncations that
``verify_export`` called verified. Only a SIGNED anchor, checked under a key the
verifier obtained elsewhere, shows nothing was removed; without one the result
must say completeness was not checked. Every bundle here comes from the real
ledger and the real attestation signer; the forgeries are what someone holding
the whole file can do (the hashes are unkeyed, so a chain can be rebuilt).
"""

from __future__ import annotations

import copy
import json

import pytest

from assurance.attest import AttestationLog, SigningKey, attest
from assurance.cli import main as cli_main
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger
from assurance.evidence import ledger as ledger_module
from assurance.evidence.ledger import GENESIS, AnchorContradictsLedgerError, LedgerEntry
from assurance.evidence.verify_export import ANCHORED, FAILED, NOT_CHECKED, verify_export

SECRET = "SECRET-BODY-MARKER-9f3a"


def _ev(n: int, **extra) -> Evidence:
    return Evidence(kind="t.record", body={"n": n, **extra},
                    actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


@pytest.fixture()
def signed(tmp_path):
    """8 entries (CASE-A at 1,3,5,7; CASE-B at 2,4,6,8); a signature over the first 6."""
    led = EvidenceLedger(tmp_path / "anchored.db")
    for i in range(6):
        led.append(_ev(i), subject="CASE-A" if i % 2 == 0 else "CASE-B")
    key = SigningKey.generate()
    log = AttestationLog(tmp_path / "attestations.jsonl")
    attest(led, key, log)
    for i in range(6, 8):
        led.append(_ev(i, secret=SECRET), subject="CASE-A" if i % 2 == 0 else "CASE-B")
    return led, key, log


def _anchor(log):
    return log.require_last().to_dict()


def _relink(records):
    """Renumber and re-chain records exactly as a forger with the whole file can."""
    prev = GENESIS
    for i, r in enumerate(records, start=1):
        r["seq"], r["prev_hash"] = i, prev
        r["link_hash"] = LedgerEntry(
            seq=i, at=r["at"], kind=r["kind"], subject=r["subject"],
            content_hash=r["content_hash"], prev_hash=prev, link_hash="",
            actor="", payload={}).expected_link_hash()
        prev = r["link_hash"]
    return records


def _rebuild_without(bundle, drop):
    """A consistent bundle with the records at ``drop`` (original seqs) left out."""
    out = copy.deepcopy(bundle)
    records = sorted([*out["entries"], *out.get("skeleton", [])], key=lambda r: r["seq"])
    records = _relink([r for r in records if r["seq"] not in drop])
    out["entries"] = [r for r in records if "evidence" in r]
    if "skeleton" in out:
        out["skeleton"] = [r for r in records if "evidence" not in r]
    else:  # whole ledger: the exporter's unsigned attestation is rewritten to match
        out["attestation"].update(length=len(records), head_seq=len(records),
                                  head_link_hash=records[-1]["link_hash"])
    return out


def _cut_tail(bundle, keep):
    out = copy.deepcopy(bundle)
    out["entries"] = [e for e in out["entries"] if e["seq"] <= keep]
    if "skeleton" in out:
        out["skeleton"] = [s for s in out["skeleton"] if s["seq"] <= keep]
    else:
        last = out["entries"][-1]
        out["attestation"].update(length=len(out["entries"]), head_seq=last["seq"],
                                  head_link_hash=last["link_hash"])
    return out


REPROS = [
    "subject bundle, tail cut",
    "whole bundle, tail cut and attestation rewritten",
    "subject bundle, middle entry removed",
    "subject bundle, head entries removed",
]


def _repro(led, anchor, name):
    whole = led.export(anchor=anchor)
    subj = led.export(subject="CASE-A", anchor=anchor)
    return {
        REPROS[0]: lambda: _cut_tail(subj, 4),
        REPROS[1]: lambda: _cut_tail(whole, 4),
        REPROS[2]: lambda: _rebuild_without(subj, {3}),
        REPROS[3]: lambda: _rebuild_without(subj, {1}),
    }[name]()


class TestCompletenessNeedsASignedAnchor:
    def test_an_untampered_export_verifies_and_is_anchored(self, signed):
        led, key, log = signed
        for bundle in (led.export(anchor=_anchor(log)),
                       led.export(subject="CASE-A", anchor=_anchor(log))):
            r = verify_export(bundle, trusted_key=key.verifying)
            assert r.ok and r.completeness == ANCHORED, r.problems
            assert r.anchor["head_seq"] == 6 and r.anchor["records_after_anchor"] == 2
            assert any("signed anchor" in v for v in r.verified)
            assert any("covered by no signature" in c for c in r.checks_skipped)
            assert r.text().startswith("VERIFIED — anchored")

    @pytest.mark.parametrize("name", REPROS)
    def test_each_truncation_is_rejected_with_a_trusted_key_and_anchor(self, signed, name):
        led, key, log = signed
        r = verify_export(_repro(led, _anchor(log), name), trusted_key=key.verifying)
        assert not r.ok and r.completeness == FAILED
        assert any("anchor" in p for p in r.problems), r.problems

    @pytest.mark.parametrize("name", REPROS)
    def test_each_truncation_without_a_key_reports_completeness_not_checked(
            self, signed, name):
        led, _, log = signed
        for anchor in (_anchor(log), None):
            r = verify_export(_repro(led, anchor, name))
            # Internally consistent, so nothing to find; but never a bare pass.
            assert r.ok and r.completeness == NOT_CHECKED
            assert r.checks_skipped[0].startswith("COMPLETENESS NOT CHECKED")
            assert r.text().startswith("VERIFIED (internal consistency only; "
                                       "completeness NOT CHECKED)")
            assert r.anchor is None

    def test_the_unsigned_embedded_attestation_is_never_an_anchor(self, signed):
        led, key, _ = signed
        bundle = led.export()  # nothing signed in it
        assert verify_export(bundle).completeness == NOT_CHECKED
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and any("no signed anchor" in p for p in r.problems)
        assert r.completeness != ANCHORED

    def test_stripping_the_anchor_does_not_buy_a_pass_when_a_key_is_supplied(self, signed):
        led, key, log = signed
        bundle = led.export(subject="CASE-A", anchor=_anchor(log))
        del bundle["anchor"]
        assert not verify_export(bundle, trusted_key=key.verifying).ok

    def test_a_signed_anchor_without_the_key_is_not_checked_and_says_so(self, signed):
        led, _, log = signed
        r = verify_export(led.export(anchor=_anchor(log)))
        assert r.ok and r.completeness == NOT_CHECKED
        assert "no trusted public key" in r.checks_skipped[0]

    def test_an_anchor_from_a_foreign_key_is_rejected(self, signed, tmp_path):
        led, key, _ = signed
        foreign_log = AttestationLog(tmp_path / "foreign.jsonl")
        attest(led, SigningKey.generate(), foreign_log)
        r = verify_export(led.export(anchor=_anchor(foreign_log)), trusted_key=key.verifying)
        assert not r.ok and any("not the trusted key" in p for p in r.problems)

    def test_a_forged_anchor_signature_is_rejected(self, signed):
        led, key, log = signed
        bundle = led.export(anchor=_anchor(log))
        bundle["anchor"]["head_link_hash"] = "ab" * 32
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and any("signature does not verify" in p for p in r.problems)

    def test_the_key_is_never_taken_from_the_bundle(self, signed):
        led, key, log = signed
        bundle = led.export(anchor=_anchor(log))
        bundle["anchor"]["public_key_pem"] = key.verifying.pem()
        assert not verify_export(bundle, trusted_key=SigningKey.generate().verifying).ok

    def test_the_verifiers_own_copy_of_an_attestation_catches_a_resigned_cut(
            self, signed, tmp_path):
        """A hosted operator holding the key signs the shorter ledger. Only the
        customer's retained earlier record contradicts it."""
        led, key, log = signed
        retained = log.require_last()
        short = EvidenceLedger(tmp_path / "operator-view.db")
        for e in led.entries():
            if e.seq <= 4:
                short.append(e.evidence(), subject=e.subject)
        fresh = AttestationLog(tmp_path / "operator.jsonl")
        attest(short, key, fresh)
        cut = _cut_tail(led.export(), 4)
        cut["anchor"] = fresh.require_last().to_dict()
        assert verify_export(cut, trusted_key=key.verifying).ok  # embedded anchor alone passes
        r = verify_export(cut, trusted_key=key.verifying, anchors=[retained])
        assert not r.ok and r.completeness == FAILED

    def test_supplied_attestations_anchor_a_bundle_that_carries_none(self, signed):
        led, key, log = signed
        ok = verify_export(led.export(subject="CASE-A"), trusted_key=key.verifying,
                           anchors=[log.require_last()])
        assert ok.ok and ok.completeness == ANCHORED
        cut = verify_export(_cut_tail(led.export(subject="CASE-A"), 4),
                            trusted_key=key.verifying, anchors=[log.require_last()])
        assert not cut.ok

    def test_a_declared_length_longer_than_the_bundle_is_a_cut_even_if_the_link_matches(
            self, signed):
        """A counter-signature is whatever head the holder declared. If it signs for
        more records than the bundle holds, the bundle is short, whatever seq 4 links as."""
        from assurance.attest import LedgerHead

        led, key, _ = signed
        four = led.entries()[3]
        log = AttestationLog(led.path.parent / "declared.jsonl")
        attest(LedgerHead(length=8, head_seq=4, head_link_hash=four.link_hash), key, log)
        bundle = led.export()
        bundle["entries"] = bundle["entries"][:4]
        bundle["attestation"].update(length=4, head_seq=4, head_link_hash=four.link_hash)
        bundle["anchor"] = _anchor(log)
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and any("signed record(s) were cut" in p for p in r.problems)

    def test_an_anchor_over_an_empty_ledger_covers_no_record(self, tmp_path):
        led = EvidenceLedger(tmp_path / "e.db")
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)
        led.append(_ev(1), subject="X")
        r = verify_export(led.export(anchor=_anchor(log)), trusted_key=key.verifying)
        assert r.ok and r.completeness == ANCHORED
        assert any("covers no record" in v for v in r.verified)

    def test_assumptions_name_the_hosted_case_and_key_provenance(self, signed):
        led, key, log = signed
        r = verify_export(led.export(anchor=_anchor(log)), trusted_key=key.verifying)
        joined = " ".join(r.assumptions)
        assert "also holds the signing key" in joined and "kept a signed record" in joined
        assert "nothing here can tell" in joined

    def test_an_anchor_that_contradicts_the_ledger_stops_the_export(self, signed, tmp_path):
        led, _, log = signed
        shorter = EvidenceLedger(tmp_path / "short.db")
        for i in range(3):
            shorter.append(_ev(i), subject="CASE-A")
        with pytest.raises(AnchorContradictsLedgerError, match="removed after"):
            shorter.export(anchor=_anchor(log))
        forked = EvidenceLedger(tmp_path / "forked.db")
        for i in range(8):
            forked.append(_ev(100 + i), subject="CASE-A")
        with pytest.raises(AnchorContradictsLedgerError, match="differs from what was signed"):
            forked.export(anchor=_anchor(log))
        with pytest.raises(AnchorContradictsLedgerError, match="not a head attestation"):
            led.export(anchor={"nonsense": 1})


class TestTheSkeleton:
    def test_a_subject_bundle_carries_a_skeleton_of_the_other_entries_only(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        assert [s["seq"] for s in bundle["skeleton"]] == [2, 4, 6, 8]
        assert all(set(s) == {"seq", "at", "kind", "subject", "content_hash",
                              "prev_hash", "link_hash"} for s in bundle["skeleton"])
        assert bundle["skeleton_truncated"] is False
        assert "skeleton" not in led.export()

    def test_the_skeleton_leaks_no_evidence_body_or_actor(self, signed):
        led, _, _ = signed
        text = json.dumps(led.export(subject="CASE-A")["skeleton"])
        assert SECRET not in text and "a.person" not in text and "engineer" not in text

    def test_a_skeleton_at_the_cap_fits_the_public_verify_body_limit(self, signed):
        led, _, _ = signed
        item = json.dumps(led.export(subject="CASE-A")["skeleton"][0])
        assert len(item) * ledger_module.MAX_SKELETON_ENTRIES < 3 * 1024 * 1024

    def test_a_clean_subject_bundle_verifies_through_the_skeleton(self, signed):
        led, _, _ = signed
        r = verify_export(led.export(subject="CASE-A"))
        assert r.ok and any("skeleton" in v for v in r.verified)

    def test_naive_removals_are_found_without_any_key(self, signed):
        led, _, _ = signed
        for drop in (3, 1, 7):  # middle, head, tail of the subject
            bundle = led.export(subject="CASE-A")
            bundle["entries"] = [e for e in bundle["entries"] if e["seq"] != drop]
            r = verify_export(bundle)
            assert not r.ok and any("a record was removed" in p for p in r.problems)

    def test_removing_a_skeleton_entry_is_found(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        del bundle["skeleton"][1]
        r = verify_export(bundle)
        assert not r.ok and any("neither the entries nor the skeleton" in p
                                for p in r.problems)

    def test_reordering_skeleton_entries_is_found(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        a, b = bundle["skeleton"][0], bundle["skeleton"][1]
        a["seq"], b["seq"] = b["seq"], a["seq"]
        r = verify_export(bundle)
        assert not r.ok and any("link_hash does not match" in p for p in r.problems)

    def test_editing_a_skeleton_entry_is_found(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        bundle["skeleton"][2]["kind"] = "t.other"
        assert not verify_export(bundle).ok

    def test_an_entry_of_the_subject_hidden_in_the_skeleton_is_found(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        stripped = bundle["entries"].pop(1)
        bundle["skeleton"].append({k: stripped[k] for k in (
            "seq", "at", "kind", "subject", "content_hash", "prev_hash", "link_hash")})
        r = verify_export(bundle)
        assert not r.ok and any("evidence was stripped" in p for p in r.problems)

    def test_a_skeleton_with_evidence_in_it_is_refused(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        bundle["skeleton"][0]["evidence"] = {}
        assert not verify_export(bundle).ok

    def test_a_whole_bundle_with_a_skeleton_is_refused(self, signed):
        led, _, _ = signed
        bundle = led.export()
        bundle["skeleton"] = []
        assert not verify_export(bundle).ok

    def test_a_bundle_without_a_skeleton_cannot_show_completeness(self, signed):
        led, key, log = signed
        bundle = led.export(subject="CASE-A", anchor=_anchor(log))
        del bundle["skeleton"], bundle["skeleton_truncated"]
        plain = verify_export(bundle)
        assert plain.ok and plain.completeness == NOT_CHECKED
        assert "no skeleton" in " ".join(plain.checks_skipped)
        keyed = verify_export(bundle, trusted_key=key.verifying)
        assert not keyed.ok and any("could not be established" in p for p in keyed.problems)

    def test_an_anchor_on_one_of_the_subjects_own_entries_does_not_make_a_skeleton_less_bundle_complete(
            self, tmp_path):
        """Seq 5 is CASE-A's. Entries 1, 3, 5 alone can match that signed link while
        saying nothing about entries 2 and 4 -- or whether 3 was ever removed."""
        led = EvidenceLedger(tmp_path / "five.db")
        for i in range(7):
            led.append(_ev(i), subject="CASE-A" if i % 2 == 0 else "CASE-B")
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "five.jsonl")
        from assurance.attest import LedgerHead
        five = led.entries()[4]
        attest(LedgerHead(length=5, head_seq=5, head_link_hash=five.link_hash), key, log)
        bundle = led.export(subject="CASE-A", anchor=_anchor(log))
        assert verify_export(bundle, trusted_key=key.verifying).completeness == ANCHORED
        del bundle["skeleton"], bundle["skeleton_truncated"]
        r = verify_export(bundle, trusted_key=key.verifying)
        assert not r.ok and r.completeness != ANCHORED

    def test_a_truncated_skeleton_makes_completeness_unchecked_never_passed(
            self, signed, monkeypatch):
        led, key, log = signed
        monkeypatch.setattr(ledger_module, "MAX_SKELETON_ENTRIES", 2)
        bundle = led.export(subject="CASE-A", anchor=_anchor(log))
        assert bundle["skeleton_truncated"] is True and bundle["skeleton"] == []
        plain = verify_export(bundle)
        assert plain.ok and plain.completeness == NOT_CHECKED
        assert "too many of them" in " ".join(plain.checks_skipped)
        keyed = verify_export(bundle, trusted_key=key.verifying)
        assert not keyed.ok and keyed.completeness != ANCHORED

    def test_a_truncated_flag_beside_a_full_skeleton_is_a_problem(self, signed):
        led, _, _ = signed
        bundle = led.export(subject="CASE-A")
        bundle["skeleton_truncated"] = True
        assert not verify_export(bundle).ok

    def test_unsupported_format_versions_are_still_rejected(self, signed):
        led, key, log = signed
        bundle = led.export(subject="CASE-A", anchor=_anchor(log))
        bundle["ledger_schema_version"] = 2
        assert not verify_export(bundle, trusted_key=key.verifying).ok


# ---------------------------------------------------------------------------
# The CLI, as a user drives it: export with --attestations, verify with --public-key.
# ---------------------------------------------------------------------------
class TestTheCliAsAUser:
    def _setup(self, tmp_path, signed):
        led, key, log = signed
        pub = tmp_path / "signer.pub"
        pub.write_text(key.verifying.pem(), encoding="utf-8")
        return led, pub, log

    def test_art14_export_with_attestations_then_verify_with_the_key(
            self, tmp_path, signed, capsys):
        led, pub, log = self._setup(tmp_path, signed)
        out = tmp_path / "bundle.json"
        assert cli_main(["art14", "--ledger", str(led.path), "export", "--case", "CASE-A",
                         "-o", str(out), "--attestations", str(log.path)]) == 0
        assert "anchored to attestation 1" in capsys.readouterr().out
        assert cli_main(["evidence", "verify", str(out), "--public-key", str(pub)]) == 0
        assert "VERIFIED — anchored to a signed head" in capsys.readouterr().out
        # The same file without the key: a pass that says what it did not check.
        assert cli_main(["evidence", "verify", str(out)]) == 0
        assert "completeness NOT CHECKED" in capsys.readouterr().out

    def test_art14_export_without_attestations_says_it_is_not_anchored(
            self, tmp_path, signed, capsys):
        led, _, _ = signed
        out = tmp_path / "bundle.json"
        assert cli_main(["art14", "--ledger", str(led.path), "export", "--case", "CASE-A",
                         "-o", str(out)]) == 0
        assert "not anchored" in capsys.readouterr().out

    def test_a_cut_bundle_is_exit_one_with_the_key_and_exit_zero_but_loud_without(
            self, tmp_path, signed, capsys):
        led, pub, log = self._setup(tmp_path, signed)
        cut = tmp_path / "cut.json"
        cut.write_text(json.dumps(_rebuild_without(
            led.export(subject="CASE-A", anchor=_anchor(log)), {3})))
        assert cli_main(["evidence", "verify", str(cut), "--public-key", str(pub)]) == 1
        assert "DOES NOT VERIFY" in capsys.readouterr().out
        assert cli_main(["evidence", "verify", str(cut)]) == 0
        assert "COMPLETENESS NOT CHECKED" in capsys.readouterr().out

    def test_the_customers_own_attestation_log_catches_what_the_bundle_hides(
            self, tmp_path, signed, capsys):
        led, pub, log = self._setup(tmp_path, signed)
        stripped = tmp_path / "stripped.json"
        stripped.write_text(json.dumps(_cut_tail(led.export(subject="CASE-A"), 4)))
        assert cli_main(["evidence", "verify", str(stripped), "--public-key", str(pub),
                         "--attestations", str(log.path)]) == 1
        capsys.readouterr()

    def test_attestations_without_a_key_is_a_usage_error(self, tmp_path, signed):
        led, _, log = signed
        out = tmp_path / "b.json"
        out.write_text(json.dumps(led.export()))
        with pytest.raises(SystemExit) as exc:
            cli_main(["evidence", "verify", str(out), "--attestations", str(log.path)])
        assert exc.value.code == 2

    def test_a_missing_key_or_log_is_exit_two_not_a_quiet_pass(self, tmp_path, signed, capsys):
        led, pub, log = self._setup(tmp_path, signed)
        out = tmp_path / "b.json"
        out.write_text(json.dumps(led.export()))
        assert cli_main(["evidence", "verify", str(out), "--public-key",
                         str(tmp_path / "nope.pub")]) == 2
        assert cli_main(["evidence", "verify", str(out), "--public-key", str(pub),
                         "--attestations", str(tmp_path / "nope.jsonl")]) == 2
        capsys.readouterr()

    def test_exporting_with_a_missing_or_empty_log_refuses(self, tmp_path, signed, capsys):
        led, _, _ = signed
        out = tmp_path / "b.json"
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        for log in (tmp_path / "nope.jsonl", empty):
            assert cli_main(["art14", "--ledger", str(led.path), "export", "--case",
                             "CASE-A", "-o", str(out), "--attestations", str(log)]) == 2
        assert not out.exists()
        capsys.readouterr()

    def test_exporting_against_a_rewound_ledger_refuses_and_writes_nothing(
            self, tmp_path, signed, capsys):
        _, _, log = signed
        shorter = EvidenceLedger(tmp_path / "short.db")
        for i in range(3):
            shorter.append(_ev(i), subject="CASE-A")
        out = tmp_path / "b.json"
        assert cli_main(["art14", "--ledger", str(shorter.path), "export", "--case",
                         "CASE-A", "-o", str(out), "--attestations", str(log.path)]) == 2
        assert "removed after" in capsys.readouterr().err and not out.exists()
