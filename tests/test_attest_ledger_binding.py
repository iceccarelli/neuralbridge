"""A signed head names the ledger it describes (PR #106 limitation 1) -- and the open items
from the same review: rollback, fork, rotation, revoked key, corrupted chain, concurrent writers.

Before: a head signed for tenant A's ledger (same length, same head seq, same link hash -- trivially
true of two fresh ledgers, or of a copied one) verified as tenant B's, because the signed bytes
carried no ledger identity. Everything here is synthetic.
"""

from __future__ import annotations

import multiprocessing
import sqlite3
from dataclasses import replace

import pytest

from assurance.attest import (
    ATTESTATION_FORMAT,
    ATTESTATION_FORMAT_BOUND,
    AttestationError,
    AttestationLog,
    HeadAttestation,
    LedgerHead,
    SigningKey,
    attest,
    verify_log,
)
from assurance.attest.attestation import check_log_against_ledger
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger
from assurance.evidence.verify_export import verify_export


def _ev(n: int) -> Evidence:
    return Evidence(kind="test.record", body={"n": n}, actor=Actor("t"),
                    origin=Origin("pytest")).seal()


def _fill(ledger: EvidenceLedger, n: int) -> EvidenceLedger:
    for i in range(n):
        ledger.append(_ev(i), subject=f"m{i}")
    return ledger


def _strip_id(ledger: EvidenceLedger) -> None:
    """A ledger as an older build left it: no lineage id."""
    db = sqlite3.connect(ledger.path)
    db.execute("DELETE FROM meta WHERE key = 'ledger_id'")
    db.commit()
    db.close()


def _legacy_v1(att: HeadAttestation, key: SigningKey) -> HeadAttestation:
    """The same head signed the way PR #106 did: format v1, no ledger identity."""
    import base64

    v1 = replace(att, format=ATTESTATION_FORMAT, ledger_id="", tenant="", signature="")
    return replace(v1, signature=base64.b64encode(key.sign(v1.signed_payload())).decode())


def _twin(tmp_path, name: str, source: EvidenceLedger) -> EvidenceLedger:
    """A second ledger whose chain is byte-identical to *source* but whose lineage id differs."""
    import shutil

    shutil.copy(source.path, tmp_path / name)
    twin = EvidenceLedger(tmp_path / name)
    db = sqlite3.connect(twin.path)
    db.execute("UPDATE meta SET value = 'twin' || value WHERE key = 'ledger_id'")
    db.commit()
    db.close()
    assert twin.ledger_id() != source.ledger_id()
    assert [e.link_hash for e in twin.entries()] == [e.link_hash for e in source.entries()]
    return twin


class TestCrossTenantReplay:
    def test_a_head_signed_for_ledger_a_does_not_verify_as_ledger_b(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 4)
        b = _twin(tmp_path, "b.db", a)
        log = AttestationLog(tmp_path / "a.jsonl")
        att = attest(a, key, log)
        assert att.format == ATTESTATION_FORMAT_BOUND and att.ledger_id == a.ledger_id()

        mine = verify_log(log.read(), key.verifying, ledger=a)
        assert mine.ok and mine.bound_to_this_ledger and mine.binding == "bound"

        theirs = verify_log(log.read(), key.verifying, ledger=b)   # the replay
        assert not theirs.ok and not theirs.bound_to_this_ledger
        assert any("different ledger" in p for p in theirs.problems)

    def test_the_id_alone_is_enough_when_the_verifier_holds_no_ledger(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 2)
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(a, key, log)
        assert verify_log(log.read(), key.verifying, expect_ledger_id=a.ledger_id()).ok
        wrong = verify_log(log.read(), key.verifying, expect_ledger_id="f" * 32)
        assert not wrong.ok and any("different ledger" in p for p in wrong.problems)

    def test_check_log_against_ledger_refuses_it_too(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        b = _twin(tmp_path, "b.db", a)
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(a, key, log)
        problems, _ = check_log_against_ledger(log.read(), b)
        assert any("different ledger" in p for p in problems)

    def test_the_signed_id_cannot_be_edited_or_stripped(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "a.jsonl")
        att = attest(a, key, log)
        for forged in (replace(att, ledger_id="e" * 32), replace(att, ledger_id=""),
                       replace(att, tenant="mallory"), replace(att, format=ATTESTATION_FORMAT)):
            verdict = verify_log([forged], key.verifying, expect_ledger_id=a.ledger_id())
            assert not verdict.ok, forged

    def test_a_bound_head_is_not_accepted_for_a_ledger_that_has_no_id(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(a, key, log)
        _strip_id(a)
        verdict = verify_log(log.read(), key.verifying, ledger=EvidenceLedger.open_readonly(a.path))
        assert not verdict.ok and not verdict.bound_to_this_ledger

    def test_signing_another_ledgers_head_into_a_bound_log_is_refused(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        b = _twin(tmp_path, "b.db", a)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, key, log)
        with pytest.raises(AttestationError, match="substitution"):
            attest(b, key, log)

    def test_tenant_is_signed_and_checked(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "log.jsonl")
        att = attest(a, key, log, tenant="acct-a")
        assert att.tenant == "acct-a"
        assert verify_log(log.read(), key.verifying, ledger=a, expect_tenant="acct-a").ok
        other = verify_log(log.read(), key.verifying, ledger=a, expect_tenant="acct-b")
        assert not other.ok and any("tenant" in p for p in other.problems)
        with pytest.raises(AttestationError, match="tenant"):
            attest(a, key, log, tenant="acct-b")

    def test_a_bundle_cannot_show_which_ledger_a_bound_anchor_is_for_and_says_so(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        b = _twin(tmp_path, "b.db", a)
        log = AttestationLog(tmp_path / "log.jsonl")
        att = attest(a, key, log)
        assert "ledger_id" not in b.export()          # the bundle format names no ledger
        result = verify_export(b.export(anchor=att.to_dict()), trusted_key=key.verifying)
        # Not a failure the bundle can prove, but never presented as a ledger match either.
        assert any("NOT checked" in str(x) for x in (*result.checks_skipped, *getattr(
            result, "assumptions", ())))


class TestOldUnboundHeadsAreWeakerAndSaySo:
    def test_a_v1_head_still_verifies_but_is_reported_unbound(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "scratch.jsonl")
        bound = attest(a, key, log)
        legacy = _legacy_v1(bound, key)
        verdict = verify_log([legacy], key.verifying, ledger=a)
        assert verdict.ok                              # backward compatible: still genuine
        assert verdict.binding == "unbound" and verdict.unbound == [1]
        assert not verdict.bound_to_this_ledger        # never "verified for this ledger"
        assert any("UNBOUND" in line for line in verdict.checks_skipped)
        assert "UNBOUND" in verdict.summary()

    def test_a_v1_head_replays_across_ledgers_but_is_labelled_so(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        b = _twin(tmp_path, "b.db", a)
        legacy = _legacy_v1(attest(a, key, AttestationLog(tmp_path / "s.jsonl")), key)
        verdict = verify_log([legacy], key.verifying, ledger=b)
        assert verdict.ok and verdict.binding == "unbound" and not verdict.bound_to_this_ledger

    def test_require_bound_turns_an_unbound_head_into_a_problem(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        legacy = _legacy_v1(attest(a, key, AttestationLog(tmp_path / "s.jsonl")), key)
        verdict = verify_log([legacy], key.verifying, ledger=a, require_bound=True)
        assert not verdict.ok and any("unbound" in p for p in verdict.problems)

    def test_ledger_id_text_added_to_a_v1_record_is_not_believed(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        legacy = _legacy_v1(attest(a, key, AttestationLog(tmp_path / "s.jsonl")), key)
        data = {**legacy.to_dict(), "ledger_id": a.ledger_id()}
        parsed = HeadAttestation.from_dict(data)
        assert parsed.binding == "unbound" and parsed.ledger_id == ""

    def test_a_ledger_without_an_id_is_signed_unbound(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        _strip_id(a)
        log = AttestationLog(tmp_path / "log.jsonl")
        att = attest(EvidenceLedger.open_readonly(a.path), key, log)
        assert att.format == ATTESTATION_FORMAT and att.binding == "unbound"

    def test_an_unbound_head_cannot_be_slipped_into_a_bound_log(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, key, log)
        _strip_id(a)
        with pytest.raises(AttestationError, match="downgrade"):
            attest(EvidenceLedger.open_readonly(a.path), key, log)

    def test_a_declared_head_is_unbound_unless_the_caller_names_a_ledger(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 2)
        entries = a.entries()
        head = LedgerHead(length=2, head_seq=entries[-1].seq, head_link_hash=entries[-1].link_hash)
        log = AttestationLog(tmp_path / "log.jsonl")
        assert attest(head, key, log).binding == "unbound"


def _worker(log_path: str, key_path: str, ledger_path: str, count: int) -> None:
    key = SigningKey.load(key_path)
    ledger = EvidenceLedger.open_existing(ledger_path)
    log = AttestationLog(log_path)
    for _ in range(count):
        attest(ledger, key, log)


class TestTheRemainingScenariosAreCovered:
    """Rollback / shortened / forked / rotated / revoked / corrupted / concurrent, one each, so a
    gap in the named list is visible here rather than assumed to live elsewhere."""

    def test_shortened_ledger_is_refused_and_flagged_against_a_bound_log(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 6)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, key, log)
        db = sqlite3.connect(a.path)
        db.execute("DELETE FROM chain WHERE seq > 3")
        db.commit()
        db.close()
        with pytest.raises(AttestationError, match="shorter|removed|no longer"):
            attest(a, key, log)
        verdict = verify_log(log.read(), key.verifying, ledger=a)
        assert not verdict.ok

    def test_rollback_with_the_log_cut_to_match_needs_the_remembered_head(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, key, log)
        _fill(a, 3)
        newest = attest(a, key, log)
        db = sqlite3.connect(a.path)
        db.execute("DELETE FROM chain WHERE seq > 3")
        db.commit()
        db.close()
        log.path.write_text(log.path.read_text().splitlines(keepends=True)[0])
        records = AttestationLog(log.path).read()
        assert verify_log(records, key.verifying, ledger=a).ok            # the stated limit
        caught = verify_log(records, key.verifying, ledger=a, min_sequence=newest.sequence)
        assert not caught.ok

    def test_a_forked_ledger_is_refused_at_the_attested_position(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 4)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, key, log)
        db = sqlite3.connect(a.path)
        db.execute("UPDATE chain SET link_hash = ? WHERE seq = 4", ("0" * 64,))
        db.commit()
        db.close()
        with pytest.raises(AttestationError):
            attest(a, key, log)

    def test_a_rotation_must_be_declared_and_each_key_verifies_its_own_span(self, tmp_path):
        old, new = SigningKey.generate(), SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, old, log)
        with pytest.raises(AttestationError, match="rotation"):
            attest(a, new, log)
        _fill(a, 1)
        attest(a, new, log, rotating=True)
        both = verify_log(log.read(), old.verifying, ledger=a)
        assert not both.ok                      # one key cannot vouch for both spans

    def test_a_log_signed_by_a_key_the_verifier_no_longer_trusts_fails(self, tmp_path):
        revoked, current = SigningKey.generate(), SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(a, revoked, log)
        verdict = verify_log(log.read(), current.verifying, ledger=a)
        assert not verdict.ok
        assert any("signature does not verify" in p for p in verdict.problems)

    def test_a_corrupted_chain_refuses_to_be_signed(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 4)
        db = sqlite3.connect(a.path)
        db.execute("UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":9') "
                   "WHERE seq = 2")
        db.commit()
        db.close()
        log = AttestationLog(tmp_path / "log.jsonl")
        with pytest.raises(AttestationError, match="does not verify"):
            attest(a, key, log)
        assert log.read() == []

    def test_concurrent_processes_signing_one_log_keep_one_unbroken_sequence(self, tmp_path):
        key = SigningKey.generate()
        a = _fill(EvidenceLedger(tmp_path / "a.db"), 3)
        log_path = tmp_path / "log.jsonl"
        keydir = tmp_path / "keys"
        keydir.mkdir(mode=0o700)
        key_path = key.save(keydir / "k.pem")
        ctx = multiprocessing.get_context("spawn")
        procs = [ctx.Process(target=_worker, args=(str(log_path), str(key_path), str(a.path), 4))
                 for _ in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
            assert p.exitcode == 0
        records = AttestationLog(log_path).read()
        assert [r.sequence for r in records] == list(range(1, 17))
        assert verify_log(records, key.verifying, ledger=a).ok
