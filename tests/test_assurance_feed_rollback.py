"""A supplier feed with its newest records removed must not verify as current.

The chain proves nothing is missing from the middle. Cutting the tail, or serving an
older complete copy, leaves a valid chain, and a withdrawn advisory would stand again.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.attest.keys import SigningKey
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.supplier.publish import (
    AdvisoryFeed,
    SupplierIdentity,
    publish,
    verify_feed,
    withdraw,
)

NOW = datetime(2026, 9, 12, tzinfo=UTC)
ID = SupplierIdentity("controlco", "ControlCo GmbH", "datasheet p.2")


def adv(n):
    return ComponentAdvisory(
        advisory_id=f"ADV-{n}", issued_by="ControlCo GmbH", issued_at=NOW, title="t",
        summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact("ControlCo GmbH", "SafeScan", versions=("4.0",)),),
        reference="https://example.invalid/x")


@pytest.fixture
def feed(tmp_path):
    key = SigningKey.generate()
    f = AdvisoryFeed(tmp_path / "feed.jsonl")
    publish(adv(1), ID, key, f, now=NOW)
    publish(adv(2), ID, key, f, now=NOW)
    withdraw("ADV-1", "published in error", ID, key, f, now=NOW)
    return f, key


def truncate(f, keep):
    lines = [ln for ln in f.path.read_text("utf-8").splitlines() if ln.strip()]
    f.path.write_text("\n".join(lines[:keep]) + "\n", "utf-8")


def test_the_verdict_reports_its_head(feed):
    f, key = feed
    v = verify_feed(f.read(), key.verifying)
    assert v.ok and v.head_sequence == 3 and v.head_hash == f.read()[-1].content_hash()


def test_without_a_pinned_head_the_verdict_says_newness_was_not_checked(feed):
    f, key = feed
    v = verify_feed(f.read(), key.verifying)
    assert any("NEWEST" in s for s in v.checks_skipped)


def test_a_truncated_feed_fails_against_the_sequence_seen_before(feed):
    f, key = feed
    seen = verify_feed(f.read(), key.verifying)
    truncate(f, 2)
    cut = verify_feed(f.read(), key.verifying, min_sequence=seen.head_sequence)
    assert cut.ok is False and any("removed" in p for p in cut.problems)


def test_a_feed_that_grew_since_it_was_last_seen_passes(feed):
    f, key = feed
    seen = verify_feed(f.read(), key.verifying)
    publish(adv(3), ID, key, f, now=NOW)
    now = verify_feed(f.read(), key.verifying, min_sequence=seen.head_sequence,
                      expect_head=seen.head_hash)
    # the old head is still record 3 in the grown feed
    assert now.ok and not any("NEWEST" in s for s in now.checks_skipped)


def test_a_rewritten_history_fails_the_head_hash(feed, tmp_path):
    f, key = feed
    seen = verify_feed(f.read(), key.verifying)
    other = AdvisoryFeed(tmp_path / "other.jsonl")
    publish(adv(1), ID, key, other, now=NOW)
    publish(adv(2), ID, key, other, now=NOW)
    publish(adv(9), ID, key, other, now=NOW)  # record 3 differs from the one seen
    v = verify_feed(other.read(), key.verifying, min_sequence=3, expect_head=seen.head_hash)
    assert v.ok is False


def test_trust_evaluation_marks_a_rolled_back_feed_not_intact(feed):
    from assurance.supplier.trust import evaluate_feed

    f, key = feed
    seen = verify_feed(f.read(), key.verifying)
    truncate(f, 2)
    t = evaluate_feed(f.read(), None, min_sequence=seen.head_sequence)
    assert t.chain_valid is False and not t.policy_satisfied
    assert any("removed" in p for p in t.chain_problems)
    assert evaluate_feed(f.read(), None).chain_valid is True  # nothing pinned: unchanged


# ---------------------------------------------------------------------------
# The remembered head: the account's trust store, and the watch pass that uses it
# ---------------------------------------------------------------------------

def _store(tmp_path):
    from assurance.evidence.ledger import EvidenceLedger
    from assurance.supplier.trust import SupplierTrustStore

    return SupplierTrustStore(EvidenceLedger(tmp_path / "trust.db"))


def _pinned(tmp_path, key):
    store = _store(tmp_path)
    store.pin("controlco", key.verifying.pem(), actor="a.engineer",
              obtained_via="read aloud by ControlCo PSIRT on the phone",
              effective_from=datetime(2020, 1, 1, tzinfo=UTC))
    return store


def test_the_store_remembers_only_a_head_that_moves_forward(tmp_path):
    store = _store(tmp_path)
    assert store.feed_head("controlco") is None
    assert store.record_feed_head("controlco", 2, "h2") is True
    assert store.record_feed_head("controlco", 2, "h2") is False  # not advanced: nothing written
    assert store.record_feed_head("controlco", 1, "h1") is False  # never backwards
    assert store.record_feed_head("controlco", 3, "h3") is True
    assert store.feed_head("controlco") == (3, "h3")
    assert store.feed_head("other") is None


def test_only_a_named_person_with_a_reason_moves_the_head_back(tmp_path):
    from assurance.supplier.trust import SupplierTrustError

    store = _store(tmp_path)
    store.record_feed_head("controlco", 5, "h5")
    with pytest.raises(SupplierTrustError):
        store.reset_feed_head("controlco", 2, "h2", actor="m.braun", reason=" ")
    store.reset_feed_head("controlco", 2, "h2", actor="m.braun", reason="supplier re-issued feed")
    assert store.feed_head("controlco") == (2, "h2")


def test_a_pass_over_a_trusted_feed_records_its_head_and_a_cut_feed_is_then_untrusted(
        feed, tmp_path):
    from assurance.watch.advisories import _read_feed_pinned

    f, key = feed
    store = _pinned(tmp_path, key)

    records, failure, notes, trust = _read_feed_pinned("controlco", str(f.path), store)
    assert failure is None and trust.policy_satisfied
    assert any("No earlier head" in n for n in notes)  # first pass could not check newness
    assert store.feed_head("controlco") == (3, records[-1].content_hash())

    _, _, notes2, trust2 = _read_feed_pinned("controlco", str(f.path), store)
    assert trust2.policy_satisfied and not any("No earlier head" in n for n in notes2)

    truncate(f, 2)  # the withdrawal is cut off, so ADV-1 would stand again
    _, _, _, cut = _read_feed_pinned("controlco", str(f.path), store)
    assert cut.policy_satisfied is False and cut.trust_state.startswith("untrusted")
    assert any("removed" in p for p in cut.chain_problems)
    assert store.feed_head("controlco")[0] == 3  # the cut feed did not become the baseline


def test_a_feed_that_only_grew_stays_trusted_and_advances_the_head(feed, tmp_path):
    from assurance.watch.advisories import _read_feed_pinned

    f, key = feed
    store = _pinned(tmp_path, key)
    _read_feed_pinned("controlco", str(f.path), store)
    publish(adv(3), ID, key, f, now=NOW)
    records, _, _, trust = _read_feed_pinned("controlco", str(f.path), store)
    assert trust.policy_satisfied
    assert store.feed_head("controlco") == (4, records[-1].content_hash())
