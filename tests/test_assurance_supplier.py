"""Signing the other half of the market, and the attack it closes.

The test that matters here is not that a signature verifies. It is that a feed
whose advisory text was altered — the forged "reflash your safety controllers
within 24 hours" — is refused by the tool that would otherwise fan it across a
fleet. Everything else in this file exists to make sure that refusal cannot be
bypassed by accident.
"""

from __future__ import annotations

import json

import pytest

from assurance.attest.keys import SigningKey, VerifyingKey
from assurance.core.identity import parse_utc
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)
from assurance.supplier import (
    FEED_FORMAT,
    AdvisoryFeed,
    PublishError,
    SupplierIdentity,
    publish,
    verify_feed,
    withdraw,
)

IDENTITY = SupplierIdentity(
    supplier_id="controlco",
    legal_name="ControlCo GmbH",
    key_contact="printed on every quotation, and at controlco.example/psirt/key",
)


def _advisory(advisory_id: str = "CTRL-2026-11", **over) -> ComponentAdvisory:
    body: dict = {
        "advisory_id": advisory_id,
        "issued_by": "controlco",
        "issued_at": parse_utc("2026-09-10T08:00:00Z"),
        "title": "Authentication bypass in safety controller firmware",
        "summary": "A crafted frame permits a safety parameter write.",
        "severity": AdvisorySeverity.STOP_USE,
        "reference": "https://controlco.example/psirt/CTRL-2026-11",
        "remedy": "Update to 3.9.1.",
        "affected": (AffectedArtefact(supplier="ControlCo",
                                      name="Safety controller firmware",
                                      versions=("3.8.2", "3.9.0")),),
    }
    body.update(over)
    return ComponentAdvisory(**body)


@pytest.fixture()
def key(tmp_path) -> SigningKey:
    return SigningKey.generate()


@pytest.fixture()
def feed(tmp_path) -> AdvisoryFeed:
    return AdvisoryFeed(tmp_path / "feed.jsonl")


# =====================================================================
class TestIdentity:
    def test_a_key_nobody_can_confirm_is_refused(self):
        with pytest.raises(PublishError, match="key_contact"):
            SupplierIdentity(supplier_id="x", legal_name="X GmbH", key_contact="")

    def test_a_supplier_id_that_is_not_a_plain_token_is_refused(self):
        with pytest.raises(PublishError, match="plain token"):
            SupplierIdentity(supplier_id="control co", legal_name="X",
                             key_contact="the contract")


# =====================================================================
class TestPublishing:
    def test_a_published_advisory_verifies(self, key, feed):
        record = publish(_advisory(), IDENTITY, key, feed)
        assert record.sequence == 1
        assert record.previous == ""
        assert record.format == FEED_FORMAT
        assert record.verified_by(key.verifying)
        assert record.component().advisory_id == "CTRL-2026-11"

    def test_each_record_names_its_predecessor(self, key, feed):
        first = publish(_advisory("A-1"), IDENTITY, key, feed)
        second = publish(_advisory("A-2"), IDENTITY, key, feed)
        assert second.previous == first.content_hash()
        assert second.sequence == 2

    def test_an_id_cannot_be_republished(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        with pytest.raises(PublishError, match="already published"):
            publish(_advisory(), IDENTITY, key, feed)

    def test_a_feed_belongs_to_one_supplier(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        other = SupplierIdentity(supplier_id="scanco", legal_name="ScanCo",
                                 key_contact="the contract")
        with pytest.raises(PublishError, match="One feed, one supplier"):
            publish(_advisory("S-1", issued_by="scanco"), other, key, feed)

    def test_a_feed_will_not_carry_somebody_elses_advisory(self, key, feed):
        with pytest.raises(PublishError, match="makes you the source"):
            publish(_advisory(issued_by="someone-else"), IDENTITY, key, feed)

    def test_a_different_key_needs_to_be_declared_a_rotation(self, key, feed):
        publish(_advisory("A-1"), IDENTITY, key, feed)
        other = SigningKey.generate()
        with pytest.raises(PublishError, match="rotation"):
            publish(_advisory("A-2"), IDENTITY, other, feed)
        assert publish(_advisory("A-2"), IDENTITY, other, feed,
                       rotating=True).sequence == 2


# =====================================================================
class TestWithdrawal:
    def test_a_withdrawal_keeps_the_original(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        withdraw("CTRL-2026-11", "the affected version range was wrong",
                 IDENTITY, key, feed)
        records = feed.read()
        assert len(records) == 2
        assert records[0].advisory_id == "CTRL-2026-11"
        assert records[1].is_withdrawal

        verdict = verify_feed(records, key.verifying)
        assert verdict.ok
        assert verdict.live == ()
        assert verdict.withdrawn == ("CTRL-2026-11",)

    def test_a_withdrawal_needs_a_reason(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        with pytest.raises(PublishError, match="needs a reason"):
            withdraw("CTRL-2026-11", "   ", IDENTITY, key, feed)

    def test_nothing_that_was_never_published_can_be_withdrawn(self, key, feed):
        publish(_advisory("A-1"), IDENTITY, key, feed)
        with pytest.raises(PublishError, match="nothing to withdraw"):
            withdraw("A-9", "oops", IDENTITY, key, feed)

    def test_withdrawing_twice_is_refused(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        withdraw("CTRL-2026-11", "wrong range", IDENTITY, key, feed)
        with pytest.raises(PublishError, match="already been withdrawn"):
            withdraw("CTRL-2026-11", "again", IDENTITY, key, feed)


# =====================================================================
class TestVerifying:
    def test_the_forged_advisory_is_caught(self, key, feed, tmp_path):
        """The attack: an emailed advisory telling an integrator to reflash a
        safety controller. Altering the text breaks the signature."""
        publish(_advisory(), IDENTITY, key, feed)
        raw = json.loads(feed.path.read_text().splitlines()[0])
        raw["advisory"]["remedy"] = (
            "Flash http://controlco-support.example/fw.bin within 24 hours.")
        forged = tmp_path / "forged.jsonl"
        forged.write_text(json.dumps(raw) + "\n")

        verdict = verify_feed(AdvisoryFeed(forged).read(), key.verifying)
        assert not verdict.ok
        assert any("Do not act on this advisory" in p for p in verdict.problems)

    def test_a_removed_record_breaks_the_chain_at_a_named_position(self, key, feed):
        for n in range(3):
            publish(_advisory(f"A-{n}"), IDENTITY, key, feed)
        records = feed.read()
        verdict = verify_feed([records[0], records[2]], key.verifying)
        assert not verdict.ok
        assert any("out of order" in p for p in verdict.problems)
        assert any("withdrawn from the file rather than withdrawn in it" in p
                   for p in verdict.problems)

    def test_an_empty_feed_does_not_verify(self, key):
        """A wrong path and a supplier with nothing to say look identical, and
        'you are unaffected' is the worst possible wrong answer."""
        verdict = verify_feed([], key.verifying)
        assert not verdict.ok
        assert any("did not arrive" in p for p in verdict.problems)

    def test_the_wrong_key_fails_every_record(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        verdict = verify_feed(feed.read(), SigningKey.generate().verifying)
        assert not verdict.ok

    def test_a_feed_from_the_wrong_supplier_is_named(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        verdict = verify_feed(feed.read(), key.verifying, expect_supplier="scanco")
        assert not verdict.ok
        assert any("expected a feed from" in p for p in verdict.problems)

    def test_verification_never_claims_the_advisory_is_correct(self, key, feed):
        publish(_advisory(), IDENTITY, key, feed)
        verdict = verify_feed(feed.read(), key.verifying)
        assert verdict.ok
        joined = " ".join(verdict.checks_skipped)
        assert "belongs to this supplier was not checked" in joined
        assert "correct, complete, or timely" in joined

    def test_a_record_missing_a_field_is_a_finding_not_a_crash(self, tmp_path):
        path = tmp_path / "f.jsonl"
        path.write_text('{"format": "x"}\n')
        with pytest.raises(PublishError, match="missing"):
            AdvisoryFeed(path).read()

    def test_a_public_key_from_pem_verifies_the_same(self, key, feed, tmp_path):
        publish(_advisory(), IDENTITY, key, feed)
        (tmp_path / "k.pub").write_text(key.verifying.pem())
        loaded = VerifyingKey.from_file(tmp_path / "k.pub")
        assert verify_feed(feed.read(), loaded).ok


# =====================================================================
class TestCli:
    def _sup(self, *argv) -> int:
        from assurance.supplier.cli import main

        return main(list(argv))

    def _fleet(self, *argv) -> int:
        from assurance.fleet.cli import main

        return main(list(argv))

    def _published(self, tmp_path):
        self._sup("keygen", "--out", str(tmp_path / "k.pem"))
        (tmp_path / "identity.json").write_text(json.dumps(IDENTITY.to_dict()))
        (tmp_path / "adv.json").write_text(json.dumps(_advisory().to_dict()))
        assert self._sup("publish", str(tmp_path / "adv.json"),
                         "--feed", str(tmp_path / "feed.jsonl"),
                         "--key", str(tmp_path / "k.pem"),
                         "--identity", str(tmp_path / "identity.json")) == 0

    def test_keygen_prints_the_fingerprint_to_hand_out(self, tmp_path, capsys):
        assert self._sup("keygen", "--out", str(tmp_path / "k.pem")) == 0
        out = capsys.readouterr().out
        assert "Give your customers this fingerprint" in out
        assert (tmp_path / "k.pem.pub").exists()

    def test_publish_then_verify_exits_zero(self, tmp_path, capsys):
        self._published(tmp_path)
        capsys.readouterr()
        assert self._sup("verify", "--feed", str(tmp_path / "feed.jsonl"),
                         "--public-key", str(tmp_path / "k.pem.pub"),
                         "--expect-supplier", "controlco") == 0

    def test_publish_says_when_no_hashes_were_given(self, tmp_path, capsys):
        self._published(tmp_path)
        assert "no content hashes" in capsys.readouterr().out

    def test_verify_exits_one_on_a_forged_feed(self, tmp_path, capsys):
        self._published(tmp_path)
        path = tmp_path / "feed.jsonl"
        raw = json.loads(path.read_text().splitlines()[0])
        raw["advisory"]["title"] = "URGENT: reflash all controllers"
        path.write_text(json.dumps(raw) + "\n")
        capsys.readouterr()
        assert self._sup("verify", "--feed", str(path),
                         "--public-key", str(tmp_path / "k.pem.pub")) == 1
        assert "Do not act on this feed" in capsys.readouterr().out

    def test_fleet_refuses_a_feed_with_no_key(self, tmp_path, capsys):
        self._published(tmp_path)
        ledger = tmp_path / "ledger.db"
        capsys.readouterr()
        assert self._fleet("advisory", "--feed", str(tmp_path / "feed.jsonl"),
                           "--ledger", str(ledger)) == 2
        assert "not checked against a key" in capsys.readouterr().err

    def test_fleet_refuses_a_forged_feed(self, tmp_path, capsys):
        self._published(tmp_path)
        path = tmp_path / "feed.jsonl"
        raw = json.loads(path.read_text().splitlines()[0])
        raw["advisory"]["remedy"] = "Flash http://evil.example/fw.bin now."
        path.write_text(json.dumps(raw) + "\n")
        capsys.readouterr()
        assert self._fleet("advisory", "--feed", str(path),
                           "--supplier-key", str(tmp_path / "k.pem.pub"),
                           "--ledger", str(tmp_path / "ledger.db")) == 2
        assert "refusing to act on" in capsys.readouterr().err

    def test_fleet_says_so_loudly_when_told_to_proceed_anyway(
            self, tmp_path, capsys):
        self._published(tmp_path)
        capsys.readouterr()
        rc = self._fleet("advisory", "--feed", str(tmp_path / "feed.jsonl"),
                         "--unsigned-anyway",
                         "--ledger", str(tmp_path / "ledger.db"))
        assert rc in (0, 1)
        assert "not signed, or its signature was not checked" in \
            capsys.readouterr().out

    def test_an_unsigned_advisory_file_still_warns(self, tmp_path, capsys):
        (tmp_path / "adv.json").write_text(json.dumps(_advisory().to_dict()))
        capsys.readouterr()
        self._fleet("advisory", str(tmp_path / "adv.json"),
                    "--ledger", str(tmp_path / "ledger.db"))
        assert "anyone could have written" in capsys.readouterr().out

    def test_giving_both_a_file_and_a_feed_is_refused(self, tmp_path, capsys):
        self._published(tmp_path)
        (tmp_path / "adv.json").write_text(json.dumps(_advisory().to_dict()))
        capsys.readouterr()
        assert self._fleet("advisory", str(tmp_path / "adv.json"),
                           "--feed", str(tmp_path / "feed.jsonl"),
                           "--ledger", str(tmp_path / "ledger.db")) == 2

    def test_list_says_it_verified_nothing(self, tmp_path, capsys):
        self._published(tmp_path)
        capsys.readouterr()
        assert self._sup("list", "--feed", str(tmp_path / "feed.jsonl")) == 0
        assert "Nothing here was verified" in capsys.readouterr().out
