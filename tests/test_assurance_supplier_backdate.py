"""Key validity is judged at SERVER RECEIPT time, never at the signer's own `published_at`.

A holder of a retired (possibly compromised) key must not be able to retract a
stop-use advisory by typing an earlier `published_at`. Publish and withdraw also
refuse a `published_at` that goes backwards on the feed or runs ahead of the server.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from assurance.api import supplier_routes
from assurance.attest.keys import SigningKey
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.supplier.publish import AdvisoryFeed, SignedAdvisory, publish
from assurance.supplier.trust import SupplierTrustStore, evaluate_feed

from . import interfaces_fixtures as fx
from .test_assurance_supplier_withdraw_api import (
    ADV,
    IDENTITY,
    PUBLISH,
    Hosted,
    _adv,
    _pin,
    _resign,
)

live_api = fx.live_api


def _rotate(h: Hosted, retire_at: str = "2026-06-01T00:00:00Z") -> SigningKey:
    k2 = SigningKey.generate()
    SupplierTrustStore(h.api.tenant_ledger(h.account_id)).rotate(
        "controlco", k2.verifying.pem(), retire_fingerprint=h.key.verifying.fingerprint,
        effective_at=parse_utc(retire_at), actor="x", obtained_via="phone")
    return k2


@pytest.fixture()
def hosted(live_api, tmp_path, monkeypatch):
    h = Hosted(live_api, tmp_path, monkeypatch)
    h.publish()
    yield h
    h.client.close()


def _code(r) -> str:
    d = r.json()["detail"]
    return d["error"] if isinstance(d, dict) else str(d)


def _local_copy(h: Hosted, name: str) -> AdvisoryFeed:
    path = h.tmp / name
    path.write_text(h.hosted_text(), "utf-8")
    return AdvisoryFeed(path)


class TestRetiredKeyCannotBackdate:
    def test_honest_withdrawal_under_retired_key_is_refused(self, hosted):
        _rotate(hosted)
        r = hosted.post(hosted.sign_withdrawal())
        assert r.status_code == 403 and _code(r) == "supplier_key_not_in_force"

    def test_backdated_withdrawal_under_retired_key_is_refused(self, hosted):
        _rotate(hosted)
        rec = _resign(hosted.sign_withdrawal(), hosted.key, published_at="2026-03-01T00:00:00Z")
        r = hosted.post(rec)
        assert r.status_code == 403 and _code(r) == "supplier_key_not_in_force"
        assert len(hosted.hosted_text().splitlines()) == 1   # nothing written

    def test_honest_withdrawal_under_the_new_key_is_accepted(self, hosted):
        k2 = _rotate(hosted)
        r = hosted.post(hosted.sign_withdrawal(key=k2))
        assert r.status_code == 201, r.text


class TestTimeBounds:
    def test_backdated_publish_is_422(self, hosted):
        rec = publish(_adv("CTRL-2026-12"), IDENTITY, hosted.key, _local_copy(hosted, "bd.jsonl"),
                      now=utc_now() - timedelta(days=30))
        r = hosted.client.post(PUBLISH, json=rec.to_dict(), headers=hosted.headers)
        assert r.status_code == 422 and _code(r) == "published_at_not_monotonic"

    def test_backdated_withdrawal_is_422_when_key_is_in_force(self, hosted):
        rec = _resign(hosted.sign_withdrawal(), hosted.key,
                      published_at=format_utc(utc_now() - timedelta(days=30)))
        r = hosted.post(rec)
        assert r.status_code == 422 and _code(r) == "published_at_not_monotonic"

    def test_future_dated_publish_is_422(self, hosted):
        rec = publish(_adv("CTRL-2026-12"), IDENTITY, hosted.key, _local_copy(hosted, "fut.jsonl"),
                      now=utc_now() + timedelta(days=2))
        r = hosted.client.post(PUBLISH, json=rec.to_dict(), headers=hosted.headers)
        assert r.status_code == 422 and _code(r) == "published_at_in_future"

    def test_future_dated_first_record_is_422(self, live_api, tmp_path, monkeypatch):
        h = Hosted(live_api, tmp_path, monkeypatch, email="fresh@example.de")
        rec = publish(_adv(), IDENTITY, h.key, AdvisoryFeed(tmp_path / "f.jsonl"),
                      now=utc_now() + timedelta(days=2))
        r = h.client.post(PUBLISH, json=rec.to_dict(), headers=h.headers)
        assert r.status_code == 422 and _code(r) == "published_at_in_future"
        h.client.close()

    def test_future_dated_withdrawal_is_422(self, hosted):
        rec = _resign(hosted.sign_withdrawal(), hosted.key,
                      published_at=format_utc(utc_now() + timedelta(days=2)))
        r = hosted.post(rec)
        assert r.status_code == 422 and _code(r) == "published_at_in_future"

    def test_small_skew_is_tolerated(self, hosted):
        rec = _resign(hosted.sign_withdrawal(), hosted.key,
                      published_at=format_utc(utc_now() + timedelta(minutes=2)))
        assert hosted.post(rec).status_code == 201


class TestReceiptClock:
    def test_receipt_time_decides_key_validity(self, hosted, monkeypatch):
        # K1 retires 2026-06-01. Same signed record, two server clocks.
        _rotate(hosted)
        rec = hosted.sign_withdrawal()
        # Server clock after retirement (real now): refused, whatever the record says.
        assert _code(hosted.post(rec)) == "supplier_key_not_in_force"
        # Server clock before retirement: the key IS in force on receipt, so the key
        # check passes and the request moves on to the time bounds (published_at is
        # then "in the future" for that clock). The key verdict followed the clock.
        monkeypatch.setattr(supplier_routes, "server_now",
                            lambda: parse_utc("2026-05-01T00:00:00Z"))
        assert _code(hosted.post(rec)) == "published_at_in_future"

    def test_clock_before_retirement_accepts_the_old_key(self, hosted):
        _rotate(hosted, retire_at="2099-01-01T00:00:00Z")
        assert hosted.post(hosted.sign_withdrawal()).status_code == 201


class TestParityAndEndToEnd:
    def test_cli_produced_withdrawal_is_accepted_unchanged(self, hosted):
        rec = hosted.sign_withdrawal()
        assert hosted.post(rec).status_code == 201
        last = SignedAdvisory.from_dict(json.loads(hosted.hosted_text().splitlines()[-1]))
        assert last.content_hash() == rec.content_hash()
        assert hosted.hosted_text().splitlines()[-1] == json.dumps(
            rec.to_dict(), sort_keys=True, separators=(",", ":")) or last == rec

    def test_end_to_end_publish_withdraw_evaluate(self, hosted):
        assert hosted.post(hosted.sign_withdrawal()).status_code == 201
        recs = [SignedAdvisory.from_dict(json.loads(x)) for x in hosted.hosted_text().splitlines()]
        store = SupplierTrustStore(hosted.api.tenant_ledger(hosted.account_id))
        ft = evaluate_feed(recs, store, min_sequence=0)
        assert ADV in ft.withdrawn

    def test_second_tenant_unaffected(self, hosted, live_api, tmp_path):
        _rotate(hosted)
        other = Hosted.__new__(Hosted)
        other.api = live_api
        other.tmp = tmp_path / "b"
        other.tmp.mkdir()
        other.account_id, other.headers = live_api.account("b@example.de", "supplier")
        other.key = SigningKey.generate()
        _pin(live_api.tenant_ledger(other.account_id), other.key)
        other.client = hosted.client
        other.feed_file = tmp_path / "feeds" / f"{other.account_id}.jsonl"
        other.publish()
        assert other.post(other.sign_withdrawal()).status_code == 201


def _pinned_store(tmp_path, key: SigningKey) -> SupplierTrustStore:
    store = SupplierTrustStore(EvidenceLedger(tmp_path / "reader.db"))
    store.pin("controlco", key.verifying.pem(), actor="a", obtained_via="phone",
              effective_from=parse_utc("2026-01-01T00:00:00Z"))
    return store


class TestReaderOldFeeds:
    def test_old_valid_feed_still_verifies(self, tmp_path):
        key = SigningKey.generate()
        feed = AdvisoryFeed(tmp_path / "old.jsonl")
        t = parse_utc("2026-02-01T00:00:00Z")
        for i in range(3):
            publish(_adv(f"OLD-{i}"), IDENTITY, key, feed, now=t + timedelta(days=i))
        ft = evaluate_feed(feed.read(), _pinned_store(tmp_path, key), min_sequence=0)
        assert ft.policy_satisfied, ft.problems

    def test_reader_flags_non_monotonic_and_future_records(self, tmp_path):
        key = SigningKey.generate()
        feed = AdvisoryFeed(tmp_path / "bad.jsonl")
        publish(_adv("A-1"), IDENTITY, key, feed, now=parse_utc("2026-03-01T00:00:00Z"))
        publish(_adv("A-2"), IDENTITY, key, feed, now=parse_utc("2026-02-01T00:00:00Z"))
        store = _pinned_store(tmp_path, key)
        ft = evaluate_feed(feed.read(), store, min_sequence=0, now=parse_utc("2026-04-01T00:00:00Z"))
        assert not ft.policy_satisfied
        assert any("earlier than" in p for p in ft.problems)
        ft2 = evaluate_feed(feed.read()[:1], store, min_sequence=0,
                            now=parse_utc("2026-01-15T00:00:00Z"))
        assert any("in the future" in p for p in ft2.problems)
