"""Hosted watch ingest: defects the second adversarial review proved (B-F6, B-F8, ...).

Each test failed on the branch tip before its fix.
"""

from __future__ import annotations

import importlib
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.core.identity import parse_utc
from assurance.watch.ingest import OBSERVATION_KIND, REPORT_KIND
from tests import test_assurance_watch_report as wr
from tests.test_assurance_watch_report import (
    account,
    good,
    ledger_of,
    make_manifest,
    now,
    post,
    report,
)

_env = wr._env
_client = wr._client
_accounts = wr._accounts
_cell = wr._cell

OVERFLOW = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00")


@pytest.fixture(name="lenient")
def _lenient(env):
    """A client that returns a 500 instead of re-raising, to see what a caller sees."""
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app(), raise_server_exceptions=False) as c:
        yield c


# -- B-F6: timestamps at the edge of the calendar -------------------------------

@pytest.mark.parametrize("stamp", OVERFLOW)
def test_parse_utc_raises_value_error_not_overflow(stamp):
    with pytest.raises(ValueError):
        parse_utc(stamp)


@pytest.mark.parametrize("stamp", OVERFLOW)
def test_an_overflowing_observed_at_is_a_422_and_writes_nothing(lenient, tmp_path, stamp):
    acct, h = account(deps.get_accounts(), "cell", "ov@example.de")
    e = good(make_manifest(tmp_path, "0412"), at=now())
    e["observed_at"] = stamp
    r = lenient.post("/v1/watch/report", headers=h, json=report(e))
    assert r.status_code == 422, r.text[:300]
    assert len(ledger_of(acct)) == 0


@pytest.mark.parametrize("stamp", OVERFLOW)
def test_a_mixed_report_with_an_overflowing_manifest_date_refuses_that_entry_only(
        lenient, tmp_path, stamp):
    acct, h = account(deps.get_accounts(), "cell", "mix@example.de")
    e1 = good(make_manifest(tmp_path, "0412", when=now()), at=now() - timedelta(seconds=20))
    m2 = make_manifest(tmp_path, "0501", when=now())
    m2["taken_at"] = stamp
    e2 = good(m2, at=now(), keep_taken_at=True)
    r = lenient.post("/v1/watch/report", headers=h, json=report(e2, e1))
    assert r.status_code == 200, r.text[:300]
    by_serial = {m["serial"]: m for m in r.json()["machines"]}
    assert by_serial["0501"]["outcome"] == "refused"
    assert by_serial["0501"]["reason"] == "invalid_manifest"
    assert by_serial["0412"]["outcome"] != "refused"
    led = ledger_of(acct)
    # the good entry and the report record both landed: no partial write without a record
    assert len(led.entries(kind=OBSERVATION_KIND)) == 1
    assert len(led.entries(kind=REPORT_KIND)) == 1


def test_a_per_entry_overflow_anywhere_in_the_entry_is_a_refusal_not_a_500(
        lenient, tmp_path):
    """Whatever raises inside one entry refuses that entry; the report still lands."""
    from assurance.watch import ingest

    acct, h = account(deps.get_accounts(), "cell", "boom@example.de")
    e1 = good(make_manifest(tmp_path, "0412", when=now()), at=now() - timedelta(seconds=20))
    e2 = good(make_manifest(tmp_path, "0501", when=now()), at=now())
    real = ingest._not_a_look

    def explode(manifest):
        if manifest.machine.serial == "0501":
            raise OverflowError("date value out of range")
        return real(manifest)

    ingest._not_a_look = explode
    try:
        r = lenient.post("/v1/watch/report", headers=h, json=report(e1, e2))
    finally:
        ingest._not_a_look = real
    assert r.status_code == 200, r.text[:300]
    by_serial = {m["serial"]: m for m in r.json()["machines"]}
    assert by_serial["0501"]["outcome"] == "refused"
    assert len(ledger_of(acct).entries(kind=REPORT_KIND)) == 1


# -- B-F8: a retry says what the held observation really was ---------------------

def _first_and_retry(client, h, entry, **kw):
    first = post(client, h, report(entry, **kw)).json()["machines"][0]
    retry = post(client, h, report(entry, **kw)).json()["machines"][0]
    return first, retry


def test_retry_of_a_stale_attempt_does_not_claim_it_counted(client, cell, tmp_path):
    acct, h = cell
    old = make_manifest(tmp_path, "0412", when=now() - timedelta(days=30))
    wr.enroll_manifest(acct, tmp_path)
    e = good(old, at=now(), keep_taken_at=True)       # old manifest, observed now
    first, retry = _first_and_retry(client, h, e)
    assert first["recorded_status"] == "manifest_stale"
    assert first["counts_as_observation"] is False
    assert retry["outcome"] == "already_recorded"
    assert retry["counts_as_observation"] is False


def test_retry_of_a_not_a_look_attempt_does_not_claim_it_counted(client, cell, tmp_path):
    acct, h = cell
    wr.enroll_manifest(acct, tmp_path)
    first, retry = _first_and_retry(
        client, h, wr.failed("0412", at=now() - timedelta(minutes=1)))
    assert first["counts_as_observation"] is False
    assert retry["outcome"] == "already_recorded"
    assert retry["counts_as_observation"] is False


def test_retry_of_a_real_observation_still_says_it_counted(client, cell, tmp_path):
    _, h = cell
    e = good(make_manifest(tmp_path, "0412"), at=now() - timedelta(seconds=5))
    first, retry = _first_and_retry(client, h, e)
    assert first["counts_as_observation"] is True
    assert retry["outcome"] == "already_recorded"
    assert retry["counts_as_observation"] is True


# -- B-F10: a case opened from reporter-supplied manifests says so ----------------

def _drift_case(client, h, tmp_path):
    m = make_manifest(tmp_path, "0412", when=now())
    post(client, h, report(good(m, at=now() - timedelta(seconds=30))))
    m2 = make_manifest(tmp_path, "0412", fw=b"drift", when=now())
    r = post(client, h, report(good(m2, at=now()), watch_id="W2"))
    case_id = r.json()["machines"][0]["case_id"]
    assert case_id
    return client.get(f"/v1/change/cases/{case_id}", headers=h).json()


def test_a_hosted_drift_case_is_not_high_confidence_and_says_why(client, cell, tmp_path):
    _, h = cell
    case = _drift_case(client, h, tmp_path)
    assert case["confidence"] != "high"
    assert case["confidence"] == "medium"
    skipped = " ".join(case["checks_skipped"]).lower()
    assert "client-reported" in skipped or "client reported" in skipped
    assert "did not observe" in skipped


def test_the_sealed_divergence_carries_the_same_caveat(client, cell, tmp_path):
    acct, h = cell
    _drift_case(client, h, tmp_path)
    divergences = [e for e in ledger_of(acct).entries()
                   if e.kind == "machinery.divergence"]
    assert divergences
    ev = divergences[-1].evidence()
    assert ev.confidence.value != "high"
    assert any("client-reported" in c.lower() for c in ev.checks_skipped)
