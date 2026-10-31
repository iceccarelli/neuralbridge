"""Observation history: dedupe by sha, diffs, append-only, one writer.

Payloads are SYNTHETIC or minimized public-source contract fixtures (see intel_support).
"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from assurance.intel.fetch import fetch, ingest_bytes
from assurance.intel.sources import SOURCES
from assurance.intel.store import IntelStore

from .intel_support import (
    Clock,
    ContractFixtureTransport,
    dump,
    fixture_bytes,
    kev_doc,
)

KEV = SOURCES["cisa_kev"].url


def put(store, doc, clock=None):
    return ingest_bytes(store, "cisa_kev", dump(doc), url=KEV, locator="file:kev.json",
                        via="file", http_status=None, retrieved_at=(clock or Clock())())


@pytest.fixture
def store(tmp_path):
    return IntelStore(tmp_path / "intel.db")


def test_first_then_identical_bytes_is_unchanged_and_not_a_downstream_event(store):
    clock = Clock()
    a = put(store, kev_doc("CVE-2026-0001"), clock)
    b = put(store, kev_doc("CVE-2026-0001"), clock)
    assert (a.disposition, b.disposition) == ("first", "unchanged")
    assert a.sha256 == b.sha256 and b.seq == a.seq + 1 and b.diff is None
    assert [o.seq for o in store.downstream_events()] == [a.seq]


def test_changed_bytes_record_a_new_observation_with_added_removed_modified(store):
    clock = Clock()
    put(store, kev_doc("CVE-2026-0001", "CVE-2026-0002"), clock)
    doc = kev_doc("CVE-2026-0002", "CVE-2026-0003")
    doc["vulnerabilities"][0]["dueDate"] = "2026-12-01"      # CVE-2026-0002 modified
    changed = put(store, doc, clock)
    assert changed.disposition == "changed"
    assert changed.diff["added"] == ["CVE-2026-0003"]
    assert changed.diff["removed"] == ["CVE-2026-0001"]
    assert changed.diff["modified"] == ["CVE-2026-0002"]
    assert changed.diff["truncated"] is False
    assert [o.disposition for o in store.downstream_events()] == ["first", "changed"]


def test_going_back_to_older_bytes_is_a_change_not_an_unchanged(store):
    clock = Clock()
    put(store, kev_doc("CVE-2026-0001"), clock)
    put(store, kev_doc("CVE-2026-0001", "CVE-2026-0002"), clock)
    back = put(store, kev_doc("CVE-2026-0001"), clock)
    assert back.disposition == "changed" and back.diff["removed"] == ["CVE-2026-0002"]


def test_a_rejected_observation_changes_nothing_else(store):
    clock = Clock()
    good = put(store, kev_doc("CVE-2026-0001"), clock)
    before = (store.raw_row(good.seq), store.latest_accepted())
    bad = ingest_bytes(store, "cisa_kev", b'{"vulnerabilities": [', url=KEV, locator="x",
                       via="file", http_status=None, retrieved_at=clock())
    assert bad.disposition == "rejected" and bad.parse_result == "malformed"
    assert bad.reason.startswith("truncated")
    assert store.body(bad.sha256) is None                      # no payload stored
    assert (store.raw_row(good.seq), store.latest_accepted()) == before
    again = put(store, kev_doc("CVE-2026-0001"), clock)        # baseline survived
    assert again.disposition == "unchanged"
    assert [o.seq for o in store.downstream_events()] == [good.seq]


def test_second_refresh_leaves_the_first_observation_byte_identical(store):
    clock = Clock()
    first = put(store, kev_doc("CVE-2026-0001"), clock)
    snapshot = store.raw_row(first.seq)
    put(store, kev_doc("CVE-2026-0001"), clock)
    put(store, kev_doc("CVE-2026-0001", "CVE-2026-0009"), clock)
    assert store.raw_row(first.seq) == snapshot
    assert store.get(first.seq) == first


def test_history_cannot_be_updated_or_deleted_even_with_raw_sql(store):
    obs = put(store, kev_doc("CVE-2026-0001"))
    raw = sqlite3.connect(store.path)
    for sql in ("UPDATE observations SET disposition='first' WHERE seq=1",
                "DELETE FROM observations", "DELETE FROM blobs",
                "UPDATE blobs SET body=x'00'"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            raw.execute(sql)
    raw.close()
    assert store.get(obs.seq) == obs


def test_a_foreign_sqlite_file_is_refused(tmp_path):
    other = tmp_path / "other.db"
    c = sqlite3.connect(other)
    c.execute("create table t (x)")
    c.commit()
    c.close()
    with pytest.raises(Exception, match="not an intel observation store"):
        IntelStore(other)


def test_identical_concurrent_ingests_produce_one_first_and_the_rest_unchanged(tmp_path):
    path = tmp_path / "c.db"
    IntelStore(path)
    payload = dump(kev_doc("CVE-2026-0001"))

    def work(i):
        s = IntelStore(path)               # its own handle: a different writer
        return ingest_bytes(s, "cisa_kev", payload, url=KEV, locator=f"w{i}", via="file",
                            http_status=None).disposition

    with ThreadPoolExecutor(8) as pool:
        got = sorted(pool.map(work, range(8)))
    assert got.count("first") == 1 and got.count("unchanged") == 7


def test_distinct_concurrent_ingests_form_one_unforked_sequence(tmp_path):
    path = tmp_path / "c.db"
    IntelStore(path)

    def work(i):
        s = IntelStore(path)
        return ingest_bytes(s, "cisa_kev", dump(kev_doc(*[f"CVE-2026-{n:04d}"
                                                          for n in range(1, i + 2)])),
                            url=KEV, locator=f"w{i}", via="file", http_status=None)

    with ThreadPoolExecutor(6) as pool:
        list(pool.map(work, range(6)))
    rows = IntelStore(path).observations()
    assert [o.seq for o in rows] == list(range(1, 7))
    assert sorted(o.disposition for o in rows) == ["changed"] * 5 + ["first"]
    # each diff was computed against the observation that really preceded it
    for o in rows:
        if o.disposition == "changed":
            assert o.diff["added_total"] + o.diff["removed_total"] + o.diff["modified_total"] > 0


def test_a_rejected_transport_failure_still_leaves_one_observation(store):
    t = ContractFixtureTransport({KEV: (503, b"busy")})
    obs = fetch(store, "kev", KEV, t, clock=Clock())
    assert (obs.disposition, obs.http_status, obs.byte_length) == ("rejected", 503, 4)
    assert obs.reason == "http_status: 503" and len(obs.sha256) == 64
    assert store.latest_accepted() == []


def test_fixture_payloads_round_trip_and_carry_provenance(store):
    for name, src in (("kev_min.json", "cisa_kev"), ("nvd_min.json", "nvd_cve_api"),
                      ("epss_min.json", "first_epss")):
        obs = ingest_bytes(store, src, fixture_bytes(name), url=SOURCES[src].url,
                           locator=name, via="file", http_status=None)
        assert obs.disposition == "first" and obs.record_count >= 1, name
        assert b"minimized from public source, retrieved 2026-10-31" in fixture_bytes(name)
