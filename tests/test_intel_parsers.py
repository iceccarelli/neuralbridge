"""Feeds are accepted whole or rejected whole. Payloads: SYNTHETIC or minimized contract fixtures."""

from __future__ import annotations

import json

import pytest

from assurance.intel.fetch import fetch, ingest_bytes
from assurance.intel.parsers import FeedRejected, parse_csaf, parse_epss, parse_kev, parse_nvd
from assurance.intel.sources import SOURCES, epss_url, nvd_url
from assurance.intel.store import IntelStore
from assurance.intel.transport import ResponseTooLarge

from .intel_support import (
    Clock,
    ContractFixtureTransport,
    dump,
    epss_doc,
    fixture_bytes,
    fixture_json,
    kev_doc,
)

CAP = 1 << 20


def reason(fn, raw):
    with pytest.raises(FeedRejected) as exc:
        fn(raw, CAP)
    return str(exc.value)


def test_minimized_public_fixtures_parse():
    kev = parse_kev(fixture_bytes("kev_min.json"), CAP)
    assert set(kev.records) == {"CVE-2021-22681", "CVE-2016-8562", "CVE-2021-44228"}
    assert kev.meta["catalogVersion"] == "2026.10.30"
    nvd = parse_nvd(fixture_bytes("nvd_min.json"), CAP)
    assert list(nvd.records) == ["CVE-2021-44228"]
    epss = parse_epss(fixture_bytes("epss_min.json"), CAP)
    assert epss.records["CVE-2021-44228"]["epss"] == 0.99999
    assert epss.feed_stamp == "2026-10-31"                      # the score date is kept
    assert parse_csaf(fixture_bytes("csaf_synthetic.json"), CAP).meta["cves"] == ["CVE-2026-0001"]


@pytest.mark.parametrize("parse,good", [
    (parse_kev, dump(kev_doc("CVE-2026-0001"))),
    (parse_nvd, fixture_bytes("nvd_min.json")),
    (parse_epss, fixture_bytes("epss_min.json")),
    (parse_csaf, fixture_bytes("csaf_synthetic.json")),
])
def test_truncation_at_any_point_is_rejected_never_half_read(parse, good):
    good = good.rstrip()
    for cut in (1, len(good) // 3, len(good) // 2, len(good) - 5, len(good) - 1):
        with pytest.raises(FeedRejected):
            parse(good[:cut], CAP)
    assert reason(parse, good[:len(good) // 2]).startswith("truncated")


def test_bad_json_empty_non_utf8_and_constants():
    assert reason(parse_kev, b"").startswith("empty")
    assert reason(parse_kev, b"   \n").startswith("empty")
    assert reason(parse_kev, b"\xff\xfe\x00{").startswith("not_utf8")
    assert reason(parse_kev, b'{"a": }').startswith("bad_json")
    assert reason(parse_epss, b'{"status": NaN}').startswith("bad_json")
    assert reason(parse_kev, b"[" * 100000 + b"]" * 100000).startswith("bad_json")


def test_oversized_is_rejected_before_it_is_parsed():
    raw = dump(kev_doc("CVE-2026-0001"))
    assert reason(lambda r, _c: parse_kev(r, 64), raw).startswith("oversized")


def test_kev_count_mismatch_means_truncated_or_altered():
    doc = kev_doc("CVE-2026-0001", "CVE-2026-0002")
    doc["count"] = 3
    assert reason(parse_kev, dump(doc)).startswith("truncated_or_altered")


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("vulnerabilities"),
    lambda d: d.pop("catalogVersion"),
    lambda d: d.update(count="2"),
    lambda d: d["vulnerabilities"][0].update(cveID="not-a-cve"),
    lambda d: d["vulnerabilities"][0].pop("vendorProject"),
    lambda d: d["vulnerabilities"][0].update(dateAdded="yesterday"),
    lambda d: d.update(vulnerabilities=["x"]),
])
def test_kev_wrong_shape(mutate):
    doc = kev_doc("CVE-2026-0001")
    mutate(doc)
    assert reason(parse_kev, dump(doc)).startswith(("wrong_shape", "truncated_or_altered"))
    assert reason(parse_kev, b"[]").startswith("wrong_shape")


def test_duplicate_record_ids_make_the_feed_ambiguous():
    doc = kev_doc("CVE-2026-0001", "CVE-2026-0001")
    assert reason(parse_kev, dump(doc)).startswith("duplicate_record")


def test_nvd_wrong_version_wrong_shape_and_truncated_page():
    doc = fixture_json("nvd_min.json")
    assert reason(parse_nvd, dump({**doc, "version": "1.0"})).startswith("wrong_shape")
    assert reason(parse_nvd, dump({**doc, "totalResults": 5, "resultsPerPage": 10})).startswith("truncated_or_altered")
    bad = fixture_json("nvd_min.json")
    bad["vulnerabilities"][0]["cve"]["id"] = "nope"
    assert reason(parse_nvd, dump(bad)).startswith("wrong_shape")


@pytest.mark.parametrize("row", [
    ("CVE-2026-0001", "1.5", "0.2", "2026-10-31"),
    ("CVE-2026-0001", "-0.1", "0.2", "2026-10-31"),
    ("CVE-2026-0001", "abc", "0.2", "2026-10-31"),
    ("CVE-2026-0001", "0.1", "0.2", "not-a-date"),
    ("CVE-2026-0001", "nan", "0.2", "2026-10-31"),
])
def test_epss_rejects_impossible_scores_and_dates(row):
    assert reason(parse_epss, dump(epss_doc(row))).startswith("wrong_shape")


def test_epss_status_must_be_ok_and_total_must_agree():
    doc = epss_doc(("CVE-2026-0001", "0.1", "0.2", "2026-10-31"))
    assert reason(parse_epss, dump({**doc, "status": "ERROR"})).startswith("wrong_shape")
    assert reason(parse_epss, dump({**doc, "total": 9})).startswith("truncated_or_altered")


def test_csaf_must_pass_the_repos_own_importer():
    doc = fixture_json("csaf_synthetic.json")
    doc["document"]["tracking"]["status"] = "draft"
    assert "importer refused" in reason(parse_csaf, dump(doc))
    assert reason(parse_csaf, b'{"x": 1}').startswith("wrong_shape")


def test_each_rejection_is_recorded_with_its_sha_and_reason(tmp_path):
    store = IntelStore(tmp_path / "i.db")
    clock = Clock()
    cases = {
        "oversized": ResponseTooLarge("cap", status=200, partial=b"x" * 10),
    }
    t = ContractFixtureTransport({
        SOURCES["cisa_kev"].url: (200, b'{"vulnerabilities": ['),
        nvd_url("CVE-2026-0001"): cases["oversized"],
        epss_url(["CVE-2026-0001"]): (200, json.dumps({"status": "ERROR"}).encode()),
    })
    kev = fetch(store, "kev", SOURCES["cisa_kev"].url, t, clock=clock)
    nvd = fetch(store, "nvd", nvd_url("CVE-2026-0001"), t, clock=clock)
    epss = fetch(store, "epss", epss_url(["CVE-2026-0001"]), t, clock=clock)
    assert kev.reason.startswith("truncated") and kev.http_status == 200
    assert nvd.reason.startswith("oversized") and nvd.byte_length == 10
    assert epss.reason.startswith("wrong_shape")
    for o in (kev, nvd, epss):
        assert o.disposition == "rejected" and o.parse_result == "malformed"
        assert o.parser_version.startswith("assurance-intel-parse/")
        assert o.retrieved_at.endswith("Z")
    assert store.latest_accepted() == []


def test_oversized_file_is_rejected_by_ingest(tmp_path):
    store = IntelStore(tmp_path / "i.db")
    o = ingest_bytes(store, "cisa_kev", b" " * 100 + dump(kev_doc("CVE-2026-0001")),
                     url="u", locator="l", via="file", http_status=None, max_bytes=50)
    assert o.disposition == "rejected" and o.reason.startswith("oversized")
