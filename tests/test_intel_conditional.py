"""Conditional GET (ETag / Last-Modified, 304) for the public-source fetchers.

Every response is a CONTRACT FIXTURE served by an in-memory transport (``intel_support``): it
proves how the code handles a response of that shape, it is NOT live integration, and no socket
is opened. The urllib transport is exercised through a scripted opener, as in
``test_intel_transport.py``.
"""

from __future__ import annotations

import sqlite3
import urllib.request

import pytest

from assurance.intel.csaf_live import CsafRefusal, refresh_documents, refresh_provider
from assurance.intel.fetch import fetch
from assurance.intel.sources import SOURCES
from assurance.intel.store import (
    IntelStore,
    IntelStoreError,
    Validators,
    clean_validators,
)
from assurance.intel.transport import RedirectRefused
from assurance.intel.transport_urllib import UrllibTransport, _SameHostRedirect

from .intel_support import (
    CSAF_DIR,
    CSAF_HOST,
    CSAF_META_URL,
    Clock,
    ConditionalFixtureTransport,
    PlainFixtureTransport,
    csaf_doc,
    dump,
    kev_doc,
    provider_metadata,
)
from .test_intel_transport import KEV, Opener, Resp, http_error, transport

ETAG = '"v1-abc"'
LM = "Wed, 21 Oct 2026 07:28:00 GMT"
ETAG2 = '"v2-def"'
LM2 = "Thu, 22 Oct 2026 07:28:00 GMT"


@pytest.fixture()
def store(tmp_path):
    return IntelStore(tmp_path / "intel.sqlite")


def corrupt_blobs(path, *, replace=b"{}") -> None:
    """Edit every stored payload in place (the append-only triggers are dropped first)."""
    db = sqlite3.connect(path)
    db.execute("DROP TRIGGER blobs_no_update")
    db.execute("UPDATE blobs SET body=?", (replace,))
    db.commit()
    db.close()


def cond(headers) -> dict:
    return {k: v for k, v in headers.items() if k.startswith("If-")}


def blob_count(path) -> int:
    db = sqlite3.connect(path)
    try:
        return db.execute("SELECT count(*) FROM blobs").fetchone()[0]
    finally:
        db.close()


def kev_bytes(*cves, version="2026.10.30") -> bytes:
    return dump(kev_doc(*cves, version=version))


# -- documents: fetch() --------------------------------------------------------------------
def test_the_first_fetch_sends_no_validator_and_the_second_sends_what_was_stored(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    first = fetch(store, "kev", KEV, t, clock=clock)
    assert first.disposition == "first"
    assert t.calls[0][1] == {}
    second = fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[1][1] == {"If-None-Match": ETAG, "If-Modified-Since": LM}
    assert (second.disposition, second.http_status, second.accepted) == ("unchanged", 304, True)
    assert second.reason.startswith("not_modified")


def test_a_304_records_a_dated_unchanged_observation_and_downloads_nothing_new(store):
    body = kev_bytes("CVE-2026-0001")
    t = ConditionalFixtureTransport({KEV: (body, ETAG, LM)})
    clock = Clock()
    first = fetch(store, "kev", KEV, t, clock=clock)
    blobs = blob_count(store.path)
    first_row = store.raw_row(first.seq)
    second = fetch(store, "kev", KEV, t, clock=clock)
    assert second.sha256 == first.sha256 and second.byte_length == first.byte_length
    assert second.record_count == first.record_count and second.feed_stamp == first.feed_stamp
    assert second.retrieved_at > first.retrieved_at          # the time of the check is on file
    assert blob_count(store.path) == blobs                    # no second copy, no re-hash as new
    assert store.raw_row(first.seq) == first_row              # history untouched
    assert store.body(second.sha256) == body
    assert store.downstream_events() == [first]               # a 304 is never an event
    assert [o.seq for o in store.latest_accepted()] == [second.seq]


def test_validators_carry_forward_through_a_304(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    for _ in range(3):
        fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[2][1] == {"If-None-Match": ETAG, "If-Modified-Since": LM}
    assert [o.disposition for o in store.observations()] == ["first", "unchanged", "unchanged"]


def test_a_changed_body_replaces_the_validators_for_the_next_request(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)
    t.resources[KEV] = (kev_bytes("CVE-2026-0001", "CVE-2026-0002", version="2026.10.31"),
                        ETAG2, LM2)
    changed = fetch(store, "kev", KEV, t, clock=clock)          # server sees the old validator
    assert (changed.disposition, changed.http_status) == ("changed", 200)
    fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[2][1] == {"If-None-Match": ETAG2, "If-Modified-Since": LM2}


def test_a_304_that_carries_a_new_etag_updates_the_validators(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)
    t.resources[KEV] = (t.resources[KEV][0], ETAG, LM)
    orig = t.get_conditional

    def renew(url, headers, timeout):
        status, body, _ = orig(url, headers, timeout)
        return status, body, {"etag": ETAG2}
    t.get_conditional = renew
    fetch(store, "kev", KEV, t, clock=clock)
    assert store.validators_for("cisa_kev", KEV) == Validators(ETAG2, "")


def test_a_server_that_ignores_validators_still_works(store):
    body = kev_bytes("CVE-2026-0001")
    t = ConditionalFixtureTransport({KEV: (body, ETAG, LM)}, honour=False)
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)
    again = fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[1][1]                                      # it was asked conditionally
    assert (again.disposition, again.http_status) == ("unchanged", 200)
    t.resources[KEV] = (kev_bytes("CVE-2026-0009", version="2026.11.01"), ETAG2, LM2)
    assert fetch(store, "kev", KEV, t, clock=clock).disposition == "changed"


def test_a_transport_without_get_conditional_is_never_sent_a_validator(store):
    inner = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    plain = PlainFixtureTransport(inner)
    clock = Clock()
    fetch(store, "kev", KEV, plain, clock=clock)
    again = fetch(store, "kev", KEV, plain, clock=clock)
    assert [c[1] for c in inner.calls] == [{}, {}]
    assert again.disposition == "unchanged" and again.http_status == 200
    assert store.validators_for("cisa_kev", KEV) is None       # none were captured either


def test_a_response_without_validators_means_the_next_request_is_unconditional(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)
    t.resources[KEV] = (kev_bytes("CVE-2026-0002", version="2026.10.31"), "", "")
    fetch(store, "kev", KEV, t, clock=clock)                  # changed, and carries no validator
    fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[2][1] == {}                                # the old ETag belongs to old bytes


def test_a_failed_fetch_in_between_does_not_lose_the_validators(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)

    class Down:
        def get(self, url, headers, timeout):
            return 503, b"busy"
    assert fetch(store, "kev", KEV, Down(), clock=clock).disposition == "rejected"
    fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[1][1] == {"If-None-Match": ETAG, "If-Modified-Since": LM}


def test_validators_are_per_series_not_shared_between_urls(store):
    a = f"{SOURCES['first_epss'].url}?cve=CVE-2026-0001"
    b = f"{SOURCES['first_epss'].url}?cve=CVE-2026-0002"
    from .intel_support import epss_doc
    doc = dump(epss_doc(("CVE-2026-0001", "0.1", "0.5", "2026-10-30")))
    t = ConditionalFixtureTransport({a: (doc, ETAG, LM), b: (doc, ETAG2, LM2)})
    clock = Clock()
    fetch(store, "epss", a, t, clock=clock)
    fetch(store, "epss", b, t, clock=clock)
    assert t.calls[1][1] == {}                                # a's validators never go to b


# -- a validator is only as good as the stored body behind it --------------------------------
def test_validators_are_dropped_when_the_stored_blob_fails_its_rehash(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)
    corrupt_blobs(store.path, replace=kev_bytes("CVE-2026-0666"))     # still valid JSON
    assert store.validators_for("cisa_kev", KEV) is None
    again = fetch(store, "kev", KEV, t, clock=clock)
    assert t.calls[1][1] == {}                                # full download, nothing conditional
    assert again.http_status == 200


def test_a_304_whose_blob_was_damaged_after_the_validators_were_read_is_unknown(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    first = fetch(store, "kev", KEV, t, clock=clock)
    orig = t.get_conditional

    def damage_then_304(url, headers, timeout):
        corrupt_blobs(store.path)
        return orig(url, headers, timeout)
    t.get_conditional = damage_then_304
    obs = fetch(store, "kev", KEV, t, clock=clock)
    assert obs.disposition == "rejected" and not obs.accepted and obs.http_status == 304
    assert obs.reason.startswith("not_modified_unusable") and "unknown" in obs.reason
    assert store.latest_accepted()[0].seq == first.seq        # the baseline is not advanced


def test_a_304_with_no_stored_body_at_all_is_an_error_not_unchanged(store):
    obs = store.append_not_modified(source="cisa_kev", url=KEV, locator=KEV,
                                    retrieved_at=Clock()(), sent=Validators(ETAG, LM))
    assert obs.disposition == "rejected" and obs.http_status == 304 and not obs.accepted
    assert "no accepted observation" in obs.reason
    assert store.latest_accepted() == [] and store.downstream_events() == []


def test_a_304_for_validators_other_than_the_recorded_ones_is_unknown(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    clock = Clock()
    fetch(store, "kev", KEV, t, clock=clock)
    obs = store.append_not_modified(source="cisa_kev", url=KEV, locator=KEV,
                                    retrieved_at=clock(), sent=Validators('"other"', ""))
    assert obs.disposition == "rejected" and "validators" in obs.reason


def test_a_304_nobody_asked_for_is_rejected(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)},
                                    force_304=True)
    obs = fetch(store, "kev", KEV, t, clock=Clock())          # no validator was sent
    assert obs.disposition == "rejected" and obs.http_status == 304
    assert "not requested" in obs.reason
    assert store.latest_accepted() == []


def test_hostile_validator_values_are_never_stored_or_echoed():
    assert clean_validators({"ETag": '"ok"'}) == Validators('"ok"', "")
    assert clean_validators({"ETag": '"a"\r\nX-Evil: 1'}) == Validators()
    assert clean_validators({"etag": '"é"'}) == Validators()
    assert clean_validators({"etag": '"' + "a" * 600 + '"'}) == Validators()
    assert clean_validators({"last-modified": "not a date"}) == Validators()
    assert clean_validators({"last-modified": LM}) == Validators("", LM)
    assert clean_validators(None) == Validators() and clean_validators({"etag": 5}) == Validators()


def test_validator_and_listing_rows_are_append_only(store):
    t = ConditionalFixtureTransport({KEV: (kev_bytes("CVE-2026-0001"), ETAG, LM)})
    fetch(store, "kev", KEV, t, clock=Clock())
    store.record_listing("https://x.example/l", retrieved_at=Clock()(), raw=b"a",
                         validators=Validators(ETAG, ""))
    db = sqlite3.connect(store.path)
    for sql in ("UPDATE validators SET etag='x'", "DELETE FROM validators",
                "UPDATE listings SET etag='x'", "DELETE FROM listings"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.execute(sql)
    db.close()


def test_a_store_from_before_validators_existed_reads_as_no_validators(store):
    db = sqlite3.connect(store.path)
    db.execute("DROP TABLE validators")
    db.execute("DROP TABLE listings")
    db.commit()
    db.close()
    assert store.validators_for("cisa_kev", KEV) is None
    assert store.listing_state("https://x.example/l") is None
    ro = IntelStore.open_existing(store.path)
    assert ro.validators_for("cisa_kev", KEV) is None


# -- the urllib transport ---------------------------------------------------------------------
def test_get_conditional_returns_only_etag_and_last_modified():
    t = transport(Opener(Resp(b"{}", ETag=ETAG, Last_Modified=LM, Set_Cookie="s=1",
                              Server="x")))
    status, body, seen = t.get_conditional(KEV, {"If-None-Match": ETAG}, 5)
    assert (status, body, seen) == (200, b"{}", {"etag": ETAG, "last-modified": LM})


def test_the_request_carries_the_validators_the_caller_gave():
    opener = Opener(http_error(304, ETag=ETAG))
    t = transport(opener)
    status, body, seen = t.get_conditional(
        KEV, {"If-None-Match": ETAG, "If-Modified-Since": LM}, 5)
    assert (status, body, seen) == (304, b"", {"etag": ETAG})
    sent = opener.requests[0][1]
    assert sent["If-none-match"] == ETAG and sent["If-modified-since"] == LM


def test_a_304_is_an_answer_not_a_refused_redirect_but_other_3xx_still_are():
    assert transport(Opener(http_error(304))).get(KEV, {}, 5) == (304, b"")
    for code in (301, 302, 307, 308):
        with pytest.raises(RedirectRefused):
            transport(Opener(http_error(code))).get_conditional(KEV, {}, 5)


def test_a_validator_is_never_replayed_to_another_host():
    handler = _SameHostRedirect(frozenset({"www.cisa.gov", "api.first.org"}))
    req = urllib.request.Request(  # noqa: S310
        KEV, headers={"If-None-Match": ETAG, "If-Modified-Since": LM})
    for target in ("https://api.first.org/x", "https://evil.example/x",
                   "http://www.cisa.gov/x"):
        with pytest.raises(RedirectRefused):
            handler.redirect_request(req, None, 302, "Found", _hdrs(), target)


def test_a_conditional_request_to_a_refused_host_makes_no_request():
    opener = Opener()
    with pytest.raises(Exception, match="allow-list"):
        transport(opener).get_conditional("https://evil.example/x",
                                          {"If-None-Match": ETAG}, 5)
    assert opener.requests == []


def test_the_real_transport_end_to_end_with_fetch_and_a_scripted_opener(store):
    body = kev_bytes("CVE-2026-0001")
    opener = Opener(Resp(body, ETag=ETAG, Last_Modified=LM), http_error(304, ETag=ETAG))
    t = UrllibTransport(opener=opener, sleep=lambda s: None)
    clock = Clock()
    assert fetch(store, "kev", KEV, t, clock=clock).disposition == "first"
    second = fetch(store, "kev", KEV, t, clock=clock)
    assert (second.disposition, second.http_status) == ("unchanged", 304)
    assert opener.requests[1][1]["If-none-match"] == ETAG


def _hdrs():
    from email.message import Message
    return Message()


# -- CSAF provider mode ---------------------------------------------------------------------------
def doc_url(name):
    return f"{CSAF_DIR}/{name}"


def csaf_provider(*, kind="index"):
    docs = {"a.json": dump(csaf_doc("EX-A")), "b.json": dump(csaf_doc("EX-B"))}
    res = {CSAF_META_URL: (dump(provider_metadata()), '"m1"', "")}
    if kind == "index":
        res[f"{CSAF_DIR}/index.txt"] = (b"a.json\nb.json\n", '"i1"', "")
    else:
        res[f"{CSAF_DIR}/changes.csv"] = (
            b'"a.json","2026-10-02T08:30:00Z"\n"b.json","2026-10-02T08:30:00Z"\n', '"c1"', "")
    for n, b in docs.items():
        res[doc_url(n)] = (b, f'"{n}-1"', "")
    return res


def test_a_provider_without_listing_times_rechecks_every_document_but_downloads_none(store):
    t = ConditionalFixtureTransport(csaf_provider())
    clock = Clock()
    r1 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert r1.counts()["first"] == 2 and r1.bytes_fetched > 0
    r2 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert r2.counts() == {"first": 0, "changed": 0, "unchanged": 2, "rejected": 0}
    assert all(o.http_status == 304 for o in r2.observations)
    assert r2.bytes_fetched == 0                              # not one byte downloaded
    assert all(i.get("not_modified") for i in r2.index_status.values())
    assert store.downstream_events() == r1.observations
    # the fresh check is on file for each document
    assert all(o.retrieved_at > r1.observations[0].retrieved_at for o in r2.observations)


def test_a_304_document_stays_settled_for_incremental_skipping(store):
    res = csaf_provider(kind="changes")
    t = ConditionalFixtureTransport(res)
    clock = Clock()
    refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    r2 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert r2.up_to_date == 2 and r2.observations == []


def test_a_document_republished_with_a_newer_listing_but_identical_bytes_is_a_304(store):
    res = csaf_provider(kind="changes")
    t = ConditionalFixtureTransport(res)
    clock = Clock()
    refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    t.resources[f"{CSAF_DIR}/changes.csv"] = (
        b'"a.json","2026-10-09T08:30:00Z"\n"b.json","2026-10-02T08:30:00Z"\n', '"c2"', "")
    r2 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert [(o.url.rsplit("/", 1)[1], o.disposition, o.http_status)
            for o in r2.observations] == [("a.json", "unchanged", 304)]
    assert r2.index_status["changes.csv"]["http_status"] == 200      # the listing did change


def test_a_rolie_feed_is_not_redownloaded_when_unchanged(store):
    feed_url = f"https://{CSAF_HOST}/rolie/feed.json"
    meta = provider_metadata()
    meta["distributions"] = [{"rolie": {"feeds": [{"url": feed_url, "tlp_label": "WHITE"}]}}]
    feed = {"feed": {"entry": [
        {"updated": "2026-10-02T08:30:00Z", "content": {"src": doc_url("a.json")}}]}}
    t = ConditionalFixtureTransport({
        CSAF_META_URL: (dump(meta), '"m"', ""), feed_url: (dump(feed), '"f"', LM),
        doc_url("a.json"): (dump(csaf_doc("EX-A")), '"a"', "")})
    clock = Clock()
    r1 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert r1.index_kind == "rolie" and r1.counts()["first"] == 1
    r2 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert r2.index_kind == "rolie" and r2.listed == 1 and r2.up_to_date == 1
    assert r2.index_status["rolie-feed"] == {"url": f"{CSAF_HOST}/rolie/feed.json",
                                             "http_status": 304, "bytes": 0,
                                             "not_modified": True}
    feed_calls = [h for u, h in t.calls if u == feed_url]
    assert cond(feed_calls[1]) == {"If-None-Match": '"f"', "If-Modified-Since": LM}


def test_a_listing_304_without_an_intact_stored_copy_is_a_refusal_not_unchanged(store):
    t = ConditionalFixtureTransport(csaf_provider())
    clock = Clock()
    refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    orig = t.get_conditional

    def damage_then_304(url, headers, timeout):
        corrupt_blobs(store.path)
        return orig(url, headers, timeout)
    t.get_conditional = damage_then_304
    with pytest.raises(CsafRefusal, match="unknown, not unchanged"):
        refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)


def test_a_listing_304_nobody_asked_for_is_a_refusal(store):
    t = ConditionalFixtureTransport(csaf_provider(), force_304=True)
    with pytest.raises(CsafRefusal, match="HTTP 304"):
        refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=Clock())


def test_a_damaged_listing_copy_is_dropped_and_fetched_in_full(store):
    t = ConditionalFixtureTransport(csaf_provider())
    clock = Clock()
    refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    corrupt_blobs(store.path)
    r2 = refresh_provider(store, CSAF_META_URL, t, allowed_hosts=[CSAF_HOST], clock=clock)
    meta_calls = [h for u, h in t.calls if u == CSAF_META_URL]
    assert cond(meta_calls[1]) == {}
    assert r2.index_status["provider-metadata.json"]["http_status"] == 200


def test_listing_state_and_304_are_refused_when_validators_do_not_match(store):
    store.record_listing("https://x.example/l", retrieved_at=Clock()(), raw=b"body",
                         validators=Validators(ETAG, ""))
    with pytest.raises(IntelStoreError, match="validators"):
        store.record_listing_not_modified("https://x.example/l", retrieved_at=Clock()(),
                                          sent=Validators('"zzz"', ""))
    assert store.record_listing_not_modified(
        "https://x.example/l", retrieved_at=Clock()(), sent=Validators(ETAG, "")) == b"body"
    with pytest.raises(IntelStoreError, match="no stored copy"):
        store.record_listing_not_modified("https://x.example/none", retrieved_at=Clock()(),
                                          sent=Validators(ETAG, ""))


def test_direct_document_urls_use_conditional_get_too(store):
    u = doc_url("a.json")
    t = ConditionalFixtureTransport({u: (dump(csaf_doc("EX-A")), '"a"', "")})
    clock = Clock()
    refresh_documents(store, [u], t, allowed_hosts=[CSAF_HOST], clock=clock)
    r2 = refresh_documents(store, [u], t, allowed_hosts=[CSAF_HOST], clock=clock)
    assert [(o.disposition, o.http_status) for o in r2.observations] == [("unchanged", 304)]
    assert cond(t.calls[1][1]) == {"If-None-Match": '"a"'}
    assert r2.bytes_fetched == 0
    prov = store.provenance(r2.observations[0].seq)
    assert prov is not None and prov["settled"] is True
    assert prov["tracking"]["id"] == "EX-A"          # carried from the observation it confirms
