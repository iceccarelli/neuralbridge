"""``intel refresh --source csaf --live``: provider-metadata incremental refresh.

Every response here is a CONTRACT FIXTURE served by an in-memory transport: a synthetic
provider-metadata.json, changes.csv and CSAF documents on ``csaf.example.invalid``. It proves
how the code handles responses of those shapes. It is NOT live integration; the one real-host
check is a manual smoke run recorded in the hand-off, not a test.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from assurance.cli import main as top
from assurance.intel import cli as intel_cli
from assurance.intel.csaf_live import (
    CsafRefusal,
    normalise_allow_hosts,
    refresh_documents,
    refresh_provider,
)
from assurance.intel.store import IntelStore
from assurance.intel.transport import RedirectRefused, ResponseTooLarge
from assurance.intel.transport_urllib import UrllibTransport
from assurance.intel.view import build_report

from .intel_support import (
    CSAF_DIR,
    CSAF_HOST,
    CSAF_META_URL,
    Clock,
    ContractFixtureTransport,
    changes_csv,
    csaf_doc,
    dump,
    provider_metadata,
)

SECRET = "tok-9f8e7d6c5b4a-never-print"
HOSTS = [CSAF_HOST]


def url(path: str) -> str:
    return f"{CSAF_DIR}/{path}"


def provider(listing: dict[str, str], docs: dict[str, object], *,
             meta: dict | None = None) -> ContractFixtureTransport:
    """listing: path -> last-change time. docs: path -> dict | bytes | (status, bytes) | Exception."""
    table: dict[str, object] = {
        CSAF_META_URL: (200, dump(meta or provider_metadata())),
        url("changes.csv"): (200, changes_csv(*listing.items())),
    }
    for path, d in docs.items():
        table[url(path)] = ((200, dump(d)) if isinstance(d, dict) else
                            (200, d) if isinstance(d, bytes) else d)
    return ContractFixtureTransport(table)  # type: ignore[arg-type]


def doc_fetches(t: ContractFixtureTransport) -> list[str]:
    return [c[0].rsplit("/", 1)[1] for c in t.calls if c[0].endswith(".json")
            and "provider-metadata" not in c[0]]


def refresh(store, t, **kw):
    kw.setdefault("allowed_hosts", HOSTS)
    kw.setdefault("clock", Clock())
    return refresh_provider(store, CSAF_META_URL, t, **kw)


@pytest.fixture
def store(tmp_path):
    return IntelStore(tmp_path / "intel.db")


T0, T1, T2 = "2026-10-10T00:00:00Z", "2026-10-20T00:00:00Z", "2026-10-25T00:00:00Z"
D101 = csaf_doc("EX-2026-101")
D102 = csaf_doc("EX-2026-102")


# --------------------------------------------------------------------------- incremental
def three_document_scenario(store):
    """102 was already recorded; now 101 is new, bad.json is malformed, big.json oversized."""
    refresh(store, provider({"2026/ex-2026-102.json": T0}, {"2026/ex-2026-102.json": D102}))
    t = provider(
        {"2026/ex-2026-101.json": T2, "2026/bad.json": T1, "2026/big.json": T1,
         "2026/ex-2026-102.json": T0},
        {"2026/ex-2026-101.json": D101, "2026/bad.json": b'{"document": {"tracking": ',
         "2026/big.json": ResponseTooLarge("body exceeded 8388608 bytes", status=200,
                                           partial=b"x" * 64),
         "2026/ex-2026-102.json": D102})
    return t, refresh(store, t)


def test_incremental_refresh_fetches_only_newer_documents_and_survives_bad_ones(store):
    t, report = three_document_scenario(store)
    assert "ex-2026-102.json" not in doc_fetches(t)          # already settled at that time
    assert doc_fetches(t) == ["ex-2026-101.json", "bad.json", "big.json"]   # newest first
    assert report.listed == 4 and report.up_to_date == 1 and report.not_fetched == 0
    by_name = {o.url.rsplit("/", 1)[1]: o for o in report.observations}
    assert by_name["ex-2026-101.json"].disposition == "first"
    bad, big = by_name["bad.json"], by_name["big.json"]
    assert bad.disposition == big.disposition == "rejected"
    assert bad.reason.startswith(("truncated", "bad_json")) and big.reason.startswith("oversized")
    assert big.http_status == 200 and big.byte_length == 64
    for o in report.observations:                 # source, url, time, status, bytes, sha, parser
        assert o.source == "csaf" and o.url.startswith(CSAF_DIR) and o.retrieved_at
        assert o.http_status == 200 and o.byte_length > 0 and len(o.sha256) == 64
        assert o.parser_version.startswith("assurance-intel-parse/")


def test_a_second_run_fetches_nothing_and_raises_no_downstream_event(store):
    three_document_scenario(store)
    before = [o.seq for o in store.downstream_events()]
    t = provider({"2026/ex-2026-101.json": T2, "2026/bad.json": T1, "2026/big.json": T1,
                  "2026/ex-2026-102.json": T0}, {})
    report = refresh(store, t)
    assert doc_fetches(t) == [] and report.up_to_date == 4 and report.observations == []
    assert [o.seq for o in store.downstream_events()] == before


def test_a_relisted_document_with_the_same_bytes_is_unchanged_and_not_an_event(store):
    refresh(store, provider({"2026/ex-2026-102.json": T0}, {"2026/ex-2026-102.json": D102}))
    events = [o.seq for o in store.downstream_events()]
    t = provider({"2026/ex-2026-102.json": T1}, {"2026/ex-2026-102.json": D102})
    report = refresh(store, t)
    assert [o.disposition for o in report.observations] == ["unchanged"]
    assert [o.seq for o in store.downstream_events()] == events


def test_a_revision_is_changed_keeps_the_old_and_records_tracking_history(store):
    refresh(store, provider({"2026/ex-2026-101.json": T0}, {"2026/ex-2026-101.json": D101}))
    v2 = csaf_doc("EX-2026-101", version="2", current="2026-10-19T00:00:00Z",
                  extra="Fixed firmware V2.003 is available.")
    refresh(store, provider({"2026/ex-2026-101.json": T1}, {"2026/ex-2026-101.json": v2}))
    first, second = store.observations(source="csaf")
    assert (first.disposition, second.disposition) == ("first", "changed")
    assert second.diff and second.diff["modified"] == ["EX-2026-101"]
    assert store.body(first.sha256) is not None and store.body(second.sha256) is not None
    p1, p2 = store.provenance(first.seq), store.provenance(second.seq)
    assert p1["tracking"]["version"] == "1" and p2["tracking"]["version"] == "2"
    assert p2["tracking"]["id"] == "EX-2026-101"
    assert p2["tracking"]["initial_release_date"] and p2["tracking"]["current_release_date"]
    assert p2["provider"] == CSAF_META_URL and p2["listed_at"] == T1
    assert p2["publisher"]["name"] == "Example Controls GmbH"


def test_a_revision_not_yet_listed_as_newer_is_not_fetched(store):
    """The cursor is the listing time: this mutation guard fails if every run refetches."""
    refresh(store, provider({"2026/ex-2026-101.json": T1}, {"2026/ex-2026-101.json": D101}))
    t = provider({"2026/ex-2026-101.json": T1}, {})
    refresh(store, t)
    assert doc_fetches(t) == []
    t = provider({"2026/ex-2026-101.json": T0}, {})        # an older listing never refetches
    refresh(store, t)
    assert doc_fetches(t) == []


def test_a_transient_failure_is_recorded_and_retried_next_run(store):
    t = provider({"2026/a.json": T1, "2026/b.json": T0},
                 {"2026/a.json": (500, b"oops"), "2026/b.json": D101})
    report = refresh(store, t)
    assert [o.disposition for o in report.observations] == ["rejected", "first"]
    assert report.observations[0].http_status == 500
    t2 = provider({"2026/a.json": T1, "2026/b.json": T0}, {"2026/a.json": D102})
    report2 = refresh(store, t2)
    assert doc_fetches(t2) == ["a.json"] and report2.observations[0].disposition == "first"


def test_a_429_stops_the_batch_and_reports_the_rest(store):
    t = provider({"2026/a.json": T2, "2026/b.json": T1, "2026/c.json": T0},
                 {"2026/a.json": (429, b""), "2026/b.json": D101, "2026/c.json": D102})
    report = refresh(store, t)
    assert doc_fetches(t) == ["a.json"] and report.not_fetched == 2
    assert "429" in report.stopped


def test_a_permanent_404_is_recorded_once_until_relisted(store):
    refresh(store, provider({"2026/gone.json": T0}, {"2026/gone.json": (404, b"")}))
    t = provider({"2026/gone.json": T0}, {})
    refresh(store, t)
    assert doc_fetches(t) == []


# --------------------------------------------------------------------------- caps
def many(n: int):
    names = [f"2026/ex-{i:03d}.json" for i in range(n)]
    listing = {p: f"2026-10-10T{i // 60:02d}:{i % 60:02d}:00Z" for i, p in enumerate(names)}
    docs = {p: csaf_doc(f"EX-2026-{i:03d}") for i, p in enumerate(names)}
    return listing, docs


def test_max_documents_is_honoured_reported_and_resumed_never_silently_truncated(store):
    listing, docs = many(5)
    t = provider(listing, docs)
    report = refresh(store, t, max_documents=2)
    assert doc_fetches(t) == ["ex-004.json", "ex-003.json"]            # newest first
    assert report.not_fetched == 3 and "max-documents" in report.stopped
    t2 = provider(listing, docs)
    report2 = refresh(store, t2, max_documents=2)
    assert doc_fetches(t2) == ["ex-002.json", "ex-001.json"] and report2.not_fetched == 1
    t3 = provider(listing, docs)
    report3 = refresh(store, t3, max_documents=2)
    assert doc_fetches(t3) == ["ex-000.json"] and report3.not_fetched == 0
    assert len(store.observations(source="csaf")) == 5


def test_default_max_documents_is_50(store):
    listing, docs = many(55)
    t = provider(listing, docs)
    report = refresh(store, t)
    assert len(report.observations) == 50 and report.not_fetched == 5


def test_the_total_byte_cap_stops_the_run_and_says_so(store):
    listing, docs = many(4)
    t = provider(listing, docs)
    one = len(dump(docs["2026/ex-000.json"]))
    report = refresh(store, t, max_total_bytes=one * 2)
    assert 1 <= len(report.observations) < 4
    assert report.not_fetched == 4 - len(report.observations)
    assert "byte cap" in report.stopped


def test_the_cap_must_be_positive():
    with pytest.raises(CsafRefusal):
        refresh_provider(None, CSAF_META_URL, ContractFixtureTransport({}),  # type: ignore[arg-type]
                         allowed_hosts=HOSTS, max_documents=0)


# --------------------------------------------------------------------------- network rules
def test_a_metadata_host_not_on_the_allow_list_is_refused_with_no_request(store):
    t = provider({}, {})
    with pytest.raises(CsafRefusal, match="allow-list"):
        refresh_provider(store, CSAF_META_URL, t, allowed_hosts=["other.example.invalid"])
    assert t.calls == []


def test_a_directory_url_on_a_host_the_operator_did_not_name_is_refused(store):
    meta = provider_metadata("https://cdn.other.invalid/csaf/white")
    t = provider({}, {}, meta=meta)
    with pytest.raises(CsafRefusal, match="no usable directory_url"):
        refresh(store, t)
    assert [c[0] for c in t.calls] == [CSAF_META_URL]       # only the metadata was requested
    assert store.observations() == []


@pytest.mark.parametrize("bad", [
    "http://csaf.example.invalid/a.json", "https://evil.invalid/a.json",
    f"https://{CSAF_HOST}:8443/a.json", f"https://user:pw@{CSAF_HOST}/a.json",
    f"https://{CSAF_HOST}/a.json?token={SECRET}", f"https://{CSAF_HOST}/a.json#{SECRET}",
    f"https://{CSAF_HOST}.evil.invalid/a.json",
])
def test_direct_urls_off_list_or_carrying_a_query_are_refused_before_any_request(store, bad):
    good = f"https://{CSAF_HOST}/ok.json"
    t = ContractFixtureTransport({good: (200, dump(D101))})
    with pytest.raises(CsafRefusal) as err:
        refresh_documents(store, [good, bad], t, allowed_hosts=HOSTS)
    assert t.calls == [] and SECRET not in str(err.value)       # all-or-nothing, no leak


def test_allow_host_must_be_a_bare_exact_host():
    assert normalise_allow_hosts(["Cert.Example.COM"]) == {"cert.example.com"}
    for bad in ("*", "*.example.com", "https://a.example.com", "a.example.com:443",
                "a.example.com/x", "", " ", "a b"):
        with pytest.raises(CsafRefusal):
            normalise_allow_hosts([bad])
    with pytest.raises(CsafRefusal, match="required"):
        normalise_allow_hosts([])


def test_traversal_and_foreign_paths_in_the_index_are_skipped_and_counted(store):
    t = provider({"../etc/passwd.json": T1, "/abs.json": T1, "a/../b.json": T1,
                  "https://evil.invalid/x.json": T1, "2026/ok.json": T1, "2026/x.txt": T1,
                  "2026/nodate.json": "garbage"}, {"2026/ok.json": D101})
    report = refresh(store, t)
    assert doc_fetches(t) == ["ok.json"] and report.skipped_rows == 6


def test_an_off_host_redirect_is_a_recorded_rejection_and_the_batch_goes_on(store):
    t = provider({"2026/a.json": T2, "2026/b.json": T1},
                 {"2026/a.json": RedirectRefused("redirect to another host (evil.invalid) "
                                                 "refused"),
                  "2026/b.json": D101})
    report = refresh(store, t)
    a, b = report.observations
    assert a.disposition == "rejected" and "redirect" in a.reason and a.http_status == 0
    assert b.disposition == "first"


def test_the_real_transport_refuses_a_redirect_and_a_foreign_host_end_to_end(store):
    """Real UrllibTransport guards over a scripted opener (still no socket)."""

    class Opener:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def open(self, request, timeout=None):
            self.requests.append(request.full_url)
            if request.full_url.endswith("provider-metadata.json"):
                return _Resp(dump(provider_metadata()))
            if request.full_url.endswith("changes.csv"):
                return _Resp(changes_csv(("2026/a.json", T1)))
            raise RedirectRefused("redirect to another host (evil.invalid) refused")

    op = Opener()
    transport = UrllibTransport(allowed_hosts=HOSTS, opener=op, sleep=lambda _s: None)
    report = refresh(store, transport)
    assert report.observations[0].disposition == "rejected"
    assert "redirect" in report.observations[0].reason
    assert all(u.startswith(f"https://{CSAF_HOST}/") for u in op.requests)
    assert refresh_documents(store, [f"https://{CSAF_HOST}/x.json"], transport,
                             allowed_hosts=HOSTS).observations[0].disposition == "rejected"


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._io = io.BytesIO(body)
        self.status = 200
        self.headers: dict = {}

    def read(self, n=-1):
        return self._io.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_retry_after_is_honoured_by_the_shared_transport_not_reimplemented():
    sleeps: list[float] = []
    err = urllib.error.HTTPError(f"https://{CSAF_HOST}/a", 429, "x", {"Retry-After": "7"},
                                 io.BytesIO(b""))

    class Opener:
        calls = 0

        def open(self, request, timeout=None):
            Opener.calls += 1
            if Opener.calls == 1:
                raise err
            return _Resp(b"{}")

    t = UrllibTransport(allowed_hosts=HOSTS, opener=Opener(), sleep=sleeps.append)
    assert t.get(f"https://{CSAF_HOST}/a", {}, 5)[0] == 200 and sleeps == [7.0]


# --------------------------------------------------------------------------- documents
def test_index_txt_is_used_when_there_is_no_changes_csv(store):
    t = ContractFixtureTransport({
        CSAF_META_URL: (200, dump(provider_metadata())),
        url("changes.csv"): (404, b""),
        url("index.txt"): (200, b"2026/a.json\n2026/b.json\n"),
        url("2026/a.json"): (200, dump(D101)), url("2026/b.json"): (200, dump(D102))})
    report = refresh(store, t)
    assert report.index_kind == "index.txt" and len(report.observations) == 2
    again = refresh(store, t)               # no listing time, so nothing can be skipped ...
    assert [o.disposition for o in again.observations] == ["unchanged", "unchanged"]   # ... dedupe


def test_the_importer_decides_acceptance_and_imports_stay_unsigned(store):
    draft = csaf_doc("EX-2026-103")
    draft["document"]["tracking"]["status"] = "draft"
    t = provider({"2026/ok.json": T1, "2026/draft.json": T1},
                 {"2026/ok.json": D101, "2026/draft.json": draft})
    report = refresh(store, t)
    by = {o.url.rsplit("/", 1)[1]: o for o in report.observations}
    assert by["draft.json"].disposition == "rejected" and "importer" in by["draft.json"].reason
    cands = build_report(store).candidates
    assert [c.advisory.advisory_id for c in cands] and all(
        "signed" not in c.trust.replace("unsigned", "") for c in cands)
    assert all(c.advisory.import_record is None or c.advisory.import_record.trust != "trusted"
               for c in cands)


def test_a_document_without_fixed_data_leaves_fixed_unknown(store):
    with_fix = csaf_doc("EX-2026-104")
    no_fix = csaf_doc("EX-2026-105")
    for vuln in no_fix.get("vulnerabilities", []):
        vuln.pop("remediations", None)
        vuln["product_status"].pop("fixed", None)
    refresh(store, provider({"2026/f.json": T1, "2026/n.json": T0},
                            {"2026/f.json": with_fix, "2026/n.json": no_fix}))
    cands = {c.advisory.advisory_id: c.advisory for c in build_report(store).candidates}
    fixed = [a for a in cands.values() if any(x.fixed_versions for x in a.affected)]
    unknown = [a for a in cands.values() if not any(x.fixed_versions for x in a.affected)]
    assert len(fixed) == 1 and len(unknown) == 1 and unknown[0].remedy == ""


# --------------------------------------------------------------------------- ROLIE-only provider
ROLIE_URL = f"https://{CSAF_HOST}/csaf/feed-tlp-white.json"


def rolie_provider(entries: list[dict], docs: dict[str, object], *, feeds=None
                   ) -> ContractFixtureTransport:
    """Shape minimized from a real provider that announces only a ROLIE feed (no directory)."""
    meta = provider_metadata()
    meta["distributions"] = [{"rolie": {"feeds": feeds or [
        {"summary": "All TLP:WHITE advisories", "tlp_label": "WHITE", "url": ROLIE_URL}]}}]
    table: dict[str, object] = {
        CSAF_META_URL: (200, dump(meta)),
        ROLIE_URL: (200, dump({"feed": {"id": "f", "updated": T2, "entry": entries}}))}
    for u, d in docs.items():
        table[u] = (200, dump(d)) if isinstance(d, dict) else d
    return ContractFixtureTransport(table)  # type: ignore[arg-type]


def rolie_entry(name: str, updated: str, src: str | None = None) -> dict:
    src = src or f"https://{CSAF_HOST}/csaf/{name}.json"
    return {"id": name, "updated": updated, "link": [{"rel": "self", "href": src}],
            "content": {"type": "application/json", "src": src}}


def test_a_rolie_only_provider_is_read_incrementally(store):
    a, b = f"https://{CSAF_HOST}/csaf/a.json", f"https://{CSAF_HOST}/csaf/b.json"
    t = rolie_provider([rolie_entry("a", T0), rolie_entry("b", T1)], {a: D101, b: D102})
    report = refresh(store, t)
    assert report.index_kind == "rolie" and report.listed == 2
    assert [c[0] for c in t.calls if c[0].endswith(".json")][2:] == [b, a]     # newest first
    t2 = rolie_provider([rolie_entry("a", T0), rolie_entry("b", T1)], {})
    assert refresh(store, t2).observations == [] and t2.calls[-1][0] == ROLIE_URL
    t3 = rolie_provider([rolie_entry("a", T2), rolie_entry("b", T1)], {a: D101})
    assert [o.disposition for o in refresh(store, t3).observations] == ["unchanged"]


def test_rolie_entries_off_host_unusable_or_with_queries_are_not_fetched(store):
    ok = f"https://{CSAF_HOST}/csaf/ok.json"
    entries = [rolie_entry("ok", T1),
               rolie_entry("evil", T1, "https://evil.invalid/csaf/evil.json"),
               rolie_entry("q", T1, f"https://{CSAF_HOST}/csaf/q.json?k={SECRET}"),
               rolie_entry("txt", T1, f"https://{CSAF_HOST}/csaf/x.txt"),
               {"id": "nolink", "updated": T1}, rolie_entry("baddate", "yesterday")]
    t = rolie_provider(entries, {ok: D101})
    report = refresh(store, t)
    assert [o.url for o in report.observations] == [ok]
    assert report.refused == ["evil.invalid/csaf/evil.json"] and report.skipped_rows == 4
    assert report.rejected == 1                      # a refused entry is reported, not dropped
    assert not any("evil.invalid" in c[0] or SECRET in c[0] for c in t.calls)


def test_a_rolie_feed_that_is_not_tlp_white_is_not_used(store):
    t = rolie_provider([rolie_entry("a", T0)], {}, feeds=[
        {"tlp_label": "AMBER", "url": ROLIE_URL}])
    with pytest.raises(CsafRefusal, match="no usable directory_url or ROLIE feed"):
        refresh(store, t)
    assert [c[0] for c in t.calls] == [CSAF_META_URL]


# --------------------------------------------------------------------------- the CLI
@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "cli.db")


def run(capsys, *argv):
    code = top(["intel", *map(str, argv)])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.fixture
def wired(monkeypatch):
    seen = {}

    def install(t):
        def make(source_id, allowed_hosts=None):
            seen["source"], seen["hosts"] = source_id, allowed_hosts
            return t
        monkeypatch.setattr(intel_cli, "_make_transport", make)
        return seen
    return install


def test_cli_requires_live_and_allow_host_and_one_mode(capsys, db, wired):
    t = provider({}, {})
    wired(t)
    base = ["refresh", "--source", "csaf", "--store", db]
    assert run(capsys, *base, "--allow-host", CSAF_HOST,
               "--provider-metadata-url", CSAF_META_URL)[0] == 2          # no --live
    code, _, err = run(capsys, *base, "--live", "--provider-metadata-url", CSAF_META_URL)
    assert code == 2 and "--allow-host is required" in err
    code, _, err = run(capsys, *base, "--live", "--allow-host", CSAF_HOST)
    assert code == 2 and "either --url" in err
    code, _, err = run(capsys, *base, "--live", "--allow-host", CSAF_HOST, "--url", url("a.json"),
                       "--provider-metadata-url", CSAF_META_URL)
    assert code == 2
    assert t.calls == []


def test_cli_provider_run_end_to_end_and_second_run(capsys, db, wired):
    listing, docs = many(3)
    t = provider(listing, docs)
    seen = wired(t)
    args = ["refresh", "--source", "csaf", "--store", db, "--live", "--allow-host", CSAF_HOST,
            "--provider-metadata-url", CSAF_META_URL, "--max-documents", "2"]
    code, out, _ = run(capsys, *args)
    assert code == 0 and "1 more not fetched" in out and "first 2" in out
    assert seen["source"] == "csaf" and seen["hosts"] == frozenset({CSAF_HOST})
    code, out, _ = run(capsys, *args)
    assert code == 0 and "fetched 1" in out and "more not fetched" not in out
    code, out, _ = run(capsys, *args)
    assert code == 0 and "fetched 0" in out and "up to date 3" in out
    code, out, _ = run(capsys, "history", "--store", db, "--source", "csaf")
    assert code == 0 and "csaf id=EX-2026-" in out and f"provider={CSAF_META_URL}" in out
    code, out, _ = run(capsys, "history", "--store", db, "--source", "csaf", "--json")
    rows = json.loads(out)
    assert rows[0]["provenance"]["tracking"]["version"] == "1" and len(rows) == 3
    code, out, _ = run(capsys, "candidates", "--store", db)
    assert code == 0 and "3 candidate advisories" in out


def test_cli_exit_1_on_a_rejection_and_the_off_host_directory_is_exit_2(capsys, db, wired):
    wired(provider({"2026/bad.json": T1}, {"2026/bad.json": b"not json"}))
    base = ["refresh", "--source", "csaf", "--store", db, "--live", "--allow-host", CSAF_HOST,
            "--provider-metadata-url", CSAF_META_URL]
    code, out, _ = run(capsys, *base)
    assert code == 1 and "rejected 1" in out
    wired(provider({}, {}, meta=provider_metadata("https://elsewhere.invalid/x")))
    code, _, err = run(capsys, *base)
    assert code == 2 and "no usable directory_url" in err


def test_cli_direct_url_mode_and_secrets_never_appear(capsys, db, wired, monkeypatch):
    monkeypatch.setenv("MY_KEY", SECRET)
    t = ContractFixtureTransport({url("2026/a.json"): (200, dump(D101))})
    wired(t)
    base = ["refresh", "--source", "csaf", "--store", db, "--live", "--allow-host", CSAF_HOST]
    code, out, err = run(capsys, *base, "--url", url("2026/a.json"))
    assert code == 0 and "first" in out
    code, out, err = run(capsys, *base, "--url", url("2026/a.json"), "--api-key-env", "MY_KEY")
    assert code == 2 and SECRET not in out + err
    code, out, err = run(capsys, *base, "--url", url(f"2026/a.json?token={SECRET}"))
    assert code == 2 and SECRET not in out + err
    assert all(SECRET not in c[0] and "apiKey" not in c[1] for c in t.calls)
    assert SECRET.encode() not in open(db, "rb").read()


def test_allow_host_is_rejected_for_the_fixed_sources(capsys, db, wired):
    wired(ContractFixtureTransport({}))
    code, _, err = run(capsys, "refresh", "--source", "kev", "--store", db, "--live",
                       "--allow-host", "www.cisa.gov")
    assert code == 2 and "csaf only" in err
