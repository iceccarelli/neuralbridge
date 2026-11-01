"""``--allow-interim``: the operator option that admits CSAF documents whose tracking status is
``interim`` (found in a live smoke check: Siemens publishes ongoing advisories as interim).

Every response is a CONTRACT FIXTURE (in-memory transport, synthetic documents); no network is
opened. Pinned: the default is unchanged and counted; the option admits interim and ONLY interim;
the status survives verbatim into the observation, the provenance row, the candidate, the API
and a watch finding; a final revision supersedes and drops the note while history keeps both;
trust never changes; an old store reads on.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from assurance.cli import main as top
from assurance.intel import cli as intel_cli
from assurance.intel.csaf_live import refresh_documents, refresh_provider
from assurance.intel.fetch import ingest_bytes, ingest_file
from assurance.intel.parsers import INTERIM_REFUSAL, INTERIM_STATUS_NOTE, FeedRejected, parse_csaf
from assurance.intel.store import IntelStore
from assurance.intel.view import build_report
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from . import interfaces_fixtures as fx
from .intel_support import (
    CSAF_DIR,
    CSAF_HOST,
    CSAF_META_URL,
    Clock,
    ContractFixtureTransport,
    changes_csv,
    csaf_doc,
    csaf_doc_with_status,
    dump,
    provider_metadata,
)
from .test_assurance_intel_api import STORE_ENV, get
from .test_assurance_watch_intel import _plant

live_api = fx.live_api
HOSTS = [CSAF_HOST]
DOC_URL = f"{CSAF_DIR}/adv.json"
REASON = "tracking status is interim"
NOTE = "tracking status was interim when read; the vendor may revise it"


def one(doc: object) -> ContractFixtureTransport:
    return ContractFixtureTransport({DOC_URL: (200, dump(doc))})


def interim(rev: str = "1", **kw: str) -> dict:
    return csaf_doc_with_status("SYN-INTERIM-1", "interim", version=rev, **kw)


def fetch_one(store, doc, **kw):
    return refresh_documents(store, [DOC_URL], one(doc), allowed_hosts=HOSTS, clock=Clock(),
                             **kw).observations[0]


def listing(store, doc, *, allow_interim=False):
    t = ContractFixtureTransport({
        CSAF_META_URL: (200, dump(provider_metadata())),
        f"{CSAF_DIR}/changes.csv": (200, changes_csv(("adv.json", "2026-10-30T00:00:00Z"))),
        DOC_URL: (200, dump(doc))})
    return refresh_provider(store, CSAF_META_URL, t, allowed_hosts=HOSTS, clock=Clock(),
                            allow_interim=allow_interim)


@pytest.fixture
def store(tmp_path):
    return IntelStore(tmp_path / "intel.db")


# ------------------------------------------------------------------ default unchanged
def test_the_constants_are_the_stable_wording():
    assert INTERIM_STATUS_NOTE == NOTE
    assert INTERIM_REFUSAL == f"wrong_shape: {REASON}"


def test_default_refuses_interim_with_the_exact_reason(store):
    obs = fetch_one(store, interim())
    assert obs.disposition == "rejected" and obs.reason == f"wrong_shape: {REASON}"
    assert "allow_interim" not in store.provenance(obs.seq)
    assert not build_report(store).candidates


def test_default_summary_counts_the_refusals(tmp_path, capsys, monkeypatch):
    t = ContractFixtureTransport({
        CSAF_META_URL: (200, dump(provider_metadata())),
        f"{CSAF_DIR}/changes.csv": (200, changes_csv(("a.json", "2026-10-30T00:00:00Z"),
                                                     ("b.json", "2026-10-30T01:00:00Z"),
                                                     ("c.json", "2026-10-30T02:00:00Z"))),
        f"{CSAF_DIR}/a.json": (200, dump(csaf_doc_with_status("A", "interim"))),
        f"{CSAF_DIR}/b.json": (200, dump(csaf_doc_with_status("B", "interim"))),
        f"{CSAF_DIR}/c.json": (200, dump(csaf_doc("C"))),
    })
    monkeypatch.setattr(intel_cli, "_make_transport", lambda *a, **k: t)
    db = str(tmp_path / "cli.db")
    code = top(["intel", "refresh", "--source", "csaf", "--store", db, "--live", "--allow-host",
                CSAF_HOST, "--provider-metadata-url", CSAF_META_URL])
    out = capsys.readouterr().out
    hint = "2 interim document(s) refused; pass --allow-interim to import them as inspect-only"
    assert code == 1 and hint in out
    top(["intel", "history", "--store", db])
    assert hint in capsys.readouterr().out


def test_provider_refusal_is_not_settled_so_a_rerun_with_the_option_imports_it(store):
    first = listing(store, interim())
    assert first.interim_refused == 1
    again = listing(store, interim(), allow_interim=True)
    assert again.up_to_date == 0 and again.observations[0].disposition == "first"
    third = listing(store, interim(), allow_interim=True)      # imported documents do settle
    assert third.up_to_date == 1 and third.observations == []


def test_ingest_default_refuses_and_prints_the_hint(tmp_path, capsys):
    f = tmp_path / "i.json"
    f.write_bytes(dump(interim()))
    db = str(tmp_path / "x.db")
    code = top(["intel", "ingest", "--store", db, "--csaf", str(f)])
    assert code == 1
    assert "1 interim document(s) refused; pass --allow-interim" in capsys.readouterr().out
    code = top(["intel", "ingest", "--store", db, "--csaf", str(f), "--allow-interim"])
    assert code == 0
    assert IntelStore(db).observations()[-1].disposition == "first"


# ------------------------------------------------------------------ the option
def test_option_accepts_interim_and_records_it(store):
    obs = fetch_one(store, interim(), allow_interim=True)
    assert obs.disposition == "first" and obs.accepted
    prov = store.provenance(obs.seq)
    assert prov["allow_interim"] is True
    assert prov["tracking"]["status"] == "interim"          # verbatim


def test_candidate_carries_the_note_and_stays_inspect_only(store):
    fetch_one(store, interim(), allow_interim=True)
    [cand] = build_report(store).candidates
    assert cand.notes[0] == NOTE and cand.trust == "unsigned_inspect_only"
    record = cand.advisory.import_record
    assert record.partial and record.trust == "unsigned_inspect_only"
    assert record.tracking_status == "interim"


def test_ingest_file_with_the_option_is_recorded_in_provenance(store, tmp_path):
    f = tmp_path / "i.json"
    f.write_bytes(dump(interim()))
    obs = ingest_file(store, "csaf", f, allow_interim=True)
    assert obs.accepted and store.provenance(obs.seq)["allow_interim"] is True
    assert build_report(store).candidates[0].notes[0] == NOTE


def test_final_revision_supersedes_drops_the_note_and_history_keeps_both(store):
    first = fetch_one(store, interim("1"), allow_interim=True)
    final = fetch_one(store, csaf_doc("SYN-INTERIM-1", version="2"), allow_interim=True)
    assert final.disposition == "changed" and final.sha256 != first.sha256
    assert [o.disposition for o in store.observations()] == ["first", "changed"]
    assert store.provenance(first.seq)["tracking"]["status"] == "interim"
    assert store.provenance(final.seq)["tracking"]["status"] == "final"
    [cand] = build_report(store).candidates
    assert NOTE not in cand.notes


def test_a_final_document_needs_no_option(store):
    assert fetch_one(store, csaf_doc("FINAL-1")).accepted


def test_draft_stays_refused_with_the_option(store):
    obs = fetch_one(store, csaf_doc_with_status("SYN-D", "draft"), allow_interim=True)
    assert obs.disposition == "rejected" and obs.reason == "wrong_shape: tracking status is draft"
    assert store.provenance(obs.seq)["allow_interim"] is True    # the option was in force


def test_other_rejection_reasons_are_unaffected(store):
    bad = interim()
    bad["document"]["references"] = []                      # no reference URL
    obs = fetch_one(store, bad, allow_interim=True)
    assert obs.disposition == "rejected" and "reference" in obs.reason
    assert obs.reason != INTERIM_REFUSAL
    for raw in (b"{truncated", b"", dump({"document": {}})):
        with pytest.raises(FeedRejected):
            parse_csaf(raw, 10_000, allow_interim=True)
    missing = csaf_doc_with_status("SYN-S", "")             # missing status is not interim
    assert fetch_one(store, missing, allow_interim=True).disposition == "rejected"
    # without the option, a document that is bad for another reason is not counted as interim
    assert fetch_one(store, bad).reason != INTERIM_REFUSAL


def test_the_option_is_csaf_only(store):
    with pytest.raises(ValueError, match="csaf"):
        ingest_bytes(store, "cisa_kev", b"{}", url="u", locator="l", via="file",
                     http_status=None, allow_interim=True)


def test_cli_refuses_the_option_for_other_sources(tmp_path, capsys):
    code = top(["intel", "refresh", "--source", "kev", "--store", str(tmp_path / "k.db"),
                "--live", "--allow-interim"])
    assert code == 2 and "csaf only" in capsys.readouterr().err


def test_provenance_is_still_append_only(store):
    obs = fetch_one(store, interim(), allow_interim=True)
    with sqlite3.connect(store.path) as db, pytest.raises(sqlite3.DatabaseError,
                                                          match="append-only"):
        db.execute("UPDATE provenance SET meta_json='{}' WHERE seq=?", (obs.seq,))


def test_an_existing_store_without_the_field_still_reads(store):
    fetch_one(store, csaf_doc("OLD-1"))                      # recorded before the option
    reopened = IntelStore(store.path)                        # idempotent re-open
    assert "allow_interim" not in reopened.provenance(1)
    assert build_report(reopened).candidates[0].notes[0] != NOTE
    # no schema change: the flag is a key of the existing provenance meta_json
    with sqlite3.connect(store.path) as db:
        cols = [r[1] for r in db.execute("PRAGMA table_info(provenance)")]
    assert cols == ["seq", "provider", "listed_at", "settled", "meta_json"]


def test_a_missing_flag_makes_the_payload_unreadable_never_silently_trusted(store):
    obs = fetch_one(store, interim(), allow_interim=True)
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TRIGGER provenance_no_update")
        db.execute("UPDATE provenance SET meta_json='{}' WHERE seq=?", (obs.seq,))
    report = build_report(IntelStore(store.path))
    assert not report.candidates and list(report.unreadable) == [obs.seq]


# ------------------------------------------------------------------ the API and the watch
def test_api_candidates_carry_the_note(live_api, tmp_path, monkeypatch):
    path = tmp_path / "api.db"
    fetch_one(IntelStore(path), interim(), allow_interim=True)
    monkeypatch.setenv(STORE_ENV, str(path))
    _, headers = live_api.account("interim@example.de", tier="cell")
    r = get(live_api, headers, "/v1/intel/candidates")
    assert r.status_code == 200, r.text
    [cand] = r.json()["candidates"]
    assert NOTE in cand["notes"] and cand["trust"] == "unsigned_inspect_only"


def test_watch_finding_carries_the_note_and_no_consequence(tmp_path):
    p = _plant(tmp_path, supplier="Example Controls GmbH", name="EX-100", version="V2.001",
               sources=("csaf",))
    fetch_one(p["store"], interim(), allow_interim=True)
    run = run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
    f = next(x for x in run.advisories.findings if x.inspect_only)
    assert NOTE in json.dumps(f.to_dict())
    assert f.machines == () and f.report is None and f.case_id == "" and f.trust_basis == "none"
    assert not run.advisories.stop_use
