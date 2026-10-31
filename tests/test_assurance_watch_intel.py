"""A recorded public-intel store as an advisory source for the watch.

Payloads: the minimized / SYNTHETIC contract fixtures under ``tests/fixtures/intel``. They
prove how the watch handles data of that shape; they are not live integration, and nothing
here fetches (the store is filled by ``ingest_bytes`` from local bytes).

What is pinned: an exposure is a finding for a person, never a consequence; enrichment is
context that cannot move the verdict; a seen observation is not re-announced and a changed
one is an update; every way the store can be unusable is DEGRADED, never quiet; and the
watch itself imports no network client.
"""

from __future__ import annotations

import ast
import json
import sqlite3
from pathlib import Path

import pytest

from assurance.change.service import (
    UntrustedAdvisoryError,
    assess_advisory,
)
from assurance.change.store import CaseStore
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.intel.fetch import ingest_bytes
from assurance.intel.sources import SOURCES, nvd_url
from assurance.intel.store import IntelStore
from assurance.watch.config import IntelSubscription, WatchConfig, WatchError
from assurance.watch.intel_source import check_intel, impact_for_case
from assurance.watch.runner import run_watch

from .intel_support import Clock, dump, epss_doc, fixture_json, kev_doc
from .support import plan_dict, write_export

CVE = "CVE-2026-0001"
SRC = Path(__file__).resolve().parents[1] / "src" / "assurance" / "watch"
CLOCK = Clock()


def _put(store: IntelStore, source: str, doc: object, *, url: str | None = None):
    raw = doc if isinstance(doc, bytes) else dump(doc)
    return ingest_bytes(store, source, raw, url=url or SOURCES[source].url, locator="t",
                        via="file", http_status=None, retrieved_at=CLOCK())


def _nvd(modified: str = "2026-10-03T00:00:00.000") -> dict:
    doc = fixture_json("nvd_synthetic.json")
    doc["vulnerabilities"][0]["cve"]["lastModified"] = modified
    return doc


def _fill(store: IntelStore, *, epss: bool = True, kev: bool = True,
          nvd_modified: str = "2026-10-03T00:00:00.000") -> None:
    _put(store, "nvd_cve_api", _nvd(nvd_modified), url=nvd_url(CVE))
    if kev:
        _put(store, "cisa_kev", kev_doc(CVE))
    if epss:
        _put(store, "first_epss", epss_doc((CVE, "0.00043", "0.09", "2026-10-31")))


def _plant(tmp_path, *, create_store=True, supplier="example_controls", name="ex-100_firmware",
           version="v2.001", sources=("nvd", "kev", "epss"), article_14=None):
    """Two enrolled machines whose manifest names the strings the NVD fixture uses."""
    plan = plan_dict()
    plan["items"][1]["supplier"], plan["items"][1]["name"] = supplier, name
    (tmp_path / "plans").mkdir()
    (tmp_path / "plans" / "cell.json").write_text(json.dumps(plan))
    for n, serial in enumerate(("CELL-0412", "CELL-0501")):
        root = write_export(tmp_path / "exports" / serial, stamp="2026-09-14T06:02:11Z",
                            operator="ci", seq=f"004{n}")
        (root / "robot-params.json").write_text(json.dumps({
            "export": {"timestamp": "2026-09-14T06:02:11Z", "operator": "ci"},
            "safety": {"max_tcp_speed_mm_s": 400, "stop_category": 1},
            "firmware": {"version": version}}), encoding="utf-8")
    store = IntelStore(tmp_path / "intel.db") if create_store else None
    config = {
        "watch_id": "plant-1", "organisation": "Grimaldi Engineering S.r.l.",
        "targets": [{"serial": s, "plan": "plans/cell.json", "root": f"exports/{s}",
                     "site": "Plant 1", "country": "IT", "read_from_machine": True}
                    for s in ("CELL-0412", "CELL-0501")],
        "intel": [{"kind": "intel_store", "store": "intel.db", "sources": list(sources)}],
    }
    if article_14:
        config["article_14"] = article_14
    (tmp_path / "watch.json").write_text(json.dumps(config))
    return {"dir": tmp_path, "store": store, "ledger": EvidenceLedger(tmp_path / "ev.db")}


@pytest.fixture()
def plant(tmp_path):
    p = _plant(tmp_path)
    _fill(p["store"])
    return p


def _run(p, **kw):
    return run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"], **kw)


def _person() -> Actor:
    return Actor(identifier="Dana Reviewer", role="safety engineer", kind="person")


# =====================================================================
class TestConfig:
    def test_it_resolves_against_the_config_and_round_trips(self, plant):
        c = WatchConfig.from_json(plant["dir"] / "watch.json")
        assert c.intel[0].store == str(plant["dir"] / "intel.db")
        assert WatchConfig.from_dict(c.to_dict()).intel[0].sources == c.intel[0].sources

    def test_an_existing_watch_keeps_its_hash(self, plant):
        body = json.loads((plant["dir"] / "watch.json").read_text())
        body.pop("intel")
        with_none = WatchConfig.from_dict(body)
        assert "intel" not in with_none.to_dict()
        assert WatchConfig.from_json(plant["dir"] / "watch.json").content_hash() \
            != with_none.content_hash()

    @pytest.mark.parametrize("sources, match", [
        (("kev", "epss"), "at least one of 'nvd' or 'csaf'"),
        (("nvd", "nvd"), "twice"),
        (("nvd", "shodan"), "unknown intel source"),
    ])
    def test_bad_source_lists_are_refused(self, sources, match):
        with pytest.raises(WatchError, match=match):
            IntelSubscription(store="i.db", sources=sources)

    def test_an_unknown_kind_is_refused(self):
        with pytest.raises(WatchError, match="kind"):
            IntelSubscription.from_dict({"kind": "rss", "store": "x"})


# =====================================================================
class TestAnExposureIsAFindingForAPerson:
    def test_it_is_a_finding_with_no_consequence(self, plant):
        run = _run(plant)
        assert run.verdict == "findings"
        adv = run.advisories
        f = next(x for x in adv.findings if x.advisory_id == f"nvd:{CVE}")
        assert (f.state, f.inspect_only) == ("new", True)
        assert (f.trust_basis, f.trust_state) == ("none", "unauthenticated_public_source")
        assert f.machines == () and f.report is None and f.case_id == ""
        assert set(f.inspect_machines) == {"Grimaldi/AR-7#CELL-0412", "Grimaldi/AR-7#CELL-0501"}
        assert not f.stops_use and adv.stop_use == ()
        assert "NOT TRUSTED" in adv.summary()

    def test_it_opens_no_case_and_drafts_no_intake_even_for_a_manufacturer(self, tmp_path):
        p = _plant(tmp_path, article_14={"as_manufacturer": True, "received_by": "QA desk"})
        _fill(p["store"])
        run = _run(p)
        assert run.advisories.new
        assert not [f for f in run.advisories.findings if f.case_id]
        assert CaseStore(p["ledger"]).ledger.entries(kind="change.case") == []
        assert not run.filings.prompts

    def test_a_case_from_it_needs_a_named_person(self, plant):
        _run(plant)                                 # seals the manifests the fleet is read from
        sub = WatchConfig.from_json(plant["dir"] / "watch.json").intel[0]
        report = impact_for_case(sub, f"nvd:{CVE}", Fleet.from_ledger(plant["ledger"]))
        assert report.provenance["inspect_only"] is True
        assert report.provenance["trust_basis"] == "none"
        store = CaseStore(plant["ledger"])
        for actor in (Actor("assurance-watch", kind="automation"),
                      Actor("api", kind="service")):
            with pytest.raises(AssuranceError, match="person"):
                assess_advisory(store, report, actor=actor)
        case = assess_advisory(store, report, actor=_person())
        assert case is not None
        assert case.provenance["advisory_trust"] == "unauthenticated_public_source"
        assert case.provenance["advisory_accepted_by"] == "Dana Reviewer"

    def test_a_csaf_candidate_needs_the_unsigned_import_override_and_a_reason(self, tmp_path):
        p = _plant(tmp_path, supplier="Example Controls GmbH", name="EX-100",
                   version="V2.001", sources=("csaf",))
        _put(p["store"], "csaf", fixture_json("csaf_synthetic.json"), url="file:csaf.json")
        _run(p)
        run = _run(p, seal=False)
        f = next(x for x in run.advisories.findings if x.inspect_only)
        assert f.impact != "clear" and f.machines == () and f.state == "outstanding"
        assert f.trust_basis == "none"
        sub = WatchConfig.from_json(p["dir"] / "watch.json").intel[0]
        report = impact_for_case(sub, f.advisory_id, Fleet.from_ledger(p["ledger"]))
        store = CaseStore(p["ledger"])
        with pytest.raises(UntrustedAdvisoryError, match="unsigned"):
            assess_advisory(store, report, actor=_person())
        with pytest.raises(UntrustedAdvisoryError, match="reason"):
            assess_advisory(store, report, actor=_person(), accept_unsigned=True)
        assert assess_advisory(store, report, actor=_person(), accept_unsigned=True,
                               reason="read against the vendor page") is not None


# =====================================================================
class TestEnrichmentIsContextOnly:
    def _finding(self, run):
        return next(x for x in run.advisories.findings if x.advisory_id == f"nvd:{CVE}")

    def test_kev_and_epss_are_attached_with_citations(self, plant):
        f = self._finding(_run(plant))
        e = f.intel["enrichment"][0]
        assert e["kev"]["status"] == "listed" and e["kev"]["citation"]["sha256"]
        assert e["epss"]["status"] == "available" and e["epss"]["score"] == 0.00043
        assert e["nvd"]["status"] == "present"
        assert "did not change" in f.intel["enrichment_note"]
        assert f.to_dict()["intel"]["citation"]["source"] == "nvd_cve_api"

    def test_epss_absent_is_unavailable_not_zero(self, tmp_path):
        p = _plant(tmp_path)
        _fill(p["store"], epss=False)
        e = self._finding(_run(p)).intel["enrichment"][0]
        assert e["epss"]["status"] == "unavailable" and e["epss"]["score"] is None

    def test_kev_not_listed_carries_the_not_established_note(self, tmp_path):
        p = _plant(tmp_path)
        _fill(p["store"], kev=False)
        _put(p["store"], "cisa_kev", kev_doc("CVE-2026-9999"))
        run = _run(p)
        e = self._finding(run).intel["enrichment"][0]
        assert e["kev"]["status"] == "not_listed_in_kev"
        assert "does not establish" in e["kev"]["not_established"]
        assert any("does not establish" in c for c in run.checks_skipped)

    def test_enrichment_cannot_change_the_match_or_the_verdict(self, tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir(), b.mkdir()
        loud, quiet = _plant(a), _plant(b)
        _fill(loud["store"])                       # KEV-listed, EPSS present
        _fill(quiet["store"], kev=False, epss=False)
        fl, fq = (self._finding(_run(x)) for x in (loud, quiet))
        assert (fl.impact, fl.inspect_machines, fl.severity, fl.state) == \
               (fq.impact, fq.inspect_machines, fq.severity, fq.state)
        assert fl.severity == "safety_relevant"    # no severity derived from KEV/EPSS

    def test_a_source_the_watch_was_not_told_to_read_is_not_claimed(self, tmp_path):
        p = _plant(tmp_path, sources=("nvd",))
        _fill(p["store"])
        run = _run(p)
        e = self._finding(run).intel["enrichment"][0]
        assert e["kev"]["status"] == "unchecked" and e["epss"]["status"] == "unavailable"
        assert run.verdict == "findings"


# =====================================================================
class TestNoMatchIsClearButSaysWhatWasNotEstablished:
    def test_clear_is_counted_and_the_limits_are_stated(self, tmp_path):
        p = _plant(tmp_path, version="v9.999")
        _fill(p["store"])
        _run(p)                                     # first look at the machines
        run = _run(p)
        assert run.verdict == "quiet"
        assert run.advisories.findings == ()
        out = run.advisories.feeds[0]
        assert out.status == "verified" and out.cleared >= 1
        text = " ".join(run.checks_skipped)
        assert "not that the fleet is unaffected" in text
        assert "bounded version range is not matched" in text
        assert "unauthenticated" in text and "intel refresh --live" in text

    def test_an_empty_fleet_clears_nothing(self, plant):
        sub = WatchConfig.from_json(plant["dir"] / "watch.json").intel[0]
        empty = Fleet.from_ledger(EvidenceLedger(plant["dir"] / "empty.db"))
        result = check_intel([sub], empty)
        assert [f.state for f in result.findings] == ["not_assessed"]
        assert result.findings[0].impact == "not_assessed"
        assert result.feeds[0].cleared == 0 and result.feeds[0].not_assessed
        assert not result.new and "NOT ASSESSED" in result.summary()

    def test_a_not_assessed_advisory_is_assessed_as_new_once_a_fleet_exists(self, plant):
        sub = WatchConfig.from_json(plant["dir"] / "watch.json").intel[0]
        empty = Fleet.from_ledger(EvidenceLedger(plant["dir"] / "empty.db"))
        seen = {f.advisory_id: f.state for f in check_intel([sub], empty).findings}
        run = _run(plant)
        assert seen == {f"nvd:{CVE}": "not_assessed"}
        assert run.advisories.new


# =====================================================================
class TestSeenAndChanged:
    def test_the_same_observation_is_not_announced_twice(self, plant):
        first = _run(plant)
        assert first.advisories.new and first.verdict == "findings"
        # a refresh that learned nothing: byte-identical re-observation
        _fill(plant["store"])
        second = _run(plant)
        assert second.advisories.new == () and second.advisories.updated == ()
        assert [f.state for f in second.advisories.findings] == ["outstanding"]
        assert second.verdict == "quiet"

    def test_a_changed_observation_is_an_update(self, plant):
        _run(plant)
        _fill(plant["store"], nvd_modified="2026-10-20T00:00:00.000")
        run = _run(plant)
        f = run.advisories.findings[0]
        assert f.state == "updated" and run.advisories.updated == (f,)
        assert run.verdict == "findings"
        assert "updated" in run.advisories.summary()
        again = _run(plant)                       # and the update is announced once
        assert again.advisories.updated == () and again.verdict == "quiet"


# =====================================================================
class TestAnUnusableStoreIsNeverQuiet:
    def _only(self, run):
        assert run.verdict == "degraded"
        (out,) = run.advisories.feeds
        return out

    def test_missing_store(self, tmp_path):
        p = _plant(tmp_path, create_store=False)
        out = self._only(_run(p))
        assert out.status == "absent" and "blind" in out.detail

    def test_missing_store_is_not_created_by_the_watch(self, tmp_path):
        p = _plant(tmp_path, create_store=False)
        _run(p)
        assert not (tmp_path / "intel.db").exists()

    def test_zero_byte_file_is_empty_and_is_left_untouched(self, tmp_path):
        p = _plant(tmp_path, create_store=False)
        (tmp_path / "intel.db").write_bytes(b"")
        assert self._only(_run(p)).status == "empty"
        assert (tmp_path / "intel.db").stat().st_size == 0

    def test_an_initialised_store_with_no_observations(self, tmp_path):
        p = _plant(tmp_path)
        assert self._only(_run(p)).status == "empty"

    def test_not_an_intel_store(self, tmp_path):
        p = _plant(tmp_path, create_store=False)
        (tmp_path / "intel.db").write_text("not a database at all")
        assert self._only(_run(p)).status == "unreadable"
        other = tmp_path / "other.db"
        with sqlite3.connect(other) as db:
            db.execute("create table t (x)")
        body = json.loads((tmp_path / "watch.json").read_text())
        body["intel"][0]["store"] = "other.db"
        (tmp_path / "watch.json").write_text(json.dumps(body))
        assert self._only(_run(p)).status == "unreadable"

    def test_a_rejected_latest_observation_degrades_even_with_older_data(self, plant):
        _run(plant)
        bad = _put(plant["store"], "nvd_cve_api", b"{ not json", url=nvd_url(CVE))
        assert bad.disposition == "rejected"
        run = _run(plant)
        out = self._only(run)
        assert out.status == "rejected_latest"
        assert any("REJECTED" in x for x in out.problems)
        assert "DEGRADED" in run.summary()

    def test_a_payload_that_can_no_longer_be_read_degrades(self, plant):
        with sqlite3.connect(plant["dir"] / "intel.db") as db:     # simulate bit-rot
            db.execute("DROP TRIGGER blobs_no_update")
            db.execute("UPDATE blobs SET body = ? WHERE sha256 = ?",
                       (b"{ rotted", plant["store"].observations(source="nvd_cve_api")[0].sha256))
        out = self._only(_run(plant))
        assert out.status == "unreadable"
        assert any("could not be re-read" in x for x in out.problems)

    def test_a_named_source_with_no_observation_degrades(self, tmp_path):
        p = _plant(tmp_path)
        _fill(p["store"], kev=False)                # watch reads kev, store has none
        out = self._only(_run(p))
        assert out.status == "incomplete"
        assert any("'kev'" in x for x in out.problems)

    def test_the_exit_code_is_the_existing_degraded_two(self, plant):
        from assurance.watch.cli import main

        (plant["dir"] / "intel.db").unlink()
        for ext in ("-wal", "-shm"):
            Path(str(plant["dir"] / "intel.db") + ext).unlink(missing_ok=True)
        code = main(["run", str(plant["dir"] / "watch.json"),
                     "--ledger", str(plant["dir"] / "cli.db"), "--dry-run"])
        assert code == 2


# =====================================================================
class TestTheWatchStaysOffline:
    def test_no_watch_module_that_reads_the_store_imports_a_network_client(self):
        roots = {"httpx", "requests", "urllib3", "aiohttp", "http", "urllib", "socket",
                 "ssl", "smtplib", "ftplib", "stripe", "websockets"}
        for name in ("intel_source.py", "config.py", "advisories.py", "runner.py"):
            tree = ast.parse((SRC / name).read_text())
            for node in ast.walk(tree):
                mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                        else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
                for m in mods:
                    assert m.split(".")[0] not in roots, f"{name} imports {m}"
                    assert "transport" not in m and not m.endswith("intel.fetch"), \
                        f"{name} imports {m}"

    def test_a_run_opens_no_socket(self, plant, monkeypatch):
        import socket

        def refuse(*a, **k):
            raise AssertionError("the watch opened a socket")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        assert _run(plant).advisories.new

    def test_a_run_appends_nothing_to_the_store(self, plant):
        before = len(plant["store"].observations())
        _run(plant)
        assert len(plant["store"].observations()) == before
