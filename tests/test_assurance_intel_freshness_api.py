"""The hosted intel routes always say how old the shared store is; a stale store is not an all-clear.

The offline Watch judges the age of every advisory source against a limit (72 h unless the
subscription states one). The hosted ``/v1/intel/*`` routes read the same kind of store and used
to say nothing about its age, so a refresh job that had silently stopped served last month's
candidates as if they were current. Every answer now carries ``store_freshness``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from assurance.api.intel_routes import INTEL_MAX_AGE_ENV, INTEL_STORE_ENV, store_freshness
from assurance.intel.fetch import ingest_bytes
from assurance.intel.sources import SOURCES, nvd_url
from assurance.intel.store import IntelStore

from . import interfaces_fixtures as fx
from .intel_support import dump, epss_doc, kev_doc
from .test_assurance_watch_intel import CVE, _nvd

live_api = fx.live_api

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def _put(store, source, doc, at, url=None):
    raw = doc if isinstance(doc, bytes) else dump(doc)
    return ingest_bytes(store, source, raw, url=url or SOURCES[source].url, locator="t",
                        via="file", http_status=None, retrieved_at=at)


def _store(path, *, nvd_age=1.0, kev_age=1.0, epss_age=1.0):
    store = IntelStore(path)
    if nvd_age is not None:
        _put(store, "nvd_cve_api", _nvd(), NOW - timedelta(hours=nvd_age), nvd_url(CVE))
    if kev_age is not None:
        _put(store, "cisa_kev", kev_doc(CVE), NOW - timedelta(hours=kev_age))
    if epss_age is not None:
        _put(store, "first_epss", epss_doc((CVE, "0.1", "0.2", "2026-11-06")),
             NOW - timedelta(hours=epss_age))
    return store


def _states(freshness):
    return {r["source"]: r["state"] for r in freshness["sources"]}


class TestTheJudgement:
    def test_fresh_sources_are_fresh_and_the_limit_is_the_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv(INTEL_MAX_AGE_ENV, raising=False)
        f = store_freshness(_store(tmp_path / "i.db"), NOW)
        assert f["checked"] is True and f["status"] == "fresh"
        assert f["limit_hours"] == 72.0 and f["limit_basis"] == "default"
        assert _states(f) == {"cisa_kev": "fresh", "csaf": "never_observed",
                              "first_epss": "fresh", "nvd_cve_api": "fresh"}

    def test_one_old_source_makes_the_store_stale_not_fresh(self, tmp_path, monkeypatch):
        monkeypatch.delenv(INTEL_MAX_AGE_ENV, raising=False)
        f = store_freshness(_store(tmp_path / "i.db", kev_age=100.0), NOW)
        assert f["status"] == "stale" and _states(f)["cisa_kev"] == "stale"
        assert f["sources"][0]["age_hours"] is not None

    def test_the_edge_of_the_limit(self, tmp_path, monkeypatch):
        monkeypatch.delenv(INTEL_MAX_AGE_ENV, raising=False)
        assert store_freshness(_store(tmp_path / "a.db", nvd_age=72.0), NOW)["status"] == "fresh"
        assert store_freshness(_store(tmp_path / "b.db", nvd_age=72.01), NOW)["status"] == "stale"

    def test_nothing_accepted_is_unknown_never_fresh(self, tmp_path):
        store = IntelStore(tmp_path / "empty.db")
        f = store_freshness(store, NOW)
        assert f["status"] == "unknown" and set(_states(f).values()) == {"never_observed"}

    def test_the_operators_limit_is_recorded_as_a_server_setting(self, tmp_path, monkeypatch):
        monkeypatch.setenv(INTEL_MAX_AGE_ENV, "200")
        f = store_freshness(_store(tmp_path / "i.db", nvd_age=150.0), NOW)
        assert f["status"] == "fresh" and f["limit_hours"] == 200.0
        assert f["limit_basis"] == "server_setting"

    @pytest.mark.parametrize("bad", ["0", "-5", "nan", "inf", "soon", "1e9"])
    def test_a_malformed_setting_falls_back_to_the_default_and_says_so(
            self, tmp_path, monkeypatch, bad):
        monkeypatch.setenv(INTEL_MAX_AGE_ENV, bad)
        f = store_freshness(_store(tmp_path / "i.db", nvd_age=100.0), NOW)
        assert f["limit_hours"] == 72.0 and "not a valid limit" in f["limit_basis"]
        assert f["status"] == "stale"          # never silently unchecked

    def test_a_retrieval_after_the_clock_cannot_establish_an_age(self, tmp_path):
        store = _store(tmp_path / "i.db", nvd_age=-5.0)
        f = store_freshness(store, NOW)
        assert _states(f)["nvd_cve_api"] == "future" and f["status"] == "stale"


class TestOverHttp:
    @pytest.fixture
    def served(self, live_api, tmp_path, monkeypatch):
        monkeypatch.setenv(INTEL_STORE_ENV, str(tmp_path / "intel.db"))
        monkeypatch.delenv(INTEL_MAX_AGE_ENV, raising=False)
        _, headers = live_api.account("intel-fresh@example.de")
        return live_api, headers, tmp_path / "intel.db"

    def test_every_read_route_carries_store_freshness(self, served):
        api, headers, path = served
        old = datetime.now(UTC) - timedelta(hours=500)
        store = IntelStore(path)
        _put(store, "nvd_cve_api", _nvd(), old, nvd_url(CVE))
        _put(store, "cisa_kev", kev_doc(CVE), old)
        with api.client() as http:
            for url in ("/v1/intel/history", f"/v1/intel/cve/{CVE}", "/v1/intel/candidates"):
                r = http.get(url, headers=headers)
                assert r.status_code == 200, (url, r.text)
                fresh = r.json()["store_freshness"]
                assert fresh["checked"] is True and fresh["status"] == "stale", url
                assert fresh["limit_hours"] == 72.0
            # and the observation route (one row) is a single record, not a judgement of the store
            assert "store_freshness" not in http.get(
                "/v1/intel/observations/1", headers=headers).json()
