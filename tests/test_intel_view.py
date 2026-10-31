"""What the observations mean downstream. Payloads: SYNTHETIC or minimized contract fixtures."""

from __future__ import annotations

import pytest

from assurance.fleet.advisory import MatchBasis, match_item
from assurance.intel.fetch import ingest_bytes, ingest_file
from assurance.intel.sources import SOURCES
from assurance.intel.store import IntelStore
from assurance.intel.view import build_report
from assurance.machinery.manifest import HashSource, ItemKind, SafetyItem

from .intel_support import (
    FIXTURES,
    Clock,
    dump,
    epss_doc,
    fixture_json,
    kev_doc,
    nvd_doc,
)


@pytest.fixture
def store(tmp_path):
    return IntelStore(tmp_path / "i.db")


def put(store, source, doc):
    return ingest_bytes(store, source, dump(doc), url=SOURCES[source].url, locator="t",
                        via="file", http_status=None, retrieved_at=Clock()())


def enrich(store, cve):
    return next(e for e in build_report(store, cve_ids=[cve]).enrichments if e.cve_id == cve)


def test_absent_epss_is_unavailable_never_zero(store):
    put(store, "first_epss", epss_doc(("CVE-2026-0001", "0.5", "0.9", "2026-10-31")))
    e = enrich(store, "CVE-1900-0000")
    assert e.epss["status"] == "unavailable" and e.epss["score"] is None
    assert "0.0" in e.epss["note"] and "not a score of 0.0" in e.epss["note"]
    assert 0.0 not in [v for v in e.epss.values() if isinstance(v, float)]


def test_no_epss_observation_at_all_is_also_unavailable(store):
    assert enrich(store, "CVE-2026-0001").epss["status"] == "unavailable"


def test_epss_value_carries_its_score_date_and_citation(store):
    put(store, "first_epss", epss_doc(("CVE-2026-0001", "0.00043", "0.09", "2026-10-31")))
    e = enrich(store, "CVE-2026-0001").epss
    assert (e["status"], e["score"], e["score_date"]) == ("available", 0.00043, "2026-10-31")
    assert "time-sensitive" in e["note"] and len(e["citation"]["sha256"]) == 64
    assert e["citation"]["url"] == SOURCES["first_epss"].url


def test_kev_absent_is_not_listed_and_explicitly_not_not_exploited(store):
    put(store, "cisa_kev", kev_doc("CVE-2026-0002"))
    e = enrich(store, "CVE-2026-0001").kev
    assert e["status"] == "not_listed_in_kev"
    assert "does not establish" in e["not_established"] and "not exploited" in e["not_established"]
    assert e["status"] not in ("not_exploited", "safe", "clear")
    assert enrich(store, "CVE-2026-0002").kev["status"] == "listed"


def test_kev_with_no_catalogue_recorded_is_unchecked_not_not_listed(store):
    assert enrich(store, "CVE-2026-0001").kev["status"] == "unchecked"


def test_missing_nvd_record_is_unknown(store):
    put(store, "nvd_cve_api", nvd_doc())
    assert enrich(store, "CVE-2026-0001").nvd["status"] == "unknown"


def test_kev_never_yields_an_advisory_only_enrichment(store):
    put(store, "cisa_kev", kev_doc("CVE-2026-0001"))
    report = build_report(store)
    assert report.candidates == () and report.enrichments[0].kev["status"] == "listed"


def test_exact_cpe_versions_become_a_candidate_and_ranges_never_become_versions(store):
    ingest_file(store, "nvd_cve_api", FIXTURES / "nvd_synthetic.json")
    report = build_report(store)
    (cand,) = report.candidates
    adv = cand.advisory
    assert adv.advisory_id == "nvd:CVE-2026-0001" and cand.trust == "unsigned_public_feed"
    names = {a.name: a for a in adv.affected}
    assert names["ex-100_firmware"].versions == ("v2.001", "v2.002")
    assert "ex-50_firmware" not in names                       # range only: no artefact
    assert any("versionEndExcluding=V1.009" in u for u in cand.not_representable)
    assert adv.fixed_versions == () and adv.import_record is None
    assert adv.severity.value == "safety_relevant"             # defaulted, not derived from CVSS
    assert any("defaulted" in n for n in cand.notes)


def test_a_range_on_the_same_component_rides_in_version_note_not_in_versions(store):
    doc = nvd_doc({
        "id": "CVE-2026-0007", "published": "2026-10-01T00:00:00.000",
        "lastModified": "2026-10-02T00:00:00.000", "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "SYNTHETIC"}],
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:plc:1.0:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:plc:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "3.9"}]}]}]})
    put(store, "nvd_cve_api", doc)
    art = build_report(store).candidates[0].advisory.affected[0]
    assert art.versions == ("1.0",) and "versionEndExcluding=3.9" in art.version_note


def test_a_candidate_matches_by_label_equality_only(store):
    ingest_file(store, "nvd_cve_api", FIXTURES / "nvd_synthetic.json")
    adv = build_report(store).candidates[0].advisory

    def item(version):
        return SafetyItem("I", ItemKind.FIRMWARE, "ex-100_firmware", version, "",
                          HashSource.DECLARED, supplier="example_controls",
                          implements=("SF-1",))

    assert match_item(adv, item("V2.001"))[0] is MatchBasis.VERSION
    other = match_item(adv, item("V2.0015"))                     # no arithmetic, no prefix
    assert other is None or other[0] is MatchBasis.NAME_ONLY


def test_rejected_and_awaiting_records_yield_no_candidate(store):
    base = {"published": "2026-10-01T00:00:00.000", "lastModified": "2026-10-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "x"}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:acme:plc:1.0:*:*:*:*:*:*:*"}]}]}]}
    put(store, "nvd_cve_api", nvd_doc({**base, "id": "CVE-2026-0011", "vulnStatus": "Rejected"},
                                      {**base, "id": "CVE-2026-0012", "vulnStatus": "Awaiting Analysis",
                                       "configurations": []}))
    report = build_report(store)
    assert report.candidates == ()
    assert enrich(store, "CVE-2026-0011").nvd["status"] == "rejected"


def test_cvss_is_annotated_not_turned_into_a_decision(store):
    ingest_file(store, "nvd_cve_api", FIXTURES / "nvd_min.json")     # minimized real record
    e = enrich(store, "CVE-2021-44228")
    assert e.cvss[0]["base_score"] == 10.0 and e.cvss[0]["version"] == "3.1"
    assert e.cvss[0]["citation"]["retrieved_at"].endswith("Z")
    assert e.not_representable                                    # a range: enrichment only
    assert build_report(store).candidates == ()


def test_csaf_is_the_existing_importer_unchanged(store):
    ingest_file(store, "csaf", FIXTURES / "csaf_synthetic.json")
    (cand,) = build_report(store).candidates
    assert cand.advisory.import_record.trust == "unsigned_inspect_only"
    assert cand.advisory.advisory_id == "EX-2026-001" and cand.source == "csaf"


def _conflicting(store, nvd_cpes):
    nvd = fixture_json("nvd_synthetic.json")
    cve = nvd["vulnerabilities"][0]["cve"]
    cve["configurations"] = [{"nodes": [{"operator": "OR", "cpeMatch": nvd_cpes}]}]
    put(store, "nvd_cve_api", nvd)
    ingest_file(store, "csaf", FIXTURES / "csaf_synthetic.json")
    return build_report(store)


def test_conflict_fixed_version_listed_as_affected_is_surfaced_with_both_citations(store):
    report = _conflicting(store, [
        {"vulnerable": True, "criteria": "cpe:2.3:o:example_controls:ex-100_firmware:V2.002:*:*:*:*:*:*:*"}])
    (c,) = [c for c in report.conflicts if c["kind"] == "fixed_listed_as_affected"]
    assert c["status"] == "conflict" and c["cve_id"] == "CVE-2026-0001"
    assert c["nvd"]["citation"]["source"] == "nvd_cve_api"
    assert c["csaf"]["citation"]["source"] == "csaf" and c["csaf"]["citation"]["record_id"] == "EX-2026-001"
    assert "none" in c["resolution"]
    assert enrich(store, "CVE-2026-0001").conflicts == (c,)
    assert len(report.candidates) == 2                         # nothing was dropped to resolve it


def test_conflict_nvd_boundary_differs_from_vendor_fixed(store):
    report = _conflicting(store, [
        {"vulnerable": True, "criteria": "cpe:2.3:o:example_controls:ex-100_firmware:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "V2.0015"}])
    (c,) = report.conflicts
    assert c["kind"] == "fixed_boundary_differs"
    assert "V2.0015" in c["nvd"]["says"] and "V2.002" in c["csaf"]["says"]
    assert c["component_link"] == "name_match"


def test_agreeing_boundary_is_not_a_conflict(store):
    report = _conflicting(store, [
        {"vulnerable": True, "criteria": "cpe:2.3:o:example_controls:ex-100_firmware:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "V2.002"}])
    assert report.conflicts == ()


def test_a_newer_series_for_the_same_cve_wins_and_older_stays_in_history(store):
    base = {"published": "2026-10-01T00:00:00.000", "lastModified": "2026-10-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "x"}], "vulnStatus": "Analyzed",
            "id": "CVE-2026-0021", "configurations": []}
    put(store, "nvd_cve_api", nvd_doc(base))
    put(store, "nvd_cve_api", nvd_doc({**base, "vulnStatus": "Modified"}))
    assert enrich(store, "CVE-2026-0021").nvd["vuln_status"] == "Modified"
    assert len(store.observations()) == 2
