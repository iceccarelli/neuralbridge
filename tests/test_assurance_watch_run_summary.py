"""Findings of the local watch run are not lost on the way to the hosted ledger."""

from __future__ import annotations

from assurance.api.watch_routes import WatchReportIn
from assurance.watch.push import run_summary

RUN = {
    "finished_at": "2026-10-20T06:00:01Z",
    "stale_observations": ["Acme/AR-7#0412: last seen 2026-09-01"],
    "outcomes": [{"serial": "0412", "case_id": "case-aaa"}],
    "advisories": {
        "feeds": [{"supplier_id": "ControlCo", "status": "untrusted", "trust_basis": "none",
                   "problems": ["x" * 5000]}],
        "findings": [{
            "advisory_id": "CTRL-2026-11", "supplier_id": "ControlCo", "severity": "stop_use",
            "state": "new", "impact": "affected", "machines": ["Acme/AR-7#0412"],
            "functions_in_question": ["SF-01"], "trust_basis": "none",
            "trust_state": "untrusted_unknown_key", "inspect_only": True,
            "case_id": "", "title": "must not be forwarded wholesale",
        }]},
    "filings": {"enabled": True, "prompts": [{
        "advisory_id": "CTRL-2026-11", "state": "unassessed", "escalating": True,
        "received_at": "2026-10-19T05:00:00Z",
        "draft": {"awareness_at": "2026-10-19T05:00:00Z", "classification": "x"}}]},
    "checks_skipped": ["a limit"],
}


def test_the_summary_keeps_trust_state_and_case_references():
    s = run_summary(RUN)
    f = s["advisory_findings"][0]
    assert f["trust_state"] == "untrusted_unknown_key" and f["inspect_only"] is True
    assert "title" not in f
    assert s["local_case_ids"] == ["case-aaa"] and s["stale_observations"]
    assert s["checks_skipped"] == ["a limit"]


def test_no_article_14_awareness_time_classification_or_draft_leaves_the_plant():
    s = run_summary(RUN)
    blob = str(s)
    assert "awareness" not in blob and "draft" not in blob and "classification" not in blob
    assert "received_at" not in blob
    assert s["filings_prompts"] == [
        {"advisory_id": "CTRL-2026-11", "state": "unassessed", "escalating": True}]


def test_the_summary_is_accepted_by_the_hosted_model_and_nothing_extra_is():
    s = run_summary(RUN)
    body = {"watch_id": "w", "run_started_at": "2026-10-20T06:00:00Z", "run_summary": s,
            "machines": [{"serial": "1", "status": "uncollectable",
                          "observed_at": "2026-10-20T06:00:00Z", "collection_complete": False}]}
    assert WatchReportIn(**body).run_summary is not None
    body["run_summary"] = {**s, "awareness_at": "2026-10-19T05:00:00Z"}
    try:
        WatchReportIn(**body)
    except Exception as exc:  # noqa: BLE001
        assert "awareness_at" in str(exc)
    else:
        raise AssertionError("an unknown field in the summary was accepted")
