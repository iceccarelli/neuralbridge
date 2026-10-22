"""``assurance value``: a position derived from sealed records, never estimated."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

from assurance.change.model import CaseStatus
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.manifest import HashSource
from assurance.machinery.record import record_manifest
from assurance.value.cli import main as value_main
from assurance.value.position import assess_position, render_text

from .test_assurance_change import (
    LATER,
    drive,
    fw,
    manifest,
    seal_a_real_verification,
)
from .test_assurance_change import ledger as ledger  # noqa: F401  (fixture)
from .test_assurance_change import store as store  # noqa: F401  (fixture)

NOW = datetime(2026, 10, 22, tzinfo=UTC)


def kinds(result):
    return {f["kind"] for f in result["findings"]}


def test_an_empty_ledger_has_no_machines_and_says_what_was_not_assessed(ledger):
    r = assess_position(ledger, now=NOW)
    assert r["ledger"]["chain_verified"] and r["machines"] == []
    assert r["not_assessed"] and r["next_work"] == []


def test_a_machine_with_an_open_drift_case_owes_reverification_before_anything_else(
        ledger, store):
    drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
    r = assess_position(ledger, now=NOW)
    work = [w["work"] for w in r["next_work"]]
    assert "reverification_owed" in work
    assert work == sorted(work, key=lambda k: [x["kind"] for x in r["priority_rule"]].index(k))
    assert r["totals"]["open_cases"] == 1
    # every recommendation is labelled as one and says why
    assert all(w["kind"] == "recommendation" and w["because"] for w in r["next_work"])


def test_a_case_ready_to_close_owes_a_human_decision(ledger, store):
    drive(ledger, store, CaseStatus.READY_TO_CLOSE)
    r = assess_position(ledger, now=NOW)
    assert [w["work"] for w in r["next_work"]][0] == "decision_owed"


def test_declared_and_vendor_items_are_assumptions_not_facts(ledger):
    m = manifest(fw(hash_source=HashSource.SUPPLIED_BY_VENDOR), manifest_id="VENDOR")
    record_manifest(ledger, m)
    r = assess_position(ledger, now=NOW)
    assert "assumption" in kinds(r)
    assert r["machines"][0]["inventory"]["read_from_machine"] == 0
    assert r["totals"]["machines_with_inventory_fully_read_off_the_unit"] == 0


def test_never_verified_functions_and_unobserved_machines_are_unknown_never_green(ledger):
    record_manifest(ledger, manifest(manifest_id="M1"))
    r = assess_position(ledger, now=NOW)
    assert "unknown" in kinds(r)
    assert r["machines"][0]["coverage"]["current"] == 0
    assert r["machines"][0]["observation"]["stale"] is True
    assert {"function_never_verified", "machine_unobserved"} <= {
        w["work"] for w in r["next_work"]}


def test_a_current_verification_is_counted_current_and_traced(ledger):
    record_manifest(ledger, manifest(manifest_id="M1", taken_at=datetime(2026, 1, 20, tzinfo=UTC)))
    seal_a_real_verification(ledger, when=LATER)
    r = assess_position(ledger, now=NOW)
    assert r["machines"][0]["coverage"]["current"] >= 1


def test_a_ledger_whose_chain_is_broken_withholds_everything(ledger, tmp_path):
    record_manifest(ledger, manifest(manifest_id="M1"))
    record_manifest(ledger, manifest(manifest_id="M2"))
    db = sqlite3.connect(ledger.path)
    db.execute("UPDATE chain SET at = '2001-01-01T00:00:00Z' WHERE seq = 1")
    db.commit()
    db.close()
    r = assess_position(EvidenceLedger(ledger.path), now=NOW)
    assert not r["ledger"]["chain_verified"]
    assert r["findings"] == [] and r["next_work"] == [] and r["withheld"]


def test_no_score_money_or_probability_is_produced(ledger, store):
    drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
    def keys(x):
        if isinstance(x, dict):
            for k, v in x.items():
                yield str(k).lower()
                yield from keys(v)
        elif isinstance(x, list):
            for v in x:
                yield from keys(v)

    names = set(keys(assess_position(ledger, now=NOW)))
    assert not {n for n in names if any(
        w in n for w in ("score", "saving", "eur", "probab", "roi", "percent", "cost"))}


def test_the_result_is_reproducible(ledger, store):
    drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
    a, b = assess_position(ledger, now=NOW), assess_position(ledger, now=NOW)
    assert a == b
    assert "Next work" in render_text(a)


def test_cli_exit_codes(ledger, store, tmp_path, capsys):
    path = str(ledger.path)
    assert value_main(["report", "--ledger", str(tmp_path / "missing.db")]) == 2
    drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
    assert value_main(["report", "--ledger", path, "--now", "2026-10-22T00:00:00Z",
                       "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["schema"] == "assurance.position/1" and out["next_work"]
