"""A passport's printed blocks must repeat what the seal covers, or be named as unchecked.

Regression: ``machinery check`` compared the printed coverage's verdict and functions with the
sealed body but not its evidence tier floor, manifest id, configuration hash, machine or
assessed-at, and compared a printed intervention list by id only. Raising the printed tier floor
to "validated", or rewriting an intervention's reason or date, still checked ``ok``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from assurance.machinery.cli import main

KEY = "Acme/AR-7#0001"
MANIFEST = {
    "manifest_id": "M1", "machine": {"manufacturer": "Acme", "model": "AR-7", "serial": "0001"},
    "source": "as_found", "taken_at": "2026-01-01T00:00:00Z",
    "taken_by": {"identifier": "t", "role": "tech", "kind": "person"},
    "items": [{"item_id": "I", "kind": "firmware", "name": "fw", "version": "1",
               "content_hash": "a" * 64, "hash_source": "read_from_machine",
               "supplier": "S", "implements": ["SF"], "modifiable_in_field": False}],
    "functions": [{"function_id": "SF", "description": "d", "verified_by": ["c"]}],
}
INTERVENTION = {
    "intervention_id": "INT-1", "machine_key": KEY, "item_id": "I", "kind": "update",
    "occurred_at": "2026-02-01T09:00:00Z",
    "performed_by": {"identifier": "t", "role": "tech", "kind": "person"},
    "reason": "firmware update", "from_hash": "a" * 64, "to_hash": "b" * 64,
    "affects_functions": ["SF"], "authorization": None, "revalidation": None, "notes": "",
}


@pytest.fixture()
def passport(tmp_path):
    ledger = str(tmp_path / "l.db")
    (tmp_path / "m.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "iv.json").write_text(json.dumps(INTERVENTION))
    assert main(["record-manifest", str(tmp_path / "m.json"), "--ledger", ledger]) == 0
    assert main(["record-change", str(tmp_path / "iv.json"), "--ledger", ledger]) == 0
    out = tmp_path / "p.json"
    main(["passport", str(tmp_path / "m.json"), "--ledger", ledger, "--actor", "t",
          "--out", str(out)])
    return tmp_path, ledger, out


def _check(tmp_path, ledger, doc, capsys, *, with_ledger=True):
    path = tmp_path / "edited.json"
    path.write_text(json.dumps(doc))
    args = ["check", str(path), "--json"] + (["--ledger", ledger] if with_ledger else [])
    capsys.readouterr()
    rc = main(args)
    return rc, json.loads(capsys.readouterr().out)


def test_an_untouched_passport_still_checks_ok(passport, capsys):
    tmp_path, ledger, out = passport
    rc, body = _check(tmp_path, ledger, json.loads(out.read_text()), capsys)
    assert rc == 0 and body["ok"] is True


@pytest.mark.parametrize("field,value", [
    ("evidence_tier_floor", "validated"), ("configuration_hash", "0" * 64),
    ("manifest_id", "OTHER"), ("machine", "Acme/AR-7#9999"),
    ("assessed_at", "2030-01-01T00:00:00Z"),
])
def test_an_edited_printed_coverage_field_fails_the_check(passport, capsys, field, value):
    tmp_path, ledger, out = passport
    doc = json.loads(out.read_text())
    doc["coverage"][field] = value
    rc, body = _check(tmp_path, ledger, doc, capsys)
    assert rc != 0 and body["ok"] is False


@pytest.mark.parametrize("field,value", [
    ("reason", "nothing happened"), ("affects_functions", []),
    ("occurred_at", "2020-01-01T00:00:00Z"), ("kind", "inspection"),
])
def test_an_edited_printed_intervention_fails_against_the_ledger(passport, capsys, field, value):
    tmp_path, ledger, out = passport
    doc = json.loads(out.read_text())
    doc["interventions"][0][field] = value
    rc, body = _check(tmp_path, ledger, doc, capsys)
    assert rc != 0 and body["ok"] is False


def test_without_a_ledger_the_unchecked_interventions_are_named(passport, capsys):
    tmp_path, ledger, out = passport
    rc, body = _check(tmp_path, ledger, json.loads(out.read_text()), capsys, with_ledger=False)
    assert rc == 0                       # internally consistent, as before
    assert any("interventions" in p and "NOT CHECKED" in p for p in body["problems"])


def test_assessed_at_tolerates_the_moment_between_the_two_timestamps(passport, capsys):
    tmp_path, ledger, out = passport
    doc = json.loads(out.read_text())
    sealed = datetime.fromisoformat(doc["evidence"]["body"]["assessed_at"].replace("Z", "+00:00"))
    doc["coverage"]["assessed_at"] = (sealed + timedelta(seconds=2)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    rc, body = _check(tmp_path, ledger, doc, capsys)
    assert rc == 0 and body["ok"] is True
