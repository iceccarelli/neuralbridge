"""A ledger whose chain does not verify can be neither "covered" nor a pass, on every surface.

Regression (round-2 review, F4): ``fleet list`` exited 2 on a broken chain, but ``machinery
coverage``, ``machinery passport`` and ``fleet declaration --ledger`` exited 0 or 3 and the
passport sealed ``verified / ledger_chain_verified: false``. The exit contract is 0 covered, 1 gaps,
2 could not vouch, 3 covered at community; "could not vouch" includes a chain that does not verify.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.fleet.cli import main as fleet_cli
from assurance.fleet.declaration import DeclarationOfConformity
from assurance.machinery.cli import main as machinery_cli
from assurance.machinery.record import build_passport, record_manifest, verify_passport

from .support_trust_hardening import (
    KEY,
    attested_bundle,
    community_bundle,
    ledger,
    manifest,
)
from .test_assurance_machine_provenance import ACTOR


def _break_the_chain(led) -> None:
    """Zero the link hash of an UNRELATED row (a different machine's manifest)."""
    record_manifest(led, manifest("Other", "Co", "9999"))
    db = sqlite3.connect(led.path)
    db.execute("update chain set link_hash=? where subject=?", ("0" * 64, "Other/Co#9999"))
    db.commit()
    db.close()
    assert led.verify_chain()[0] is False


def _files(tmp_path: Path):
    man = manifest()
    m, d = tmp_path / "manifest.json", tmp_path / "doc.json"
    m.write_text(json.dumps(man.to_dict()), encoding="utf-8")
    d.write_text(json.dumps(DeclarationOfConformity.bind(
        man, doc_id="DOC-1", issued_by="G", issued_at=datetime(2026, 10, 1, tzinfo=UTC),
        legislation=("Regulation (EU) 2023/1230",)).to_dict()), encoding="utf-8")
    return m, d


@pytest.fixture(params=["validated", "community"])
def broken(tmp_path, request):
    led = ledger(tmp_path)
    record_manifest(led, manifest())
    if request.param == "validated":
        attested_bundle(KEY, file_under=led)
    else:
        community_bundle(KEY, file_under=led)
    _break_the_chain(led)
    return led


def test_machinery_coverage_exits_2(tmp_path, broken, capsys):
    m, _ = _files(tmp_path)
    rc = machinery_cli(["coverage", str(m), "--ledger", str(broken.path), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert out["ledger_chain_verified"] is False


def test_machinery_coverage_text_says_it_first(tmp_path, broken, capsys):
    m, _ = _files(tmp_path)
    machinery_cli(["coverage", str(m), "--ledger", str(broken.path)])
    assert "DOES NOT VERIFY" in capsys.readouterr().out.splitlines()[0]


def test_machinery_passport_exits_2_and_does_not_seal_a_covered_verdict(
        tmp_path, broken, capsys):
    m, _ = _files(tmp_path)
    rc = machinery_cli(["passport", str(m), "--ledger", str(broken.path), "--actor", "a.i",
                        "--no-seal", "--json"])
    out = json.loads(capsys.readouterr().out)
    body = out["evidence"]["body"]
    assert rc == 2
    assert body["verdict"] == "ledger_chain_not_verified"
    assert body["ledger_chain_verified"] is False
    assert out["evidence"]["validation_state"] == "indeterminate"
    assert out["evidence"]["confidence"] == "low"
    assert not str(body["verdict"]).startswith("covered")


def test_the_library_passport_on_a_broken_chain_is_not_covered(broken):
    passport = build_passport(broken, manifest(), actor=ACTOR, seal=False)
    assert passport.verdict == "ledger_chain_not_verified"
    assert passport.evidence.body["coverage_verdict"] in ("covered", "covered_at_community")
    assert passport.evidence.validation_state.value == "indeterminate"
    assert any("DOES NOT VERIFY" in c for c in passport.evidence.checks_skipped)


def test_a_passport_sealed_on_a_broken_chain_is_still_refused_by_the_checker(tmp_path, broken):
    passport = build_passport(broken, manifest(), actor=ACTOR)
    out = tmp_path / "p.json"
    passport.write(out)
    ok, problems = verify_passport(out)
    assert ok is False
    assert any("chain did not verify" in p for p in problems)
    assert not any("implies" in p for p in problems)      # the verdict itself is coherent


def test_fleet_declaration_with_a_ledger_exits_2(tmp_path, broken, capsys):
    m, d = _files(tmp_path)
    rc = fleet_cli(["declaration", str(d), "--manifest", str(m), "--ledger",
                    str(broken.path), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert out["ledger_chain_verified"] is False


def test_a_whole_chain_is_unchanged(tmp_path, capsys):
    led = ledger(tmp_path)
    record_manifest(led, manifest())
    attested_bundle(KEY, file_under=led)
    m, d = _files(tmp_path)
    assert machinery_cli(["coverage", str(m), "--ledger", str(led.path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ledger_chain_verified"] is True
    assert fleet_cli(["declaration", str(d), "--manifest", str(m), "--ledger",
                      str(led.path), "--json"]) == 0
