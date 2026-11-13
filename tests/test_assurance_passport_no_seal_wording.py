"""`machinery passport --no-seal` must not say it sealed anything."""

from __future__ import annotations

from assurance.collect.cli import main as collect_main
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.cli import main as machinery_main

from .test_assurance_kit_outcomes import make_kit, run_cli


def _ledger_and_manifest(tmp_path):
    kit = make_kit(tmp_path)
    out = tmp_path / "out"
    assert run_cli("run", str(kit), "--out", str(out)) == 0
    manifest = tmp_path / "manifest.json"
    assert collect_main([
        "run", str(tmp_path / "plans" / "cell.json"), "--root",
        str(tmp_path / "exports" / "AR7-1001"), "--serial", "AR7-1001", "--actor", "Jane Doe",
        "--site", "Hamburg Works", "--country", "IT", "--year", "2024",
        "--out", str(manifest)]) == 0
    return out / "evidence.db", manifest


def test_no_seal_says_not_sealed_and_appends_nothing(tmp_path, capsys):
    ledger, manifest = _ledger_and_manifest(tmp_path)
    before = len(EvidenceLedger(ledger).entries())
    capsys.readouterr()
    machinery_main(["passport", "--ledger", str(ledger), "--actor", "Jane Doe", str(manifest),
                    "--no-seal"])
    text = capsys.readouterr().out
    assert len(EvidenceLedger(ledger).entries()) == before
    assert "(not sealed)" in text and "content hash" in text
    assert "sealed as" not in text


def test_sealing_still_says_sealed_as(tmp_path, capsys):
    ledger, manifest = _ledger_and_manifest(tmp_path)
    before = len(EvidenceLedger(ledger).entries())
    capsys.readouterr()
    machinery_main(["passport", "--ledger", str(ledger), "--actor", "Jane Doe", str(manifest)])
    text = capsys.readouterr().out
    assert len(EvidenceLedger(ledger).entries()) == before + 1
    assert "sealed as " in text and "(not sealed)" not in text
