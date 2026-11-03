"""Nothing assessed is nothing cleared (issue #83), and fleet size / identity sanity."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import MachineIdentity
from assurance.machinery.record import record_manifest

from .test_assurance_change import MACHINE, item, manifest

SRC = Path(__file__).resolve().parents[1] / "src"


def _advisory(name="Safety controller firmware", supplier="ControlCo", version="3.8.2"):
    return ComponentAdvisory(
        advisory_id="ADV-1", issued_by=supplier, issued_at=datetime(2026, 9, 1, tzinfo=UTC),
        title="t", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(supplier=supplier, name=name, versions=(version,)),),
        reference="https://example.invalid/a")


def _ledger():
    return EvidenceLedger(os.path.join(tempfile.mkdtemp(), "f.db"))


def _enrol(led, serial, *, model="AR-7", site="Plant", fw_version="3.8.2"):
    ident = MachineIdentity(manufacturer="Grimaldi", model=model, serial=serial, site=site)
    record_manifest(led, manifest(item(version=fw_version), machine=ident,
                                  manifest_id=f"M-{model}-{serial}"))
    return ident.key


class TestEmptyFleet:
    def test_the_verdict_is_not_clear_and_says_why(self):
        report = assess_impact(_advisory(), Fleet.from_ledger(_ledger()))
        assert report.machines_in_fleet == 0
        assert report.verdict != "clear" and report.clear_is_complete is False
        d = report.to_dict()
        assert d["verdict"] == "needs_review" and d["not_clear_reasons"]
        text = report.summary()
        assert "CLEAR" not in text.split("\n")[0] and "NOT ASSESSED" in text

    def test_one_assessed_machine_with_no_match_stays_clear(self):
        led = _ledger()
        _enrol(led, "1", fw_version="9.9")
        report = assess_impact(_advisory(), Fleet.from_ledger(led))
        assert report.verdict == "clear" and report.clear_is_complete is True
        assert report.not_clear_reasons == ()

    def test_the_cli_exit_codes(self, tmp_path: Path):
        def cli(*args):
            return subprocess.run(  # noqa: S603
                [sys.executable, "-m", "assurance", *map(str, args)],
                capture_output=True, text=True, cwd=tmp_path, timeout=120, check=False,
                env={**os.environ, "PYTHONPATH": str(SRC)})

        adv = tmp_path / "adv.json"
        adv.write_text(json.dumps(_advisory().to_dict()))
        empty = tmp_path / "empty.db"
        EvidenceLedger(empty)
        run = cli("fleet", "advisory", adv, "--ledger", empty, "--json")
        report = json.loads(run.stdout)["advisories"][0]
        assert run.returncode == 3 and report["verdict"] != "clear"
        assert report["clear_is_complete"] is False and report["not_clear_reasons"]
        human = cli("fleet", "advisory", adv, "--ledger", empty)
        assert human.returncode == 3 and "CLEAR —" not in human.stdout

        full = tmp_path / "full.db"
        _enrol(EvidenceLedger(full), "1", fw_version="9.9")
        run = cli("fleet", "advisory", adv, "--ledger", full, "--json")
        assert run.returncode == 0
        assert json.loads(run.stdout)["advisories"][0]["verdict"] == "clear"


class TestScaleAndIdentity:
    @pytest.mark.parametrize("n", [1, 7, 300])
    def test_n_machines_are_each_classified_once_in_bounded_time(self, n):
        led = _ledger()
        keys = [_enrol(led, f"S{i:04d}", fw_version="3.8.2" if i % 3 == 0 else "9.9")
                for i in range(n)]
        started = time.monotonic()
        fleet = Fleet.from_ledger(led)
        report = assess_impact(_advisory(), fleet)
        assert time.monotonic() - started < 60
        assert fleet.chain_verified and len(fleet) == n == report.machines_in_fleet
        assert [c.machine_key for c in report.classifications] == sorted(keys)
        hit = {k for i, k in enumerate(keys) if i % 3 == 0}
        assert set(report.machines_affected) == hit
        assert report.verdict == ("exposed" if hit and any(
            e.newly_in_question for e in report.exposures) else
            "needs_review" if hit else "clear")

    def test_the_same_serial_on_different_machines_never_merges(self):
        led = _ledger()
        a = _enrol(led, "0001", model="AR-7", fw_version="3.8.2")
        b = _enrol(led, "0001", model="AR-9", fw_version="9.9")
        c = _enrol(led, "0001", model="AR-7", site="Other")   # same key as a: the same machine
        assert a == c and a != b
        fleet = Fleet.from_ledger(led)
        assert len(fleet) == 2 and {r.machine_key for r in fleet.records} == {a, b}
        report = assess_impact(_advisory(), fleet)
        # b is never charged with a's firmware, and a is never cleared by b's.
        assert report.machines_affected == (a,)
        by = {c.machine_key: c.classification for c in report.classifications}
        assert by[b] == "no_match_found"

    def test_a_different_manufacturer_with_the_same_model_and_serial_is_another_machine(self):
        led = _ledger()
        a = _enrol(led, "0001")
        other = replace(MACHINE, manufacturer="Other", serial="0001")
        record_manifest(led, manifest(item(version="9.9"), machine=other, manifest_id="M-O"))
        fleet = Fleet.from_ledger(led)
        assert len(fleet) == 2 and fleet.record(a) is not None
        assert fleet.record(other.key) is not None
