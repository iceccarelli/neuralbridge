"""A watch that cannot observe says so (exit 2); it never reports "quiet" and never re-baselines.

``watch run`` compares each machine with the baseline READ from its ledger. The shared readers
(``manifests_from_ledger``) drop, without a word, a record that no longer matches its own seal. On
a ledger whose baseline had been edited the machine therefore had no history: it was announced as
a "first observation", sealed again onto the broken chain, and the run read QUIET (exit 0) while
the real change in the export folder was swallowed.

The contract these tests pin: exit 0 no findings, 1 findings, 2 unable to observe.

* a ledger whose hash chain does not verify => ``watch run`` exits 2, names the ledger, says that
  no observation was recorded, and appends NOTHING (not an observation, not a run record);
* a machine whose manifests do not all load (the chain verified, the record changed after) is
  degraded, never a first observation;
* an item that exists and cannot be read (corrupt archive, no permission) is "could not observe"
  (2), not "removed" (a finding, a case, exit 1).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.change.store import CaseStore
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.cli import main
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export
from .test_assurance_watch import T0

SRC = str(Path(__file__).resolve().parents[1] / "src")
SERIALS = ("CELL-0412", "CELL-0501")


@pytest.fixture()
def plant(tmp_path):
    (tmp_path / "plan.json").write_text(json.dumps(plan_dict()))
    for n, serial in enumerate(SERIALS):
        write_export(tmp_path / serial, stamp="2026-09-14T06:02:11Z", operator="ci",
                     seq=f"004{n}")
    (tmp_path / "watch.json").write_text(json.dumps({
        "watch_id": "plant-1", "max_age_hours": 168,
        "targets": [{"serial": s, "plan": "plan.json", "root": s, "site": "P1",
                     "country": "IT", "read_from_machine": True} for s in SERIALS]}))
    return tmp_path


def _watch(root: Path, *flags: str) -> list[str]:
    return ["run", str(root / "watch.json"), "--ledger", str(root / "ev.db"), *flags]


def _baseline(root: Path, capsys) -> None:
    """Two runs: the first look, then a quiet one. After this the baseline is sealed."""
    main(_watch(root))
    assert main(_watch(root)) == 0
    capsys.readouterr()


def _rows(root: Path) -> list[tuple]:
    db = sqlite3.connect(root / "ev.db")
    try:
        return list(db.execute("SELECT * FROM chain ORDER BY seq"))
    finally:
        db.close()


def _tamper(root: Path, kind: str) -> int:
    """Edit one stored payload in place, behind the ledger's back. Returns its seq."""
    db = sqlite3.connect(root / "ev.db")
    try:
        seq = db.execute("SELECT MIN(seq) FROM chain WHERE kind = ?", (kind,)).fetchone()[0]
        assert seq is not None, f"no {kind} record to edit"
        db.execute("UPDATE chain SET payload = replace(payload, 'ControlCo', 'ControlC0') "
                   "WHERE seq = ? AND payload LIKE '%ControlCo%'", (seq,))
        if db.total_changes == 0:        # a record that does not name a supplier: flip a char
            db.execute("UPDATE chain SET payload = replace(payload, 'assurance', 'assuranc3') "
                       "WHERE seq = ?", (seq,))
        assert db.total_changes == 1, f"the edit of {kind} did not change anything"
        db.commit()
    finally:
        db.close()
    return seq


def _drift(root: Path, serial: str = SERIALS[0]) -> None:
    write_export(root / serial, stamp="2026-09-14T06:02:11Z", operator="ci",
                 seq="0040", radius=900)


# ---------------------------------------------------------------------------------------------
# the gate: a ledger that does not verify is "unable to observe"
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("flags", [(), ("--json",), ("--dry-run",)],
                         ids=["run", "run-json", "dry-run"])
@pytest.mark.parametrize("kind", ["machinery.safety_manifest", "watch.observation", "watch.run"])
def test_a_ledger_that_does_not_verify_is_exit_2_and_nothing_is_appended(
        plant, capsys, flags, kind):
    _baseline(plant, capsys)
    _tamper(plant, kind)
    _drift(plant)                                   # the change the baseline would have caught
    before = _rows(plant)
    assert EvidenceLedger.open_existing(plant / "ev.db").verify_chain()[0] is False

    code = main(_watch(plant, *flags))
    out = capsys.readouterr()

    assert code == 2, out.out + out.err
    assert "QUIET" not in out.out and "first observation" not in out.out
    assert "does not verify" in out.err and "ev.db" in out.err
    assert "no observation was recorded" in out.err
    assert _rows(plant) == before                    # not an observation, not a run record
    assert EvidenceLedger.open_existing(plant / "ev.db").verify_chain()[0] is False


def test_it_stays_exit_2_on_every_later_run_until_the_ledger_is_restored(plant, capsys):
    _baseline(plant, capsys)
    _tamper(plant, "machinery.safety_manifest")
    for _ in range(3):
        assert main(_watch(plant)) == 2
    capsys.readouterr()


def test_the_edit_is_what_the_old_code_buried(plant, capsys):
    """The scenario of the finding, in full: tampered baseline + a real change in the export."""
    _baseline(plant, capsys)
    _tamper(plant, "machinery.safety_manifest")
    _drift(plant)
    assert main(_watch(plant, "--json")) == 2
    err = capsys.readouterr().err
    assert "payload does not match content_hash" in err        # says WHAT broke, at which seq
    assert "seq 1" in err


def test_control_an_untampered_ledger_behaves_exactly_as_before(plant, capsys):
    _baseline(plant, capsys)
    assert EvidenceLedger.open_existing(plant / "ev.db").verify_chain()[0] is True
    _drift(plant)
    assert main(_watch(plant)) == 1                          # the drift is a finding
    out = capsys.readouterr().out
    assert "DRIFT" in out and "CELL-0412" in out and "first observation" not in out
    assert EvidenceLedger.open_existing(plant / "ev.db").verify_chain()[0] is True
    assert main(_watch(plant)) == 0                          # and quiet once it is the baseline


def test_control_a_new_empty_ledger_is_not_refused(plant, capsys):
    assert not (plant / "ev.db").exists()
    assert main(_watch(plant)) in (0, 1)
    assert (plant / "ev.db").exists()
    capsys.readouterr()


# ---------------------------------------------------------------------------------------------
# the second line: the chain verified, yet a machine's manifests do not all load
# ---------------------------------------------------------------------------------------------
def test_a_machine_whose_manifests_do_not_load_is_degraded_not_a_first_observation(
        plant, capsys, monkeypatch):
    """Simulates an edit landing AFTER the chain walk (the walk is made blind on purpose)."""
    config = WatchConfig.from_json(plant / "watch.json")
    ledger = EvidenceLedger(plant / "ev.db")
    run_watch(config, ledger, now=T0)
    run_watch(config, ledger, now=T0)
    _tamper(plant, "machinery.safety_manifest")
    _drift(plant)
    monkeypatch.setattr(EvidenceLedger, "verify_chain", lambda self: (True, []))
    before = _rows(plant)

    run = run_watch(config, EvidenceLedger(plant / "ev.db"), seal=False, now=T0)

    by_serial = {o.serial: o for o in run.outcomes}
    lost = by_serial[SERIALS[0]]
    assert lost.status == "uncollectable" and lost.status != "first_seen"
    assert "baseline cannot be trusted" in lost.detail
    assert by_serial[SERIALS[1]].status == "observed"       # the other machine is still looked at
    assert run.verdict == "degraded"
    assert _rows(plant) == before

    # sealed, the same refusal: no manifest re-baselines the machine
    sealed = run_watch(config, ledger, now=T0)
    assert sealed.verdict == "degraded"
    manifests = [r for r in _rows(plant) if r[0] > before[-1][0] and "safety_manifest" in str(r)]
    assert manifests == []


# ---------------------------------------------------------------------------------------------
# an item that cannot be read is not an item that was removed
# ---------------------------------------------------------------------------------------------
def _damage_plc_archive(root: Path, serial: str = SERIALS[1]) -> None:
    (root / serial / "plc-project.zip").write_bytes(b"PK\x03\x04 this is not a zip archive")


def _cases(root: Path) -> list:
    return CaseStore(EvidenceLedger(root / "ev.db")).list()


def test_a_corrupt_archive_is_could_not_observe_not_removed(plant, capsys):
    _baseline(plant, capsys)
    _damage_plc_archive(plant)
    before = _rows(plant)

    code = main(_watch(plant))
    out = capsys.readouterr().out

    assert code == 2, out
    assert "DEGRADED" in out and "BLIND" in out and "CELL-0501" in out
    assert "ITM-PLC" in out and "could not be read" in out
    assert "ITM-PLC removed" not in out and "FINDINGS" not in out
    assert "0 required item(s) were not found" not in out
    assert _cases(plant) == []                               # no case opened on a non-finding
    new = [r for r in _rows(plant) if r[0] > before[-1][0]]
    assert not any("safety_manifest" in str(r) or "divergence" in str(r) for r in new)
    assert any("watch.observation" in str(r) and "uncollectable" in str(r) for r in new)
    assert any(r[0] > before[-1][0] and "watch.run" in str(r) for r in new)   # the run is recorded


def test_the_json_run_says_unreadable_and_not_missing(plant, capsys):
    _baseline(plant, capsys)
    _damage_plc_archive(plant)
    assert main(_watch(plant, "--json")) == 2
    doc = json.loads(capsys.readouterr().out)
    blind = {o["serial"]: o for o in doc["outcomes"]}["CELL-0501"]
    assert doc["verdict"] == "degraded" and blind["status"] == "uncollectable"
    assert "ITM-PLC" in blind["detail"] and "could not be read" in blind["detail"]
    assert blind["drift_items"] == [] and blind["case_id"] == ""


def test_it_clears_once_the_archive_can_be_read_again_and_nothing_was_re_baselined(plant, capsys):
    _baseline(plant, capsys)
    good = (plant / SERIALS[1] / "plc-project.zip").read_bytes()
    _damage_plc_archive(plant)
    assert main(_watch(plant)) == 2
    (plant / SERIALS[1] / "plc-project.zip").write_bytes(good)
    assert main(_watch(plant)) == 0                          # unchanged against the ORIGINAL baseline
    out = capsys.readouterr().out
    assert "unchanged at" in out and "DRIFT" not in out


def test_control_a_file_that_is_really_gone_is_still_a_removal_finding(plant, capsys):
    _baseline(plant, capsys)
    (plant / SERIALS[1] / "robot-params.json").unlink()
    assert main(_watch(plant)) == 1
    out = capsys.readouterr().out
    assert "ITM-PARAMS removed" in out and "1 required item(s) were not found" in out


def _without_dac_override() -> list[str] | None:
    """A prefix that makes file modes bind a root process too, or None when none is needed."""
    if os.geteuid() != 0:
        return []
    setpriv = shutil.which("setpriv")
    return [setpriv, "--bounding-set=-dac_override,-dac_read_search"] if setpriv else None


def test_a_file_without_read_permission_is_could_not_observe_not_removed(plant):
    """The real thing: ``chmod 000``. Run as root only with CAP_DAC_OVERRIDE dropped (setpriv)."""
    prefix = _without_dac_override()
    if prefix is None:
        pytest.skip("running as root without setpriv: file modes cannot be made to bind")
    argv = [*prefix, sys.executable, "-m", "assurance", "watch", *_watch(plant)]
    env = {"PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ.get("PATH", "")}

    def go() -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, env=env,  # noqa: S603
                              cwd=plant, check=False)

    go()
    assert go().returncode == 0
    target = plant / SERIALS[1] / "robot-params.json"
    target.chmod(0o000)
    try:
        r = go()
    finally:
        target.chmod(0o644)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "DEGRADED" in r.stdout and "ITM-PARAMS" in r.stdout and "could not be read" in r.stdout
    assert "ITM-PARAMS removed" not in r.stdout
    assert _cases(plant) == []
