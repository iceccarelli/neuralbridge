"""Bulk enrolment from an inventory export file (``machinery import-inventory``).

Pins: every row goes through ``enrol_machine`` and comes back with enrol's own outcome; one bad
row never aborts the batch; nothing is truncated, guessed, evaluated or hidden; a refused file
is refused before any write; a dry run writes nothing and creates no ledger; the batch record
holds machine keys and counts only; the API takes canonical rows under the same gate as enrol;
there is no MCP tool; no receipt says the machines are verified, compliant or safe.

All fixtures are SYNTHETIC (tests/fixtures/inventory/).
"""
# ruff: noqa: S603  (the tests run this package's own CLI)
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery import inventory as inv
from assurance.machinery.enrol import ENROLMENT_KIND, EnrolmentError
from assurance.machinery.inventory import IMPORT_KIND, import_file

from . import interfaces_fixtures as fx
from . import test_assurance_change as _change

live_api = fx.live_api
client = _change.client
account_store = _change.account_store

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "inventory"
SRC = ROOT / "src"
PERSON = Actor("a.integrator", "safety engineer")
FORBIDDEN = ("compliant", "compliance", "certified", "safe", "verified")
H1, H2 = "1" * 64, "2" * 64

HEADER = ["Hersteller", "Typ", "Seriennr", "Standort", "Eigentuemer", "Baujahr", "Land",
          "SPS Firmware", "SPS Version", "SPS SHA256", "Scanner Version"]


def _mapping(**over):
    m = json.loads((FIXTURES / "mapping.synthetic.json").read_text("utf-8"))
    m.update(over)
    return m


def _row(serial, *, fw="3.8.2", sha=H1, scanner="r4", site="Plant 1", model="AR-7",
         maker="Grimaldi", owner="Example GmbH", year="2021", country="DE"):
    return [maker, model, serial, site, owner, year, country, "Safety controller firmware",
            fw, sha, scanner]


def _csv(rows, header=HEADER, delimiter=",", bom=False):
    buf = io.StringIO(newline="")
    w = csv.writer(buf, delimiter=delimiter, lineterminator="\r\n")
    w.writerow(header)
    w.writerows(rows)
    return ("﻿" if bom else "") + buf.getvalue()


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.dir = tmp_path
        self.ledger = tmp_path / "fleet.db"
        self.mapping = tmp_path / "map.json"
        self.file = tmp_path / "inventory.csv"
        self.write_mapping(_mapping())

    def write_mapping(self, m) -> None:
        self.mapping.write_text(json.dumps(m), "utf-8")

    def write(self, rows, **kw) -> None:
        self.file.write_text(_csv(rows, **kw), "utf-8", newline="")

    def cli(self, *extra, actor="a.integrator", file=None, ledger=None):
        env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [sys.executable, "-m", "assurance", "machinery", "import-inventory",
             str(file or self.file), "--mapping", str(self.mapping),
             "--ledger", str(ledger or self.ledger), "--actor", actor, *extra],
            cwd=self.dir, capture_output=True, text=True, check=False, env=env)

    def run(self, **kw):
        return import_file(self.file, self.mapping, self.ledger, actor=PERSON, **kw)

    def entries(self):
        return list(EvidenceLedger(self.ledger).entries())


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def five():
    return [_row(f"050{n}") for n in range(1, 6)]


def statuses(report):
    return {o.row: o.status for o in report.outcomes}


# -- the happy path -------------------------------------------------------------


class TestHappyPath:
    def test_five_machines_are_enrolled_and_never_verified(self, env):
        env.write(five())
        report = env.run()
        assert report.counts["enrolled"] == 5 and report.ok
        kinds = [e.kind for e in env.entries()]
        assert kinds.count(ENROLMENT_KIND) == 5 and kinds.count(IMPORT_KIND) == 1
        ledger = EvidenceLedger(env.ledger)
        assert ledger.verify_chain()[0]
        for o in report.outcomes:
            assert o.machine == f"Grimaldi/AR-7#{'050' + str(o.row)}"

    def test_provenance_is_in_the_sealed_manifest_and_says_customer_provided(self, env):
        env.write(five()[:1])
        env.run()
        manifest = next(e for e in env.entries() if e.kind == "machinery.safety_manifest")
        body = manifest.evidence().body["manifest"]
        sha = hashlib.sha256(env.file.read_bytes()).hexdigest()
        assert body["source"] == "as_declared"
        assert {i["hash_source"] for i in body["items"]} == {"declared"}
        for part in (inv.IMPORTER, "source_system=sap-pm-export", "export_date=2026-10-15",
                     f"file_sha256={sha}", "row=1", "not collected from the machine"):
            assert part in body["notes"], part
        assert "not collected from the machine" in body["method"]
        assert body["taken_at"].startswith("2026-10-15")

    def test_an_item_without_a_hash_stays_uncomparable(self, env):
        env.write([_row("0503", sha="")])
        env.run()
        enrolment = next(e for e in env.entries() if e.kind == ENROLMENT_KIND)
        assert enrolment.evidence().body["uncomparable_items"] == [
            "ITM-1-safety-controller-firmware", "ITM-2-safety-scanner-zone-set"]

    def test_the_fixture_files_import(self, env):
        env.file = FIXTURES / "sap-pm-export.synthetic.csv"
        report = env.run()
        assert report.counts["enrolled"] == 5

    def test_json_input(self, env):
        records = [dict(zip(HEADER, r, strict=True)) for r in five()[:2]]
        env.file = env.dir / "inventory.json"
        env.file.write_text(json.dumps(records), "utf-8")
        assert env.run().counts["enrolled"] == 2

    def test_json_with_duplicate_keys_is_refused(self, env):
        env.file = env.dir / "inventory.json"
        env.file.write_text('[{"Typ": "a", "Typ": "b"}]', "utf-8")
        with pytest.raises(inv.InventoryImportError, match="duplicate key"):
            env.run()

    def test_reimport_is_idempotent_and_writes_nothing(self, env):
        env.write(five())
        env.run()
        before = [(e.seq, e.content_hash) for e in env.entries()]
        again = env.run()
        assert again.counts["already_enrolled"] == 5 and again.ok
        assert [(e.seq, e.content_hash) for e in env.entries()] == before
        assert again.batch_entry == 0                       # nothing enrolled: no batch record

    def test_a_changed_firmware_version_is_configuration_differs_with_a_pointer(self, env):
        env.write(five())
        env.run()
        before = len(env.entries())
        env.write([_row("0501", fw="3.9.0"), *five()[1:]])
        report = env.run()
        assert statuses(report)[1] == "configuration_differs"
        assert report.counts["already_enrolled"] == 4 and not report.ok
        row = report.outcomes[0]
        assert "machinery diff" in row.pointer
        assert len(env.entries()) == before

    def test_identity_conflict_when_the_declared_site_differs(self, env):
        env.write([_row("0501")])
        env.run()
        env.write([_row("0501", site="Plant 9")])
        report = env.run()
        # a different site is part of the manifest, so the configuration differs AND the
        # declared attribute conflicts: enrol reports the conflict first
        assert report.outcomes[0].status == "identity_conflict"
        env.write([_row("0501", owner="Other AG")])
        report = env.run()
        assert report.outcomes[0].status == "identity_conflict"
        assert report.outcomes[0].machine == "Grimaldi/AR-7#0501"

    def test_a_row_may_be_enrolled_alongside_refused_rows(self, env):
        env.write([_row("0501")])
        env.run()
        env.write([_row("0501", fw="9.9.9"), _row("0502")])
        report = env.run()
        assert statuses(report) == {1: "configuration_differs", 2: "enrolled"}
        assert [o.row for o in report.outcomes if not o.ok] == [1]


# -- bad rows --------------------------------------------------------------------


class TestRows:
    def test_a_bad_sha256_rejects_that_row_and_the_others_proceed(self, env):
        env.write([_row("0501"), _row("0502", sha="abc123"), _row("0503", sha="g" * 64),
                   _row("0504", sha="sha256:" + H1), _row("0505")])
        report = env.run()
        assert statuses(report) == {1: "enrolled", 2: "rejected", 3: "rejected",
                                    4: "rejected", 5: "enrolled"}
        assert "64 hexadecimal" in report.outcomes[1].reason
        assert not report.ok
        keys = {e.subject for e in env.entries() if e.kind == ENROLMENT_KIND}
        assert keys == {"Grimaldi/AR-7#0501", "Grimaldi/AR-7#0505"}

    def test_an_uppercase_digest_is_accepted_as_the_same_digest(self, env):
        env.write([_row("0501", sha="AB" * 32)])
        env.run()
        manifest = next(e for e in env.entries() if e.kind == "machinery.safety_manifest")
        assert manifest.evidence().body["manifest"]["items"][0]["content_hash"] == "ab" * 32

    def test_duplicate_key_in_the_file_second_is_rejected(self, env):
        env.write([_row("0501"), _row("0502"), _row("0501", fw="9.9.9")])
        report = env.run()
        assert statuses(report) == {1: "enrolled", 2: "enrolled", 3: "rejected"}
        assert "duplicate in file" in report.outcomes[2].reason
        assert "row 1" in report.outcomes[2].reason

    def test_missing_required_values_are_rejected_with_a_reason(self, env):
        env.write([_row(""), _row("0502", model=""), _row("0503", country="Deutschland"),
                   _row("0504", year="21")])
        report = env.run()
        assert [o.status for o in report.outcomes] == ["rejected"] * 4
        assert "serial: empty" in report.outcomes[0].reason
        assert "model: empty" in report.outcomes[1].reason
        assert "country" in report.outcomes[2].reason and "year" in report.outcomes[3].reason
        assert env.ledger.exists() and not [e for e in env.entries()
                                            if e.kind == ENROLMENT_KIND]

    def test_a_row_with_no_software_items_is_rejected(self, env):
        env.write([_row("0501", fw="", scanner="")])
        report = env.run()
        assert report.outcomes[0].status == "rejected"
        assert "no software" in report.outcomes[0].reason

    def test_an_item_without_a_version_is_not_listed_and_the_row_says_so(self, env):
        env.write([_row("0501", scanner="")])
        report = env.run()
        assert report.outcomes[0].status == "enrolled"
        assert any("no version" in n for n in report.outcomes[0].notes)
        enrolment = next(e for e in env.entries() if e.kind == ENROLMENT_KIND)
        assert len(enrolment.evidence().body["functions"]) == 1
        manifest = next(e for e in env.entries() if e.kind == "machinery.safety_manifest")
        assert len(manifest.evidence().body["manifest"]["items"]) == 1

    def test_a_short_csv_row_is_rejected_not_padded(self, env):
        env.file.write_text(",".join(HEADER) + "\r\nGrimaldi,AR-7,0501\r\n", "utf-8")
        report = env.run()
        assert report.outcomes[0].status == "rejected"
        assert "fields" in report.outcomes[0].reason

    def test_rows_over_max_rows_are_reported_not_processed(self, env):
        env.write(five())
        report = env.run(max_rows=3)
        assert report.not_processed == 2 and len(report.outcomes) == 3 and not report.ok
        assert "2 rows not processed" in report.summary()
        keys = {e.subject for e in env.entries() if e.kind == ENROLMENT_KIND}
        assert "Grimaldi/AR-7#0504" not in keys and len(keys) == 3
        batch = next(e for e in env.entries() if e.kind == IMPORT_KIND).evidence().body
        assert batch["rows_not_processed"] == 2 and batch["rows_read"] == 5

    def test_max_rows_must_be_positive(self, env):
        env.write(five())
        with pytest.raises(inv.InventoryImportError, match="at least 1"):
            env.run(max_rows=0)


# -- the file --------------------------------------------------------------------


class TestFile:
    def test_a_missing_mapped_column_is_refused_before_any_write(self, env):
        env.write(five(), header=[h if h != "SPS SHA256" else "Hash" for h in HEADER])
        with pytest.raises(inv.InventoryImportError, match="SPS SHA256"):
            env.run()
        assert not env.ledger.exists()

    def test_bom_and_semicolon_delimiter_and_quoted_newlines(self, env):
        rows = [_row("0501", site="Plant 1\nHall 2", owner='Example "GmbH"; Sub')]
        env.write(rows, delimiter=";", bom=True)
        report = env.run()
        assert report.outcomes[0].status == "enrolled"
        enrolment = next(e for e in env.entries() if e.kind == ENROLMENT_KIND)
        declared = enrolment.evidence().body["declared"]
        assert declared["site"] == "Plant 1 Hall 2" and declared["owner"] == 'Example "GmbH"; Sub'

    def test_not_utf8_is_refused(self, env):
        env.file.write_bytes(_csv(five()).encode("utf-16"))
        with pytest.raises(inv.InventoryImportError):
            env.run()
        assert not env.ledger.exists()

    def test_oversized_field_rejects_the_row(self, env):
        env.write([_row("0501", owner="x" * 201)])
        assert env.run().outcomes[0].status == "rejected"

    def test_empty_file_and_duplicate_headers_are_refused(self, env):
        env.file.write_text("", "utf-8")
        with pytest.raises(inv.InventoryImportError, match="empty"):
            env.run()
        env.write([], header=[*HEADER, "Typ"])
        with pytest.raises(inv.InventoryImportError, match="duplicate column"):
            env.run()

    def test_mapping_faults_are_refused(self, env):
        for bad in (_mapping(source_system=""), _mapping(export_date="soon"),
                    _mapping(extra=1), _mapping(columns={"model": "Typ"}),
                    _mapping(items=[{"name": "x"}]),
                    _mapping(items=[{"name": "x", "version_column": "v", "implements": ["nope"]}])):
            env.write_mapping(bad)
            env.write(five()[:1])
            with pytest.raises(inv.InventoryImportError):
                env.run()
        assert not env.ledger.exists()


# -- CSV injection and control characters ----------------------------------------


class TestHostileCells:
    @pytest.mark.parametrize("cell", ["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)",
                                      '=HYPERLINK("http://x","y")'])
    def test_formula_cells_are_kept_as_inert_text(self, env, cell):
        env.write([_row(cell, owner=cell)])
        report = env.run()
        assert report.outcomes[0].status == "enrolled"
        assert report.outcomes[0].machine == f"Grimaldi/AR-7#{cell}"
        assert any("never evaluated" in n for n in report.outcomes[0].notes)
        enrolment = next(e for e in env.entries() if e.kind == ENROLMENT_KIND)
        assert enrolment.evidence().body["identity"]["serial"] == cell

    def test_control_and_invisible_characters_are_refused(self, env):
        for bad in ("a\x00b", "a\x1bb", "a\x07b", "a‮b", "a​b", "a b"):
            env.write([_row("0501", owner=bad)])
            if "\x00" in bad:
                with pytest.raises(inv.InventoryImportError):
                    env.run()
                continue
            report = env.run()
            assert report.outcomes[0].status == "rejected", repr(bad)
            assert "control or invisible" in report.outcomes[0].reason
            assert bad not in report.summary()
        assert not env.ledger.exists() or not [e for e in env.entries()
                                               if e.kind == ENROLMENT_KIND]


# -- dry run ---------------------------------------------------------------------


class TestDryRun:
    def test_dry_run_creates_no_ledger_and_shows_would_be_outcomes(self, env):
        env.write(five())
        report = env.run(dry_run=True)
        assert report.dry_run and report.counts["enrolled"] == 5
        assert not env.ledger.exists()
        assert sorted(p.name for p in env.dir.iterdir()) == ["inventory.csv", "map.json"]

    def test_dry_run_against_a_real_ledger_reports_already_enrolled_and_writes_nothing(self, env):
        env.write(five()[:3])
        env.run()
        raw = env.ledger.read_bytes()
        names = sorted(p.name for p in env.dir.iterdir())
        env.write(five())
        report = env.run(dry_run=True)
        assert report.counts == {"enrolled": 2, "already_enrolled": 3,
                                 "configuration_differs": 0, "identity_conflict": 0,
                                 "rejected": 0}
        assert env.ledger.read_bytes() == raw
        assert sorted(p.name for p in env.dir.iterdir()) == names
        assert report.batch_entry == 0
        assert "DRY RUN" in report.summary()

    def test_dry_run_keeps_the_row_checks(self, env):
        env.write([_row("0501"), _row("0501"), _row("0502", sha="zz")])
        report = env.run(dry_run=True)
        assert statuses(report) == {1: "enrolled", 2: "rejected", 3: "rejected"}

    def test_dry_run_still_refuses_automation(self, env):
        env.write(five())
        assert env.cli("--dry-run", actor="automation").returncode == 2
        assert not env.ledger.exists()


# -- the batch record and the actor ----------------------------------------------


class TestBatchRecord:
    def test_the_batch_entry_has_hashes_counts_and_machine_keys_only(self, env):
        env.write([_row("0501", owner="Secret Owner GmbH"), _row("0502", sha="bad")])
        env.run()
        entry = next(e for e in env.entries() if e.kind == IMPORT_KIND)
        body = entry.evidence().body
        assert body["file_sha256"] == hashlib.sha256(env.file.read_bytes()).hexdigest()
        assert body["mapping_sha256"] == hashlib.sha256(env.mapping.read_bytes()).hexdigest()
        assert body["counts"]["enrolled"] == 1 and body["counts"]["rejected"] == 1
        assert entry.actor == "a.integrator"
        assert body["machines"] == [{"row": 1, "machine": "Grimaldi/AR-7#0501",
                                     "status": "enrolled"},
                                    {"row": 2, "machine": "", "status": "rejected"}]
        text = json.dumps(entry.evidence().to_dict())
        for content in ("Secret Owner", "Plant 1", "3.8.2", H1, "Example GmbH"):
            assert content not in text, content

    def test_ledger_is_created_on_first_use_and_the_chain_is_verified_first(self, env):
        env.write(five()[:1])
        env.run()
        assert env.ledger.exists()
        # break the chain: the import must refuse before enrolling anything
        import sqlite3
        db = sqlite3.connect(env.ledger)
        db.execute("UPDATE chain SET link_hash = 'x' WHERE seq = 1")
        db.commit()
        db.close()
        env.write(five())
        before = len(env.entries())
        with pytest.raises(inv.LedgerChainUnverifiedError):
            env.run()
        assert len(env.entries()) == before
        assert env.cli().returncode == 2
        assert len(env.entries()) == before

    @pytest.mark.parametrize("actor", ["automation", "bot", "", "system-3", "​"])
    def test_a_non_person_actor_is_refused_and_no_ledger_is_created(self, env, actor):
        env.write(five())
        with pytest.raises(EnrolmentError):
            import_file(env.file, env.mapping, env.ledger, actor=Actor(actor, kind="person"))
        with pytest.raises(EnrolmentError):
            import_file(env.file, env.mapping, env.ledger,
                        actor=Actor("a.integrator", kind="automation"))
        assert not env.ledger.exists()

    def test_a_ledger_path_that_is_not_a_ledger_is_refused(self, env):
        env.write(five())
        env.ledger.write_text("not a database" * 100, "utf-8")
        assert env.cli("--dry-run").returncode == 2
        assert env.cli().returncode == 2


# -- the receipt's words -----------------------------------------------------------


def _prose(report) -> str:
    text = report.summary() + json.dumps(report.to_dict())
    for line in inv.NOT_ESTABLISHED + inv.NEXT_STEPS:
        text = text.replace(line, "").replace(json.dumps(line)[1:-1], "")
    for stated in ("does NOT establish", "does_not_establish", "not authenticated",
                   "nothing was read from a machine", "no verification has been run",
                   "next_steps", "next steps", "verify the machines that matter"):
        text = text.replace(stated, "")
    return text.lower()


def test_no_receipt_says_verified_compliant_or_safe(env):
    env.write([*five(), _row("0501", fw="9.9"), _row("0599", sha="bad")])
    for report in (env.run(dry_run=True), env.run(), env.run()):
        prose = _prose(report)
        for word in FORBIDDEN:
            assert word not in prose, word


# -- CLI ---------------------------------------------------------------------------


class TestCli:
    def test_exit_0_when_all_rows_are_enrolled_or_already(self, env):
        env.write(five())
        run = env.cli()
        assert run.returncode == 0, run.stderr
        assert "enrolled              5" in run.stdout and "does NOT establish" in run.stdout
        assert env.cli().returncode == 0                        # idempotent re-run

    def test_exit_1_when_a_row_is_refused_and_json_lists_it(self, env):
        env.write([_row("0501"), _row("0502", sha="bad")])
        run = env.cli("--json")
        assert run.returncode == 1
        doc = json.loads(run.stdout)
        assert doc["counts"]["rejected"] == 1 and doc["all_enrolled"] is False
        assert doc["outcomes"][1]["reason"]
        assert doc["data_basis"].startswith("customer-provided")

    def test_exit_1_when_rows_were_not_processed(self, env):
        env.write(five())
        run = env.cli("--max-rows", "2")
        assert run.returncode == 1 and "3 rows not processed" in run.stdout

    def test_exit_2_for_usage_and_io(self, env):
        env.write(five())
        assert env.cli(file=env.dir / "missing.csv").returncode == 2
        assert env.cli(actor="automation").returncode == 2
        assert not env.ledger.exists()
        env.write(five(), header=["a"] * 11)
        assert env.cli().returncode == 2
        assert not env.ledger.exists()

    def test_dry_run_flag(self, env):
        env.write(five())
        run = env.cli("--dry-run")
        assert run.returncode == 0 and "DRY RUN" in run.stdout and not env.ledger.exists()


# -- API ---------------------------------------------------------------------------

URL = "/v1/machinery/enrol/batch"


def machine(serial, **over):
    d = {"manufacturer": "Grimaldi", "model": "AR-7", "serial": serial, "site": "Plant 1",
         "owner": "Example GmbH", "year": "2021", "country": "DE",
         "items": [{"name": "Safety controller firmware", "version": "3.8.2", "sha256": H1,
                    "supplier": "ControlCo", "implements": ["SF-01"]},
                   {"name": "Scanner zones", "version": "r4", "kind": "safety_configuration",
                    "implements": ["SF-01"]}]}
    d.update(over)
    return d


FUNCTIONS = [{"function_id": "SF-01", "description": "Protective stop on zone intrusion",
              "required_performance": "PL d", "verified_by": ["ssm_separation"]}]


def body(rows, **over):
    b = {"rows": rows, "source_system": "sap-pm-export", "actor": "a.integrator",
         "functions": FUNCTIONS, "export_date": "2026-10-15"}
    b.update(over)
    return b


class TestApi:
    def test_no_key_is_401_and_unentitled_is_402(self, client, account_store):
        assert client.post(URL, json=body([machine("1")])).status_code == 401
        h = _change.keyed(account_store, "register")
        assert client.post(URL, json=body([machine("1")]), headers=h).status_code == 402

    def test_batch_enrols_through_the_same_function_and_coverage_is_never_verified(self, live_api):
        _, h = live_api.account("cell-a@example.de")
        with live_api.client() as http:
            r = http.post(URL, json=body([machine("1"), machine("2")]), headers=h)
            assert r.status_code == 200, r.text
            doc = r.json()
            assert doc["counts"]["enrolled"] == 2 and doc["all_enrolled"]
            assert doc["file_sha256_basis"] == "asserted by the caller, not checked"
            single = http.post("/v1/machinery/enrol", headers=h, json={
                "manifest": _manifest_dict(machine("1")), "actor": "a.integrator"})
            assert single.status_code == 200
            cov = http.post("/v1/machinery/coverage", headers=h,
                            json={"manifest": _manifest_dict(machine("1"))})
            assert cov.status_code == 200, cov.text
            fns = cov.json()["functions"]
            assert [f["coverage"] for f in fns] == ["never_verified"]
            again = http.post(URL, json=body([machine("1"), machine("2")]), headers=h).json()
            assert again["counts"]["already_enrolled"] == 2

    def test_per_row_outcomes_and_partial_success(self, live_api):
        _, h = live_api.account("cell-b@example.de")
        with live_api.client() as http:
            http.post(URL, json=body([machine("1")]), headers=h)
            rows = [machine("1", items=[{"name": "Safety controller firmware",
                                         "version": "9.9", "implements": ["SF-01"]}]),
                    machine("2"), machine("2"), machine("3", items=[
                        {"name": "x", "version": "1", "sha256": "nothex"}]),
                    machine("4", owner="Other AG"), "not an object"]
            r = http.post(URL, json=body(rows), headers=h)
            assert r.status_code == 200
            out = {o["row"]: o["status"] for o in r.json()["outcomes"]}
            assert out == {1: "configuration_differs", 2: "enrolled", 3: "rejected",
                           4: "rejected", 5: "enrolled", 6: "rejected"}
            assert "duplicate in file" in r.json()["outcomes"][2]["reason"]

    def test_over_the_cap_is_413_and_nothing_is_written(self, live_api):
        acct, h = live_api.account("cell-c@example.de")
        with live_api.client() as http:
            r = http.post(URL, json=body([machine(str(n)) for n in range(201)]), headers=h)
            assert r.status_code == 413 and r.json()["detail"]["error"] == "too_many_rows"
            assert r.json()["detail"]["limit"] == 200
            ok = http.post(URL, json=body([machine(str(n)) for n in range(200)]), headers=h)
            assert ok.status_code == 200 and ok.json()["counts"]["enrolled"] == 200
        assert len(list(live_api.tenant_ledger(acct).entries(kind=ENROLMENT_KIND))) == 200

    def test_the_actor_must_be_a_named_person(self, live_api):
        _, h = live_api.account("cell-d@example.de")
        with live_api.client() as http:
            for actor in ("automation", "bot-1"):
                r = http.post(URL, json=body([machine("1")], actor=actor), headers=h)
                assert r.status_code == 422, actor
            assert http.post(URL, json=body([machine("1")], actor=""), headers=h
                             ).status_code == 422
            assert http.post(URL, json=body([machine("1")], extra=1), headers=h
                             ).status_code == 422
            assert http.post(URL, json=body([], ), headers=h).status_code == 422
            assert http.post(URL, json=body([machine("1")], file_sha256="zz"), headers=h
                             ).status_code == 422

    def test_tenants_are_isolated(self, live_api):
        a_id, ha = live_api.account("tenant-a@example.de")
        b_id, hb = live_api.account("tenant-b@example.de")
        with live_api.client() as http:
            http.post(URL, json=body([machine("1")]), headers=ha)
            rb = http.post(URL, json=body([machine("1", owner="B AG")]), headers=hb)
            assert rb.json()["counts"]["enrolled"] == 1          # B never saw A's machine
            fa = http.get("/v1/fleet/machines", headers=ha).json()["machines"]
            fb = http.get("/v1/fleet/machines", headers=hb).json()["machines"]
            assert len(fa) == len(fb) == 1
        a_kinds = [e.kind for e in live_api.tenant_ledger(a_id).entries()]
        b_kinds = [e.kind for e in live_api.tenant_ledger(b_id).entries()]
        assert a_kinds.count(IMPORT_KIND) == b_kinds.count(IMPORT_KIND) == 1

    def test_batch_entry_has_no_row_contents(self, live_api):
        acct, h = live_api.account("cell-e@example.de")
        with live_api.client() as http:
            http.post(URL, json=body([machine("1", owner="Secret Owner GmbH")],
                                     file_sha256=H2), headers=h)
        entry = next(e for e in live_api.tenant_ledger(acct).entries() if e.kind == IMPORT_KIND)
        text = json.dumps(entry.evidence().to_dict())
        assert "Secret Owner" not in text and "3.8.2" not in text and H1 not in text
        assert entry.evidence().body["file_sha256"] == H2
        assert entry.evidence().body["channel"] == "api"

    def test_the_response_never_says_verified_compliant_or_safe(self, live_api):
        _, h = live_api.account("cell-f@example.de")
        with live_api.client() as http:
            r = http.post(URL, json=body([machine("1")]), headers=h)
        assert r.status_code == 200


def _manifest_dict(row_dict):
    row = inv.canonical_row(row_dict, 1, frozenset({"SF-01"}))
    fns = inv.parse_functions(FUNCTIONS)
    return inv._manifest_for(row, actor=PERSON, source_system="sap-pm-export",
                             export_date=None, file_sha256="", functions=fns).to_dict()


# -- surfaces -----------------------------------------------------------------------


def test_registered_as_one_capability_with_cli_and_api_and_no_mcp():
    from assurance.capabilities import CAPABILITIES
    cap = next(c for c in CAPABILITIES if c.id == "machinery.import_inventory")
    assert cap.cli == ("machinery import-inventory",)
    assert cap.api == ("POST /v1/machinery/enrol/batch",) and not cap.mcp
    assert cap.gaps["mcp"][0] == "by_design"


@pytest.mark.asyncio
async def test_there_is_no_mcp_tool_for_it():
    pytest.importorskip("mcp", reason="needs the optional assurance-mcp extra")
    from assurance.mcp import server
    names = {t.name for t in await server.mcp.list_tools()}
    assert not [n for n in names if "inventory" in n or "batch" in n or "enrol" in n]


def test_importer_is_not_described_as_a_supported_adapter():
    text = (inv.__doc__ or "").lower()
    assert "not a cmdb connector" in text and "not a supported adapter" in text
