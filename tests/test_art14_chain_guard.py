"""The Article 14 register refuses to read or extend a ledger whose chain does not verify.

Issue #81. Editing one old awareness payload directly in the SQLite file moves every deadline
that runs from it; before this guard the register served the moved deadline as fact and went on
appending to the broken chain. Reads are guarded incrementally, writes with a full walk.
``verify`` and ``export`` keep their own behaviour.
"""

from __future__ import annotations

import importlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import assurance
from assurance.core import Actor
from assurance.core.errors import LedgerIntegrityError
from assurance.core.identity import parse_utc
from assurance.evidence import EvidenceLedger
from assurance.evidence.ledger import ChainBrokenError
from assurance.security.art14 import Art14Register, Awareness, Signal, SignalChannel, Stage, Track
from assurance.security.art14.report import readiness_report

ACTOR_JSON = {"identifier": "m.braun", "role": "Entwicklungsleitung"}
ACTOR = Actor("m.braun", "Entwicklungsleitung")
KEY = "test-key-do-not-ship-0123456789abcdef0123456789"
ORIGINAL = "2026-10-01T09:00:00Z"
SHIFTED = "2026-10-11T09:00:00Z"

SIGNAL = {"received_at": "2026-10-01T08:00:00Z", "channel": "other", "description": "d",
          "actor": ACTOR_JSON}
AWARENESS = {"established_at": ORIGINAL, "assessment_started_at": "2026-10-01T08:00:00Z",
             "assessment_completed_at": ORIGINAL, "track": "actively_exploited_vulnerability",
             "reasoning": "x", "actor": ACTOR_JSON}


def edit_awareness(path) -> None:
    db = sqlite3.connect(path)
    (payload,) = db.execute("SELECT payload FROM chain WHERE kind LIKE '%awareness%'").fetchone()
    assert ORIGINAL in payload
    db.execute("UPDATE chain SET payload=? WHERE kind LIKE '%awareness%'",
               (payload.replace(ORIGINAL, SHIFTED),))
    db.commit()
    db.close()


def build(path) -> Art14Register:
    reg = Art14Register(EvidenceLedger(path))
    reg.record_signal("C1", Signal(received_at=parse_utc("2026-10-01T08:00:00Z"),
                                   channel=SignalChannel.OTHER, received_by="a", description="d"),
                      ACTOR)
    reg.record_awareness(
        "C1",
        Awareness(established_at=parse_utc(ORIGINAL),
                  assessment_started_at=parse_utc("2026-10-01T08:00:00Z"),
                  assessment_completed_at=parse_utc(ORIGINAL), determined_by="a", reasoning="r"),
        Track.VULNERABILITY, ACTOR)
    return reg


@pytest.fixture(autouse=True)
def recheck_every_read(monkeypatch):
    """Make the incremental check a full pass, so a read sees an old-record edit at once.

    With the default 60 s window an old-record edit is only seen by the next full pass; the
    window itself is covered by ``test_writes_never_rely_on_the_window``.
    """
    monkeypatch.setenv("ASSURANCE_CHAIN_RECHECK_SECONDS", "0")


class TestLibrary:
    def test_require_intact_passes_on_a_clean_chain_and_names_the_break(self, tmp_path):
        ledger = build(tmp_path / "l.db").ledger
        ledger.require_intact()
        ledger.require_intact(full=True)
        edit_awareness(tmp_path / "l.db")
        for full in (False, True):
            with pytest.raises(ChainBrokenError, match="seq 2"):
                ledger.require_intact(full=full)
        assert issubclass(ChainBrokenError, LedgerIntegrityError)

    def test_every_register_read_refuses(self, tmp_path):
        reg = build(tmp_path / "l.db")
        edit_awareness(tmp_path / "l.db")
        for read in (lambda: reg.case("C1"), reg.case_ids, reg.cases, reg.survey, reg.breaches,
                     lambda: readiness_report(reg)):
            with pytest.raises(ChainBrokenError):
                read()

    def test_every_register_write_refuses_and_appends_nothing(self, tmp_path):
        from datetime import timedelta

        from assurance.security.art14.model import ProductVersion

        reg = build(tmp_path / "l.db")
        edit_awareness(tmp_path / "l.db")
        before = len(reg.ledger)
        at = parse_utc(SHIFTED)
        writes = [
            lambda: reg.record_signal("C2", Signal(received_at=at, channel=SignalChannel.OTHER,
                                                   received_by="a", description="d"), ACTOR),
            lambda: reg.record_awareness("C1", Awareness(
                established_at=at, assessment_started_at=at - timedelta(hours=1),
                assessment_completed_at=at, determined_by="a", reasoning="r"),
                Track.VULNERABILITY, ACTOR),
            lambda: reg.record_triage("C1", {}, ACTOR, reasoning="r"),
            lambda: reg.record_availability("C1", ProductVersion(product_name="P", version_range="1.0"), ACTOR),
            lambda: reg.record_measure_available("C1", at, "m", ACTOR),
            lambda: reg.record_filing("C1", Stage.EARLY_WARNING, at, {}, ACTOR, now=at),
            lambda: reg.record_user_notification("C1", at, "all", "c", ACTOR),
        ]
        for write in writes:
            with pytest.raises(ChainBrokenError):
                write()
        assert len(reg.ledger) == before

    def test_writes_never_rely_on_the_window(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASSURANCE_CHAIN_RECHECK_SECONDS", "3600")
        reg = build(tmp_path / "l.db")
        reg.case("C1")  # primes the incremental cache for this file
        edit_awareness(tmp_path / "l.db")
        # The incremental read may still serve inside the window; a write must not.
        with pytest.raises(ChainBrokenError):
            reg.record_user_notification("C1", parse_utc(SHIFTED), "all", "c", ACTOR)

    def test_a_clean_ledger_is_unaffected(self, tmp_path):
        reg = build(tmp_path / "l.db")
        assert reg.case_ids() == ["C1"]
        assert reg.case("C1").state == "awaiting_triage"
        assert readiness_report(reg)["ledger"]["chain_verified"] is True

    def test_verify_and_export_behave_as_before(self, tmp_path):
        reg = build(tmp_path / "l.db")
        assert reg.ledger.verify_chain() == (True, [])
        assert len(reg.ledger.export(subject="C1")["entries"]) == 2
        edit_awareness(tmp_path / "l.db")
        ok, problems = reg.ledger.verify_chain()
        assert ok is False and any("seq 2" in p for p in problems)
        with pytest.raises(LedgerIntegrityError):
            reg.ledger.export(subject="C1")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", KEY)
    from assurance.api import deps

    deps._register_for.cache_clear()
    app_module = importlib.import_module("assurance.api.service")
    with TestClient(app_module.create_app()) as c:
        c.headers.update({"X-API-Key": KEY})
        assert c.post("/v1/cases/C1/signal", json=SIGNAL).status_code == 201
        assert c.post("/v1/cases/C1/awareness", json=AWARENESS).status_code == 201
        yield c, tmp_path / "art14.db"


class TestApi:
    def refused(self, response):
        assert response.status_code == 500, response.text
        assert response.json()["detail"]["error"] == "ledger_integrity"
        assert "does not verify" in response.json()["detail"]["detail"]

    def test_every_read_is_refused_with_a_structured_error(self, client):
        c, path = client
        assert "2026-10-02T09:00:00Z" in str(c.get("/v1/cases/C1").json())
        edit_awareness(path)
        for url in ("/v1/cases/C1", "/v1/cases", "/v1/register", "/v1/register/breaches"):
            self.refused(c.get(url))

    def test_every_write_is_refused_and_appends_nothing(self, client):
        c, path = client
        edit_awareness(path)
        before = c.get("/v1/ledger/verify").json()["attestation"]["length"]
        bodies = {
            "C2/signal": SIGNAL,
            "C1/triage": {"answers": {}, "actor": ACTOR_JSON},
            "C1/availability": {"product_name": "P", "actor": ACTOR_JSON},
            "C1/measure": {"available_at": "2026-10-02T10:00:00Z", "description": "m",
                           "actor": ACTOR_JSON},
            "C1/filings": {"stage": "early_warning", "submitted_at": "2026-10-02T10:00:00Z",
                           "payload": {}, "actor": ACTOR_JSON},
            "C1/user-notification": {"at": "2026-10-12T10:00:00Z", "scope": "all", "content": "c",
                                     "actor": ACTOR_JSON},
            "C3/awareness": AWARENESS,
        }
        for route, body in bodies.items():
            self.refused(c.post(f"/v1/cases/{route}", json=body))
        verified = c.get("/v1/ledger/verify").json()
        assert verified["attestation"]["length"] == before

    def test_verify_still_reports_the_break_and_answers_200(self, client):
        c, path = client
        edit_awareness(path)
        response = c.get("/v1/ledger/verify")
        assert response.status_code == 200
        assert response.json()["verified"] is False


class TestCli:
    def run(self, path, *args):
        env = {**os.environ, "PYTHONPATH": str(Path(assurance.__file__).resolve().parent.parent)}
        return subprocess.run(  # noqa: S603 - fixed argv, test-owned paths
            [sys.executable, "-m", "assurance.security.art14.cli", "--ledger", str(path), *args],
            capture_output=True, text=True, env=env, check=False)

    def test_a_clean_ledger_reads(self, tmp_path):
        build(tmp_path / "l.db")
        run = self.run(tmp_path / "l.db", "case", "C1")
        assert run.returncode == 0 and "2026-10-02T09:00:00Z" in run.stdout

    def test_reads_exit_non_zero_with_a_clear_message_and_print_no_case(self, tmp_path):
        build(tmp_path / "l.db")
        edit_awareness(tmp_path / "l.db")
        for args in (("case", "C1"), ("case", "C1", "--json"), ("register",),
                     ("register", "--json")):
            run = self.run(tmp_path / "l.db", *args)
            assert run.returncode != 0, args
            assert "does not verify" in run.stderr, run.stderr
            assert "2026-10-12T09:00:00Z" not in run.stdout  # the moved deadline is never shown

    def test_writes_exit_non_zero_and_append_nothing(self, tmp_path):
        reg = build(tmp_path / "l.db")
        edit_awareness(tmp_path / "l.db")
        before = len(reg.ledger)
        run = self.run(tmp_path / "l.db", "signal", "C2", "--by", "t:analyst", "--at",
                       "2026-10-02T08:00:00Z", "--description", "after edit")
        assert run.returncode != 0 and "does not verify" in run.stderr
        assert len(reg.ledger) == before

    def test_verify_still_exits_1_and_names_the_edit(self, tmp_path):
        build(tmp_path / "l.db")
        edit_awareness(tmp_path / "l.db")
        run = self.run(tmp_path / "l.db", "verify")
        assert run.returncode == 1 and "CHAIN VERIFICATION FAILED" in run.stderr

    def test_a_bad_timestamp_is_refused_before_anything_is_written(self, tmp_path):
        reg = build(tmp_path / "l.db")
        before = len(reg.ledger)
        for bad in ("2026-10-02", "2026-10-02T08:00:00", "9999-12-31T23:59:59Z"):
            run = self.run(tmp_path / "l.db", "signal", "C2", "--by", "t:analyst", "--at", bad,
                           "--description", "d")
            assert run.returncode == 2 and "--at" in run.stderr, (bad, run.stderr)
        assert len(reg.ledger) == before
