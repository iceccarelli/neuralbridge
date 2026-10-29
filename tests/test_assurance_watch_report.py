"""Reporting Watch results to the customer's own hosted ledger.

``POST /v1/watch/report`` and ``GET /v1/fleet/observations`` exist so a paying
customer can see the thing they pay for: the last successful observation, the
attempts that failed and the machines nobody has looked at lately. Everything
here runs the real engines — collection plans over synthetic vendor exports,
the manifest ledger, ``compare()``, ``assess_drift``, the case store — and the
real per-account ledgers behind ``get_register``. The properties pinned are the
ones that make the feature honest:

* a failed look is recorded as a failed look and never as a positive one;
* the hosted side adds no finding of its own: a case it opens is the case
  ``assess_drift`` opens for the same manifests;
* a retry writes nothing; an older report cannot rewind the record;
* one tenant's report is never another tenant's data.
"""

from __future__ import annotations

import importlib
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.change import CaseStatus, CaseStore, assess_drift
from assurance.change.store import CASE_KINDS
from assurance.collect.collector import collect
from assurance.collect.plan import CollectionPlan
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import HashSource, ManifestSource
from assurance.machinery.record import manifests_from_ledger, record_manifest
from assurance.watch.ingest import ingest_report
from assurance.watch.observations import fleet_observations
from assurance.watch.runner import _last_observation_at

from .support import plan_dict, write_export

OPERATOR_KEY = "operator-key-test-watch-report"
KEY_0412 = "Grimaldi/AR-7#0412"
KEY_0501 = "Grimaldi/AR-7#0501"
SCANNER = Actor("assurance-watch", "scheduled watch", "automation")


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- building reports from the real collector --------------------------------

_counter = {"n": 0}


def make_manifest(base: Path, serial: str = "0412", *, fw: bytes = b"firmware 3.8.2",
                  when: datetime | None = None) -> dict:
    """A real manifest: the collection plan run over synthetic vendor exports."""
    _counter["n"] += 1
    root = base / f"exports-{serial}-{_counter['n']}"
    write_export(root, stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181", fw=fw)
    plan = CollectionPlan.from_dict(plan_dict())
    result = collect(plan, root, serial=serial, taken_by=SCANNER, site="Plant 2",
                     country="DE", source=ManifestSource.AS_FOUND,
                     taken_at=when or now(),
                     # The harness plays a collector running ON the machine; an export
                     # folder is no longer labelled that implicitly (B6).
                     hash_source=HashSource.READ_FROM_MACHINE)
    return result.manifest.to_dict()


def good(manifest: dict, *, at: datetime, status: str = "unchanged", detail: str = "",
         keep_taken_at: bool = False) -> dict:
    """A positive entry. The manifest is stamped as taken at the observation, as a run does."""
    if not keep_taken_at:
        manifest = {**manifest, "taken_at": iso(at)}
    m = manifest["machine"]
    return {"serial": m["serial"],
            "machine_key": f"{m['manufacturer']}/{m['model']}#{m['serial']}",
            "status": status, "observed_at": iso(at), "collection_complete": True,
            "manifest": manifest, "detail": detail}


def failed(serial: str, *, at: datetime, status: str = "uncollectable",
           key: str | None = None, detail: str = "could not be collected") -> dict:
    return {"serial": serial, "machine_key": key if key is not None else f"Grimaldi/AR-7#{serial}",
            "status": status, "observed_at": iso(at), "collection_complete": False,
            "manifest": None, "detail": detail,
            "missing_items": ["ITM-PLC"] if status == "incomplete" else []}


def report(*machines: dict, started: datetime | None = None, watch_id: str = "WATCH-T",
           max_age_hours: float | None = None, **extra) -> dict:
    body = {"watch_id": watch_id, "run_started_at": iso(started or now()),
            "machines": list(machines)}
    if max_age_hours is not None:
        body["max_age_hours"] = max_age_hours
    body.update(extra)
    return body


# -- fixtures ------------------------------------------------------------------

@pytest.fixture(name="env")
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "shared" / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.delenv("ASSURANCE_MAX_BODY_BYTES", raising=False)
    for cache in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
        cache.cache_clear()
    yield tmp_path
    for cache in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
        cache.cache_clear()


@pytest.fixture(name="client")
def _client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


@pytest.fixture(name="accounts")
def _accounts(client):
    return deps.get_accounts()


def account(accounts, tier="cell", email="a@example.de"):
    acct = accounts.upsert_account(email=email, tier=tier, stripe_customer_id=f"cus_{email}")
    return acct, {"X-API-Key": accounts.issue_key(acct.id)}


@pytest.fixture(name="cell")
def _cell(accounts):
    return account(accounts, "cell", "cell@example.de")


def _chain_head(ledger) -> dict:
    """The head of a chain, without the wall-clock `attested_at` stamp.

    `head_attestation()` carries the moment it was produced (one-second
    resolution), so two calls straddling a second boundary differ although the
    chain did not move. What a test means to compare is the head.
    """
    return {k: v for k, v in ledger.head_attestation().items() if k != "attested_at"}


def ledger_of(acct) -> EvidenceLedger:
    return EvidenceLedger(deps.tenant_ledger_path(acct.id))


def enroll_manifest(acct, base, serial="0412", model=None):
    """A machine the account already knows: a manifest in its own ledger.

    A failed look is only ever recorded against an enrolled machine, so tests of
    failures begin from one.
    """
    from assurance.machinery.manifest import SafetyManifest

    raw = make_manifest(base, serial)
    if model:
        raw["machine"]["model"] = model
    record_manifest(ledger_of(acct), SafetyManifest.from_dict(raw))


def post(client, headers, body):
    return client.post("/v1/watch/report", headers=headers, json=body)


def observations(client, headers):
    r = client.get("/v1/fleet/observations", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def machine_row(client, headers, key):
    return next(m for m in observations(client, headers)["machines"] if m["machine"] == key)


def case_entries(ledger):
    return [e for e in ledger.entries() if e.kind in CASE_KINDS]


# =====================================================================
# the boundary: who may call, and what a body may be
# =====================================================================

class TestAccess:
    def test_no_key_is_401_on_both_routes(self, client, tmp_path):
        body = report(failed("0412", at=now()))
        assert client.post("/v1/watch/report", json=body).status_code == 401
        assert client.get("/v1/fleet/observations").status_code == 401

    def test_a_wrong_key_is_401(self, client):
        h = {"X-API-Key": "asr_not_a_real_key"}
        assert post(client, h, report(failed("0412", at=now()))).status_code == 401
        assert client.get("/v1/fleet/observations", headers=h).status_code == 401

    def test_register_tier_is_402_on_both_routes_and_writes_nothing(self, client, accounts):
        acct, h = account(accounts, "register", "reg@example.de")
        r = post(client, h, report(failed("0412", at=now())))
        assert r.status_code == 402
        assert r.json()["detail"]["error"] == "plan_does_not_include_machine_verification"
        assert client.get("/v1/fleet/observations", headers=h).status_code == 402
        assert len(ledger_of(acct)) == 0

    def test_an_oversize_body_is_413_and_writes_nothing(self, client, cell):
        acct, h = cell
        body = report(failed("0412", at=now(), detail="x" * 100))
        body["padding"] = "p" * (1024 * 1024 + 10)
        r = client.post("/v1/watch/report", headers=h, json=body)
        assert r.status_code == 413
        assert r.json()["detail"]["error"] == "request_too_large"
        assert len(ledger_of(acct)) == 0

    def test_a_fleet_of_200_machines_fits_under_the_default_cap(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(hours=1)
        from assurance.machinery.manifest import SafetyManifest
        base = make_manifest(tmp_path, "0000")
        for n in range(200):
            raw = {**base, "machine": {**base["machine"], "serial": f"{n:04d}"}}
            record_manifest(ledger_of(acct), SafetyManifest.from_dict(raw))
        machines = [failed(f"{n:04d}", at=t, detail="could not be collected: no export folder")
                    for n in range(200)]
        raw = json.dumps(report(*machines, max_age_hours=168))
        assert len(raw.encode()) < 1024 * 1024
        r = client.post("/v1/watch/report", headers={**h, "content-type": "application/json"},
                        content=raw)
        assert r.status_code == 200, r.text[:300]
        assert r.json()["summary"]["recorded"] == 200

    def test_more_than_200_machines_in_one_report_is_422(self, client, cell):
        _, h = cell
        t = now() - timedelta(hours=1)
        machines = [failed(f"{n:04d}", at=t) for n in range(201)]
        assert post(client, h, report(*machines)).status_code == 422

    @pytest.mark.parametrize("mutate", [
        lambda b: b.update(surprise=1),
        lambda b: b["machines"][0].update(surprise=1),
        lambda b: b["machines"][0].update(status="fine"),
        lambda b: b.update(machines=[]),
        lambda b: b.update(watch_id=""),
        lambda b: b.update(run_started_at="yesterday"),
        lambda b: b.update(run_started_at="2026-10-01T06:00:00"),   # naive: refuses to guess
        lambda b: b["machines"][0].update(observed_at="2026-10-01T06:00:00"),
        lambda b: b.update(max_age_hours=0),
        lambda b: b.update(max_age_hours=-5),
        lambda b: b.update(batch_index=1),
        lambda b: b["machines"][0].update(detail="d" * 2001),
        lambda b: b["machines"][0].update(collection_complete="maybe"),
    ])
    def test_malformed_bodies_are_422_and_write_nothing(self, client, cell, mutate):
        acct, h = cell
        body = report(failed("0412", at=now() - timedelta(minutes=5)))
        mutate(body)
        assert post(client, h, body).status_code == 422
        assert len(ledger_of(acct)) == 0

    def test_a_report_started_in_the_future_is_422(self, client, cell):
        acct, h = cell
        body = report(failed("0412", at=now()), started=now() + timedelta(hours=2))
        r = post(client, h, body)
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "run_started_at_in_future"
        assert len(ledger_of(acct)) == 0


# =====================================================================
# failure to observe is explicit, and never a positive observation
# =====================================================================

class TestFailureIsExplicit:
    def test_uncollectable_is_recorded_as_exactly_that(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0501")
        r = post(client, h, report(failed("0501", at=now() - timedelta(minutes=3))))
        m = r.json()["machines"][0]
        assert (m["outcome"], m["recorded_status"]) == ("recorded", "uncollectable")
        assert m["counts_as_observation"] is False
        body = [e.evidence().body for e in ledger_of(acct).entries(kind="watch.observation")][0]
        assert body["status"] == "uncollectable" and body["complete"] is False
        row = machine_row(client, h, KEY_0501)
        assert row["last_successful_observation_at"] is None
        assert row["last_attempt_status"] == "uncollectable"
        assert row["last_attempt_succeeded"] is False
        assert row["stale"] is True and row["stale_reason"] == "never_successfully_observed"
        assert row["consecutive_failed_attempts"] == 1

    def test_incomplete_is_recorded_as_incomplete_and_is_not_a_look(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0501")
        post(client, h, report(failed("0501", at=now() - timedelta(minutes=3), status="incomplete")))
        row = machine_row(client, h, KEY_0501)
        assert row["last_attempt_status"] == "incomplete"
        assert row["last_successful_observation_at"] is None and row["stale"] is True

    def test_a_failed_attempt_after_a_good_one_does_not_replace_it(self, client, cell, tmp_path):
        acct, h = cell
        good_at = now() - timedelta(hours=30)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=good_at),
                               started=good_at, max_age_hours=24))
        bad_at = now() - timedelta(hours=1)
        post(client, h, report(failed("0412", at=bad_at), started=bad_at, max_age_hours=24))
        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_observation_at"] == iso(good_at)
        assert row["last_attempt_at"] == iso(bad_at)
        assert row["last_attempt_status"] == "uncollectable"
        assert row["stale"] is True and row["stale_reason"] == "older_than_cadence"
        assert row["consecutive_failed_attempts"] == 1

    def test_the_runners_own_staleness_code_reads_the_hosted_ledger_the_same_way(
            self, client, cell, tmp_path):
        acct, h = cell
        good_at = now() - timedelta(hours=40)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=good_at),
                               failed("0501", at=now() - timedelta(hours=1))))
        post(client, h, report(failed("0412", at=now() - timedelta(hours=1))))
        ledger = ledger_of(acct)
        assert _last_observation_at(ledger, "0412") == good_at
        assert _last_observation_at(ledger, "0501") is None

    def test_an_incomplete_look_is_not_a_look_to_the_runners_staleness_code_either(
            self, client, cell, tmp_path):
        acct, h = cell
        post(client, h, report(failed("0501", at=now() - timedelta(hours=2), status="incomplete")))
        assert _last_observation_at(ledger_of(acct), "0501") is None

    def test_consecutive_failures_count_and_a_success_resets_them(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        for hours in (50, 40, 30):
            post(client, h, report(failed("0412", at=now() - timedelta(hours=hours))))
        assert machine_row(client, h, KEY_0412)["consecutive_failed_attempts"] == 3
        recovered = now() - timedelta(hours=5)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=recovered)))
        row = machine_row(client, h, KEY_0412)
        assert row["consecutive_failed_attempts"] == 0
        assert row["last_attempt_succeeded"] is True and row["stale"] is False

    def test_a_failed_look_cannot_carry_a_manifest(self, client, cell, tmp_path):
        acct, h = cell
        entry = failed("0412", at=now() - timedelta(minutes=2))
        entry["manifest"] = make_manifest(tmp_path, "0412")
        m = post(client, h, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "manifest_not_accepted")
        assert len(ledger_of(acct)) == 0

    @pytest.mark.parametrize("status,flag,reason", [
        ("unchanged", False, "inconsistent_collection_flag"),
        ("changed", False, "inconsistent_collection_flag"),
        ("uncollectable", True, "inconsistent_collection_flag"),
        ("incomplete", True, "inconsistent_collection_flag"),
    ])
    def test_a_status_that_contradicts_its_completeness_flag_is_refused(
            self, client, cell, tmp_path, status, flag, reason):
        acct, h = cell
        if status in ("unchanged", "changed"):
            entry = good(make_manifest(tmp_path), at=now() - timedelta(minutes=2), status=status)
        else:
            entry = failed("0412", at=now() - timedelta(minutes=2), status=status)
        entry["collection_complete"] = flag
        m = post(client, h, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", reason)
        assert len(ledger_of(acct)) == 0

    def test_a_positive_look_without_its_manifest_is_refused(self, client, cell, tmp_path):
        acct, h = cell
        entry = good(make_manifest(tmp_path), at=now() - timedelta(minutes=2))
        entry["manifest"] = None
        m = post(client, h, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "manifest_required")

    def test_a_manifest_that_says_its_collection_was_incomplete_cannot_be_positive(
            self, client, cell, tmp_path):
        acct, h = cell
        manifest = make_manifest(tmp_path)
        manifest["notes"] = "[collection incomplete: ITM-PLC not collected]"
        m = post(client, h, report(good(manifest, at=now() - timedelta(minutes=2)))
                 ).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "manifest_marked_incomplete")
        assert len(ledger_of(acct)) == 0

    def test_an_uncollectable_machine_never_moves_an_open_case(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(days=2)
        post(client, h, report(good(make_manifest(tmp_path), at=t), started=t))
        t2 = now() - timedelta(days=1)
        r = post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                        status="changed"), started=t2))
        case_id = r.json()["machines"][0]["case_id"]
        ledger = ledger_of(acct)
        before = (CaseStore(ledger).get(case_id), len(case_entries(ledger)))
        assert before[0].status is CaseStatus.OPEN

        for status in ("uncollectable", "incomplete"):
            m = post(client, h, report(failed("0412", at=now() - timedelta(minutes=1), status=status
                                              ))).json()["machines"][0]
            assert m["case_id"] == "" and m["case_status"] == ""
            assert case_id in m["open_case_ids"]            # named, left exactly where it was
            ledger = ledger_of(acct)
            assert CaseStore(ledger).get(case_id) == before[0]
            assert len(case_entries(ledger)) == before[1]

    def test_nothing_a_report_does_can_close_a_case(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(days=3)
        post(client, h, report(good(make_manifest(tmp_path), at=t), started=t))
        t2 = now() - timedelta(days=2)
        r = post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                        status="changed"), started=t2))
        case_id = r.json()["machines"][0]["case_id"]
        # A later look that is perfectly clean — same, drifted configuration — is
        # not a reason for the case to move: only a person with evidence closes it.
        t3 = now() - timedelta(hours=1)
        post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t3), started=t3))
        case = CaseStore(ledger_of(acct)).get(case_id)
        assert case.status is CaseStatus.OPEN
        kinds = {h["kind"] for h in case.history}
        assert kinds <= {"assurance.change.opened", "assurance.change.updated"}
        for entry in case_entries(ledger_of(acct)):
            assert entry.evidence().actor.kind == "automation"


# =====================================================================
# staleness against a declared cadence
# =====================================================================

class TestStale:
    def test_stale_is_judged_against_the_declared_cadence(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(hours=30)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=t),
                               good(make_manifest(tmp_path, "0501"), at=now() - timedelta(hours=10)),
                               started=t, max_age_hours=24))
        data = observations(client, h)
        rows = {m["machine"]: m for m in data["machines"]}
        assert rows[KEY_0412]["cadence_hours"] == 24 and rows[KEY_0412]["cadence_declared"] is True
        assert rows[KEY_0412]["stale"] is True
        assert rows[KEY_0412]["age_hours"] == pytest.approx(30, abs=0.1)
        assert rows[KEY_0501]["stale"] is False and rows[KEY_0501]["stale_reason"] == ""
        assert data["summary"]["stale"] == 1

    def test_the_default_cadence_is_168_hours_until_one_is_declared(self, client, cell, tmp_path):
        acct, h = cell
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=now() - timedelta(hours=100))))
        post(client, h, report(good(make_manifest(tmp_path, "0501"), at=now() - timedelta(hours=200))))
        data = observations(client, h)
        assert data["default_cadence_hours"] == 168
        rows = {m["machine"]: m for m in data["machines"]}
        assert all(r["cadence_hours"] == 168 and r["cadence_declared"] is False for r in rows.values())
        assert rows[KEY_0412]["stale"] is False and rows[KEY_0501]["stale"] is True

    def test_a_late_older_report_cannot_move_a_machines_cadence(self, client, cell, tmp_path):
        acct, h = cell
        new = now() - timedelta(hours=2)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=new), started=new,
                               max_age_hours=24))
        old = now() - timedelta(days=3)
        late = post(client, h, report(good(make_manifest(tmp_path, "0412"), at=old), started=old,
                                      max_age_hours=720)).json()
        assert late["machines"][0]["reason"] == "superseded_by_newer_observation"
        assert machine_row(client, h, KEY_0412)["cadence_hours"] == 24

    def test_an_enrolled_machine_nobody_ever_reported_is_stale_and_says_so(
            self, client, cell, tmp_path):
        acct, h = cell
        record_manifest(ledger_of(acct), _manifest_obj(tmp_path, "0777"))
        data = observations(client, h)
        assert data["reporting"] is False
        row = data["machines"][0]
        assert row["machine"] == "Grimaldi/AR-7#0777"
        assert row["reported"] is False and row["last_attempt_at"] is None
        assert row["stale"] is True and row["stale_reason"] == "never_reported"
        assert data["summary"]["never_reported"] == 1

    def test_an_empty_ledger_reports_nothing_rather_than_something_invented(self, client, cell):
        _, h = cell
        data = observations(client, h)
        assert data["machines"] == [] and data["reporting"] is False
        assert data["summary"]["machines"] == 0


def _manifest_obj(base, serial):
    from assurance.machinery.manifest import SafetyManifest
    return SafetyManifest.from_dict(make_manifest(base, serial))


# =====================================================================
# the hosted side derives no finding of its own
# =====================================================================

class TestSameDomainFunctions:
    def test_a_changed_manifest_opens_exactly_the_case_assess_drift_opens(
            self, client, cell, tmp_path):
        acct, h = cell
        base = make_manifest(tmp_path, fw=b"firmware 3.8.2")
        moved = make_manifest(tmp_path, fw=b"firmware 3.9.0")
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)

        r1 = post(client, h, report(good(base, at=t1), started=t1)).json()["machines"][0]
        assert (r1["recorded_status"], r1["case_id"]) == ("first_seen", "")
        r2 = post(client, h, report(good(moved, at=t2, status="changed"), started=t2)
                  ).json()["machines"][0]
        assert r2["recorded_status"] == "changed" and r2["case_opened"] is True
        hosted = CaseStore(ledger_of(acct)).get(r2["case_id"])

        # The reference: the very function and the very inputs, on a fresh ledger.
        ref_ledger = EvidenceLedger(tmp_path / "reference.db")
        from assurance.machinery.manifest import SafetyManifest
        b, o = SafetyManifest.from_dict(base), SafetyManifest.from_dict(moved)
        record_manifest(ref_ledger, b)
        reference = assess_drift(CaseStore(ref_ledger), compare(b, o), o, [], [],
                                 actor=Actor("ref", "scheduled watch", "automation"))
        assert hosted.case_id == reference.case_id
        assert hosted.changed_items == reference.changed_items
        assert hosted.affected_functions == reference.affected_functions
        assert hosted.required_actions == reference.required_actions
        assert hosted.after_hash == reference.after_hash and hosted.before_hash == reference.before_hash

        # And it is the case /v1/change serves, in the same ledger.
        listed = client.get("/v1/change/cases", headers=h).json()["cases"]
        assert [c["case_id"] for c in listed] == [r2["case_id"]]

    def test_the_status_the_reporter_claims_is_not_trusted(self, client, cell, tmp_path):
        acct, h = cell
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)
        post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.8.2"), at=t1)))
        # "unchanged" over a manifest that moved: this ledger compares, and a case opens.
        m = post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                        status="unchanged"))).json()["machines"][0]
        assert (m["reported_status"], m["recorded_status"]) == ("unchanged", "changed")
        assert m["case_id"] and "reporter said" in m["detail"]
        # "changed" over a manifest identical to what is held: no case, no new manifest.
        t3 = now() - timedelta(hours=1)
        n = len(manifests_from_ledger(ledger_of(acct), KEY_0412))
        m = post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t3,
                                        status="changed"))).json()["machines"][0]
        assert m["recorded_status"] == "observed" and m["case_opened"] is False
        assert len(manifests_from_ledger(ledger_of(acct), KEY_0412)) == n

    def test_a_first_manifest_is_a_baseline_not_a_finding(self, client, cell, tmp_path):
        acct, h = cell
        m = post(client, h, report(good(make_manifest(tmp_path), at=now() - timedelta(minutes=5),
                                        status="changed"))).json()["machines"][0]
        assert m["recorded_status"] == "first_seen" and m["case_id"] == ""
        assert client.get("/v1/change/cases", headers=h).json()["cases"] == []
        assert len(manifests_from_ledger(ledger_of(acct), KEY_0412)) == 1

    def test_a_drift_that_is_not_safety_relevant_opens_no_case(self, client, cell, tmp_path):
        acct, h = cell
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)
        a = make_manifest(tmp_path)
        post(client, h, report(good(a, at=t1)))
        b = json.loads(json.dumps(a))
        for item in b["items"]:
            if item["item_id"] == "ITM-ZONES":
                item["name"] = "Safety scanner zone set (renamed)"
        m = post(client, h, report(good(b, at=t2, status="changed"))).json()["machines"][0]
        assert m["recorded_status"] == "changed" and m["case_id"] == ""


# =====================================================================
# idempotent, and order-safe
# =====================================================================

class TestRetryAndOrder:
    def test_replaying_a_report_writes_nothing_and_opens_no_second_case(
            self, client, cell, tmp_path):
        acct, h = cell
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)
        post(client, h, report(good(make_manifest(tmp_path), at=t1),
                               good(make_manifest(tmp_path, "0501"), at=t1), started=t1))
        moved = report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2, status="changed"),
                       failed("0501", at=t2), started=t2, max_age_hours=100)
        first = post(client, h, moved).json()
        ledger = ledger_of(acct)
        length = len(ledger)
        cases = len(case_entries(ledger))

        for _ in range(3):
            again = post(client, h, moved).json()
            assert [m["outcome"] for m in again["machines"]] == ["already_recorded"] * 2
            assert again["report_recorded"] is False
            assert again["cases_opened"] == []
        assert len(ledger_of(acct)) == length
        assert len(case_entries(ledger_of(acct))) == cases
        assert len(client.get("/v1/change/cases", headers=h).json()["cases"]) == 1
        assert first["cases_opened"] and first["report_recorded"] is True

    def test_a_retry_that_spells_the_same_instant_differently_is_still_a_retry(
            self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        t = now() - timedelta(hours=2)
        entry = failed("0412", at=t)
        post(client, h, report(entry, started=t))
        length = len(ledger_of(acct))
        entry2 = dict(entry, observed_at=t.strftime("%Y-%m-%dT%H:%M:%S+00:00"))
        m = post(client, h, report(entry2, started=t)).json()["machines"][0]
        assert m["outcome"] == "already_recorded"
        assert len(ledger_of(acct)) == length

    def test_an_older_report_arriving_late_is_ignored(self, client, cell, tmp_path):
        acct, h = cell
        t_new, t_old = now() - timedelta(hours=1), now() - timedelta(hours=30)
        post(client, h, report(good(make_manifest(tmp_path), at=t_new), started=t_new))
        length = len(ledger_of(acct))
        r = post(client, h, report(failed("0412", at=t_old), started=t_old)).json()
        m = r["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "superseded_by_newer_observation")
        assert len(ledger_of(acct)) == length
        row = machine_row(client, h, KEY_0412)
        assert row["last_attempt_status"] == "first_seen"      # not rewound to the old failure
        assert row["last_attempt_at"] == iso(t_new)

    def test_a_different_observation_at_a_recorded_instant_conflicts(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        t = now() - timedelta(hours=2)
        post(client, h, report(failed("0412", at=t, detail="no folder")))
        m = post(client, h, report(failed("0412", at=t, detail="a different story")))\
            .json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "conflicts_with_recorded_observation")

    def test_entries_in_one_report_are_applied_oldest_first(self, client, cell, tmp_path):
        acct, h = cell
        good_at, bad_at = now() - timedelta(days=9), now() - timedelta(hours=1)
        # The newer failure is listed first on purpose: it must not make the older
        # success look "older than recorded".
        r = post(client, h, report(failed("0412", at=bad_at),
                                   good(make_manifest(tmp_path), at=good_at),
                                   started=bad_at)).json()
        assert [m["outcome"] for m in r["machines"]] == ["recorded", "recorded"]
        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_observation_at"] == iso(good_at)
        assert row["last_attempt_status"] == "uncollectable"

    def test_a_crash_between_the_case_and_the_manifest_leaves_a_retry_with_one_case(
            self, env, tmp_path, monkeypatch):
        ledger = EvidenceLedger(tmp_path / "crash.db")
        actor = Actor("hosted-watch-report", "watch report via account acc_x", "automation")
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)
        ingest_report(ledger, _plain(report(good(make_manifest(tmp_path), at=t1), started=t1)),
                      actor=actor)
        moved = _plain(report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                   status="changed"), started=t2))

        from assurance.watch import ingest
        real = ingest.record_manifest
        calls = {"n": 0}

        def die_once(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("process died after the case was opened")
            return real(*a, **k)

        monkeypatch.setattr(ingest, "record_manifest", die_once)
        with pytest.raises(RuntimeError):
            ingest_report(ledger, moved, actor=actor)
        assert len([e for e in case_entries(ledger) if e.kind.endswith("opened")]) == 1
        # The baseline is still the old one, so the retry sees the same drift.
        retried = ingest_report(ledger, moved, actor=actor)
        assert retried.results[0].outcome == "recorded"
        assert len([e for e in case_entries(ledger) if e.kind.endswith("opened")]) == 1
        assert len(CaseStore(ledger).list()) == 1

    def test_two_overlapping_identical_retries_write_one_set_of_records(
            self, env, tmp_path):
        ledger = EvidenceLedger(tmp_path / "race.db")
        actor = Actor("hosted-watch-report", "watch report via account acc_x", "automation")
        body = _plain(report(good(make_manifest(tmp_path), at=now() - timedelta(hours=1)),
                             good(make_manifest(tmp_path, "0501"), at=now() - timedelta(hours=1))))
        results = []

        def go():
            results.append(ingest_report(ledger, body, actor=actor))

        threads = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        recorded = sum(1 for r in results for m in r.results if m.outcome == "recorded")
        assert recorded == 2
        assert len(ledger.entries(kind="watch.observation")) == 2
        assert ledger.verify_chain()[0] is True


def _plain(body: dict) -> dict:
    """What the route hands the domain function: the validated body, as a dict."""
    from assurance.api.watch_routes import WatchReportIn
    return WatchReportIn.model_validate(body).model_dump(mode="json")


# =====================================================================
# time
# =====================================================================

class TestTime:
    def test_an_observation_from_the_future_is_refused(self, client, cell, tmp_path):
        acct, h = cell
        entry = failed("0412", at=now() + timedelta(hours=3))
        m = post(client, h, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "observed_at_in_future")
        assert len(ledger_of(acct)) == 0

    def test_a_small_clock_skew_is_tolerated(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        entry = failed("0412", at=now() + timedelta(seconds=30))
        assert post(client, h, report(entry)).json()["machines"][0]["outcome"] == "recorded"

    def test_a_manifest_taken_after_its_observation_is_refused(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(days=1)
        manifest = make_manifest(tmp_path, when=now() - timedelta(hours=1))
        m = post(client, h, report(good(manifest, at=t, keep_taken_at=True))).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "manifest_taken_after_observation")

    def test_an_old_manifest_replayed_as_a_fresh_look_is_not_an_observation(self, client, cell, tmp_path):
        """A 400-day-old manifest with observed_at=now is a replay, not a look."""
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        manifest = make_manifest(tmp_path, when=now() - timedelta(days=400))
        entry = good(manifest, at=now() - timedelta(minutes=1), keep_taken_at=True)
        m = post(client, h, report(entry)).json()["machines"][0]
        assert m["outcome"] == "recorded"
        assert m["reason"] == "manifest_stale"
        assert m["recorded_status"] == "manifest_stale"
        assert m["counts_as_observation"] is False
        assert 399 * 24 < m["manifest_age_hours"] < 401 * 24

        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_observation_at"] is None
        assert row["stale"] is True
        assert row["stale_reason"] == "never_successfully_observed"
        assert row["last_attempt_status"] == "manifest_stale"
        assert row["last_attempt_succeeded"] is False
        assert 399 * 24 < row["last_attempt_manifest_age_hours"] < 401 * 24
        assert len(case_entries(ledger_of(acct))) == 0

    def test_a_stale_manifest_does_not_move_the_baseline_or_open_a_case(self, client, cell, tmp_path):
        acct, h = cell
        t0 = now() - timedelta(days=2)
        post(client, h, report(good(make_manifest(tmp_path), at=t0), started=t0))
        before = len(manifests_from_ledger(ledger_of(acct), KEY_0412))
        old = make_manifest(tmp_path, fw=b"firmware 3.9.0", when=now() - timedelta(days=300))
        m = post(client, h, report(good(old, at=now() - timedelta(minutes=1), status="changed",
                                        keep_taken_at=True))).json()["machines"][0]
        assert m["reason"] == "manifest_stale"
        assert len(manifests_from_ledger(ledger_of(acct), KEY_0412)) == before
        assert case_entries(ledger_of(acct)) == []
        row = machine_row(client, h, KEY_0412)
        # the earlier genuine look is still the last successful one
        assert row["last_successful_observation_at"] == iso(t0)

    def test_the_window_is_the_declared_cadence(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        taken = now() - timedelta(hours=30)
        entry = good(make_manifest(tmp_path, when=taken), at=now() - timedelta(minutes=1),
                     keep_taken_at=True)
        # 30 h old against a 24 h cadence: stale. The same manifest in a 48 h cadence: fresh.
        stale = post(client, h, report(entry, max_age_hours=24)).json()["machines"][0]
        assert stale["reason"] == "manifest_stale"
        entry2 = good(make_manifest(tmp_path, when=taken), at=now() - timedelta(seconds=30),
                      keep_taken_at=True)
        fresh = post(client, h, report(entry2, max_age_hours=48, watch_id="W2")).json()["machines"][0]
        assert fresh["counts_as_observation"] is True and fresh["reason"] == ""
        assert 29 < fresh["manifest_age_hours"] < 31

    def test_a_manifest_as_old_as_the_default_window_is_stale_for_an_undeclared_cadence(
            self, client, cell, tmp_path):
        from assurance.watch.observations import DEFAULT_CADENCE_HOURS

        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        taken = now() - timedelta(hours=DEFAULT_CADENCE_HOURS + 5)
        entry = good(make_manifest(tmp_path, when=taken), at=now() - timedelta(minutes=1),
                     keep_taken_at=True)
        assert post(client, h, report(entry)).json()["machines"][0]["reason"] == "manifest_stale"

    def test_a_stale_manifest_for_an_unenrolled_machine_is_refused_not_enrolled(
            self, client, cell, tmp_path):
        acct, h = cell
        manifest = make_manifest(tmp_path, when=now() - timedelta(days=400))
        m = post(client, h, report(good(manifest, at=now() - timedelta(minutes=1),
                                        keep_taken_at=True))).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "manifest_stale")
        assert len(ledger_of(acct)) == 0

    # -- manifest_relayed is a claim, honoured only for a manifest this account holds ----
    #
    # Before: `manifest_relayed: true` skipped the staleness check for ANY manifest, so
    # a 60-day-old fabricated manifest with a current observed_at was recorded as an
    # observation and the machine read fresh. That used to be pinned as intended
    # (`test_a_relayed_manifest_counts_but_its_age_is_recorded_and_shown`). It is not:
    # the server cannot tell a relayed manifest from one invented for the occasion, so it
    # honours the mark only when its own ledger already holds that exact manifest.

    def test_a_relayed_flag_on_a_manifest_the_account_never_held_does_not_count(
            self, client, cell, tmp_path):
        """The old test's input, with the corrected expectation."""
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        # a DIFFERENT configuration: the same one would be honoured (same_configuration_held)
        manifest = make_manifest(tmp_path, fw=b"firmware 9.9.9", when=now() - timedelta(days=60))
        entry = {**good(manifest, at=now() - timedelta(minutes=1), status="changed",
                        keep_taken_at=True), "manifest_relayed": True}
        before = len(manifests_from_ledger(ledger_of(acct), KEY_0412))
        m = post(client, h, report(entry)).json()["machines"][0]
        assert m["outcome"] == "recorded"
        assert m["reason"] == "relayed_manifest_not_held"
        assert m["recorded_status"] == "manifest_stale"
        assert m["counts_as_observation"] is False
        assert m["manifest_relayed_verified"] is False
        assert "Remedy" in m["detail"] and "does not hold" in m["detail"]
        assert 59 * 24 < m["manifest_age_hours"] < 61 * 24
        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_observation_at"] is None
        assert row["stale"] is True
        assert row["last_attempt_status"] == "manifest_stale"
        assert row["last_attempt_succeeded"] is False
        assert len(manifests_from_ledger(ledger_of(acct), KEY_0412)) == before
        assert case_entries(ledger_of(acct)) == []

    def test_a_relayed_flag_on_an_unheld_manifest_does_not_enrol_a_machine(
            self, client, cell, tmp_path):
        acct, h = cell
        manifest = make_manifest(tmp_path, when=now() - timedelta(days=60))
        entry = {**good(manifest, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        m = post(client, h, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "relayed_manifest_not_held")
        assert "Remedy" in m["detail"]
        assert len(ledger_of(acct)) == 0

    def test_a_relayed_unheld_changed_manifest_opens_no_case_and_moves_no_baseline(
            self, client, cell, tmp_path):
        acct, h = cell
        t0 = now() - timedelta(days=2)
        post(client, h, report(good(make_manifest(tmp_path), at=t0), started=t0))
        before = len(manifests_from_ledger(ledger_of(acct), KEY_0412))
        forged = make_manifest(tmp_path, fw=b"firmware 9.9.9", when=now() - timedelta(days=60))
        entry = {**good(forged, at=now() - timedelta(minutes=1), status="changed",
                        keep_taken_at=True), "manifest_relayed": True}
        m = post(client, h, report(entry, watch_id="W2")).json()["machines"][0]
        assert m["reason"] == "relayed_manifest_not_held" and m["counts_as_observation"] is False
        assert len(manifests_from_ledger(ledger_of(acct), KEY_0412)) == before
        assert case_entries(ledger_of(acct)) == []
        assert machine_row(client, h, KEY_0412)["last_successful_observation_at"] == iso(t0)

    def test_a_genuine_unchanged_relayed_manifest_still_counts(self, client, cell, tmp_path):
        """The `watch push` case: the manifest sealed 60 days ago, re-confirmed today."""
        acct, h = cell
        t0 = now() - timedelta(days=60)
        manifest = make_manifest(tmp_path, when=t0)
        first = post(client, h, report(good(manifest, at=t0), started=t0))
        assert first.json()["machines"][0]["recorded_status"] == "first_seen"
        again = {**good(manifest, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        m = post(client, h, report(again, watch_id="W2")).json()["machines"][0]
        assert m["counts_as_observation"] is True and m["reason"] == ""
        assert m["recorded_status"] == "observed"
        assert m["manifest_relayed_verified"] is True
        assert 59 * 24 < m["manifest_age_hours"] < 61 * 24
        row = machine_row(client, h, KEY_0412)
        assert row["stale"] is False
        assert row["last_successful_manifest_relayed"] is True
        assert 59 * 24 < row["last_successful_manifest_age_hours"] < 61 * 24
        assert case_entries(ledger_of(acct)) == []

    def test_a_restamped_manifest_of_the_held_configuration_is_labelled_same_configuration(
            self, client, cell, tmp_path):
        """Restamping taken_at keeps the configuration hash. The relay is honoured on the
        weaker basis (same configuration held, not the exact manifest) and says so; a
        different configuration is never honoured (see TestRelayBasis)."""
        acct, h = cell
        t0 = now() - timedelta(days=60)
        manifest = make_manifest(tmp_path, when=t0)
        post(client, h, report(good(manifest, at=t0), started=t0))
        restamped = {**manifest, "taken_at": iso(now() - timedelta(days=59))}
        entry = {**good(restamped, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        m = post(client, h, report(entry, watch_id="W2")).json()["machines"][0]
        assert m["counts_as_observation"] is True
        assert m["relay_basis"] == "same_configuration_held"

    def test_a_relayed_flag_changes_nothing_for_a_manifest_that_is_fresh_anyway(
            self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(minutes=5)
        entry = {**good(make_manifest(tmp_path), at=t), "manifest_relayed": True}
        m = post(client, h, report(entry, started=t)).json()["machines"][0]
        assert m["counts_as_observation"] is True
        assert m["manifest_relayed_verified"] is False      # nothing held it; nothing needed it

    # -- the server's clock is the only one it trusts ---------------------------------

    def test_a_restamped_observed_at_cannot_make_an_old_manifest_a_current_observation(
            self, client, cell, tmp_path):
        """observed_at set to just after taken_at hides the manifest's age from the reporter's
        own arithmetic. The record keeps the server's receipt and flags the skew, and this
        single entry leaves the machine stale. It does NOT show that a second, relayed entry
        cannot then borrow the manifest this one planted: it can, and
        ``TestRelayBasis.test_a_manifest_planted_in_the_same_report_is_labelled_not_hidden``
        pins that the result is labelled ``planted_in_same_report``, not refused."""
        acct, h = cell
        taken = now() - timedelta(days=60)
        manifest = make_manifest(tmp_path, when=taken)
        entry = good(manifest, at=taken + timedelta(hours=1), keep_taken_at=True)
        m = post(client, h, report(entry)).json()["machines"][0]
        assert m["observed_at_skew"] is True
        assert m["manifest_age_hours"] == 1.0                 # the reporter's own arithmetic
        row = machine_row(client, h, KEY_0412)
        assert row["stale"] is True and row["stale_reason"] == "older_than_cadence"
        assert row["last_successful_observed_at_skew"] is True
        assert row["age_hours"] > 59 * 24
        body = [e.evidence().body for e in ledger_of(acct).entries(kind="watch.observation")][-1]
        assert body["manifest_age_at_receipt_hours"] > 59 * 24   # what the server's clock says

    def test_received_at_is_recorded_and_a_late_delivery_is_flagged_not_freshened(
            self, client, cell, tmp_path):
        acct, h = cell
        late = now() - timedelta(days=3)
        entry = good(make_manifest(tmp_path), at=late)
        m = post(client, h, report(entry, started=late)).json()["machines"][0]
        assert m["outcome"] == "recorded" and m["counts_as_observation"] is True
        assert m["observed_at_skew"] is True
        assert m["basis"] == "client_reported"
        received = datetime.fromisoformat(m["received_at"].replace("Z", "+00:00"))
        assert abs((received - datetime.now(UTC)).total_seconds()) < 30
        row = machine_row(client, h, KEY_0412)
        # the look is still read at the time the reporter said, three days ago
        assert row["last_successful_observation_at"] == iso(late)
        assert row["last_successful_observed_at_declared"] == iso(late)
        assert row["last_successful_received_at"] == m["received_at"]
        assert row["last_successful_observed_at_skew"] is True
        assert 71 < row["age_hours"] < 73

    def test_a_prompt_report_is_not_flagged(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(minutes=5)
        m = post(client, h, report(good(make_manifest(tmp_path), at=t), started=t)
                 ).json()["machines"][0]
        assert m["observed_at_skew"] is False
        assert machine_row(client, h, KEY_0412)["last_successful_observed_at_skew"] is False

    def test_a_look_dated_ahead_of_receipt_is_read_as_received_for_staleness(self, tmp_path):
        """observed_at may run up to 60 s ahead; staleness is judged from receipt, not from it."""
        ledger = EvidenceLedger(tmp_path / "ahead.db")
        received = now() - timedelta(days=9)
        ahead = received + timedelta(seconds=50)
        entry = good(make_manifest(tmp_path), at=ahead)
        r = ingest_report(ledger, report(entry, started=received), actor=SCANNER, now=received)
        assert r.results[0].counts_as_observation is True
        # 168 h after receipt + 30 s: past the default cadence from receipt, but still inside it
        # if the reporter's own (later) date were believed.
        as_of = received + timedelta(hours=168, seconds=30)
        row = fleet_observations(ledger, now=as_of)["machines"][0]
        assert row["last_successful_observation_at"] == iso(received)
        assert row["stale"] is True and row["stale_reason"] == "older_than_cadence"

    def test_a_late_delivery_is_never_made_fresher_than_its_own_stated_time(self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "late.db")
        received = now() - timedelta(days=9)
        stated = received - timedelta(days=8)          # delivered 8 days after the look
        entry = good(make_manifest(tmp_path), at=stated)
        ingest_report(ledger, report(entry, started=received), actor=SCANNER, now=received)
        row = fleet_observations(ledger, now=received)["machines"][0]
        assert row["last_successful_observation_at"] == iso(stated)
        assert row["last_successful_observed_at_skew"] is True
        assert row["stale"] is True            # 8 days old at receipt, cadence 168 h

    # -- every observation says whose word it is --------------------------------------

    def test_every_surface_labels_observations_client_reported_and_names_the_replay(
            self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(minutes=5)
        posted = post(client, h, report(good(make_manifest(tmp_path), at=t), started=t)).json()
        assert posted["machines"][0]["basis"] == "client_reported"
        assert any("fabricate a current-looking observation" in x for x in posted["limitations"])
        data = observations(client, h)
        assert data["basis"] == "client_reported"
        assert all(m["basis"] == "client_reported" for m in data["machines"])
        assert all(r["basis"] == "client_reported" for r in data["recent_reports"])
        joined = " ".join(data["limitations"])
        assert "fabricate a current-looking observation" in joined
        assert "does not prevent it" in joined
        body = [e.evidence().body for e in ledger_of(acct).entries(kind="watch.observation")][-1]
        assert body["basis"] == "client_reported" and body["received_at"]

    def test_the_push_client_marks_an_older_manifest_as_relayed(self, tmp_path):
        from assurance.watch.push import _relayed

        at = now()
        assert _relayed({"taken_at": iso(at - timedelta(days=30))}, at) is True
        assert _relayed({"taken_at": iso(at - timedelta(seconds=20))}, at) is False
        assert _relayed({"taken_at": "garbage"}, at) is False

    def test_a_fresh_look_reports_the_manifest_age(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(minutes=5)
        post(client, h, report(good(make_manifest(tmp_path), at=t), started=t))
        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_manifest_age_hours"] == 0.0
        assert row["stale"] is False

    def test_a_future_entry_does_not_poison_the_rest_of_the_report(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0501")
        r = post(client, h, report(failed("0412", at=now() + timedelta(days=1)),
                                   failed("0501", at=now() - timedelta(minutes=1)))).json()
        assert [m["outcome"] for m in r["machines"]] == ["refused", "recorded"]
        assert r["summary"] == {**r["summary"], "recorded": 1, "refused": 1}


# =====================================================================
# a manifest that is not a look at the machine is not an observation
# =====================================================================

def declared_copy(manifest: dict, *, source: str = "as_declared",
                  hash_source: str = "supplied_by_vendor") -> dict:
    """The same configuration, presented as something other than a look at the unit."""
    out = {**manifest, "source": source}
    out["items"] = [{**i, "hash_source": hash_source} for i in manifest["items"]]
    return out


def manifest_ids(acct, key=KEY_0412):
    return [m.manifest_id for m in manifests_from_ledger(ledger_of(acct), key)]


class TestAManifestThatIsNotALookIsNotAnObservation:
    """Hash equality is not enough: ``configuration_hash`` ignores who looked and how."""

    def _baseline(self, client, h, tmp_path):
        t = now() - timedelta(hours=5)
        post(client, h, report(good(make_manifest(tmp_path), at=t), started=t))

    @pytest.mark.parametrize("variant", [
        {},                                                 # declared + vendor-supplied
        {"source": "as_found"},                             # looks found, hashes are the vendor's
        {"hash_source": "read_from_machine"},               # hashes from the unit, but as_declared
        {"source": "as_intended"},
        {"source": "as_found", "hash_source": "declared"},  # nothing hashed at all
    ], ids=["declared+vendor", "found+vendor", "declared+read", "intended+vendor",
            "found+declared-hash"])
    def test_an_unchanged_claim_on_a_non_look_is_incomplete_and_counts_for_nothing(
            self, client, cell, tmp_path, variant):
        acct, h = cell
        self._baseline(client, h, tmp_path)
        before_manifests = manifest_ids(acct)
        before_cases = len(case_entries(ledger_of(acct)))
        t = now() - timedelta(minutes=2)
        entry = good(declared_copy(make_manifest(tmp_path), **variant), at=t)
        if variant.get("hash_source") == "declared":
            for i in entry["manifest"]["items"]:
                i["content_hash"] = ""
        m = post(client, h, report(entry, started=t, watch_id="W2")).json()["machines"][0]
        assert m["outcome"] == "recorded"
        assert m["recorded_status"] == "incomplete"
        assert m["counts_as_observation"] is False
        assert m["reason"] == "manifest_not_a_look_at_the_machine"
        assert "unchanged at" not in m["detail"]
        assert (m["case_id"], m["case_status"], m["case_opened"]) == ("", "", False)
        ledger = ledger_of(acct)
        body = [e.evidence().body for e in ledger.entries(kind="watch.observation")][-1]
        assert body["status"] == "incomplete" and body["complete"] is False
        assert body["reported_status"] == "unchanged" and body["configuration_hash"] == ""
        assert manifest_ids(acct) == before_manifests        # the baseline did not move
        assert len(case_entries(ledger)) == before_cases
        row = machine_row(client, h, KEY_0412)
        assert row["last_attempt_status"] == "incomplete"
        assert row["last_attempt_succeeded"] is False
        assert row["last_successful_observation_at"] != iso(t)

    def test_a_changed_claim_on_a_non_look_opens_no_case_and_moves_no_baseline(
            self, client, cell, tmp_path):
        acct, h = cell
        self._baseline(client, h, tmp_path)
        before = manifest_ids(acct)
        t = now() - timedelta(minutes=2)
        entry = good(declared_copy(make_manifest(tmp_path, fw=b"firmware 3.9.0")), at=t,
                     status="changed")
        m = post(client, h, report(entry, started=t, watch_id="W2")).json()["machines"][0]
        assert (m["recorded_status"], m["counts_as_observation"]) == ("incomplete", False)
        assert m["case_id"] == ""
        assert case_entries(ledger_of(acct)) == []
        assert manifest_ids(acct) == before

    @pytest.mark.parametrize("variant", [
        {}, {"hash_source": "read_from_machine"}, {"source": "as_found"},
    ], ids=["declared+vendor", "declared+read", "found+vendor"])
    def test_a_non_look_cannot_enrol_an_unknown_machine(self, client, cell, tmp_path, variant):
        acct, h = cell
        t = now() - timedelta(minutes=2)
        entry = good(declared_copy(make_manifest(tmp_path), **variant), at=t)
        m = post(client, h, report(entry, started=t)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "manifest_not_a_look_at_the_machine")
        assert m["counts_as_observation"] is False
        assert len(ledger_of(acct)) == 0

    def test_a_non_look_wins_over_the_relayed_flag_and_over_staleness(
            self, client, cell, tmp_path):
        acct, h = cell
        self._baseline(client, h, tmp_path)
        t = now() - timedelta(minutes=2)
        old = declared_copy(make_manifest(tmp_path, when=now() - timedelta(days=60)))
        relayed = {**good(old, at=t, keep_taken_at=True), "manifest_relayed": True}
        m = post(client, h, report(relayed, started=t, watch_id="W2")).json()["machines"][0]
        assert (m["recorded_status"], m["counts_as_observation"]) == ("incomplete", False)
        t2 = now() - timedelta(minutes=1)
        stale = good(old, at=t2, keep_taken_at=True)
        m2 = post(client, h, report(stale, started=t2, watch_id="W3")).json()["machines"][0]
        assert (m2["recorded_status"], m2["counts_as_observation"]) == ("incomplete", False)
        assert m2["reason"] == "manifest_not_a_look_at_the_machine"

    def test_the_real_collectors_report_is_unaffected(self, client, cell, tmp_path):
        acct, h = cell
        self._baseline(client, h, tmp_path)
        t = now() - timedelta(minutes=2)
        m = post(client, h, report(good(make_manifest(tmp_path), at=t), started=t,
                                   watch_id="W2")).json()["machines"][0]
        assert (m["recorded_status"], m["counts_as_observation"]) == ("observed", True)
        t2 = now() - timedelta(minutes=1)
        m = post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                        status="changed"), started=t2,
                                   watch_id="W3")).json()["machines"][0]
        assert (m["recorded_status"], m["counts_as_observation"]) == ("changed", True)
        assert m["case_id"]

    def test_the_recorded_status_comes_from_the_divergence_verdict_not_hash_equality(
            self, env, tmp_path, monkeypatch):
        """If compare() cannot vouch for an equal hash, the look is not recorded as unchanged."""
        from dataclasses import replace

        from assurance.watch import ingest

        ledger = EvidenceLedger(tmp_path / "verdict.db")
        actor = Actor("hosted-watch-report", "watch report via account acc_x", "automation")
        t1, t2 = now() - timedelta(hours=3), now() - timedelta(minutes=2)
        ingest_report(ledger, _plain(report(good(make_manifest(tmp_path), at=t1), started=t1)),
                      actor=actor)
        real = ingest.compare
        monkeypatch.setattr(ingest, "compare", lambda b, o: replace(
            real(b, o), uncompared=("ITM-PLC",)))
        res = ingest_report(ledger, _plain(report(
            good(make_manifest(tmp_path), at=t2), started=t2, watch_id="W2")),
            actor=actor).results[0]
        assert (res.recorded_status, res.counts_as_observation) == ("incomplete", False)
        assert res.reason == "manifest_not_a_look_at_the_machine"
        body = [e.evidence().body for e in ledger.entries(kind="watch.observation")][-1]
        assert body["status"] == "incomplete" and body["complete"] is False

    def test_a_partial_manifest_in_the_ledger_is_never_the_baseline(self, env, tmp_path):
        from dataclasses import replace

        from assurance.machinery.manifest import SafetyManifest

        ledger = EvidenceLedger(tmp_path / "partial.db")
        actor = Actor("hosted-watch-report", "watch report via account acc_x", "automation")
        t1, t2 = now() - timedelta(hours=3), now() - timedelta(minutes=2)
        first = ingest_report(ledger, _plain(report(good(make_manifest(tmp_path), at=t1),
                                                    started=t1)), actor=actor)
        assert first.results[0].recorded_status == "first_seen"
        whole = SafetyManifest.from_dict(make_manifest(tmp_path))
        partial = replace(whole, manifest_id="PARTIAL", items=whole.items[:-1],
                          notes="[collection incomplete: x not collected]")
        record_manifest(ledger, partial)
        res = ingest_report(ledger, _plain(report(
            good(make_manifest(tmp_path), at=t2), started=t2, watch_id="W2")),
            actor=actor).results[0]
        assert (res.recorded_status, res.counts_as_observation) == ("observed", True)
        assert res.case_id == ""

    def test_the_library_function_records_the_same_thing(self, env, tmp_path):
        ledger = EvidenceLedger(tmp_path / "nonlook.db")
        actor = Actor("hosted-watch-report", "watch report via account acc_x", "automation")
        t1, t2 = now() - timedelta(hours=3), now() - timedelta(minutes=2)
        ingest_report(ledger, _plain(report(good(make_manifest(tmp_path), at=t1), started=t1)),
                      actor=actor)
        n = len(manifests_from_ledger(ledger, KEY_0412))
        res = ingest_report(ledger, _plain(report(
            good(declared_copy(make_manifest(tmp_path)), at=t2), started=t2,
            watch_id="W2")), actor=actor).results[0]
        assert (res.recorded_status, res.counts_as_observation) == ("incomplete", False)
        assert len(manifests_from_ledger(ledger, KEY_0412)) == n


# =====================================================================
# the tenant boundary
# =====================================================================

class TestTenancy:
    def test_a_report_is_visible_to_its_sender_and_to_nobody_else(self, client, accounts, tmp_path):
        a, ha = account(accounts, "cell", "a@example.de")
        b, hb = account(accounts, "cell", "b@example.de")
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)
        enroll_manifest(a, tmp_path, "0501")
        post(client, ha, report(good(make_manifest(tmp_path), at=t1), started=t1))
        post(client, ha, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                     status="changed"), failed("0501", at=t2), started=t2))

        assert len(observations(client, ha)["machines"]) == 2
        for path in ("/v1/fleet/observations", "/v1/fleet/machines", "/v1/change/cases"):
            body = client.get(path, headers=hb).json()
            assert KEY_0412 not in json.dumps(body) and KEY_0501 not in json.dumps(body)
        assert observations(client, hb)["machines"] == []
        assert observations(client, hb)["reporting"] is False
        assert len(ledger_of(b)) == 0

    def test_the_same_machine_key_reported_by_b_lands_in_bs_ledger_only(
            self, client, accounts, tmp_path):
        a, ha = account(accounts, "cell", "a@example.de")
        b, hb = account(accounts, "cell", "b@example.de")
        t = now() - timedelta(hours=5)
        post(client, ha, report(good(make_manifest(tmp_path), at=t), started=t))
        a_len, a_head = len(ledger_of(a)), _chain_head(ledger_of(a))

        # B names A's machine. The key is per tenant ledger, so this is B's own
        # row about B's own claim and cannot touch A's record.
        enroll_manifest(b, tmp_path, "0412")
        r = post(client, hb, report(failed("0412", at=now() - timedelta(minutes=1)))).json()
        assert r["machines"][0]["outcome"] == "recorded"
        assert len(ledger_of(a)) == a_len and _chain_head(ledger_of(a)) == a_head
        assert machine_row(client, ha, KEY_0412)["last_attempt_succeeded"] is True
        assert machine_row(client, hb, KEY_0412)["last_attempt_succeeded"] is False

    def test_an_entry_cannot_name_one_machine_and_carry_the_manifest_of_another(
            self, client, accounts, tmp_path):
        a, ha = account(accounts, "cell", "a@example.de")
        t = now() - timedelta(minutes=5)
        entry = good(make_manifest(tmp_path, "0412"), at=t)
        entry["machine_key"] = "Grimaldi/AR-7#0999"
        m = post(client, ha, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "machine_key_mismatch")
        entry["machine_key"] = KEY_0412
        entry["serial"] = "0999"
        m = post(client, ha, report(entry)).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "serial_mismatch")
        assert len(ledger_of(a)) == 0

    def test_the_operator_key_reaches_the_shared_ledger_and_a_customers_does_not(
            self, client, accounts, tmp_path):
        a, ha = account(accounts, "cell", "a@example.de")
        t = now() - timedelta(minutes=5)
        post(client, {"X-API-Key": OPERATOR_KEY}, report(failed("0412", at=t)))
        assert observations(client, ha)["machines"] == []


# =====================================================================
# the read model, on its own
# =====================================================================

class TestObservationsReadModel:
    def test_open_cases_are_listed_per_machine(self, client, cell, tmp_path):
        acct, h = cell
        t1, t2 = now() - timedelta(days=2), now() - timedelta(days=1)
        post(client, h, report(good(make_manifest(tmp_path), at=t1), started=t1))
        r = post(client, h, report(good(make_manifest(tmp_path, fw=b"firmware 3.9.0"), at=t2,
                                        status="changed"), started=t2)).json()
        case_id = r["cases_opened"][0]
        row = machine_row(client, h, KEY_0412)
        assert row["open_case_ids"] == [case_id]
        assert fleet_observations(ledger_of(acct))["machines"][0]["open_case_ids"] == [case_id]

    def test_a_tampered_observation_record_is_ignored_not_trusted(self, client, cell, tmp_path):
        acct, h = cell
        post(client, h, report(failed("0412", at=now() - timedelta(hours=2))))
        import sqlite3
        db = sqlite3.connect(ledger_of(acct).path)
        db.execute("UPDATE chain SET payload = replace(payload, 'uncollectable', 'observed') "
                   "WHERE kind = 'watch.observation'")
        db.commit()
        db.close()
        # The forged "observed" does not verify, so it is not read at all: the
        # machine is not reported as seen by anything this ledger can vouch for.
        assert observations(client, h)["machines"] == []
        assert observations(client, h)["reporting"] is False

    def test_the_response_carries_honest_limitations(self, client, cell, tmp_path):
        acct, h = cell
        r = post(client, h, report(failed("0412", at=now() - timedelta(minutes=1)))).json()
        text = " ".join(r["limitations"])
        assert "cannot tell a true report from a false one" in text
        assert "never count as a successful observation" in text
        assert "advisory" in text
        assert observations(client, h)["limitations"]


class TestWhenTheIngestLockIsHeld:
    def test_a_report_behind_a_stuck_ingest_is_a_503_that_writes_nothing_not_a_hang(
            self, client, cell, tmp_path, monkeypatch):
        import threading

        from assurance.watch import ingest

        acct, h = cell
        enroll_manifest(acct, tmp_path)
        before = len(ledger_of(acct))
        monkeypatch.setattr(ingest, "LOCK_DEADLINE", 0.5)
        inside, release = threading.Event(), threading.Event()

        def hold() -> None:
            with ingest._ingest_lock(ledger_of(acct)):
                inside.set()
                release.wait(20)

        holder = threading.Thread(target=hold)
        holder.start()
        assert inside.wait(5)
        try:
            r = post(client, h, report(failed("0412", at=now() - timedelta(minutes=1))))
        finally:
            release.set()
            holder.join(10)
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "ingest_busy"
        assert r.headers["Retry-After"] == "5"
        assert len(ledger_of(acct)) == before
        # and the same report is accepted once the lock is free (retry is safe)
        assert post(client, h, report(failed("0412", at=now() - timedelta(minutes=1)))).status_code == 200


class TestRunSummaryReachesTheHostedRecord:
    def test_supplier_findings_and_local_cases_are_stored_as_client_reported(
            self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path)  # an enrolled machine to fail against
        summary = {
            "stale_observations": ["Grimaldi/AR-7#0412 last seen long ago"],
            "advisory_findings": [{
                "advisory_id": "CTRL-2026-11", "supplier_id": "ControlCo",
                "severity": "stop_use", "state": "new", "impact": "affected",
                "machines": ["Grimaldi/AR-7#0412"], "functions_in_question": ["SF-01"],
                "trust_basis": "none", "trust_state": "untrusted_unknown_key",
                "inspect_only": True}],
            "local_case_ids": ["case-local-1"], "checks_skipped": ["a limit"],
        }
        r = post(client, h, report(failed("0412", at=now()), run_summary=summary,
                                   verdict="findings"))
        assert r.status_code == 200, r.text
        got = observations(client, h)["recent_reports"][-1]
        assert got["source"] == "client_reported_watch_run"
        rs = got["run_summary"]
        assert rs["advisory_findings"][0]["trust_state"] == "untrusted_unknown_key"
        assert rs["advisory_findings"][0]["inspect_only"] is True
        assert rs["local_case_ids"] == ["case-local-1"]
        # the summary opened no hosted case and made no machine look observed
        assert not case_entries(ledger_of(acct))

    def test_a_summary_with_an_unknown_field_is_refused_and_writes_nothing(self, client, cell):
        acct, h = cell
        r = post(client, h, report(failed("0412", at=now()),
                                   run_summary={"awareness_at": "2026-10-19T05:00:00Z"}))
        assert r.status_code == 422
        assert len(ledger_of(acct)) == 0


# =====================================================================
# how a look became current: relay_basis (F2 label, F3 same-configuration relay)
# =====================================================================
#
# The server cannot prevent a reporter holding the account key from fabricating a
# current-looking observation: one entry plants an old manifest (observed_at just
# after taken_at, recorded and counted), a second relays it. That is also exactly what
# the legitimate `watch push` anchor + relayed pair looks like. So these tests pin what
# the server DOES provide: the observation is labelled with how its freshness was
# obtained, so a person reading the row can see it.

class TestRelayBasis:
    @staticmethod
    def _plant_and_relay(tmp_path, *, days=90):
        taken = now() - timedelta(days=days)
        manifest = make_manifest(tmp_path, when=taken)
        plant = good(manifest, at=taken + timedelta(hours=1), keep_taken_at=True)
        relay = {**good(manifest, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        return plant, relay

    def test_a_manifest_planted_in_the_same_report_is_labelled_not_hidden(
            self, client, cell, tmp_path):
        acct, h = cell
        plant, relay = self._plant_and_relay(tmp_path)
        r = post(client, h, report(plant, relay)).json()
        planted, relayed = r["machines"]
        # not refused: the honest push depends on this exact shape ...
        assert relayed["counts_as_observation"] is True
        # ... so it is labelled instead
        assert relayed["relay_basis"] == "planted_in_same_report"
        assert relayed["manifest_first_received_in_this_report"] is True
        assert relayed["manifest_age_at_receipt_hours"] > 89 * 24
        assert planted["relay_basis"] == "unrelayed"
        assert planted["manifest_first_received_in_this_report"] is False
        row = machine_row(client, h, KEY_0412)
        assert row["stale"] is False                      # the gate does not stop it
        assert row["last_successful_relay_basis"] == "planted_in_same_report"
        assert row["last_successful_manifest_first_received_in_this_report"] is True
        assert row["last_successful_manifest_age_at_receipt_hours"] > 89 * 24
        assert row["last_successful_manifest_age_exceeds_window_at_receipt"] is True
        body = [e.evidence().body for e in ledger_of(acct).entries(kind="watch.observation")][-1]
        assert body["relay_basis"] == "planted_in_same_report"
        assert body["manifest_first_received_in_this_report"] is True

    def test_a_manifest_held_from_an_earlier_report_is_labelled_as_such(
            self, client, cell, tmp_path):
        acct, h = cell
        t0 = now() - timedelta(days=60)
        manifest = make_manifest(tmp_path, when=t0)
        post(client, h, report(good(manifest, at=t0), started=t0))
        again = {**good(manifest, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        m = post(client, h, report(again, watch_id="W2")).json()["machines"][0]
        assert m["relay_basis"] == "held_from_earlier_report"
        assert m["manifest_first_received_in_this_report"] is False
        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_relay_basis"] == "held_from_earlier_report"
        assert row["last_successful_manifest_first_received_in_this_report"] is False
        # an old manifest relayed as current is visible from the receipt-time age alone
        assert row["last_successful_manifest_age_exceeds_window_at_receipt"] is True
        assert row["last_successful_manifest_age_at_receipt_hours"] > 59 * 24

    def test_a_fresh_unrelayed_look_is_labelled_unrelayed(self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(minutes=5)
        m = post(client, h, report(good(make_manifest(tmp_path), at=t), started=t)
                 ).json()["machines"][0]
        assert m["relay_basis"] == "unrelayed"
        row = machine_row(client, h, KEY_0412)
        assert row["last_successful_relay_basis"] == "unrelayed"
        assert row["last_successful_manifest_age_exceeds_window_at_receipt"] is False

    def test_a_non_observation_has_no_relay_basis_to_show(self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        other = make_manifest(tmp_path, fw=b"firmware 9.9.9", when=now() - timedelta(days=60))
        entry = {**good(other, at=now() - timedelta(minutes=1), status="changed",
                        keep_taken_at=True), "manifest_relayed": True}
        m = post(client, h, report(entry)).json()["machines"][0]
        assert m["counts_as_observation"] is False
        assert m["relay_basis"] == "unrelayed"

    # -- F3: the same configuration, a different manifest ---------------------------

    def test_an_honest_push_is_current_when_the_ledger_holds_the_same_configuration(
            self, client, cell, tmp_path):
        """Enrolled with M2 (taken now); Watch pushes anchor(M1, 30 d) + relayed(M1)."""
        from assurance.machinery.manifest import SafetyManifest

        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")                    # M2, taken now
        m1 = make_manifest(tmp_path, when=now() - timedelta(days=30))
        held = manifests_from_ledger(ledger_of(acct), KEY_0412)
        assert SafetyManifest.from_dict(m1).configuration_hash() == held[-1].configuration_hash()
        assert SafetyManifest.from_dict(m1).content_hash() != held[-1].content_hash()
        anchor = {**good(m1, at=now() - timedelta(days=30), status="changed",
                         keep_taken_at=True), "manifest_relayed": False}
        relay = {**good(m1, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        r = post(client, h, report(anchor, relay)).json()["machines"]
        assert r[1]["counts_as_observation"] is True, r[1]
        assert r[1]["relay_basis"] == "same_configuration_held"
        assert r[1]["manifest_relayed_verified"] is True
        row = machine_row(client, h, KEY_0412)
        assert row["stale"] is False
        assert row["last_successful_relay_basis"] == "same_configuration_held"
        assert case_entries(ledger_of(acct)) == []

    def test_the_same_configuration_relay_alone_is_current_and_writes_no_manifest(
            self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")
        m1 = make_manifest(tmp_path, when=now() - timedelta(days=30))
        before = len(manifests_from_ledger(ledger_of(acct), KEY_0412))
        relay = {**good(m1, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        m = post(client, h, report(relay)).json()["machines"][0]
        assert m["recorded_status"] == "observed" and m["counts_as_observation"] is True
        assert m["relay_basis"] == "same_configuration_held"
        assert len(manifests_from_ledger(ledger_of(acct), KEY_0412)) == before

    def test_a_relay_of_a_different_configuration_is_not_made_current(
            self, client, cell, tmp_path):
        acct, h = cell
        enroll_manifest(acct, tmp_path, "0412")                    # firmware 3.8.2
        other = make_manifest(tmp_path, fw=b"firmware 9.9.9", when=now() - timedelta(days=30))
        relay = {**good(other, at=now() - timedelta(minutes=1), status="changed",
                        keep_taken_at=True), "manifest_relayed": True}
        m = post(client, h, report(relay)).json()["machines"][0]
        assert m["reason"] == "relayed_manifest_not_held"
        assert m["counts_as_observation"] is False and m["relay_basis"] == "unrelayed"
        assert case_entries(ledger_of(acct)) == []
        assert machine_row(client, h, KEY_0412)["last_successful_observation_at"] is None

    def test_a_configuration_held_only_in_history_is_not_the_current_one(
            self, client, cell, tmp_path):
        """Held A, then B is the baseline: a relayed older-dated A is not 'the same as now'."""
        acct, h = cell
        t0 = now() - timedelta(days=3)
        a = make_manifest(tmp_path, when=t0)
        b = make_manifest(tmp_path, fw=b"firmware 4.0.0", when=t0 + timedelta(days=1))
        post(client, h, report(good(a, at=t0), good(b, at=t0 + timedelta(days=1),
                                                    status="changed"), started=t0))
        a2 = make_manifest(tmp_path, when=now() - timedelta(days=30))
        relay = {**good(a2, at=now() - timedelta(minutes=1), keep_taken_at=True),
                 "manifest_relayed": True}
        m = post(client, h, report(relay, watch_id="W2")).json()["machines"][0]
        assert m["counts_as_observation"] is False
        assert m["reason"] == "relayed_manifest_not_held"

    # -- the words say what the server can and cannot do --------------------------------

    def test_the_limitations_say_a_key_holder_can_fabricate_a_current_looking_observation(
            self, client, cell, tmp_path):
        acct, h = cell
        t = now() - timedelta(minutes=5)
        posted = post(client, h, report(good(make_manifest(tmp_path), at=t), started=t)).json()
        for text in (" ".join(posted["limitations"]),
                     " ".join(observations(client, h)["limitations"])):
            assert "fabricate a current-looking observation" in text
            assert "never held being presented as a relayed one" not in text
            assert "whichever is later" not in text
            assert "planted_in_same_report" in text
        assert "recorded, not gating" in " ".join(observations(client, h)["limitations"])

    def test_the_docs_do_not_claim_a_relay_cannot_be_planted(self):
        from assurance.watch import ingest

        root = Path(__file__).resolve().parents[1]
        md = (root / "deploy" / "assurance" / "WATCH.md").read_text()
        assert "cannot become current from an old manifest alone" not in md
        assert "fabricate a current-looking observation" in md
        assert "planted_in_same_report" in md and "same_configuration_held" in md
        src = (root / "src" / "assurance" / "watch" / "ingest.py").read_text()
        assert "cannot be put on a manifest the account has never been given" not in src
        assert ingest.RELAY_BASES == (
            "unrelayed", "held_from_earlier_report", "planted_in_same_report",
            "same_configuration_held")
