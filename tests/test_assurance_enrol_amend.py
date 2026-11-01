"""Amending an enrolment: a named person changes a declared site or owner, as a new record.

Pins: the enrolment entry is never touched; the effective identity is the enrolment plus its
amendments in order; every reader shows the effective value AND that it was amended (who, when,
why, from -> to); the actor / reason / no-op / not-enrolled / attribute / key guards; a
re-enrolment is judged against the effective identity; concurrent amendments never fork the
chain; CLI exit codes and no ledger created on a typo; API 401/402/tenant isolation; coverage
is unchanged by an amendment; the words a receipt may never say are absent.
"""
# ruff: noqa: S603  (the tests run this package's own CLI)
from __future__ import annotations

import json
import subprocess
import sys
import threading

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.machinery.amend import (
    AMENDMENT_KIND,
    AmendmentError,
    amend_enrolment,
    effective_identity,
)
from assurance.machinery.enrol import ENROLMENT_KIND, enrol_machine
from assurance.machinery.record import MANIFEST_KIND

from . import test_assurance_change as _change
from .test_assurance_check import fw, manifest, zones

client = _change.client
account_store = _change.account_store

PERSON = Actor("a.integrator", "safety engineer")
OTHER = Actor("b.keller", "site manager")
KEY = "Grimaldi/AR-7#0412"
FORBIDDEN = ("compliant", "compliance", "certified", "safe", "verified")


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "amend.db")


@pytest.fixture
def enrolled(ledger):
    enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON, owner="A GmbH")
    return ledger


def kinds(ledger):
    return [e.kind for e in ledger.entries()]


def snapshot(ledger):
    return [(e.seq, e.content_hash, e.link_hash) for e in ledger.entries()]


def amend(ledger, **over):
    kw = {"actor": PERSON, "changes": {"site": "Plant 3"}, "reason": "moved to Plant 3"}
    kw.update(over)
    return amend_enrolment(ledger, KEY, **kw)


def _prose(receipt) -> str:
    text = receipt.summary() + json.dumps(receipt.to_dict())
    for stated in ("does NOT establish", "does_not_establish", "not authenticated"):
        text = text.replace(stated, "")
    return text.lower()


# -- the amendment -------------------------------------------------------------


class TestAmend:
    def test_effective_identity_changes_and_the_original_is_untouched(self, enrolled):
        before = enrolled.entries(kind=ENROLMENT_KIND)[0]
        r = amend(enrolled)
        assert r.status == "amended" and r.written
        assert r.changes == {"site": {"from": "Plant 2", "to": "Plant 3"}}
        assert kinds(enrolled) == [MANIFEST_KIND, ENROLMENT_KIND, AMENDMENT_KIND]
        after = enrolled.entries(kind=ENROLMENT_KIND)[0]
        assert (after.content_hash, after.link_hash, after.payload) == (
            before.content_hash, before.link_hash, before.payload)
        ident = effective_identity(enrolled, KEY)
        assert ident.effective["site"] == "Plant 3" and ident.effective["owner"] == "A GmbH"
        assert ident.original["site"] == "Plant 2"
        assert enrolled.verify_chain() == (True, [])

    def test_who_when_why_from_to_are_recorded(self, enrolled):
        r = amend(enrolled, changes={"owner": "B AG", "site": "Plant 3"},
                  reason="sold with the plant")
        (am,) = effective_identity(enrolled, KEY).amendments
        assert am.by == "a.integrator" and am.reason == "sold with the plant"
        assert am.at and am.at == r.amended_at
        assert am.changes == {"owner": {"from": "A GmbH", "to": "B AG"},
                              "site": {"from": "Plant 2", "to": "Plant 3"}}

    def test_chain_references_the_enrolment_and_the_previous_amendment(self, enrolled):
        enrol_hash = enrolled.entries(kind=ENROLMENT_KIND)[0].content_hash
        a1 = amend(enrolled)
        a2 = amend(enrolled, actor=OTHER, changes={"site": "Plant 4"}, reason="moved again")
        a3 = amend(enrolled, changes={"owner": "C SA"}, reason="sold")
        assert (a1.sequence, a2.sequence, a3.sequence) == (1, 2, 3)
        bodies = [e.evidence().body for e in enrolled.entries(kind=AMENDMENT_KIND)]
        assert all(b["enrolment_content_hash"] == enrol_hash for b in bodies)
        assert [b["previous_amendment_hash"] for b in bodies] == [
            "", a1.amendment_content_hash, a2.amendment_content_hash]
        ident = effective_identity(enrolled, KEY)
        assert [a.by for a in ident.amendments] == ["a.integrator", "b.keller", "a.integrator"]
        assert ident.effective["site"] == "Plant 4" and ident.effective["owner"] == "C SA"
        assert ident.amendments[1].changes["site"] == {"from": "Plant 3", "to": "Plant 4"}
        assert enrolled.verify_chain() == (True, [])

    def test_an_attribute_never_declared_can_be_added(self, ledger):
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON)   # no owner
        r = amend(ledger, changes={"owner": "A GmbH"}, reason="owner was not known")
        assert r.changes["owner"] == {"from": "", "to": "A GmbH"}

    def test_the_receipt_states_what_it_does_not_establish(self, enrolled):
        d = amend(enrolled).to_dict()
        text = " ".join(d["does_not_establish"]).lower()
        assert "not authenticated to a physical unit" in text and "not erased" in text
        assert "does NOT establish" in amend(enrolled, changes={"site": "P5"}).summary()
        body = enrolled.entries(kind=AMENDMENT_KIND)[0].evidence().body
        assert body["does_not_establish"] and "previous_values_remain" in body

    def test_no_forbidden_words(self, enrolled):
        for r in (amend(enrolled), amend(enrolled), amend(enrolled, changes={"x": "y"}),
                  amend_enrolment(enrolled, "nope", actor=PERSON, changes={"site": "a"},
                                  reason="r")):
            prose = _prose(r)
            for word in FORBIDDEN:
                assert word not in prose, (word, r.status)


class TestNoOp:
    def test_same_values_write_nothing(self, enrolled):
        snap = snapshot(enrolled)
        r = amend(enrolled, changes={"site": "Plant 2", "owner": "A GmbH"})
        assert r.status == "no_change" and not r.written and not r.refused
        assert snapshot(enrolled) == snap

    def test_whitespace_only_difference_is_a_no_op(self, enrolled):
        snap = snapshot(enrolled)
        assert amend(enrolled, changes={"site": "  Plant   2 "}).status == "no_change"
        assert snapshot(enrolled) == snap

    def test_same_as_the_amended_value_is_a_no_op(self, enrolled):
        amend(enrolled)
        snap = snapshot(enrolled)
        assert amend(enrolled).status == "no_change"
        assert snapshot(enrolled) == snap

    def test_a_partial_change_records_only_what_changed(self, enrolled):
        r = amend(enrolled, changes={"site": "Plant 2", "owner": "B AG"})
        assert list(r.changes) == ["owner"]


class TestRefusals:
    @pytest.mark.parametrize("actor", [
        None, Actor("", "x"), Actor("   "), Actor("m.braun", kind="automation"),
        Actor("m.braun", kind="service"), Actor("automation"), Actor("Bot-7"), Actor("---"),
    ])
    def test_only_a_named_person(self, enrolled, actor):
        snap = snapshot(enrolled)
        with pytest.raises(AmendmentError):
            amend(enrolled, actor=actor)
        assert snapshot(enrolled) == snap

    @pytest.mark.parametrize("reason", ["", "   ", "\n\t", None])
    def test_a_reason_is_required(self, enrolled, reason):
        snap = snapshot(enrolled)
        with pytest.raises(AmendmentError, match="reason"):
            amend(enrolled, reason=reason)
        assert snapshot(enrolled) == snap

    def test_nothing_to_amend_and_empty_values_are_input_errors(self, enrolled):
        snap = snapshot(enrolled)
        with pytest.raises(AmendmentError, match="nothing to amend"):
            amend(enrolled, changes={})
        for bad in ("", "  ", 3, "x​"):
            with pytest.raises(AmendmentError):
                amend(enrolled, changes={"site": bad})
        assert snapshot(enrolled) == snap

    def test_not_enrolled(self, ledger):
        r = amend_enrolment(ledger, KEY, actor=PERSON, changes={"site": "P"}, reason="r")
        assert r.status == "not_enrolled" and r.refused and not r.written
        assert len(ledger) == 0
        assert "enrol" in r.pointer

    def test_a_manifest_alone_is_not_an_enrolment(self, ledger):
        from assurance.machinery.record import record_manifest
        record_manifest(ledger, manifest("0412", fw(), zones()), actor=PERSON)
        r = amend(ledger)
        assert r.status == "not_enrolled" and len(ledger) == 1

    @pytest.mark.parametrize("attr", ["year", "country", "colour", "Site"])
    def test_unknown_or_unamendable_attribute(self, enrolled, attr):
        snap = snapshot(enrolled)
        r = amend(enrolled, changes={attr: "x", "site": "Plant 3"})
        assert r.status == "unknown_attribute" and r.refused and r.rejected == (attr,)
        assert snapshot(enrolled) == snap        # the valid half is not applied either

    @pytest.mark.parametrize("attr", ["serial", "model", "manufacturer", "key",
                                      "configuration_hash", "items", "firmware"])
    def test_key_or_configuration_change_is_not_an_amendment(self, enrolled, attr):
        snap = snapshot(enrolled)
        r = amend(enrolled, changes={attr: "x"})
        assert r.status == "key_change_refused" and r.refused
        assert "machinery enrol" in r.pointer and "machinery diff" in r.pointer
        assert snapshot(enrolled) == snap

    def test_a_broken_chain_amends_nothing(self, enrolled):
        import sqlite3
        db = sqlite3.connect(enrolled.path)
        db.execute("UPDATE chain SET content_hash = 'f' WHERE seq = 1")
        db.commit()
        db.close()
        n = len(enrolled)
        with pytest.raises(AmendmentError, match="chain does not verify"):
            amend(enrolled)
        assert len(enrolled) == n

    def test_an_amendment_with_a_wrong_link_is_reported_not_applied(self, enrolled):
        """A forged-but-sealed amendment that skips the chain is not shown as in force."""
        from assurance.core.evidence import Evidence, Origin
        a1 = amend(enrolled)
        body = dict(enrolled.entries(kind=AMENDMENT_KIND)[0].evidence().body)
        body.update(previous_amendment_hash="f" * 64, sequence=2,
                    changes={"site": {"from": "Plant 3", "to": "Forged"}})
        forged = Evidence(kind=AMENDMENT_KIND, body=body, actor=PERSON,
                          origin=Origin(system="test", reference="forged")).seal()
        enrolled.append(forged, subject=KEY)
        ident = effective_identity(enrolled, KEY)
        assert ident.effective["site"] == "Plant 3" and len(ident.amendments) == 1
        assert ident.problems and a1.sequence == 1
        with pytest.raises(AmendmentError, match="inconsistent"):
            amend(enrolled, changes={"site": "Plant 9"})


# -- re-reading: the receipt and the fleet ----------------------------------------


class TestReaders:
    def test_reenrolling_with_the_original_site_is_now_an_identity_conflict(self, enrolled):
        amend(enrolled)
        snap = snapshot(enrolled)
        r = enrol_machine(enrolled, manifest("0412", fw(), zones()), actor=PERSON)
        assert r.status == "identity_conflict" and r.refused
        assert r.conflicts[0] == {"attribute": "site", "enrolled": "Plant 3",
                                  "claimed": "Plant 2"}
        assert snapshot(enrolled) == snap

    def test_reenrolling_with_the_original_owner_is_now_an_identity_conflict(self, enrolled):
        amend(enrolled, changes={"owner": "B AG"}, reason="sold")
        r = enrol_machine(enrolled, manifest("0412", fw(), zones()), actor=PERSON,
                          owner="A GmbH")
        assert r.status == "identity_conflict"
        assert r.conflicts[0]["enrolled"] == "B AG"

    def test_reenrolling_with_the_effective_value_is_already_enrolled_and_shows_the_trail(
            self, enrolled):
        amend(enrolled, changes={"owner": "B AG"}, reason="sold with the plant")
        r = enrol_machine(enrolled, manifest("0412", fw(), zones()), actor=OTHER,
                          owner="B AG")
        assert r.status == "already_enrolled" and not r.written
        assert r.declared["owner"] == "B AG"
        assert r.original_declared["owner"] == "A GmbH"
        (a,) = r.amendments
        assert (a["by"], a["reason"], a["changes"]["owner"]) == (
            "a.integrator", "sold with the plant", {"from": "A GmbH", "to": "B AG"})
        d = r.to_dict()
        assert d["identity_amended"] is True and d["amendments"][0]["at"]
        text = r.summary()
        assert "'A GmbH' -> 'B AG' by a.integrator" in text and "sold with the plant" in text

    def test_an_unamended_receipt_says_so(self, enrolled):
        r = enrol_machine(enrolled, manifest("0412", fw(), zones()), actor=PERSON)
        assert r.to_dict()["identity_amended"] is False and r.to_dict()["amendments"] == []
        assert "amended" not in r.summary()

    def test_the_fleet_listing_shows_the_effective_site_and_that_it_was_amended(self, enrolled):
        row = Fleet.from_ledger(enrolled).to_dict()["machines"][0]
        assert row["site"] == "Plant 2" and "identity_amendments" not in row
        amend(enrolled, reason="moved to Plant 3 for the retrofit")
        fleet = Fleet.from_ledger(enrolled)
        row = fleet.to_dict()["machines"][0]
        assert row["site"] == "Plant 3" and row["declared_site"] == "Plant 2"
        (a,) = row["identity_amendments"]
        assert a["by"] == "a.integrator" and a["reason"].startswith("moved to Plant 3")
        assert a["changes"]["site"] == {"from": "Plant 2", "to": "Plant 3"} and a["at"]
        assert fleet.summary().sites == {"Plant 3": 1}
        assert "Plant 3*" in fleet.table() and "amended since enrolment" in fleet.table()

    def test_an_owner_only_amendment_leaves_the_fleet_site_alone(self, enrolled):
        amend(enrolled, changes={"owner": "B AG"}, reason="sold")
        row = Fleet.from_ledger(enrolled).to_dict()["machines"][0]
        assert row["site"] == "Plant 2" and "identity_amendments" not in row

    def test_coverage_is_never_verified_and_unchanged_by_an_amendment(self, enrolled):
        m = manifest("0412", fw(), zones())
        before = enrol_machine(enrolled, m, actor=PERSON).coverage
        fleet_before = Fleet.from_ledger(enrolled).to_dict()["machines"][0]
        amend(enrolled, changes={"owner": "B AG"}, reason="sold")
        amend(enrolled, changes={"owner": "C SA"}, reason="sold again")
        after = enrol_machine(enrolled, m, actor=PERSON, owner="C SA")
        assert set(before.values()) == {"never_verified"} and after.coverage == before
        row = Fleet.from_ledger(enrolled).to_dict()["machines"][0]
        for k in ("verdict", "worst", "stale", "uncovered", "configuration_hash",
                  "interventions", "unrecorded_changes", "verifications", "tier_ceiling"):
            assert row[k] == fleet_before[k], k
        assert after.configuration_hash == m.configuration_hash()


# -- concurrency -------------------------------------------------------------------


class TestConcurrency:
    def test_two_concurrent_amendments_never_fork(self, tmp_path):
        path = tmp_path / "c.db"
        seed = EvidenceLedger(path)
        enrol_machine(seed, manifest("0412", fw(), zones()), actor=PERSON, owner="A GmbH")
        barrier = threading.Barrier(6)
        results: list[object] = []

        def work(i: int) -> None:
            led = EvidenceLedger(path)
            barrier.wait()
            try:
                results.append(amend_enrolment(
                    led, KEY, actor=Actor(f"person.{i}"), changes={"site": f"Plant {i}"},
                    reason=f"move {i}"))
            except AmendmentError as exc:     # cleanly refused, never a fork
                results.append(exc)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        led = EvidenceLedger(path)
        assert led.verify_chain() == (True, [])
        ident = effective_identity(led, KEY)
        assert not ident.problems
        written = [r for r in results if getattr(r, "written", False)]
        assert len(ident.amendments) == len(written) >= 1
        assert [a.sequence for a in ident.amendments] == list(range(1, len(written) + 1))
        # each amendment's `from` is the value its predecessor left in force
        site = "Plant 2"
        for a in ident.amendments:
            assert a.changes["site"]["from"] == site
            site = a.changes["site"]["to"]
        assert ident.effective["site"] == site

    def test_a_stale_head_is_a_conflict_not_an_overwrite(self, enrolled, monkeypatch):
        """If another amendment lands after the read, the append is refused and retried."""
        from assurance.machinery import amend as mod
        real = mod.effective_identity
        state = {"n": 0}

        def racing(ledger, key, enrolment=None):
            ident = real(ledger, key, enrolment)
            if state["n"] == 0:
                state["n"] = 1
                amend_enrolment(ledger, key, actor=OTHER, changes={"site": "Plant 8"},
                                reason="someone got there first")
            return ident

        monkeypatch.setattr(mod, "effective_identity", racing)
        r = amend(enrolled, changes={"site": "Plant 9"}, reason="second")
        assert r.written and r.changes["site"] == {"from": "Plant 8", "to": "Plant 9"}
        ident = real(enrolled, KEY)
        assert [a.sequence for a in ident.amendments] == [1, 2] and not ident.problems


# -- CLI ---------------------------------------------------------------------------


def cli(tmp_path, *args):
    return subprocess.run([sys.executable, "-m", "assurance", "machinery", *args],
                          cwd=tmp_path, capture_output=True, text=True, check=False)


class TestCli:
    def _enrol(self, tmp_path):
        (tmp_path / "a.json").write_text(
            json.dumps(manifest("0412", fw(), zones()).to_dict()), "utf-8")
        run = cli(tmp_path, "enrol", "a.json", "--ledger", "l.db", "--actor", "a.integrator",
                  "--owner", "A GmbH")
        assert run.returncode == 0, run.stderr

    def test_exit_codes(self, tmp_path):
        self._enrol(tmp_path)
        base = ("amend-enrolment", "--ledger", "l.db", "--machine", KEY,
                "--actor", "a.integrator")
        run = cli(tmp_path, *base, "--reason", "moved", "--site", "Plant 3")
        assert run.returncode == 0, run.stderr
        assert "'Plant 2' -> 'Plant 3'" in run.stdout and "amendment does NOT establish" in run.stdout
        again = cli(tmp_path, *base, "--reason", "moved", "--site", "Plant 3", "--json")
        assert again.returncode == 0 and json.loads(again.stdout)["status"] == "no_change"
        unknown = cli(tmp_path, "amend-enrolment", "--ledger", "l.db", "--machine", "X/Y#1",
                      "--actor", "a.integrator", "--reason", "r", "--site", "P")
        assert unknown.returncode == 1 and "not enrolled" in unknown.stdout
        ledger = EvidenceLedger.open_existing(tmp_path / "l.db")
        assert kinds(ledger).count(AMENDMENT_KIND) == 1
        assert ledger.verify_chain() == (True, [])

    @pytest.mark.parametrize("actor", ["", "automation", "bot-1"])
    def test_empty_or_automation_actor_is_exit_2(self, tmp_path, actor):
        self._enrol(tmp_path)
        run = cli(tmp_path, "amend-enrolment", "--ledger", "l.db", "--machine", KEY,
                  "--actor", actor, "--reason", "r", "--site", "P")
        assert run.returncode == 2 and "named person" in run.stderr

    def test_no_reason_no_change_and_missing_args_are_exit_2(self, tmp_path):
        self._enrol(tmp_path)
        common = ("amend-enrolment", "--ledger", "l.db", "--machine", KEY,
                  "--actor", "a.integrator")
        assert cli(tmp_path, *common, "--reason", " ", "--site", "P").returncode == 2
        assert cli(tmp_path, *common, "--reason", "r").returncode == 2      # nothing to amend
        assert cli(tmp_path, *common, "--site", "P").returncode == 2        # no --reason

    def test_a_typo_in_the_ledger_path_creates_no_ledger(self, tmp_path):
        run = cli(tmp_path, "amend-enrolment", "--ledger", "typo.db", "--machine", KEY,
                  "--actor", "a.integrator", "--reason", "r", "--site", "P")
        assert run.returncode == 2 and "does not exist" in run.stderr
        assert not (tmp_path / "typo.db").exists()


# -- API ---------------------------------------------------------------------------


def enrol_body(m, **over):
    return {"manifest": m.to_dict(), "actor": "a.integrator", **over}


def amend_body(**over):
    body = {"machine": KEY, "actor": "a.integrator", "reason": "moved",
            "changes": {"site": "Plant 3"}}
    body.update(over)
    return body


URL = "/v1/machinery/enrol/amend"


class TestApi:
    def test_no_key_is_401(self, client):
        assert client.post(URL, json=amend_body()).status_code == 401

    def test_authenticated_but_unentitled_is_402(self, client, account_store):
        headers = _change.keyed(account_store, "register")
        assert client.post(URL, json=amend_body(), headers=headers).status_code == 402
        same = client.post("/v1/machinery/enrol",
                           json=enrol_body(manifest("0412", fw(), zones())), headers=headers)
        assert same.status_code == 402          # gated exactly like enrolment

    def test_amend_then_idempotent_then_refusals(self, client, account_store):
        h = _change.keyed(account_store, "cell")
        m = manifest("0412", fw(), zones())
        assert client.post("/v1/machinery/enrol", json=enrol_body(m), headers=h).status_code == 200
        r = client.post(URL, json=amend_body(), headers=h)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["status"] == "amended" and d["effective"]["site"] == "Plant 3"
        assert d["changes"]["site"] == {"from": "Plant 2", "to": "Plant 3"} and d["does_not_establish"]
        again = client.post(URL, json=amend_body(), headers=h)
        assert again.status_code == 200 and again.json()["status"] == "no_change"

        for changes, error in (({"serial": "9"}, "key_change_refused"),
                               ({"year": "2030"}, "unknown_attribute")):
            r = client.post(URL, json=amend_body(changes=changes), headers=h)
            assert r.status_code == 409 and r.json()["detail"]["error"] == error
            assert r.json()["detail"]["receipt"]["written"] is False
        r = client.post(URL, json=amend_body(machine="Grimaldi/AR-7#9999"), headers=h)
        assert r.status_code == 409 and r.json()["detail"]["error"] == "not_enrolled"

        # the re-read shows the effective site, and a re-enrol with the original conflicts
        c = client.post("/v1/machinery/enrol", json=enrol_body(m), headers=h)
        assert c.status_code == 409 and c.json()["detail"]["error"] == "identity_conflict"
        fleet = client.get("/v1/fleet/machines", headers=h).json()["machines"][0]
        assert fleet["site"] == "Plant 3" and fleet["identity_amendments"][0]["by"] == "a.integrator"

    def test_unnamed_automation_or_reasonless_is_422(self, client, account_store):
        h = _change.keyed(account_store, "cell")
        client.post("/v1/machinery/enrol", json=enrol_body(manifest("0412", fw(), zones())),
                    headers=h)
        for over in ({"actor": "automation"}, {"actor": "bot-3"}, {"actor": ""},
                     {"reason": ""}, {"reason": "   "}, {"changes": {}}, {"changes": {"site": " "}}):
            r = client.post(URL, json=amend_body(**over), headers=h)
            assert r.status_code == 422, over
        bad = client.post(URL, json=amend_body(extra="x"), headers=h)
        assert bad.status_code == 422

    def test_a_second_tenant_cannot_amend_or_see_the_first(self, client, account_store):
        a = {"X-API-Key": account_store.issue_key(account_store.upsert_account(
            email="a@example.de", tier="cell").id)}
        b = {"X-API-Key": account_store.issue_key(account_store.upsert_account(
            email="b@example.de", tier="cell").id)}
        m = manifest("0412", fw(), zones())
        client.post("/v1/machinery/enrol", json=enrol_body(m), headers=a)
        # B has not enrolled this key: A's machine is not B's to amend
        rb = client.post(URL, json=amend_body(), headers=b)
        assert rb.status_code == 409 and rb.json()["detail"]["error"] == "not_enrolled"
        client.post("/v1/machinery/enrol", json=enrol_body(m), headers=b)
        assert client.post(URL, json=amend_body(changes={"site": "A-only"}),
                           headers=a).status_code == 200
        fb = client.get("/v1/fleet/machines", headers=b).json()["machines"][0]
        assert fb["site"] == "Plant 2" and "identity_amendments" not in fb
        fa = client.get("/v1/fleet/machines", headers=a).json()["machines"][0]
        assert fa["site"] == "A-only"


def test_amend_is_registered_as_a_capability_without_an_mcp_tool():
    from assurance.capabilities import CAPABILITIES
    cap = next(c for c in CAPABILITIES if c.id == "machinery.amend_enrolment")
    assert cap.cli == ("machinery amend-enrolment",)
    assert cap.api == ("POST /v1/machinery/enrol/amend",) and not cap.mcp
    assert cap.gaps["mcp"][0] == "by_design"
