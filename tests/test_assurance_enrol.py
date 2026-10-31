"""Enrolment: the front door of the lifecycle.

``enrol_machine`` seals the manifest, records the machine's declared identity once, and
returns a receipt that says what it does NOT establish. These tests pin the receipt, the
idempotency, the two refusals (changed configuration, identity conflict), that nothing is
written when refusing, that coverage stays ``never_verified``, that the words a receipt may
never say are absent, and that CLI and API are the same function.
"""
# ruff: noqa: S603  (the tests run this package's own CLI)
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import (
    ENROLMENT_KIND,
    EnrolmentError,
    enrol_machine,
    enrolment_of,
)
from assurance.machinery.manifest import HashSource, ItemKind, SafetyItem
from assurance.machinery.record import MANIFEST_KIND
from assurance.machinery.staleness import VerificationRecord, assess_coverage

from . import test_assurance_change as _change
from .test_assurance_check import FUNCS, fw, manifest, zones

client = _change.client
account_store = _change.account_store

PERSON = Actor("a.integrator", "safety engineer")

#: Words a receipt must never use to describe the machine. "not verified safe" is the
#: limit it states; these are checked on the text with the stated limits removed.
FORBIDDEN = ("compliant", "compliance", "certified", "safe to operate")


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "enrol.db")


def uncomparable():
    return SafetyItem("ITM-PARAMS", ItemKind.SAFETY_CONFIGURATION, "Safety parameters", "1",
                      "", HashSource.DECLARED, supplier="ControlCo",
                      implements=("SF-01",))


def kinds(ledger):
    return [e.kind for e in ledger.entries()]


def _prose(receipt) -> str:
    """The receipt's text with the limits it states stripped, for the forbidden-word check."""
    text = receipt.summary() + json.dumps(receipt.to_dict())
    for stated in ("not verified safe", "not been verified", "does not establish",
                   "not authenticated", "NOT establish"):
        text = text.replace(stated, "")
    return text.lower()


# -- the receipt -------------------------------------------------------------


class TestReceipt:
    def test_first_enrolment_seals_manifest_then_enrolment(self, ledger):
        m = manifest("0412", fw(), zones(), uncomparable())
        r = enrol_machine(ledger, m, actor=PERSON, site="Plant 2", owner="Example GmbH")
        assert r.status == "enrolled" and r.written
        assert kinds(ledger) == [MANIFEST_KIND, ENROLMENT_KIND]
        assert (r.manifest_entry, r.enrolment_entry) == (1, 2)
        assert r.machine_key == m.machine.key == "Grimaldi/AR-7#0412"
        assert r.configuration_hash == m.configuration_hash()
        assert r.manifest_content_hash == ledger.entries()[0].content_hash
        assert r.enrolment_content_hash == ledger.entries()[1].content_hash
        assert r.declared["site"] == "Plant 2" and r.declared["owner"] == "Example GmbH"

    def test_receipt_content(self, ledger):
        m = manifest("0412", fw(), zones(), uncomparable())
        d = enrol_machine(ledger, m, actor=PERSON).to_dict()
        assert d["items"] == 3
        assert d["uncomparable_items"] == ["ITM-PARAMS"]
        assert "no hash" in d["uncomparable_note"]
        assert d["tier_ceiling"] == m.tier_ceiling.value
        assert "not a result" in d["tier_ceiling_note"]
        assert d["identity_basis"].endswith("not authenticated to a physical unit")
        joined = " | ".join(d["does_not_establish"])
        for must in ("not verified safe", "no verification has been run yet",
                     "manifest completeness is not shown",
                     "identity is as declared, not authenticated to a physical unit"):
            assert must in joined
        assert any("verify" in s for s in d["next_steps"])
        assert any("baseline" in s for s in d["next_steps"])

    def test_undemonstrable_functions_are_named(self, ledger):
        from assurance.machinery.manifest import SafetyFunction
        funcs = (*FUNCS, SafetyFunction("SF-09", "Unchecked function", "PL c"))
        m = manifest("0412", fw(implements=("SF-01", "SF-02", "SF-09")), zones(),
                     functions=funcs)
        r = enrol_machine(ledger, m, actor=PERSON)
        assert r.undemonstrable_functions == ("SF-09",)
        assert r.coverage["SF-09"] == "not_demonstrable"

    def test_coverage_is_never_verified_until_a_verification_exists(self, ledger):
        m = manifest("0412", fw(), zones())
        r = enrol_machine(ledger, m, actor=PERSON)
        assert set(r.coverage) == {"SF-01", "SF-02"}
        assert set(r.coverage.values()) == {"never_verified"}
        # and the independent read of the ledger agrees
        report = assess_coverage(m, VerificationRecord.from_ledger(ledger, subject=m.machine.key),
                                 [])
        assert {f.coverage.value for f in report.functions} == {"never_verified"}
        assert report.verdict == "gaps"

    def test_the_receipt_never_says_verified_compliant_or_safe(self, ledger):
        m = manifest("0412", fw(), zones())
        for r in (enrol_machine(ledger, m, actor=PERSON),
                  enrol_machine(ledger, m, actor=PERSON)):
            text = _prose(r)
            for word in FORBIDDEN:
                assert word not in text, word
            assert "verified" not in text.replace("never_verified", "").replace(
                "unverified", "").replace("no verification", ""), text

    def test_the_chain_still_verifies(self, ledger):
        m = manifest("0412", fw(), zones())
        enrol_machine(ledger, m, actor=PERSON)
        enrol_machine(ledger, m, actor=PERSON)
        assert ledger.verify_chain() == (True, [])
        entry, body = enrolment_of(ledger, m.machine.key)
        assert entry.actor == "a.integrator" and body["configuration_hash"]


# -- idempotency -------------------------------------------------------------


class TestIdempotent:
    def test_reenrolling_the_same_configuration_writes_nothing(self, ledger):
        m = manifest("0412", fw(), zones())
        first = enrol_machine(ledger, m, actor=PERSON)
        n = len(ledger)
        again = enrol_machine(ledger, m, actor=Actor("someone.else", "x"))
        assert again.status == "already_enrolled" and not again.written and not again.refused
        assert len(ledger) == n
        assert again.enrolment_content_hash == first.enrolment_content_hash
        assert again.enrolled_by == "a.integrator"       # not rewritten by the second caller

    def test_a_later_manifest_of_the_same_configuration_is_already_enrolled(self, ledger):
        m = manifest("0412", fw(), zones())
        enrol_machine(ledger, m, actor=PERSON)
        later = replace(m, manifest_id="MAN-LATER", notes="looked again")
        assert later.configuration_hash() == m.configuration_hash()
        n = len(ledger)
        assert enrol_machine(ledger, later, actor=PERSON).status == "already_enrolled"
        assert len(ledger) == n

    def test_an_attribute_not_declared_at_enrolment_is_not_added_silently(self, ledger):
        m = manifest("0412", fw(), zones())
        enrol_machine(ledger, m, actor=PERSON)
        n = len(ledger)
        r = enrol_machine(ledger, m, actor=PERSON, owner="Late Owner AG")
        assert r.status == "already_enrolled" and len(ledger) == n
        assert any("owner" in note and "not added" in note for note in r.notes)

    def test_a_manifest_already_sealed_by_record_manifest_is_referenced_not_duplicated(
            self, ledger):
        from assurance.machinery.record import record_manifest
        m = manifest("0412", fw(), zones())
        record_manifest(ledger, m, actor=PERSON)
        r = enrol_machine(ledger, m, actor=PERSON)
        assert r.status == "enrolled" and kinds(ledger) == [MANIFEST_KIND, ENROLMENT_KIND]
        assert r.manifest_entry == 1 and r.enrolment_entry == 2
        assert any("already sealed" in n for n in r.notes)


# -- the refusals ------------------------------------------------------------


class TestChangedConfiguration:
    def test_is_refused_with_a_pointer_and_nothing_is_written(self, ledger):
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON)
        n = len(ledger)
        changed = manifest("0412", fw(content_hash="9" * 64), zones(), manifest_id="MAN-NEW")
        r = enrol_machine(ledger, changed, actor=PERSON)
        assert r.status == "configuration_differs" and r.refused and not r.written
        assert len(ledger) == n
        assert "already enrolled, configuration differs" in r.pointer
        assert "machinery diff" in r.pointer and "drift" in r.pointer
        assert r.enrolled_configuration_hash != r.configuration_hash

    def test_the_changed_manifest_is_not_sealed_as_a_side_effect(self, ledger):
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON)
        enrol_machine(ledger, manifest("0412", fw(version="4.0", content_hash="8" * 64),
                                       zones(), manifest_id="MAN-X"), actor=PERSON)
        assert kinds(ledger) == [MANIFEST_KIND, ENROLMENT_KIND]


class TestIdentityConflict:
    def test_different_site_is_a_conflict_and_writes_nothing(self, ledger):
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON, owner="A GmbH")
        n = len(ledger)
        r = enrol_machine(ledger, manifest("0412", fw(), zones(), site="Plant 9"),
                          actor=PERSON)
        assert r.status == "identity_conflict" and r.refused and len(ledger) == n
        assert r.conflicts[0]["attribute"] == "site"
        assert r.conflicts[0]["enrolled"] == "Plant 2" and r.conflicts[0]["claimed"] == "Plant 9"

    def test_different_owner_is_a_conflict_even_with_the_same_configuration(self, ledger):
        m = manifest("0412", fw(), zones())
        enrol_machine(ledger, m, actor=PERSON, owner="A GmbH")
        n = len(ledger)
        r = enrol_machine(ledger, m, actor=PERSON, owner="B AG")
        assert r.status == "identity_conflict" and len(ledger) == n
        assert [c["attribute"] for c in r.conflicts] == ["owner"]

    def test_the_conflict_wins_over_configuration_differs(self, ledger):
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON, owner="A GmbH")
        r = enrol_machine(ledger, manifest("0412", fw(content_hash="9" * 64), zones()),
                          actor=PERSON, owner="B AG")
        assert r.status == "identity_conflict"

    def test_an_unstated_owner_does_not_conflict(self, ledger):
        m = manifest("0412", fw(), zones())
        enrol_machine(ledger, m, actor=PERSON, owner="A GmbH")
        assert enrol_machine(ledger, m, actor=PERSON).status == "already_enrolled"

    def test_a_site_that_contradicts_the_manifest_is_refused_as_input(self, ledger):
        with pytest.raises(EnrolmentError, match="disagrees"):
            enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON,
                          site="Somewhere else")
        assert len(ledger) == 0

    def test_a_different_serial_is_a_different_machine(self, ledger):
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON)
        assert enrol_machine(ledger, manifest("0413", fw(), zones()),
                             actor=PERSON).status == "enrolled"


class TestActor:
    @pytest.mark.parametrize("actor", [
        None, Actor("", "x"), Actor("   ", "x"), Actor("m.braun", "x", kind="automation"),
        Actor("m.braun", "x", kind="service"), Actor("automation"), Actor("Bot-7"),
        Actor("agent."), Actor("​​"), Actor("---"),
    ])
    def test_refused_and_nothing_written(self, ledger, actor):
        with pytest.raises(EnrolmentError):
            enrol_machine(ledger, manifest("0412", fw(), zones()), actor=actor)
        assert len(ledger) == 0

    def test_a_name_that_merely_contains_a_reserved_word_is_a_person(self, ledger):
        assert enrol_machine(ledger, manifest("0412", fw(), zones()),
                             actor=Actor("Agent Smith")).status == "enrolled"


class TestLedgerIntegrity:
    def test_a_broken_chain_enrols_nothing(self, ledger):
        import sqlite3
        enrol_machine(ledger, manifest("0412", fw(), zones()), actor=PERSON)
        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET content_hash = 'f' WHERE seq = 1")
        db.commit()
        db.close()
        n = len(ledger)
        with pytest.raises(EnrolmentError, match="chain does not verify"):
            enrol_machine(ledger, manifest("0413", fw(), zones()), actor=PERSON)
        assert len(ledger) == n


# -- CLI ---------------------------------------------------------------------


def cli(tmp_path, *args):
    return subprocess.run([sys.executable, "-m", "assurance", "machinery", *args],
                          cwd=tmp_path, capture_output=True, text=True, check=False)


class TestCli:
    def _write(self, tmp_path, name, m):
        path = tmp_path / name
        path.write_text(json.dumps(m.to_dict()), "utf-8")
        return path.name

    def test_exit_codes_and_creation_on_first_use(self, tmp_path):
        a = self._write(tmp_path, "a.json", manifest("0412", fw(), zones()))
        run = cli(tmp_path, "enrol", a, "--ledger", "l.db", "--actor", "a.integrator",
                  "--owner", "Example GmbH")
        assert run.returncode == 0, run.stderr
        assert (tmp_path / "l.db").exists()
        assert "enrolled Grimaldi/AR-7#0412" in run.stdout
        assert "enrolment does NOT establish" in run.stdout
        again = cli(tmp_path, "enrol", a, "--ledger", "l.db", "--actor", "a.integrator",
                    "--owner", "Example GmbH")
        assert again.returncode == 0 and "already enrolled" in again.stdout

        b = self._write(tmp_path, "b.json",
                        manifest("0412", fw(content_hash="9" * 64), zones(), manifest_id="N"))
        differs = cli(tmp_path, "enrol", b, "--ledger", "l.db", "--actor", "a.integrator")
        assert differs.returncode == 1 and "configuration differs" in differs.stdout
        conflict = cli(tmp_path, "enrol", a, "--ledger", "l.db", "--actor", "a.integrator",
                       "--owner", "Other AG")
        assert conflict.returncode == 1 and "different declared attributes" in conflict.stdout

        ledger = EvidenceLedger.open_existing(tmp_path / "l.db")
        assert kinds(ledger) == [MANIFEST_KIND, ENROLMENT_KIND]
        assert ledger.verify_chain() == (True, [])

    def test_json_is_the_receipt(self, tmp_path):
        a = self._write(tmp_path, "a.json", manifest("0412", fw(), zones()))
        run = cli(tmp_path, "enrol", a, "--ledger", "l.db", "--actor", "a.integrator", "--json")
        d = json.loads(run.stdout)
        assert d["status"] == "enrolled" and d["coverage"] == {
            "SF-01": "never_verified", "SF-02": "never_verified"}

    @pytest.mark.parametrize("actor", ["", "automation", "bot-1"])
    def test_empty_or_automation_actor_is_exit_2_and_creates_no_ledger(self, tmp_path, actor):
        a = self._write(tmp_path, "a.json", manifest("0412", fw(), zones()))
        run = cli(tmp_path, "enrol", a, "--ledger", "l.db", "--actor", actor)
        assert run.returncode == 2 and "named person" in run.stderr
        assert not (tmp_path / "l.db").exists()

    def test_missing_actor_and_missing_file_are_exit_2(self, tmp_path):
        a = self._write(tmp_path, "a.json", manifest("0412", fw(), zones()))
        assert cli(tmp_path, "enrol", a, "--ledger", "l.db").returncode == 2
        assert cli(tmp_path, "enrol", "nope.json", "--ledger", "l.db",
                   "--actor", "x.y").returncode == 2

    def test_site_contradicting_the_manifest_is_exit_2(self, tmp_path):
        a = self._write(tmp_path, "a.json", manifest("0412", fw(), zones()))
        run = cli(tmp_path, "enrol", a, "--ledger", "l.db", "--actor", "x.y", "--site", "Elsewhere")
        assert run.returncode == 2 and "disagrees" in run.stderr


# -- API ---------------------------------------------------------------------


def body(m, **over):
    return {"manifest": m.to_dict(), "actor": "a.integrator", **over}


class TestApi:
    def test_no_key_is_401(self, client):
        r = client.post("/v1/machinery/enrol", json=body(manifest("0412", fw(), zones())))
        assert r.status_code == 401

    def test_authenticated_but_unentitled_is_402(self, client, account_store):
        headers = _change.keyed(account_store, "register")
        r = client.post("/v1/machinery/enrol", json=body(manifest("0412", fw(), zones())),
                        headers=headers)
        assert r.status_code == 402
        same = client.post("/v1/machinery/manifest",
                           json={"manifest": manifest("0412", fw(), zones()).to_dict()},
                           headers=headers)
        assert same.status_code == 402          # gated exactly like the manifest route

    def test_enrol_then_idempotent_then_refusals(self, client, account_store):
        h = _change.keyed(account_store, "cell")
        m = manifest("0412", fw(), zones())
        r = client.post("/v1/machinery/enrol", json=body(m, owner="A GmbH"), headers=h)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["status"] == "enrolled" and d["enrolment_entry"] == 2
        assert set(d["coverage"].values()) == {"never_verified"}
        assert d["does_not_establish"]
        again = client.post("/v1/machinery/enrol", json=body(m, owner="A GmbH"), headers=h)
        assert again.status_code == 200 and again.json()["status"] == "already_enrolled"

        changed = manifest("0412", fw(content_hash="9" * 64), zones(), manifest_id="N")
        r = client.post("/v1/machinery/enrol", json=body(changed), headers=h)
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "configuration_differs"
        assert r.json()["detail"]["receipt"]["written"] is False
        r = client.post("/v1/machinery/enrol", json=body(m, owner="B AG"), headers=h)
        assert r.status_code == 409 and r.json()["detail"]["error"] == "identity_conflict"

    def test_coverage_through_the_api_agrees(self, client, account_store):
        h = _change.keyed(account_store, "cell")
        m = manifest("0412", fw(), zones())
        client.post("/v1/machinery/enrol", json=body(m), headers=h)
        cov = client.post("/v1/machinery/coverage", json={"manifest": m.to_dict()}, headers=h)
        assert cov.status_code == 200
        assert {f["coverage"] for f in cov.json()["functions"]} == {"never_verified"}

    def test_unnamed_or_automation_actor_is_422(self, client, account_store):
        h = _change.keyed(account_store, "cell")
        m = manifest("0412", fw(), zones())
        for actor in ("automation", "bot-3"):
            r = client.post("/v1/machinery/enrol", json=body(m, actor=actor), headers=h)
            assert r.status_code == 422, actor
            assert r.json()["detail"]["error"] == "invalid_enrolment"
        assert client.post("/v1/machinery/enrol", json=body(m, actor=""),
                           headers=h).status_code == 422

    def test_a_second_tenant_cannot_see_or_collide_with_the_first(self, client, account_store):
        a = {"X-API-Key": account_store.issue_key(account_store.upsert_account(
            email="a@example.de", tier="cell").id)}
        b = {"X-API-Key": account_store.issue_key(account_store.upsert_account(
            email="b@example.de", tier="cell").id)}
        m = manifest("0412", fw(), zones())
        assert client.post("/v1/machinery/enrol", json=body(m, owner="A GmbH"),
                           headers=a).json()["status"] == "enrolled"
        # B enrols the same key with a different owner: no conflict, it is B's own ledger.
        rb = client.post("/v1/machinery/enrol", json=body(m, owner="B AG"), headers=b)
        assert rb.status_code == 200 and rb.json()["status"] == "enrolled"
        assert rb.json()["declared"]["owner"] == "B AG"
        # and B's coverage/passport reads show only B's ledger
        other = manifest("0999", fw(), zones())
        client.post("/v1/machinery/enrol", json=body(other), headers=a)
        cov = client.post("/v1/machinery/coverage", json={"manifest": other.to_dict()},
                          headers=b)
        assert {f["coverage"] for f in cov.json()["functions"]} == {"never_verified"}
        from assurance.api import deps
        regs = {p.name for p in deps.tenant_ledgers_dir().glob("*.db")}
        assert len(regs) == 2


def test_enrol_is_registered_as_a_capability_without_an_mcp_tool():
    from assurance.capabilities import CAPABILITIES
    cap = next(c for c in CAPABILITIES if c.id == "machinery.enrol")
    assert cap.cli and cap.api == ("POST /v1/machinery/enrol",) and not cap.mcp
    assert cap.gaps["mcp"][0] == "by_design"
