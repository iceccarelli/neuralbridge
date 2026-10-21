"""The hosted Change Assurance lifecycle can finish.

Before these routes existed a hosted Cell customer whose case had an open human
question, or had been deferred, or named an entry nobody could re-verify, had no
route that moved it: ``resume``, ``resolve-decision``, ``waive-reverification``
and ``assess-intervention`` were CLI-only. Everything here goes through the real
FastAPI app, real per-account ledgers and the real domain functions.

Contract tested here (the workspace is built against it):

======================================================  =============================
``POST /v1/change/cases/{id}/resume``                   ``{reason, actor}``
``POST /v1/change/cases/{id}/resolve-decision``         ``{decision, resolution, actor}``
``POST /v1/change/cases/{id}/waive-reverification``     ``{entry, reason, actor}``
``POST /v1/change/assess/intervention``                 ``{manifest, intervention_id, actor?}``
``GET  /v1/change/cases/{id}/export``                   a verifiable bundle
``GET  /v1/change/cases/{id}/replay``                   the case rebuilt from the ledger
======================================================  =============================
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest

from . import test_assurance_change as _change
from .test_assurance_change import (
    advisory,
    fw,
    intervention,
    item,
    keyed,
    manifest,
    seal_a_real_verification,
)

# The app + per-account ledger fixtures are the ones the change tests already use.
client = _change.client
account_store = _change.account_store

PERSON = "v.grimaldi"

CELL_ONLY_POSTS = (
    ("resume", {"reason": "back", "actor": PERSON}),
    ("resolve-decision", {"decision": "q", "resolution": "a", "actor": PERSON}),
    ("waive-reverification", {"entry": "SF-01", "reason": "r", "actor": PERSON}),
)


def _drift(client, headers):
    r = client.post("/v1/change/assess/drift",
                    json={"baseline": manifest(manifest_id="BASE").to_dict(),
                          "observed": manifest(item(content_hash="d" * 64),
                                               manifest_id="NOW").to_dict()},
                    headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["case"]["case_id"]


def _seal_manifest(client, headers, m):
    r = client.post("/v1/machinery/manifest", json={"manifest": m.to_dict()}, headers=headers)
    assert r.status_code == 200, r.text


def _advisory_case(client, headers, *, contradictory: bool):
    """An advisory case. ``contradictory`` seals a label the advisory names with
    an artefact hash it contradicts, which is a question only a person can answer."""
    m = manifest(fw(content_hash="9" * 64) if contradictory else fw(),
                 manifest_id="MAN-0412")
    _seal_manifest(client, headers, m)
    r = client.post("/v1/change/assess/advisory",
                    json={"advisory": advisory().to_dict()}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["opened"] is True
    return r.json()["case"]


def _post(client, headers, case_id, verb, body):
    return client.post(f"/v1/change/cases/{case_id}/{verb}", json=body, headers=headers)


def _account_ids() -> list[str]:
    from assurance.api import deps

    db = sqlite3.connect(deps.get_accounts().path)
    try:
        return [r[0] for r in db.execute("SELECT id FROM accounts")]
    finally:
        db.close()


def _tenant_ledger(account_id: str):
    from assurance.api import deps

    return deps._tenant_register_for(str(deps.tenant_ledger_path(account_id))).ledger


class TestUnknownCaseIsA404OnEveryVerb:
    """GET gave 404 and every POST gave 409 for the same id. One answer now."""

    @pytest.mark.parametrize("verb,body", [
        ("claim", {"owner": PERSON, "actor": PERSON}),
        ("advance", {"actor": PERSON}),
        ("reverification", {"manifest": manifest().to_dict(),
                            "verification_content_hash": "a" * 64, "actor": PERSON}),
        ("decision", {"disposition": "rejected", "reason": "r", "actor": PERSON}),
        *CELL_ONLY_POSTS,
    ])
    def test_post(self, client, account_store, verb, body):
        headers = keyed(account_store, "cell")
        r = _post(client, headers, "case-doesnotexist", verb, body)
        assert r.status_code == 404, (verb, r.text)
        assert r.json()["detail"] == {"error": "case_not_found",
                                      "case_id": "case-doesnotexist"}

    @pytest.mark.parametrize("suffix", ["", "/export", "/replay"])
    def test_get(self, client, account_store, suffix):
        headers = keyed(account_store, "cell")
        r = client.get(f"/v1/change/cases/case-doesnotexist{suffix}", headers=headers)
        assert r.status_code == 404
        assert r.json()["detail"] == {"error": "case_not_found",
                                      "case_id": "case-doesnotexist"}

    def test_the_actor_rules_do_not_hide_an_unknown_case(self, client, account_store):
        """A reserved name on a case that does not exist is still 'no such case'."""
        headers = keyed(account_store, "cell")
        for verb, body in (("resume", {"reason": "r", "actor": "automation"}),
                           ("claim", {"owner": "automation", "actor": PERSON}),
                           ("decision", {"disposition": "closed", "reason": "r",
                                         "actor": "automation"})):
            assert _post(client, headers, "case-doesnotexist", verb, body).status_code == 404


class TestTheNewRoutesAreCellOnly:
    @pytest.mark.parametrize("verb,body", CELL_ONLY_POSTS)
    def test_unentitled_is_402_and_no_key_is_401(self, client, account_store, verb, body):
        url = f"/v1/change/cases/case-x/{verb}"
        assert client.post(url, json=body).status_code == 401
        assert client.post(url, json=body, headers={"X-API-Key": "nope"}).status_code == 401
        assert client.post(url, json=body, headers=keyed(account_store, "register")
                           ).status_code == 402

    def test_assess_intervention_and_the_reads_are_gated_the_same_way(
            self, client, account_store):
        body = {"manifest": manifest().to_dict(), "intervention_id": "INT-0007"}
        for headers, expected in ((None, 401), ({"X-API-Key": "nope"}, 401),
                                  (keyed(account_store, "register"), 402)):
            assert client.post("/v1/change/assess/intervention", json=body,
                               headers=headers).status_code == expected
            for suffix in ("/export", "/replay"):
                assert client.get(f"/v1/change/cases/case-x{suffix}",
                                  headers=headers).status_code == expected


class TestActorIsRequiredAndBoundToTheAccount:
    @pytest.mark.parametrize("verb,body", CELL_ONLY_POSTS)
    def test_a_missing_or_blank_actor_is_refused_at_the_door(
            self, client, account_store, verb, body):
        headers = keyed(account_store, "cell")
        case_id = _drift(client, headers)
        no_actor = {k: v for k, v in body.items() if k != "actor"}
        for candidate in (no_actor, {**no_actor, "actor": ""}, {**no_actor, "actor": "   "}):
            assert _post(client, headers, case_id, verb, candidate).status_code == 422

    def test_the_ledger_records_the_declared_person_and_the_vouching_account(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        case_id = _drift(client, headers)
        assert _post(client, headers, case_id, "claim",
                     {"owner": PERSON, "actor": PERSON}).status_code == 200
        r = _post(client, headers, case_id, "decision",
                  {"disposition": "deferred", "reason": "not today", "actor": PERSON})
        assert r.status_code == 200
        r = _post(client, headers, case_id, "resume",
                  {"reason": "back on it", "actor": "m.engineer"})
        assert r.status_code == 200 and r.json()["status"] == "in_review"
        (account_id,) = _account_ids()
        last = _tenant_ledger(account_id).entries(subject=case_id)[-1].evidence()
        assert last.actor.identifier == "m.engineer"
        assert last.actor.kind == "person"
        assert f"via account {account_id}" in last.actor.role


class TestNonPersonActorsAreRefusedByTheDomainNotTheRoute:
    @pytest.mark.parametrize("name", ["automation", "agent", "System", "bot-7",
                                      "аutomation"])
    def test_resume_resolve_waive_refuse_a_name_automation_goes_by(
            self, client, account_store, name):
        headers = keyed(account_store, "cell")
        case = _advisory_case(client, headers, contradictory=True)
        cid = case["case_id"]
        question = case["human_decisions_required"][0]
        entry = case["required_reverifications"][0]
        for verb, body in (
            ("resolve-decision", {"decision": question, "resolution": "ok", "actor": name}),
            ("waive-reverification", {"entry": entry, "reason": "r", "actor": name}),
        ):
            r = _post(client, headers, cid, verb, body)
            assert r.status_code == 409, (verb, r.text)
            assert "named person" in r.json()["detail"]
        assert _post(client, headers, cid, "decision",
                     {"disposition": "deferred", "reason": "later", "actor": PERSON}
                     ).status_code == 200
        r = _post(client, headers, cid, "resume", {"reason": "r", "actor": name})
        assert r.status_code == 409 and "named person" in r.json()["detail"]
        assert client.get(f"/v1/change/cases/{cid}", headers=headers).json()["status"] \
            == "deferred"


class TestResume:
    def test_a_deferred_case_can_be_resumed_by_a_person_and_only_from_deferred(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        cid = _drift(client, headers)
        r = _post(client, headers, cid, "resume", {"reason": "r", "actor": PERSON})
        assert r.status_code == 409 and "not deferred" in r.json()["detail"]
        assert _post(client, headers, cid, "decision",
                     {"disposition": "deferred", "reason": "not today",
                      "actor": PERSON}).status_code == 200
        r = _post(client, headers, cid, "resume", {"reason": "  ", "actor": PERSON})
        assert r.status_code == 409 and "reason" in r.json()["detail"]
        r = _post(client, headers, cid, "resume", {"reason": "capacity", "actor": PERSON})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "in_review"
        assert body["owner"] == PERSON
        assert body["decision"] == ""
        assert any("resumed by" in h["detail"] for h in body["history"])


class TestResolveDecisionAndWaiveFinishAHostedCase:
    def test_an_advisory_case_with_an_open_question_reaches_closed_over_http(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        case = _advisory_case(client, headers, contradictory=True)
        cid = case["case_id"]
        questions = list(case["human_decisions_required"])
        entries = list(case["required_reverifications"])
        assert questions, "the scenario must raise a question"
        assert entries

        assert _post(client, headers, cid, "claim",
                     {"owner": PERSON, "actor": PERSON}).status_code == 200
        for _ in range(2):
            r = _post(client, headers, cid, "advance", {"actor": PERSON})
            assert r.status_code == 200, r.text
        assert r.json()["status"] == "awaiting_reverification"

        # A question or entry that is not open is a 409, not a silent success.
        r = _post(client, headers, cid, "resolve-decision",
                  {"decision": "no such question", "resolution": "x", "actor": PERSON})
        assert r.status_code == 409 and "no open human decision" in r.json()["detail"]
        r = _post(client, headers, cid, "waive-reverification",
                  {"entry": "nope/SF-09", "reason": "x", "actor": PERSON})
        assert r.status_code == 409 and "no outstanding re-verification" in r.json()["detail"]
        r = _post(client, headers, cid, "decision",
                  {"disposition": "closed", "reason": "x", "actor": PERSON})
        assert r.status_code == 409                      # nothing answered yet

        for e in entries:
            r = _post(client, headers, cid, "waive-reverification",
                      {"entry": e, "reason": "Machine is out of service.", "actor": PERSON})
            assert r.status_code == 200, r.text
        waived = r.json()
        assert waived["required_reverifications"] == []
        assert all(waived["evidence_current"][e] == "waived" for e in entries)

        # With a question still open, the case must not reach ready_to_close.
        r = _post(client, headers, cid, "advance", {"actor": PERSON})
        assert r.status_code == 200 and r.json()["status"] == "awaiting_action"
        r = _post(client, headers, cid, "advance", {"actor": PERSON})
        assert r.status_code == 409 and "unresolved" in r.json()["detail"]

        for q in questions:
            r = _post(client, headers, cid, "resolve-decision",
                      {"decision": q, "resolution": "Hash checked against the table.",
                       "actor": PERSON})
            assert r.status_code == 200, r.text
        resolved = r.json()
        assert resolved["human_decisions_required"] == []
        assert [d["by"] for d in resolved["resolved_decisions"]
                if d.get("kind") != "waiver"] == [PERSON] * len(questions)

        r = _post(client, headers, cid, "advance", {"actor": PERSON})
        assert r.status_code == 200 and r.json()["status"] == "ready_to_close"
        r = _post(client, headers, cid, "decision",
                  {"disposition": "closed", "reason": "Closed on the waivers.",
                   "actor": PERSON})
        assert r.status_code == 200 and r.json()["status"] == "closed"

        replay = client.get(f"/v1/change/cases/{cid}/replay", headers=headers)
        assert replay.status_code == 200 and replay.json()["ok"] is True

    def test_an_empty_resolution_or_reason_is_refused_by_the_domain(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        case = _advisory_case(client, headers, contradictory=True)
        cid = case["case_id"]
        r = _post(client, headers, cid, "resolve-decision",
                  {"decision": case["human_decisions_required"][0],
                   "resolution": " ", "actor": PERSON})
        assert r.status_code == 409 and "resolution" in r.json()["detail"]
        r = _post(client, headers, cid, "waive-reverification",
                  {"entry": case["required_reverifications"][0], "reason": " ",
                   "actor": PERSON})
        assert r.status_code == 409 and "reason" in r.json()["detail"]

    def test_a_settled_case_cannot_be_waived_or_resolved(self, client, account_store):
        headers = keyed(account_store, "cell")
        case = _advisory_case(client, headers, contradictory=True)
        cid = case["case_id"]
        assert _post(client, headers, cid, "decision",
                     {"disposition": "rejected", "reason": "r", "actor": PERSON}
                     ).status_code == 200
        r = _post(client, headers, cid, "waive-reverification",
                  {"entry": case["required_reverifications"][0], "reason": "r",
                   "actor": PERSON})
        assert r.status_code == 409 and "already rejected" in r.json()["detail"]


class TestAssessIntervention:
    def _setup(self, client, headers):
        _seal_manifest(client, headers, manifest())
        (account_id,) = _account_ids()
        seal_a_real_verification(_tenant_ledger(account_id),
                                 when=datetime(2026, 2, 9, tzinfo=UTC))
        r = client.post("/v1/machinery/intervention",
                        json={"intervention": intervention().to_dict()}, headers=headers)
        assert r.status_code == 200, r.text

    def test_opens_a_case_and_is_idempotent(self, client, account_store):
        headers = keyed(account_store, "cell")
        self._setup(client, headers)
        body = {"manifest": manifest().to_dict(), "intervention_id": "INT-0007"}
        r = client.post("/v1/change/assess/intervention", json=body, headers=headers)
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["opened"] is True
        assert out["case"]["trigger_type"] == "intervention"
        assert "SF-01" in out["case"]["affected_functions"]
        again = client.post("/v1/change/assess/intervention", json=body, headers=headers)
        assert again.json()["case"]["case_id"] == out["case"]["case_id"]
        assert len(client.get("/v1/change/cases", headers=headers).json()["cases"]) == 1

    def test_an_intervention_the_ledger_does_not_hold_is_a_422_not_a_case(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        _seal_manifest(client, headers, manifest())
        r = client.post("/v1/change/assess/intervention",
                        json={"manifest": manifest().to_dict(),
                              "intervention_id": "INT-9999"}, headers=headers)
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "unknown_intervention"
        assert client.get("/v1/change/cases", headers=headers).json()["cases"] == []

    def test_a_bad_manifest_is_a_422(self, client, account_store):
        headers = keyed(account_store, "cell")
        r = client.post("/v1/change/assess/intervention",
                        json={"manifest": {"nonsense": True}, "intervention_id": "I"},
                        headers=headers)
        assert r.status_code == 422 and r.json()["detail"]["error"] == "invalid_manifest"


class TestTenancy:
    def test_another_accounts_case_is_a_404_on_every_new_route(self, client, account_store):
        a = keyed(account_store, "cell")
        other = account_store.upsert_account(email="other-cell@example.de", tier="cell")
        b = {"X-API-Key": account_store.issue_key(other.id)}
        cid = _drift(client, a)
        for verb, body in CELL_ONLY_POSTS:
            assert _post(client, b, cid, verb, body).status_code == 404, verb
        for suffix in ("", "/export", "/replay"):
            assert client.get(f"/v1/change/cases/{cid}{suffix}", headers=b).status_code == 404
        assert client.get(f"/v1/change/cases/{cid}", headers=a).json()["status"] == "open"


class TestExportAndReplay:
    def test_a_case_exported_over_http_verifies_offline(self, client, account_store, tmp_path):
        from assurance.evidence.verify_export import verify_export_file

        headers = keyed(account_store, "cell")
        cid = _drift(client, headers)
        assert _post(client, headers, cid, "claim",
                     {"owner": PERSON, "actor": PERSON}).status_code == 200
        r = client.get(f"/v1/change/cases/{cid}/export", headers=headers)
        assert r.status_code == 200
        bundle = r.json()
        assert bundle["subject"] == cid and bundle["chain_verified"] is True
        assert [e["kind"] for e in bundle["entries"]] == [
            "assurance.change.opened", "assurance.change.transition"]
        path = tmp_path / "case.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        result = verify_export_file(str(path))
        assert result.ok, result.text()

    def test_export_refuses_when_the_tenant_ledger_has_been_edited(
            self, client, account_store):
        from assurance.api import deps

        headers = keyed(account_store, "cell")
        cid = _drift(client, headers)
        (account_id,) = _account_ids()
        db = sqlite3.connect(deps.tenant_ledger_path(account_id))
        try:
            db.execute("UPDATE chain SET payload = replace(payload, 'drift', 'dxift')")
            db.commit()
        finally:
            db.close()
        r = client.get(f"/v1/change/cases/{cid}/export", headers=headers)
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "ledger_integrity"
        assert "does not verify" in r.json()["detail"]["detail"]


class TestAVerificationCanBeFiledUnderTheMachine:
    """Coverage, re-verification and the passport read verifications filed under
    the machine's key. ``machine verify`` filed them under ``product@version``
    only, so a hosted or CLI customer had no way to produce evidence that could
    clear a case."""

    def _verify(self, client, headers, **extra):
        from .interfaces_support import envelope_dict, trace_dict

        return client.post("/v1/machine/verify", json={
            "envelope": envelope_dict(),
            "trace": trace_dict(datetime(2026, 9, 1, tzinfo=UTC)),
            "actor": PERSON, **extra}, headers=headers)

    def test_the_api_files_it_under_the_machine_key_when_asked(self, client, account_store):
        from assurance.machinery.staleness import VerificationRecord

        from .test_assurance_change import MACHINE

        headers = keyed(account_store, "cell")
        r = self._verify(client, headers, subject=MACHINE.key)
        assert r.status_code == 200, r.text
        (account_id,) = _account_ids()
        ledger = _tenant_ledger(account_id)
        found = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert [v.content_hash for v in found] == [r.json()["content_hash"]]

    def test_the_default_is_unchanged_and_a_machine_key_is_not_guessed(
            self, client, account_store):
        from assurance.machinery.staleness import VerificationRecord

        from .test_assurance_change import MACHINE

        headers = keyed(account_store, "cell")
        assert self._verify(client, headers).status_code == 200
        (account_id,) = _account_ids()
        ledger = _tenant_ledger(account_id)
        assert VerificationRecord.from_ledger(ledger, subject=MACHINE.key) == []
        assert len(VerificationRecord.from_ledger(ledger, subject="AR-7@2.4.1")) == 1

    def test_the_cli_takes_the_same_subject(self, tmp_path):
        from assurance.evidence.ledger import EvidenceLedger
        from assurance.machine.cli import main as machine_main
        from assurance.machinery.staleness import VerificationRecord

        from .interfaces_support import envelope_dict, trace_dict
        from .test_assurance_change import MACHINE

        env, tr = tmp_path / "env.json", tmp_path / "trace.json"
        env.write_text(json.dumps(envelope_dict()))
        tr.write_text(json.dumps(trace_dict(datetime(2026, 9, 1, tzinfo=UTC))))
        ledger_path = tmp_path / "l.db"
        rc = machine_main(["verify", "--envelope", str(env), "--trace", str(tr),
                           "--actor", PERSON, "--ledger", str(ledger_path),
                           "--subject", MACHINE.key])
        assert rc == 0
        ledger = EvidenceLedger(ledger_path)
        assert len(VerificationRecord.from_ledger(ledger, subject=MACHINE.key)) == 1


class TestTheRegisterExportOfAnUnknownCase:
    """`GET /v1/cases/{id}/export` answered 200 with an empty bundle for an id that
    names nothing, which `evidence verify` then (wrongly) called verified."""

    def test_unknown_is_404_with_the_shape_the_other_verbs_use(self, client, account_store):
        headers = keyed(account_store, "register")
        r = client.get("/v1/cases/C-nope/export", headers=headers)
        assert r.status_code == 404
        assert r.json()["detail"] == {"error": "case_not_found", "case_id": "C-nope"}

    def test_a_known_case_still_exports_and_another_tenants_is_a_404(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        cid = _drift(client, headers)
        assert client.get(f"/v1/cases/{cid}/export", headers=headers).status_code == 200
        other = account_store.upsert_account(email="other-register@example.de", tier="register")
        b = {"X-API-Key": account_store.issue_key(other.id)}
        assert client.get(f"/v1/cases/{cid}/export", headers=b).status_code == 404


class TestNoAlwaysEmptyFieldIsPresentedAsData:
    """`reviewer` and `last_valid_verification` were never set by anything, so every
    case said `""` and the text view said 'reviewer: —'. They are reserved: not
    emitted until something truthfully fills them."""

    def test_the_api_case_does_not_carry_them(self, client, account_store):
        headers = keyed(account_store, "cell")
        cid = _drift(client, headers)
        case = client.get(f"/v1/change/cases/{cid}", headers=headers).json()
        assert "reviewer" not in case and "last_valid_verification" not in case
        rows = client.get("/v1/change/cases", headers=headers).json()["cases"]
        assert "reviewer" not in rows[0]

    def test_old_snapshots_that_carry_the_keys_still_load(self):
        from assurance.change.model import CaseStatus, ChangeAssuranceCase, TriggerType

        case = ChangeAssuranceCase(case_id="c", trigger_type=TriggerType.MACHINE_DRIFT,
                                   trigger_id="t", status=CaseStatus.OPEN)
        old = {**case.to_dict(), "reviewer": "", "last_valid_verification": ""}
        assert ChangeAssuranceCase.from_dict(old) == case
        assert "reviewer:" not in case.summary()
