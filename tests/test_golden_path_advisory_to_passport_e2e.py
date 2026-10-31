"""The golden path's missing second half: a supplier advisory, through to a machine passport.

``test_golden_path_e2e.py`` covers provisioning, drift cases, waivers and signed exports. It
has no advisory, no intervention and no passport. This file drives ONE scenario through the
real FastAPI app (a real socket, real accounts and entitlements, real per-account ledgers,
throwaway keys; nothing in the domain or HTTP layer is mocked):

    entitled account -> machine manifest -> baseline verification -> signed supplier
    advisory (unpinned, then pinned by a named decider) -> case opened by a named person ->
    intervention recorded -> coverage goes stale -> fresh manifest + attested verification ->
    re-verification (``ready_to_close``, NOT closed) -> a named human closes -> passport ->
    anonymous passport check.

At every step it asserts that the status vocabulary stays separate (``trusted`` /
``untrusted_*``, ``current`` / ``stale`` / ``never_verified``, ``covered`` / ``gaps``,
``ready_to_close`` / ``closed``), that the reason travels with the status, that no key is
401 and an unentitled key is 402, that a second tenant sees nothing, and that software alone
cannot close a case.

What this does not prove: that any recorder, supplier or machine is truthful, that the
supplier's advisory is correct, or anything about a deployed service. The manifest is the
synthetic vendor export of ``Plant``; the supplier key and the recorder are throwaway keys.
"""

from __future__ import annotations

import copy
import json
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from assurance.attest.keys import SigningKey
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.supplier import AdvisoryFeed, SupplierIdentity, publish

from . import interfaces_fixtures as fx
from .interfaces_scenario import KEY, PERSON, Plant, run_started
from .interfaces_support import envelope, envelope_dict, trace
from .support_recorder import RECORDER

live_api = fx.live_api

SUPPLIER = "roboco"
ADVISORY_ID = "ROBO-2026-77"
ITEM = "ITM-PARAMS"
FIXED_HASH = "f" * 64
IDENTITY = SupplierIdentity(supplier_id=SUPPLIER, legal_name="RoboCo GmbH",
                            key_contact="the 2025 supply contract")
ENTRIES = (f"{KEY}/SF-01", f"{KEY}/SF-02")


def now_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def advisory_for(manifest: dict[str, Any], advisory_id: str = ADVISORY_ID,
                 **over: Any) -> ComponentAdvisory:
    """An advisory naming the exact artefact (by hash) the machine's parameter set is."""
    params = next(i for i in manifest["items"] if i["item_id"] == ITEM)
    body: dict[str, Any] = {
        "advisory_id": advisory_id, "issued_by": SUPPLIER,
        "issued_at": datetime(2026, 9, 12, 8, tzinfo=UTC),
        "title": "Parameter export may omit the stop category", "summary": "s",
        "severity": AdvisorySeverity.SAFETY_RELEVANT,
        "affected": (AffectedArtefact(supplier="RoboCo", name="Robot safety parameter set",
                                      versions=(params["version"],),
                                      content_hashes=(params["content_hash"],)),),
        "remedy": "Re-export with the 3.9.0 tool.",
        "reference": "https://roboco.example/psirt/" + advisory_id,
        "fixed_versions": ("3.9.0",), "fixed_hashes": (FIXED_HASH,),
    }
    body.update(over)
    return ComponentAdvisory(**body)


def signed_feed(tmp_path, advisory: ComponentAdvisory, key: SigningKey, name: str = "feed") -> str:
    feed = AdvisoryFeed(tmp_path / f"{name}.jsonl")
    publish(advisory, IDENTITY, key, feed)
    return feed.path.read_text(encoding="utf-8")


def verification_body(trace_id: str, *, attested: bool = True) -> dict[str, Any]:
    run = trace(run_started(), trace_id=trace_id)
    body: dict[str, Any] = {"envelope": envelope_dict(), "trace": run.hashable_payload(),
                            "actor": PERSON, "subject": KEY}
    if attested:
        body["recorder_attestations"] = RECORDER.attestation_dicts(
            envelope(), run, machine_serial="0501")
    return body


@pytest.fixture(scope="module")
def sealed_manifest(tmp_path_factory) -> dict[str, Any]:
    """The machine as a vendor-export collection reads it (synthetic; see ``Plant``)."""
    plant = Plant(tmp_path_factory.mktemp("plant"), serials=("0501",))
    plant.kit_run("cli")
    return plant.manifest_dict(KEY)


class World:
    """One entitled account (A) with a decider operator, over the real app."""

    def __init__(self, live: fx.LiveApi, manifest: dict[str, Any], tmp_path) -> None:
        self.live, self.manifest, self.tmp = live, manifest, tmp_path
        self.http = live.client()
        self.account_id, self.key = live.account("alpha@golden.example", "cell")
        self.decider = live.operator_headers(self.account_id, PERSON)
        self.supplier_key = SigningKey.generate()

    def call(self, method: str, path: str, headers: dict[str, str] | None = None,
             body: Any = None, **params: Any) -> httpx.Response:
        return self.http.request(method, path, json=body, params=params,
                                 headers=self.key if headers is None else headers)

    def ok(self, method: str, path: str, headers: dict[str, str] | None = None,
           body: Any = None, **params: Any) -> dict[str, Any]:
        r = self.call(method, path, headers, body, **params)
        assert r.status_code in (200, 201), f"{method} {path}: {r.status_code} {r.text[:400]}"
        return r.json()

    def seal_manifest(self, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.ok("POST", "/v1/machinery/manifest",
                       body={"manifest": manifest or self.manifest, "actor": "m.keller"})

    def verify(self, trace_id: str, *, attested: bool = True) -> dict[str, Any]:
        return self.ok("POST", "/v1/machine/verify",
                       body=verification_body(trace_id, attested=attested))

    def coverage(self, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.ok("POST", "/v1/machinery/coverage", body={"manifest": manifest or self.manifest})

    def pin_supplier(self) -> dict[str, Any]:
        return self.ok("POST", "/v1/supplier/trust/pin", self.decider, {
            "supplier_id": SUPPLIER, "public_key_pem": self.supplier_key.verifying.pem(),
            "expected_fingerprint": self.supplier_key.fingerprint,
            "obtained_via": "read aloud by RoboCo PSIRT on the phone"})

    def signed(self, feed_text: str, **extra: Any) -> dict[str, Any]:
        return self.ok("POST", "/v1/fleet/advisory/signed", body={"feed": feed_text, **extra})

    def assess(self, advisory: ComponentAdvisory, actor: str = PERSON, **extra: Any
               ) -> httpx.Response:
        body = {"advisory": advisory.to_dict(), **extra}
        if actor:
            body["actor"] = actor
        return self.call("POST", "/v1/change/assess/advisory", body=body)

    def case(self, case_id: str) -> dict[str, Any]:
        return self.ok("GET", f"/v1/change/cases/{case_id}")


@pytest.fixture
def world(live_api, sealed_manifest, tmp_path):
    w = World(live_api, sealed_manifest, tmp_path)
    try:
        yield w
    finally:
        w.http.close()


def second_tenant(live: fx.LiveApi) -> tuple[str, dict[str, str], dict[str, str]]:
    acct, key = live.account("bravo@golden.example", "cell")
    return acct, key, live.operator_headers(acct, "b.decider")


def trust_view(trust: dict[str, Any]) -> tuple[Any, ...]:
    """The separate states a feed evaluation reports; there is deliberately no single flag."""
    assert "verified" not in trust and "ok" not in trust
    return (trust["trust_state"], trust["signature_state"], trust["key_trust_state"],
            trust["chain_valid"], trust["policy_satisfied"])


# =====================================================================
# the happy path, one step at a time
# =====================================================================
class TestAdvisoryToPassport:
    def test_the_whole_path(self, world: World, live_api: fx.LiveApi, tmp_path):
        w, manifest = world, world.manifest
        http = w.http

        # -- 0. the gate on every paid route: no key 401, bad key 401, unentitled 402 ------
        r_acct, r_key = live_api.account("romeo@golden.example", "register")
        adv = advisory_for(manifest)
        feed_text = signed_feed(tmp_path, adv, w.supplier_key)
        paid = [
            ("POST", "/v1/machinery/manifest", {"manifest": manifest, "actor": "m.keller"}),
            ("POST", "/v1/fleet/advisory/signed", {"feed": feed_text}),
            ("POST", "/v1/change/assess/advisory", {"advisory": adv.to_dict(), "actor": PERSON}),
            ("POST", "/v1/machinery/intervention", {"intervention": {}}),
            ("POST", "/v1/machinery/coverage", {"manifest": manifest}),
            ("POST", "/v1/machinery/passport", {"manifest": manifest, "actor": PERSON}),
            ("POST", "/v1/machine/verify", verification_body("RUN-GATE")),
            ("GET", "/v1/change/cases", None),
        ]
        for method, path, body in paid:
            assert w.call(method, path, {}, body).status_code == 401, path
            assert w.call(method, path, {"X-API-Key": "asr_not_a_key"}, body).status_code == 401, path
            denied = w.call(method, path, r_key, body)
            assert denied.status_code == 402, (path, denied.status_code, denied.text[:200])
            assert denied.json()["detail"]["tier"] == "register", path
        # the one free route stays free: anonymous passport check is not gated (step 9)
        assert r_acct != w.account_id

        # -- 1. seal the machine's manifest --------------------------------------------------
        sealed = w.seal_manifest()
        assert sealed["machine"] == KEY and sealed["items"] == 4
        assert sealed["tier_ceiling"] == "validated"           # a ceiling, not a result
        assert sealed["uncomparable_items"] == [] and sealed["undemonstrable_functions"] == []
        assert sealed["checks_skipped"], "a manifest must say what it did not establish"
        assert any("does not establish that the collection was complete" in c
                   for c in sealed["checks_skipped"])

        # -- 1b. before anything is verified, coverage is never_verified, not 'ok' -----------
        before = w.coverage()
        assert before["verdict"] == "gaps"
        assert {f["coverage"] for f in before["functions"]} == {"never_verified"}
        assert all(f["detail"] for f in before["functions"])

        # -- 1c. a baseline verification by a recorder the server trusts: current/validated --
        baseline = w.verify("RUN-BASELINE")
        assert baseline["recorder_attestation"]["attested"] is True
        assert baseline["tier"] == "validated"
        cov = w.coverage()
        assert cov["verdict"] == "covered"
        assert {f["coverage"] for f in cov["functions"]} == {"current"}
        assert {f["evidence_tier"] for f in cov["functions"]} == {"validated"}

        # -- 2. a signed advisory, NOT yet pinned: assessed, but inspect-only ----------------
        unpinned = w.signed(feed_text)
        t = unpinned["trust"]
        assert t["trust_state"] == "untrusted_unknown_key"
        assert trust_view(t) == ("untrusted_unknown_key", "not_checkable", "unknown_key",
                                 True, False)
        assert t["problems"] and "unknown key" in t["problems"][0]
        assert unpinned["inspect_only"] is True
        row = unpinned["advisories"][0]
        assert row["automated_consequences_permitted"] is False
        assert row["trust_basis"] == "none" and row["record_authentic"] is False
        assert row["impact"]["provenance"]["inspect_only"] is True
        # the impact is still computed for a human to read ...
        assert row["impact"]["machine_classification"][0]["classification"] == "match_by_hash"
        # ... and what a signature does not prove is said, not implied
        assert "correct, complete or timely" in unpinned["trust_statement"]

        # pinning a supplier key is a human decision: an account key cannot make it
        by_account = w.call("POST", "/v1/supplier/trust/pin", None, {
            "supplier_id": SUPPLIER, "public_key_pem": w.supplier_key.verifying.pem(),
            "obtained_via": "phone"})
        assert by_account.status_code == 403
        assert by_account.json()["detail"]["error"] == "operator_required"
        assert w.ok("GET", "/v1/supplier/trust")["pins"] == []
        pin = w.pin_supplier()["pin"]
        assert pin["status"] == "active" and pin["fingerprint"] == w.supplier_key.fingerprint
        assert PERSON in pin["pinned_by"] and pin["obtained_via"]

        # -- 2b. pinned: trusted, with the states still reported separately ------------------
        pinned = w.signed(feed_text)
        assert trust_view(pinned["trust"]) == ("trusted", "all_valid", "pinned", True, True)
        assert pinned["inspect_only"] is False
        prow = pinned["advisories"][0]
        assert prow["automated_consequences_permitted"] is True
        assert prow["trust_basis"] == "pinned_key_policy" and prow["record_authentic"] is True
        impact = prow["impact"]
        assert impact["verdict"] == "exposed"       # a verdict about exposure, not safe/unsafe
        assert impact["functions_newly_in_question"] == 2
        assert impact["machines_affected"] == [KEY] and impact["unknown_machines"] == []
        assert impact["clear_is_complete"] is False
        assert impact["checks_skipped"]
        # an advisory does not make a currently-verified function newly unverified
        assert impact["exposures"][0]["functions"][0]["coverage_before"] == "current"
        assert "correct, complete or timely" in pinned["trust_statement"]

        # -- 3. software alone does not open a case: it needs a named person -----------------
        for who in ("", "automation"):
            refused = w.assess(adv, actor=who)
            assert refused.status_code == 409, (who, refused.status_code)
            assert "needs a named person" in refused.json()["detail"], who
        assert w.ok("GET", "/v1/change/cases")["cases"] == []

        ledger = live_api.tenant_ledger(w.account_id)
        opened = w.assess(adv).json()
        assert opened["opened"] is True and opened["verdict"] == "exposed"
        case = opened["case"]
        cid = case["case_id"]
        assert case["status"] == "open" and case["trigger_type"] == "supplier_advisory"
        assert case["trigger_id"] == ADVISORY_ID and case["machines"] == [KEY]
        assert case["change_severity"] == "safety_relevant"
        assert case["affected_functions"] == ["SF-01", "SF-02"]
        # the changed item carries the reason it is in the case (hash, not a label)
        item = case["changed_items"][0]
        assert item["item_id"] == f"{KEY}/{ITEM}" and item["confidence"] == "confirmed"
        assert "byte-identical" in item["detail"]
        # the evidence states are kept apart: it WAS current; the case still owes entries
        assert set(case["evidence_before"].values()) == {"current"}
        assert sorted(case["required_reverifications"]) == sorted(ENTRIES)
        assert case["decision"] == "" and case["closed_at"] == ""
        # advisory trust is recorded on the case, and it is the honest answer for this route
        assert case["provenance"]["advisory_accepted_by"] == PERSON
        assert opened["advisory_trust"]["inspect_only"] is True
        assert any("nobody has authenticated" in c for c in case["checks_skipped"])
        assert case["linked_evidence"][0]["relation"] == "concerns"
        assert case["linked_evidence"][0]["content_hash"] == impact["advisory_hash"]

        # -- 4. the same advisory delivered again: the same case, no duplicate, no new write -
        entries_before = len(list(ledger.entries()))
        again = w.assess(adv).json()
        assert again["case"]["case_id"] == cid
        queue = w.ok("GET", "/v1/change/cases")
        assert [c["case_id"] for c in queue["cases"]] == [cid]
        assert queue["summary"]["open"] == 1
        assert len(list(ledger.entries())) == entries_before
        assert len(list(ledger.entries(subject=cid))) == 1       # only the opening

        # -- 5. software cannot close it: every route to a human decision says so ------------
        target = f"/v1/change/cases/{cid}"
        decision = {"disposition": "closed", "reason": "looks fine", "actor": PERSON}
        by_key = w.call("POST", f"{target}/decision", None, decision)
        assert by_key.status_code == 403 and by_key.json()["detail"]["error"] == "operator_required"
        contributor = w.ok("POST", "/v1/operators", w.decider,
                           {"name": "c.contributor", "role": "contributor"})
        by_contrib = w.call("POST", f"{target}/decision", {"X-API-Key": contributor["api_key"]},
                            {**decision, "actor": "c.contributor"})
        assert by_contrib.status_code == 403
        assert by_contrib.json()["detail"]["error"] == "decider_role_required"
        impostor = w.call("POST", f"{target}/decision", w.decider, {**decision, "actor": "automation"})
        assert impostor.status_code == 403 and impostor.json()["detail"]["error"] == "actor_mismatch"
        # even a decider cannot close it while it is open: a state, not a permission
        early = w.call("POST", f"{target}/decision", w.decider, decision)
        assert early.status_code == 409 and "not ready_to_close" in early.json()["detail"]
        assert w.case(cid)["status"] == "open"

        # -- 6. the review: claim, advance, advance -> awaiting_reverification ---------------
        assert w.ok("POST", f"{target}/claim", None, {"owner": PERSON, "actor": PERSON})[
            "status"] == "in_review"
        assert w.ok("POST", f"{target}/advance", None, {"actor": PERSON})[
            "status"] == "awaiting_action"
        waiting = w.ok("POST", f"{target}/advance", None, {"actor": PERSON})
        assert waiting["status"] == "awaiting_reverification"
        assert sorted(waiting["required_reverifications"]) == sorted(ENTRIES)
        assert w.call("POST", f"{target}/advance", None, {"actor": PERSON}).status_code == 409

        # -- 7. the intervention: the supplier's remedy applied on the machine ---------------
        time.sleep(1.1)                 # the change must postdate the baseline verification
        params = next(i for i in manifest["items"] if i["item_id"] == ITEM)
        intervention = {
            "intervention_id": "INT-77", "machine_key": KEY, "item_id": ITEM, "kind": "update",
            "occurred_at": now_z(), "reason": f"Apply the remedy of {ADVISORY_ID}",
            "performed_by": {"identifier": "m.keller", "role": "integrator", "kind": "person"},
            "from_hash": params["content_hash"], "to_hash": FIXED_HASH,
            "affects_functions": ["SF-01", "SF-02"],
            "authorization": {"authorised_by": {"identifier": PERSON, "role": "safety lead",
                                                "kind": "person"},
                              "reference": "CR-77", "basis": ADVISORY_ID}}
        # refusals first: nothing is written for a machine or function the ledger does not hold
        ghost = w.call("POST", "/v1/machinery/intervention", None, {"intervention": {
            **intervention, "intervention_id": "INT-GHOST", "machine_key": "Grimaldi/AR-7#9999"}})
        assert ghost.status_code == 409 and ghost.json()["detail"]["error"] == "unknown_machine"
        nofn = w.call("POST", "/v1/machinery/intervention", None, {"intervention": {
            **intervention, "intervention_id": "INT-NOFN", "affects_functions": ["SF-99"]}})
        assert nofn.status_code == 422 and nofn.json()["detail"]["error"] == "unknown_function"
        done = w.ok("POST", "/v1/machinery/intervention", None,
                    {"intervention": intervention, "actor": "m.keller"})
        assert done["intervention_id"] == "INT-77" and done["authorised"] is True
        assert done["revalidated"] is False, "nothing was re-run, and the record must say so"
        assert any("nothing was re-run" in f for f in done["findings"])
        assert done["effective_affects_functions"] == ["SF-01", "SF-02"]

        # a recorded change with no fresh evidence turns 'current' into 'stale', by name
        stale = w.coverage()
        assert stale["verdict"] == "gaps"
        assert {f["coverage"] for f in stale["functions"]} == {"stale"}
        assert {f["invalidated_by"] for f in stale["functions"]} == {"INT-77"}
        assert all(f["last_verified_hash"] == baseline["content_hash"] for f in stale["functions"])
        assert "INT-77" in stale["unrevalidated_interventions"]
        # and a passport taken NOW says gaps, not covered
        gap_passport = w.ok("POST", "/v1/machinery/passport", None,
                            {"manifest": manifest, "actor": PERSON})
        assert gap_passport["verdict"] == "gaps" and gap_passport["sealed"] is True
        assert {f["coverage"] for f in gap_passport["evidence"]["body"]["functions"]} == {"stale"}

        # -- 8. re-verification: the case does not clear on the old evidence -----------------
        # (a) evidence that existed before the case cannot be evidence about it
        old = w.call("POST", f"{target}/reverification", None, {
            "manifest": manifest, "verification_content_hash": baseline["content_hash"],
            "actor": PERSON})
        assert old.status_code == 409
        assert "sealed before this case was opened" in old.json()["detail"]
        assert w.case(cid)["status"] == "awaiting_reverification"
        # (b) a fresh run, attested by the trusted recorder, after the change ...
        time.sleep(1.1)
        fresh = w.verify("RUN-AFTER-REMEDY")
        assert fresh["tier"] == "validated" and fresh["content_hash"] != baseline["content_hash"]
        # ... against a manifest older than the case is still refused, and says why
        predates = w.call("POST", f"{target}/reverification", None, {
            "manifest": manifest, "verification_content_hash": fresh["content_hash"],
            "actor": PERSON})
        assert predates.status_code == 409
        assert "predates this case's trigger" in predates.json()["detail"]
        # (c) seal the machine as it is now (remedy applied), then re-verify against it
        after = copy.deepcopy(manifest)
        for it in after["items"]:
            if it["item_id"] == ITEM:
                it["content_hash"], it["version"] = FIXED_HASH, "3.9.0"
        after["manifest_id"], after["taken_at"] = "PLAN-AR7-0501-after-remedy", now_z()
        resealed = w.seal_manifest(after)
        assert resealed["configuration_hash"] != sealed["configuration_hash"]
        fresh = w.verify("RUN-AFTER-REMEDY")
        assert fresh["tier"] == "validated" and fresh["content_hash"] != baseline["content_hash"]
        ready = w.ok("POST", f"{target}/reverification", None, {
            "manifest": after, "verification_content_hash": fresh["content_hash"],
            "actor": PERSON})
        assert ready["status"] == "ready_to_close" and "blocked_reason" not in ready
        assert set(ready["evidence_current"].values()) == {"current"}
        assert ready["required_reverifications"] == []
        assert ready["decision"] == "" and ready["closed_at"] == "", \
            "re-verification must leave the case waiting for a person"
        assert ready["resolved_decisions"] == []               # nothing waived

        # -- 9. a named human closes; the case says who ---------------------------------------
        closed = w.ok("POST", f"{target}/decision", w.decider, {
            "disposition": "closed", "reason": "Remedy applied and re-verified.",
            "actor": PERSON})
        assert closed["status"] == "closed" and closed["decision"] == "closed"
        assert closed["decision_by"] == PERSON and closed["closed_at"]
        assert w.call("POST", f"{target}/decision", w.decider, {
            "disposition": "closed", "reason": "again", "actor": PERSON}).status_code == 409
        export = w.ok("GET", f"{target}/export")
        final = export["entries"][-1]["evidence"]["body"]["case"]
        assert final["status"] == "closed" and final["decision_by"] == PERSON
        assert set(final["evidence_current"].values()) == {"current"}
        assert [d for d in final["resolved_decisions"] if d.get("kind") == "waiver"] == []
        assert w.ok("GET", "/v1/change/cases", status="closed")["cases"][0]["case_id"] == cid

        # -- 10. tenant B sees none of it: not the case, not the pin, not the ledger ----------
        b_acct, b_key, b_decider = second_tenant(live_api)
        operator_db = live_api.root / "operator.db"
        operator_ledger = EvidenceLedger(operator_db)
        assert w.ok("GET", "/v1/change/cases", b_key)["cases"] == []
        for path in (target, f"{target}/export", f"{target}/replay"):
            missing = w.call("GET", path, b_key)
            assert missing.status_code == 404, path
            assert missing.json()["detail"] == {"error": "case_not_found", "case_id": cid}
        for verb, body in (("claim", {"owner": "b", "actor": "b.decider"}),
                           ("decision", {**decision, "actor": "b.decider"})):
            hdr = b_decider if verb == "decision" else b_key
            assert w.call("POST", f"{target}/{verb}", hdr, body).status_code == 404
        assert w.ok("GET", "/v1/supplier/trust", b_key)["pins"] == []
        b_view = w.ok("POST", "/v1/fleet/advisory/signed", b_key, {"feed": feed_text})
        assert b_view["trust"]["key_trust_state"] == "unknown_key" and b_view["inspect_only"]
        b_cov = w.ok("POST", "/v1/machinery/coverage", b_key, {"manifest": manifest})
        assert {f["coverage"] for f in b_cov["functions"]} == {"never_verified"}
        assert list(live_api.tenant_ledger(b_acct).entries()) == []
        assert list(live_api.tenant_ledger(w.account_id).entries()) != []
        assert list(operator_ledger.entries()) == [], "the shared ledger is operator-only"

        # -- 11. the passport: sealed, covered, and checkable by anyone, with no key ----------
        passport = w.ok("POST", "/v1/machinery/passport", None,
                        {"manifest": after, "actor": PERSON})
        assert passport["sealed"] is True and passport["verdict"] == "covered"
        body = passport["evidence"]["body"]
        assert body["coverage_verdict"] == "covered" and body["evidence_tier_floor"] == "validated"
        assert {f["coverage"] for f in body["functions"]} == {"current"}
        assert {f["evidence_tier"] for f in body["functions"]} == {"validated"}
        assert {f["last_verified_hash"] for f in body["functions"]} == {fresh["content_hash"]}
        assert fresh["content_hash"] in body["verification_hashes"]
        assert "INT-77" in body["intervention_ids"] and body["ledger_chain_verified"] is True
        assert body["configuration_hash"] == resealed["configuration_hash"]
        checked = http.post("/v1/machinery/passport/check", json={"passport": passport})
        assert checked.status_code == 200, checked.text       # anonymous: no X-API-Key sent
        c = checked.json()
        assert c["ok"] is True
        assert c["problems"] and all(p.startswith("NOT CHECKED") for p in c["problems"]), c["problems"]
        assert any("no ledger was supplied" in p for p in c["problems"])
        assert c["checked"] == {"seal": True, "internal_consistency": True,
                                "against_ledger": False}, "it must say what it did NOT check"
        assert c["recorded_verdict"] == "covered" and c["functions_not_current"] == []
        assert c["machine"]["serial"] == "0501"

        # -- 12. the same passport, edited, fails ---------------------------------------------
        for mutate in (
                lambda p: p["evidence"]["body"].update(verdict="covered", ledger_chain_verified=False),
                lambda p: p["evidence"]["body"]["functions"][0].update(coverage="never_verified"),
                lambda p: p["evidence"]["body"].update(configuration_hash="0" * 64),
                lambda p: p["evidence"]["body"].update(verification_hashes=["0" * 64])):
            forged = copy.deepcopy(passport)
            mutate(forged)
            bad = http.post("/v1/machinery/passport/check", json={"passport": forged}).json()
            assert bad["ok"] is False, bad
            assert any(not p.startswith("NOT CHECKED") for p in bad["problems"]), bad

        # the earlier gap passport still verifies, and still says gaps: history is not rewritten
        old_check = http.post("/v1/machinery/passport/check", json={"passport": gap_passport}).json()
        assert old_check["ok"] is True and old_check["recorded_verdict"] == "gaps"
        assert {f["coverage"] for f in old_check["functions_not_current"]} == {"stale"}


# =====================================================================
# negative variants, each from a fresh account
# =====================================================================
class TestUnsignedAndUntrusted:
    def test_a_tampered_feed_is_not_trusted_even_under_a_pinned_key(self, world, tmp_path):
        w = world
        w.seal_manifest()
        adv = advisory_for(w.manifest)
        text = signed_feed(tmp_path, adv, w.supplier_key)
        w.pin_supplier()
        assert trust_view(w.signed(text)["trust"])[0] == "trusted"
        record = json.loads(text.splitlines()[0])
        record["advisory"]["remedy"] = "Flash http://evil.example/fw.bin."
        out = w.signed(json.dumps(record))
        state = trust_view(out["trust"])
        assert state[0] == "untrusted_signature_invalid" and state[1] == "some_invalid"
        assert state[2] == "pinned", "the key is still pinned; it is the bytes that failed"
        assert out["inspect_only"] is True and out["trust"]["policy_satisfied"] is False
        row = out["advisories"][0]
        assert row["automated_consequences_permitted"] is False and row["trust_basis"] == "none"
        assert row["record_authentic"] is False
        assert "does not verify" in out["trust"]["problems"][0]

    def test_a_feed_signed_by_a_key_nobody_pinned_is_not_trusted(self, world, tmp_path):
        w = world
        w.seal_manifest()
        w.pin_supplier()
        stranger = SigningKey.generate()
        text = signed_feed(tmp_path, advisory_for(w.manifest), stranger)
        out = w.signed(text)
        assert out["trust"]["trust_state"] == "untrusted_unknown_key"
        assert out["trust"]["key_trust_state"] == "unknown_key"
        assert out["inspect_only"] is True
        assert out["advisories"][0]["automated_consequences_permitted"] is False

    def test_a_feed_that_does_not_parse_is_a_state_not_a_crash(self, world):
        out = world.signed("this is not a feed")
        assert out["advisories"] == [] and out["inspect_only"] is True
        assert out["trust"]["trust_state"] == "untrusted_unreadable"
        assert out["trust"]["structurally_readable"] is False and out["trust"]["problems"]

    def test_an_unsigned_advisory_opens_a_case_only_for_a_named_person_and_says_so(self, world):
        w = world
        w.seal_manifest()
        adv = advisory_for(w.manifest, "ROBO-UNSIGNED-1")
        for actor in ("", "automation", "System"):
            refused = w.assess(adv, actor=actor)
            assert refused.status_code == 409, (actor, refused.text[:200])
        assert w.ok("GET", "/v1/change/cases")["cases"] == []
        # `accept_unsigned` is for unsigned IMPORTS, and an override is a decider's act
        override = w.assess(adv, accept_unsigned=True, reason="read against the vendor page")
        assert override.status_code == 403
        assert override.json()["detail"]["error"] == "operator_required"
        # a named person opens it; the case says nobody authenticated the advisory
        out = w.assess(adv).json()
        assert out["opened"] is True
        assert out["advisory_trust"]["trust_state"] == "unauthenticated_input"
        assert out["advisory_trust"]["signature_state"] == "none"
        assert out["advisory_trust"]["automated_consequences_permitted"] is False
        assert out["case"]["provenance"]["advisory_trust"] == "unauthenticated_input"
        assert any("no signature was checked" in c for c in out["case"]["checks_skipped"])

    @pytest.mark.xfail(strict=True, reason=(
        "GAP, found by this test: /v1/fleet/advisory/signed evaluates a signed+pinned feed and "
        "says automated_consequences_permitted=true (and always returns case_opened=''), but "
        "the only route that opens a case, POST /v1/change/assess/advisory, takes a bare "
        "advisory body and cannot receive the signed record. The case it opens therefore says "
        "'nobody has authenticated ... no signature was checked' (trust_state "
        "unauthenticated_input) about an advisory this account already verified under a pinned "
        "key, and still demands a named person. The honest direction (never over-trusting) is "
        "preserved, but the signed leg of the path does not reach the case."))
    def test_a_pinned_signed_advisory_reaches_the_case_with_its_trust(self, world, tmp_path):
        w = world
        w.seal_manifest()
        adv = advisory_for(w.manifest, "ROBO-SIGNED-1")
        text = signed_feed(tmp_path, adv, w.supplier_key)
        w.pin_supplier()
        assert w.signed(text)["advisories"][0]["automated_consequences_permitted"] is True
        reply = w.assess(adv, actor="")      # no named person: the feed itself is trusted
        assert reply.status_code == 200, reply.text[:200]
        out = reply.json()
        assert out["opened"] is True
        assert out["advisory_trust"]["trust_basis"] == "pinned_key_policy"


class TestNotInTheFleet:
    @staticmethod
    def _foreign(w: World, **over: Any) -> ComponentAdvisory:
        body: dict[str, Any] = {
            "affected": (AffectedArtefact(supplier="NoSuchCo", name="Widget controller",
                                          versions=("1.0",)),)}
        body.update(over)
        return advisory_for(w.manifest, "NOFLEET-1", **body)

    def test_an_advisory_for_another_product_is_no_match_with_a_reason_never_safe(self, world):
        w = world
        w.seal_manifest()
        adv = self._foreign(w)
        impact = w.ok("POST", "/v1/fleet/advisory", body={"advisory": adv.to_dict()})
        assert impact["verdict"] == "clear" and impact["machines_affected"] == []
        row = impact["machine_classification"][0]
        assert row["machine"] == KEY
        assert row["classification"] == "no_match_found"        # not 'not_affected', not 'safe'
        assert "rests on the manifest being complete" in row["uncertainty"]
        # the report names what it could not see, and about the inspected advisory itself
        assert any("absence here is not evidence of safety" in c for c in impact["checks_skipped"])
        assert any("rests on a version label" in c or "A label is not an artefact" in c
                   for c in impact["checks_skipped"])
        assert impact["provenance"]["trust_state"] == "unauthenticated_input"
        # nothing is opened, and nothing is written, by an advisory that matches nothing
        out = w.assess(adv).json()
        assert out["opened"] is False and out["case"] is None and out["verdict"] == "clear"
        assert w.ok("GET", "/v1/change/cases")["cases"] == []

    def test_same_product_other_version_is_no_match_and_still_not_called_safe(self, world):
        w = world
        w.seal_manifest()
        adv = advisory_for(w.manifest, "NOFLEET-2", affected=(AffectedArtefact(
            supplier="RoboCo", name="Robot safety parameter set", versions=("9.9.9",)),))
        out = w.assess(adv).json()
        assert out["opened"] is False and out["verdict"] == "clear"
        impact = w.ok("POST", "/v1/fleet/advisory", body={"advisory": adv.to_dict()})
        assert impact["machines_affected"] == []
        assert impact["machine_classification"][0]["classification"] == "no_match_found"
        assert any("absence here is not evidence of safety" in c for c in impact["checks_skipped"])

    def test_a_machine_whose_version_is_not_recorded_is_possible_not_clear(self, world):
        w = world
        w.seal_manifest()
        adv = advisory_for(w.manifest, "NOFLEET-3", affected=(AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware", versions=("3.8.2",)),))
        out = w.assess(adv).json()
        assert out["opened"] is True and out["verdict"] == "needs_review"
        cls = w.ok("POST", "/v1/fleet/advisory", body={"advisory": adv.to_dict()})[
            "machine_classification"][0]
        assert cls["classification"] == "possible_match_name_only" and cls["item_ids"] == ["ITM-FW"]
        assert "not recorded" in cls["uncertainty"]
        assert out["case"]["evidence_current"]  # states are listed, none invented

    def test_an_advisory_with_no_machine_enrolled_says_it_assessed_nothing(self, world):
        w = world                               # nothing sealed: the fleet is empty
        adv = advisory_for(w.manifest, "NOFLEET-4")
        impact = w.ok("POST", "/v1/fleet/advisory", body={"advisory": adv.to_dict()})
        assert impact["machines_affected"] == [] and impact["machines_in_fleet"] == 0
        assert any("about an empty fleet, not about any machine" in c
                   for c in impact["checks_skipped"])
        assert any("absence here is not evidence of safety" in c for c in impact["checks_skipped"])
        assert w.assess(adv).json()["opened"] is False

    def test_an_empty_fleet_is_incomplete_not_clear_and_complete(self, world):
        w = world
        adv = advisory_for(w.manifest, "NOFLEET-5")
        impact = w.ok("POST", "/v1/fleet/advisory", body={"advisory": adv.to_dict()})
        assert impact["clear_is_complete"] is False and impact["machines_in_fleet"] == 0
        reply = w.assess(adv).json()
        # `incomplete` means "the advisory's own import was partial"; whether a CLEAR verdict can
        # be relied on is `clear_is_complete`, and an empty fleet never earns it.
        assert reply["clear_is_complete"] is False and reply["opened"] is False


class TestPassportNegatives:
    def test_a_passport_for_a_machine_nobody_verified_says_gaps_and_cannot_be_edited_to_covered(
            self, world):
        w = world
        w.seal_manifest()
        passport = w.ok("POST", "/v1/machinery/passport", None,
                        {"manifest": w.manifest, "actor": PERSON})
        assert passport["verdict"] == "gaps" and passport["sealed"] is True
        body = passport["evidence"]["body"]
        assert {f["coverage"] for f in body["functions"]} == {"never_verified"}
        assert body["evidence_tier_floor"] == "" and body["verification_hashes"] == []
        honest = w.http.post("/v1/machinery/passport/check", json={"passport": passport}).json()
        assert honest["ok"] is True and honest["recorded_verdict"] == "gaps"
        assert {f["coverage"] for f in honest["functions_not_current"]} == {"never_verified"}
        assert honest["checked"]["against_ledger"] is False

        forged = copy.deepcopy(passport)
        forged["evidence"]["body"]["verdict"] = "covered"
        forged["evidence"]["body"]["coverage_verdict"] = "covered"
        for fn in forged["evidence"]["body"]["functions"]:
            fn["coverage"], fn["evidence_tier"] = "current", "validated"
        bad = w.http.post("/v1/machinery/passport/check", json={"passport": forged}).json()
        assert bad["ok"] is False and bad["problems"]
        assert bad["recorded_verdict"] == "covered"      # echoes what it was handed, ok is False

    def test_a_passport_that_is_not_a_passport_is_refused_not_passed(self, world):
        r = world.http.post("/v1/machinery/passport/check", json={"passport": {}})
        assert r.status_code == 200 and r.json()["ok"] is False and r.json()["problems"]

    def test_passport_and_check_gates(self, world, live_api):
        w = world
        body = {"manifest": w.manifest, "actor": PERSON}
        assert w.call("POST", "/v1/machinery/passport", {}, body).status_code == 401
        _, r_key = live_api.account("rr@golden.example", "register")
        assert w.call("POST", "/v1/machinery/passport", r_key, body).status_code == 402
        # the check is free for everyone, with or without a key
        probe = {"passport": {}}
        assert w.call("POST", "/v1/machinery/passport/check", {}, probe).status_code == 200
        assert w.call("POST", "/v1/machinery/passport/check", r_key, probe).status_code == 200
