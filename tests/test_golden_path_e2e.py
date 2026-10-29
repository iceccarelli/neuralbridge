"""The golden path: one reproducible run of what a manufacturer buys, end to end.

Everything is real except Stripe's network. A paid account is provisioned by the real
webhook route (a body signed with a throwaway secret) and the real
``GET /v1/checkout/complete``; the plant is synthetic vendor exports driven through the
real ``collect probe`` / ``collect run`` / ``kit run`` / ``watch run`` / ``watch push``
subprocesses; the hosted API is a uvicorn server on a real socket with per-account
ledgers; the operator signs the account's ledger head with the real ``assurance attest
sign``; the evidence is then verified in a fresh interpreter with the signer's public key
AND anonymously over ``POST /v1/evidence/verify``.

Three machines changed firmware and each drift case ends differently, and the exports
must say so:

* ``validated``: a recorder the server trusts attested the verification; the entries read
  ``current``; nothing in the case is a waiver.
* ``waived``: nobody verified; a named decider closed the entries without evidence; they
  read ``waived``, never ``current``, and no verification is cited.
* ``refused``: a verification with no recorder attestation is ``community`` and is
  recorded but clears nothing; the case cannot be closed and the export says why.

What this does not prove: that any recorder, machine or export is physically true, that
the hosted ledger's operator is trustworthy (the service holds the ledger and the
signing key; the anchor protects only a customer who keeps their own copy), that Stripe
sends what the test sends, or anything about a deployed service. The kit run and Watch
read synthetic files.

Each step asserts on parsed JSON, never on a substring of rendered text.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from assurance.change.store import OPENED_KIND
from assurance.evidence.ledger import EvidenceLedger
from assurance.evidence.verify_export import _SAME_PARTY

from . import interfaces_fixtures as fx
from .interfaces_scenario import PERSON, Plant, run_cli, run_started
from .interfaces_support import envelope, envelope_dict, trace
from .support import write_export
from .support_recorder import RECORDER
from .test_assurance_export_completeness import _cut_tail

live_api = fx.live_api

WEBHOOK_SECRET = "whsec_golden_path_throwaway"
VALIDATED, WAIVED, REFUSED = "0501", "0412", "0777"      # the three machines' serials
SERIALS = (WAIVED, VALIDATED, REFUSED)


def key_of(serial: str) -> str:
    return f"Grimaldi/AR-7#{serial}"


# ---------------------------------------------------------------------------
# the hosted service, as a customer's client sees it
# ---------------------------------------------------------------------------

class Hosted:
    def __init__(self, live: fx.LiveApi) -> None:
        self.live = live
        self.http = httpx.Client(base_url=live.url, timeout=60.0)

    def call(self, method: str, path: str, key: str | None = None, body: Any = None,
             **params: Any) -> httpx.Response:
        headers = {"X-API-Key": key} if key else {}
        return self.http.request(method, path, json=body, headers=headers, params=params)

    def ok(self, method: str, path: str, key: str | None = None, body: Any = None,
           **params: Any) -> dict[str, Any]:
        r = self.call(method, path, key, body, **params)
        assert r.status_code in (200, 201), f"{method} {path}: {r.status_code} {r.text[:400]}"
        return r.json()

    def close(self) -> None:
        self.http.close()

    def webhook(self, event: dict[str, Any], *, signed_with: str = WEBHOOK_SECRET,
                age: int = 0) -> httpx.Response:
        """A Stripe event signed the way Stripe signs it, with a throwaway secret.

        ``signed_with`` and ``age`` (seconds the timestamp is in the past) exist to send the
        forgeries: a signature made with another secret, and a captured request replayed late.
        """
        raw = json.dumps(event).encode()
        stamp = str(int(time.time()) - age)
        sig = hmac.new(signed_with.encode(), f"{stamp}.".encode() + raw,
                       hashlib.sha256).hexdigest()
        return self.http.post("/v1/billing/webhook", content=raw, headers={
            "stripe-signature": f"t={stamp},v1={sig}", "content-type": "application/json"})

    def checkout(self, tier: str, name: str) -> tuple[str, str, str]:
        """Pay for ``tier`` through the real handover: webhook, then ``/checkout/complete``.

        Returns (account id, API key, Stripe customer id). The key exists only on the
        far side of the webhook, is handed over once, and is not minted by a redirect.
        """
        session, customer = f"cs_golden_{name}", f"cus_golden_{name}"
        before = self.call("GET", "/v1/checkout/complete", session_id=session)
        assert before.status_code == 202 and before.json()["detail"]["status"] == "pending"
        event = {
            "id": f"evt_golden_{name}", "created": int(time.time()),
            "type": "checkout.session.completed",
            "data": {"object": {
                "id": session, "payment_status": "paid", "customer": customer,
                "subscription": f"sub_golden_{name}",
                "customer_details": {"email": f"{name}@golden.example"},
                "metadata": {"tier": tier, "company": f"Golden {name}"}}}}
        accounts = self.live.accounts
        known = len(accounts.list_accounts())
        # a forged or replayed-late webhook grants nothing and mints no key
        for forged in (self.webhook(event, signed_with="whsec_not_the_secret"),
                       self.webhook(event, age=3600)):
            assert forged.status_code == 400, forged.text
            assert forged.json()["detail"]["error"] == "signature_rejected"
        assert self.call("GET", "/v1/checkout/complete", session_id=session).status_code == 202
        assert len(accounts.list_accounts()) == known
        granted = self.webhook(event)
        assert granted.status_code == 200 and granted.json()["tier"] == tier, granted.text
        assert len(accounts.list_accounts()) == known + 1
        # the same signed event delivered again: acknowledged as a duplicate, nothing new
        replay = self.webhook(event)
        assert replay.status_code == 200 and replay.json()["duplicate"] is True, replay.text
        assert len(accounts.list_accounts()) == known + 1
        assert len(accounts.keys_for(granted.json()["account_id"])) == 1
        handed = self.call("GET", "/v1/checkout/complete", session_id=session)
        assert handed.status_code == 200, handed.text
        body = handed.json()
        assert body["tier"] == tier and body["account_id"] == granted.json()["account_id"]
        again = self.call("GET", "/v1/checkout/complete", session_id=session)
        assert again.status_code == 202, "the key must be handed over exactly once"
        me = self.ok("GET", "/v1/me", body["api_key"])
        assert me["tier"] == tier
        return body["account_id"], body["api_key"], customer


# ---------------------------------------------------------------------------
# reading an export
# ---------------------------------------------------------------------------

def final_case(bundle: dict[str, Any]) -> dict[str, Any]:
    return bundle["entries"][-1]["evidence"]["body"]["case"]


def supports(case: dict[str, Any]) -> list[str]:
    return [r["content_hash"] for r in case["linked_evidence"] if r["relation"] == "supports"]


def outcome_of(bundle: dict[str, Any]) -> str:
    """What an export says happened to a drift case, from the export alone."""
    case = final_case(bundle)
    states = set(case["evidence_current"].values())
    waivers = [d for d in case["resolved_decisions"] if d.get("kind") == "waiver"]
    if case["status"] == "closed" and states == {"current"} and supports(case) \
            and not waivers:
        return "validated"
    if case["status"] == "closed" and states == {"waived"} and waivers \
            and not supports(case):
        return "waived"
    if case["status"] == "closed" and states == {"waived"} and waivers and supports(case):
        return "waived_citing_unattested_evidence"
    if case["status"] == "awaiting_reverification" and states \
            and all(s == "below_validated:community" for s in states):
        return "refused_below_validated"
    return f"unclassified {case['status']} {sorted(states)}"


# ---------------------------------------------------------------------------
# offline and anonymous verification of an export
# ---------------------------------------------------------------------------

def verify_offline(bundle: dict[str, Any], tmp: Path, name: str,
                   public_key: Path) -> tuple[int, dict[str, Any]]:
    """``assurance evidence verify --public-key ... --json`` in a fresh interpreter."""
    path = tmp / f"{name}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    r = run_cli("evidence", "verify", path, "--public-key", public_key, "--json")
    assert r.stdout.strip(), r.stderr
    return r.returncode, json.loads(r.stdout)


def verify_anonymously(live: fx.LiveApi, bundle: dict[str, Any],
                       public_key_pem: str) -> dict[str, Any]:
    r = httpx.post(f"{live.url}/v1/evidence/verify", content=json.dumps(bundle), headers={
        "Content-Type": "application/json",
        "X-Issuer-Public-Key": " ".join(public_key_pem.split())}, timeout=60.0)
    assert r.status_code == 200, r.text
    return r.json()


def attest_sign(tmp: Path, account_id: str, signing_key: Path) -> dict[str, Any]:
    """What the operator does: sign the head of the account's hosted ledger, reading it."""
    ledger = tmp / "tenants" / f"{account_id}.db"
    log = tmp / "attestations" / f"{account_id}.jsonl"
    r = run_cli("attest", "sign", "--ledger", ledger, "--key", signing_key,
                "--log", log, "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout)


def verify_run(hosted: Hosted, key: str, serial: str, *, attested: bool) -> dict[str, Any]:
    """File a verification of ``serial`` through ``POST /v1/machine/verify``.

    ``attested`` adds a real signature, by the shared test recorder, over the actual
    trace bytes. Whether the SERVER accepts it is the server's own trust list's call.
    """
    when = run_started()
    run = trace(when, trace_id=f"RUN-{serial}-{when:%Y%m%d%H%M%S}")
    body: dict[str, Any] = {
        "envelope": envelope_dict(), "trace": run.hashable_payload(),
        "actor": PERSON, "subject": key_of(serial)}
    if attested:
        body["recorder_attestations"] = RECORDER.attestation_dicts(
            envelope(), run, machine_serial=serial)
    return hosted.ok("POST", "/v1/machine/verify", key, body)


def reverify(hosted: Hosted, key: str, plant: Plant, case_id: str, serial: str,
             content_hash: str) -> dict[str, Any]:
    return hosted.ok("POST", f"/v1/change/cases/{case_id}/reverification", key, {
        "manifest": plant.manifest_dict(key_of(serial)),
        "verification_content_hash": content_hash, "actor": PERSON})


def drift_the_plant(live: fx.LiveApi, key: str, plant: Plant, serials: tuple[str, ...]) -> None:
    """Enrol with the kit, look, push a baseline, change firmware on ``serials``, look, push."""
    plant.kit_run("cli")
    plant.watch_run("cli", expect=1)             # first look: never verified
    plant.push(live.url, key)                    # the baselines
    time.sleep(1.1)                              # one observation per machine per second
    for serial in serials:
        plant.change_firmware(serial)
    plant.watch_run("cli", expect=1)             # drift
    plant.push(live.url, key)


def advance_to_reverification(hosted: Hosted, key: str, case_id: str) -> dict[str, Any]:
    base = f"/v1/change/cases/{case_id}"
    hosted.ok("POST", f"{base}/claim", key, {"owner": PERSON, "actor": PERSON})
    hosted.ok("POST", f"{base}/advance", key, {"actor": PERSON})
    moved = hosted.ok("POST", f"{base}/advance", key, {"actor": PERSON})
    assert moved["status"] == "awaiting_reverification", moved["status"]
    assert moved["required_reverifications"]
    return moved


def waive_and_close(hosted: Hosted, key: str, decider: str, case_id: str) -> dict[str, Any]:
    """A named decider closes every outstanding entry without evidence, then the case."""
    base = f"/v1/change/cases/{case_id}"
    owed = hosted.ok("GET", base, key)["required_reverifications"]
    assert owed
    for entry in owed:
        waived = hosted.ok("POST", f"{base}/waive-reverification", decider, {
            "entry": entry, "reason": "Machine is out of service.", "actor": PERSON})
        assert waived["evidence_current"][entry] == "waived"
    assert waived["required_reverifications"] == []
    ready = hosted.ok("POST", f"{base}/advance", key, {"actor": PERSON})
    assert ready["status"] == "ready_to_close"
    return hosted.ok("POST", f"{base}/decision", decider, {
        "disposition": "closed", "reason": "Closed on the waivers.", "actor": PERSON})


@pytest.fixture
def env(live_api, tmp_path, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    for var in ("STRIPE_SECRET_KEY", "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL"):
        monkeypatch.delenv(var, raising=False)
    hosted = Hosted(live_api)
    try:
        yield live_api, hosted, tmp_path
    finally:
        hosted.close()


class TestTheGoldenPath:
    def test_provision_collect_drift_close_three_ways_sign_and_verify(self, env, monkeypatch):
        live, hosted, tmp = env

        # -- provision: A (Cell), B (Cell), R (Register) through the real handover -------
        a_id, a_key, a_customer = hosted.checkout("cell", "alpha")
        b_id, b_key, _ = hosted.checkout("cell", "bravo")
        r_id, r_key, _ = hosted.checkout("register", "romeo")
        assert len({a_id, b_id, r_id}) == 3
        # A's first operator is a decider, minted by the real bootstrap route. Only an
        # operator key can make a human decision; the account key cannot.
        op = hosted.ok("POST", "/v1/operators", a_key, {"name": PERSON, "role": "decider"})
        assert op["role"] == "decider" and op["name"] == PERSON
        decider = op["api_key"]

        # -- the plant: probe the plan, collect a baseline, enrol, look, change ----------
        plant = Plant(tmp / "plant", serials=SERIALS)
        write_export(plant.root / "exports" / "0501b", stamp="2026-09-15T07:30:00Z",
                     operator="other.tech", seq="4182")
        probe = run_cli("collect", "probe", "plans/cell.json", "--first", "exports/0501",
                        "--second", "exports/0501b", "--json", cwd=plant.root)
        assert probe.returncode == 0, probe.stdout + probe.stderr
        probed = json.loads(probe.stdout)
        assert probed["verdict"] == "stable" and probed["volatile_items"] == []

        baseline_path = plant.root / "baseline-0501.json"
        collected = run_cli("collect", "run", "plans/cell.json", "--root", "exports/0501",
                            "--serial", "0501", "--actor", "m.keller", "--site", "Plant 2",
                            "--country", "DE", "--out", baseline_path, "--json",
                            "--read-from-machine",     # the harness plays an on-machine collector (B6)
                            cwd=plant.root)
        assert collected.returncode == 0, collected.stdout + collected.stderr
        baseline = json.loads(collected.stdout)
        assert baseline["complete"] is True
        sealed_base = hosted.ok("POST", "/v1/machinery/manifest", a_key, {
            "manifest": json.loads(baseline_path.read_text(encoding="utf-8")),
            "actor": "m.keller"})
        assert sealed_base["machine"] == key_of(VALIDATED)
        assert sealed_base["configuration_hash"] == baseline["configuration_hash"]

        drift_the_plant(live, a_key, plant, SERIALS)

        # -- the ingest opened one drift case per machine, in A's queue only -------------
        queue = hosted.ok("GET", "/v1/change/cases", a_key)
        drifts = {c["machines"][0]: c for c in queue["cases"] if c["trigger"] == "machine_drift"}
        assert set(drifts) == {key_of(s) for s in SERIALS}
        assert {c["status"] for c in drifts.values()} == {"open"}
        cid = {s: plant.expected_drift_case_id(key_of(s)) for s in SERIALS}
        assert {s: drifts[key_of(s)]["case_id"] for s in SERIALS} == cid
        # the drift is measured against the baseline `collect run` produced and the
        # hosted manifest route sealed, not against something the watch invented
        case0501 = hosted.ok("GET", f"/v1/change/cases/{cid[VALIDATED]}", a_key)
        assert case0501["before_hash"] == baseline["configuration_hash"]
        assert case0501["after_hash"] != case0501["before_hash"]
        assert hosted.ok("GET", "/v1/change/cases", b_key)["cases"] == []
        # ... and they live in A's own ledger file: A's is not empty; B's is empty; the
        # operator's shared ledger exists and holds exactly nothing
        a_ledger, b_ledger = live.tenant_ledger(a_id), live.tenant_ledger(b_id)
        # The service creates the shared ledger lazily and nothing here should ever touch it,
        # so create it empty first: "holds exactly nothing" is then a statement about a file
        # that exists, not about one that happens not to.
        operator_db = live.root / "operator.db"
        operator_ledger = EvidenceLedger(operator_db)
        for serial in SERIALS:
            assert [e.kind for e in a_ledger.entries(subject=cid[serial])] == [OPENED_KIND]

        def tenancy_holds() -> None:
            assert list(a_ledger.entries()) != []
            assert list(b_ledger.entries()) == []
            assert operator_db.exists()
            assert list(operator_ledger.entries()) == []

        tenancy_holds()

        # -- the other paid routes keep the same gate: 401 / 401 / 402 ---------------------
        now = run_started().strftime("%Y-%m-%dT%H:%M:%SZ")
        when = run_started()
        run = trace(when, trace_id="RUN-GATE-PROBE")
        paid = [
            ("POST", "/v1/machinery/manifest", {
                "manifest": json.loads(baseline_path.read_text(encoding="utf-8")),
                "actor": "m.keller"}),
            ("POST", "/v1/machine/verify", {
                "envelope": envelope_dict(), "trace": run.hashable_payload(),
                "actor": PERSON, "subject": key_of(VALIDATED)}),
            ("POST", "/v1/watch/report", {
                "watch_id": "WATCH-GATE-PROBE", "run_started_at": now, "machines": [{
                    "serial": "0777", "status": "uncollectable", "observed_at": now,
                    "collection_complete": False, "detail": "probe"}]}),
            ("GET", "/v1/operators", None),
            ("POST", "/v1/operators", {"name": "x.operator", "role": "decider"})]
        for method, path, body in paid:
            assert hosted.call(method, path, None, body).status_code == 401, path
            assert hosted.call(method, path, "asr_not_a_key", body).status_code == 401, path
            refused = hosted.call(method, path, r_key, body)
            assert refused.status_code == 402, (path, refused.status_code, refused.text[:200])
            assert refused.json()["detail"]["tier"] == "register", path
        # the Register plan DOES include the Article 14 register: the boundary is exact
        late_signal = {
            "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
            "description": "Gate probe", "reference": "T-1",
            "actor": {"identifier": PERSON, "role": "Head of Engineering"}}
        # FINDING, pinned as found: a keyless write to the register on a deployment with NO
        # operator key configured is 503 ("refuses unauthenticated writes by default"), not
        # 401; CLAUDE.md says 401. The deployment sets ASSURANCE_API_KEYS (the e2e script
        # does), and then it is the 401 below. /v1/change, /v1/machine etc. are 401 either way.
        unconfigured = hosted.call("POST", "/v1/cases/CASE-GATE/signal", None, late_signal)
        assert unconfigured.status_code == 503
        operator_key = "golden-path-throwaway-operator-key"
        monkeypatch.setenv("ASSURANCE_API_KEYS", operator_key)
        assert hosted.call("POST", "/v1/cases/CASE-GATE/signal", None,
                           late_signal).status_code == 401
        assert hosted.call("POST", "/v1/cases/CASE-GATE/signal", "asr_not_a_key",
                           late_signal).status_code == 401
        assert hosted.call("POST", "/v1/cases/CASE-GATE/signal", r_key,
                           late_signal).status_code == 201

        # -- refusals on A's case ---------------------------------------------------------
        target = f"/v1/change/cases/{cid[VALIDATED]}"
        claim_body = {"owner": PERSON, "actor": PERSON}
        b_op = hosted.ok("POST", "/v1/operators", b_key, {"name": PERSON, "role": "decider"})
        manifest = plant.manifest_dict(key_of(VALIDATED))
        human = ("decision", "resume", "resolve-decision", "waive-reverification")
        case_routes = [
            ("GET", target, None), ("GET", f"{target}/export", None),
            ("GET", f"{target}/replay", None),
            ("POST", f"{target}/claim", claim_body),
            ("POST", f"{target}/advance", {"actor": PERSON}),
            ("POST", f"{target}/reverification", {
                "manifest": manifest, "verification_content_hash": "a" * 64, "actor": PERSON}),
            ("POST", f"{target}/decision", {"disposition": "rejected", "reason": "r",
                                            "actor": PERSON}),
            ("POST", f"{target}/resume", {"reason": "r", "actor": PERSON}),
            ("POST", f"{target}/resolve-decision",
             {"decision": "q", "resolution": "r", "actor": PERSON}),
            ("POST", f"{target}/waive-reverification",
             {"entry": "SF-01", "reason": "r", "actor": PERSON})]
        other_routes = [
            ("GET", "/v1/change/cases", None),
            ("POST", "/v1/change/assess/advisory", {"advisory": {}}),
            ("POST", "/v1/change/assess/drift", {"baseline": {}, "observed": {}}),
            ("POST", "/v1/change/assess/intervention",
             {"manifest": {}, "intervention_id": "INT-1"})]
        for method, path, body in case_routes + other_routes:
            assert hosted.call(method, path, None, body).status_code == 401, path
            assert hosted.call(method, path, "asr_not_a_key", body).status_code == 401, path
            denied = hosted.call(method, path, r_key, body)
            assert denied.status_code == 402, (path, denied.status_code)
            assert denied.json()["detail"]["error"] == \
                "plan_does_not_include_machine_verification"
            assert denied.json()["detail"]["tier"] == "register"
        for method, path, body in case_routes:
            as_b = b_op["api_key"] if path.rsplit("/", 1)[-1] in human else b_key
            missing = hosted.call(method, path, as_b, body)
            assert missing.status_code == 404, (path, missing.status_code, missing.text[:200])
            assert missing.json()["detail"] == {"error": "case_not_found",
                                                "case_id": cid[VALIDATED]}
        # -- who may make a human decision: a decider OPERATOR, never an account key ------
        decision = {"disposition": "rejected", "reason": "r", "actor": PERSON}
        someone_else = hosted.call("POST", f"{target}/decision", decider,
                                   {**decision, "actor": "not.the.operator"})
        assert someone_else.status_code == 403
        assert someone_else.json()["detail"]["error"] == "actor_mismatch"
        contributor = hosted.ok("POST", "/v1/operators", decider,
                                {"name": "c.contributor", "role": "contributor"})
        assert contributor["role"] == "contributor"
        human_bodies = {
            "decision": decision, "resume": {"reason": "r", "actor": PERSON},
            "resolve-decision": {"decision": "q", "resolution": "r", "actor": PERSON},
            "waive-reverification": {"entry": "SF-01", "reason": "r", "actor": PERSON}}
        for verb, body in human_bodies.items():
            by_account = hosted.call("POST", f"{target}/{verb}", a_key, body)
            assert by_account.status_code == 403, (verb, by_account.status_code)
            assert by_account.json()["detail"]["error"] == "operator_required", verb
            by_contributor = hosted.call("POST", f"{target}/{verb}", contributor["api_key"],
                                         {**body, "actor": "c.contributor"})
            assert by_contributor.status_code == 403, (verb, by_contributor.status_code)
            assert by_contributor.json()["detail"]["error"] == "decider_role_required", verb
        # every refusal left the case exactly as the push opened it
        assert hosted.ok("GET", target, a_key)["status"] == "open"

        # -- the lifecycle: claim and advance with the account key -----------------------
        for serial in SERIALS:
            advance_to_reverification(hosted, a_key, cid[serial])

        # -- 1. validated: a trusted recorder attested the run ---------------------------
        good = verify_run(hosted, a_key, VALIDATED, attested=True)
        assert good["tier"] == "validated"
        assert good["recorder_attestation"]["status"] == "accepted"
        assert good["recorder_attestation"]["attested"] is True
        cleared = reverify(hosted, a_key, plant, cid[VALIDATED], VALIDATED, good["content_hash"])
        assert cleared["status"] == "ready_to_close" and "blocked_reason" not in cleared
        assert set(cleared["evidence_current"].values()) == {"current"}
        assert cleared["required_reverifications"] == []
        closed = hosted.ok("POST", f"{target}/decision", decider, {
            "disposition": "closed", "reason": "Re-verified after the firmware change.",
            "actor": PERSON})
        assert closed["status"] == "closed" and closed["decision_by"] == PERSON

        # -- 2. waived: nobody verified; a named decider closes without evidence ---------
        waive_base = f"/v1/change/cases/{cid[WAIVED]}"
        assert hosted.call("POST", f"{waive_base}/decision", decider, {
            "disposition": "closed", "reason": "early", "actor": PERSON}).status_code == 409
        shut = waive_and_close(hosted, a_key, decider, cid[WAIVED])
        assert shut["status"] == "closed"

        # -- 3. refused: an unattested verification is community and clears nothing ------
        weak = verify_run(hosted, a_key, REFUSED, attested=False)
        assert weak["tier"] == "community"
        assert weak["recorder_attestation"]["attested"] is False
        held = reverify(hosted, a_key, plant, cid[REFUSED], REFUSED, weak["content_hash"])
        assert held["status"] == "awaiting_reverification"
        assert held["blocked_reason"]["code"] == "below_validated_tier"
        assert set(held["evidence_current"].values()) == {"below_validated:community"}
        refuse_base = f"/v1/change/cases/{cid[REFUSED]}"
        assert hosted.call("POST", f"{refuse_base}/decision", decider, {
            "disposition": "closed", "reason": "Looks fine.", "actor": PERSON}
        ).status_code == 409
        assert hosted.ok("GET", refuse_base, a_key)["status"] == "awaiting_reverification"

        # -- sign the head, export with the skeleton, tell the three outcomes apart ------
        keygen = run_cli("attest", "keygen", "--out", tmp / "secrets" / "head.pem",
                         "--public-out", tmp / "head.pub")
        assert keygen.returncode == 0, keygen.stderr
        signing_key, public_key = tmp / "secrets" / "head.pem", tmp / "head.pub"
        signed = attest_sign(tmp, a_id, signing_key)
        assert signed["basis"] == "read_from_ledger"

        bundles = {s: hosted.ok("GET", f"/v1/change/cases/{cid[s]}/export", a_key,
                                skeleton="true") for s in SERIALS}
        exports_seen = list(bundles.values())     # scanned for secrets at the end
        outcomes = {s: outcome_of(b) for s, b in bundles.items()}
        assert outcomes == {VALIDATED: "validated", WAIVED: "waived",
                            REFUSED: "refused_below_validated"}
        # the validated case cites exactly the verification the server graded `validated`,
        # the refused one cites the one it graded `community`, the waived one cites none
        assert supports(final_case(bundles[VALIDATED])) == [good["content_hash"]]
        assert supports(final_case(bundles[REFUSED])) == [weak["content_hash"]]
        assert supports(final_case(bundles[WAIVED])) == []
        waiver_case = final_case(bundles[WAIVED])
        assert {d["by"] for d in waiver_case["resolved_decisions"]} == {PERSON}
        assert "waived" not in final_case(bundles[VALIDATED])["evidence_current"].values()
        assert "current" not in waiver_case["evidence_current"].values()
        # who did it, as the export records it: every waiver and the closing decision carry
        # an operator-bound credential; claim / advance / re-verify were an account key's
        # declared names; the case was opened by the hosted watch report (automation)
        for serial in (VALIDATED, WAIVED):
            entries = bundles[serial]["entries"]
            assert entries[0]["evidence"]["actor"]["identifier"] == "hosted-watch-report"
            assert entries[0]["evidence"]["actor"]["kind"] == "automation"
            by_operator = [e for e in entries
                           if "attribution=authenticated_operator" in e["evidence"]["actor"]["role"]]
            by_account_key = [e for e in entries
                              if "attribution=declared_by_account_key" in e["evidence"]["actor"]["role"]]
            human_steps = len(final_case(bundles[serial])["resolved_decisions"]) + 1
            assert len(by_operator) == human_steps, (serial, len(by_operator), human_steps)
            assert entries[-1] in by_operator          # the close is the operator's
            assert {e["evidence"]["actor"]["identifier"] for e in by_operator} == {PERSON}
            assert {e["evidence"]["actor"]["kind"] for e in by_operator} == {"person"}
            assert len(by_account_key) + len(by_operator) + 1 == len(entries), serial

        # -- verify independently: offline with the key, and anonymously over HTTP -------
        public_pem = public_key.read_text(encoding="utf-8")
        for serial, bundle in bundles.items():
            code, offline = verify_offline(bundle, tmp, f"export-{serial}", public_key)
            assert code == 0 and offline["ok"] is True, (serial, offline)
            assert offline["completeness"] == "anchored", (serial, offline)
            assert offline["anchor"]["basis"] == "read_from_ledger"
            assert offline["problems"] == []
            anon = verify_anonymously(live, bundle, public_pem)
            assert anon["ok"] is True and anon["completeness"] == "anchored", (serial, anon)
            assert anon["problems"] == []
            # "anchored" is never a stronger claim than it is: the verifier still says the
            # party holding a hosted ledger could hold the signing key too
            for said in (offline, anon):
                assert said["assumptions"], serial
                assert _SAME_PARTY in said["assumptions"], (serial, said["assumptions"])
            # the same bundle with no key is only internally consistent, and says so
            keyless = run_cli("evidence", "verify", tmp / f"export-{serial}.json", "--json")
            assert keyless.returncode == 0
            assert json.loads(keyless.stdout)["completeness"] == "not_checked"

        # -- a tampered export is rejected on both paths ---------------------------------
        edited = copy.deepcopy(bundles[REFUSED])
        edited["entries"][-1]["evidence"]["body"]["case"]["status"] = "closed"
        cut = copy.deepcopy(bundles[VALIDATED])
        cut["entries"] = cut["entries"][:-1]
        # the careful forger: the ledger's last record removed from the entries AND the
        # skeleton, the unsigned head rewritten to match, so every internal check agrees;
        # only the signed anchor still remembers the longer ledger
        head = bundles[VALIDATED]["attestation"]["head_seq"]
        tail_cut = _cut_tail(bundles[VALIDATED], head - 1)
        assert tail_cut["attestation"]["head_seq"] == head - 1
        # ... and the forger who also re-points the embedded anchor at the shorter head but
        # cannot sign it: the signature is garbage of the right shape
        repointed = copy.deepcopy(tail_cut)
        repointed["anchor"] = {
            **bundles[VALIDATED]["anchor"],
            "ledger_length": tail_cut["attestation"]["length"],
            "head_seq": tail_cut["attestation"]["head_seq"],
            "head_link_hash": tail_cut["attestation"]["head_link_hash"],
            "signature": base64.b64encode(bytes(64)).decode()}
        assert repointed["anchor"]["signature"] != bundles[VALIDATED]["anchor"]["signature"]
        for label, forged in (("edited", edited), ("truncated", cut),
                              ("tail-cut-and-rewritten", tail_cut),
                              ("tail-cut-with-forged-anchor", repointed)):
            code, offline = verify_offline(forged, tmp, f"forged-{label}", public_key)
            anon = verify_anonymously(live, forged, public_pem)
            assert code != 0 and offline["ok"] is False, (label, offline)
            assert offline["completeness"] != "anchored", (label, offline)
            assert anon["ok"] is False and anon["completeness"] != "anchored", (label, anon)

        # a perfectly good export checked against somebody else's key is not anchored either
        other = run_cli("attest", "keygen", "--out", tmp / "secrets" / "other.pem",
                        "--public-out", tmp / "other.pub")
        assert other.returncode == 0, other.stderr
        code, offline = verify_offline(bundles[VALIDATED], tmp, "wrong-key", tmp / "other.pub")
        anon = verify_anonymously(live, bundles[VALIDATED],
                                  (tmp / "other.pub").read_text(encoding="utf-8"))
        assert code != 0 and offline["ok"] is False and offline["completeness"] != "anchored"
        assert anon["ok"] is False and anon["completeness"] != "anchored", anon

        # a head the service was only TOLD (POST /v1/ledger/attest, signed by the same
        # key) is never an anchor: embedded in the same export it reads declared_head
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(signing_key))
        told = bundles[VALIDATED]["attestation"]
        counter = hosted.ok("POST", "/v1/ledger/attest", a_key, {
            "ledger_length": told["length"], "head_seq": told["head_seq"],
            "head_link_hash": told["head_link_hash"], "note": "declared by the holder"})
        assert counter["attestation"]["basis"] == "declared_by_holder"
        bare = hosted.ok("GET", f"{target}/export", a_key, skeleton="true", anchor="false")
        assert "anchor" not in bare
        declared = {**bare, "anchor": counter["attestation"]}
        code, offline = verify_offline(declared, tmp, "declared-head", public_key)
        anon = verify_anonymously(live, declared, public_pem)
        assert code == 3 and offline["completeness"] == "declared_head", offline
        assert anon["completeness"] == "declared_head", anon
        assert offline["anchor"]["basis"] == "declared_by_holder"

        # -- a record sealed after the signature is covered by no signature --------------
        # ("anchored" must be earned: a head that stops short of the ledger is partial)
        hosted.ok("POST", "/v1/cases/CASE-LATE/signal", a_key, {
            "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
            "description": "Recorded after the head was signed", "reference": "T-1",
            "actor": {"identifier": PERSON, "role": "Head of Engineering"}})
        late = hosted.ok("GET", f"{target}/export", a_key, skeleton="true")
        exports_seen.append(late)
        code, partial = verify_offline(late, tmp, "late", public_key)
        assert code == 3 and partial["completeness"] == "anchored_partial", partial
        assert partial["anchor"]["records_after_anchor"] == 1
        anon = verify_anonymously(live, late, public_pem)
        assert anon["completeness"] == "anchored_partial", anon
        # the operator signs the new head, and the same export is anchored again
        assert attest_sign(tmp, a_id, signing_key)["basis"] == "read_from_ledger"
        again = hosted.ok("GET", f"{target}/export", a_key, skeleton="true")
        exports_seen.append(again)
        code, offline = verify_offline(again, tmp, "resigned", public_key)
        assert code == 0 and offline["completeness"] == "anchored", offline
        assert verify_anonymously(live, again, public_pem)["completeness"] == "anchored"

        # -- the subscription lapses: only the documented read-out survives --------------
        lapse = hosted.webhook({
            "id": "evt_golden_lapse", "created": int(time.time()) + 60,
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": a_customer, "status": "canceled"}}})
        assert lapse.status_code == 200, lapse.text
        # every change-assurance route, read or write, is 402 and says the evidence is theirs
        for method, path, body in (
                ("GET", "/v1/change/cases", None), ("GET", target, None),
                ("GET", f"{target}/export", None), ("GET", f"{target}/replay", None),
                ("POST", f"{refuse_base}/advance", {"actor": PERSON})):
            r = hosted.call(method, path, a_key, body)
            assert r.status_code == 402, (path, r.status_code)
            detail = r.json()["detail"]
            assert detail["account_status"] == "cancelled" and "export" in detail["remedy"]
        assert hosted.call("POST", "/v1/machine/verify", a_key, {}).status_code == 402
        # The documented read-out (plans.EVIDENCE_READOUT_AFTER_LAPSE, claims-registry
        # "lapsed" row) still works from the account's own ledger. FOUNDER DECISION, asserted
        # here as the current behaviour and not as a stated promise: the registry lists the
        # change-case routes as 402 after a lapse and does not mention that the read-out
        # route `GET /v1/cases/{id}/export` exports by subject and so also reaches a closed
        # CHANGE case. Same chain, still anchored. If the founder rules otherwise, this block
        # and the 402 list above are the two places to change.
        lapsed = hosted.call("GET", f"/v1/cases/{cid[VALIDATED]}/export", a_key,
                             skeleton="true")
        assert lapsed.status_code == 200
        exports_seen.append(lapsed.json())
        assert lapsed.headers["x-assurance-access"] == "evidence-readout-only"
        assert outcome_of(lapsed.json()) == "validated"
        code, offline = verify_offline(lapsed.json(), tmp, "lapsed", public_key)
        assert code == 0 and offline["completeness"] == "anchored"
        assert hosted.ok("GET", "/v1/ledger/verify", a_key)["verified"] is True
        # B, who never lapsed, is untouched and still sees none of A's evidence
        assert hosted.ok("GET", "/v1/change/cases", b_key)["cases"] == []
        assert hosted.call("GET", f"{target}/export", b_key).status_code == 404

        # nothing leaked sideways, before or after any of it
        tenancy_holds()
        # a lapsed account's read-out lists every SUBJECT in its own ledger.
        # FOUNDER DECISION (open, see docs/claims-registry.md): GET /v1/cases is documented as
        # the readout of "your cases" but lists change-case ids and machine keys too, while
        # GET /v1/cases/{id} answers 404 for a change case. Pinned as found.
        listing = hosted.ok("GET", "/v1/cases", a_key)
        assert set(cid.values()) <= set(listing)
        assert {key_of(s) for s in SERIALS} <= set(listing)
        assert hosted.call("GET", f"/v1/cases/{cid[VALIDATED]}", a_key).status_code == 404

        # no secret of any party is in any export (key PREFIXES such as `asr_55TknW`, the
        # first 11 characters, appear in actor roles BY DESIGN; only full values are scanned)
        signing_body = "".join(line for line in signing_key.read_text(encoding="utf-8").split()
                               if not line.startswith("-----"))
        assert len(signing_body) > 40
        secrets = {"A key": a_key, "B key": b_key, "R key": r_key, "A decider key": decider,
                   "B decider key": b_op["api_key"],
                   "A contributor key": contributor["api_key"],
                   "operator key": operator_key, "webhook secret": WEBHOOK_SECRET,
                   "signing key": signing_body}
        assert len(exports_seen) == 6
        for n, bundle in enumerate(exports_seen):
            text = json.dumps(bundle)
            for name, value in secrets.items():
                assert value not in text, f"export {n} contains the {name}"


class TestWithoutAServerRecorderTrustList:
    """The path the golden path's ``validated`` case depends on, taken away.

    A recorder's signature only counts under the SERVER's own trust list. With none
    configured, or one the server cannot read, an attested run is ``community``, clears
    nothing, and the case closes only by a named person's waiver, which the export shows
    as a waiver.
    """

    @pytest.mark.parametrize("trust", ["unset", "unreadable"])
    def test_an_attested_run_is_community_and_only_a_waiver_closes(
            self, env, monkeypatch, trust):
        live, hosted, tmp = env
        if trust == "unset":
            monkeypatch.delenv("ASSURANCE_RECORDER_TRUST")
        else:
            monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(tmp / "no-such-file.json"))
        a_id, a_key, _ = hosted.checkout("cell", "alpha")
        decider = hosted.ok("POST", "/v1/operators", a_key,
                            {"name": PERSON, "role": "decider"})["api_key"]
        plant = Plant(tmp / "plant", serials=(VALIDATED,))
        drift_the_plant(live, a_key, plant, (VALIDATED,))
        case_id = plant.expected_drift_case_id(key_of(VALIDATED))
        advance_to_reverification(hosted, a_key, case_id)

        signed_by_a_recorder = verify_run(hosted, a_key, VALIDATED, attested=True)
        assert signed_by_a_recorder["recorder_trust"]["status"] == trust
        assert signed_by_a_recorder["recorder_attestation"]["attested"] is False
        assert signed_by_a_recorder["tier"] == "community"
        held = reverify(hosted, a_key, plant, case_id, VALIDATED,
                        signed_by_a_recorder["content_hash"])
        assert held["status"] == "awaiting_reverification"
        assert held["blocked_reason"]["code"] == "below_validated_tier"
        assert hosted.call("POST", f"/v1/change/cases/{case_id}/decision", decider, {
            "disposition": "closed", "reason": "It was signed.", "actor": PERSON}
        ).status_code == 409

        assert waive_and_close(hosted, a_key, decider, case_id)["status"] == "closed"
        # the waiver is a waiver in the export, though a (community) verification was cited
        exported = hosted.ok("GET", f"/v1/change/cases/{case_id}/export", a_key)
        case = final_case(exported)
        assert set(case["evidence_current"].values()) == {"waived"}
        assert [d["kind"] for d in case["resolved_decisions"]] == ["waiver"] * len(
            case["evidence_current"])
        assert outcome_of(exported) == "waived_citing_unattested_evidence"
