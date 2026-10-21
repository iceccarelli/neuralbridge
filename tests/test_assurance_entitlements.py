"""The entitlement contract, end to end.

``billing/plans.py`` says what each tier may do; ``api/deps.py`` holds the gates;
the routes carry them. These tests read the *live FastAPI app* rather than a
list somebody has to remember to extend, so a new ``/v1`` route that reads or
writes tenant data without a gate fails here, and a plan flag that no route
consults fails here.

Also pinned: what a customer can still do after the subscription ends (read,
verify and export their own evidence, but write nothing), what happens at a
quota limit (a 429 that says what to do, never a silent drop), and that a
revoked key stops at once on every route.
"""

from __future__ import annotations

import dataclasses
import importlib
from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing import plans as plans_module
from assurance.billing.plans import PLANS
from assurance.core.identity import utc_now

OPERATOR_KEY = "operator-key-entitlements"
ACTOR = {"identifier": "m.braun", "role": "Entwicklungsleitung"}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL", "ASSURANCE_PRICE_PAYG",
                 "ASSURANCE_TENANT_LEDGERS", "ASSURANCE_TRUST_FLY_PROXY"):
        monkeypatch.delenv(name, raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def app(env):
    return importlib.import_module("assurance.api.service").create_app()


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def store(client):
    return deps.get_accounts()


def _acct(store, tier, email, *, status="active", customer=True):
    account = store.upsert_account(
        email=email, tier=tier, status=status,
        stripe_customer_id=f"cus_{email}" if customer else "",
    )
    return account, {"X-API-Key": store.issue_key(account.id)}


def _signal(client, headers, case="CASE-1"):
    return client.post(
        f"/v1/cases/{case}/signal", headers=headers,
        json={"received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
              "description": "Exploitation of the SK-4200 service port observed",
              "reference": "T-1", "actor": ACTOR},
    )


def _routes(app) -> Iterator[APIRoute]:
    """Every APIRoute, whichever way this FastAPI version nests included routers."""
    def walk(routes):
        for route in routes:
            if isinstance(route, APIRoute):
                yield route
            elif hasattr(route, "original_router"):
                yield from walk(route.original_router.routes)
            elif hasattr(route, "routes"):
                yield from walk(route.routes)
    yield from walk(app.routes)


def _calls(dependant) -> set:
    found = set()
    for sub in dependant.dependencies:
        found.add(sub.call)
        found |= _calls(sub)
    return found


def _v1(app) -> dict[tuple[str, str], APIRoute]:
    out = {}
    for route in _routes(app):
        if route.path.startswith("/v1"):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                out[(method, route.path)] = route
    return out


def _gates(route: APIRoute) -> set[str]:
    calls = _calls(route.dependant)
    return {name for fn, name in deps.ENTITLEMENT_GATES.items() if fn in calls}


# ---------------------------------------------------------------------------
# 1. every /v1 route has a stated gate
# ---------------------------------------------------------------------------
#: Routes with no entitlement gate, and why that is right. Each is stateless
#: (nothing of an account is read or written) or acts only on the caller's own
#: account. A new route that is neither must carry a gate, or be added here
#: with a reason a reviewer can disagree with.
FREE_ROUTES = {
    ("GET", "/v1/plans"): "the catalogue",
    ("GET", "/v1/spec/fields"): "the public specification",
    ("POST", "/v1/spec/validate"): "free validator, daily allowance via metering",
    ("POST", "/v1/machine/separation"): "stateless calculator, daily allowance via metering",
    ("POST", "/v1/machine/bundle/check"): "re-verifies a bundle the caller supplies",
    ("POST", "/v1/machinery/diff"): "stateless comparison, daily allowance via metering",
    ("POST", "/v1/machinery/passport/check"): "re-verifies a passport the caller supplies",
    ("POST", "/v1/fleet/advisory/check"): "stateless, daily allowance via metering",
    ("POST", "/v1/fleet/declaration/check"):
        "stateless; reads the caller's ledger only inside a plan.machine_verification branch",
    ("POST", "/v1/check/machine"): "ad-hoc check of two documents the caller supplies",
    ("GET", "/v1/ledger/attest/key"): "the public verification key",
    ("POST", "/v1/ledger/attest/verify"): "verifies a signed attestation the caller supplies",
    ("POST", "/v1/evidence/verify"):
        "stateless: verifies an evidence file the caller supplies; daily allowance via metering",
    ("GET", "/v1/supplier/feed/{supplier_account_id}"):
        "a supplier feed is public by design (ADR-0001)",
}
#: Acts only on the caller's own account, whatever the plan or status: a lapsed
#: customer must still be able to revoke a leaked key, see what they used, and
#: reach the billing portal.
ACCOUNT_ROUTES = {
    ("POST", "/v1/checkout"), ("GET", "/v1/checkout/complete"),
    ("POST", "/v1/billing/webhook"), ("GET", "/v1/me"),
    ("GET", "/v1/keys"), ("POST", "/v1/keys"), ("POST", "/v1/keys/revoke"),
    ("POST", "/v1/billing/portal"),
    ("GET", "/v1/usage"), ("POST", "/v1/usage/limits"),
}
#: Routes that reach a ledger (``get_register``) without an entitlement gate.
LEDGER_WITHOUT_GATE = {("POST", "/v1/fleet/declaration/check")}


class TestEveryRouteHasAStatedGate:
    def test_no_v1_route_is_unclassified_or_ungated(self, app):
        ungated = []
        for (method, path), route in sorted(_v1(app).items()):
            if _gates(route):
                continue
            if (method, path) in FREE_ROUTES or (method, path) in ACCOUNT_ROUTES:
                continue
            ungated.append(f"{method} {path}")
        assert ungated == [], (
            "these /v1 routes have no entitlement gate and no entry in FREE_ROUTES / "
            f"ACCOUNT_ROUTES: {ungated}")

    def test_the_allow_lists_do_not_name_routes_that_no_longer_exist(self, app):
        live = set(_v1(app))
        stale = (set(FREE_ROUTES) | ACCOUNT_ROUTES | LEDGER_WITHOUT_GATE) - live
        assert stale == set(), f"stale entries: {sorted(stale)}"

    def test_a_route_that_reads_a_ledger_is_gated_or_explicitly_listed(self, app):
        offenders = []
        for key, route in sorted(_v1(app).items()):
            if deps.get_register in _calls(route.dependant) and not _gates(route) \
                    and key not in LEDGER_WITHOUT_GATE:
                offenders.append(key)
        assert offenders == []

    def test_a_free_route_is_not_secretly_gated(self, app):
        gated_but_listed = [k for k in FREE_ROUTES if _gates(_v1(app)[k])]
        assert gated_but_listed == [], "remove it from FREE_ROUTES, the gate is real"

    def test_the_scanner_can_fail(self, app):
        """Mutation check: strip a gate off a real route and the scan must see it."""
        route = _v1(app)[("GET", "/v1/cases")]
        assert _gates(route)
        stripped = dataclasses.replace(route.dependant, dependencies=[])
        assert deps.require_register not in _calls(stripped)

    def test_every_gate_a_plan_can_switch_is_carried_by_a_route(self, app):
        carried = set()
        for route in _v1(app).values():
            carried |= _gates(route)
        for flag in ("register", "machine_verification", "signed_attestation",
                     "supplier_publish"):
            assert flag in carried, f"Plan.{flag} gates nothing"
        assert "evidence_readout" in carried

    def test_every_gate_names_a_real_plan_flag(self):
        fields = {f.name for f in dataclasses.fields(plans_module.Plan)}
        for name in deps.ENTITLEMENT_GATES.values():
            assert name == "evidence_readout" or name in fields, name

    def test_the_documented_gate_flags_equal_the_enforced_ones(self):
        enforced = {n for n in deps.ENTITLEMENT_GATES.values() if n != "evidence_readout"}
        assert enforced == set(plans_module.GATE_FLAGS)


# ---------------------------------------------------------------------------
# 2. what each gate does to each kind of caller
# ---------------------------------------------------------------------------
def _call(client, method, path, headers):
    path = path.replace("{case_id}", "CASE-1").replace("{supplier_account_id}", "x")
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, headers=headers, json={})


class TestGateBehaviour:
    def test_anonymous_gets_401_and_a_free_key_gets_402_on_every_gated_route(
            self, app, client, store):
        _, free_key = _acct(store, "free", "f@example.de", customer=False)
        for (method, path), route in sorted(_v1(app).items()):
            gates = _gates(route)
            if not gates:
                continue
            anonymous = _call(client, method, path, {})
            assert anonymous.status_code in (401, 503), (method, path, anonymous.status_code)
            paid_only = _call(client, method, path, free_key)
            assert paid_only.status_code == 402, (method, path, paid_only.status_code)

    def test_a_revoked_key_is_401_on_every_route_that_reads_a_key(self, app, client, store):
        account, headers = _acct(store, "cell", "c@example.de")
        assert store.revoke_account_key(account.id, key_prefix=store.keys_for(account.id)[0]["prefix"]) \
            == "revoked"
        for (method, path), route in sorted(_v1(app).items()):
            if deps.current_principal not in _calls(route.dependant):
                continue
            if (method, path) == ("POST", "/v1/billing/webhook"):
                continue
            response = _call(client, method, path, headers)
            assert response.status_code == 401, (method, path, response.status_code)

    def test_the_402_names_the_remedy(self, client, store):
        _, free_key = _acct(store, "free", "f@example.de", customer=False)
        body = client.get("/v1/register", headers=free_key).json()["detail"]
        assert body["error"] == "plan_does_not_include_register"
        assert "POST /v1/checkout" in body["remedy"]


# ---------------------------------------------------------------------------
# 3. after the subscription ends: read, verify and export your own evidence;
#    write nothing
# ---------------------------------------------------------------------------
READOUT = {
    ("GET", "/v1/cases"), ("GET", "/v1/cases/{case_id}"),
    ("GET", "/v1/cases/{case_id}/export"), ("GET", "/v1/ledger/verify"),
}


class TestLapsedCustomerKeepsTheirEvidence:
    def _lapse(self, store, account, how="deleted"):
        if how == "deleted":
            store.set_status(stripe_customer_id=account.stripe_customer_id,
                             status="cancelled", tier="free", event_created=5000)
        elif how == "paused":
            store.set_status(stripe_customer_id=account.stripe_customer_id,
                             status="cancelled", tier=None, event_created=5000)

    @pytest.mark.parametrize("how", ["deleted", "paused"])
    def test_export_and_verify_still_work_and_say_so(self, client, store, how):
        account, headers = _acct(store, "register", "r@example.de")
        assert _signal(client, headers).status_code == 201
        self._lapse(store, store.account(account.id), how)

        export = client.get("/v1/cases/CASE-1/export", headers=headers)
        assert export.status_code == 200, export.text
        assert export.json()["chain_verified"] is True
        assert len(export.json()["entries"]) == 1
        assert export.headers["x-assurance-access"] == "evidence-readout-only"

        verify = client.get("/v1/ledger/verify", headers=headers)
        assert verify.status_code == 200 and verify.json()["verified"] is True
        assert client.get("/v1/cases", headers=headers).json() == ["CASE-1"]
        assert client.get("/v1/cases/CASE-1", headers=headers).status_code == 200

    def test_the_bundle_a_lapsed_customer_exports_verifies_offline(self, client, store):
        from assurance.evidence.verify_export import verify_export  # the offline verifier

        account, headers = _acct(store, "register", "r@example.de")
        _signal(client, headers)
        self._lapse(store, store.account(account.id))
        bundle = client.get("/v1/cases/CASE-1/export", headers=headers).json()
        assert verify_export(bundle).ok is True

    def test_but_every_write_and_every_operational_view_stops(self, app, client, store):
        account, headers = _acct(store, "cell", "c@example.de")
        assert _signal(client, headers).status_code == 201
        self._lapse(store, store.account(account.id))
        readable = {(m, p) for (m, p) in _v1(app) if (m, p) in READOUT}
        assert readable == READOUT
        for (method, path), route in sorted(_v1(app).items()):
            gates = _gates(route)
            if not gates or (method, path) in READOUT:
                continue
            denied = _call(client, method, path, headers)
            assert denied.status_code == 402, (method, path, denied.status_code)
        denied = _signal(client, headers, case="CASE-2")
        assert denied.status_code == 402
        detail = denied.json()["detail"]
        assert detail["account_status"] == "cancelled"
        assert "export" in detail["remedy"].lower()
        # And nothing was written.
        assert client.get("/v1/cases", headers=headers).json() == ["CASE-1"]

    def test_the_readout_set_is_exactly_the_documented_one(self, app):
        carried = {k for k, r in _v1(app).items() if "evidence_readout" in _gates(r)}
        assert carried == READOUT
        assert {tuple(x) for x in plans_module.EVIDENCE_READOUT_AFTER_LAPSE} == {
            (m, p) for m, p in READOUT}

    def test_someone_who_never_paid_gets_no_readout(self, client, store):
        _, headers = _acct(store, "free", "n@example.de", customer=False)
        for path in ("/v1/cases", "/v1/ledger/verify", "/v1/cases/X/export"):
            assert client.get(path, headers=headers).status_code == 402, path

    def test_a_lapsed_customer_sees_only_their_own_ledger(self, client, store):
        a, ha = _acct(store, "register", "a@example.de")
        b, hb = _acct(store, "register", "b@example.de")
        _signal(client, ha)
        self._lapse(store, store.account(a.id))
        self._lapse(store, store.account(b.id))
        assert client.get("/v1/cases", headers=hb).json() == []
        assert "SK-4200" not in client.get("/v1/cases/CASE-1/export", headers=hb).text

    def test_past_due_keeps_everything_it_always_had(self, client, store):
        account, headers = _acct(store, "register", "r@example.de", status="past_due")
        assert _signal(client, headers).status_code == 201

    def test_a_revoked_key_gets_no_readout(self, client, store):
        account, headers = _acct(store, "register", "r@example.de")
        _signal(client, headers)
        self._lapse(store, store.account(account.id))
        prefix = store.keys_for(account.id)[0]["prefix"]
        store.revoke_account_key(account.id, key_prefix=prefix)
        assert client.get("/v1/cases/CASE-1/export", headers=headers).status_code == 401

    def test_a_lapsed_account_can_still_manage_keys_and_see_itself(self, client, store):
        account, headers = _acct(store, "register", "r@example.de")
        self._lapse(store, store.account(account.id))
        assert client.get("/v1/keys", headers=headers).status_code == 200
        me = client.get("/v1/me", headers=headers).json()
        assert me["evidence_readout"] is True
        assert me["tier"] == "free"

    def test_the_plan_flag_still_governs_an_entitled_export(self, client, store, monkeypatch):
        _, headers = _acct(store, "register", "e@example.de")
        monkeypatch.setitem(PLANS, "register", dataclasses.replace(PLANS["register"], export=False))
        denied = client.get("/v1/cases/NONE/export", headers=headers)
        assert denied.status_code == 402
        assert denied.json()["detail"]["error"] == "plan_does_not_include_export"


# ---------------------------------------------------------------------------
# 4. at the quota: a 429 that says what to do
# ---------------------------------------------------------------------------
SEPARATION = {"robot_speed_mm_s": 250, "reaction_time_s": 0.1, "stop_time_s": 0.2,
              "stop_distance_mm": 50, "measured_at_speed_mm_s": 250,
              "intrusion_distance_mm": 100}
VALIDATE = {"track": "actively_exploited_vulnerability", "stage": "early_warning",
            "payload": {}}


class TestQuotaLimitIsLoud:
    def test_a_free_caller_at_the_limit_gets_a_429_with_everything_needed(self, client):
        limit = PLANS["free"].validations_per_day
        for _ in range(limit):
            assert client.post("/v1/spec/validate", json=VALIDATE).status_code == 200
        over = client.post("/v1/spec/validate", json=VALIDATE)
        assert over.status_code == 429
        detail = over.json()["detail"]
        assert detail["error"] == "quota_exceeded"
        assert (detail["scope"], detail["limit"], detail["used"]) == ("validate", limit, limit)
        assert detail["tier"] == "free"
        assert "POST /v1/checkout" in detail["remedy"]
        # When it opens again, in both machine and human form.
        retry = int(over.headers["retry-after"])
        assert 1 <= retry <= 86400
        assert detail["resets_at"].endswith("Z")
        assert detail["retry_after_seconds"] == retry

    def test_the_other_free_scopes_say_the_same(self, client):
        for path, body, limit in (
            ("/v1/machine/separation", SEPARATION, PLANS["free"].separations_per_day),
        ):
            for _ in range(limit):
                assert client.post(path, json=body).status_code == 200
            over = client.post(path, json=body)
            assert over.status_code == 429, path
            assert over.json()["detail"]["error"] == "quota_exceeded"
            assert "retry-after" in over.headers

    def test_a_registered_customer_is_not_capped(self, client, store):
        _, headers = _acct(store, "register", "r@example.de")
        for _ in range(PLANS["free"].validations_per_day + 3):
            assert client.post("/v1/spec/validate", json=VALIDATE,
                               headers=headers).status_code == 200

    def test_the_day_rolls_over_at_utc_midnight(self, client, store):
        seconds = int((utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
                       + timedelta(days=1) - utc_now()).total_seconds())
        for _ in range(PLANS["free"].validations_per_day):
            client.post("/v1/spec/validate", json=VALIDATE)
        over = client.post("/v1/spec/validate", json=VALIDATE)
        assert abs(int(over.headers["retry-after"]) - seconds) <= 5
