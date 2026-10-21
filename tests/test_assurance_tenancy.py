"""Tenant isolation: one customer's ledger is not another customer's ledger.

Before this, every account shared one evidence ledger, so any paying account
could list, read, export and write over every other account's Article 14 cases.
These tests pin the fix at the single choke point (``deps.get_register``) and
through the HTTP surface.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing.accounts import Account, Principal

from .test_assurance_check import advisory, manifest

OPERATOR_KEY = "operator-key-test-tenancy"
ACTOR = {"identifier": "m.braun", "role": "Entwicklungsleitung"}
SECRET = "Integrator A observed exploitation of the SK-4200 service port"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "shared" / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


@pytest.fixture()
def store(client):
    return deps.get_accounts()


def _account(store, tier="register", email="x@example.de"):
    account = store.upsert_account(
        email=email, tier=tier, stripe_customer_id=f"cus_{email}"
    )
    return account, {"X-API-Key": store.issue_key(account.id)}


def _signal(client, headers, case="CASE-1", description=SECRET):
    return client.post(
        f"/v1/cases/{case}/signal",
        headers=headers,
        json={
            "received_at": "2026-09-18T21:40:00Z",
            "channel": "customer_or_integrator",
            "description": description,
            "reference": "TICKET-1",
            "actor": ACTOR,
        },
    )


class TestTwoAccounts:
    def test_b_cannot_list_read_or_export_a_case_of_a(self, client, store):
        _, a = _account(store, email="a@example.de")
        _, b = _account(store, email="b@example.de")
        assert _signal(client, a).status_code == 201

        assert client.get("/v1/cases", headers=a).json() == ["CASE-1"]

        # B sees nothing: not in the listing, not by id, not in an export, not
        # in the readiness report or the breach list.
        assert client.get("/v1/cases", headers=b).json() == []
        assert client.get("/v1/cases/CASE-1", headers=b).status_code == 404
        exported = client.get("/v1/cases/CASE-1/export", headers=b)
        assert SECRET not in exported.text
        assert SECRET not in client.get("/v1/register", headers=b).text
        assert client.get("/v1/register/breaches", headers=b).json() == []

        # And A still has it, byte for byte.
        assert SECRET in client.get("/v1/cases/CASE-1/export", headers=a).text

    def test_b_can_use_the_same_case_id_without_colliding(self, client, store):
        _, a = _account(store, email="a@example.de")
        _, b = _account(store, email="b@example.de")
        ra = _signal(client, a, description="A's own description of the signal")
        rb = _signal(client, b, description="B's own description of the signal")
        assert ra.status_code == 201 and rb.status_code == 201
        # Each ledger started at its own sequence 1: they are separate chains.
        assert ra.json()["ledger_seq"] == 1
        assert rb.json()["ledger_seq"] == 1
        assert "A's own" in client.get("/v1/cases/CASE-1/export", headers=a).text
        assert "B's own" in client.get("/v1/cases/CASE-1/export", headers=b).text
        assert "A's own" not in client.get("/v1/cases/CASE-1/export", headers=b).text

    def test_each_ledger_verifies_independently_and_has_its_own_head(self, client, store):
        _, a = _account(store, email="a@example.de")
        _, b = _account(store, email="b@example.de")
        _signal(client, a)
        _signal(client, a, case="CASE-2")
        _signal(client, b, description="something else entirely")
        va = client.get("/v1/ledger/verify", headers=a).json()
        vb = client.get("/v1/ledger/verify", headers=b).json()
        assert va["verified"] is True and vb["verified"] is True
        assert va["attestation"]["head_link_hash"] != vb["attestation"]["head_link_hash"]
        assert va["attestation"]["length"] == 2
        assert vb["attestation"]["length"] == 1

    def test_each_account_gets_its_own_file_beside_the_operator_ledger(self, client, store, env):
        a_acc, a = _account(store, email="a@example.de")
        b_acc, b = _account(store, email="b@example.de")
        _signal(client, a)
        _signal(client, b)
        tenants = env / "shared" / "tenants"
        assert sorted(p.name for p in tenants.glob("*.db")) == sorted(
            [f"{a_acc.id}.db", f"{b_acc.id}.db"]
        )
        # The shared (operator) ledger was never written by an account.
        assert not (env / "shared" / "art14.db").exists() or len(
            deps.shared_register().ledger
        ) == 0

    def test_the_tenant_directory_can_be_configured(self, client, store, env, monkeypatch):
        elsewhere = env / "elsewhere"
        monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(elsewhere))
        acc, a = _account(store, email="a@example.de")
        assert _signal(client, a).status_code == 201
        assert (elsewhere / f"{acc.id}.db").exists()

    def test_machine_evidence_is_isolated_too(self, client, store):
        # The cell-plan routes (/v1/machinery, /v1/fleet, /v1/check, /v1/change)
        # reach the ledger through the same dependency.
        _, a = _account(store, tier="cell", email="a@example.de")
        _, b = _account(store, tier="cell", email="b@example.de")
        enrol = client.post("/v1/machinery/manifest", headers=a,
                            json={"manifest": manifest("0412").to_dict()})
        assert enrol.status_code == 200, enrol.text
        key = "Grimaldi/AR-7#0412"

        mine = client.post("/v1/check/fleet-machine", headers=a,
                           json={"machine_key": key, "advisory": advisory().to_dict()})
        theirs = client.post("/v1/check/fleet-machine", headers=b,
                             json={"machine_key": key, "advisory": advisory().to_dict()})
        assert mine.status_code == 200
        assert theirs.status_code == 404
        assert client.get("/v1/fleet/machines", headers=a).json()["summary"]["machines"] == 1
        assert client.get("/v1/fleet/machines", headers=b).json()["summary"]["machines"] == 0


class TestOperatorAndOpenMode:
    def test_the_operator_keeps_the_shared_ledger(self, client, store, env):
        op = {"X-API-Key": OPERATOR_KEY}
        _, a = _account(store, email="a@example.de")
        assert _signal(client, op, case="OP-1", description="operator-only text").status_code == 201
        assert client.get("/v1/cases", headers=op).json() == ["OP-1"]
        assert (env / "shared" / "art14.db").exists()
        # An account does not see the operator's cases, and the operator does
        # not see the account's: the shared ledger is the operator's own.
        assert client.get("/v1/cases", headers=a).json() == []
        _signal(client, a, case="ACC-1")
        assert client.get("/v1/cases", headers=op).json() == ["OP-1"]

    def test_open_mode_stays_on_the_shared_ledger(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "open.db"))
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
        monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
        monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
        monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
        deps._register_for.cache_clear()
        deps._tenant_register_for.cache_clear()
        deps._accounts_for.cache_clear()
        service = importlib.import_module("assurance.api.service")
        with TestClient(service.create_app()) as c:
            assert _signal(c, {}).status_code == 201
            assert c.get("/v1/cases").json() == ["CASE-1"]
        assert len(deps.shared_register().ledger) == 1
        assert not (tmp_path / "tenants").exists()


class TestAnonymous:
    def test_an_anonymous_caller_is_never_handed_a_ledger(self, env):
        anonymous = Principal(account=None, key_prefix="", anonymous_subject="ip:1.2.3.4")
        register = deps.get_register(anonymous)
        for attribute in ("ledger", "case_ids", "record_signal"):
            with pytest.raises(HTTPException) as caught:
                getattr(register, attribute)
            assert caught.value.status_code == 401
        # Nothing was created for it, anywhere.
        assert not (env / "shared").exists()
        assert not (env / "tenants").exists()

    def test_the_free_declaration_check_still_works_without_an_account(self, client):
        # It accepts anonymous callers AND asks for the register; it must keep
        # working for them without ever touching a ledger.
        from datetime import UTC, datetime

        from assurance.fleet.declaration import DeclarationOfConformity

        man = manifest()
        doc = DeclarationOfConformity.bind(
            man, doc_id="DOC-1", issued_by="Grimaldi",
            issued_at=datetime(2026, 1, 20, tzinfo=UTC),
            legislation=("Regulation (EU) 2023/1230",))
        r = client.post("/v1/fleet/declaration/check", json={
            "declaration": doc.to_dict(), "manifest": man.to_dict(),
            "with_coverage": True})
        assert r.status_code == 200
        assert r.json()["coverage_assessed"] is False


class TestPathSafety:
    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "operator",
            "../etc/passwd",
            "acc_../../../../x",
            "acc_0123456789abcde",       # too short
            "acc_0123456789abcdef0",     # too long
            "acc_0123456789abcdeg",      # not hex
            "ACC_0123456789abcdef",      # wrong case
            "acc_0123456789abcdef\n",
            "acc_0123456789abcdef/../acc_0123456789abcdef",
            "acc_0123456789abcdef.db",
            "/acc_0123456789abcdef",
            "acc_0123456789abcde\x00",
        ],
    )
    def test_traversal_shaped_ids_are_rejected(self, env, bad):
        with pytest.raises(ValueError):
            deps.tenant_ledger_path(bad)

    def test_a_good_id_maps_inside_the_tenant_directory(self, env):
        path = deps.tenant_ledger_path("acc_0123456789abcdef")
        assert path.parent == deps.tenant_ledgers_dir()
        assert path.name == "acc_0123456789abcdef.db"

    def test_a_corrupt_account_id_is_refused_not_given_a_shared_ledger(self, env):
        bad = Account(id="../../etc/x", email="", company="", tier="register", status="active")
        with pytest.raises(HTTPException) as caught:
            deps.get_register(Principal(account=bad, key_prefix="asr_x"))
        assert caught.value.status_code == 500
        assert not (env / "shared").exists()


class TestTheChokePoint:
    def test_nothing_but_deps_builds_a_ledger_for_a_request(self):
        """Every route must reach a ledger through get_register.

        A route that built its own register, or reached for the shared one,
        would bypass the tenant decision silently. Fail on the pattern, not on
        a list of routes that someone has to remember to extend.
        """
        api = Path(deps.__file__).parent
        offenders = []
        for source in sorted(api.glob("*.py")):
            if source.name == "deps.py":
                continue
            text = source.read_text()
            if re.search(r"\b_register_for\b|\b_tenant_register_for\b|EvidenceLedger\(", text):
                offenders.append(source.name)
            # shared_register() is allowed only in the unauthenticated /healthz.
            uses = len(re.findall(r"\bshared_register\b", text))
            if uses and not (source.name == "routes.py" and uses <= 2):
                offenders.append(f"{source.name}: shared_register")
        assert offenders == []

    def test_the_isolation_assertions_would_catch_a_shared_ledger(self, client, store, monkeypatch):
        """Mutation check, inside the suite: put the old behaviour back and the
        isolation property must fail. If this passes with isolation intact, the
        tests above are not testing isolation."""
        _, a = _account(store, email="a@example.de")
        _, b = _account(store, email="b@example.de")
        with monkeypatch.context() as patched:
            patched.setattr(deps, "_tenant_register_for", lambda _path: deps.shared_register())
            _signal(client, a)
            assert client.get("/v1/cases", headers=b).json() == ["CASE-1"]  # the leak

    def test_the_tenant_cache_is_large_enough_not_to_thrash(self):
        assert deps._tenant_register_for.cache_info().maxsize >= 128
