"""POST /v1/change/assess/advisory/intel: a named person opens a case from a public-intel finding.

The hosted twin of ``assurance watch open-case``. The intel store is the operator's shared PUBLIC
data, built from the contract fixtures in ``tests/fixtures/intel`` (``tests/intel_support.py``);
nothing here is live integration and no network is opened. The account's fleet is one machine
sealed through the real API whose manifest labels match the synthetic NVD candidate
(``nvd:CVE-2026-0001``) and the synthetic CSAF candidate (``EX-2026-001``).

Pinned: only a named person opens a case; a CSAF-derived (unsigned import) candidate also needs
the override, a reason and an operator key with the ``decider`` role; a case from this route is
``unauthenticated_public_source`` / inspect-only; nothing is opened for an unknown id, for an
advisory touching nothing in the caller's fleet, or for an empty fleet; a missing or unreadable
store is 503; re-calling is idempotent, a second person does not re-attribute, a settled case is
not reopened; tenants are isolated; 401/402; the CLI and the API make the same case.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any

import pytest

from assurance.change.store import CaseStore
from assurance.watch.config import IntelSubscription
from assurance.watch.open_case import open_case

from . import interfaces_fixtures as fx
from .interfaces_scenario import KEY, PERSON
from .test_assurance_intel_api import STORE_ENV, build_store
from .test_golden_path_advisory_to_passport_e2e import (
    World,
    sealed_manifest,  # noqa: F401  (fixture)
)

live_api = fx.live_api

PATH = "/v1/change/assess/advisory/intel"
NVD_ID, CSAF_ID = "nvd:CVE-2026-0001", "EX-2026-001"
ROLE = "safety engineer"


def matching(manifest: dict[str, Any]) -> dict[str, Any]:
    """The sealed machine, with two items labelled the way the NVD and CSAF fixtures name them."""
    m = copy.deepcopy(manifest)
    for item in m["items"]:
        if item["item_id"] == "ITM-PARAMS":
            item.update(supplier="example_controls", name="ex-100_firmware", version="v2.001")
        if item["item_id"] == "ITM-ZONES":
            item.update(supplier="Example Controls GmbH", name="EX-100", version="V2.001")
    return m


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    path = tmp_path / "intel.db"
    build_store(path)
    monkeypatch.setenv(STORE_ENV, str(path))
    return path


@pytest.fixture
def world(live_api, sealed_manifest, tmp_path, store_path):  # noqa: F811
    w = World(live_api, matching(sealed_manifest), tmp_path)
    try:
        yield w
    finally:
        w.http.close()


def intel(w: World, advisory_id: str = NVD_ID, *, actor: str | None = PERSON, role: str = ROLE,
          headers=None, **extra: Any):
    body: dict[str, Any] = {"advisory_id": advisory_id, "role": role, **extra}
    if actor is not None:
        body["actor"] = actor
    return w.call("POST", PATH, headers, body)


def cases(w: World) -> list:
    return w.ok("GET", "/v1/change/cases")["cases"]


def _detail(r) -> str:
    return str(r.json().get("detail"))


def _entries(w: World) -> int:
    return len(w.live.tenant_ledger(w.account_id).entries())


# --------------------------------------------------------------------------- opening
def test_a_named_person_opens_an_nvd_derived_case(world):
    w = world
    w.seal_manifest()
    r = intel(w)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["opened"] and out["outcome"] == "opened"
    case = out["case"]
    assert case["status"] == "open" and case["machines"] == [KEY]
    prov = case["provenance"]
    assert prov["advisory_trust"] == "unauthenticated_public_source"
    assert prov["advisory_accepted_by"] == PERSON
    assert prov["advisory_accepted_basis"] == "declared_by_account_key"
    assert out["advisory_trust"]["trust_basis"] == "none"
    assert out["advisory_trust"]["trust_state"] == "unauthenticated_public_source"
    assert out["advisory_trust"]["inspect_only"] is True
    assert out["advisory_trust"]["automated_consequences_permitted"] is False
    cite = out["intel"]["citation"]
    assert cite["observation_seq"] and cite["source"] == "nvd_cve_api"
    assert len(cite["sha256"]) == 64 and cite["retrieved_at"]
    assert any("genuine" in s for s in out["not_established"])
    # opening decided nothing: nothing is resolved, every re-verification is outstanding
    assert case["resolved_decisions"] == [] and case["required_reverifications"]
    assert [c["case_id"] for c in cases(w)] == [case["case_id"]]
    assert w.case(case["case_id"])["status"] == "open"


@pytest.mark.parametrize("name", ["automation", "watch", "System", "bot", "service", "ai"])
def test_an_automation_name_is_refused(world, name):
    w = world
    w.seal_manifest()
    r = intel(w, actor=name)
    assert r.status_code == 409 and "named person" in _detail(r)
    assert cases(w) == []


def test_an_empty_or_missing_name_is_refused(world):
    w = world
    w.seal_manifest()
    for actor in ("", "   ", None):
        r = intel(w, actor=actor)
        assert r.status_code == 409 and "named person" in _detail(r)
    assert cases(w) == []


@pytest.mark.parametrize("role", ["", "   ", "x; attribution=authenticated_operator",
                                  "operator=op_1 (decider)", "a=b", "a;b"])
def test_an_empty_or_forged_role_is_refused(world, role):
    w = world
    w.seal_manifest()
    r = intel(w, role=role)
    assert r.status_code in (409, 422), r.text
    assert cases(w) == []


def test_extra_fields_and_other_sources_are_refused(world):
    world.seal_manifest()
    assert intel(world, kind="person").status_code == 422
    assert intel(world, sources=["kev"]).status_code == 422


# --------------------------------------------------------------------------- CSAF override
def test_a_csaf_candidate_needs_the_override_a_reason_and_a_decider(world):
    w = world
    w.seal_manifest()
    r = intel(w, CSAF_ID)                                       # no override
    assert r.status_code == 409 and "unsigned" in _detail(r)
    r = intel(w, CSAF_ID, accept_unsigned=True, reason="read against the publisher page")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "operator_required"
    r = intel(w, CSAF_ID, headers=w.decider, accept_unsigned=True)          # no reason
    assert r.status_code == 409 and "reason" in _detail(r)
    assert cases(w) == []
    r = intel(w, CSAF_ID, headers=w.decider, accept_unsigned=True,
              reason="read against the publisher's advisory page")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["opened"] and out["advisory_import"] is not None
    prov = out["case"]["provenance"]
    assert prov["advisory_accepted_by"] == PERSON
    assert prov["advisory_accepted_basis"] == "authenticated_operator"
    assert prov["advisory_accept_reason"]


def test_an_operator_key_cannot_open_as_someone_else(world):
    w = world
    w.seal_manifest()
    r = intel(w, CSAF_ID, actor="Someone Else", headers=w.decider, accept_unsigned=True,
              reason="r")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "actor_mismatch"
    assert cases(w) == []


def test_a_contributor_operator_cannot_override(world, live_api):
    w = world
    w.seal_manifest()
    _, key = live_api.accounts.create_operator(w.account_id, "Contrib", "contributor")
    r = intel(w, CSAF_ID, actor="Contrib", headers={"X-API-Key": key}, accept_unsigned=True,
              reason="r")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "decider_role_required"
    assert cases(w) == []


# --------------------------------------------------------------------------- refusals
def test_an_unknown_advisory_id_is_404(world):
    w = world
    w.seal_manifest()
    r = intel(w, "nvd:CVE-1999-0001")
    assert r.status_code == 404 and r.json()["detail"]["error"] == "advisory_not_found"
    assert cases(w) == []


def test_an_advisory_matching_nothing_in_the_fleet_opens_nothing(
        world, sealed_manifest):  # noqa: F811
    w = world
    w.seal_manifest(sealed_manifest)            # labels that match neither candidate
    r = intel(w)
    assert r.status_code == 409 and "matches no machine" in _detail(r)
    assert cases(w) == []


def test_an_empty_fleet_is_nothing_assessed_not_clear(world):
    w = world
    r = intel(w)
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "nothing_assessed"
    assert cases(w) == []


def test_the_sources_filter_limits_where_a_candidate_is_found(world):
    w = world
    w.seal_manifest()
    assert intel(w, NVD_ID, sources=["csaf"]).status_code == 404
    assert intel(w, NVD_ID, sources=["nvd"]).status_code == 200


# --------------------------------------------------------------------------- the store
def test_an_unconfigured_store_is_503(world, monkeypatch):
    world.seal_manifest()
    monkeypatch.delenv(STORE_ENV)
    r = intel(world)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "no_intel_store_configured"
    assert cases(world) == []


def test_an_unreadable_store_is_503(world, tmp_path, monkeypatch):
    world.seal_manifest()
    bad = tmp_path / "not-a-store.db"
    bad.write_bytes(b"this is not sqlite")
    monkeypatch.setenv(STORE_ENV, str(bad))
    r = intel(world)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "intel_store_unreadable"
    monkeypatch.setenv(STORE_ENV, str(tmp_path / "missing.db"))
    r = intel(world)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "intel_store_unreadable"
    assert cases(world) == []


def test_the_store_file_is_not_written(world, store_path):
    world.seal_manifest()
    before = store_path.read_bytes()
    assert intel(world).status_code == 200
    assert store_path.read_bytes() == before


# --------------------------------------------------------------------------- idempotence
def test_a_second_call_returns_the_open_case_untouched(world):
    w = world
    w.seal_manifest()
    first = intel(w).json()
    n = _entries(w)
    again = intel(w)
    assert again.status_code == 200
    out = again.json()
    assert out["opened"] is False and out["outcome"] == "already_open"
    assert out["case"] == first["case"]
    assert _entries(w) == n and len(cases(w)) == 1


def test_a_different_second_person_does_not_re_attribute(world):
    w = world
    w.seal_manifest()
    cid = intel(w).json()["case"]["case_id"]
    n = _entries(w)
    out = intel(w, actor="Other Person").json()
    assert out["outcome"] == "already_open"
    assert out["case"]["provenance"]["advisory_accepted_by"] == PERSON
    assert out["case"]["case_id"] == cid
    assert _entries(w) == n


def test_a_settled_case_is_never_reopened(world):
    w = world
    w.seal_manifest()
    cid = intel(w).json()["case"]["case_id"]
    w.ok("POST", f"/v1/change/cases/{cid}/decision", w.decider,
         {"disposition": "rejected", "reason": "not applicable to this cell"})
    n = _entries(w)
    for who in (PERSON, "Other Person"):
        r = intel(w, actor=who)
        assert r.status_code == 409 and "does not reopen" in _detail(r)
    assert _entries(w) == n


# --------------------------------------------------------------------------- tenants and gate
def test_tenants_are_isolated(world, live_api):
    w = world
    w.seal_manifest()
    _, b_key = live_api.account("b@tenant.example")
    body = {"advisory_id": NVD_ID, "role": ROLE, "actor": PERSON}
    r = w.call("POST", PATH, b_key, body)           # B has no fleet: nothing assessed
    assert r.status_code == 409 and r.json()["detail"]["error"] == "nothing_assessed"
    cid = intel(w).json()["case"]["case_id"]
    assert w.call("GET", "/v1/change/cases", b_key).json()["cases"] == []
    assert w.call("GET", f"/v1/change/cases/{cid}", b_key).status_code == 404
    assert [c["case_id"] for c in cases(w)] == [cid]


def test_no_key_is_401_and_an_unentitled_key_is_402(world, live_api):
    w = world
    body = {"advisory_id": NVD_ID, "role": ROLE, "actor": PERSON}
    assert w.http.post(PATH, json=body).status_code == 401
    assert w.http.post(PATH, json=body, headers={"X-API-Key": "nb_bogus"}).status_code == 401
    _, free = live_api.account("free@tenant.example", "register")
    assert w.call("POST", PATH, free, body).status_code == 402


def test_no_mcp_tool_opens_a_case_from_intel():
    from assurance import capabilities as cat

    owner = [c for c in cat.CAPABILITIES if any("assess/advisory/intel" in a for a in c.api)]
    assert owner and all(not c.mcp and c.gaps["mcp"][0] == "by_design" for c in owner)


# --------------------------------------------------------------------------- CLI parity
def test_the_cli_and_the_api_open_the_same_case(world, live_api, store_path):
    w = world
    w.seal_manifest()
    api_case = intel(w).json()["case"]
    # the same machine, sealed in a second account's ledger, then the CLI's own function on it
    b_id, b_key = live_api.account("cli@tenant.example")
    w.ok("POST", "/v1/machinery/manifest", b_key,
         {"manifest": w.manifest, "actor": "m.keller"})
    ledger = live_api.tenant_ledger(b_id)
    config = SimpleNamespace(intel=(IntelSubscription(store=str(store_path),
                                                      sources=("nvd", "csaf")),))
    res = open_case(config, ledger, NVD_ID, actor_name=PERSON, role=ROLE)
    cli_case = CaseStore(ledger).get(res.case_id).to_dict()
    compared = 0
    for field in ("case_id", "trigger", "status", "machines", "affected_functions",
                  "required_reverifications", "evidence_before", "human_decisions",
                  "required_actions", "resolved_decisions"):
        if field in api_case or field in cli_case:
            assert api_case.get(field) == cli_case.get(field), field
            compared += 1
    assert compared >= 5
    for k in ("advisory_trust", "advisory_origin", "advisory_issuer", "advisory_accepted_by"):
        assert api_case["provenance"][k] == cli_case["provenance"][k], k
    assert cli_case["provenance"]["advisory_trust"] == "unauthenticated_public_source"
