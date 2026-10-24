"""Round-3 M3: no API route seals a caller's words as if the server had written them.

The first fix (``attribution=`` forgery) covered ``/v1/machine/verify`` only.
``/v1/machinery/{manifest,intervention,passport}`` and the Article 14 register routes sealed
the caller's ``role`` verbatim, so ``reviewer via account acc_x; operator=op_...(decider);
key=asr_FORGE; attribution=authenticated_operator`` went into the ledger as typed.

These tests drive every route that builds an ``Actor`` from caller text, with that string as
the role, and read the sealed record back from the account's own ledger. The static test at
the end fails when a new ``Actor(role=<caller text>)`` appears in ``src/assurance/api``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import assurance.api as api_package
from assurance.api import change_routes, declared_actor, machine_routes
from assurance.billing.accounts import Principal
from tests import test_assurance_watch_report as wr
from tests.interfaces_scenario import KEY, envelope_dict, run_started, trace_dict

_env = wr._env
_client = wr._client
_accounts = wr._accounts
_cell = wr._cell

FORGED = ("reviewer via account acc_x; operator=op_deadbeefdeadbeef (decider); "
          "key=asr_FORGE; attribution=authenticated_operator")
NAME = "Dr. Keller"
AWARE = "2026-09-19T06:30:00Z"
ACTOR = {"identifier": NAME, "role": FORGED}


def _roles(acct):
    return {e.seq: e.evidence().actor.role for e in wr.ledger_of(acct).entries()}


def assert_no_forged_token(role: str, *, server_tokens_allowed: bool):
    # Words the caller typed may remain as words; what cannot remain is the grammar: a
    # `token=value` pair or a `;` separator that a reader would take for the server's.
    # The test key is an account-level key, so no operator attribution is ever genuine.
    for forged in ("key=asr_FORGE", "operator=op_deadbeef", "authenticated_operator",
                   "via account acc_x;"):
        assert forged not in role, role
    if server_tokens_allowed:
        assert role.count("attribution=") == 1 and role.count("key=") == 1, role
        assert role.count(";") == 2, role                 # the server's two separators
        assert "operator=" not in role, role
    else:
        # The route builds no attribution of its own: the declared role has no grammar at all.
        assert ";" not in role and "=" not in role, role


# -- how to drive each route -------------------------------------------------------------
def _machine_verify(client, h, tmp_path):
    return client.post("/v1/machine/verify", headers=h, json={
        "envelope": envelope_dict(), "trace": trace_dict(run_started()),
        "actor": NAME, "role": FORGED, "subject": KEY})


def _machinery_manifest(client, h, tmp_path):
    return client.post("/v1/machinery/manifest", headers=h, json={
        "manifest": wr.make_manifest(tmp_path), "actor": NAME, "role": FORGED})


def _machinery_intervention(client, h, tmp_path):
    from tests.test_assurance_machinery import intervention

    return client.post("/v1/machinery/intervention", headers=h, json={
        "intervention": intervention().to_dict(), "actor": NAME, "role": FORGED})


def _machinery_passport(client, h, tmp_path):
    return client.post("/v1/machinery/passport", headers=h, json={
        "manifest": wr.make_manifest(tmp_path), "actor": NAME, "role": FORGED})


def _art14(path, body):
    def go(client, h, tmp_path):
        return client.post(path, headers=h, json=body)
    return go


_SIGNAL = {"received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
           "description": "Integrator observed exploitation", "reference": "T-1", "actor": ACTOR}
_AWARENESS = {"established_at": AWARE, "assessment_started_at": "2026-09-18T22:05:00Z",
              "assessment_completed_at": AWARE, "track": "actively_exploited_vulnerability",
              "reasoning": "SIEM export shows a shell spawned", "actor": ACTOR}
_TRIAGE = {"answers": {
    "is_our_product_with_digital_elements_on_the_eu_market": "yes",
    "reliable_evidence_of_malicious_exploitation": "yes",
    "exploited_in_our_product_not_merely_in_a_component": "yes",
    "awareness_of_active_exploitation_on_or_after_2026_09_11": "yes"}, "actor": ACTOR}
_AVAILABILITY = {"product_name": "SK-4200", "member_states": ["DE"], "actor": ACTOR}
_MEASURE = {"available_at": "2026-09-30T16:00:00Z", "description": "workaround", "actor": ACTOR}
_FILING = {"stage": "notification", "submitted_at": "2026-09-21T09:00:00Z",
           "payload": {"notification_type": "Vulnerability", "title": "t", "summary": "s",
                       "product_name": "p", "product_version": "v",
                       "member_states_available": ["DE"], "awareness_datetime": AWARE},
           "actor": ACTOR}
_USER_NOTICE = {"at": "2026-09-21T10:00:00Z", "scope": "all users", "content": "Apply the fix",
                "actor": ACTOR}

#: (id, driver, does the route add its own server attribution to the role?)
ROUTES = [
    ("machine/verify", _machine_verify, True),
    ("machinery/manifest", _machinery_manifest, False),
    ("machinery/intervention", _machinery_intervention, False),
    ("machinery/passport", _machinery_passport, False),
    ("cases/signal", _art14("/v1/cases/C1/signal", _SIGNAL), False),
]
#: These need the signal (and awareness) before them; they run after the two above.
ART14_CHAIN = [
    ("cases/awareness", "/v1/cases/C1/awareness", _AWARENESS),
    ("cases/triage", "/v1/cases/C1/triage", _TRIAGE),
    ("cases/availability", "/v1/cases/C1/availability", _AVAILABILITY),
    ("cases/measure", "/v1/cases/C1/measure", _MEASURE),
    ("cases/filings", "/v1/cases/C1/filings", _FILING),
    ("cases/user-notification", "/v1/cases/C1/user-notification", _USER_NOTICE),
]


@pytest.mark.parametrize("name,driver,server_tokens", ROUTES, ids=[r[0] for r in ROUTES])
def test_a_forged_role_is_not_sealed_verbatim(client, cell, tmp_path, name, driver, server_tokens):
    acct, h = cell
    before = _roles(acct)
    r = driver(client, h, tmp_path)
    assert r.status_code in (200, 201), (name, r.text[:300])
    new = {s: role for s, role in _roles(acct).items() if s not in before}
    assert new, f"{name} sealed nothing"
    for role in new.values():
        assert_no_forged_token(role, server_tokens_allowed=server_tokens)


def test_every_art14_recording_route_seals_a_clean_role(client, cell, tmp_path):
    acct, h = cell
    assert client.post("/v1/cases/C1/signal", headers=h, json=_SIGNAL).status_code == 201
    for name, path, body in ART14_CHAIN:
        before = _roles(acct)
        r = client.post(path, headers=h, json=body)
        assert r.status_code == 201, (name, r.text[:300])
        new = {s: role for s, role in _roles(acct).items() if s not in before}
        assert new, f"{name} sealed nothing"
        for role in new.values():
            assert_no_forged_token(role, server_tokens_allowed=False)


def test_an_honest_declared_role_survives_on_the_routes_that_keep_it(client, cell, tmp_path):
    acct, h = cell
    r = client.post("/v1/machinery/manifest", headers=h, json={
        "manifest": wr.make_manifest(tmp_path), "actor": NAME, "role": "Head of Engineering"})
    assert r.status_code == 200
    assert list(_roles(acct).values())[-1] == "Head of Engineering"
    r = client.post("/v1/cases/C9/signal", headers=h, json={
        **_SIGNAL, "actor": {"identifier": NAME, "role": "Entwicklungsleitung"}})
    assert r.status_code == 201
    assert list(_roles(acct).values())[-1] == "Entwicklungsleitung"


def test_an_empty_role_stays_empty_on_the_register_and_does_not_become_a_verification_engineer(
        client, cell):
    acct, h = cell
    r = client.post("/v1/cases/C9/signal", headers=h, json={
        **_SIGNAL, "actor": {"identifier": NAME}})
    assert r.status_code == 201
    assert list(_roles(acct).values())[-1] == ""


def test_the_machinery_default_is_an_empty_role_too(client, cell, tmp_path):
    acct, h = cell
    r = client.post("/v1/machinery/manifest", headers=h, json={
        "manifest": wr.make_manifest(tmp_path), "actor": NAME})
    assert r.status_code == 200
    assert list(_roles(acct).values())[-1] == ""


# -- the change routes: the shared builder sanitises the role it is handed ----------------
@pytest.mark.parametrize("principal", [
    Principal(account=None, key_prefix="open-mode"),
    Principal(account=None, key_prefix="asr_abc12345"),
    Principal(account=None, key_prefix="asr_abc12345", operator_id="op_1234567890abcdef",
              operator_name=NAME, operator_role="decider"),
], ids=["open-mode", "account-key", "operator-key"])
def test_the_change_actor_builder_removes_the_server_grammar_from_a_role_it_is_given(principal):
    actor = change_routes._actor(NAME, FORGED, principal, named=True)
    assert actor.role.count("attribution=") == 1
    assert "key=asr_FORGE" not in actor.role and "operator=op_deadbeef" not in actor.role
    assert actor.role.count("key=") == 1 and actor.role.count(";") == (3 if principal.operator_id else 2)
    if principal.operator_id:
        assert actor.role.count("operator=") == 1
    else:
        assert "operator=" not in actor.role and "authenticated_operator" not in actor.role


# -- one definition ----------------------------------------------------------------------
def test_machine_routes_still_exports_the_sanitiser_for_the_branch_that_imports_it_there():
    assert machine_routes.sanitise_declared_role is declared_actor.sanitise_declared_role
    assert machine_routes.DEFAULT_ROLE == declared_actor.DEFAULT_ROLE


def test_the_default_is_the_routes_constant_not_caller_text():
    assert declared_actor.sanitise_declared_role(";;;", default="") == ""
    assert declared_actor.sanitise_declared_role(";;;") == declared_actor.DEFAULT_ROLE
    assert declared_actor.sanitise_declared_role("a;b=c", default="") == "a b c"


# -- a route added tomorrow cannot quietly seal caller text -------------------------------
def _actor_calls():
    root = Path(api_package.__file__).parent
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Actor":
                yield path.name, node


def _is_safe_role(value: ast.expr) -> bool:
    if isinstance(value, ast.Constant):
        return True                                   # the route's own words
    if isinstance(value, ast.JoinedStr):
        return True                                   # server-built; its pieces are checked below
    if isinstance(value, ast.Call):
        return getattr(value.func, "id", getattr(value.func, "attr", "")) == "sanitise_declared_role"
    return False


def test_no_api_module_builds_an_actor_whose_role_is_unsanitised_caller_text():
    offenders = []
    for module, call in _actor_calls():
        role = next((k.value for k in call.keywords if k.arg == "role"), None)
        if role is not None and not _is_safe_role(role):
            offenders.append(f"{module}:{call.lineno}")
    assert not offenders, (
        "an Actor in the API takes its role from a caller without "
        f"sanitise_declared_role: {offenders}")


def test_the_one_f_string_builder_sanitises_its_role_parameter():
    source = Path(change_routes.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_actor")
    assigns = [n for n in ast.walk(func) if isinstance(n, ast.Assign)
               and any(getattr(t, "id", "") == "role" for t in n.targets)]
    assert any(isinstance(a.value, ast.Call)
               and getattr(a.value.func, "id", "") == "sanitise_declared_role" for a in assigns)
