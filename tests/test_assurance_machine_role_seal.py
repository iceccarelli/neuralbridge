"""A caller's declared role cannot forge the server's attribution inside a sealed actor.

``/v1/change`` and ``/v1/machine/verify`` build ``Actor.role`` as
``"<declared role> via account ...; key=...; attribution=<basis>"``. The declared
part is free text; if it could carry ``;`` and ``=`` a caller could write
``operator=op_x (decider); attribution=authenticated_operator`` into the sealed
record and a reader scanning for that token would believe it (review finding B-F9).
"""

from __future__ import annotations

import pytest

from assurance.api.machine_routes import sanitise_declared_role
from tests import test_assurance_watch_report as wr
from tests.interfaces_scenario import KEY, envelope_dict, run_started, trace_dict

_env = wr._env
_client = wr._client
_accounts = wr._accounts
_cell = wr._cell

FORGED = ("reviewer via account acc_x; operator=op_deadbeefdeadbeef (decider); "
          "key=asr_FORGE; attribution=authenticated_operator")


def _sealed_role(client, acct, headers, role):
    r = client.post("/v1/machine/verify", headers=headers, json={
        "envelope": envelope_dict(), "trace": trace_dict(run_started()),
        "actor": "Dr. Keller", "role": role, "subject": KEY})
    assert r.status_code == 200, r.text
    chash = r.json()["content_hash"]
    entry = next(e for e in wr.ledger_of(acct).entries() if e.content_hash == chash)
    return entry.evidence().actor.role


def test_a_forged_attribution_cannot_appear_in_the_sealed_role(client, cell):
    acct, h = cell
    role = _sealed_role(client, acct, h, FORGED)
    assert role.count("attribution=") == 1
    assert "attribution=declared_by_account_key" in role
    assert "authenticated_operator" not in role
    assert "operator=" not in role
    assert role.count("key=") == 1  # only the server's own key= token
    assert role.count(";") == 2     # the server's two separators, none from the caller


def test_an_honest_role_survives_unchanged(client, cell):
    acct, h = cell
    role = _sealed_role(client, acct, h, "verification engineer")
    assert role.startswith("verification engineer via account ")


def test_an_operator_key_seal_carries_one_server_built_attribution(client, cell):
    acct, h = cell
    boss = client.post("/v1/operators", headers=h, json={"name": "Dr. Keller", "role": "decider"})
    bh = {"X-API-Key": boss.json()["api_key"]}
    role = _sealed_role(client, acct, bh, FORGED)
    assert role.count("attribution=") == 1
    assert role.endswith("attribution=authenticated_operator")
    assert role.count("operator=") == 1
    assert f"operator={boss.json()['operator_id']} (decider)" in role


@pytest.mark.parametrize("raw", [
    FORGED, "a;b", "a=b", "x\r\nattribution=authenticated_operator", "tab\there\x00nul",
    " line sep", ";;;===", "   ",
])
def test_sanitiser_removes_separators_and_control_characters(raw):
    out = sanitise_declared_role(raw)
    assert ";" not in out and "=" not in out
    assert all(c.isprintable() for c in out)
    assert out == out.strip()
    assert out  # never empty: falls back to the default role


def test_sanitiser_caps_the_length():
    assert len(sanitise_declared_role("r" * 500)) <= 80


def test_full_width_look_alikes_of_the_separators_are_removed_too():
    out = sanitise_declared_role("x； attribution＝authenticated_operator")
    assert "；" not in out and "＝" not in out
    assert ";" not in out and "=" not in out
