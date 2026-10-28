"""``python -m assurance.billing.issue_key``: the operator's way to re-issue a lost key.

The restore runbook says a customer whose checkout key was unclaimed at backup time must be
issued a new one. ``pending_keys`` is (rightly) never copied into a backup, and the session
marker that survives makes ``/v1/checkout/complete`` answer 202 for ever, so without this
command that customer is paid and locked out.
"""

from __future__ import annotations

import json
import logging
import shutil

import pytest
from fastapi.testclient import TestClient

from assurance.billing import issue_key as issue
from assurance.billing.accounts import AccountStore
from assurance.evidence import restore_check

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    checkout_event,
    send,
)


@pytest.fixture()
def store(billing_env):
    return AccountStore(billing_env / "accounts.db")


def _account(store, customer="cus_1", tier="cell", status="active"):
    return store.upsert_account(email="a@x.invalid", tier=tier, status=status,
                                stripe_customer_id=customer, stripe_subscription_id="sub_1")


def test_it_issues_a_working_key_to_stdout_only_and_exactly_once(store, capsys, caplog):
    acct = _account(store)
    with caplog.at_level(logging.DEBUG):
        code = issue.main(["--customer", "cus_1"])
    out, err = capsys.readouterr()
    key = out.strip()
    assert code == 0 and out == key + "\n" and key.startswith("asr_")
    assert key not in err and key not in caplog.text
    principal = store.resolve_key(key)
    assert principal is not None and principal.account.id == acct.id
    assert store.keys_for(acct.id)[-1]["label"].startswith("operator re-issue")


def test_by_account_id_and_as_json(store, capsys):
    acct = _account(store)
    assert issue.main(["--account", acct.id, "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["account_id"] == acct.id and store.resolve_key(body["api_key"]) is not None
    assert body["prefix"] == body["api_key"][:10]


@pytest.mark.parametrize("status,tier", [("cancelled", "free"), ("cancelled", "cell"),
                                         ("active", "free")])
def test_it_refuses_an_account_that_is_not_paying(store, capsys, status, tier):
    acct = _account(store, tier=tier, status=status)
    assert issue.main(["--customer", "cus_1"]) == 1
    out, err = capsys.readouterr()
    assert out == "" and "not entitled" in err
    assert store.keys_for(acct.id) == []


def test_past_due_still_pays_and_gets_a_key(store, capsys):
    _account(store, status="past_due")
    assert issue.main(["--customer", "cus_1"]) == 0


@pytest.mark.parametrize("argv", [["--customer", "cus_nope"], ["--account", "acc_nope"],
                                  ["--account", "operator"]])
def test_it_refuses_unknown_and_operator_accounts(store, capsys, argv):
    _account(store)
    assert issue.main(argv) == 1
    assert capsys.readouterr().out == ""


def test_it_refuses_an_account_with_no_stripe_customer(store, capsys):
    acct = store.upsert_account(email="m@x.invalid", tier="cell", status="active")
    assert issue.main(["--account", acct.id]) == 1
    assert "Stripe" in capsys.readouterr().err


def test_it_respects_the_active_key_limit(store, capsys):
    from assurance.billing.accounts import MAX_ACTIVE_KEYS

    acct = _account(store)
    for _ in range(MAX_ACTIVE_KEYS):
        store.issue_key(acct.id)
    assert issue.main(["--customer", "cus_1"]) == 1
    out, err = capsys.readouterr()
    assert out == "" and "key" in err


def test_a_missing_store_is_exit_2_and_creates_nothing(billing_env, capsys, monkeypatch):
    missing = billing_env / "typo.db"
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(missing))
    assert issue.main(["--customer", "cus_1"]) == 2
    assert not missing.exists() and capsys.readouterr().out == ""


def test_a_customer_with_an_unclaimed_key_at_backup_time_can_be_let_back_in(
        billing_client, billing_env, tmp_path, capsys, monkeypatch):
    """The runbook's restore story, end to end through the real backup and the real API."""
    c = billing_client
    assert send(c, checkout_event("cs_lost", "cus_1", "sub_1", "cell", T)).status_code == 200
    # the customer never collected the key; the backup leaves pending_keys out
    restore_check.backup(billing_env, tmp_path / "bk")
    restored = tmp_path / "restored"
    shutil.copytree(tmp_path / "bk", restored)
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(restored / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(restored / "tenants"))
    monkeypatch.setenv("ASSURANCE_LEDGER", str(restored / "art14.db"))
    from assurance.api import deps, service

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    with TestClient(service.create_app()) as client:
        # the stuck state the runbook describes
        assert client.get("/v1/checkout/complete", params={"session_id": "cs_lost"}
                          ).status_code == 202
        assert send(client, checkout_event("cs_lost", "cus_1", "sub_1", "cell", T)
                    ).json()["result"] == "duplicate"
        assert issue.main(["--customer", "cus_1"]) == 0
        key = capsys.readouterr().out.strip()
        assert client.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 200
