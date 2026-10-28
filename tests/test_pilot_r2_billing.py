# ruff: noqa: F811  (the fixtures are imported from test_pilot_manual_grant and used by name)
"""Round 2: the operator path for a manual pilot, against what a customer or a typo can do.

* ``--store`` pointing at a ledger or any other SQLite file wrote the account schema into it.
* the operator could not end a grant at once: revoke was by prefix, ``list`` showed no prefixes,
  a customer can mint their own keys, and ``extend`` refuses past dates.
* a pilot told to ``POST /v1/checkout`` got a 409 whose remedy (the portal) is a 404 for it.
* ``grant`` could mint a key and fail to deliver it, silently.
* small hardening: unicode e-mail duplicates, e-mail and expiry validation at the store layer
  (a value that cannot be read ends the grant), ``extend`` removing the expiry on an empty
  string, and four mutants the first pass did not kill.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.billing import accounts as accounts_module
from assurance.billing.accounts import AccountStore, ManualGrantError
from assurance.cli import main as assurance_main
from assurance.core.identity import utc_now
from assurance.evidence.ledger import EvidenceLedger

from .test_pilot_manual_grant import (  # noqa: F401  (fixtures)
    CELL_ROUTE,
    app_env,
    client,
    grant,
    granted,
    headers,
    store_path,
)

ROOT = Path(__file__).resolve().parent.parent


def _cli(*argv):
    return assurance_main(["billing", *map(str, argv)])


def _tables(path) -> list[str]:
    db = sqlite3.connect(path)
    try:
        return sorted(r[0] for r in db.execute("select name from sqlite_master where type='table'"))
    finally:
        db.close()


def _digest(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _child_env():
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    env.pop("PYTHONUNBUFFERED", None)
    return env


# =====================================================================
class TestAStoreThatIsNotAnAccountStoreIsNeverWrittenTo:
    @pytest.mark.parametrize("verb", [
        ["list"], ["grant", "--email", "a@b.example", "--tier", "cell"],
        ["grant", "--create", "--email", "a@b.example", "--tier", "cell"],
        ["issue-key", "--account", "acc_x"], ["extend", "--account", "acc_x",
                                              "--expires-on", "2999-01-01"],
        ["end", "--account", "acc_x"], ["revoke-key", "--account", "acc_x", "--prefix", "asr_000000"]])
    def test_a_ledger_file_is_refused_and_left_byte_for_byte(self, tmp_path, capsys, verb):
        ledger = tmp_path / "evidence.db"
        EvidenceLedger(ledger)
        before_tables, before = _tables(ledger), _digest(ledger)
        capsys.readouterr()
        rc = _cli(*verb, "--store", ledger)
        err = capsys.readouterr().err
        assert rc == 2 and "hash chain" in err
        assert _tables(ledger) == before_tables and _digest(ledger) == before

    def test_a_ledger_that_already_carries_account_tables_is_still_a_ledger(
            self, tmp_path, capsys):
        """The damage this guards against has been done once: the schema is in the file."""
        damaged = tmp_path / "damaged.db"
        EvidenceLedger(damaged)
        AccountStore(damaged)                       # what the first pass's tool would have done
        before = _digest(damaged)
        assert _cli("list", "--store", damaged) == 2
        assert _cli("grant", "--store", damaged, "--email", "a@b.example", "--tier", "cell") == 2
        assert "hash chain" in capsys.readouterr().err
        assert _digest(damaged) == before

    def test_list_does_not_migrate_an_older_store(self, tmp_path, capsys):
        path = tmp_path / "old.db"
        AccountStore(path).upsert_account(email="l@x.example", tier="cell",
                                          stripe_customer_id="cus_old")
        db = sqlite3.connect(path)
        db.execute("alter table accounts drop column source")
        db.commit()
        db.close()
        before = _digest(path)
        assert _cli("list", "--store", path, "--json") == 0
        assert "source" not in [r[1] for r in sqlite3.connect(path).execute(
            "pragma table_info(accounts)")]
        assert _digest(path) == before

    def test_any_other_sqlite_file_is_refused_too(self, tmp_path, capsys):
        other = tmp_path / "other.db"
        db = sqlite3.connect(other)
        db.execute("create table something (x)")
        db.commit()
        db.close()
        before = _digest(other)
        assert _cli("list", "--store", other) == 2
        assert _cli("grant", "--store", other, "--create", "--email", "a@b.example",
                    "--tier", "cell") == 2
        assert _digest(other) == before
        assert "account store" in capsys.readouterr().err

    def test_a_file_that_is_not_sqlite_is_refused(self, tmp_path, capsys):
        text = tmp_path / "notes.txt"
        text.write_text("hello")
        assert _cli("list", "--store", text) == 2
        assert text.read_text() == "hello"

    def test_list_does_not_write_to_a_real_store(self, tmp_path, capsys, store_path):
        granted(capsys, store_path)
        before = _digest(store_path)
        assert _cli("list", "--store", store_path) == 0
        assert _cli("list", "--store", store_path, "--json") == 0
        assert _digest(store_path) == before

    def test_an_empty_file_needs_create_and_then_works(self, tmp_path, capsys):
        empty = tmp_path / "empty.db"
        empty.write_bytes(b"")
        rc, cap = grant(capsys, empty)
        assert rc == 2 and "--create" in cap.err
        assert granted(capsys, empty, "--create")["account_id"]


# =====================================================================
class TestTheOperatorCanEndAGrantAtOnce:
    def _minted(self, capsys, store_path):
        out = granted(capsys, store_path)
        customer_key = AccountStore(store_path).issue_key(out["account_id"], label="customer")
        return out, customer_key

    def test_list_shows_every_key_prefix_including_the_customers(self, capsys, store_path):
        out, customer_key = self._minted(capsys, store_path)
        capsys.readouterr()
        assert _cli("list", "--store", store_path, "--json") == 0
        (row,) = [a for a in json.loads(capsys.readouterr().out)["accounts"]
                  if a["id"] == out["account_id"]]
        prefixes = {k["prefix"] for k in row["keys"] if not k["revoked"]}
        assert prefixes == {out["api_key"][:10], customer_key[:10]}
        assert "api_key" not in json.dumps(row)
        assert _cli("list", "--store", store_path) == 0
        text = capsys.readouterr().out
        assert out["api_key"][:10] in text and customer_key[:10] in text
        assert out["api_key"] not in text

    def test_end_revokes_every_key_and_the_entitlement_at_once(
            self, capsys, store_path, client):
        out, customer_key = self._minted(capsys, store_path)
        assert client.get(CELL_ROUTE, headers=headers(customer_key)).status_code == 200
        capsys.readouterr()
        assert _cli("end", "--store", store_path, "--account", out["account_id"],
                    "--reason", "pilot over", "--json") == 0
        body = json.loads(capsys.readouterr().out)
        assert body["keys_revoked"] == 2 and body["status"] == "cancelled"
        for key in (out["api_key"], customer_key):
            assert client.get(CELL_ROUTE, headers=headers(key)).status_code == 401
        account = AccountStore(store_path).account(out["account_id"])
        assert account.status == "cancelled" and "pilot over" in account.grant_note
        assert account.plan.tier == "free"

    def test_end_by_email_and_a_second_end_is_a_no_op(self, capsys, store_path):
        out = granted(capsys, store_path, email="End@Me.example")
        assert _cli("end", "--store", store_path, "--email", "end@me.example") == 0
        capsys.readouterr()
        assert _cli("end", "--store", store_path, "--email", "end@me.example") == 0
        assert "already ended" in capsys.readouterr().out
        assert AccountStore(store_path).active_key_count(out["account_id"]) == 0

    def test_an_ended_grant_does_not_block_a_new_one_for_the_same_email(self, capsys, store_path):
        first = granted(capsys, store_path, email="again@me.example")
        _cli("end", "--store", store_path, "--account", first["account_id"])
        second = granted(capsys, store_path, email="again@me.example")
        assert second["account_id"] != first["account_id"]

    def test_end_refuses_a_stripe_account_and_an_unknown_one(self, capsys, store_path):
        stripe = AccountStore(store_path).upsert_account(
            email="s@x.example", tier="cell", stripe_customer_id="cus_1")
        capsys.readouterr()
        assert _cli("end", "--store", store_path, "--account", stripe.id) == 2
        assert "not a manual grant" in capsys.readouterr().err
        assert _cli("end", "--store", store_path, "--email", "nobody@x.example") == 2
        assert AccountStore(store_path).account(stripe.id).status == "active"

    def test_the_runbook_names_end(self):
        text = " ".join((ROOT / "deploy/assurance/README.md").read_text().split())
        assert "billing end" in text and "do not roll back" in text.lower()


# =====================================================================
class TestAPilotIsNotSentToADeadEnd:
    def test_checkout_by_a_manual_grant_is_a_purpose_written_409(self, capsys, store_path, client):
        key = granted(capsys, store_path, tier="register")["api_key"]
        r = client.post("/v1/checkout", headers=headers(key),
                        json={"tier": "cell", "email": "pilot@acme.example"})
        assert r.status_code == 409
        detail = r.json()["detail"]
        assert detail["error"] == "pilot_account"
        assert "operator" in detail["remedy"] and "/v1/billing/portal" not in detail["remedy"]

    def test_the_402_remedy_for_a_manual_grant_does_not_point_at_checkout(
            self, capsys, store_path, client):
        key = granted(capsys, store_path, tier="register")["api_key"]
        r = client.get(CELL_ROUTE, headers=headers(key))
        assert r.status_code == 402
        remedy = r.json()["detail"]["remedy"]
        assert "operator" in remedy and "POST /v1/checkout" not in remedy

    def test_a_lapsed_grant_says_when_it_ended(self, capsys, store_path, client, monkeypatch):
        last_day = (utc_now() + timedelta(days=1)).date()
        key = granted(capsys, store_path, "--expires-on", last_day.isoformat())["api_key"]
        later = datetime(last_day.year, last_day.month, last_day.day, tzinfo=UTC) + timedelta(days=2)
        monkeypatch.setattr(accounts_module, "utc_now", lambda: later)
        r = client.get(CELL_ROUTE, headers=headers(key))
        assert r.status_code == 402
        remedy = r.json()["detail"]["remedy"]
        assert f"ended on {last_day.isoformat()}" in remedy and "POST /v1/checkout" not in remedy

    def test_a_stripe_account_keeps_the_ordinary_remedy_and_409(self, store_path, client):
        store = AccountStore(store_path)
        paid = store.upsert_account(email="p@x.example", tier="register", stripe_customer_id="cus_2")
        key = store.issue_key(paid.id)
        r = client.get(CELL_ROUTE, headers=headers(key))
        assert r.status_code == 402 and "POST /v1/checkout" in r.json()["detail"]["remedy"]
        c = client.post("/v1/checkout", headers=headers(key),
                        json={"tier": "cell", "email": "p@x.example"})
        assert c.status_code == 409 and c.json()["detail"]["error"] == "already_subscribed"

    def test_the_conversion_path_is_documented(self):
        text = " ".join((ROOT / "deploy/assurance/README.md").read_text().split())
        assert "converting a pilot" in text.lower() and "second account" in text


# =====================================================================
class TestAKeyThatCouldNotBeDeliveredIsNotLeftLive:
    def _closed_pipe(self, tmp_path, *argv):
        r, w = os.pipe()
        os.close(r)
        try:
            return subprocess.run(  # noqa: S603
                [sys.executable, "-m", "assurance", "billing", *map(str, argv)],
                stdout=w, stderr=subprocess.PIPE, text=True, env=_child_env(), timeout=60,
                cwd=tmp_path, check=False)
        finally:
            os.close(w)

    def test_grant_with_nowhere_to_print_revokes_the_key_and_says_so(self, tmp_path):
        store = tmp_path / "a.db"
        done = self._closed_pipe(tmp_path, "grant", "--store", store, "--create",
                                 "--email", "d@d.example", "--tier", "cell")
        accounts = AccountStore(store).list_accounts()
        assert done.returncode == 2 and len(accounts) == 1
        assert "NOT delivered" in done.stderr and accounts[0].id in done.stderr
        assert AccountStore(store).active_key_count(accounts[0].id) == 0
        assert "issue-key" in done.stderr

    def test_json_grant_is_the_same(self, tmp_path):
        store = tmp_path / "a.db"
        done = self._closed_pipe(tmp_path, "grant", "--store", store, "--create", "--json",
                                 "--email", "d@d.example", "--tier", "cell")
        (account,) = AccountStore(store).list_accounts()
        assert done.returncode == 2 and AccountStore(store).active_key_count(account.id) == 0

    def test_issue_key_into_a_closed_pipe_leaves_only_the_original_key(self, tmp_path, capsys):
        store = tmp_path / "a.db"
        out = granted(capsys, store, "--create")
        done = self._closed_pipe(tmp_path, "issue-key", "--store", store,
                                 "--account", out["account_id"])
        assert done.returncode == 2 and "NOT delivered" in done.stderr
        assert AccountStore(store).active_key_count(out["account_id"]) == 1

    def test_the_cli_docstring_no_longer_says_nothing_is_lost(self):
        src = (ROOT / "src" / "assurance" / "cli.py").read_text()
        assert "nothing is lost" not in src and "billing grant" in src


# =====================================================================
class TestHardeningAtTheStore:
    def test_unicode_case_duplicates_are_one_person(self, tmp_path):
        store = AccountStore(tmp_path / "a.db")
        store.grant_manual(email="MÜLLER@Beispiel.DE", tier="cell")
        with pytest.raises(ManualGrantError):
            store.grant_manual(email="müller@beispiel.de", tier="cell")
        store.grant_manual(email="Straße@beispiel.de", tier="cell")
        with pytest.raises(ManualGrantError):
            store.grant_manual(email="STRASSE@beispiel.de", tier="cell")

    @pytest.mark.parametrize("email", ["@", "a b@c.d", "a@@b.c", "a@", "@b.c", "a@b\n.c",
                                       "a@b .c", "", "plain"])
    def test_an_email_must_be_one_at_with_both_sides_and_no_whitespace(self, tmp_path, email):
        with pytest.raises(ManualGrantError):
            AccountStore(tmp_path / "a.db").grant_manual(email=email, tier="cell")

    @pytest.mark.parametrize("bad", ["abc", "2026-10-28T10:00", "2026-13-01", "20261028",
                                     "2026-1-1", " 2026-12-31"])
    def test_an_unreadable_expiry_is_refused_at_the_store(self, tmp_path, bad):
        store = AccountStore(tmp_path / "a.db")
        with pytest.raises(ManualGrantError):
            store.grant_manual(email="a@b.example", tier="cell", expires_on=bad)
        account, _ = store.grant_manual(email="a@b.example", tier="cell")
        with pytest.raises(ManualGrantError):
            store.extend_grant(account.id, bad)

    def test_an_unreadable_stored_expiry_ends_the_grant(self, tmp_path):
        path = tmp_path / "a.db"
        store = AccountStore(path)
        account, _ = store.grant_manual(email="a@b.example", tier="cell")
        db = sqlite3.connect(path)
        db.execute("update accounts set grant_expires_on='whenever' where id=?", (account.id,))
        db.commit()
        db.close()
        reread = store.account(account.id)
        assert reread.grant_lapsed is True and reread.plan.tier == "free"

    def test_extend_with_an_empty_value_is_refused_and_no_expiry_must_be_explicit(
            self, capsys, store_path):
        out = granted(capsys, store_path, "--expires-on",
                      (utc_now() + timedelta(days=5)).date().isoformat())
        capsys.readouterr()
        assert _cli("extend", "--store", store_path, "--account", out["account_id"],
                    "--expires-on", "") == 2
        assert AccountStore(store_path).account(out["account_id"]).grant_expires_on \
            == out["expires_on"]
        assert _cli("extend", "--store", store_path, "--account", out["account_id"]) == 2
        assert _cli("extend", "--store", store_path, "--account", out["account_id"],
                    "--no-expiry") == 0
        assert AccountStore(store_path).account(out["account_id"]).grant_expires_on == ""

    def test_the_two_forms_cannot_be_combined(self, store_path, capsys):
        out = granted(capsys, store_path)
        with pytest.raises(SystemExit) as exc:
            _cli("extend", "--store", store_path, "--account", out["account_id"],
                 "--expires-on", "2999-01-01", "--no-expiry")
        assert exc.value.code == 2

    def test_extend_grant_itself_refuses_an_account_that_is_not_a_manual_grant(self, tmp_path):
        """Defence in depth: the CLI checks, and so does the store."""
        store = AccountStore(tmp_path / "a.db")
        paid = store.upsert_account(email="p@x.example", tier="cell", stripe_customer_id="cus_3")
        with pytest.raises(ManualGrantError):
            store.extend_grant(paid.id, "2999-01-01")
        assert store.account(paid.id).grant_expires_on == ""

    def test_revoke_by_prefix_will_not_guess_between_two_live_keys(self, tmp_path):
        path = tmp_path / "a.db"
        store = AccountStore(path)
        account, key = store.grant_manual(email="a@b.example", tier="cell")
        db = sqlite3.connect(path)
        row = db.execute("select * from api_keys where account_id=?", (account.id,)).fetchone()
        db.execute("insert into api_keys (key_hash, prefix, account_id, label, created_at) "
                   "values ('dup-hash', ?, ?, 'dup', '2026-01-01T00:00:00Z')", (row[1], account.id))
        db.commit()
        db.close()
        assert store.revoke_account_key(account.id, key_prefix=key[:10]) == "ambiguous"
        assert store.active_key_count(account.id) == 2

    def test_the_cli_reports_ambiguous_as_a_refusal(self, tmp_path, capsys):
        path = tmp_path / "a.db"
        store = AccountStore(path)
        account, key = store.grant_manual(email="a@b.example", tier="cell")
        db = sqlite3.connect(path)
        db.execute("insert into api_keys (key_hash, prefix, account_id, label, created_at) "
                   "values ('dup-hash', ?, ?, 'dup', '2026-01-01T00:00:00Z')",
                   (key[:10], account.id))
        db.commit()
        db.close()
        capsys.readouterr()
        assert _cli("revoke-key", "--store", path, "--account", account.id,
                    "--prefix", key[:10]) == 2
        assert "more than one live key" in capsys.readouterr().err
