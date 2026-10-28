"""An operator path to provision an account without Stripe, for a pilot invoiced outside it.

Before ``assurance billing grant`` the only way to give a pilot customer a key was to call
``AccountStore.upsert_account`` and ``issue_key`` from Python, and the account that came out
looked like nobody had ever paid (``ever_paid`` is the Stripe customer id) and was
indistinguishable from a Stripe-paid one. These tests drive the real CLI against a real
``AccountStore`` file and then the real FastAPI app on that same file, so what is asserted is
what a customer's request would meet: 401 with no key, 402 with a key that lacks the plan, 200
with one that has it, and the same answers read again on every request.

This is operator tooling. It decides nothing about who should get a grant (the founder does),
creates no Stripe object, charges nobody and opens no socket.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing.accounts import AccountStore
from assurance.cli import main as assurance_main
from assurance.core.identity import utc_now
from assurance.kit.airgap import no_network

ROOT = Path(__file__).resolve().parent.parent
OPERATOR_KEY = "operator-key-manual-grant"
CELL_ROUTE = "/v1/change/cases"          # Machine gate: Cell and up
REGISTER_ROUTE = "/v1/cases"             # Register gate: Register and up


@pytest.fixture()
def store_path(tmp_path) -> Path:
    path = tmp_path / "accounts.db"
    AccountStore(path)                   # the file a deployment's service created
    return path


@pytest.fixture()
def app_env(tmp_path, store_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(store_path))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL", "ASSURANCE_PRICE_PAYG",
                 "ASSURANCE_TENANT_LEDGERS", "ASSURANCE_TRUST_FLY_PROXY"):
        monkeypatch.delenv(name, raising=False)
    for fn in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
        fn.cache_clear()
    yield
    for fn in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
        fn.cache_clear()


@pytest.fixture()
def client(app_env):
    app = importlib.import_module("assurance.api.service").create_app()
    with TestClient(app) as c:
        yield c


def grant(capsys, store_path, *extra, email="pilot@acme.example", tier="cell"):
    capsys.readouterr()
    rc = assurance_main(["billing", "grant", "--store", str(store_path), "--email", email,
                         "--tier", tier, "--json", *extra])
    cap = capsys.readouterr()
    return rc, cap


def granted(capsys, store_path, *extra, **kw):
    rc, cap = grant(capsys, store_path, *extra, **kw)
    assert rc == 0, cap.err or cap.out
    return json.loads(cap.out)


def headers(key):
    return {"X-API-Key": key}


# =====================================================================
class TestWhatTheGrantCreates:
    def test_a_manual_account_is_not_a_stripe_account(self, capsys, store_path):
        out = granted(capsys, store_path, "--note", "pilot invoiced by bank transfer, ref 7")
        account = AccountStore(store_path).account(out["account_id"])
        assert account.tier == "cell" and account.status == "active"
        assert account.source == "manual_grant"
        assert account.stripe_customer_id == "" and account.stripe_subscription_id == ""
        assert account.ever_paid is False            # unchanged: Stripe binds that, not us
        assert account.grant_note == "pilot invoiced by bank transfer, ref 7"
        assert account.granted_at
        assert out["source"] == "manual_grant" and out["tier"] == "cell"

    def test_the_key_is_printed_once_and_only_its_hash_is_kept(self, capsys, store_path):
        out = granted(capsys, store_path)
        key = out["api_key"]
        assert key.startswith("asr_") and "once" in out["key_note"].lower()
        assert key not in store_path.read_bytes().decode("latin-1")
        store = AccountStore(store_path)
        assert all(key not in json.dumps(k) for k in store.keys_for(out["account_id"]))
        # Nothing else the CLI prints ever shows it again.
        capsys.readouterr()
        for verb in (["list"], ["list", "--json"]):
            assert assurance_main(["billing", *verb, "--store", str(store_path)]) == 0
            seen = capsys.readouterr()
            assert key not in seen.out and key not in seen.err

    def test_the_text_output_says_once_and_that_nothing_else_prints_it(self, capsys, store_path):
        capsys.readouterr()
        rc = assurance_main(["billing", "grant", "--store", str(store_path),
                             "--email", "t@acme.example", "--tier", "register"])
        cap = capsys.readouterr()
        assert rc == 0
        assert "shown once" in " ".join(cap.out.split()).lower()
        assert "asr_" in cap.out and "asr_" not in cap.err

    def test_only_register_and_cell_can_be_granted(self, capsys, store_path):
        for tier in ("free", "payg", "enterprise"):
            with pytest.raises(SystemExit) as exc:
                grant(capsys, store_path, tier=tier)
            assert exc.value.code == 2
        assert AccountStore(store_path).list_accounts() == []

    def test_a_store_that_does_not_exist_is_refused_unless_created_on_purpose(
            self, capsys, tmp_path):
        missing = tmp_path / "typo" / "accounts.db"
        rc, cap = grant(capsys, missing)
        assert rc == 2 and "does not exist" in cap.err and "--create" in cap.err
        assert not missing.exists()
        out = granted(capsys, missing, "--create")
        assert missing.exists() and out["account_id"]

    def test_the_help_says_what_it_is_for_and_who_decides(self, capsys):
        with pytest.raises(SystemExit):
            assurance_main(["billing", "grant", "--help"])
        text = " ".join(capsys.readouterr().out.split()).lower()
        assert "outside stripe" in text
        assert "founder" in text
        assert "no network" in text or "never opens a network" in text


class TestWhatTheCustomerMeets:
    def test_a_cell_grant_works_on_every_request(self, capsys, store_path, client):
        key = granted(capsys, store_path)["api_key"]
        assert client.get(CELL_ROUTE).status_code == 401                       # no key
        assert client.get(CELL_ROUTE, headers=headers("asr_not-a-key")).status_code == 401
        assert client.get(CELL_ROUTE, headers=headers(key)).status_code == 200
        assert client.get(REGISTER_ROUTE, headers=headers(key)).status_code == 200

    def test_a_register_grant_is_402_on_a_cell_route(self, capsys, store_path, client):
        key = granted(capsys, store_path, tier="register")["api_key"]
        r = client.get(CELL_ROUTE, headers=headers(key))
        assert r.status_code == 402
        assert r.json()["detail"]["error"] == "plan_does_not_include_machine_verification"
        assert client.get(REGISTER_ROUTE, headers=headers(key)).status_code == 200

    def test_me_says_this_account_is_a_manual_grant_not_a_stripe_customer(
            self, capsys, store_path, client):
        out = granted(capsys, store_path, "--note", "pilot, bank transfer",
                      "--expires-on", (utc_now() + timedelta(days=30)).date().isoformat())
        body = client.get("/v1/me", headers=headers(out["api_key"])).json()
        assert body["tier"] == "cell"
        assert body["account"]["source"] == "manual_grant"
        grant_info = body["account"]["grant"]
        assert grant_info["note"] == "pilot, bank transfer"
        assert grant_info["granted_at"] and grant_info["expires_on"] == out["expires_on"]
        assert grant_info["invoiced_outside_stripe"] is True

    def test_me_tells_a_stripe_account_and_an_unbilled_one_apart(self, store_path, client):
        store = AccountStore(store_path)
        paid = store.upsert_account(email="p@x.example", tier="cell",
                                    stripe_customer_id="cus_1")
        bare = store.upsert_account(email="b@x.example", tier="cell")
        for account, source in ((paid, "stripe"), (bare, "unbilled")):
            key = store.issue_key(account.id)
            got = client.get("/v1/me", headers=headers(key)).json()["account"]
            assert got["source"] == source and "grant" not in got

    def test_a_revoked_key_stops_at_once(self, capsys, store_path, client):
        out = granted(capsys, store_path)
        key = out["api_key"]
        assert client.get(CELL_ROUTE, headers=headers(key)).status_code == 200
        capsys.readouterr()
        rc = assurance_main(["billing", "revoke-key", "--store", str(store_path),
                             "--account", out["account_id"], "--prefix", out["key_prefix"],
                             "--json"])
        assert rc == 0 and json.loads(capsys.readouterr().out)["result"] == "revoked"
        assert client.get(CELL_ROUTE, headers=headers(key)).status_code == 401

    def test_issue_key_gives_a_second_working_key_and_refuses_a_stripe_account(
            self, capsys, store_path, client):
        out = granted(capsys, store_path)
        capsys.readouterr()
        assert assurance_main(["billing", "issue-key", "--store", str(store_path),
                               "--account", out["account_id"], "--json"]) == 0
        second = json.loads(capsys.readouterr().out)["api_key"]
        assert second != out["api_key"]
        assert client.get(CELL_ROUTE, headers=headers(second)).status_code == 200
        stripe = AccountStore(store_path).upsert_account(
            email="s@x.example", tier="cell", stripe_customer_id="cus_9")
        rc = assurance_main(["billing", "issue-key", "--store", str(store_path),
                             "--account", stripe.id])
        assert rc == 2 and "not a manual grant" in capsys.readouterr().err


class TestASecondGrantForTheSameEmailIsRefused:
    def test_it_is_refused_naming_the_existing_account_and_mints_nothing(
            self, capsys, store_path):
        first = granted(capsys, store_path, email="Pilot@Acme.example")
        rc, cap = grant(capsys, store_path, email="pilot@acme.example", tier="register")
        assert rc == 2
        assert first["account_id"] in cap.err
        assert "issue-key" in cap.err                     # the explicit way to a second key
        assert "asr_" not in cap.out + cap.err
        store = AccountStore(store_path)
        assert [a.id for a in store.list_accounts()] == [first["account_id"]]
        assert store.active_key_count(first["account_id"]) == 1

    def test_a_different_email_is_a_different_account(self, capsys, store_path):
        a = granted(capsys, store_path, email="a@acme.example")
        b = granted(capsys, store_path, email="b@acme.example")
        assert a["account_id"] != b["account_id"] and a["api_key"] != b["api_key"]


class TestExpiry:
    def _tomorrow(self):
        return (utc_now() + timedelta(days=1)).date()

    def test_a_grant_lapses_after_its_last_day_and_not_before(
            self, capsys, store_path, client, monkeypatch):
        last_day = self._tomorrow()
        out = granted(capsys, store_path, "--expires-on", last_day.isoformat())
        key = out["api_key"]
        assert out["expires_on"] == last_day.isoformat()
        assert client.get(CELL_ROUTE, headers=headers(key)).status_code == 200

        from datetime import datetime

        from assurance.billing import accounts as accounts_module

        def at(moment):
            monkeypatch.setattr(accounts_module, "utc_now", lambda: moment)

        at(datetime(last_day.year, last_day.month, last_day.day, 23, 59, 59,
                    tzinfo=utc_now().tzinfo))
        assert client.get(CELL_ROUTE, headers=headers(key)).status_code == 200   # inclusive
        at(datetime(last_day.year, last_day.month, last_day.day, tzinfo=utc_now().tzinfo)
           + timedelta(days=1))
        lapsed = client.get(CELL_ROUTE, headers=headers(key))
        assert lapsed.status_code == 402                                         # read each time
        assert client.get("/v1/me", headers=headers(key)).json()["tier"] == "free"

    def test_lapse_is_the_same_as_never_having_paid_for_evidence_readout(
            self, capsys, store_path, client, monkeypatch):
        """Characterisation of an OPEN founder decision, pinned so a change is deliberate:
        a lapsed manual grant has no Stripe customer id, so ``ever_paid`` is false and the
        evidence read-out that lapsed Stripe customers keep is closed to it too."""
        last_day = self._tomorrow()
        key = granted(capsys, store_path, "--expires-on", last_day.isoformat())["api_key"]
        assert client.get(REGISTER_ROUTE, headers=headers(key)).status_code == 200
        from datetime import datetime

        from assurance.billing import accounts as accounts_module

        monkeypatch.setattr(
            accounts_module, "utc_now",
            lambda: datetime(last_day.year, last_day.month, last_day.day,
                             tzinfo=utc_now().tzinfo) + timedelta(days=2))
        r = client.get(REGISTER_ROUTE, headers=headers(key))
        assert r.status_code == 402
        assert "x-assurance-access" not in {k.lower() for k in r.headers}
        me = client.get("/v1/me", headers=headers(key)).json()
        assert me["evidence_readout"] is False

    def test_a_date_in_the_past_or_not_a_date_is_refused(self, capsys, store_path):
        for bad in ((utc_now() - timedelta(days=1)).date().isoformat(), "next friday",
                    "2026-13-45", "2026/12/31"):
            rc, cap = grant(capsys, store_path, "--expires-on", bad)
            assert rc == 2 and "--expires-on" in cap.err, bad
        assert AccountStore(store_path).list_accounts() == []

    def test_no_expiry_means_it_does_not_lapse_and_says_so(self, capsys, store_path):
        out = granted(capsys, store_path)
        assert out["expires_on"] == ""
        capsys.readouterr()
        assurance_main(["billing", "grant", "--store", str(store_path),
                        "--email", "n@acme.example", "--tier", "cell"])
        assert "no expiry" in capsys.readouterr().out.lower()

    def test_extend_moves_the_last_day_and_revives_a_lapsed_grant(
            self, capsys, store_path, client, monkeypatch):
        out = granted(capsys, store_path, "--expires-on", self._tomorrow().isoformat())
        from datetime import datetime

        from assurance.billing import accounts as accounts_module

        later = (utc_now() + timedelta(days=40)).date()
        monkeypatch.setattr(accounts_module, "utc_now", lambda: datetime(
            later.year, later.month, later.day, tzinfo=utc_now().tzinfo))
        assert client.get(CELL_ROUTE, headers=headers(out["api_key"])).status_code == 402
        new_last = later + timedelta(days=30)
        capsys.readouterr()
        rc = assurance_main(["billing", "extend", "--store", str(store_path),
                             "--account", out["account_id"],
                             "--expires-on", new_last.isoformat(), "--json"])
        assert rc == 0 and json.loads(capsys.readouterr().out)["expires_on"] == new_last.isoformat()
        assert client.get(CELL_ROUTE, headers=headers(out["api_key"])).status_code == 200


class TestItIsOfflineAndNeverStripe:
    def test_it_opens_no_socket(self, capsys, store_path):
        with no_network() as guard:
            rc, _ = grant(capsys, store_path)
        assert rc == 0 and guard.held and not guard.attempts

    def test_it_never_loads_the_stripe_gateway(self, tmp_path, store_path):
        code = (
            "import sys, json\n"
            "from assurance.cli import main\n"
            f"rc = main(['billing','grant','--store',{str(store_path)!r},"
            "'--email','x@acme.example','--tier','cell','--json'])\n"
            "mods = sorted(m for m in sys.modules if 'stripe' in m)\n"
            "print('\\nMODULES=' + json.dumps(mods)); sys.exit(rc)\n")
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")}
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,  # noqa: S603
                              env=env, check=False, cwd=tmp_path, timeout=60)
        assert done.returncode == 0, done.stderr
        assert json.loads(done.stdout.rsplit("MODULES=", 1)[1]) == []

    @pytest.mark.parametrize("name,value", [
        ("STRIPE_SECRET_KEY", "sk_live_" + "a" * 24),
        ("SOME_OTHER_NAME", "rk_live_" + "b" * 24),
        ("STRIPE_WEBHOOK_SECRET", "whsec_live_" + "c" * 12),
        ("STRIPE_PUBLISHABLE_LIVE", "anything"),
        ("ASSURANCE_PAYG_ALLOW_LIVE", "1"),
    ])
    def test_a_live_looking_stripe_environment_is_refused_without_echoing_it(
            self, capsys, store_path, monkeypatch, name, value):
        monkeypatch.setenv(name, value)
        rc, cap = grant(capsys, store_path)
        assert rc == 2
        assert name in cap.err                              # the name, to find it
        assert value not in cap.out + cap.err               # never the value
        assert AccountStore(store_path).list_accounts() == []

    def test_a_test_mode_environment_does_not_stop_it(self, capsys, store_path, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_" + "a" * 24)
        rc, _ = grant(capsys, store_path)
        assert rc == 0

    def test_reconcile_leaves_a_manual_grant_alone(self, capsys, store_path):
        """It has no Stripe customer id, so the Stripe reconciler never considers it."""
        from assurance.billing.reconcile import reconcile

        class _EmptyStripe:
            def list_subscriptions(self, **kwargs):
                return {"data": [], "has_more": False}

            def retrieve_subscription(self, sub_id):
                raise AssertionError("a manual grant was asked about in Stripe")

        out = granted(capsys, store_path)
        report = reconcile(AccountStore(store_path), _EmptyStripe(), apply=True)
        assert {"account_id": out["account_id"], "reason": "no Stripe customer id"} \
            in report.skipped
        assert report.findings == []
        account = AccountStore(store_path).account(out["account_id"])
        assert account.status == "active" and account.tier == "cell"


class TestTheStoreMigratesAdditively:
    def test_a_store_written_before_the_grant_columns_still_opens_and_grants(
            self, capsys, tmp_path):
        path = tmp_path / "old.db"
        AccountStore(path)
        db = sqlite3.connect(path)
        for col in ("source", "grant_note", "granted_at", "grant_expires_on", "granted_by"):
            db.execute(f"ALTER TABLE accounts DROP COLUMN {col}")
        db.commit()
        db.close()
        old = AccountStore(path)                          # migrates
        acct = old.upsert_account(email="legacy@x.example", tier="cell",
                                  stripe_customer_id="cus_legacy")
        assert acct.source == "" and acct.ever_paid
        out = granted(capsys, path)
        assert AccountStore(path).account(out["account_id"]).source == "manual_grant"


class TestListIsAnHonestInventory:
    def test_it_separates_manual_from_stripe_and_shows_expiry_without_secrets(
            self, capsys, store_path):
        store = AccountStore(store_path)
        store.upsert_account(email="paid@x.example", tier="cell", stripe_customer_id="cus_1")
        out = granted(capsys, store_path, "--expires-on",
                      (utc_now() + timedelta(days=10)).date().isoformat(), "--note", "pilot A")
        capsys.readouterr()
        assert assurance_main(["billing", "list", "--store", str(store_path), "--json"]) == 0
        rows = {r["id"]: r for r in json.loads(capsys.readouterr().out)["accounts"]}
        manual = rows[out["account_id"]]
        assert manual["source"] == "manual_grant" and manual["note"] == "pilot A"
        assert manual["expires_on"] == out["expires_on"] and manual["entitled_now"] is True
        assert [r["source"] for r in rows.values()].count("stripe") == 1
        assert "api_key" not in json.dumps(rows)


def test_the_operator_docs_carry_the_command_and_its_limits():
    for rel in ("deploy/assurance/README.md", "docs/buyer-journey.md"):
        text = " ".join((ROOT / rel).read_text(encoding="utf-8").split())
        assert "assurance billing grant" in text, rel
        assert "outside Stripe" in text, rel
        assert "founder" in text, rel
    readme = " ".join((ROOT / "deploy/assurance/README.md").read_text(encoding="utf-8").split())
    assert "fly ssh console" in readme and "/data/accounts.db" in readme
