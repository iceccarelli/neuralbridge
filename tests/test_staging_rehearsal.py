"""The go-live rehearsal tool (``scripts/staging_rehearsal.py``), proven locally.

Nothing here talks to Stripe, Fly or any host the test did not start. The tool's own
promise is what is under test:

* it refuses anything that looks like a live Stripe credential, before doing anything;
* it never prints, records or reports a secret, on success, on failure or on an exception;
* an absent prerequisite is ``UNCHECKED`` (exit 3), never a pass;
* ``smoke`` passes against the real assurance API on a real socket and FAILS against a
  server that is deliberately wrong (wrong plans, 200 on a bad key, a leaked secret ...);
* ``webhook-test`` refuses an unconfirmed or production host and a non-``whsec_`` secret,
  and against the real app hands the key over exactly once;
* ``restore-drill`` fails on a corrupted or truncated backup, with real SQLite ledgers;
* ``report`` is redacted and says what stayed unchecked.

The tests need no ``node_modules`` and no network: the servers are loopback sockets the
kernel assigned.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from assurance.billing.accounts import AccountStore
from assurance.billing.plans import public_catalogue
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger

from . import interfaces_fixtures as fx

live_api = fx.live_api

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "staging_rehearsal.py"

# Sentinels: values that must never appear in any output, record or report.
SK_TEST = "sk" "_test_SENTINEL51KeyDoNotPrint0123456789"
WHSEC = "whsec" "_SENTINELWebhookDoNotPrint0123456789"
OPERATOR_KEY = "SENTINELoperatorkeyDoNotPrint0123456789abcdef"
REGISTER_KEY_ENV = "asr_SENTINELregisterkeyDoNotPrint01234"
SENTINELS = (SK_TEST, WHSEC, OPERATOR_KEY, REGISTER_KEY_ENV)

PRICES = {"ASSURANCE_PRICE_REGISTER": "price_1TestRegister0001",
          "ASSURANCE_PRICE_CELL": "price_1TestCell00000002"}


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("staging_rehearsal", SCRIPT)
    assert spec and spec.loader, f"{SCRIPT} is missing"
    module = importlib.util.module_from_spec(spec)
    sys.modules["staging_rehearsal"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def sr() -> ModuleType:
    return _load()


@pytest.fixture(autouse=True)
def _scratch_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A phase always leaves a record, by default in ./.rehearsal: keep that out of the repo.
    monkeypatch.chdir(tmp_path)


def full_env(**extra: str) -> dict[str, str]:
    """A complete, valid TEST-mode deploy environment (all values are throwaways)."""
    env = {
        "STRIPE_SECRET_KEY": SK_TEST,
        "STRIPE_WEBHOOK_SECRET": WHSEC,
        "ASSURANCE_API_KEYS": OPERATOR_KEY,
        "ASSURANCE_PUBLIC_URL": "https://assurance-staging.fly.dev",
        "ASSURANCE_MARKETING_URL": "https://assurance-staging-site.vercel.app",
        "ASSURANCE_ALLOWED_ORIGINS": "https://assurance-staging-site.vercel.app",
        **PRICES,
    }
    env.update(extra)
    return env


class Ran(SimpleNamespace):
    code: int
    out: str
    err: str

    @property
    def text(self) -> str:
        return self.out + self.err


def cli(sr: ModuleType, capsys: pytest.CaptureFixture[str], *args: str,
        env: dict[str, str] | None = None) -> Ran:
    code = sr.main(list(args), environ=dict(env or {}))
    captured = capsys.readouterr()
    return Ran(code=code, out=captured.out, err=captured.err)


def record(rec: Path, phase: str) -> dict[str, Any]:
    return json.loads((rec / f"{phase}.json").read_text(encoding="utf-8"))


def statuses(rec: Path, phase: str) -> dict[str, str]:
    return {s["id"]: s["status"] for s in record(rec, phase)["steps"]}


def assert_no_secrets(*texts: str) -> None:
    for text in texts:
        for secret in SENTINELS:
            assert secret not in text, f"a secret reached the output: {secret[:12]}..."


# ---------------------------------------------------------------------------
# a deliberately wrong (or right) service, for smoke and webhook-test
# ---------------------------------------------------------------------------

def fake_service(**d: Any) -> FastAPI:
    """The assurance contract in miniature, with switchable defects."""
    app = FastAPI()
    origins = {"wildcard": ["*"], "extra_origin": ["https://neuralbridge.io",
                                                   "https://evil.invalid"]}
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins.get(d.get("cors", ""), ["https://neuralbridge.io"]),
        allow_credentials=d.get("cors") == "credentials",
        allow_methods=["GET", "POST"], allow_headers=["x-api-key", "content-type"])

    @app.get("/healthz", response_model=None)
    def healthz() -> Any:
        if d.get("redirect"):
            return RedirectResponse("http://127.0.0.1:1/healthz", status_code=302)
        body: dict[str, Any] = {"status": "ok", "ledger_ok": True, "accounts_ok": True,
                                "auth_mode": "open" if d.get("open") else "api_key"}
        if d.get("leak"):
            body["debug"] = d["leak"]
        return body

    @app.get("/v1/plans")
    def plans() -> Any:
        catalogue = public_catalogue()
        for plan in catalogue:
            plan["purchasable"] = d.get("purchasable", True) if plan["tier"] != "free" else False
        if d.get("plans") == "wrong_price":
            catalogue[1]["price"] = "EUR 1 / month"
        if d.get("plans") == "missing_tier":
            catalogue = catalogue[:2]
        if d.get("plans") == "unlimited_cell":
            catalogue[2]["limits"]["machine_verification"] = False
        return catalogue

    @app.post("/v1/machine/verify")
    async def verify(request: Request) -> JSONResponse:
        key = request.headers.get("x-api-key", "")
        challenge = {"WWW-Authenticate": "ApiKey"}
        if not key:
            return JSONResponse({"ok": 1} if d.get("nokey_ok") else {"detail": "key"},
                                200 if d.get("nokey_ok") else 401, headers=challenge)
        if key == d.get("register_key"):
            if d.get("register_ok"):
                return JSONResponse({"ok": 1}, 200)
            if d.get("register_401"):
                return JSONResponse({"detail": "no"}, 401, headers=challenge)
            return JSONResponse({"detail": {"error": "plan_does_not_include_machine_verification"}},
                                402)
        if d.get("bad_key_ok"):
            return JSONResponse({"ok": 1}, 200)
        return JSONResponse({"detail": "Invalid or revoked API key."}, 401, headers=challenge)

    return app


@contextmanager
def serving(app: Any) -> Iterator[str]:
    with fx.serve(app) as url:
        yield url


def run_smoke(sr: ModuleType, capsys: pytest.CaptureFixture[str], url: str, rec: Path,
              env: dict[str, str] | None = None, *extra: str) -> tuple[Ran, dict[str, str]]:
    ran = cli(sr, capsys, "smoke", "--base-url", url, "--record-dir", str(rec), *extra,
              env=env)
    return ran, statuses(rec, "smoke")


# ---------------------------------------------------------------------------
# live-key refusal
# ---------------------------------------------------------------------------

LIVE_VALUES = ["sk" "_live_AAAAAAAAAAAAAAAAAAAAAAAA", "rk" "_live_BBBBBBBBBBBBBBBBBBBBBBBB",
               "pk" "_live_CCCCCCCCCCCCCCCCCCCCCCCC"]


@pytest.mark.parametrize("live", LIVE_VALUES)
@pytest.mark.parametrize("name", ["STRIPE_SECRET_KEY", "SOME_OTHER_VARIABLE",
                                  "STRIPE_RESTRICTED_BACKUP"])
def test_every_live_prefix_is_refused_loudly_in_any_variable(sr, capsys, tmp_path, live, name):
    env = full_env()
    env[name] = live
    ran = cli(sr, capsys, "config-check", "--checkout-expected",
              "--record-dir", str(tmp_path), env=env)
    assert ran.code == 1
    assert "REFUSED" in ran.err and name in ran.err
    assert live not in ran.text and live[:12] not in ran.text      # name, never the value
    assert statuses(tmp_path, "config-check")["config.no_live_keys"] == "FAIL"


def test_a_live_prefix_buried_inside_a_longer_value_is_refused(sr, capsys, tmp_path):
    env = full_env(HEADER_NOTES="Authorization: Bearer sk" "_live_ZZZZZZZZZZZZZZZZ trailing")
    ran = cli(sr, capsys, "config-check", env=env)
    assert ran.code == 1 and "REFUSED" in ran.err and "HEADER_NOTES" in ran.err
    assert "sk_live_ZZZ" not in ran.text


def test_a_mixed_environment_is_refused_even_when_the_main_key_is_a_test_key(
        sr, capsys, tmp_path):
    env = full_env(MY_OLD_STRIPE_KEY="rk" "_live_DDDDDDDDDDDDDDDDDDDDDDD")
    assert env["STRIPE_SECRET_KEY"].startswith("sk_test_")
    ran = cli(sr, capsys, "config-check", env=env)
    assert ran.code == 1 and "MY_OLD_STRIPE_KEY" in ran.err
    assert "rk_live_DDD" not in ran.text


@pytest.mark.parametrize("env_extra", [
    {"STRIPE_LIVE_WEBHOOK_SECRET": "whsec" "_anything12345"},
    {"STRIPE_WEBHOOK_SECRET_LIVE": "whsec" "_anything12345"},
    {"ASSURANCE_PAYG_ALLOW_LIVE": "1"},
    {"STRIPE_WEBHOOK_SECRET": "whsec" "_live_notrealbutnamedlive123456"},
])
def test_live_mode_markers_other_than_a_key_prefix_are_refused(sr, capsys, env_extra):
    # Stripe's webhook signing secrets are all ``whsec_...``: the string carries no mode.
    # What can be refused is every *explicit* live marker.
    ran = cli(sr, capsys, "config-check", env=full_env(**env_extra))
    assert ran.code == 1 and "REFUSED" in ran.err, ran.text


@pytest.mark.parametrize("phase", ["smoke", "webhook-test", "restore-drill", "report"])
def test_every_subcommand_refuses_a_live_key_before_doing_anything(
        sr, capsys, tmp_path, phase, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(httpx.Client, "request", lambda self, *a, **k: calls.append("http"))
    monkeypatch.setattr(httpx.Client, "send", lambda self, *a, **k: calls.append("http"))
    args = {"smoke": ["--base-url", "http://127.0.0.1:19609"],
            "webhook-test": ["--base-url", "http://127.0.0.1:19609", "--i-am-testing-staging"],
            "restore-drill": ["--data-dir", str(tmp_path)],
            "report": ["--records", str(tmp_path), "--out", str(tmp_path / "out")]}[phase]
    ran = cli(sr, capsys, phase, *args,
              env=full_env(STAGING_CONFIRM="127.0.0.1", STRIPE_SECRET_KEY=LIVE_VALUES[0]))
    assert ran.code == 1 and "REFUSED" in ran.err
    assert calls == [] and not (tmp_path / "out").exists()
    assert LIVE_VALUES[0] not in ran.text


def test_a_test_key_and_a_complete_environment_is_not_refused(sr, capsys, tmp_path):
    ran = cli(sr, capsys, "config-check", "--checkout-expected",
              "--record-dir", str(tmp_path), env=full_env())
    assert "REFUSED" not in ran.text
    assert statuses(tmp_path, "config-check")["config.no_live_keys"] == "PASS"


# ---------------------------------------------------------------------------
# config-check
# ---------------------------------------------------------------------------

def test_a_complete_test_mode_environment_passes_what_it_can_and_never_exits_0(
        sr, capsys, tmp_path):
    # "open mode is off on the host" cannot be observed from a shell: it is ATTESTED, and an
    # attested step blocks exit 0 (smoke's healthz is what observes auth_mode on the host)
    ran = cli(sr, capsys, "config-check", "--checkout-expected",
              "--record-dir", str(tmp_path), env=full_env())
    found = statuses(tmp_path, "config-check")
    assert ran.code == 3, ran.text
    assert found.pop("config.allow_unauthenticated") == "ATTESTED"
    assert set(found.values()) == {"PASS"}, found
    data = record(tmp_path, "config-check")
    assert data["purchasable"] == {"register": True, "cell": True}
    assert "register" in ran.out and "cell" in ran.out
    assert_no_secrets(ran.text, json.dumps(data))


def test_an_empty_environment_is_unchecked_exit_3_never_a_pass(sr, capsys, tmp_path):
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path), env={})
    assert ran.code == 3
    found = statuses(tmp_path, "config-check")
    assert found["config.stripe_secret_key"] == "UNCHECKED"
    assert found["config.stripe_webhook_secret"] == "UNCHECKED"
    assert found["config.price_register"] == "UNCHECKED"
    assert "FAIL" not in found.values()
    assert record(tmp_path, "config-check")["purchasable"] == {"register": False, "cell": False}


def test_a_missing_price_id_is_a_failure_when_checkout_is_expected(sr, capsys, tmp_path):
    env = full_env()
    del env["ASSURANCE_PRICE_CELL"]
    ran = cli(sr, capsys, "config-check", "--checkout-expected",
              "--record-dir", str(tmp_path), env=env)
    assert ran.code == 1
    found = statuses(tmp_path, "config-check")
    assert found["config.price_cell"] == "FAIL" and found["config.price_register"] == "PASS"
    assert record(tmp_path, "config-check")["purchasable"] == {"register": True, "cell": False}
    # not expected: the same absence is only unchecked
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path), env=env)
    assert ran.code == 3 and statuses(tmp_path, "config-check")["config.price_cell"] == "UNCHECKED"


@pytest.mark.parametrize("name,value,step", [
    ("STRIPE_SECRET_KEY", "sk_test_REPLACE", "config.stripe_secret_key"),
    ("STRIPE_SECRET_KEY", "sk" "_test_REPLACEREPLACEREPLACE0000", "config.stripe_secret_key"),
    ("STRIPE_WEBHOOK_SECRET", "whsec" "_REPLACEREPLACEREPLACE0000", "config.stripe_webhook_secret"),
    ("ASSURANCE_PRICE_REGISTER", "price_REPLACE1234", "config.price_register"),
    ("STRIPE_SECRET_KEY", "not_a_stripe_key_at_all_12345", "config.stripe_secret_key"),
    ("STRIPE_WEBHOOK_SECRET", "whsec_REPLACE", "config.stripe_webhook_secret"),
    ("STRIPE_WEBHOOK_SECRET", "abcdefghijklmnop", "config.stripe_webhook_secret"),
    ("ASSURANCE_API_KEYS", "short", "config.api_keys"),
    ("ASSURANCE_API_KEYS", "REPLACE_me_REPLACE_me_REPLACE_me_REPLACE_me", "config.api_keys"),
    ("ASSURANCE_ALLOW_UNAUTHENTICATED", "1", "config.allow_unauthenticated"),
    ("ASSURANCE_PUBLIC_URL", "http://assurance-staging.example.test", "config.public_url"),
    ("ASSURANCE_PUBLIC_URL", "https://assurance.example.fly.dev", "config.public_url"),
    ("ASSURANCE_PRICE_REGISTER", "price_REPLACE_REGISTER", "config.price_register"),
    ("ASSURANCE_PRICE_CELL", "prod_notaprice", "config.price_cell"),
])
def test_a_malformed_or_placeholder_value_fails_its_step(
        sr, capsys, tmp_path, name, value, step):
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path),
              env=full_env(**{name: value}))
    assert ran.code == 1, ran.text
    assert statuses(tmp_path, "config-check")[step] == "FAIL"


def test_the_same_price_id_for_both_skus_is_a_failure(sr, capsys, tmp_path):
    env = full_env(ASSURANCE_PRICE_CELL=PRICES["ASSURANCE_PRICE_REGISTER"])
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path), env=env)
    assert ran.code == 1 and statuses(tmp_path, "config-check")["config.price_cell"] == "FAIL"


def test_the_tool_has_no_way_to_create_anything_at_stripe_or_send_mail():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("api.stripe.com", "checkout/sessions", "/v1/prices", "/v1/products",
                      "/v1/customers", "/v1/charges", "smtplib", "create_checkout_session",
                      "stripe_gateway", "import stripe"):
        assert forbidden not in source, forbidden


def test_the_http_client_refuses_any_host_it_was_not_given(sr):
    http = sr.Http("http://127.0.0.1:19609", timeout=1.0)
    with pytest.raises(sr.RefusedHostError):
        http.request("GET", "https://api.stripe.com/v1/prices")
    with pytest.raises(sr.RefusedHostError):
        http.request("GET", "http://evil.invalid/healthz")


# ---------------------------------------------------------------------------
# secrets never leave the process
# ---------------------------------------------------------------------------

def all_secret_env(**extra: str) -> dict[str, str]:
    return full_env(REHEARSAL_REGISTER_KEY=REGISTER_KEY_ENV, STAGING_CONFIRM="127.0.0.1",
                    STAGING_STRIPE_MODE="test", **extra)


def test_secrets_do_not_appear_when_a_server_leaks_them(sr, capsys, tmp_path):
    leaky = fake_service(leak=f"{SK_TEST} {WHSEC} {OPERATOR_KEY} {REGISTER_KEY_ENV}",
                         register_key=REGISTER_KEY_ENV)
    with serving(leaky) as url:
        ran, found = run_smoke(sr, capsys, url, tmp_path, all_secret_env())
    assert found["smoke.provided_secrets_absent"] == "FAIL"
    assert found["smoke.no_secret_shapes"] == "FAIL"
    assert ran.code == 1
    assert_no_secrets(ran.text, *(p.read_text() for p in tmp_path.glob("*")))


def test_secrets_do_not_appear_in_any_subcommand_or_in_a_report(sr, capsys, tmp_path):
    data = tmp_path / "data"
    make_data_dir(data, tenants=1)
    recs, out = tmp_path / "recs", tmp_path / "out"
    env = all_secret_env()
    runs = [
        ("config-check", "--checkout-expected", "--record-dir", str(recs)),
        ("smoke", "--base-url", "http://127.0.0.1:1", "--record-dir", str(recs)),  # refused port
        ("webhook-test", "--base-url", "http://127.0.0.1:1", "--i-am-testing-staging",
         "--record-dir", str(recs), "--poll-seconds", "1"),
        ("webhook-test", "--base-url", "http://127.0.0.1:1", "--record-dir", str(recs)),
        ("restore-drill", "--data-dir", str(data), "--record-dir", str(recs)),
        ("restore-drill", "--data-dir", str(tmp_path / "nowhere"), "--record-dir", str(recs)),
        ("report", "--records", str(recs), "--out", str(out)),
    ]
    for args in runs:
        ran = cli(sr, capsys, *args, env=env)
        assert ran.code in (0, 1, 3), (args, ran.text)
        assert_no_secrets(ran.text)
    for path in list(recs.glob("*")) + list(out.glob("*")):
        assert_no_secrets(path.read_text(encoding="utf-8"))


def test_an_exception_message_carrying_a_secret_is_redacted(sr, capsys, tmp_path, monkeypatch):
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError(f"upstream said: key={SK_TEST} secret={WHSEC} op={OPERATOR_KEY}")

    for phase in ("config-check", "smoke", "webhook-test", "restore-drill", "report"):
        monkeypatch.setitem(sr.PHASES, phase, boom)
        ran = cli(sr, capsys, phase, env=all_secret_env())
        assert ran.code == 1, phase
        assert "RuntimeError" in ran.err or "RuntimeError" in ran.out
        assert_no_secrets(ran.text)


def test_credentials_cannot_be_passed_on_the_command_line_and_are_not_echoed(sr, capsys):
    ran = cli(sr, capsys, "smoke", "--api-key", OPERATOR_KEY, "--stripe-key", SK_TEST,
              env=full_env())
    assert ran.code == 2
    assert_no_secrets(ran.text)


@pytest.mark.parametrize("phase,extra", [("smoke", []), ("webhook-test", ["--i-am-testing-staging"])])
def test_plain_http_to_a_non_loopback_host_is_refused_without_a_request(
        sr, capsys, tmp_path, monkeypatch, phase, extra):
    calls: list[str] = []
    monkeypatch.setattr(httpx.Client, "request", lambda self, *a, **k: calls.append("x"))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: calls.append("tls"))
    ran = cli(sr, capsys, phase, "--base-url", "http://203.0.113.7", "--record-dir",
              str(tmp_path), *extra, env={**all_secret_env(), "STAGING_CONFIRM": "203.0.113.7"})
    assert ran.code == 1 and calls == []
    first = record(tmp_path, phase)["steps"][0]
    assert first["status"] == "FAIL" and "plain http" in first["detail"]


def test_an_embedded_credential_in_the_base_url_is_refused_not_used(sr, capsys, tmp_path):
    ran, found = run_smoke(sr, capsys, f"http://user:{OPERATOR_KEY}@127.0.0.1:1", tmp_path)
    assert ran.code == 1 and found["smoke.base_url"] == "FAIL"
    assert_no_secrets(ran.text, (tmp_path / "smoke.json").read_text())


# ---------------------------------------------------------------------------
# UNCHECKED, never inferred
# ---------------------------------------------------------------------------

def test_every_phase_with_nothing_provided_is_unchecked_exit_3(sr, capsys, tmp_path):
    for phase, args in [("smoke", []), ("webhook-test", ["--i-am-testing-staging"]),
                        ("restore-drill", [])]:
        ran = cli(sr, capsys, phase, "--record-dir", str(tmp_path), *args, env={})
        assert ran.code == 3, (phase, ran.text)
        found = set(statuses(tmp_path, phase).values())
        assert found == {"UNCHECKED"}, (phase, found)
    ran = cli(sr, capsys, "report", "--records", str(tmp_path / "empty"),
              "--out", str(tmp_path / "out"), env={})
    assert ran.code == 3


def test_smoke_against_a_server_without_a_register_key_is_exit_3_not_0(
        sr, capsys, tmp_path, live_api, monkeypatch):
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    ran, found = run_smoke(sr, capsys, live_api.url, tmp_path)
    assert found["smoke.register_key_402"] == "UNCHECKED"
    assert ran.code == 3 and "FAIL" not in found.values(), found


def test_webhook_test_without_its_prerequisites_sends_nothing(
        sr, capsys, tmp_path, live_api, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WHSEC)
    before = len(live_api.accounts.list_accounts())
    for env in ({"STAGING_CONFIRM": "127.0.0.1", "STAGING_STRIPE_MODE": "test"},   # no secret
                {"STRIPE_WEBHOOK_SECRET": WHSEC, "STAGING_STRIPE_MODE": "test"},   # no confirm
                {"STRIPE_WEBHOOK_SECRET": WHSEC, "STAGING_CONFIRM": "127.0.0.1"}):  # no mode
        ran = cli(sr, capsys, "webhook-test", "--base-url", live_api.url,
                  "--i-am-testing-staging", "--record-dir", str(tmp_path), env=env)
        assert ran.code == 3, ran.text
        assert "FAIL" not in statuses(tmp_path, "webhook-test").values()
    assert len(live_api.accounts.list_accounts()) == before


# ---------------------------------------------------------------------------
# smoke: the real service
# ---------------------------------------------------------------------------

@pytest.fixture()
def staging_like(live_api, monkeypatch):
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WHSEC)
    monkeypatch.setenv("STRIPE_SECRET_KEY", SK_TEST)
    monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", PRICES["ASSURANCE_PRICE_REGISTER"])
    monkeypatch.setenv("ASSURANCE_PRICE_CELL", PRICES["ASSURANCE_PRICE_CELL"])
    return live_api


def test_smoke_passes_against_the_real_service_and_leaves_only_https_steps_unchecked(
        sr, capsys, tmp_path, staging_like):
    _, register_header = staging_like.account("register@rehearsal.invalid", "register")
    env = full_env(REHEARSAL_REGISTER_KEY=register_header["X-API-Key"])
    ran, found = run_smoke(sr, capsys, staging_like.url, tmp_path, env,
                           "--expect-purchasable", "register,cell")
    assert found == {
        "smoke.base_url": "PASS", "smoke.healthz": "PASS", "smoke.plans": "PASS",
        "smoke.plans_purchasable": "PASS", "smoke.no_key_401": "PASS",
        "smoke.bad_key_401": "PASS", "smoke.register_key_402": "PASS", "smoke.cors": "PASS",
        "smoke.https_redirect": "UNCHECKED", "smoke.tls_cert": "UNCHECKED",
        "smoke.provided_secrets_absent": "PASS", "smoke.no_secret_shapes": "PASS",
    }, (found, ran.text)
    assert ran.code == 3        # plain http on loopback: TLS and redirect cannot be checked
    assert_no_secrets(ran.text, (tmp_path / "smoke.json").read_text())


def test_smoke_expectation_of_a_sku_that_is_not_purchasable_fails(
        sr, capsys, tmp_path, staging_like, monkeypatch):
    monkeypatch.delenv("ASSURANCE_PRICE_CELL")
    ran, found = run_smoke(sr, capsys, staging_like.url, tmp_path, {},
                           "--expect-purchasable", "register,cell")
    assert found["smoke.plans_purchasable"] == "FAIL" and ran.code == 1


def test_smoke_without_an_expectation_leaves_purchasability_unchecked(
        sr, capsys, tmp_path, staging_like):
    _, found = run_smoke(sr, capsys, staging_like.url, tmp_path, {})
    assert found["smoke.plans_purchasable"] == "UNCHECKED"


def test_smoke_reports_a_dead_server_as_a_failure_and_the_rest_as_not_attempted(
        sr, capsys, tmp_path):
    sock = fx.listening_socket()
    port = sock.getsockname()[1]
    sock.close()                                    # nothing listens here any more
    ran, found = run_smoke(sr, capsys, f"http://127.0.0.1:{port}", tmp_path)
    assert ran.code == 1 and found["smoke.healthz"] == "FAIL"
    assert found["smoke.plans"] == "UNCHECKED" and found["smoke.no_key_401"] == "UNCHECKED"


def test_a_redirect_is_reported_not_followed_to_another_host(sr, capsys, tmp_path):
    with serving(fake_service(redirect=True)) as url:
        run_smoke(sr, capsys, url, tmp_path)
    steps = {s["id"]: s for s in record(tmp_path, "smoke")["steps"]}
    assert steps["smoke.healthz"]["status"] == "FAIL"
    assert "302" in steps["smoke.healthz"]["detail"]            # answered, and not followed


def test_the_exit_code_never_reads_an_unknown_status_or_an_empty_run_as_a_pass(sr):
    step = sr.Step
    assert sr.exit_code([]) == 3
    assert sr.exit_code([step("a", "PASS", "")]) == 0
    assert sr.exit_code([step("a", "PASS", ""), step("b", "UNCHECKED", "")]) == 3
    assert sr.exit_code([step("a", "UNCHECKED", ""), step("b", "FAIL", "")]) == 1
    for bad in ("OK", "pass", "", "SKIPPED"):
        assert sr.exit_code([step("a", "PASS", ""), step("b", bad, "")]) == 1


# ---------------------------------------------------------------------------
# smoke: deliberately wrong servers must FAIL, one defect at a time
# ---------------------------------------------------------------------------

def good_service(**extra: Any) -> FastAPI:
    return fake_service(register_key=REGISTER_KEY_ENV, **extra)


def smoke_with(sr, capsys, tmp_path, app: FastAPI, *extra: str,
               register: bool = True) -> tuple[Ran, dict[str, str]]:
    env = {"REHEARSAL_REGISTER_KEY": REGISTER_KEY_ENV} if register else {}
    with serving(app) as url:
        return run_smoke(sr, capsys, url, tmp_path, env, *extra)


def test_the_fake_service_with_no_defect_passes_so_the_defect_tests_mean_something(
        sr, capsys, tmp_path):
    ran, found = smoke_with(sr, capsys, tmp_path, good_service())
    failed = {k: v for k, v in found.items() if v == "FAIL"}
    assert not failed, (failed, ran.text)


@pytest.mark.parametrize("defect,step", [
    ({"plans": "wrong_price"}, "smoke.plans"),
    ({"plans": "missing_tier"}, "smoke.plans"),
    ({"plans": "unlimited_cell"}, "smoke.plans"),
    ({"open": True}, "smoke.healthz"),
    ({"nokey_ok": True}, "smoke.no_key_401"),
    ({"bad_key_ok": True}, "smoke.bad_key_401"),
    ({"register_ok": True}, "smoke.register_key_402"),
    ({"register_401": True}, "smoke.register_key_402"),
    ({"cors": "wildcard"}, "smoke.cors"),
    ({"cors": "extra_origin"}, "smoke.cors"),
    ({"cors": "credentials"}, "smoke.cors"),
])
def test_each_defect_fails_exactly_its_own_step(sr, capsys, tmp_path, defect, step):
    ran, found = smoke_with(sr, capsys, tmp_path, good_service(**defect))
    assert found[step] == "FAIL", (step, found, ran.text)
    others = {k for k, v in found.items() if v == "FAIL"} - {step}
    assert not others, (others, found)
    assert ran.code == 1


def test_accepting_a_bad_key_does_not_hide_behind_the_no_key_pass(sr, capsys, tmp_path):
    _, found = smoke_with(sr, capsys, tmp_path, good_service(bad_key_ok=True))
    assert found["smoke.no_key_401"] == "PASS" and found["smoke.bad_key_401"] == "FAIL"


def test_a_secret_shaped_string_in_a_body_fails_even_when_no_secret_was_provided(
        sr, capsys, tmp_path):
    leaky = fake_service(leak="sk_test_" + "A" * 24)
    ran, found = smoke_with(sr, capsys, tmp_path, leaky, register=False)
    assert found["smoke.no_secret_shapes"] == "FAIL"
    assert found["smoke.provided_secrets_absent"] == "UNCHECKED"
    assert "A" * 24 not in ran.text


def test_a_provided_secret_in_a_header_is_found_too(sr, capsys, tmp_path):
    app = fake_service(register_key=REGISTER_KEY_ENV)

    @app.middleware("http")
    async def echo(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["x-debug"] = REGISTER_KEY_ENV
        return response

    ran, found = smoke_with(sr, capsys, tmp_path, app)
    assert found["smoke.provided_secrets_absent"] == "FAIL"
    assert_no_secrets(ran.text)


# ---------------------------------------------------------------------------
# TLS certificate expiry (read-only) against a real local TLS server
# ---------------------------------------------------------------------------

def make_cert(tmp: Path, *, days: float, name: str = "tls") -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=30))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]),
                critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp / f"{name}.crt", tmp / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert_path, key_path


@contextmanager
def tls_server(cert: Path, key: Path) -> Iterator[int]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = fx.listening_socket()
    sock.settimeout(0.2)
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=5)
        sock.close()


def tls_step(sr, capsys, tmp_path, port: int, env: dict[str, str], *extra: str) -> str:
    cli(sr, capsys, "smoke", "--base-url", f"https://127.0.0.1:{port}", "--record-dir",
        str(tmp_path), *extra, env=env)
    return statuses(tmp_path, "smoke")["smoke.tls_cert"]


def test_a_valid_trusted_certificate_far_from_expiry_passes(sr, capsys, tmp_path):
    cert, key = make_cert(tmp_path, days=90)
    with tls_server(cert, key) as port:
        assert tls_step(sr, capsys, tmp_path, port,
                        {"REHEARSAL_CA_BUNDLE": str(cert)}) == "PASS"


def test_a_certificate_close_to_expiry_fails(sr, capsys, tmp_path):
    cert, key = make_cert(tmp_path, days=3)
    with tls_server(cert, key) as port:
        assert tls_step(sr, capsys, tmp_path, port,
                        {"REHEARSAL_CA_BUNDLE": str(cert)}) == "FAIL"
        # the threshold is the founder's to set
        assert tls_step(sr, capsys, tmp_path, port, {"REHEARSAL_CA_BUNDLE": str(cert)},
                        "--min-cert-days", "1") == "PASS"


def test_an_expired_certificate_fails(sr, capsys, tmp_path):
    cert, key = make_cert(tmp_path, days=-2)
    with tls_server(cert, key) as port:
        assert tls_step(sr, capsys, tmp_path, port,
                        {"REHEARSAL_CA_BUNDLE": str(cert)}) == "FAIL"


def test_an_untrusted_certificate_fails_rather_than_being_skipped(sr, capsys, tmp_path):
    cert, key = make_cert(tmp_path, days=90)
    with tls_server(cert, key) as port:
        assert tls_step(sr, capsys, tmp_path, port, {}) == "FAIL"


def test_a_plain_http_target_leaves_tls_and_redirect_unchecked(sr, capsys, tmp_path):
    cli(sr, capsys, "smoke", "--base-url", "http://127.0.0.1:1", "--record-dir",
        str(tmp_path), env={})
    found = statuses(tmp_path, "smoke")
    assert found["smoke.tls_cert"] == "UNCHECKED" and found["smoke.https_redirect"] == "UNCHECKED"


# ---------------------------------------------------------------------------
# webhook-test
# ---------------------------------------------------------------------------

def webhook_env(**extra: str) -> dict[str, str]:
    return {"STRIPE_WEBHOOK_SECRET": WHSEC, "STAGING_CONFIRM": "127.0.0.1",
            "STAGING_STRIPE_MODE": "test", **extra}


def test_webhook_test_without_the_staging_flag_is_refused(
        sr, capsys, tmp_path, staging_like, monkeypatch):
    calls: list[str] = []
    real = httpx.Client.request
    monkeypatch.setattr(httpx.Client, "request",
                        lambda self, *a, **k: calls.append("x") or real(self, *a, **k))
    before = len(staging_like.accounts.list_accounts())
    ran = cli(sr, capsys, "webhook-test", "--base-url", staging_like.url,
              "--record-dir", str(tmp_path), env=webhook_env())
    assert ran.code == 1 and "REFUSED" in ran.err
    assert statuses(tmp_path, "webhook-test")["webhook.preconditions"] == "FAIL"
    assert calls == [] and len(staging_like.accounts.list_accounts()) == before


@pytest.mark.parametrize("confirm", ["localhost", "staging.example.test", "127.0.0.2", ""])
def test_webhook_test_refuses_a_mismatched_confirmation(
        sr, capsys, tmp_path, staging_like, confirm):
    before = len(staging_like.accounts.list_accounts())
    env = webhook_env(STAGING_CONFIRM=confirm)
    ran = cli(sr, capsys, "webhook-test", "--base-url", staging_like.url,
              "--i-am-testing-staging", "--record-dir", str(tmp_path), env=env)
    assert ran.code in (1, 3) and ran.code != 0
    found = statuses(tmp_path, "webhook-test")
    assert found["webhook.preconditions"] in ("FAIL", "UNCHECKED")
    assert "PASS" not in {v for k, v in found.items() if k != "webhook.preconditions"}
    assert len(staging_like.accounts.list_accounts()) == before


def test_webhook_test_refuses_a_production_host_even_when_confirmed(
        sr, capsys, tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(httpx.Client, "request", lambda self, *a, **k: calls.append("x"))
    monkeypatch.setattr(httpx.Client, "send", lambda self, *a, **k: calls.append("x"))
    for host in ("neuralbridge.io", "www.neuralbridge.io", "assurance-register.fly.dev"):
        ran = cli(sr, capsys, "webhook-test", "--base-url", f"https://{host}",
                  "--i-am-testing-staging", "--record-dir", str(tmp_path),
                  env=webhook_env(STAGING_CONFIRM=host))
        assert ran.code == 1 and "REFUSED" in ran.err, host
        assert statuses(tmp_path, "webhook-test")["webhook.preconditions"] == "FAIL"
    # and the founder can add hosts to the deny list without a code change
    ran = cli(sr, capsys, "webhook-test", "--base-url", "https://api.prod.example.test",
              "--i-am-testing-staging", "--record-dir", str(tmp_path),
              env=webhook_env(STAGING_CONFIRM="api.prod.example.test",
                              REHEARSAL_PRODUCTION_HOSTS="x.example.test,api.prod.example.test"))
    assert ran.code == 1
    assert calls == []


@pytest.mark.parametrize("secret", [
    "sk" "_test_notawebhooksecret1234567890", "plainsecretvalue12345678",
    "whsec_REPLACE", "whsec_ab12", "whsec" "_tooshort"])
def test_webhook_test_refuses_a_secret_that_is_not_a_usable_test_secret(
        sr, capsys, tmp_path, staging_like, secret):
    before = len(staging_like.accounts.list_accounts())
    ran = cli(sr, capsys, "webhook-test", "--base-url", staging_like.url,
              "--i-am-testing-staging", "--record-dir", str(tmp_path),
              env=webhook_env(STRIPE_WEBHOOK_SECRET=secret))
    assert ran.code == 1
    assert statuses(tmp_path, "webhook-test")["webhook.secret_is_test"] == "FAIL"
    assert len(staging_like.accounts.list_accounts()) == before
    assert secret not in ran.text


def test_webhook_test_hands_the_key_over_exactly_once_against_the_real_service(
        sr, capsys, tmp_path, staging_like):
    before = len(staging_like.accounts.list_accounts())
    ran = cli(sr, capsys, "webhook-test", "--base-url", staging_like.url,
              "--i-am-testing-staging", "--record-dir", str(tmp_path), env=webhook_env())
    found = statuses(tmp_path, "webhook-test")
    assert found == {**dict.fromkeys((
        "webhook.preconditions", "webhook.forged_rejected", "webhook.pending_before",
        "webhook.delivered", "webhook.replay_duplicate", "webhook.key_handover_once",
        "webhook.key_works", "webhook.cleanup"), "PASS"),
        "webhook.secret_is_test": "ATTESTED"}, (found, ran.text)
    assert ran.code == 3            # the secret's mode is the founder's statement, not measured
    accounts = staging_like.accounts.list_accounts()
    assert len(accounts) == before + 1
    created = accounts[-1] if accounts[-1].email.startswith("rehearsal-") else next(
        a for a in accounts if a.email.startswith("rehearsal-"))
    assert created.tier == "register" and created.email.endswith("@example.invalid")
    assert staging_like.accounts.active_key_count(created.id) == 0      # cleaned up
    assert_no_secrets(ran.text, (tmp_path / "webhook-test.json").read_text())
    assert "asr_" not in ran.text                                         # no key, even masked


def test_webhook_test_fails_when_the_service_holds_a_different_secret(
        sr, capsys, tmp_path, staging_like, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec" "_someotherthrowawaysecret99")
    before = len(staging_like.accounts.list_accounts())
    ran = cli(sr, capsys, "webhook-test", "--base-url", staging_like.url,
              "--i-am-testing-staging", "--record-dir", str(tmp_path), env=webhook_env())
    found = statuses(tmp_path, "webhook-test")
    assert ran.code == 1 and found["webhook.delivered"] == "FAIL"
    assert found["webhook.key_handover_once"] == "UNCHECKED"
    assert len(staging_like.accounts.list_accounts()) == before


FAKE_KEY = "asr_FAKEFAKEFAKEFAKEFAKEFAKE"


def fake_checkout(**d: Any) -> FastAPI:
    """Webhook and handover endpoints with switchable defects.

    ``app.state.log`` counts what the host was asked, so a test can see that the key was
    revoked whatever else went wrong.
    """
    app = FastAPI()
    state: dict[str, Any] = {"delivered": False, "claims": 0, "revoked": False,
                             "revoke_calls": 0, "me_calls": 0}
    app.state.log = state
    key = d.get("key", FAKE_KEY)

    @app.post("/v1/billing/webhook")
    async def webhook(request: Request) -> JSONResponse:
        sig = request.headers.get("stripe-signature", "")
        # a real service checks the HMAC; the stand-in does the same so a forged call is seen
        if not signed_with_the_right_secret(sig, await request.body()) \
                and not d.get("accept_forged"):
            return JSONResponse({"detail": {"error": "signature_rejected"}}, 400)
        if state["delivered"] and not d.get("regrant"):
            return JSONResponse({"duplicate": True}, 200)
        state["delivered"] = not d.get("never_ready")
        return JSONResponse({"handled": "checkout.session.completed",
                             "tier": d.get("tier", "register"),
                             "account_id": "acc_0123456789abcdef"}, 200)

    @app.get("/v1/checkout/complete")
    async def complete(session_id: str) -> JSONResponse:
        if not state["delivered"] and not d.get("early_key"):
            return JSONResponse({"detail": {"status": "pending"}}, 202)
        state["claims"] += 1
        if state["claims"] > 1 and not d.get("hand_over_twice"):
            return JSONResponse({"detail": {"status": "pending"}}, 202)
        return JSONResponse({"api_key": key, "tier": "register",
                             "account_id": "acc_0123456789abcdef"}, 200,
                            headers={} if d.get("cacheable") else {"Cache-Control": "no-store"})

    @app.get("/v1/me")
    async def me(request: Request) -> Any:
        state["me_calls"] += 1
        if d.get("me_hang") and state["me_calls"] == 1:
            await asyncio.sleep(4)
        if state["revoked"] or d.get("me_dead"):
            return JSONResponse({"detail": "Invalid or revoked API key."}, 401)
        if d.get("me_list"):
            return JSONResponse([1, 2, 3], 200)
        if d.get("me_echo_key"):
            return JSONResponse({"tier": key}, 200)
        return JSONResponse({"tier": d.get("me_tier", "register")}, 200)

    @app.post("/v1/keys/revoke")
    async def revoke() -> JSONResponse:
        state["revoke_calls"] += 1
        if d.get("revoke_500"):
            return JSONResponse({"detail": "boom"}, 500)
        state["revoked"] = not d.get("no_revoke")
        return JSONResponse({"revoked": True, "active_keys_remaining": 0}, 200)

    return app


def signed_with_the_right_secret(header: str, payload: bytes) -> bool:
    parts = dict(p.strip().split("=", 1) for p in header.split(",") if "=" in p)
    expected = hmac.new(WHSEC.encode(), f"{parts.get('t', '')}.".encode() + payload,
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


def run_webhook(sr, capsys, tmp_path, app: FastAPI, *extra: str,
                env: dict[str, str] | None = None) -> tuple[Ran, dict[str, str]]:
    with serving(app) as url:
        ran = cli(sr, capsys, "webhook-test", "--base-url", url, "--i-am-testing-staging",
                  "--record-dir", str(tmp_path), "--poll-seconds", "2", *extra,
                  env=env or webhook_env())
    return ran, statuses(tmp_path, "webhook-test")


def test_the_stand_in_checkout_service_passes_so_its_defects_mean_something(
        sr, capsys, tmp_path):
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout())
    assert found.pop("webhook.secret_is_test") == "ATTESTED"
    assert set(found.values()) == {"PASS"}, (found, ran.text)


@pytest.mark.parametrize("defect,step", [
    ({"accept_forged": True}, "webhook.forged_rejected"),
    ({"hand_over_twice": True}, "webhook.key_handover_once"),
    ({"never_ready": True}, "webhook.key_handover_once"),
    ({"cacheable": True}, "webhook.key_handover_once"),
    ({"no_revoke": True}, "webhook.cleanup"),
    ({"tier": "cell"}, "webhook.delivered"),
])
def test_webhook_test_fails_on_each_handover_defect(sr, capsys, tmp_path, defect, step):
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout(**defect))
    assert found[step] == "FAIL", (found, ran.text)
    assert ran.code == 1
    assert FAKE_KEY not in ran.text and "asr_FAKEFAKEFAKE" not in ran.text   # a prefix, never the key


# ---------------------------------------------------------------------------
# restore-drill, on real SQLite ledgers
# ---------------------------------------------------------------------------

def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


def make_data_dir(root: Path, *, tenants: int = 2, entries: int = 4,
                  shared: bool = True) -> list[str]:
    """A data volume as the service lays it out, written through the real stores."""
    root.mkdir(parents=True, exist_ok=True)
    store = AccountStore(root / "accounts.db")
    ids = []
    for i in range(tenants):
        acct = store.upsert_account(email=f"t{i}@rehearsal.invalid", tier="cell",
                                    stripe_customer_id=f"cus_t{i}")
        ledger = EvidenceLedger(tenant_path(root, acct.id))
        for n in range(entries):
            ledger.append(_ev(n), subject="CASE-1")
        ids.append(acct.id)
    if shared:
        EvidenceLedger(root / "art14-register.db").append(_ev(0))
    (root / "attestations").mkdir(exist_ok=True)
    if ids:
        (root / "attestations" / f"{ids[0]}.jsonl").write_text('{"x":1}\n')
    return ids


def tenant_path(root: Path, account_id: str) -> Path:
    path = root / "tenants" / f"{account_id}.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def drill(sr, capsys, tmp_path, *args: str) -> tuple[Ran, dict[str, str]]:
    rec = tmp_path / "rec"
    ran = cli(sr, capsys, "restore-drill", "--record-dir", str(rec), *args, env={})
    return ran, statuses(rec, "restore-drill")


def test_restore_drill_passes_on_a_real_data_dir_and_does_not_touch_it(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    ids = make_data_dir(data)
    before = {p.name: sha(p) for p in data.rglob("*.db")}
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data),
                       "--work-dir", str(tmp_path / "work"))
    assert ran.code == 0, (found, ran.text)
    assert found == dict.fromkeys((
        "restore.source", "restore.backup", "restore.wipe_restore", "restore.verify",
        "restore.counts_match", "restore.negative_control", "restore.source_untouched"), "PASS")
    assert {p.name: sha(p) for p in data.rglob("*.db")} == before
    assert len(ids) == 2
    assert not (tmp_path / "work").exists() or not any((tmp_path / "work").iterdir())


def test_restore_drill_fails_on_a_tampered_backup_even_though_the_counts_match(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    ids = make_data_dir(data)
    backup = tmp_path / "bk"
    shutil.copytree(data, backup)
    db = sqlite3.connect(backup / "tenants" / f"{ids[0]}.db")
    db.execute("UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":9') WHERE seq = 2")
    db.commit()
    db.close()
    ran, found = drill(sr, capsys, tmp_path, "--backup-dir", str(backup),
                       "--data-dir", str(data))
    assert ran.code == 1
    assert found["restore.verify"] == "FAIL"
    assert found["restore.counts_match"] == "PASS"       # the chain, not the count, caught it


def test_restore_drill_fails_on_a_truncated_backup_whose_chain_still_verifies(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    ids = make_data_dir(data)
    backup = tmp_path / "bk"
    shutil.copytree(data, backup)
    db = sqlite3.connect(backup / "tenants" / f"{ids[1]}.db")
    db.execute("DELETE FROM chain WHERE seq = (SELECT MAX(seq) FROM chain)")
    db.commit()
    db.close()
    ran, found = drill(sr, capsys, tmp_path, "--backup-dir", str(backup),
                       "--data-dir", str(data))
    assert found["restore.verify"] == "PASS"             # a shorter chain is still a chain
    assert found["restore.counts_match"] == "FAIL" and ran.code == 1


@pytest.mark.parametrize("damage", ["garbage", "no_accounts", "orphan"])
def test_restore_drill_fails_on_a_damaged_backup(sr, capsys, tmp_path, damage):
    data = tmp_path / "data"
    ids = make_data_dir(data)
    backup = tmp_path / "bk"
    shutil.copytree(data, backup)
    if damage == "garbage":
        (backup / "tenants" / f"{ids[0]}.db").write_bytes(b"not a database" * 100)
    elif damage == "no_accounts":
        (backup / "accounts.db").unlink()
    else:
        shutil.copy(backup / "tenants" / f"{ids[0]}.db",
                    backup / "tenants" / "acc_0123456789abcdef.db")
    ran, found = drill(sr, capsys, tmp_path, "--backup-dir", str(backup),
                       "--data-dir", str(data))
    assert ran.code == 1 and "FAIL" in found.values(), found


def test_restore_drill_without_a_source_to_compare_leaves_counts_unchecked(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    make_data_dir(data)
    ran, found = drill(sr, capsys, tmp_path, "--backup-dir", str(data))
    assert found["restore.verify"] == "PASS" and found["restore.counts_match"] == "UNCHECKED"
    assert ran.code == 3


def test_restore_drill_fails_on_a_missing_or_empty_data_dir(sr, capsys, tmp_path):
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(tmp_path / "nowhere"))
    assert ran.code == 1 and found["restore.source"] == "FAIL"
    empty = tmp_path / "empty"
    empty.mkdir()
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(empty))
    assert ran.code == 1 and "FAIL" in found.values()


def test_restore_drill_on_ledgers_with_no_entries_proves_nothing_and_says_so(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    make_data_dir(data, tenants=1, entries=0, shared=False)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    assert ran.code == 3 and "FAIL" not in found.values(), (found, ran.text)
    assert found["restore.counts_match"] == "UNCHECKED"


def test_restore_drill_refuses_to_wipe_the_data_dir_it_was_asked_to_protect(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    make_data_dir(data)
    before = {p.name: sha(p) for p in data.rglob("*.db")}
    for work in (data, data / "tenants", tmp_path):
        ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data),
                           "--work-dir", str(work))
        assert ran.code == 1 and "REFUSED" in ran.err, work
        assert {p.name: sha(p) for p in data.rglob("*.db")} == before
    assert (tmp_path / "data" / "accounts.db").exists()


def test_the_negative_control_notices_a_verifier_that_cannot_see_tampering(
        sr, capsys, tmp_path, monkeypatch):
    data = tmp_path / "data"
    make_data_dir(data)
    real = sr.restore_check.verify
    seen: list[Path] = []

    def blind(root: Path) -> dict[str, Any]:
        seen.append(root)
        result = real(root)
        if len(seen) > 1:                       # the control run: pretend nothing is wrong
            return {**result, "ok": True, "problems": []}
        return result

    monkeypatch.setattr(sr.restore_check, "verify", blind)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    assert found["restore.negative_control"] == "FAIL" and ran.code == 1


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def phase_steps(sr: ModuleType, phase: str, status: str = "PASS") -> list[dict[str, str]]:
    return [{"id": i, "status": status, "detail": "ok"} for i in sr.STEP_IDS[phase]]


def iso(hours_ago: float = 0.0) -> str:
    when = dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_record(sr: ModuleType, rec: Path, phase: str,
                 steps: list[dict[str, Any]] | None = None, *,
                 host: str = "staging.example.test", hours_ago: float = 0.0,
                 state: str = "complete", version: str | None = None,
                 run_id: str | None = None) -> None:
    """A phase record as the tool itself would leave it (complete, current, every step)."""
    rec.mkdir(parents=True, exist_ok=True)
    (rec / f"{phase}.json").write_text(json.dumps({
        "tool": "staging_rehearsal", "script_version": version or sr.VERSION,
        "run_id": run_id or f"run-{phase}", "phase": phase, "state": state,
        "generated_at": iso(hours_ago), "target_host": host,
        "steps": phase_steps(sr, phase) if steps is None else steps,
        "observations": []}), encoding="utf-8")


ALL_PHASES = ("config-check", "smoke", "webhook-test", "restore-drill")


def all_records(sr: ModuleType, rec: Path, **kw: Any) -> None:
    for phase in ALL_PHASES:
        write_record(sr, rec, phase, **kw)


def report(sr, capsys, rec: Path, out: Path, *extra: str) -> Ran:
    return cli(sr, capsys, "report", "--records", str(rec), "--out", str(out), *extra, env={})


def test_the_report_lists_every_phase_and_what_stayed_unchecked(sr, capsys, tmp_path):
    rec, out = tmp_path / "rec", tmp_path / "out"
    write_record(sr, rec, "config-check")
    smoke = phase_steps(sr, "smoke")
    smoke[-3]["status"], smoke[-3]["detail"] = "UNCHECKED", "plain http"
    assert smoke[-3]["id"] == "smoke.tls_cert"
    write_record(sr, rec, "smoke", smoke)
    ran = report(sr, capsys, rec, out)
    assert ran.code == 3
    data = json.loads((out / "rehearsal-report.json").read_text())
    markdown = (out / "rehearsal-report.md").read_text()
    assert data["overall"] == "UNCHECKED" and data["exit_code"] == 3
    ids = {s["id"]: s["status"] for s in data["steps"]}
    assert ids["smoke.tls_cert"] == "UNCHECKED"
    assert ids["webhook-test.not_run"] == "UNCHECKED" and ids["restore-drill.not_run"] == "UNCHECKED"
    for needle in ("smoke.tls_cert", "webhook-test.not_run", "UNCHECKED"):
        assert needle in markdown
    assert "nothing in this repository has been deployed" in markdown.lower()
    assert set(data["unchecked"]) >= {"smoke.tls_cert", "webhook-test.not_run"}
    assert data["target_host"] == "staging.example.test"


def test_the_report_is_exit_0_only_when_every_step_of_every_phase_passed(sr, capsys, tmp_path):
    rec, out = tmp_path / "rec", tmp_path / "out"
    all_records(sr, rec)
    assert report(sr, capsys, rec, out).code == 0
    smoke = phase_steps(sr, "smoke")
    smoke[0]["status"] = "FAIL"
    smoke[1]["status"] = "UNCHECKED"
    write_record(sr, rec, "smoke", smoke)
    assert report(sr, capsys, rec, out).code == 1


@pytest.mark.parametrize("status", ["OK", "pass", "", "SKIPPED", None])
def test_a_record_with_an_unknown_status_is_never_read_as_a_pass(sr, capsys, tmp_path, status):
    rec, out = tmp_path / "rec", tmp_path / "out"
    all_records(sr, rec)
    smoke = phase_steps(sr, "smoke")
    smoke[0]["status"] = status
    write_record(sr, rec, "smoke", smoke)
    assert report(sr, capsys, rec, out).code == 1


def test_a_corrupt_or_empty_record_is_a_failure_not_a_missing_phase(sr, capsys, tmp_path):
    rec, out = tmp_path / "rec", tmp_path / "out"
    all_records(sr, rec)
    (rec / "smoke.json").write_text("{not json")
    assert report(sr, capsys, rec, out).code == 1
    write_record(sr, rec, "smoke", [])
    assert report(sr, capsys, rec, out).code == 1


def test_the_report_redacts_a_secret_that_got_into_a_record(sr, capsys, tmp_path):
    rec, out = tmp_path / "rec", tmp_path / "out"
    all_records(sr, rec)
    smoke = phase_steps(sr, "smoke")
    smoke[0] = {"id": smoke[0]["id"], "status": "FAIL",
                "detail": f"echoed {SK_TEST} and {OPERATOR_KEY} and sk_test_{'Q' * 20} "
                          f"and whsec_{'W' * 20}"}
    write_record(sr, rec, "smoke", smoke)
    ran = cli(sr, capsys, "report", "--records", str(rec), "--out", str(out), env=full_env())
    for path in out.glob("*"):
        text = path.read_text(encoding="utf-8")
        assert_no_secrets(text)
        assert "Q" * 20 not in text and "W" * 20 not in text
    assert_no_secrets(ran.text)
    assert "[REDACTED]" in (out / "rehearsal-report.md").read_text()


def test_phase_records_feed_the_report_end_to_end(sr, capsys, tmp_path, staging_like):
    rec, out = tmp_path / "rec", tmp_path / "out"
    cli(sr, capsys, "config-check", "--record-dir", str(rec), env=full_env())
    run_smoke(sr, capsys, staging_like.url, rec, {})
    ran = report(sr, capsys, rec, out)
    data = json.loads((out / "rehearsal-report.json").read_text())
    assert ran.code == 3 and data["steps"], ran.text
    assert any(s["id"] == "smoke.healthz" and s["status"] == "PASS" for s in data["steps"])
    assert any(s["id"] == "webhook-test.not_run" for s in data["steps"])
    assert "config.allow_unauthenticated" in data["attested"]


# ---------------------------------------------------------------------------
# the real command line, in a fresh interpreter, from anywhere
# ---------------------------------------------------------------------------

def test_the_script_runs_as_a_program_without_pythonpath_and_never_exits_0_on_nothing(
        tmp_path):
    result = subprocess.run(  # noqa: S603  (our own script, fixed argv)
        [sys.executable, str(SCRIPT), "config-check"], cwd=tmp_path, capture_output=True,
        text=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
    assert result.returncode == 3, result.stdout + result.stderr
    assert "UNCHECKED" in result.stdout
    result = subprocess.run(  # noqa: S603  (our own script, fixed argv)
        [sys.executable, str(SCRIPT), "config-check"], cwd=tmp_path, capture_output=True,
        text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "STRIPE_SECRET_KEY": "sk_live_" + "x" * 24})
    assert result.returncode == 1 and "REFUSED" in result.stderr
    assert "sk_live_" + "x" * 24 not in result.stdout + result.stderr


def test_the_time_the_tool_takes_is_bounded_by_its_own_timeouts(sr, capsys, tmp_path):
    started = time.monotonic()
    cli(sr, capsys, "smoke", "--base-url", "http://127.0.0.1:1", "--record-dir",
        str(tmp_path), "--timeout", "2", env={})
    assert time.monotonic() - started < 30
