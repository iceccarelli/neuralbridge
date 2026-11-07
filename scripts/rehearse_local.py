#!/usr/bin/env python3
"""LOCAL buyer-path rehearsal: the real API on loopback, zero real credentials.

    python scripts/rehearse_local.py [--record-dir DIR] [--keep] [--with-site]

THIS IS A LOCAL REHEARSAL, NOT A HOSTED STAGING PROOF. It proves what the code does when Stripe-
shaped events reach the real HTTP service. It does not prove that Stripe sends those events, that
a hosted host's TLS, DNS, proxy, volume or secrets are right, or that a real card was charged:
nothing here touches Stripe, a real host or a real credential. ``scripts/staging_rehearsal.py`` is
the tool for the hosted host and needs the founder's test-mode secrets; this one needs none.

What it starts: ``uvicorn assurance.api.service:app`` (one worker, like the shipped image) on
127.0.0.1 with a webhook signing secret and an operator key generated for this run and held only in
this process's memory and the child's environment. The environment is scrubbed first: every
``STRIPE_*``, ``ASSURANCE_*`` and ``NEURALBRIDGE_*`` variable of the caller is dropped, so no
price, Stripe key or real secret can reach the child, and the run is refused if the caller's
environment holds a ``*_live_*`` key shape.

What it proves (each line of the record says PASS or FAIL with what was observed):
  plans/checkout   catalogue has no purchasable price; POST /v1/checkout refuses 503 honestly
  webhook          forged / missing / tampered / stale-timestamp signatures are rejected, accepted
                   when valid, a replay is a no-op, an out-of-order event is held then applied,
                   a stale one is ignored
  claim            the key is claimable once, only with the claim token, never twice
  entitlements     no key 401, bad key 401, authenticated-but-unentitled 402, entitled 201
  lifecycle        renewal, payment failure (past_due, still entitled), recovery, cancellation
                   (writes 402, read/verify/export of own evidence still 200), key revocation
  restore          backup -> verify -> restore into a NEW directory -> a second API process on the
                   restored volume serves the same entitlements and the same verifying ledger

One thing is a fixture: ``POST /v1/checkout`` cannot complete without a Stripe price, so the
claim token that it would have issued is registered with the account store directly. Everything
the API does with that token afterwards is the real code.

Exit: 0 every step PASSed; 1 a step FAILed; 2 could not run. The record is redacted and contains
no key, token or secret; it is checked for them before it is written (0600, in a 0700 directory).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import httpx  # noqa: E402

from assurance.billing.accounts import AccountStore  # noqa: E402
from assurance.evidence import EvidenceLedger, restore_check  # noqa: E402

LABEL = "local rehearsal, not a hosted staging proof"
LIVE_SHAPES = re.compile(r"(sk|rk|pk|ek)_live_|whsec_live")
PASS, FAIL = "PASS", "FAIL"


class Rehearsal:
    def __init__(self) -> None:
        self.steps: list[dict[str, str]] = []
        self.secrets: list[str] = []

    def check(self, step: str, ok: bool, observed: str) -> bool:
        self.steps.append({"step": step, "status": PASS if ok else FAIL, "observed": observed})
        print(f"[{PASS if ok else FAIL}] {step}: {observed}", file=sys.stderr)
        return ok

    def hide(self, value: str) -> str:
        if value and len(value) > 6:
            self.secrets.append(value)
        return value

    def scrub(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, "[REDACTED]")
        return text


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Api:
    """A real uvicorn process on loopback, started with a scrubbed environment."""

    def __init__(self, data: Path, webhook_secret: str, operator_key: str, log: Path) -> None:
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("STRIPE_", "ASSURANCE_", "NEURALBRIDGE_", "REHEARSAL_"))}
        env.update({
            "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1",
            "ASSURANCE_HOST": "127.0.0.1",
            "ASSURANCE_API_KEYS": operator_key,
            "STRIPE_WEBHOOK_SECRET": webhook_secret,        # generated for this run, not Stripe's
            "ASSURANCE_LEDGER": str(data / "art14-register.db"),
            "ASSURANCE_ACCOUNTS": str(data / "accounts.db"),
            "ASSURANCE_TENANT_LEDGERS": str(data / "tenants"),
            "ASSURANCE_ATTEST_LOGS": str(data / "attestations"),
            "ASSURANCE_SUPPLIER_FEEDS": str(data / "supplier-feeds"),
            "ASSURANCE_MARKETING_URL": "http://127.0.0.1:1",   # never contacted: no checkout runs
        })
        self.log = log
        self._logf = open(log, "wb")  # noqa: SIM115
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "uvicorn", "assurance.api.service:app", "--host", "127.0.0.1",
             "--port", str(self.port), "--workers", "1", "--log-level", "warning"],
            env=env, stdout=self._logf, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("the API exited at start-up:\n" + log.read_text()[-1500:])
            try:
                if httpx.get(self.base + "/livez", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.2)
        raise RuntimeError("the API did not become ready")

    def stop(self) -> None:
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
        self._logf.close()


def sign(payload: bytes, secret: str, at: int | None = None) -> str:
    stamp = str(int(time.time()) if at is None else at)
    mac = hmac.new(secret.encode(), f"{stamp}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={stamp},v1={mac}"


def event(event_id: str, kind: str, obj: dict[str, Any], created: int) -> dict[str, Any]:
    return {"id": event_id, "type": kind, "created": created, "data": {"object": obj}}


def checkout_obj(session: str, customer: str, tier: str) -> dict[str, Any]:
    return {"id": session, "payment_status": "paid", "customer": customer,
            "subscription": f"sub_{customer}",
            "customer_details": {"email": f"{customer}@example.invalid"},
            "metadata": {"tier": tier, "company": f"Local Rehearsal {customer}"}}


def subscription_obj(customer: str, status: str, tier: str = "register") -> dict[str, Any]:
    return {"id": f"sub_{customer}", "customer": customer, "status": status,
            "metadata": {"tier": tier}, "items": {"data": []}}


SIGNAL = {"received_at": "2026-11-01T10:00:00Z", "channel": "other",
          "description": "local rehearsal", "product_name": "probe", "version": "1",
          "actor": {"identifier": "rehearsal@example.invalid"}}


def run(args: argparse.Namespace) -> int:
    live = [k for k, v in os.environ.items() if LIVE_SHAPES.search(v) or "LIVE" in k.upper()
            and k.upper().startswith(("STRIPE", "ASSURANCE_PAYG"))]
    if live:
        print("refusing to run: the environment holds live-mode credentials ("
              + ", ".join(sorted(live)) + "); this rehearsal needs none", file=sys.stderr)
        return 2

    rec = Rehearsal()
    work = Path(tempfile.mkdtemp(prefix="rehearse-local-"))
    os.chmod(work, 0o700)
    data = work / "data"
    data.mkdir()
    webhook_secret = rec.hide("whsec_local_" + secrets.token_hex(16))
    operator_key = rec.hide("op-local-" + secrets.token_urlsafe(32))
    AccountStore(data / "accounts.db")
    apis: list[Api] = []
    try:
        api = Api(data, webhook_secret, operator_key, work / "api-1.log")
        apis.append(api)
        accounts = AccountStore(data / "accounts.db")
        t0 = int(time.time())

        def hook(client: httpx.Client, ev: dict[str, Any], *, secret: str = webhook_secret,
                 header: str | None = None, body: bytes | None = None) -> httpx.Response:
            raw = body if body is not None else json.dumps(ev).encode()
            return client.post("/v1/billing/webhook", content=raw, headers={
                "content-type": "application/json",
                "stripe-signature": header if header is not None else sign(raw, secret)})

        with httpx.Client(base_url=api.base, timeout=30) as c:
            # ---- plans and checkout --------------------------------------------------------
            plans = c.get("/v1/plans").json()
            rec.check("plans.none_purchasable", c.get("/v1/plans").status_code == 200
                      and not any(p.get("purchasable") for p in plans),
                      f"{len(plans)} plans, purchasable={[p['tier'] for p in plans if p.get('purchasable')]}")
            for tier, want in (("register", "price_not_configured"), ("cell", "price_not_configured"),
                               ("payg", "payg_not_available")):
                r = c.post("/v1/checkout", json={"tier": tier, "email": "b@example.invalid",
                                                 "company": "Buyer"})
                err = (r.json().get("detail") or {}).get("error") if r.status_code != 422 else ""
                rec.check(f"checkout.{tier}_refused_honestly", r.status_code == 503 and err == want,
                          f"HTTP {r.status_code} {err}; no Stripe call is possible (no key set)")

            # ---- webhook signature handling -----------------------------------------------
            good = event("evt_1", "checkout.session.completed",
                         checkout_obj("cs_local_1", "cus_local_1", "register"), t0)
            raw = json.dumps(good).encode()
            cases = {
                "missing_header": dict(header=""),
                "wrong_secret": dict(secret="whsec_not_the_secret"),
                "tampered_body": dict(header=sign(raw, webhook_secret), body=raw.replace(b"register", b"cell")),
                "stale_timestamp": dict(header=sign(raw, webhook_secret, at=t0 - 3600)),
                "malformed_header": dict(header="t=abc,v1=zz"),
            }
            for name, kw in cases.items():
                r = hook(c, good, **kw)  # type: ignore[arg-type]
                rec.check(f"webhook.reject_{name}",
                          r.status_code == 400 and (r.json().get("detail") or {}).get("error")
                          == "signature_rejected", f"HTTP {r.status_code}")
            rec.check("webhook.rejections_granted_nothing", accounts.list_accounts() == [],
                      f"{len(accounts.list_accounts())} accounts after 5 rejected events")

            # ---- claim before payment ------------------------------------------------------
            claim = rec.hide(secrets.token_urlsafe(32))
            accounts.register_checkout_claim("cs_local_1", claim)     # FIXTURE, see module docstring
            r = c.post("/v1/checkout/complete", json={"session_id": "cs_local_1", "claim_token": claim})
            rec.check("claim.pending_before_webhook", r.status_code == 202,
                      f"HTTP {r.status_code} (nothing issued before a signed event)")

            # ---- out of order: a later event for an unknown customer is held --------------
            r = hook(c, event("evt_sub_early", "customer.subscription.updated",
                              subscription_obj("cus_local_1", "active"), t0 + 10))
            rec.check("webhook.out_of_order_held", r.status_code == 200
                      and r.json().get("result") == "held_until_checkout", f"HTTP {r.status_code} {r.json()}")

            # ---- the valid checkout --------------------------------------------------------
            r = hook(c, good)
            body = r.json()
            rec.check("webhook.accept_valid_checkout", r.status_code == 200
                      and body.get("tier") == "register" and body.get("account_id", "").startswith("acc_"),
                      f"HTTP {r.status_code} tier={body.get('tier')}")
            account_id = body.get("account_id", "")
            r = hook(c, good)
            rec.check("webhook.replay_is_a_noop", r.status_code == 200 and r.json().get("duplicate") is True,
                      f"HTTP {r.status_code} {r.json()}")
            r = hook(c, event("evt_1_again", "checkout.session.completed",
                              checkout_obj("cs_local_1", "cus_local_1", "register"), t0 + 1))
            rec.check("webhook.same_session_new_event_is_a_noop",
                      r.status_code == 200 and r.json().get("duplicate") is True, f"HTTP {r.status_code}")
            r = hook(c, event("evt_stale", "customer.subscription.updated",
                              subscription_obj("cus_local_1", "active"), t0 - 500))
            rec.check("webhook.stale_event_ignored",
                      r.status_code == 200 and r.json().get("result") == "ignored_stale",
                      f"HTTP {r.status_code} {r.json()}")

            # ---- key handover: once, only with the token -----------------------------------
            r = c.post("/v1/checkout/complete", json={"session_id": "cs_local_1", "claim_token": "x" * 40})
            rec.check("claim.wrong_token_403_and_nothing_consumed", r.status_code == 403, f"HTTP {r.status_code}")
            r = c.post("/v1/checkout/complete", json={"session_id": "cs_local_1", "claim_token": claim})
            key = rec.hide(r.json().get("api_key", "")) if r.status_code == 200 else ""
            rec.check("claim.collected_once_with_token", r.status_code == 200 and bool(key)
                      and r.headers.get("cache-control", "").startswith("no-store"),
                      f"HTTP {r.status_code}; key shown once, response no-store")
            r = c.post("/v1/checkout/complete", json={"session_id": "cs_local_1", "claim_token": claim})
            rec.check("claim.second_collection_410", r.status_code == 410, f"HTTP {r.status_code}")
            H = {"X-API-Key": key}

            # ---- entitlement semantics -----------------------------------------------------
            r = c.post("/v1/cases/rehearsal-1/signal", json=SIGNAL)
            rec.check("entitlement.no_key_401", r.status_code == 401, f"HTTP {r.status_code}")
            r = c.post("/v1/cases/rehearsal-1/signal", json=SIGNAL, headers={"X-API-Key": "nb_" + "0" * 40})
            rec.check("entitlement.bad_key_401", r.status_code == 401, f"HTTP {r.status_code}")
            r = c.post("/v1/cases/rehearsal-1/signal", json=SIGNAL, headers=H)
            rec.check("entitlement.register_key_writes_201", r.status_code == 201, f"HTTP {r.status_code}")
            r = c.post("/v1/ledger/attest", json={}, headers=H)
            rec.check("entitlement.register_key_on_cell_route_402", r.status_code == 402,
                      f"HTTP {r.status_code} {(r.json().get('detail') or {}).get('error') if r.headers.get('content-type','').startswith('application/json') else ''}")
            r = c.get("/v1/me", headers=H).json()
            rec.check("entitlement.me_reports_register_active",
                      r.get("tier") == "register" and r["account"]["status"] == "active"
                      and r["account"]["source"] == "stripe", f"tier={r.get('tier')} status={r['account']['status']}")

            # ---- renewal, payment failure, recovery ------------------------------------------
            r = hook(c, event("evt_renew", "customer.subscription.updated",
                              subscription_obj("cus_local_1", "active"), t0 + 100))
            rec.check("lifecycle.renewal_applied", r.status_code == 200, f"HTTP {r.status_code} {r.json().get('result')}")
            r = hook(c, event("evt_fail", "invoice.payment_failed",
                              {"id": "in_1", "customer": "cus_local_1", "subscription": "sub_cus_local_1"}, t0 + 200))
            me = c.get("/v1/me", headers=H).json()
            w = c.post("/v1/cases/rehearsal-pd/signal", json=SIGNAL, headers=H)
            rec.check("lifecycle.past_due_flagged_but_entitled",
                      r.status_code == 200 and me["account"]["status"] == "past_due" and w.status_code == 201,
                      f"status={me['account']['status']}, write HTTP {w.status_code}")
            r = hook(c, event("evt_recover", "customer.subscription.updated",
                              subscription_obj("cus_local_1", "active"), t0 + 300))
            me = c.get("/v1/me", headers=H).json()
            rec.check("lifecycle.recovery_from_past_due", r.status_code == 200
                      and me["account"]["status"] == "active" and me["tier"] == "register",
                      f"status={me['account']['status']} tier={me['tier']}")
            r = hook(c, event("evt_late_fail", "invoice.payment_failed",
                              {"id": "in_0", "customer": "cus_local_1", "subscription": "sub_cus_local_1"}, t0 + 150))
            me = c.get("/v1/me", headers=H).json()
            rec.check("lifecycle.late_old_failure_does_not_undo_recovery",
                      r.status_code == 200 and me["account"]["status"] == "active",
                      f"status={me['account']['status']} (a failure older than the recovery)")

            # ---- a second customer: key revocation -----------------------------------------
            claim2 = rec.hide(secrets.token_urlsafe(32))
            accounts.register_checkout_claim("cs_local_2", claim2)
            hook(c, event("evt_c2", "checkout.session.completed",
                          checkout_obj("cs_local_2", "cus_local_2", "register"), t0 + 20))
            r = c.post("/v1/checkout/complete", json={"session_id": "cs_local_2", "claim_token": claim2})
            key2 = rec.hide(r.json().get("api_key", ""))
            ok_before = c.post("/v1/cases/c2-1/signal", json=SIGNAL, headers={"X-API-Key": key2}).status_code
            r = c.post("/v1/keys/revoke", headers={"X-API-Key": key2})
            after = c.post("/v1/cases/c2-1/signal", json=SIGNAL, headers={"X-API-Key": key2}).status_code
            rec.check("lifecycle.key_revocation_is_immediate",
                      ok_before == 201 and r.status_code == 200 and r.json().get("revoked") is True and after == 401,
                      f"before={ok_before}, revoke HTTP {r.status_code}, after={after}")
            other = c.get("/v1/cases", headers=H)
            rec.check("tenancy.accounts_do_not_see_each_other",
                      other.status_code == 200 and "c2-1" not in other.json(), f"{other.json()}")

            # ---- cancellation: lapsed read-only access --------------------------------------
            r = hook(c, event("evt_cancel", "customer.subscription.deleted",
                              subscription_obj("cus_local_1", "canceled"), t0 + 400))
            w = c.post("/v1/cases/rehearsal-2/signal", json=SIGNAL, headers=H)
            lst = c.get("/v1/cases", headers=H)
            one = c.get("/v1/cases/rehearsal-1", headers=H)
            ver = c.get("/v1/ledger/verify", headers=H)
            exp = c.get("/v1/cases/rehearsal-1/export", headers=H)
            rec.check("lifecycle.cancelled_writes_402", r.status_code == 200 and w.status_code == 402,
                      f"cancel HTTP {r.status_code}, write HTTP {w.status_code}")
            rec.check("lifecycle.cancelled_can_still_read_verify_export",
                      lst.status_code == 200 and "rehearsal-1" in lst.json() and one.status_code == 200
                      and ver.status_code == 200 and exp.status_code == 200
                      and lst.headers.get("x-assurance-access") == "evidence-readout-only",
                      f"list {lst.status_code}, case {one.status_code}, verify {ver.status_code}, "
                      f"export {exp.status_code}, header={lst.headers.get('x-assurance-access')}")
            r = c.get("/v1/cases", headers={"X-API-Key": key2})
            rec.check("lifecycle.revoked_key_stays_dead_after_unrelated_events", r.status_code == 401,
                      f"HTTP {r.status_code}")

        api.stop()

        # ---- backup -> verify -> restore -> serve from the restored volume -------------------
        bk = work / "backup"
        restore_check.backup(data, bk)
        v = restore_check.verify(bk)
        rec.check("restore.backup_verifies", v["status"] == "ok", f"status={v['status']} checked={v['checked']}")
        restored = work / "restored"
        info = restore_check.restore(bk, restored)
        rec.check("restore.restore_verified_before_move", bool(info["manifest_sha256"]), "staged copy matched the manifest")
        try:
            restore_check.restore(bk, restored)
            refused = False
        except restore_check.RestoreRefused:
            refused = True
        rec.check("restore.refuses_to_overwrite_the_restored_volume", refused, "second restore refused")
        led = EvidenceLedger(restored / "tenants" / f"{account_id}.db", mint_id=False)
        ok, problems = led.verify_chain()
        rec.check("restore.ledger_chain_verifies", ok and len(led.entries()) == 2, f"{len(led.entries())} entries, problems={problems}")

        api2 = Api(restored, webhook_secret, operator_key, work / "api-2.log")
        apis.append(api2)
        with httpx.Client(base_url=api2.base, timeout=30) as c2:
            lst = c2.get("/v1/cases", headers=H)
            w = c2.post("/v1/cases/rehearsal-3/signal", json=SIGNAL, headers=H)
            dead = c2.get("/v1/cases", headers={"X-API-Key": key2})
            rec.check("restore.restored_volume_serves_same_entitlements",
                      lst.status_code == 200 and "rehearsal-1" in lst.json() and w.status_code == 402
                      and dead.status_code == 401,
                      f"lapsed read {lst.status_code}, lapsed write {w.status_code}, revoked key {dead.status_code}")
        api2.stop()

        if args.with_site:
            site_step(rec, work)
    except Exception as exc:  # noqa: BLE001
        rec.check("rehearsal.ran_to_completion", False, f"{type(exc).__name__}: {rec.scrub(str(exc))[:300]}")
    finally:
        for a in apis:
            a.stop()
        logs = "".join(p.read_text(errors="replace") for p in work.glob("api-*.log"))
        rec.check("logs.no_secret_in_server_output",
                  not any(s in logs for s in rec.secrets) and "Traceback" not in logs,
                  "server logs hold no key, token or secret and no traceback")

    failed = [s for s in rec.steps if s["status"] != PASS]
    record = {
        "label": LABEL,
        "rehearsal": "scripts/rehearse_local.py",
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "result": "PASS" if not failed else "FAIL",
        "steps": rec.steps,
        "not_established": [
            "Anything about Stripe itself: no request left this machine and no Stripe API was called; "
            "the events are Stripe-SHAPED fixtures signed with a secret generated for this run.",
            "A hosted host: TLS, DNS, the reverse proxy, the persistent volume, real secrets, CORS.",
            "Checkout session creation (needs a Stripe price and key); the claim token was registered "
            "with the account store directly.",
            "The marketing site's checkout success page (see --with-site).",
        ],
    }
    text = rec.scrub(json.dumps(record, indent=2))
    assert not any(s in text for s in rec.secrets)
    out = Path(args.record_dir)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    target = out / "local-rehearsal.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text + "\n")
    print(f"{record['result']}: {len(rec.steps) - len(failed)}/{len(rec.steps)} steps. {LABEL}. "
          f"Record: {target}", file=sys.stderr)
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if not failed else 1


def site_step(rec: Rehearsal, work: Path) -> None:
    """Optional: build and serve the Next.js site against the local API and fetch the buyer pages."""
    if shutil.which("npm") is None or not (ROOT / "node_modules").is_dir():
        rec.check("site.served", False, "NOT RUN: npm or node_modules is missing")
        return
    port = free_port()
    # Next requires distDir inside the application directory; a throwaway one, removed afterwards.
    dist = f".next-rehearsal-{os.getpid()}"
    # `next build` rewrites tsconfig.json (adds the dist dir to "include"); put it back afterwards.
    tsconfig = ROOT / "tsconfig.json"
    original_tsconfig = tsconfig.read_text() if tsconfig.is_file() else None
    env = {**os.environ, "NEXT_DIST_DIR": dist, "NEXT_TELEMETRY_DISABLED": "1",
           "NEXT_PUBLIC_ASSURANCE_API_URL": "http://127.0.0.1:1"}
    try:
        build = subprocess.run(["npm", "run", "build"], cwd=ROOT, env=env, capture_output=True,  # noqa: S603, S607
                               text=True, timeout=900)
    finally:
        if original_tsconfig is not None:
            tsconfig.write_text(original_tsconfig)
    if build.returncode != 0:
        rec.check("site.built", False, "next build failed: " + (build.stdout + build.stderr)[-400:])
        shutil.rmtree(ROOT / dist, ignore_errors=True)
        return
    proc = subprocess.Popen(["npx", "next", "start", "-p", str(port), "-H", "127.0.0.1"],  # noqa: S603, S607
                            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        for _ in range(60):
            try:
                if httpx.get(f"http://127.0.0.1:{port}/", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(1)
        got = {p: httpx.get(f"http://127.0.0.1:{port}{p}", timeout=10).status_code
               for p in ("/", "/checkout/success", "/developers")}
        rec.check("site.served_and_buyer_pages_answer", all(v == 200 for v in got.values()), str(got))
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        shutil.rmtree(ROOT / dist, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--record-dir", default=os.environ.get("REHEARSAL_RECORD_DIR", ".rehearsal-local"))
    ap.add_argument("--keep", action="store_true", help="keep the scratch directory (holds throwaway data)")
    ap.add_argument("--with-site", action="store_true", help="also build and serve the Next.js site")
    return run(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
