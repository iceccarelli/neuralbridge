"""Seed a local Assurance API for the /assurance workspace e2e.

Uses the real engines end to end — AccountStore, the per-account tenant ledger,
collection plans over synthetic vendor exports, the Watch runner and its case
wiring — and writes nothing but local files. The output JSON holds keys for
five accounts: A (Cell, has a fleet and an open change case, written straight
into its ledger), B (Cell, empty), C (Register, not entitled to change
assurance), D (Cell, one hand-posted manifest and no Watch report ever) and
E (Cell, whose fleet arrives ONLY through the real ``assurance watch push``),
G (Cell, two healthy verified machines: the fleet the advisory panel is exercised
against), H (Supplier tier, whose signed feed is published through the real
``assurance supplier`` CLI and hosted through the real API) and J (Cell, past due).

    ASSURANCE_LEDGER=... ASSURANCE_ACCOUNTS=... python scripts/e2e_seed_assurance.py OUT.json WORKDIR
    python scripts/e2e_seed_assurance.py OUT.json WORKDIR --report http://127.0.0.1:PORT
    python scripts/e2e_seed_assurance.py OUT.json WORKDIR --stage-checkout SESSION_ID TIER

The second form runs once the API is up. It drives E's local plant through a
timeline (real Watch runs over synthetic exports into a plant-local ledger) and
reports it with the real ``watch push`` CLI, over HTTP, and then pushes the same
run again: the replay must change nothing. It also signs and withdraws advisories
with the real ``assurance supplier`` CLI and hosts the feed through the real API.

The third form does what Stripe's webhook does after a payment, through the real
``AccountStore.apply_checkout``: it creates the account and stages the one-time key that
``GET /v1/checkout/complete?session_id=...`` hands over. Stripe itself is not reachable
from a test; everything after the webhook is real.

These are local test credentials for a throwaway database. Never run against a
deployed service.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from assurance.api.deps import accounts_path, tenant_ledger_path  # noqa: E402
from assurance.billing.accounts import AccountStore  # noqa: E402
from assurance.collect.collector import collect  # noqa: E402
from assurance.collect.plan import CollectionPlan  # noqa: E402
from assurance.core.evidence import Actor  # noqa: E402
from assurance.fleet.registry import Fleet  # noqa: E402
from assurance.evidence.ledger import EvidenceLedger  # noqa: E402
from assurance.machinery.intervention import Intervention, InterventionKind  # noqa: E402
from assurance.machinery.manifest import HashSource, ManifestSource  # noqa: E402
from assurance.machinery.record import record_manifest  # noqa: E402
from assurance.watch.config import WatchConfig  # noqa: E402
from assurance.watch.runner import run_watch  # noqa: E402
from tests.support import plan_dict, write_export  # noqa: E402
from tests.test_assurance_watch_cases import verify_machine  # noqa: E402

T0 = datetime(2026, 9, 14, 6, tzinfo=UTC)


G_SERIALS = {"6101": b"firmware 3.8.2", "6102": b"firmware 3.7.0"}


def build_plant(work: Path, ledger_path: Path, name: str, firmware: dict[str, bytes]) -> EvidenceLedger:
    """A plant of healthy, verified machines, recorded straight into a tenant ledger."""
    plant = work / name
    plant.mkdir(parents=True)
    (plant / "plan.json").write_text(json.dumps(plan_dict()))
    for serial, fw in firmware.items():
        write_export(plant / serial, stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181", fw=fw)
    (plant / "watch.json").write_text(json.dumps({
        "watch_id": f"WATCH-{name.upper()}", "max_age_hours": 168,
        # read_from_machine: the seed plays a watch running ON the machine. An export folder is
        # not labelled that implicitly any more; the operator asserts it.
        "targets": [{"serial": s, "plan": "plan.json", "root": s, "site": f"Plant {name}",
                     "country": "DE", "read_from_machine": True} for s in firmware],
    }))
    ledger = EvidenceLedger(ledger_path)
    run_watch(WatchConfig.from_json(plant / "watch.json"), ledger, now=T0)
    for serial in firmware:
        verify_machine(ledger, f"Grimaldi/AR-7#{serial}", when=T0 + timedelta(days=1))
    return ledger


def advisory(advisory_id: str, *, supplier: str, name: str, versions: list[str] | None = None,
             hashes: list[str] | None = None, severity: str = "safety_relevant") -> dict:
    return {
        "advisory_id": advisory_id, "issued_by": supplier,
        "issued_at": "2026-10-01T08:00:00Z", "title": f"{name}: defect ({advisory_id})",
        "summary": "Synthetic advisory for the end-to-end test.", "severity": severity,
        "affected": [{"supplier": supplier, "name": name, "versions": versions or [],
                      "content_hashes": hashes or [], "version_note": ""}],
        "remedy": "Apply the supplier's remedy and re-verify.",
        "reference": f"https://supplier.example.invalid/advisories/{advisory_id}",
        "fixed_versions": [], "fixed_hashes": [],
    }


def stage_checkout(session_id: str, tier: str) -> int:
    """What Stripe's webhook does after a payment, through the real store."""
    store = AccountStore(accounts_path())
    result = store.apply_checkout(
        event_id=f"evt_e2e_{session_id}", session_id=session_id,
        email=f"{session_id}@e2e.invalid", company=f"Checkout {session_id}", tier=tier,
        stripe_customer_id=f"cus_e2e_{session_id}", stripe_subscription_id=f"sub_e2e_{session_id}",
        event_created=int(datetime.now(UTC).timestamp()))
    print(json.dumps(result))
    return 0 if result.get("result") == "granted" else 1


def main(out: str, workdir: str) -> int:
    work = Path(workdir)
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    store = AccountStore(accounts_path())

    def account(name: str, tier: str) -> tuple[str, str]:
        acct = store.upsert_account(email=f"{name}@e2e.invalid", tier=tier, company=name,
                                    stripe_customer_id=f"cus_e2e_{name}",
                                    stripe_subscription_id=f"sub_e2e_{name}")
        return acct.id, store.issue_key(acct.id, label="e2e")

    id_a, key_a = account("alpha", "cell")
    # A Cell account whose ledger file does not exist yet: its first page load
    # creates the tenant ledger from the workspace's parallel requests.
    id_new, key_new = account("foxtrot", "cell")
    assert not tenant_ledger_path(id_new).exists()
    _, key_b = account("bravo", "cell")
    _, key_c = account("charlie", "register")
    id_d, key_d = account("delta", "cell")
    _, key_e = account("echo", "cell")
    id_g, key_g = account("golf", "cell")
    id_h, key_h = account("hotel", "supplier")
    id_k, key_k = account("kilo", "cell")
    acct_j = store.upsert_account(email="juliet@e2e.invalid", tier="cell", company="juliet",
                                  stripe_customer_id="cus_e2e_juliet", stripe_subscription_id="sub_e2e_juliet",
                                  status="past_due")
    key_j = store.issue_key(acct_j.id, label="e2e")
    # A customer whose subscription ended: Stripe bound a customer id to it once, so the
    # server still lets it read, verify and export what it already holds (evidence_readout).
    acct_l = store.upsert_account(email="lima@e2e.invalid", tier="cell", company="lima",
                                  stripe_customer_id="cus_e2e_lima", stripe_subscription_id="sub_e2e_lima",
                                  status="cancelled")
    key_l = store.issue_key(acct_l.id, label="e2e")

    (work / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in ("0412", "0501"):
        write_export(work / serial, stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    (work / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-E2E", "max_age_hours": 168,
        "targets": [
            {"serial": "0412", "plan": "plan.json", "root": "0412", "site": "Plant 2",
             "country": "DE", "read_from_machine": True},
            {"serial": "0501", "plan": "plan.json", "root": "0501", "site": "Plant 7",
             "country": "IT", "read_from_machine": True},
        ],
    }))
    config = WatchConfig.from_json(work / "watch.json")
    ledger = EvidenceLedger(tenant_ledger_path(id_a))

    run_watch(config, ledger, now=T0)
    for key in ("Grimaldi/AR-7#0412", "Grimaldi/AR-7#0501"):
        verify_machine(ledger, key, when=T0 + timedelta(days=1))
    # Somebody reflashed the safety controller on 0412.
    shutil.rmtree(work / "0412")
    write_export(work / "0412", stamp="2026-09-21T06:12:41Z", operator="a.integrator",
                 seq="4199", fw=b"firmware 3.9.0")
    run = run_watch(config, ledger, now=T0 + timedelta(days=7))
    case_ids = [o.case_id for o in run.outcomes if getattr(o, "case_id", "")]
    if len(case_ids) != 1:
        print(f"expected exactly one case from the watch, got {case_ids}", file=sys.stderr)
        return 1

    # D: a manifest somebody posted by hand, and no Watch report ever. The workspace
    # must say so rather than show a machine that looks quietly current.
    write_export(work / "0900", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    hand = collect(CollectionPlan.from_dict(plan_dict()), work / "0900", serial="0900",
                   taken_by=Actor("m.tech", "service technician"), site="Plant 9", country="DE",
                   source=ManifestSource.AS_FOUND, taken_at=T0,
                   hash_source=HashSource.READ_FROM_MACHINE)   # the seed plays an on-machine collector
    record_manifest(EvidenceLedger(tenant_ledger_path(id_d)), hand.manifest)

    # G: two healthy, verified machines with different firmware. The advisories are built from
    # the hashes the real collector recorded, not invented ones.
    g_ledger = build_plant(work, tenant_ledger_path(id_g), "golf", G_SERIALS)
    items = {r.machine_key.split("#")[1]: {i.item_id: i for i in r.manifest.items}
             for r in Fleet.from_ledger(g_ledger).records}
    fw_hash = items["6101"]["ITM-FW"].content_hash
    assert fw_hash and fw_hash != items["6102"]["ITM-FW"].content_hash
    assert items["6101"]["ITM-PARAMS"].version == "3.8.2"
    advisories = {
        # 6101 runs exactly the named artefact; 6102 is the same component with another firmware.
        "hash": advisory("ADV-E2E-HASH", supplier="ControlCo", name="Safety controller firmware", hashes=[fw_hash]),
        # The label matches, the supplier's own hash does not: neither affected nor clear.
        "mismatch": advisory("ADV-E2E-MISMATCH", supplier="RoboCo", name="Robot safety parameter set",
                             versions=["3.8.2"], hashes=["0" * 64]),
        "clear": advisory("ADV-E2E-CLEAR", supplier="ControlCo", name="Nonexistent safety relay", versions=["9.9"]),
    }

    # K: one verified machine for the case-lifecycle and intervention tests. The page seals the
    # intervention through the real route; the manifest is the one the collector recorded.
    k_ledger = build_plant(work, tenant_ledger_path(id_k), "kilo", {"6201": b"firmware 3.8.2"})
    k_record = Fleet.from_ledger(k_ledger).records[0]
    k_fw = next(i for i in k_record.manifest.items if i.item_id == "ITM-FW")
    k_intervention = Intervention(
        intervention_id="INT-E2E-1", machine_key=k_record.machine_key, item_id="ITM-FW",
        kind=InterventionKind.UPDATE, occurred_at=datetime(2026, 10, 2, 9, 30, tzinfo=UTC),
        performed_by=Actor("a.integrator", "integrator"), reason="Vendor advisory: watchdog fix.",
        from_hash=k_fw.content_hash, to_hash="d" * 64, affects_functions=("SF-01", "SF-02"))

    Path(out).write_text(json.dumps({
        "key_k": key_k, "k_machine": k_record.machine_key, "k_manifest": k_record.manifest.to_dict(),
        "k_intervention": k_intervention.to_dict(),
        "key_a": key_a, "key_b": key_b, "key_new": key_new, "key_register": key_c, "key_d": key_d, "key_e": key_e,
        "key_g": key_g, "key_hotel": key_h, "key_past_due": key_j, "key_lapsed": key_l,"hotel_account_id": id_h,
        "case_id": case_ids[0], "machines": ["Grimaldi/AR-7#0412", "Grimaldi/AR-7#0501"],
        "d_machine": "Grimaldi/AR-7#0900",
        "machines_g": [f"Grimaldi/AR-7#{s}" for s in G_SERIALS],
        "advisories": advisories, "fw_hash": fw_hash,
    }))
    return 0


E_SERIALS = ("7001", "7002", "7003")


def _push(config: Path, ledger: Path, url: str, key: str) -> str:
    """The real CLI, as an operator would run it. The key travels in the environment only."""
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", "watch", "push", str(config), "--ledger", str(ledger),
         "--api-url", url, "--key-env", "NB_E2E_PUSH_KEY", "--retry-wait", "0"],
        env={**os.environ, "NB_E2E_PUSH_KEY": key, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True, text=True, check=False)
    if proc.returncode != 0 or key in proc.stdout + proc.stderr:
        print(f"watch push failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}", file=sys.stderr)
        raise SystemExit(1)
    return proc.stdout


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", *args], capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")})


def publish_feed(seed: dict, workdir: Path, api_url: str) -> None:
    """A supplier signs two advisories and withdraws one, with the real CLI, and hosts the feed.

    Writes the pristine feed, a tampered copy (a severity edited after signing), the public
    key and the fingerprint, and POSTs every record to the real hosted-feed route.
    """
    import urllib.error
    import urllib.request

    feed_dir = workdir / "supplier"
    shutil.rmtree(feed_dir, ignore_errors=True)
    feed_dir.mkdir(parents=True)
    key, pub, feed = feed_dir / "psirt.pem", feed_dir / "psirt.pub", feed_dir / "psirt-feed.jsonl"
    identity = feed_dir / "identity.json"
    identity.write_text(json.dumps({
        "supplier_id": "ControlCo", "legal_name": "ControlCo GmbH",
        "key_contact": "telephone number printed in the e2e fixture documentation folder"}))
    gen = _cli("supplier", "keygen", "--out", str(key), "--public-out", str(pub))
    if gen.returncode != 0 or "publishing key" not in gen.stdout:
        raise SystemExit(f"keygen failed: {gen.stdout}{gen.stderr}")
    fingerprint = gen.stdout.split("publishing key")[1].split()[0]
    first = advisory("ADV-FEED-1", supplier="ControlCo", name="Safety controller firmware", hashes=[seed["fw_hash"]])
    second = advisory("ADV-FEED-2", supplier="ControlCo", name="Safety controller firmware", versions=["3.8.2"])
    for adv in (first, second):
        path = feed_dir / f"{adv['advisory_id']}.json"
        path.write_text(json.dumps(adv))
        done = _cli("supplier", "publish", str(path), "--feed", str(feed), "--key", str(key),
                    "--identity", str(identity))
        if done.returncode != 0:
            raise SystemExit(f"publish failed: {done.stdout}{done.stderr}")
    done = _cli("supplier", "withdraw", "ADV-FEED-2", "--reason", "the affected versions were wrong",
                "--feed", str(feed), "--key", str(key), "--identity", str(identity))
    if done.returncode != 0:
        raise SystemExit(f"withdraw failed: {done.stdout}{done.stderr}")
    verify = _cli("supplier", "verify", "--feed", str(feed), "--public-key", str(pub),
                  "--expect-supplier", "ControlCo")
    if verify.returncode != 0:
        raise SystemExit(f"the pristine feed does not verify: {verify.stdout}{verify.stderr}")

    lines = feed.read_text().splitlines()
    record = json.loads(lines[0])
    record["advisory"]["severity"] = "informational"            # edited after it was signed
    tampered = feed_dir / "psirt-feed-tampered.jsonl"
    tampered.write_text("\n".join([json.dumps(record, sort_keys=True), *lines[1:]]) + "\n")
    if _cli("supplier", "verify", "--feed", str(tampered), "--public-key", str(pub)).returncode == 0:
        raise SystemExit("the tampered feed unexpectedly verifies")

    hosted = 0
    withdrawal_refused = ""
    for line in lines:
        req = urllib.request.Request(
            f"{api_url}/v1/supplier/advisory", data=line.encode(), method="POST",
            headers={"content-type": "application/json", "X-API-Key": seed["key_hotel"]})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                if resp.status != 201:
                    raise SystemExit(f"hosting a record failed: HTTP {resp.status}")
            hosted += 1
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            # Known server defect, reported rather than hidden: POST /v1/supplier/advisory refuses a
            # signed WITHDRAWAL as a duplicate advisory id, so a hosted feed cannot carry one.
            if exc.code == 409 and json.loads(line).get("withdraws") and "duplicate_advisory_id" in body:
                withdrawal_refused = body
                continue
            raise SystemExit(f"hosting a record failed: HTTP {exc.code} {body}") from exc
    seed["supplier"] = {
        "feed_path": str(feed), "tampered_path": str(tampered), "public_key_path": str(pub),
        "fingerprint": fingerprint, "supplier_id": "ControlCo", "records": len(lines),
        "hosted_records": hosted, "hosted_withdrawal_refused": withdrawal_refused,
        "hosted_feed_id": seed["hotel_account_id"], "first_advisory_id": "ADV-FEED-1",
        "withdrawn_advisory_id": "ADV-FEED-2",
    }


def report(out: str, workdir: str, api_url: str) -> int:
    """Account E's plant: three machines, reported through the real push path.

    7001 is looked at every time and reflashed between the two pushes (one case).
    7002 has not been collectable for two runs and was last seen ten days ago (stale).
    7003 was seen two days ago and failed the latest look (failed, not yet stale).
    """
    seed = json.loads(Path(out).read_text())
    plant = Path(workdir) / "plant-e"
    shutil.rmtree(plant, ignore_errors=True)
    plant.mkdir(parents=True)
    (plant / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in E_SERIALS:
        write_export(plant / serial, stamp="2026-10-01T06:00:00Z", operator="m.tech", seq="4181")
    (plant / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-E2E-PLANT", "max_age_hours": 168,
        "targets": [{"serial": s, "plan": "plan.json", "root": s, "site": "Plant E",
                     "country": "DE", "read_from_machine": True} for s in E_SERIALS],
    }))
    config = WatchConfig.from_json(plant / "watch.json")
    local = EvidenceLedger(plant / "register.db")
    cfg, db, key = plant / "watch.json", plant / "register.db", seed["key_e"]
    now = datetime.now(UTC).replace(microsecond=0)

    run_watch(config, local, now=now - timedelta(days=10))           # everything seen
    _push(cfg, db, api_url, key)                                     # hosted baseline

    shutil.rmtree(plant / "7001")                                    # reflashed on the floor
    write_export(plant / "7001", stamp="2026-10-18T06:12:41Z", operator="a.integrator",
                 seq="4199", fw=b"firmware 3.9.0")
    shutil.rmtree(plant / "7002")                                    # export folder gone
    run_watch(config, local, now=now - timedelta(days=2))            # 7003 still fine
    shutil.rmtree(plant / "7003")
    run_watch(config, local, now=now - timedelta(hours=1))           # 7002, 7003 blind

    first = _push(cfg, db, api_url, key)
    again = _push(cfg, db, api_url, key)                             # a retry: must change nothing
    if "already recorded" not in again or "cases opened" in again:
        print(f"the replay was not a no-op:\n{again}", file=sys.stderr)
        return 1
    cases = [w for w in first.replace(",", " ").split() if w.startswith("case-")]
    seed.update({
        "machines_e": {"ok": "Grimaldi/AR-7#7001", "blind_stale": "Grimaldi/AR-7#7002",
                       "blind_fresh": "Grimaldi/AR-7#7003"},
        "case_e": cases[0] if cases else "",
    })
    if not seed["case_e"]:
        print(f"expected the push to open one case:\n{first}", file=sys.stderr)
        return 1
    publish_feed(seed, Path(workdir), api_url)
    Path(out).write_text(json.dumps(seed))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[3] == "--stage-checkout":
        raise SystemExit(stage_checkout(sys.argv[4], sys.argv[5]))
    if len(sys.argv) == 5 and sys.argv[3] == "--report":
        raise SystemExit(report(sys.argv[1], sys.argv[2], sys.argv[4]))
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
