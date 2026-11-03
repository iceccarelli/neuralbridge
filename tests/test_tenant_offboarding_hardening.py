# ruff: noqa: F811 - `data` is the fixture of test_tenant_offboarding, imported by name
"""Hardening of ``assurance tenant`` found by an adversarial review.

1. the head check and the unlink happen under the ledger's writer lock (no late write is lost);
2. a deleted account stays deleted: a marker file, 410 from the API, skipped by anchor-all;
3. nothing in the operator tombstone is taken from the (unauthenticated) export manifest
   except values that ``verify-export`` binds to something;
4. the plan tells "never existed here" from "already removed";
5. the export directory cannot be swapped for a symlink between check and use.

Real ledgers and real files on tmp directories only; deletion code never sees anything else.
"""

from __future__ import annotations

import importlib
import json
import os
import random
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import assurance.tenant.delete as delete_mod
import assurance.tenant.export as export_mod
from assurance.api import deps
from assurance.attest import SigningKey
from assurance.attest.anchor_all import anchor_all
from assurance.evidence import EvidenceLedger
from assurance.tenant.layout import MARKER_SUFFIX

from .test_tenant_offboarding import (  # noqa: F401 - `data` is a fixture
    ACC_A,
    ACC_B,
    PERSON,
    SECRET_A,
    _ev,
    data,
    do_delete,
    do_export,
    execute,
    run,
    tree,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes and flock are POSIX")


def _export(capsys, data, tmp_path, name="export", acc=ACC_A):
    out = tmp_path / name
    assert do_export(capsys, data, out, acc)[0] == 0
    return out


def _tenant(data, acc=ACC_A) -> Path:
    return data / "tenants" / f"{acc}.db"


def _marker(data, acc=ACC_A) -> Path:
    return data / "tenants" / f"{acc}{MARKER_SUFFIX}"


def _contents(path: Path) -> set[str]:
    return {e.body["note"] + str(e.body["n"]) if False else e.content_hash
            for e in EvidenceLedger(path, mint_id=False).entries()}


def _holds_no_chain(path: Path) -> bool:
    """True if ``path`` is absent, or exists but has no ledger (no ``chain`` table), e.g. an empty
    file a late writer's connect created."""
    if not path.exists():
        return True
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return db.execute("SELECT 1 FROM sqlite_master WHERE name='chain'").fetchone() is None
    except sqlite3.DatabaseError:
        return True                      # not a database at all: it holds no ledger either
    finally:
        db.close()


def _hashes(path: Path) -> set[str]:
    return {e.content_hash for e in EvidenceLedger(path, mint_id=False).entries()}


# ------------------------------------------------------------------- 1. the writer lock
def _writer_lock_is_held() -> bool:
    probe = sqlite3.connect(os.environ["TEN_PROBE_DB"], timeout=0.05, isolation_level=None)
    try:
        probe.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        return True
    probe.execute("ROLLBACK")
    return False


def test_writer_lock_is_held_while_the_head_is_read_and_files_are_removed(
        capsys, data, tmp_path, monkeypatch):
    export = _export(capsys, data, tmp_path)
    monkeypatch.setenv("TEN_PROBE_DB", str(_tenant(data)))
    seen: dict[str, bool] = {}
    real = delete_mod.live_head

    def spying_head(path):
        seen["at_head_read"] = _writer_lock_is_held()
        return real(path)

    def hook():
        seen["between_check_and_unlink"] = _writer_lock_is_held()

    monkeypatch.setattr(delete_mod, "live_head", spying_head)
    monkeypatch.setattr(delete_mod, "_BETWEEN_CHECK_AND_REMOVE", hook, raising=False)
    assert execute(capsys, data, export)[0] == 0
    assert seen == {"at_head_read": True, "between_check_and_unlink": True}


def test_a_write_between_check_and_unlink_is_never_deleted_unexported(
        capsys, data, tmp_path, monkeypatch):
    """The deterministic form of the reviewer's reproducer, with a real concurrent writer."""
    export = _export(capsys, data, tmp_path)
    acked: list[str] = []
    errors: list[str] = []
    writer: list[threading.Thread] = []

    def append_late():
        led = EvidenceLedger(_tenant(data), mint_id=False)
        ev = _ev("LATE-unexported", 99)
        try:
            led.append(ev, subject="late")
            acked.append(ev.content_hash)
        except Exception as exc:  # noqa: BLE001 - the outcome is what is asserted
            errors.append(type(exc).__name__)

    def hook():
        t = threading.Thread(target=append_late)
        t.start()
        writer.append(t)
        time.sleep(0.3)           # the writer gets its chance inside the window

    monkeypatch.setattr(delete_mod, "_BETWEEN_CHECK_AND_REMOVE", hook, raising=False)
    code, _, err = execute(capsys, data, export)
    for t in writer:
        t.join(30)
    exported = _hashes(export / "ledger.db")
    if code == 0:
        # deleted: every record a writer was told was stored must be in the export
        assert set(acked) <= exported, "an acknowledged write was deleted unexported"
    else:
        assert "export again" in err.lower() or "again" in err
        assert _tenant(data).exists()


def test_acknowledged_writes_are_in_the_export_or_the_delete_was_refused(
        capsys, data, tmp_path, monkeypatch):
    """Many rounds with a writer appending in a loop while ``--execute`` runs."""
    deleted = refused = 0
    monkeypatch.setattr(delete_mod, "_BETWEEN_CHECK_AND_REMOVE", lambda: time.sleep(0.02),
                        raising=False)
    for rnd in range(14):
        root = tmp_path / f"r{rnd}"
        (root / "tenants").mkdir(parents=True)
        (root / "attestations").mkdir()
        path = root / "tenants" / f"{ACC_A}.db"
        led = EvidenceLedger(path)
        for i in range(3):
            led.append(_ev("seed", i), subject="s")
        EvidenceLedger(root / "art14-register.db").append(_ev("op", 1), subject="op")
        out = root / "export"
        assert run(capsys, "export", "--data-dir", str(root), "--account", ACC_A, "--out",
                   str(out), "--actor", PERSON)[0] == 0
        acked: list[str] = []
        stop = threading.Event()
        delay = random.Random(rnd).uniform(0.0, 0.03)

        ready = threading.Event()

        def writer(path=path, acked=acked, stop=stop, delay=delay, ready=ready):
            # Open the ledger BEFORE the deletion can start, so this thread's constructor can never
            # run after the unlink and create a fresh, schema-bearing ledger that a later write
            # would be acknowledged into (a test artefact, not the behaviour under test).
            wl = EvidenceLedger(path, mint_id=False)
            ready.set()
            time.sleep(delay)
            n = 1000
            while not stop.is_set() and n < 1040:
                n += 1
                ev = _ev("racing", n)
                try:
                    wl.append(ev, subject="race")
                    acked.append(ev.content_hash)
                except Exception:  # noqa: BLE001 - a refused write is not acknowledged
                    return
                time.sleep(0.002)

        t = threading.Thread(target=writer)
        t.start()
        assert ready.wait(10), "the writer never opened its ledger"
        code, _, _ = execute(capsys, root, out)
        stop.set()
        t.join(30)
        if code == 0:
            deleted += 1
            assert set(acked) <= _hashes(out / "ledger.db"), (rnd, "acknowledged write lost")
            # The ledger's data is gone. The FILE can reappear as an empty orphan: the writer thread
            # here still holds a path, and SQLite creates a missing file on connect, so a write
            # attempted after the unlink makes a schema-less file that its own append then fails on.
            # (That is a refused write, never an acknowledged one; the API cannot do this because
            # get_register answers 410 before any ledger is opened.) Seen on a slower CI runner.
            assert _holds_no_chain(path), (rnd, "ledger data survived the deletion")
            assert _marker(root).exists()
        else:
            refused += 1
            assert path.exists()
            assert _hashes(out / "ledger.db") <= _hashes(path)
    assert deleted + refused == 14
    assert deleted >= 1, "no round reached a deletion: the invariant was not exercised"


def test_a_ledger_that_grew_under_the_lock_is_refused_and_nothing_is_removed(
        capsys, data, tmp_path, monkeypatch):
    export = _export(capsys, data, tmp_path)
    # a record that landed after the export, before --execute
    EvidenceLedger(_tenant(data), mint_id=False).append(_ev("after-export", 7), subject="s")
    before = tree(data)
    code, _, err = execute(capsys, data, export)
    assert code == 1 and "export" in err and "again" in err
    assert tree(data) == before and not _marker(data).exists()


def test_no_half_state_remains_after_delete(capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    left = sorted(os.listdir(data / "tenants"))
    assert left == [f"{ACC_B}.db", f"{ACC_A}{MARKER_SUFFIX}"] or \
        set(left) == {f"{ACC_B}.db", f"{ACC_A}{MARKER_SUFFIX}"} | {
            n for n in left if n.startswith(ACC_B)}
    assert not [n for n in left if n.startswith(ACC_A) and not n.endswith(MARKER_SUFFIX)]
    assert not (data / "attestations" / f"{ACC_A}.jsonl").exists()
    assert not (data / "attestations" / f"{ACC_A}.jsonl.lock").exists()


# ------------------------------------------------------------------- 2. the marker
def test_marker_is_written_0600_with_no_customer_data(capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    b_before = tree(data)
    b_before = {k: v for k, v in b_before.items() if ACC_B in k}
    op_before = EvidenceLedger(data / "art14-register.db", mint_id=False).entries()
    code, _, _ = execute(capsys, data, export)
    assert code == 0
    marker = _marker(data)
    assert (marker.stat().st_mode & 0o777) == 0o600
    doc = json.loads(marker.read_text())
    manifest = json.loads((export / "MANIFEST.json").read_text())
    import hashlib
    assert doc["account_id"] == ACC_A and doc["actor"] == PERSON
    assert doc["export_manifest_sha256"] == hashlib.sha256(
        (export / "MANIFEST.json").read_bytes()).hexdigest()
    assert doc["deleted_at"].endswith("Z")
    assert set(doc) == {"schema", "account_id", "deleted_at", "actor", "export_manifest_sha256"}
    assert SECRET_A not in marker.read_text() and manifest["head_hash"] not in {None}
    # the other tenant is byte-identical; the operator ledger gained exactly one tombstone
    assert {k: v for k, v in tree(data).items() if ACC_B in k} == b_before
    op = EvidenceLedger(data / "art14-register.db", mint_id=False)
    assert op.verify_chain()[0] and len(op.entries()) == len(op_before) + 1
    assert sum(1 for e in op.entries() if e.subject == f"tenant/{ACC_A}") == 1


def test_export_of_a_marked_account_is_refused(capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    code, _, err = do_export(capsys, data, tmp_path / "again", ACC_A)
    assert code == 1 and "already removed" in err and not (tmp_path / "again").exists()


def test_execute_on_a_marked_account_says_already_removed(capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    before = tree(data)
    code, _, err = execute(capsys, data, export)
    assert code == 1 and "already removed" in err
    assert tree(data) == before


def test_anchor_all_skips_and_reports_marked_accounts_and_creates_nothing(
        capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    report = anchor_all(data, SigningKey.generate(), dry_run=True)
    by = {o.account_id: o for o in report.outcomes if o.account_id}
    assert by[ACC_A].status == "skipped" and "deleted" in by[ACC_A].detail
    assert by[ACC_B].status == "would_anchor"
    assert report.exit_code == 0
    assert not _tenant(data).exists()
    live = anchor_all(data, SigningKey.generate())
    assert not _tenant(data).exists()
    assert not (data / "attestations" / f"{ACC_A}.jsonl").exists()
    assert any(o.account_id == ACC_A and o.status == "skipped" for o in live.outcomes)


def test_anchor_all_flags_a_ledger_that_reappeared_under_a_marker(capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    EvidenceLedger(_tenant(data)).append(_ev("recreated", 1), subject="s")
    report = anchor_all(data, SigningKey.generate())
    out = [o for o in report.outcomes if o.account_id == ACC_A and o.name.endswith(".db")]
    assert out and out[0].status == "skipped" and out[0].detail
    assert report.exit_code == 1
    assert not (data / "attestations" / f"{ACC_A}.jsonl").exists()


# ------------------------------------------------------------------- 2b. the API
OPERATOR_KEY = "operator-key-test-offboarding"


@pytest.fixture()
def api(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    monkeypatch.setenv("ASSURANCE_LEDGER", str(shared / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    for f in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
        f.cache_clear()
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as client:
        yield client, shared
    for f in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
        f.cache_clear()


def _acct(email, tier="register"):
    store = deps.get_accounts()
    account = store.upsert_account(email=email, tier=tier, stripe_customer_id=f"cus_{email}")
    return account, {"X-API-Key": store.issue_key(account.id)}


def _signal(client, headers, case="CASE-1"):
    return client.post(f"/v1/cases/{case}/signal", headers=headers, json={
        "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
        "description": "a signal", "reference": "T-1",
        "actor": {"identifier": "m.braun", "role": "Entwicklungsleitung"}})


def _delete_via_cli(capsys, shared, account_id, tmp_path):
    EvidenceLedger(shared / "art14.db").append(_ev("op", 1), subject="operator")
    out = tmp_path / "exp"
    assert run(capsys, "export", "--data-dir", str(shared), "--account", account_id, "--out",
               str(out), "--actor", PERSON)[0] == 0
    code, _, err = run(
        capsys, "delete", "--data-dir", str(shared), "--account", account_id, "--execute",
        "--confirm-account", account_id, "--export", str(out), "--actor", PERSON,
        "--operator-ledger", str(shared / "art14.db"))
    assert code == 0, err


def test_api_answers_410_for_a_deleted_account_on_every_ledger_route_class(
        api, capsys, tmp_path):
    client, shared = api
    a_acc, a = _acct("a@example.de")
    b_acc, b = _acct("b@example.de")
    assert _signal(client, a).status_code == 201 and _signal(client, b).status_code == 201
    _delete_via_cli(capsys, shared, a_acc.id, tmp_path)
    ledger_file = shared / "tenants" / f"{a_acc.id}.db"
    assert not ledger_file.exists()

    reads = ["/v1/cases", "/v1/cases/CASE-1", "/v1/ledger/verify", "/v1/register",
             "/v1/register/breaches"]            # the last two are what the MCP tools call
    for path in reads:
        r = client.get(path, headers=a)
        assert r.status_code == 410, (path, r.status_code, r.text)
        body = r.json()["detail"]
        assert body["error"] == "account_data_deleted"
        assert "removed by an operator on" in body["detail"] and "contact the operator" \
            in body["detail"]
    w = _signal(client, a, case="CASE-2")
    assert w.status_code == 410 and w.json()["detail"]["error"] == "account_data_deleted"
    # no ledger was recreated
    assert not ledger_file.exists()
    assert not [p for p in (shared / "tenants").iterdir()
                if p.name.startswith(a_acc.id) and p.suffix != MARKER_SUFFIX]

    # other accounts, the operator and anonymous callers are unchanged
    assert client.get("/v1/cases", headers=b).json() == ["CASE-1"]
    assert client.get("/v1/cases", headers={"X-API-Key": OPERATOR_KEY}).status_code == 200
    assert client.get("/v1/cases").status_code == 401
    _free, free = _acct("free@example.de", tier="free")
    assert _signal(client, free).status_code == 402


def test_lifting_the_marker_by_hand_is_the_only_way_back(api, capsys, tmp_path):
    client, shared = api
    a_acc, a = _acct("a@example.de")
    assert _signal(client, a).status_code == 201
    _delete_via_cli(capsys, shared, a_acc.id, tmp_path)
    assert client.get("/v1/cases", headers=a).status_code == 410
    (shared / "tenants" / f"{a_acc.id}{MARKER_SUFFIX}").unlink()
    assert client.get("/v1/cases", headers=a).status_code == 200


def test_a_symlink_or_unreadable_marker_still_blocks(api, tmp_path):
    client, shared = api
    a_acc, a = _acct("a@example.de")
    (shared / "tenants").mkdir(parents=True, exist_ok=True)
    (shared / "tenants" / f"{a_acc.id}{MARKER_SUFFIX}").symlink_to(tmp_path / "nowhere")
    assert client.get("/v1/cases", headers=a).status_code == 410
    assert not (shared / "tenants" / f"{a_acc.id}.db").exists()


# ------------------------------------------------------------------- 3. tombstone input
def test_tombstone_does_not_copy_unbound_strings_from_the_manifest(capsys, data, tmp_path):
    export = _export(capsys, data, tmp_path)
    mpath = export / "MANIFEST.json"
    doc = json.loads(mpath.read_text())
    doc["actor"] = "INJECTED\nFAKE-ENTRY " * 50
    doc["exported_at"] = {"nested": ["any", "json"]}
    mpath.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    code, _, _ = execute(capsys, data, export, actor="Real Person")
    assert code == 0
    tomb = [e for e in EvidenceLedger(data / "art14-register.db", mint_id=False).entries()
            if e.subject == f"tenant/{ACC_A}"][0]
    raw = json.dumps(tomb.evidence().body)
    assert "INJECTED" not in raw and "nested" not in raw
    body = tomb.evidence().body
    assert body["actor"] == "Real Person" and body["deleted_at"].endswith("Z")
    assert set(body["export"]) == {"manifest_sha256", "head_hash", "record_count",
                                   "ledger_id", "export_status"}


def test_manifest_with_malformed_bound_fields_is_refused(capsys, data, tmp_path):
    """A manifest field that is kept must be well-formed; anything else removes nothing."""
    export = _export(capsys, data, tmp_path)
    mpath = export / "MANIFEST.json"
    doc = json.loads(mpath.read_text())
    doc["ledger_id"] = "x\n" * 200
    mpath.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    before = tree(data)
    code, _, _ = execute(capsys, data, export)
    assert code != 0 and tree(data) == before


# ------------------------------------------------------------------- 4. plan wording
def test_plan_distinguishes_never_existed_from_already_removed(capsys, data, tmp_path):
    unknown = "acc_" + "c3" * 8
    code, out, _ = do_delete(capsys, data, unknown)
    assert code == 0 and "no such account data on this host" in out
    assert "already removed" not in out
    code, out, _ = do_delete(capsys, data, unknown, "--json")
    plan = json.loads(out)
    assert plan["state"] == "no_such_account_data" and plan["already_removed"] is False

    export = _export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    code, out, _ = do_delete(capsys, data, ACC_A)
    assert code == 0 and "already removed" in out and "no such account data" not in out
    plan = json.loads(do_delete(capsys, data, ACC_A, "--json")[1])
    assert plan["state"] == "already_removed" and plan["already_removed"] is True
    assert plan["removed_at"] and plan["removed_by"] == PERSON


def test_execute_on_unknown_account_says_no_such_data(capsys, data, tmp_path):
    unknown = "acc_" + "c3" * 8
    code, _, err = execute(capsys, data, tmp_path, unknown)
    assert code == 1 and "no such account data" in err and "already removed" not in err


# ------------------------------------------------------------------- 5. export directory
def test_export_dir_swapped_for_a_symlink_after_the_check_is_not_followed(
        capsys, data, tmp_path, monkeypatch):
    out = tmp_path / "exp"
    victim = tmp_path / "victim"
    victim.mkdir()
    moved = tmp_path / "moved"

    def swap(path):
        os.rename(path, moved)
        os.symlink(victim, path)

    monkeypatch.setattr(export_mod, "_AFTER_PREPARE_OUT", swap, raising=False)
    out.mkdir()
    code, _, err = do_export(capsys, data, out)
    # the files went into the directory that was opened, and nothing through the link
    assert list(victim.iterdir()) == []
    assert code == 0, err
    assert (moved / "MANIFEST.json").exists() and (moved / "ledger.db").exists()


def test_export_dir_swapped_before_it_is_opened_is_refused(capsys, data, tmp_path, monkeypatch):
    out = tmp_path / "exp"
    victim = tmp_path / "victim"
    victim.mkdir()
    out.mkdir()

    def swap(path):
        os.rmdir(path)
        os.symlink(victim, path)

    monkeypatch.setattr(export_mod, "_BEFORE_OPEN_OUT", swap, raising=False)
    code, _, err = do_export(capsys, data, out)
    assert code == 2 and "without following a link" in err
    assert list(victim.iterdir()) == []


def test_export_dir_created_fresh_is_0700_and_files_0600(capsys, data, tmp_path):
    out = tmp_path / "a" / "b" / "exp"
    assert do_export(capsys, data, out)[0] == 0
    assert (out.stat().st_mode & 0o777) == 0o700
    assert {(p.stat().st_mode & 0o777) for p in out.iterdir()} == {0o600}
    assert run(capsys, "verify-export", str(out))[0] == 0
