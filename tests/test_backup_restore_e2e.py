"""Backup -> restore end to end: accounts DB + per-account ledgers + attestations + /ai store.

``test_assurance_restore*.py`` pin what ``verify`` finds. This file pins the restore itself,
which used to be "copy the directory" in the runbook and had no code to refuse anything:

* a backup of the whole volume (accounts, operator ledger, per-account ledgers, attestation log,
  the ``/ai`` store) restores into a NEW directory that verifies strictly, whose every ledger
  verifies and has the source's length and head, and which a service can keep appending to;
* a tampered, truncated, rewound, manifest-less or partly deleted backup is REFUSED and nothing
  is written to the target;
* a restore never overwrites, merges into or deletes a live volume or a live ledger;
* plans that were unresolved in the backup cannot be approved after the restore (they may have
  executed after the backup was taken).

Scope: throwaway data on one filesystem. It does not show that an off-host copy exists, that the
manifest was not rewritten together with the data (checksums, not signatures), or restore time on
a large volume.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from assurance.api.deps import tenant_ledger_path
from assurance.attest import AttestationLog, SigningKey, attest, head_of
from assurance.billing.accounts import AccountStore
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger, restore_check
from neuralbridge.ai.store import AiStore, ConnectionRecord, PlanRecord

from .support_sqlite import connect as sqlite_connect
from .support_sqlite import tracked_connections


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


def _tree_hash(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture()
def volume(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("ASSURANCE_LEDGER", str(root / "art14-register.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(root / "accounts.db"))
    monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
    store = AccountStore(root / "accounts.db")
    ids = []
    for i, count in enumerate((7, 4)):
        acct = store.upsert_account(email=f"u{i}@x.invalid", tier="cell",
                                    stripe_customer_id=f"cus_{i}").id
        ids.append(acct)
        led = EvidenceLedger(tenant_ledger_path(acct))
        for n in range(count):
            led.append(_ev(n), subject=f"CASE-{n % 2}")
    EvidenceLedger(root / "art14-register.db").append(_ev(0))
    logs = root / "attestations"
    logs.mkdir()
    key = SigningKey.generate()
    attest(head_of(EvidenceLedger(tenant_ledger_path(ids[0]))), key,
           AttestationLog(logs / f"{ids[0]}.jsonl"), note="")

    ai = tmp_path / "ai" / "neuralbridge-ai.db"
    ai.parent.mkdir()
    ai_store = AiStore(ai)
    ai_store.create_connection(ConnectionRecord(
        id="c1", name="demo", adapter_type="postgres", registry_key="postgres",
        source="seeded_from_env", owner=""))
    for pid, status in (("p-pending", "pending_approval"), ("p-approved", "approved"),
                        ("p-executed", "executed"), ("p-denied", "denied"), ("p-failed", "failed")):
        ai_store.create_plan(PlanRecord(
            id=pid, connection_id="c1", adapter_type="postgres", operation="execute_sql",
            operation_class="write", params={"sql": "INSERT INTO t VALUES (1)"},
            proposed_by="agent", owner=ids[0]))
        with sqlite_connect(ai) as db:
            db.execute("UPDATE plans SET status=? WHERE id=?", (status, pid))
    return root, ids, ai


def _backup(volume, tmp_path, name="bk"):
    root, _ids, ai = volume
    out = tmp_path / name
    restore_check.backup(root, out, ai_store=ai)
    return out


def _entries(path: Path):
    led = EvidenceLedger(path, mint_id=False)
    return [(e.seq, e.link_hash) for e in led.entries()], led.verify_chain()


def test_backup_verify_and_restore_leave_no_sqlite_connection_open(volume, tmp_path):
    """`with sqlite3.connect(...)` does not close; the /ai-store check used it, so a leaked
    connection (a ResourceWarning on 3.13, silent before) was left for the garbage collector."""
    with tracked_connections() as tracker:
        bk = _backup(volume, tmp_path)
        assert restore_check.verify(bk)["status"] == "ok"
        restore_check.restore(bk, tmp_path / "restored")
    assert tracker.connections, "the tracker saw no connection: it is not observing anything"
    leaked = tracker.open_ones()
    assert not leaked, f"{len(leaked)} of {len(tracker.connections)} SQLite connections left open"


# ---------------------------------------------------------------------------
# a good backup restores to something that verifies and can be used
# ---------------------------------------------------------------------------
def test_restore_reproduces_every_ledger_and_the_accounts(volume, tmp_path):
    root, ids, _ai = volume
    bk = _backup(volume, tmp_path)
    assert restore_check.verify(bk)["status"] == "ok"
    target = tmp_path / "restored"
    result = restore_check.restore(bk, target)

    assert (target / restore_check.MANIFEST_NAME).is_file()
    assert result["manifest_sha256"] == hashlib.sha256(
        (bk / restore_check.MANIFEST_NAME).read_bytes()).hexdigest()
    for rel in [f"tenants/{i}.db" for i in ids] + ["art14-register.db"]:
        live, live_ok = _entries(root / rel)
        back, back_ok = _entries(target / rel)
        assert live_ok == back_ok == (True, [])
        assert back == live, f"{rel}: restored chain differs from the source"
    assert [len(_entries(target / f"tenants/{i}.db")[0]) for i in ids] == [7, 4]
    assert {a.id for a in AccountStore(target / "accounts.db").list_accounts()} == set(ids)
    assert (target / "attestations" / f"{ids[0]}.jsonl").read_bytes() == \
        (root / "attestations" / f"{ids[0]}.jsonl").read_bytes()
    # private to the owner, like the backup it came from
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in target.rglob("*") if p.is_file())
    # no staging directory is left beside it
    assert not [p for p in target.parent.iterdir() if p.name.startswith(".restore-")]


def test_a_restored_ledger_keeps_the_chain_when_the_service_appends(volume, tmp_path):
    _root, ids, _ai = volume
    target = tmp_path / "restored"
    restore_check.restore(_backup(volume, tmp_path), target)
    led = EvidenceLedger(target / "tenants" / f"{ids[0]}.db")
    entry = led.append(_ev(99), subject="CASE-NEW")
    assert entry.seq == 8
    assert led.verify_chain() == (True, [])
    # the grown restored volume still agrees with its own backup (it only ever grew)
    assert restore_check.verify(target, allow_growth=True, live_dir=None)["status"] == "ok"


def test_restore_voids_unresolved_ai_plans_and_keeps_the_rest(volume, tmp_path):
    target = tmp_path / "restored"
    result = restore_check.restore(_backup(volume, tmp_path), target)
    assert result["ai_plans_voided"] == {"pending_to_denied": 1, "approved_to_failed": 1}
    store = AiStore(target / "ai-store.db")
    status = {p.id: p.status for p in store.list_plans(limit=50)}
    assert status == {"p-pending": "denied", "p-approved": "failed", "p-executed": "executed",
                      "p-denied": "denied", "p-failed": "failed"}
    assert "voided by restore" in (store.get_plan("p-pending").deny_reason or "")
    assert [c.id for c in store.list_connections()] == ["c1"]
    # the restored pending plan can no longer be claimed (the compare-and-set finds it denied)
    assert store.transition_plan("p-pending", expected="pending_approval", status="approved") is None


def test_the_ai_store_is_part_of_the_backup_only_when_asked_for(volume, tmp_path):
    root, _ids, _ai = volume
    out = tmp_path / "no-ai"
    restore_check.backup(root, out)
    assert not (out / "ai-store.db").exists()
    with_ai = _backup(volume, tmp_path, "with-ai")
    manifest = json.loads((with_ai / restore_check.MANIFEST_NAME).read_text())
    assert "ai-store.db" in manifest["files"]
    with pytest.raises(FileNotFoundError):
        restore_check.backup(root, tmp_path / "x", ai_store=tmp_path / "missing.db")


# ---------------------------------------------------------------------------
# a damaged backup is refused, and nothing is written
# ---------------------------------------------------------------------------
def _refused(bk: Path, tmp_path: Path) -> restore_check.RestoreRefused:
    target = tmp_path / "restored"
    with pytest.raises(restore_check.RestoreRefused) as caught:
        restore_check.restore(bk, target)
    assert not target.exists(), "a refused restore must leave no target"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".restore-")]
    return caught.value


def test_a_tampered_ledger_payload_is_refused(volume, tmp_path):
    _root, ids, _ai = volume
    bk = _backup(volume, tmp_path)
    db = sqlite3.connect(bk / "tenants" / f"{ids[0]}.db")
    db.execute("UPDATE chain SET payload = replace(payload, '\"n\":3', '\"n\":4') WHERE seq = 4")
    db.commit()
    db.close()
    refused = _refused(bk, tmp_path)
    assert any("tenants/" in p for p in refused.problems)


def test_a_truncated_ledger_is_refused(volume, tmp_path):
    _root, ids, _ai = volume
    bk = _backup(volume, tmp_path)
    db = sqlite3.connect(bk / "tenants" / f"{ids[0]}.db")
    db.execute("DELETE FROM chain WHERE seq > 3")  # rows removed from the end: the chain still verifies
    db.commit()
    db.close()
    refused = _refused(bk, tmp_path)
    assert any(ids[0] in p for p in refused.problems)


def test_a_file_cut_short_is_refused(volume, tmp_path):
    _root, ids, _ai = volume
    bk = _backup(volume, tmp_path)
    path = bk / "tenants" / f"{ids[1]}.db"
    path.write_bytes(path.read_bytes()[: path.stat().st_size // 2])
    _refused(bk, tmp_path)


def test_a_deleted_ledger_and_a_deleted_manifest_are_refused(volume, tmp_path):
    _root, ids, _ai = volume
    bk = _backup(volume, tmp_path, "a")
    (bk / "tenants" / f"{ids[1]}.db").unlink()
    assert any("missing" in p for p in _refused(bk, tmp_path).problems)
    bk2 = _backup(volume, tmp_path, "b")
    (bk2 / restore_check.MANIFEST_NAME).unlink()
    refused = _refused(bk2, tmp_path)
    assert "unchecked" in refused.reason


def test_a_tampered_ai_store_and_a_tampered_attestation_log_are_refused(volume, tmp_path):
    _root, ids, _ai = volume
    bk = _backup(volume, tmp_path, "a")
    with sqlite_connect(bk / "ai-store.db") as db:
        db.execute("UPDATE plans SET status='pending_approval' WHERE id='p-executed'")
    _refused(bk, tmp_path)
    bk2 = _backup(volume, tmp_path, "b")
    log = bk2 / "attestations" / f"{ids[0]}.jsonl"
    log.write_text(log.read_text().replace("a", "b", 1))
    _refused(bk2, tmp_path)


def test_a_backup_taken_from_a_broken_source_is_refused(volume, tmp_path):
    root, ids, _ai = volume
    with sqlite_connect(root / "tenants" / f"{ids[0]}.db") as db:
        db.execute("UPDATE chain SET link_hash = 'f' || substr(link_hash, 2) WHERE seq = 2")
    out = tmp_path / "bk"
    restore_check.backup(root, out)
    assert json.loads((out / restore_check.MANIFEST_NAME).read_text())["degraded"] is True
    _refused(out, tmp_path)


# ---------------------------------------------------------------------------
# a restore never overwrites a live volume
# ---------------------------------------------------------------------------
def test_restore_refuses_a_live_volume_and_changes_nothing_in_it(volume, tmp_path):
    root, ids, _ai = volume
    bk = _backup(volume, tmp_path)
    before = _tree_hash(root)
    with pytest.raises(restore_check.RestoreRefused) as caught:
        restore_check.restore(bk, root)
    assert "not empty" in caught.value.reason or "overlap" in caught.value.reason
    assert _tree_hash(root) == before


def test_restore_refuses_any_non_empty_target_even_with_a_single_stray_file(volume, tmp_path):
    bk = _backup(volume, tmp_path)
    target = tmp_path / "other"
    target.mkdir()
    (target / "art14-register.db").write_bytes(b"a live ledger")
    with pytest.raises(restore_check.RestoreRefused, match="not empty"):
        restore_check.restore(bk, target)
    assert (target / "art14-register.db").read_bytes() == b"a live ledger"
    assert [p.name for p in target.iterdir()] == ["art14-register.db"]


def test_restore_refuses_a_file_a_symlink_and_overlaps(volume, tmp_path):
    bk = _backup(volume, tmp_path)
    a_file = tmp_path / "file"
    a_file.write_text("x")
    with pytest.raises(restore_check.RestoreRefused):
        restore_check.restore(bk, a_file)
    elsewhere = tmp_path / "real"
    elsewhere.mkdir()
    link = tmp_path / "link"
    os.symlink(elsewhere, link)
    with pytest.raises(restore_check.RestoreRefused, match="symbolic link"):
        restore_check.restore(bk, link)
    assert list(elsewhere.iterdir()) == []
    with pytest.raises(restore_check.RestoreRefused, match="overlap"):
        restore_check.restore(bk, bk / "inside")
    with pytest.raises(restore_check.RestoreRefused, match="overlap"):
        restore_check.restore(bk, tmp_path)


def test_restore_into_an_existing_empty_directory_works(volume, tmp_path):
    target = tmp_path / "empty"
    target.mkdir()
    restore_check.restore(_backup(volume, tmp_path), target)
    # the only thing a strict verify of the restored volume objects to is the /ai store the restore
    # itself changed (voided plans); every ledger and the accounts DB still match the manifest
    result = restore_check.verify(target)
    assert result["status"] == "failed"
    assert [p.split(":")[0] for p in result["problems"]] == ["ai-store.db"], result["problems"]
    assert (target / "accounts.db").is_file()


def test_a_restore_without_an_ai_store_verifies_clean_afterwards(volume, tmp_path):
    root, _ids, _ai = volume
    out = tmp_path / "no-ai"
    restore_check.backup(root, out)
    target = tmp_path / "restored"
    result = restore_check.restore(out, target)
    assert result["ai_plans_voided"] == {}
    assert restore_check.verify(target)["status"] == "ok"


def test_a_second_restore_to_the_same_target_is_refused(volume, tmp_path):
    bk = _backup(volume, tmp_path)
    target = tmp_path / "restored"
    restore_check.restore(bk, target)
    before = _tree_hash(target)
    with pytest.raises(restore_check.RestoreRefused, match="not empty"):
        restore_check.restore(bk, target)
    assert _tree_hash(target) == before


# ---------------------------------------------------------------------------
# a restore does not roll back a surviving volume silently
# ---------------------------------------------------------------------------
def test_a_restore_older_than_the_surviving_volume_is_a_shorter_ledger_not_a_fork(volume, tmp_path):
    root, ids, _ai = volume
    bk = _backup(volume, tmp_path)
    EvidenceLedger(root / "tenants" / f"{ids[0]}.db").append(_ev(50), subject="LATER")
    target = tmp_path / "restored"
    restore_check.restore(bk, target)
    # the survivor is longer than the restore: --against-live accepts it as the same lineage ...
    assert restore_check.verify(target, allow_growth=True, live_dir=root)["status"] == "ok"
    # ... and a restored copy that then diverges from the survivor is reported as a fork
    EvidenceLedger(target / "tenants" / f"{ids[0]}.db").append(_ev(51), subject="DIVERGED")
    result = restore_check.verify(target, allow_growth=True, live_dir=root)
    assert result["status"] == "failed", result


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------
def test_cli_backup_restore_exit_codes(volume, tmp_path, capsys):
    root, _ids, ai = volume
    out = tmp_path / "cli-bk"
    assert restore_check.main(["backup", str(root), str(out), "--ai-store", str(ai)]) == 0
    capsys.readouterr()
    target = tmp_path / "cli-restored"
    assert restore_check.main(["restore", str(out), str(target)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["restored_to"] == str(target)
    assert restore_check.main(["restore", str(out), str(target)]) == 1      # now non-empty
    assert json.loads(capsys.readouterr().out)["restored"] is False
    (out / "tenants" / next((out / "tenants").iterdir()).name).write_bytes(b"junk")
    assert restore_check.main(["restore", str(out), str(tmp_path / "again")]) == 1
    assert not (tmp_path / "again").exists()
    assert restore_check.main(["restore", str(out)]) == 2                    # usage
