"""A backup of the whole data volume restores to something that verifies.

Uses the real stores: accounts, per-account tenant ledgers written through the
service, and the operator ledger — then corrupts, truncates and orphans files
and expects the check to say so.
"""

from __future__ import annotations

import shutil
import sqlite3

import pytest

from assurance.api.deps import tenant_ledger_path
from assurance.billing.accounts import AccountStore
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger, restore_check


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


@pytest.fixture()
def data(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("ASSURANCE_LEDGER", str(root / "art14-register.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(root / "accounts.db"))
    monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
    store = AccountStore(root / "accounts.db")
    ids = []
    for name in ("a", "b"):
        acct = store.upsert_account(email=f"{name}@x.invalid", tier="cell",
                                    stripe_customer_id=f"cus_{name}")
        led = EvidenceLedger(tenant_ledger_path(acct.id))
        for i in range(4):
            led.append(_ev(i), subject="CASE-1")
        ids.append(acct.id)
    (root / "attestations").mkdir()
    (root / "attestations" / f"{ids[0]}.jsonl").write_text('{"x":1}\n')
    (root / "supplier-feeds").mkdir()
    (root / "supplier-feeds" / f"{ids[0]}.jsonl").write_text('{"y":1}\n')
    shared = EvidenceLedger(root / "art14-register.db")
    shared.append(_ev(0))
    return root, ids


def test_backup_then_verify_covers_every_tenant(data, tmp_path):
    root, ids = data
    names = restore_check.backup(root, tmp_path / "bk")
    assert set(names) == {"accounts.db", "art14-register.db", "attestations/",
                          "supplier-feeds/", *(f"tenants/{i}.db" for i in ids)}
    assert (tmp_path / "bk" / "attestations" / f"{ids[0]}.jsonl").read_text() == '{"x":1}\n'
    result = restore_check.verify(tmp_path / "bk")
    assert result["ok"], result
    assert all(result["checked"][f"tenants/{i}.db"] == 4 for i in ids)
    assert result["not_established"]


def test_a_tampered_tenant_ledger_is_found_in_the_restore(data, tmp_path):
    root, ids = data
    restore_check.backup(root, tmp_path / "bk")
    db = sqlite3.connect(tmp_path / "bk" / "tenants" / f"{ids[0]}.db")
    db.execute("UPDATE chain SET payload = replace(payload, '\"n\":1', '\"n\":9') WHERE seq = 2")
    db.commit()
    db.close()
    result = restore_check.verify(tmp_path / "bk")
    assert not result["ok"]
    assert any(ids[0] in p for p in result["problems"])


def test_a_missing_accounts_db_and_an_orphan_ledger_are_findings(data, tmp_path):
    root, ids = data
    restore_check.backup(root, tmp_path / "bk")
    (tmp_path / "bk" / "accounts.db").unlink()
    assert not restore_check.verify(tmp_path / "bk")["ok"]

    restore_check.backup(root, tmp_path / "bk2")
    shutil.copy(tmp_path / "bk2" / "tenants" / f"{ids[0]}.db",
                tmp_path / "bk2" / "tenants" / "acc_0123456789abcdef.db")
    result = restore_check.verify(tmp_path / "bk2")
    assert not result["ok"] and any("belongs to no account" in p for p in result["problems"])


def test_a_garbage_file_is_a_finding_not_a_crash(data, tmp_path):
    root, ids = data
    restore_check.backup(root, tmp_path / "bk")
    (tmp_path / "bk" / "tenants" / f"{ids[1]}.db").write_bytes(b"not a database" * 100)
    result = restore_check.verify(tmp_path / "bk")
    assert not result["ok"]


def test_cli_exit_codes(data, tmp_path):
    root, _ = data
    assert restore_check.main(["backup", str(root), str(tmp_path / "bk")]) == 0
    assert restore_check.main(["verify", str(tmp_path / "bk")]) == 0
    assert restore_check.main(["verify", str(tmp_path / "nowhere")]) == 1
    assert restore_check.main(["backup", str(tmp_path / "nowhere"), str(tmp_path / "x")]) == 2
    assert restore_check.main([]) == 2
