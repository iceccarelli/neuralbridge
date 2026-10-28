"""A restore that has lost evidence must not verify; a backup is not world-readable.

An independent review of ``evidence.restore_check`` found that ``verify`` only checked the
files that exist: a backup with no operator ledger and no ``tenants/`` directory, although
``accounts.db`` listed a paying account, verified "ok"; a tenant ledger rewound from 6
records to 2 verified "ok" while ``attest verify --ledger`` on the same backup said four
records were removed after being attested; and ``backup`` wrote ``accounts.db`` mode 0644
with the unclaimed plaintext API keys of ``pending_keys`` inside, then the runbook copies
it off the volume.

``backup`` now writes a manifest (file list, sizes, sha256, each ledger's head and length,
the account list); ``verify`` fails on anything that does not match it, cross-checks every
attestation log against its ledger, and reports a backup without a manifest as *unchecked*
(exit 3), never as ok.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

from assurance.api.deps import tenant_ledger_path
from assurance.attest import AttestationLog, SigningKey, attest, head_of
from assurance.billing.accounts import AccountStore
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger, restore_check

MANIFEST = "backup-manifest.json"
PENDING_SESSION = "cs_pending_unclaimed"


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


@pytest.fixture()
def data(tmp_path, monkeypatch):
    """A data volume: two accounts (one with an unclaimed checkout key), their ledgers (6 and
    3 records), an attestation log over the first, and the operator ledger."""
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("ASSURANCE_LEDGER", str(root / "art14-register.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(root / "accounts.db"))
    monkeypatch.delenv("ASSURANCE_TENANT_LEDGERS", raising=False)
    store = AccountStore(root / "accounts.db")
    first = store.apply_checkout(
        event_id="e1", session_id=PENDING_SESSION, email="a@x.invalid", company="A",
        tier="cell", stripe_customer_id="cus_a", stripe_subscription_id="sub_a",
        event_created=1_800_000_000)["account_id"]
    second = store.upsert_account(email="b@x.invalid", tier="cell",
                                  stripe_customer_id="cus_b").id
    for acct, count in ((first, 6), (second, 3)):
        led = EvidenceLedger(tenant_ledger_path(acct))
        for i in range(count):
            led.append(_ev(i), subject="CASE-1")
    EvidenceLedger(root / "art14-register.db").append(_ev(0))
    log_dir = root / "attestations"
    log_dir.mkdir()
    key = SigningKey.generate()
    attest(head_of(EvidenceLedger(tenant_ledger_path(first))), key,
           AttestationLog(log_dir / f"{first}.jsonl"), note="")
    return root, first, second


def _backup(root: Path, tmp_path: Path, name: str = "bk") -> Path:
    out = tmp_path / name
    restore_check.backup(root, out)
    return out


def _rewind(path: Path, keep: int) -> None:
    db = sqlite3.connect(path)
    db.execute("DELETE FROM chain WHERE seq > ?", (keep,))
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# the manifest
# ---------------------------------------------------------------------------
def test_a_backup_carries_a_manifest_and_verifies_against_it(data, tmp_path):
    root, first, second = data
    bk = _backup(root, tmp_path)
    manifest = json.loads((bk / MANIFEST).read_text())
    assert set(manifest["files"]) >= {"accounts.db", "art14-register.db",
                                      f"tenants/{first}.db", f"tenants/{second}.db",
                                      f"attestations/{first}.jsonl"}
    entry = manifest["files"][f"tenants/{first}.db"]
    assert len(entry["sha256"]) == 64 and entry["size"] > 0 and entry["entries"] == 6
    assert sorted(manifest["accounts"]) == sorted([first, second])
    result = restore_check.verify(bk)
    assert result["ok"] is True and result["status"] == "ok", result


def test_a_backup_missing_every_ledger_does_not_verify(data, tmp_path):
    root, _, _ = data
    bk = _backup(root, tmp_path)
    shutil.rmtree(bk / "tenants")
    (bk / "art14-register.db").unlink()
    result = restore_check.verify(bk)
    assert result["ok"] is False and result["status"] == "failed"
    text = " ".join(result["problems"])
    assert "art14-register.db" in text and "missing" in text
    assert text.count("tenants/") >= 2


def test_one_missing_tenant_ledger_is_named(data, tmp_path):
    root, first, second = data
    bk = _backup(root, tmp_path)
    (bk / "tenants" / f"{second}.db").unlink()
    result = restore_check.verify(bk)
    assert not result["ok"]
    assert any(second in p and "missing" in p for p in result["problems"])


def test_a_ledger_rewound_in_the_backup_does_not_verify(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    _rewind(bk / "tenants" / f"{first}.db", 2)
    assert EvidenceLedger(bk / "tenants" / f"{first}.db").verify_chain()[0]  # chain still fine
    result = restore_check.verify(bk)
    assert not result["ok"]
    assert any(first in p for p in result["problems"])


def test_a_changed_file_fails_its_hash(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    log = bk / "attestations" / f"{first}.jsonl"
    log.write_bytes(log.read_bytes() + b"\n")
    result = restore_check.verify(bk)
    assert not result["ok"]
    assert any("sha256" in p and f"attestations/{first}.jsonl" in p for p in result["problems"])


def test_a_missing_accounts_db_fails_even_with_a_manifest(data, tmp_path):
    root, _, _ = data
    bk = _backup(root, tmp_path)
    (bk / "accounts.db").unlink()
    result = restore_check.verify(bk)
    assert not result["ok"]
    assert any("accounts.db" in p for p in result["problems"])


def test_an_extra_file_the_manifest_does_not_know_is_a_finding(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    shutil.copy(bk / "tenants" / f"{first}.db", bk / "tenants" / "acc_0123456789abcdef.db")
    result = restore_check.verify(bk)
    assert not result["ok"]
    assert any("acc_0123456789abcdef" in p for p in result["problems"])


# ---------------------------------------------------------------------------
# attestation logs are cross-checked against the ledgers they were signed over
# ---------------------------------------------------------------------------
def test_a_rewind_is_caught_by_the_attestation_log_even_without_a_manifest(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    (bk / MANIFEST).unlink()                      # an old backup: only the attestation can tell
    _rewind(bk / "tenants" / f"{first}.db", 2)
    result = restore_check.verify(bk)
    assert result["ok"] is False and result["status"] == "failed", result
    assert any("removed after being attested" in p and first in p for p in result["problems"])


def test_an_attestation_log_whose_ledger_is_gone_is_a_finding_without_a_manifest(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    (bk / MANIFEST).unlink()
    (bk / "tenants" / f"{first}.db").unlink()
    result = restore_check.verify(bk)
    assert result["status"] == "failed"
    assert any(first in p and "attest" in p for p in result["problems"])


def test_an_intact_ledger_passes_the_attestation_cross_check(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    result = restore_check.verify(bk)
    assert result["ok"] and result["attestation_records"][f"attestations/{first}.jsonl"] == 1


# ---------------------------------------------------------------------------
# a backup without a manifest is unchecked, never ok
# ---------------------------------------------------------------------------
def test_a_backup_without_a_manifest_is_unchecked_not_ok(data, tmp_path):
    root, _, _ = data
    bk = _backup(root, tmp_path)
    (bk / MANIFEST).unlink()
    result = restore_check.verify(bk)
    assert result["ok"] is False
    assert result["status"] == "unchecked"
    assert result["problems"] == []
    assert any("no manifest" in u for u in result["unchecked"])


def test_exit_codes_distinguish_ok_finding_unchecked_and_cannot_run(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    assert restore_check.main(["verify", str(bk)]) == 0
    (bk / MANIFEST).unlink()
    assert restore_check.main(["verify", str(bk)]) == 3
    bad = _backup(root, tmp_path, "bk2")
    _rewind(bad / "tenants" / f"{first}.db", 2)
    assert restore_check.main(["verify", str(bad)]) == 1
    assert restore_check.main([]) == 2


# ---------------------------------------------------------------------------
# a live volume that has grown since the backup
# ---------------------------------------------------------------------------
def test_a_volume_that_grew_since_the_backup_verifies_only_in_live_mode(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    volume = tmp_path / "volume"
    shutil.copytree(bk, volume)
    EvidenceLedger(volume / "tenants" / f"{first}.db").append(_ev(99), subject="CASE-2")
    assert restore_check.verify(volume)["ok"] is False                    # exact: it differs
    assert restore_check.verify(volume, allow_growth=True)["ok"] is True  # it only grew
    assert restore_check.main(["verify", "--live", str(volume)]) == 0


def test_a_volume_that_shrank_fails_even_in_live_mode(data, tmp_path):
    root, first, _ = data
    bk = _backup(root, tmp_path)
    volume = tmp_path / "volume"
    shutil.copytree(bk, volume)
    _rewind(volume / "tenants" / f"{first}.db", 2)
    result = restore_check.verify(volume, allow_growth=True)
    assert not result["ok"] and any(first in p for p in result["problems"])
    assert any("record(s) were removed since" in p for p in result["problems"])


# ---------------------------------------------------------------------------
# the backup is a secret and is treated as one
# ---------------------------------------------------------------------------
def _plain_key(root: Path) -> str:
    db = sqlite3.connect(root / "accounts.db")
    try:
        return str(db.execute("SELECT api_key FROM pending_keys").fetchone()[0])
    finally:
        db.close()


def test_the_backup_is_private_to_its_owner(data, tmp_path):
    root, _, _ = data
    old = os.umask(0o022)   # the umask that made the original files world-readable
    try:
        bk = _backup(root, tmp_path)
    finally:
        os.umask(old)
    modes = {p.relative_to(bk).as_posix(): stat.S_IMODE(p.stat().st_mode)
             for p in [bk, *bk.rglob("*")]}
    loose = {name: oct(mode) for name, mode in modes.items() if mode & 0o077}
    assert loose == {}, loose
    assert modes["."] == 0o700 and modes["accounts.db"] == 0o600


def test_unclaimed_plaintext_keys_are_not_copied_into_the_backup(data, tmp_path):
    root, _, _ = data
    key = _plain_key(root)
    assert key.startswith("asr_")
    bk = _backup(root, tmp_path)
    db = sqlite3.connect(bk / "accounts.db")
    assert db.execute("SELECT COUNT(*) FROM pending_keys").fetchone()[0] == 0
    db.close()
    for path in bk.rglob("*"):
        if path.is_file():
            assert key.encode() not in path.read_bytes(), path   # not even in a free page
    assert json.loads((bk / MANIFEST).read_text())["pending_keys_not_copied"] == 1


def test_taking_a_backup_does_not_consume_the_live_pending_key(data, tmp_path):
    root, _, _ = data
    _backup(root, tmp_path)
    claimed = AccountStore(root / "accounts.db").claim_pending_key(PENDING_SESSION)
    assert claimed is not None and claimed["api_key"].startswith("asr_")


def test_a_backup_of_a_backup_dir_with_loose_permissions_is_tightened(data, tmp_path):
    root, _, _ = data
    out = tmp_path / "loose"
    out.mkdir(mode=0o755)
    os.chmod(out, 0o755)  # noqa: S103
    restore_check.backup(root, out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700


def test_a_key_claimed_before_the_backup_is_not_left_in_the_copy_either(data, tmp_path):
    # On a SQLite build without secure_delete the live file still holds the claimed key's bytes
    # in space the delete freed, and a page-level copy would carry them; the backup is rewritten
    # (VACUUM) so it does not. (On a build that secure-deletes by default this cannot fail.)
    root, _, _ = data
    key = _plain_key(root)
    store = AccountStore(root / "accounts.db")
    assert store.claim_pending_key(PENDING_SESSION)["api_key"] == key
    bk = _backup(root, tmp_path)
    assert key.encode() not in (bk / "accounts.db").read_bytes()
