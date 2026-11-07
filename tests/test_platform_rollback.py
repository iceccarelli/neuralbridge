# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Anti-rollback: restoring an OLDER backup must not bring back a revoked or rotated-away credential.

The scenario the previous change left open: ``restore_check restore`` puts an older ``/ai`` store
back (that is its job), and with it a connection that was revoked since, with its old credential.
The defence is a journal kept OUTSIDE the restored data set (``neuralbridge.ai.credentials``): every
create/rotate/revoke/delete is written to it first, and every use of a stored credential is checked
against it. These tests do the whole thing with the real ``restore_check`` — nothing is simulated
except that the "old credential" still works at the database (its password is NOT changed), so the
only thing standing between it and use is the guard.

Not claimed: a whole-volume snapshot restore that rewinds the journal too (see the same-device
warning in ``/health/ready``), or a hostile operator who rewrites the journal.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assurance.evidence import restore_check
from neuralbridge.ai import credentials as cred
from neuralbridge.ai.credentials import CredentialVault

from .credential_support import (
    ROLE_A,
    ROLE_B,
    SECRET_1,
    SECRET_2,
    bind_as,
    roles,
    rotate_to,
    sql,
    store_path,
    whoami,
)
from .platform_support import (
    API,
    Keys,
    audit_events,
    client,
    env,
    h,
    keys,
    read,
    requires_postgres,
    reset_singletons,
)

pytestmark = requires_postgres


@pytest.fixture
def volume(env, tmp_path):
    """A data directory next to the ai store, as ``restore_check backup`` expects."""
    vol = tmp_path / "vol"
    vol.mkdir()
    shutil.copy(env, vol / "accounts.db")
    return vol


def backup(volume: Path, tmp_path: Path, name: str) -> Path:
    out = tmp_path / f"bk-{name}"
    restore_check.backup(volume, out, ai_store=store_path())
    return out


def restore_into_service(client_cls_env, backup_dir: Path, tmp_path: Path, monkeypatch, name: str) -> Path:
    """Restore ``backup_dir`` to a NEW directory and point the service at the restored ai store."""
    target = tmp_path / f"restored-{name}"
    restore_check.restore(backup_dir, target)
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(target / "ai-store.db"))
    reset_singletons()
    return target


@pytest.fixture
def no_decrypt_of(monkeypatch):
    """Fail the test if the ciphertext of ``ids`` is ever DECRYPTED: a refused connection must be
    refused before its credential is even opened."""
    forbidden: set[str] = set()
    real = CredentialVault.open

    def guarded(self, row, record):
        assert record.id not in forbidden, "a revoked/rolled-back credential was decrypted"
        return real(self, row, record)

    monkeypatch.setattr(CredentialVault, "open", guarded)
    return forbidden


class TestRestoreOfAnOlderBackup:
    def test_create_rotate_revoke_backup_restore_the_older_backup_does_not_resurrect_the_credential(
        self, client, keys: Keys, roles, volume, tmp_path, monkeypatch, no_decrypt_of
    ) -> None:
        conn = bind_as(client, keys.a, user=ROLE_A, password=SECRET_1)              # create (v1)
        older = backup(volume, tmp_path, "after-create")                            # <- the OLDER backup
        assert rotate_to(client, keys.a, conn["id"]).status_code == 200             # rotate (v2)
        middle = backup(volume, tmp_path, "after-rotate")
        assert client.post(f"{API}/connections/{conn['id']}/revoke", headers=h(keys.a)).status_code == 200
        newest = backup(volume, tmp_path, "after-revoke")
        assert read(client, keys.a, conn["id"]).status_code == 409
        no_decrypt_of.add(conn["id"])

        for name, bk in (("older", older), ("middle", middle)):
            target = restore_into_service(client, bk, tmp_path, monkeypatch, name)
            # the restored store really does say "active, with a stored credential" - that is the danger
            row = sqlite3.connect(target / "ai-store.db").execute(
                "SELECT status, cred_version FROM connections WHERE id=?", (conn["id"],)).fetchone()
            assert row[0] in ("created", "rotated") and row[1] in (1, 2)
            assert sqlite3.connect(target / "ai-store.db").execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 1
            with TestClient(__import__("neuralbridge.main", fromlist=["create_app"]).create_app()) as fresh:
                r = read(fresh, keys.a, conn["id"])
                assert r.status_code == 409 and "revoked" in r.json()["detail"], (name, r.text)
                assert whoami(fresh, keys.a, conn["id"]).status_code == 409
                plan = fresh.post(f"{API}/plan", headers=h(keys.a), json={
                    "connection_id": conn["id"], "operation": "execute_sql", "params": {"sql": "SELECT 1"}})
                assert plan.status_code in (400, 409)
                listed = [c for c in fresh.get(f"{API}/connections", headers=h(keys.a)).json() if c["id"] == conn["id"]][0]
                assert listed["status"] == "revoked" and listed["usable"] is False
                # the journal's verdict was written back: the restored store now agrees, ciphertext gone
                healed = sqlite3.connect(target / "ai-store.db")
                assert healed.execute("SELECT status FROM connections WHERE id=?", (conn["id"],)).fetchone()[0] == "revoked"
                assert healed.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
            reset_singletons()

        # the newest backup (revoked) restores to the same answer
        restore_into_service(client, newest, tmp_path, monkeypatch, "newest")
        with TestClient(__import__("neuralbridge.main", fromlist=["create_app"]).create_app()) as fresh:
            assert read(fresh, keys.a, conn["id"]).status_code == 409
        reset_singletons()

    def test_a_rotation_rolled_back_by_a_restore_is_refused_until_the_connection_is_rotated_again(
        self, client, keys: Keys, roles, volume, tmp_path, monkeypatch
    ) -> None:
        conn = bind_as(client, keys.a, user=ROLE_A, password=SECRET_1)
        older = backup(volume, tmp_path, "v1")
        assert rotate_to(client, keys.a, conn["id"]).status_code == 200            # v2: ROLE_A's credential is out of service
        restore_into_service(client, older, tmp_path, monkeypatch, "v1")
        with TestClient(__import__("neuralbridge.main", fromlist=["create_app"]).create_app()) as fresh:
            r = read(fresh, keys.a, conn["id"])
            assert r.status_code == 409 and "already issued version 2" in r.json()["detail"]
            assert "rotate the connection" in r.json()["detail"]
            # rotation is the way back, and it resumes ABOVE the high-water mark
            ok = rotate_to(fresh, keys.a, conn["id"], user=ROLE_A, password=SECRET_1)
            assert ok.status_code == 200 and ok.json()["cred_version"] == 3
            assert whoami(fresh, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_A
        reset_singletons()

    def test_a_deleted_connection_is_not_resurrected_either(
        self, client, keys: Keys, roles, volume, tmp_path, monkeypatch
    ) -> None:
        conn = bind_as(client, keys.a)
        older = backup(volume, tmp_path, "before-delete")
        assert client.delete(f"{API}/connections/{conn['id']}", headers=h(keys.a)).status_code == 200
        restore_into_service(client, older, tmp_path, monkeypatch, "deleted")
        with TestClient(__import__("neuralbridge.main", fromlist=["create_app"]).create_app()) as fresh:
            assert read(fresh, keys.a, conn["id"]).status_code == 409
            # the journal's "deleted" was applied to the restored store: the record is gone again
            assert [c for c in fresh.get(f"{API}/connections", headers=h(keys.a)).json() if c["id"] == conn["id"]] == []
            assert sqlite3.connect(tmp_path / "restored-deleted" / "ai-store.db").execute(
                "SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
        reset_singletons()

    def test_the_reconcile_command_applies_the_journal_to_a_restored_store(
        self, client, keys: Keys, roles, volume, tmp_path, monkeypatch, capsys
    ) -> None:
        a, b = bind_as(client, keys.a, "a"), bind_as(client, keys.a, "b")
        older = backup(volume, tmp_path, "both-live")
        client.post(f"{API}/connections/{a['id']}/revoke", headers=h(keys.a))
        client.delete(f"{API}/connections/{b['id']}", headers=h(keys.a))
        target = restore_into_service(client, older, tmp_path, monkeypatch, "reconcile")
        assert cred.main(["reconcile", "--store", str(target / "ai-store.db")]) == 0
        assert json.loads(capsys.readouterr().out) == {"revoked": 1, "deleted": 1}
        db = sqlite3.connect(target / "ai-store.db")
        assert db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
        assert db.execute("SELECT id, status FROM connections").fetchall() == [(a["id"], "revoked")]

    def test_an_unrelated_connection_keeps_working_after_the_restore(
        self, client, keys: Keys, roles, volume, tmp_path, monkeypatch
    ) -> None:
        keep, gone = bind_as(client, keys.a, "keep"), bind_as(client, keys.a, "gone")
        older = backup(volume, tmp_path, "pair")
        client.post(f"{API}/connections/{gone['id']}/revoke", headers=h(keys.a))
        restore_into_service(client, older, tmp_path, monkeypatch, "pair")
        with TestClient(__import__("neuralbridge.main", fromlist=["create_app"]).create_app()) as fresh:
            assert whoami(fresh, keys.a, keep["id"]).json()["data"][0]["u"] == ROLE_A
            assert read(fresh, keys.a, gone["id"]).status_code == 409
        reset_singletons()


class TestWhereTheGuaranteeStops:
    """The limits are enforced as refusals, not left as prose."""

    def test_a_journal_that_would_be_restored_with_the_store_is_refused(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_JOURNAL", str(store_path().parent / "custody" / "journal.jsonl"))
        r = client.post(f"{API}/connections", headers=h(keys.a), json={
            "name": "x", "host": "h", "user": "u", "password": SECRET_1, "database": "d"})
        assert r.status_code == 503 and "inside the /ai store's directory" in r.json()["detail"]["message"]

    def test_a_restore_without_the_journal_serves_nothing_from_the_vault(
        self, client, keys: Keys, roles, volume, tmp_path, monkeypatch
    ) -> None:
        """Restore store AND journal to a new place (the volume-snapshot case with a missing journal)."""
        conn = bind_as(client, keys.a)
        older = backup(volume, tmp_path, "nojournal")
        restore_into_service(client, older, tmp_path, monkeypatch, "nojournal")
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_JOURNAL", str(tmp_path.parent / f"{tmp_path.name}-fresh" / "j.jsonl"))
        with TestClient(__import__("neuralbridge.main", fromlist=["create_app"]).create_app()) as fresh:
            r = read(fresh, keys.a, conn["id"])
            assert r.status_code == 503 and "not the one this store was created with" in r.json()["detail"]
        reset_singletons()

    def test_the_readiness_probe_reports_a_journal_that_shares_the_stores_device(self, client, keys: Keys) -> None:
        ready = client.get("/api/v1/health/ready").json()
        # tests run on one filesystem, so this is the honest answer there: the warning names the limit
        assert ready["credential_custody"]["journal"]["same_device"] is True
        assert any(n.startswith("credential_journal_same_device") for n in ready["notices"])
