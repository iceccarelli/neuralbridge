# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Credential custody for bound /ai connections: sealed, shared, rotated, revoked, audited.

Each worker process is simulated by a fresh adapter registry over the same store, journal and
environment (``as_other_worker``); ``test_platform_multiworker_custody.py`` repeats the key claims
with real uvicorn worker processes.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from neuralbridge.ai import credentials as cred
from neuralbridge.ai.credentials import (
    CustodyConfig,
    CustodyError,
    KeyRing,
    RollbackJournal,
    load_keyring,
)

from .credential_support import (
    ROLE_A,
    ROLE_B,
    SECRET_1,
    SECRET_2,
    as_other_worker,
    bind_as,
    body,
    new_key,
    roles,
    rotate_to,
    sql,
    store_path,
    whoami,
    workers,
)
from .platform_support import (
    API,
    OPERATOR_KEY,
    Keys,
    audit_events,
    client,
    env,
    h,
    keys,
    read,
    requires_postgres,
)

pytestmark = requires_postgres


def bind_raw(client, key, **extra):
    return client.post(f"{API}/connections", headers=h(key), json=body("raw", **extra))


# ───────────────────────────── fail closed ─────────────────────────────


class TestFailsClosedWithoutSafeCustody:
    def test_no_key_configured_refuses_to_bind_with_a_clear_error(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_KEYS")
        r = bind_raw(client, keys.a)
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert detail["error"] == "credential_custody_unconfigured"
        assert "NEURALBRIDGE_CREDENTIAL_KEYS" in detail["message"]
        assert "single-worker" in detail["message"]
        assert SECRET_1 not in r.text
        assert [c for c in client.get(f"{API}/connections", headers=h(keys.a)).json()
                if c["source"] != "seeded_from_env"] == []

    def test_a_key_without_an_anti_rollback_journal_is_refused(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_JOURNAL")
        r = bind_raw(client, keys.a)
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "credential_custody_unconfigured"
        assert "NEURALBRIDGE_CREDENTIAL_JOURNAL" in r.json()["detail"]["message"]

    def test_a_journal_inside_the_stores_directory_is_refused(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_JOURNAL", str(store_path().parent / "journal.jsonl"))
        r = bind_raw(client, keys.a)
        assert r.status_code == 503
        assert "inside the /ai store's directory" in r.json()["detail"]["message"]

    @pytest.mark.parametrize("bad", ["not-base64!!", base64.b64encode(b"short").decode(),
                                     base64.b64encode(os.urandom(48)).decode()])
    def test_a_malformed_key_is_refused_and_never_echoed(self, client, keys: Keys, monkeypatch, bad) -> None:
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"k1:{bad}")
        r = bind_raw(client, keys.a)
        assert r.status_code == 503
        assert bad not in r.text

    def test_a_key_file_must_be_private_and_outside_the_store_directory(self, client, keys: Keys, monkeypatch, tmp_path) -> None:
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_KEYS")
        sibling = tmp_path.parent / f"{tmp_path.name}-keys"
        sibling.mkdir()
        good = sibling / "keys"
        good.write_text(f"k1:{new_key()}\n")
        good.chmod(0o640)
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEY_FILE", str(good))
        r = bind_raw(client, keys.a)
        assert r.status_code == 503 and "group or others" in r.json()["detail"]["message"]
        good.chmod(0o600)
        assert bind_raw(client, keys.a).status_code == 200
        beside = tmp_path / "keys"  # next to the ciphertext: backed up and restored with it
        beside.write_text(good.read_text())
        beside.chmod(0o600)
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEY_FILE", str(beside))
        r = bind_raw(client, keys.a)
        assert r.status_code == 503 and "inside the /ai store's directory" in r.json()["detail"]["message"]

    def test_several_keys_need_an_explicit_active_one(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"a:{new_key()},b:{new_key()}")
        assert bind_raw(client, keys.a).status_code == 503
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY", "nope")
        assert bind_raw(client, keys.a).status_code == 503
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY", "b")
        assert bind_raw(client, keys.a).status_code == 200

    def test_rotate_is_refused_without_custody_but_revoke_and_delete_still_work(
        self, client, keys: Keys, roles, monkeypatch
    ) -> None:
        a, b = bind_as(client, keys.a), bind_as(client, keys.a, "second")
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_KEYS")
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_JOURNAL")
        r = rotate_to(client, keys.a, a["id"])
        assert r.status_code == 503 and r.json()["detail"]["error"] == "credential_custody_unconfigured"
        assert read(client, keys.a, a["id"]).status_code == 503  # a stored credential is not served unsafely
        assert client.post(f"{API}/connections/{a['id']}/revoke", headers=h(keys.a)).status_code == 200
        assert client.delete(f"{API}/connections/{b['id']}", headers=h(keys.a)).status_code == 200
        assert sql("SELECT COUNT(*) AS n FROM credentials")[0]["n"] == 0


class TestProcessLocalIsAnExplicitSingleWorkerOptIn:
    @pytest.fixture
    def local(self, monkeypatch):
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_KEYS")
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_JOURNAL")
        monkeypatch.setenv("NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS", "single-worker")
        monkeypatch.delenv("WEB_CONCURRENCY", raising=False)

    def test_it_binds_and_is_labelled_process_local(self, client, keys: Keys, roles, local) -> None:
        conn = bind_as(client, keys.a)
        assert conn["custody"] == "process_local" and conn["live"] and conn["cred_version"] is None
        assert whoami(client, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_A
        assert sql("SELECT COUNT(*) AS n FROM credentials")[0]["n"] == 0, "process-local stores nothing"
        ready = client.get("/api/v1/health/ready").json()
        assert any("credential_custody_process_local" in w for w in ready["warnings"])

    def test_another_worker_answers_an_honest_409_naming_the_single_worker_limit(
        self, client, keys: Keys, roles, local
    ) -> None:
        conn = bind_as(client, keys.a)
        with as_other_worker():
            r = read(client, keys.a, conn["id"])
            assert r.status_code == 409 and "process-local" in r.json()["detail"]
            listed = [c for c in client.get(f"{API}/connections", headers=h(keys.a)).json() if c["id"] == conn["id"]]
            assert listed[0]["live"] is False and listed[0]["usable"] is False

    def test_it_is_refused_when_more_than_one_worker_is_declared(self, client, keys: Keys, local, monkeypatch) -> None:
        monkeypatch.setenv("WEB_CONCURRENCY", "4")
        r = bind_raw(client, keys.a)
        assert r.status_code == 503 and "WEB_CONCURRENCY=4" in r.json()["detail"]["message"]

    def test_it_never_activates_by_itself(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_KEYS")
        monkeypatch.setenv("NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS", "yes")
        assert bind_raw(client, keys.a).status_code == 503

    def test_a_process_local_connection_can_be_moved_into_the_vault_by_rotating(
        self, client, keys: Keys, roles, local, monkeypatch
    ) -> None:
        conn = bind_as(client, keys.a)
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"k1:{new_key()}")
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_JOURNAL", str(store_path().parent.parent / "mv-custody" / "j.jsonl"))
        monkeypatch.delenv("NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS")
        r = rotate_to(client, keys.a, conn["id"])
        assert r.status_code == 200 and r.json()["custody"] == "vault" and r.json()["cred_version"] == 1
        with as_other_worker():
            assert whoami(client, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_B


# ───────────────────────────── encryption at rest ─────────────────────────────


class TestSealedAtRest:
    def test_no_plaintext_secret_or_user_is_stored_anywhere(self, client, keys: Keys, roles, tmp_path, capfd, caplog) -> None:
        caplog.set_level("DEBUG")
        conn = bind_as(client, keys.a, user=ROLE_A, password=SECRET_1)
        rotate_to(client, keys.a, conn["id"], user=ROLE_B, password=SECRET_2)
        whoami(client, keys.a, conn["id"])
        client.get(f"{API}/audit", headers=h(keys.a), params={"limit": 500})
        sibling = tmp_path.parent / f"{tmp_path.name}-custody"
        files = [p for p in list(tmp_path.glob("*")) + list(sibling.glob("*")) if p.is_file()]
        assert any(p.name == "journal.jsonl" for p in files) and any(p.name == "ai-store.db" for p in files)
        for p in files:
            data = p.read_bytes()
            for needle in (SECRET_1, SECRET_2, ROLE_B + ":", f'"password":"{SECRET_2}'):
                assert needle.encode() not in data, (p.name, needle)
        # the credential ROW exists and is opaque; the user name is inside the ciphertext too
        row = sql("SELECT * FROM credentials")[0]
        assert row["key_id"] == "test-key-1" and len(bytes(row["nonce"])) == 12 and len(bytes(row["ciphertext"])) > 16
        assert ROLE_B.encode() not in bytes(row["ciphertext"])
        out = capfd.readouterr()
        assert SECRET_1 not in out.out + out.err + caplog.text and SECRET_2 not in out.out + out.err + caplog.text

    def test_the_key_is_not_in_the_database(self, client, keys: Keys, roles, monkeypatch) -> None:
        key = new_key()
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"k9:{key}")
        bind_as(client, keys.a)
        raw = key.encode()
        raw_bytes = base64.b64decode(key)
        for p in store_path().parent.glob("*"):
            if p.is_file():
                data = p.read_bytes()
                assert raw not in data and raw_bytes not in data, p.name

    def test_every_record_gets_a_fresh_nonce_and_equal_secrets_seal_differently(self, client, keys: Keys, roles) -> None:
        for i in range(6):
            bind_as(client, keys.a, name=f"n{i}")
        rows = sql("SELECT nonce, ciphertext FROM credentials")
        assert len({bytes(r["nonce"]) for r in rows}) == 6 and len({bytes(r["ciphertext"]) for r in rows}) == 6

    def test_the_status_report_has_no_key_material(self, client, keys: Keys, roles, monkeypatch) -> None:
        key = new_key()
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"k9:{key}")
        bind_as(client, keys.a)
        ready = client.get("/api/v1/health/ready").json()
        assert ready["credential_custody"]["mode"] == "shared_encrypted"
        assert ready["credential_custody"]["sealed_under"] == {"k9": 1}
        assert key not in json.dumps(ready) and "journal.jsonl" not in json.dumps(ready)


class TestAuthenticatedEncryptionBinding:
    """The associated data binds tenant, connection, version, key id and target."""

    def test_a_ciphertext_moved_to_another_connection_of_the_same_tenant_is_not_used(
        self, client, keys: Keys, roles
    ) -> None:
        one, two = bind_as(client, keys.a, "one"), bind_as(client, keys.a, "two", user=ROLE_B)
        src = sql("SELECT * FROM credentials WHERE connection_id=?", one["id"])[0]
        sql("UPDATE credentials SET nonce=?, ciphertext=? WHERE connection_id=?",
            bytes(src["nonce"]), bytes(src["ciphertext"]), two["id"])
        with as_other_worker():
            r = read(client, keys.a, two["id"])
            assert r.status_code == 503 and "failed authentication" in r.json()["detail"]
            assert read(client, keys.a, one["id"]).status_code == 200

    def test_a_ciphertext_moved_to_another_tenant_is_not_used(self, client, keys: Keys, roles) -> None:
        a = bind_as(client, keys.a, "a")
        b = bind_as(client, keys.b, "b")
        src = sql("SELECT * FROM credentials WHERE connection_id=?", a["id"])[0]
        sql("UPDATE credentials SET nonce=?, ciphertext=? WHERE connection_id=?",
            bytes(src["nonce"]), bytes(src["ciphertext"]), b["id"])
        with as_other_worker():
            assert read(client, keys.b, b["id"]).status_code == 503

    def test_changing_the_owner_of_a_connection_row_breaks_the_seal(self, client, keys: Keys, roles) -> None:
        a = bind_as(client, keys.a)
        sql("UPDATE connections SET owner='someone-else' WHERE id=?", a["id"])
        sql("UPDATE credentials SET owner='someone-else' WHERE connection_id=?", a["id"])
        with as_other_worker():
            assert read(client, OPERATOR_KEY, a["id"]).status_code == 503

    def test_repointing_the_target_host_does_not_deliver_the_credential_elsewhere(
        self, client, keys: Keys, roles
    ) -> None:
        a = bind_as(client, keys.a)
        cfg = json.loads(sql("SELECT config_json FROM connections WHERE id=?", a["id"])[0][0])
        cfg["host"] = "attacker.invalid"
        sql("UPDATE connections SET config_json=? WHERE id=?", json.dumps(cfg), a["id"])
        with as_other_worker():
            r = read(client, keys.a, a["id"])
            assert r.status_code == 503 and "failed authentication" in r.json()["detail"]

    def test_a_replayed_older_version_is_not_used(self, client, keys: Keys, roles) -> None:
        a = bind_as(client, keys.a)
        v1 = sql("SELECT * FROM credentials WHERE connection_id=?", a["id"])[0]
        assert rotate_to(client, keys.a, a["id"]).status_code == 200
        sql("UPDATE credentials SET version=1, nonce=?, ciphertext=? WHERE connection_id=?",
            bytes(v1["nonce"]), bytes(v1["ciphertext"]), a["id"])
        with as_other_worker():
            assert read(client, keys.a, a["id"]).status_code == 409  # row version 1 != record version 2

    def test_the_seal_unit_contract(self) -> None:
        ring = KeyRing(keys={"k": os.urandom(32), "j": os.urandom(32)}, active_id="k")
        key_id, nonce, ct = ring.seal(b"secret", b"aad")
        assert ring.open(key_id, nonce, ct, b"aad") == b"secret"
        for kwargs in ({"aad": b"AAD"}, {"nonce": os.urandom(12)}, {"ct": ct[:-1] + bytes([ct[-1] ^ 1])}):
            with pytest.raises(CustodyError) as e:
                ring.open(key_id, kwargs.get("nonce", nonce), kwargs.get("ct", ct), kwargs.get("aad", b"aad"))
            assert e.value.code == "credential_unreadable"
        with pytest.raises(CustodyError):
            ring.open("j", nonce, ct, b"aad")
        with pytest.raises(CustodyError):
            ring.open("gone", nonce, ct, b"aad")
        assert "secret" not in repr(ring) and ring.keys["k"].hex() not in repr(ring)


# ───────────────────────────── propagation across workers ─────────────────────────────


class TestSharedAcrossWorkers:
    def test_a_connection_bound_on_one_worker_is_usable_on_another(self, client, keys: Keys, roles) -> None:
        conn = bind_as(client, keys.a)
        assert conn["custody"] == "vault" and conn["cred_version"] == 1 and conn["live"] is True
        with as_other_worker() as other:
            listed = [c for c in client.get(f"{API}/connections", headers=h(keys.a)).json() if c["id"] == conn["id"]][0]
            assert listed["live"] is False and listed["usable"] is True, "not built yet here, but usable"
            assert whoami(client, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_A
            assert other.get(f"postgres:{conn['id']}") is not None and other.version_of(f"postgres:{conn['id']}") == 1

    def test_a_rotation_on_one_worker_is_used_by_the_others_on_their_next_call(self, client, keys: Keys, roles) -> None:
        conn = bind_as(client, keys.a)
        key = f"postgres:{conn['id']}"
        with workers() as w:
            w.use("w2")
            assert whoami(client, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_A  # w2 caches version 1
            assert w.registry("w2").version_of(key) == 1
            w.use("w1")
            rotated = rotate_to(client, keys.a, conn["id"])
            assert rotated.status_code == 200 and rotated.json()["cred_version"] == 2
            assert whoami(client, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_B
            w.use("w2")  # still holding its version-1 adapter...
            assert w.registry("w2").version_of(key) == 1
            assert whoami(client, keys.a, conn["id"]).json()["data"][0]["u"] == ROLE_B  # ...but uses the new one
            assert w.registry("w2").version_of(key) == 2

    def test_a_revocation_on_one_worker_is_refused_by_a_worker_still_holding_the_adapter(
        self, client, keys: Keys, roles
    ) -> None:
        conn = bind_as(client, keys.a)
        key = f"postgres:{conn['id']}"
        with workers() as w:
            w.use("w2")
            assert read(client, keys.a, conn["id"]).status_code == 200
            assert w.registry("w2").get(key) is not None
            w.use("w1")
            assert client.post(f"{API}/connections/{conn['id']}/revoke", headers=h(keys.a)).status_code == 200
            w.use("w2")
            assert w.registry("w2").get(key) is not None, "w2 still holds the adapter..."
            r = read(client, keys.a, conn["id"])
            assert r.status_code == 409 and "revoked" in r.json()["detail"]  # ...and refuses to use it
            assert w.registry("w2").get(key) is None, "the stale adapter was dropped, not just bypassed"

    def test_concurrent_rotations_cannot_both_win(self, client, keys: Keys, roles) -> None:
        from neuralbridge.ai.store import AiStore, CredentialRow

        conn = bind_as(client, keys.a)
        store = AiStore(store_path())
        row = lambda v: CredentialRow(conn["id"], v, "o", "k", b"n" * 12, b"c" * 20)  # noqa: E731
        results: list[object] = []
        barrier = threading.Barrier(8)

        def go() -> None:
            barrier.wait()
            results.append(store.rotate_credential(conn["id"], expected_version=1, credential=row(2)))

        threads = [threading.Thread(target=go) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert sum(r is not None for r in results) == 1
        with pytest.raises(ValueError):
            store.rotate_credential(conn["id"], expected_version=2, credential=row(2))  # versions only increase

    def test_a_restart_keeps_the_connection_usable(self, client, keys: Keys, roles) -> None:
        conn = bind_as(client, keys.a)
        from fastapi.testclient import TestClient

        from neuralbridge.main import create_app

        from .platform_support import reset_singletons

        reset_singletons()  # every in-process object is gone: a new process over the same files
        with TestClient(create_app()) as fresh:
            r = whoami(fresh, keys.a, conn["id"])
            assert r.status_code == 200 and r.json()["data"][0]["u"] == ROLE_A
        reset_singletons()

    def test_the_raw_operator_route_does_not_bypass_a_revocation_made_elsewhere(
        self, client, keys: Keys, roles
    ) -> None:
        conn = bind_as(client, keys.a)
        route = f"/api/v1/adapters/postgres:{conn['id']}/execute"
        op = {"operation": "query", "params": {"sql": "SELECT 1"}}
        assert client.post(route, headers=h(OPERATOR_KEY), json=op).status_code == 200
        sql("UPDATE connections SET status='revoked' WHERE id=?", conn["id"])  # revoked "by another worker"
        sql("DELETE FROM credentials WHERE connection_id=?", conn["id"])
        r = client.post(route, headers=h(OPERATOR_KEY), json=op)
        assert r.status_code == 400 and "revoked" in r.json()["detail"]

    def test_the_connection_list_shows_the_custody_facts_and_no_secret(self, client, keys: Keys, roles) -> None:
        conn = bind_as(client, keys.a)
        listed = client.get(f"{API}/connections", headers=h(keys.a)).json()
        mine = [c for c in listed if c["id"] == conn["id"]][0]
        assert set(mine) == {"id", "name", "adapter_type", "status", "source", "live", "custody", "usable",
                             "cred_version", "four_eyes"}
        demo = [c for c in listed if c["source"] == "seeded_from_env"][0]
        assert demo["custody"] == "env" and demo["cred_version"] is None


# ───────────────────────────── key rotation ─────────────────────────────


class TestKeyRotation:
    def test_re_encrypting_moves_every_credential_to_the_active_key_and_keeps_them_usable(
        self, client, keys: Keys, roles, monkeypatch
    ) -> None:
        old, newk = new_key(), new_key()
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"old:{old}")
        conns = [bind_as(client, acct, f"c{i}") for i, acct in enumerate((keys.a, keys.a, keys.b))]
        before = {r["connection_id"]: bytes(r["ciphertext"]) for r in sql("SELECT * FROM credentials")}
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"old:{old},new:{newk}")
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY", "new")
        from neuralbridge.ai.store import AiStore

        vault = cred.vault_for(AiStore(store_path()))
        assert vault.status()["sealed_under"] == {"old": 3}
        assert vault.reencrypt() == {"resealed": 3, "already_current": 0, "failed": 0}
        assert vault.reencrypt() == {"resealed": 0, "already_current": 3, "failed": 0}
        after = {r["connection_id"]: r for r in sql("SELECT * FROM credentials")}
        assert {r["key_id"] for r in after.values()} == {"new"}
        assert all(bytes(after[c]["ciphertext"]) != before[c] for c in before)
        assert vault.status()["sealed_under"] == {"new": 3}
        # the old key can now be removed: nothing is sealed under it
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"new:{newk}")
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY")
        with as_other_worker():
            for c, acct in zip(conns, (keys.a, keys.a, keys.b), strict=True):
                assert whoami(client, acct, c["id"]).json()["data"][0]["u"] == ROLE_A

    def test_removing_the_old_key_before_re_encrypting_fails_closed_not_open(
        self, client, keys: Keys, roles, monkeypatch
    ) -> None:
        old, newk = new_key(), new_key()
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"old:{old}")
        conn = bind_as(client, keys.a)
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"new:{newk}")
        with as_other_worker():
            r = read(client, keys.a, conn["id"])
            assert r.status_code == 503 and "key 'old'" in r.json()["detail"]
        from neuralbridge.ai.store import AiStore

        assert cred.vault_for(AiStore(store_path())).reencrypt()["failed"] == 1

    def test_a_new_binding_after_a_key_change_uses_the_active_key(self, client, keys: Keys, roles, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"a:{new_key()},b:{new_key()}")
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY", "b")
        bind_as(client, keys.a)
        assert sql("SELECT key_id FROM credentials")[0][0] == "b"

    def test_the_cli_reports_status_and_re_encrypts(self, client, keys: Keys, roles, monkeypatch, capsys) -> None:
        old, newk = new_key(), new_key()
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"old:{old}")
        bind_as(client, keys.a)
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_KEYS", f"old:{old},new:{newk}")
        monkeypatch.setenv("NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY", "new")
        assert cred.main(["status", "--store", str(store_path())]) == 0
        assert json.loads(capsys.readouterr().out)["sealed_under"] == {"old": 1}
        assert cred.main(["reencrypt", "--store", str(store_path())]) == 0
        assert json.loads(capsys.readouterr().out)["resealed"] == 1
        assert old not in capsys.readouterr().out


# ───────────────────────────── retention and secure deletion ─────────────────────────────


class TestRetentionAndDeletion:
    def test_only_the_current_version_is_retained(self, client, keys: Keys, roles) -> None:
        conn = bind_as(client, keys.a)
        first = bytes(sql("SELECT ciphertext FROM credentials")[0][0])
        for _ in range(2):
            assert rotate_to(client, keys.a, conn["id"]).status_code == 200
        rows = sql("SELECT version, ciphertext FROM credentials")
        assert len(rows) == 1 and rows[0]["version"] == 3 and bytes(rows[0]["ciphertext"]) != first

    @pytest.mark.parametrize("how", ["revoke", "delete"])
    def test_revoke_and_delete_remove_the_ciphertext_and_zero_its_pages(self, client, keys: Keys, roles, how) -> None:
        conn = bind_as(client, keys.a)
        ciphertext = bytes(sql("SELECT ciphertext FROM credentials")[0][0])
        db = sqlite3.connect(store_path())
        assert ciphertext in store_path().read_bytes() or ciphertext in Path(f"{store_path()}-wal").read_bytes()
        db.close()
        r = (client.post(f"{API}/connections/{conn['id']}/revoke", headers=h(keys.a)) if how == "revoke"
             else client.delete(f"{API}/connections/{conn['id']}", headers=h(keys.a)))
        assert r.status_code == 200
        assert sql("SELECT COUNT(*) AS n FROM credentials")[0]["n"] == 0
        db = sqlite3.connect(store_path())
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.close()
        assert ciphertext not in store_path().read_bytes(), "freed pages must not keep the ciphertext"

    def test_the_store_runs_with_secure_delete(self, tmp_path) -> None:
        from neuralbridge.ai.store import AiStore

        db = AiStore(tmp_path / "fresh.db")._connect()
        assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
        db.close()

    def test_a_revoked_connection_cannot_be_rotated_back_to_life(self, client, keys: Keys, roles) -> None:
        conn = bind_as(client, keys.a)
        client.post(f"{API}/connections/{conn['id']}/revoke", headers=h(keys.a))
        assert rotate_to(client, keys.a, conn["id"]).status_code == 409
        assert sql("SELECT COUNT(*) AS n FROM credentials")[0]["n"] == 0


# ───────────────────────────── tenants ─────────────────────────────


class TestTenantIsolation:
    def test_another_tenant_cannot_rotate_revoke_or_see_the_connection_and_cannot_tell_it_exists(
        self, client, keys: Keys, roles
    ) -> None:
        conn = bind_as(client, keys.a)
        missing = "00000000-0000-0000-0000-000000000000"
        for fn in (lambda cid: rotate_to(client, keys.b, cid),
                   lambda cid: client.post(f"{API}/connections/{cid}/revoke", headers=h(keys.b)),
                   lambda cid: client.delete(f"{API}/connections/{cid}", headers=h(keys.b)),
                   lambda cid: read(client, keys.b, cid)):
            foreign, absent = fn(conn["id"]), fn(missing)
            assert foreign.status_code == absent.status_code == 404
            assert foreign.json()["detail"].replace(conn["id"], "X") == absent.json()["detail"].replace(missing, "X")
        assert read(client, keys.a, conn["id"]).status_code == 200, "A's connection is untouched"
        assert [c["id"] for c in client.get(f"{API}/connections", headers=h(keys.b)).json()
                if c["source"] != "seeded_from_env"] == []

    def test_the_credential_row_carries_its_tenant(self, client, keys: Keys, roles) -> None:
        a, b = bind_as(client, keys.a), bind_as(client, keys.b)
        owners = {r["connection_id"]: r["owner"] for r in sql("SELECT connection_id, owner FROM credentials")}
        conn_owners = {r["id"]: r["owner"] for r in sql("SELECT id, owner FROM connections")}
        assert owners == {a["id"]: conn_owners[a["id"]], b["id"]: conn_owners[b["id"]]}
        assert conn_owners[a["id"]] != conn_owners[b["id"]]


# ───────────────────────────── audit ─────────────────────────────


class TestAudit:
    def test_create_rotate_revoke_delete_are_audited_with_custody_and_never_the_secret(
        self, client, keys: Keys, roles
    ) -> None:
        a, b = bind_as(client, keys.a, "first"), bind_as(client, keys.a, "second")
        rotate_to(client, keys.a, a["id"])
        client.post(f"{API}/connections/{a['id']}/revoke", headers=h(keys.a))
        client.delete(f"{API}/connections/{b['id']}", headers=h(keys.a))
        events = audit_events(client, keys.a)
        by = {}
        for e in events:
            by.setdefault(e["event_type"], []).append(e)
        assert len(by["connection_create"]) == 2 and len(by["connection_rotate"]) == 1
        assert len(by["connection_revoke"]) == 1 and len(by["connection_delete"]) == 1
        assert by["connection_create"][0]["details"]["custody"] == "vault"
        assert by["connection_rotate"][0]["details"]["version"] == 2
        assert SECRET_1 not in json.dumps(events) and SECRET_2 not in json.dumps(events)
        assert all(e["details"]["owner"] == events[0]["details"]["owner"] for e in events)

    def test_a_refused_bind_is_audited_without_the_secret(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.delenv("NEURALBRIDGE_CREDENTIAL_KEYS")
        assert bind_raw(client, keys.a, password=SECRET_1).status_code == 503
        events = audit_events(client, keys.a)
        refused = [e for e in events if e["event_type"] == "connection_create"]
        assert refused and refused[0]["result"] == "refused:503" and SECRET_1 not in json.dumps(events)

    def test_the_platform_audit_chain_still_verifies(self, client, keys: Keys, roles) -> None:
        import asyncio

        from neuralbridge.api.dependencies import get_audit_logger

        conn = bind_as(client, keys.a)
        rotate_to(client, keys.a, conn["id"])
        assert asyncio.run(get_audit_logger().verify_integrity())


# ───────────────────────────── the journal itself ─────────────────────────────


class TestJournal:
    def test_appends_chain_and_are_read_incrementally(self, tmp_path) -> None:
        j = RollbackJournal(tmp_path / "j.jsonl")
        assert j.snapshot() == ("", {}, 0)
        first = j.append("create", connection_id="c1", owner="o", version=1)
        j.append("rotate", connection_id="c1", owner="o", version=2)
        j.append("revoke", connection_id="c1", owner="o", version=2)
        jid, state, n = j.snapshot()
        assert jid == first and n == 3 and state["c1"].min_version == 2 and state["c1"].revoked
        reader = RollbackJournal(tmp_path / "j.jsonl")  # a second process' view
        assert reader.snapshot()[0] == jid and reader.snapshot()[2] == 3
        j.append("delete", connection_id="c1", owner="o")
        assert reader.state_of("c1").deleted and reader.snapshot()[2] == 4
        assert stat.S_IMODE((tmp_path / "j.jsonl").stat().st_mode) == 0o600

    def test_concurrent_writers_in_threads_and_processes_keep_one_chain(self, tmp_path) -> None:
        import subprocess
        import sys

        path = tmp_path / "j.jsonl"
        src = Path(__file__).resolve().parents[1] / "src"
        code = ("import sys; sys.path.insert(0, " + repr(str(src)) + "); from pathlib import Path; "
                "from neuralbridge.ai.credentials import RollbackJournal; "
                "j = RollbackJournal(Path(" + repr(str(path)) + ")); "
                "[j.append('rotate', connection_id=f'p{i}', owner='o', version=i) for i in range(1, 26)]")
        procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(3)]  # noqa: S603
        j = RollbackJournal(path)
        threads = [threading.Thread(target=lambda n=n: [j.append("rotate", connection_id=f"t{n}", owner="o", version=i)
                                                         for i in range(1, 26)]) for n in range(3)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert [p.wait() for p in procs] == [0, 0, 0]
        _, state, n = RollbackJournal(path).snapshot()  # a full re-verification of the chain
        assert n == 150
        assert all(s.min_version == 25 for k, s in state.items() if k.startswith("t"))
        assert all(s.min_version == int(k[1:]) for k, s in state.items() if k.startswith("p"))

    def test_an_edited_line_stops_every_stored_credential_from_being_served(self, client, keys: Keys, roles, tmp_path) -> None:
        conn = bind_as(client, keys.a)
        journal = tmp_path.parent / f"{tmp_path.name}-custody" / "journal.jsonl"
        journal.write_text(journal.read_text().replace('"version":1', '"version":0'))
        with as_other_worker():
            r = read(client, keys.a, conn["id"])
            assert r.status_code == 503 and "integrity" in r.json()["detail"]
        assert bind_raw(client, keys.a).status_code == 503  # binding must not paper over a broken chain

    def test_a_deleted_or_replaced_journal_fails_closed_instead_of_disarming_the_check(
        self, client, keys: Keys, roles, tmp_path
    ) -> None:
        conn = bind_as(client, keys.a)
        journal = tmp_path.parent / f"{tmp_path.name}-custody" / "journal.jsonl"
        journal.unlink()
        with as_other_worker():
            r = read(client, keys.a, conn["id"])
            assert r.status_code == 503 and "not the one this store was created with" in r.json()["detail"]
        replacement = RollbackJournal(journal)
        replacement.append("create", connection_id="other", owner="o", version=1)
        with as_other_worker():
            assert read(client, keys.a, conn["id"]).status_code == 503

    def test_a_truncated_last_line_is_ignored_until_complete(self, tmp_path) -> None:
        j = RollbackJournal(tmp_path / "j.jsonl")
        j.append("create", connection_id="c", owner="o", version=1)
        with open(tmp_path / "j.jsonl", "ab") as fh:
            fh.write(b'{"seq":2,"op":"rev')
        assert RollbackJournal(tmp_path / "j.jsonl").snapshot()[2] == 1
