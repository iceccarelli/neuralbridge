# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Bound /ai connections across REAL worker processes (``uvicorn neuralbridge.main:app --workers 4``).

A bound connection's credential is sealed in the shared store; every worker reads the shared record
on every use. Proved here with four real OS processes and loopback HTTP on fresh connections, each
claim on the observable behaviour (which database role the target saw, which status the caller got),
then on the files after the servers stop:

* bind on one worker -> usable from the others (they run ``SELECT current_user`` as the bound role);
* rotate on one worker -> every worker, including those holding a cached adapter, uses the NEW role
  on its next call (zero answers with the old one);
* revoke on one worker -> every worker refuses at once (zero 200s), including workers that held a
  live adapter, and nothing executes;
* concurrent rotations on different workers cannot both win;
* a restart (new process tree over the same files) keeps the connection usable;
* with no key configured, every worker refuses to bind (503) - nothing is stored;
* no plaintext secret in any file or in the server log.

Not proved: that the kernel spreads connections evenly (each phase retries until at least three
worker processes did work and says so otherwise), anything on another filesystem, or more than four
workers.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from .credential_support import ROLE_A, ROLE_B, SECRET_1, SECRET_2, new_key, roles
from .test_multiworker_real import (
    OPERATOR_KEY,
    PG,
    Server,
    _blast,
    _mint,
    _pg_reachable,
    _workers_that_worked,
)

API = "/api/v1/ai"
READS = 120
THREADS = 8  # <= the per-worker in-flight cap (8), so a 503 "busy" can never be the explanation


@pytest.fixture
def cluster(tmp_path: Path, roles):
    """Directories + environment for a four-worker platform server; the server is started by the test."""
    if not _pg_reachable():
        pytest.skip("No reachable PostgreSQL (NEURALBRIDGE_AI_PG_*) - skipped honestly")
    data = tmp_path / "data"
    data.mkdir()
    custody = tmp_path / "custody"  # a separate directory from the store: the journal must not be in it
    custody.mkdir()
    env = {
        "ASSURANCE_API_KEYS": OPERATOR_KEY,
        "ASSURANCE_ACCOUNTS": str(data / "accounts.db"),
        "ASSURANCE_LEDGER": str(data / "art14-register.db"),
        "NEURALBRIDGE_AI_STORE": str(data / "ai.db"),
        "NEURALBRIDGE_AUDIT_DB": str(data / "audit.db"),
        "NEURALBRIDGE_ENV": "development",
        "NEURALBRIDGE_CREDENTIAL_KEYS": "mw-key-1:" + new_key(),
        "NEURALBRIDGE_CREDENTIAL_JOURNAL": str(custody / "journal.jsonl"),
        "NEURALBRIDGE_RATE_LIMIT_PER_MINUTE": "100000",
    }
    from assurance.billing.accounts import AccountStore

    AccountStore(env["ASSURANCE_ACCOUNTS"])
    return SimpleCluster(tmp_path, data, custody, env)


class SimpleCluster:
    def __init__(self, tmp: Path, data: Path, custody: Path, env: dict[str, str]) -> None:
        self.tmp, self.data, self.custody, self.env = tmp, data, custody, env
        self.servers: list[Server] = []

    def start(self, **override: str) -> Server:
        env = {**self.env, **override}
        env = {k: v for k, v in env.items() if v != ""}
        server = Server("neuralbridge.main:app", env, self.tmp, "/api/v1/health").start()
        self.servers.append(server)
        return server

    def stop(self) -> None:
        for s in self.servers:
            s.stop()


@pytest.fixture
def platform(cluster: SimpleCluster) -> Iterator[SimpleCluster]:
    try:
        yield cluster
    finally:
        cluster.stop()


def hdr(key: str) -> dict[str, str]:
    return {"X-API-Key": key, "X-NB-Actor": "mw-test"}


def bind(server: Server, key: str, user: str = ROLE_A, password: str = SECRET_1) -> httpx.Response:
    with httpx.Client(base_url=server.base, timeout=60) as c:
        return c.post(f"{API}/connections", headers=hdr(key), json={
            "name": "mw", "host": PG["HOST"], "port": int(PG["PORT"]), "user": user, "password": password,
            "database": PG["DATABASE"]})


def one(server: Server, method: str, path: str, key: str, **kw: Any) -> httpx.Response:
    with httpx.Client(base_url=server.base, timeout=60) as c:
        return c.request(method, f"{API}{path}", headers=hdr(key), **kw)


def whoami_call(key: str, cid: str) -> Callable[[httpx.Client], httpx.Response]:
    body = {"connection_id": cid, "operation": "query", "params": {"sql": "SELECT current_user AS u"}}
    return lambda c: c.post(f"{API}/read", headers=hdr(key), json=body)


def phase(server: Server, call: Callable[[httpx.Client], httpx.Response], check: Callable[[list[httpx.Response]], None],
          min_workers: int = 3) -> int:
    """Blast ``READS`` calls per batch on fresh connections; ``check`` every batch; repeat (bounded)
    until at least ``min_workers`` worker processes have done work. Returns how many did."""
    before = {pid: server.cpu_ticks(pid) for pid in server.worker_pids()}
    assert len(before) == 4, "expected four worker processes"
    for _ in range(8):
        results = _blast(server, [call] * READS, threads=THREADS)
        check(results)
        worked = _workers_that_worked(server, before)
        if worked >= min_workers:
            return worked
    pytest.fail(f"only {worked} of 4 worker processes served requests; the phase would prove too little")


def users(results: list[httpx.Response]) -> Counter[Any]:
    return Counter((r.status_code, r.json()["data"][0]["u"] if r.status_code == 200 else r.text[:80]) for r in results)


def test_bind_rotate_revoke_across_four_real_workers(platform: SimpleCluster) -> None:
    server = platform.start()
    (acct, key), (other_acct, other_key) = _mint(platform.data / "accounts.db", 2)

    # ── bind on whichever worker answers; every worker can then use it ──
    bound = bind(server, key)
    assert bound.status_code == 200, bound.text
    conn = bound.json()
    assert conn["custody"] == "vault" and conn["cred_version"] == 1 and SECRET_1 not in bound.text
    call = whoami_call(key, conn["id"])
    worked = phase(server, call, lambda rs: _expect(users(rs), {(200, ROLE_A): READS}))
    assert worked >= 3

    # ── rotate on one worker; the others (which cache a ROLE_A adapter) use ROLE_B on their next call ──
    rotated = one(server, "POST", f"/connections/{conn['id']}/rotate", key,
                  json={"user": ROLE_B, "password": SECRET_2})
    assert rotated.status_code == 200 and rotated.json()["cred_version"] == 2
    worked = phase(server, call, lambda rs: _expect(users(rs), {(200, ROLE_B): READS}))
    assert worked >= 3

    # ── a different tenant on any worker: indistinguishable from a missing id ──
    foreign = _blast(server, [whoami_call(other_key, conn["id"])] * 40, threads=THREADS)
    assert {r.status_code for r in foreign} == {404}

    # ── revoke on one worker; every worker refuses at once, nothing runs ──
    revoked = one(server, "POST", f"/connections/{conn['id']}/revoke", key)
    assert revoked.status_code == 200
    worked = phase(server, call, lambda rs: _expect(Counter(r.status_code for r in rs), {409: READS}))
    assert worked >= 3
    plans = _blast(server, [lambda c: c.post(f"{API}/plan", headers=hdr(key), json={
        "connection_id": conn["id"], "operation": "execute_sql", "params": {"sql": "SELECT 1"}})] * 24, threads=THREADS)
    assert {r.status_code for r in plans} <= {400, 409}
    assert bind(server, other_key).status_code == 200  # another tenant's bind is unaffected

    server.stop()
    _assert_clean(platform, server, [SECRET_1, SECRET_2])
    db = sqlite3.connect(f"file:{platform.data / 'ai.db'}?mode=ro", uri=True)
    assert db.execute("SELECT status FROM connections WHERE id=?", (conn["id"],)).fetchone()[0] == "revoked"
    assert db.execute("SELECT COUNT(*) FROM credentials WHERE connection_id=?", (conn["id"],)).fetchone()[0] == 0
    # the journal was written by whichever workers handled the calls; its chain is intact
    from neuralbridge.ai.credentials import RollbackJournal

    jid, state, n = RollbackJournal(platform.custody / "journal.jsonl").snapshot()
    assert state[conn["id"]].revoked and state[conn["id"]].min_version == 2 and n >= 4


def _expect(got: Counter[Any], want: dict[Any, int]) -> None:
    assert dict(got) == want, got


def _assert_clean(platform: SimpleCluster, server: Server, secrets: list[str]) -> None:
    files = [p for d in (platform.data, platform.custody) for p in d.glob("*") if p.is_file()]
    assert {p.name for p in files} >= {"ai.db", "journal.jsonl", "audit.db"}
    blobs = [p.read_bytes() for p in files] + [server.log.read_bytes()]
    for secret in secrets:
        assert not any(secret.encode() in b for b in blobs), f"plaintext {secret!r} found on disk or in the log"
    key = platform.env["NEURALBRIDGE_CREDENTIAL_KEYS"].split(":", 1)[1].encode()
    assert not any(key in b for b in blobs), "the key is on disk or in the log"


def test_concurrent_rotations_on_different_workers_cannot_both_win(platform: SimpleCluster) -> None:
    server = platform.start()
    (acct, key), = _mint(platform.data / "accounts.db", 1)
    conn = bind(server, key).json()
    body = {"user": ROLE_A, "password": SECRET_1}
    for _ in range(3):
        results = _blast(server, [lambda c: c.post(f"{API}/connections/{conn['id']}/rotate", headers=hdr(key),
                                                    json=body)] * 16, threads=THREADS)
        codes = Counter(r.status_code for r in results)
        assert set(codes) <= {200, 409} and codes[200] >= 1, codes
    server.stop()
    from neuralbridge.ai.credentials import RollbackJournal

    db = sqlite3.connect(f"file:{platform.data / 'ai.db'}?mode=ro", uri=True)
    version = db.execute("SELECT cred_version FROM connections WHERE id=?", (conn["id"],)).fetchone()[0]
    assert db.execute("SELECT COUNT(*), MIN(version) FROM credentials").fetchone() == (1, version)
    _, state, _ = RollbackJournal(platform.custody / "journal.jsonl").snapshot()
    assert state[conn["id"]].min_version >= version, "the store may never be ahead of the journal"
    assert version >= 2


def test_a_restart_keeps_a_bound_connection_usable_from_every_worker(platform: SimpleCluster) -> None:
    first = platform.start()
    (acct, key), = _mint(platform.data / "accounts.db", 1)
    conn = bind(first, key).json()
    first.stop()
    second = platform.start()  # a new process tree: no in-memory state survives
    worked = phase(second, whoami_call(key, conn["id"]), lambda rs: _expect(users(rs), {(200, ROLE_A): READS}))
    assert worked >= 3


def test_with_no_key_configured_every_worker_refuses_to_bind(platform: SimpleCluster) -> None:
    server = platform.start(NEURALBRIDGE_CREDENTIAL_KEYS="")
    (acct, key), = _mint(platform.data / "accounts.db", 1)
    results = _blast(server, [lambda c: c.post(f"{API}/connections", headers=hdr(key), json={
        "name": "x", "host": PG["HOST"], "port": int(PG["PORT"]), "user": ROLE_A, "password": SECRET_1,
        "database": PG["DATABASE"]})] * 24, threads=THREADS)
    assert {r.status_code for r in results} == {503}
    assert all(r.json()["detail"]["error"] == "credential_custody_unconfigured" for r in results)
    ready = httpx.get(server.base + "/api/v1/health/ready", timeout=10).json()
    assert ready["credential_custody"]["mode"] == "unavailable"
    assert any(w.startswith("credential_custody_unavailable") for w in ready["warnings"])
    server.stop()
    assert sqlite3.connect(f"file:{platform.data / 'ai.db'}?mode=ro", uri=True).execute(
        "SELECT COUNT(*) FROM connections").fetchone()[0] == 0
    assert SECRET_1.encode() not in server.log.read_bytes()


def test_a_journal_that_is_lost_stops_every_worker_serving_the_vault(platform: SimpleCluster) -> None:
    server = platform.start()
    (acct, key), = _mint(platform.data / "accounts.db", 1)
    conn = bind(server, key).json()
    phase(server, whoami_call(key, conn["id"]), lambda rs: _expect(users(rs), {(200, ROLE_A): READS}))
    (platform.custody / "journal.jsonl").unlink()  # e.g. the custody volume came back empty
    phase(server, whoami_call(key, conn["id"]), lambda rs: _expect(Counter(r.status_code for r in rs), {503: READS}))
