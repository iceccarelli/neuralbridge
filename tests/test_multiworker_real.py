"""Real multi-process behaviour: uvicorn with ``--workers 4`` over shared SQLite stores.

Everything else in the suite runs one process (an in-process ASGI client) or simulates several
with threads. The root image's CMD is ``uvicorn ... --workers 4``, and a hosted deployment of the
assurance service could be started that way too, so this file starts the REAL servers as OS
processes and hammers them over loopback HTTP from many threads, each request on a fresh
connection so the kernel spreads them over the worker processes.

What it proves (each assertion is on durable state read after the servers stop, not on a reply):

* concurrent appends to ONE tenant ledger keep one valid hash chain: sequence 1..N, no gap, no
  duplicate, every link verifies;
* concurrent FIRST writes to brand-new tenant ledgers (the file is created by whichever worker
  gets there first) neither corrupt the file nor mint two ledger ids;
* the free-tier daily allowance is exact across processes: of N+M concurrent calls exactly N
  succeed, M are refused with 429, and the stored counter equals N (no lost update);
* concurrent ``/ai`` approvals of one plan across worker processes execute the write exactly once
  (counted in a real PostgreSQL table), and a worker that never listed the connections can still
  serve the seeded connection.

What it does NOT prove: behaviour on another filesystem (NFS, a network volume), more than 4
workers, or sustained load; and that the distribution of connections over workers was uniform
(the test only asserts that at least two worker processes did real work, retrying until they did).
"""

from __future__ import annotations

import asyncio
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WORKERS = 4
OPERATOR_KEY = "op-" + "k" * 40  # >= 32 characters; a throwaway value for a loopback test server

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="reads /proc to count worker processes")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Server:
    """``python -m uvicorn APP --workers 4`` as a real process tree on loopback."""

    def __init__(self, app: str, env: dict[str, str], tmp: Path, health: str) -> None:
        self.app, self.health = app, health
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.log = tmp / f"{app.split(':')[0].replace('.', '_')}.log"
        full = {k: v for k, v in os.environ.items()
                if not k.startswith(("ASSURANCE_", "NEURALBRIDGE_", "STRIPE_"))}
        full.update({"PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(tmp)})
        full.update(env)
        self.env = full
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> Server:
        try:
            return self._start()
        except BaseException:
            self.stop()  # a server that never became ready must not outlive the test
            raise

    def _start(self) -> Server:
        logf = open(self.log, "wb")  # noqa: SIM115 - closed in stop()
        self._logf = logf
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv, test-owned paths
            [sys.executable, "-m", "uvicorn", self.app, "--host", "127.0.0.1",
             "--port", str(self.port), "--workers", str(WORKERS), "--log-level", "warning"],
            env=self.env, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited early:\n{self.log.read_text()[-2000:]}")
            try:
                if httpx.get(self.base + self.health, timeout=2).status_code == 200 \
                        and len(self.worker_pids()) == WORKERS:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError(f"server not ready:\n{self.log.read_text()[-2000:]}")

    def worker_pids(self) -> list[int]:
        assert self.proc is not None
        out = []
        for entry in os.scandir("/proc"):
            if entry.name.isdigit():
                try:
                    stat = Path(entry.path, "stat").read_text()
                except OSError:
                    continue
                # "pid (comm) state ppid ..." - comm may contain spaces/parens, so split after the last ")"
                ppid = int(stat.rsplit(")", 1)[1].split()[1])
                if ppid != self.proc.pid:
                    continue
                try:
                    cmd = Path(entry.path, "cmdline").read_bytes()
                except OSError:
                    continue
                # uvicorn's children: the workers (multiprocessing spawn_main) and one
                # resource_tracker, which serves no requests.
                if b"spawn_main" in cmd:
                    out.append(int(entry.name))
        return out

    @staticmethod
    def cpu_ticks(pid: int) -> int:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])  # utime + stime

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
        if getattr(self, "_logf", None) is not None:
            self._logf.close()


def _blast(server: Server, calls: list[Any], threads: int = 32) -> list[Any]:
    """Run ``calls`` (callables taking an ``httpx.Client``) concurrently, each on a NEW connection,
    and return their results in order. Repeats the whole batch shape is the caller's business."""

    def one(call: Any) -> Any:
        with httpx.Client(base_url=server.base, timeout=60) as client:
            return call(client)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        return list(pool.map(one, calls))


def _workers_that_worked(server: Server, before: dict[int, int]) -> int:
    return sum(1 for pid, t in before.items() if server.cpu_ticks(pid) > t)


def _signal_body(n: int) -> dict[str, Any]:
    return {"received_at": "2026-11-01T10:00:00Z", "channel": "other",
            "description": f"multi-worker probe {n}", "product_name": "probe", "version": "1",
            "actor": {"identifier": "probe@example.invalid"}}


@pytest.fixture
def assurance_server(tmp_path: Path) -> Iterator[tuple[Server, Path]]:
    data = tmp_path / "data"
    data.mkdir()
    env = {
        "ASSURANCE_API_KEYS": OPERATOR_KEY,
        "ASSURANCE_LEDGER": str(data / "art14-register.db"),
        "ASSURANCE_ACCOUNTS": str(data / "accounts.db"),
        "ASSURANCE_TENANT_LEDGERS": str(data / "tenants"),
        "ASSURANCE_ATTEST_LOGS": str(data / "attestations"),
        "ASSURANCE_SUPPLIER_FEEDS": str(data / "supplier-feeds"),
    }
    # the account store must exist before the workers race to create it (the image's volume does)
    from assurance.billing.accounts import AccountStore
    AccountStore(env["ASSURANCE_ACCOUNTS"])
    server = Server("assurance.api.service:app", env, tmp_path, "/livez").start()
    try:
        yield server, data
    finally:
        server.stop()


def _mint(accounts_db: Path, n: int) -> list[tuple[str, str]]:
    """``n`` register-tier accounts as (account_id, api_key), minted the way the webhook does."""
    from assurance.billing.accounts import AccountStore
    store = AccountStore(str(accounts_db))
    out = []
    for i in range(n):
        acct = store.upsert_account(email=f"mw{i}@example.invalid", tier="register",
                                    company=f"MW {i}")
        out.append((acct.id, store.issue_key(acct.id, label="multiworker")))
    return out


def _ensure_spread(server: Server, run_batch: Any) -> None:
    """Run a batch; if fewer than two worker processes did work, run another (bounded)."""
    pids = server.worker_pids()
    assert len(pids) == WORKERS
    before = {pid: server.cpu_ticks(pid) for pid in pids}
    for _ in range(6):
        run_batch()
        if _workers_that_worked(server, before) >= 2:
            return
    pytest.fail("fewer than two worker processes served any request; the test would prove nothing")


def test_concurrent_appends_to_one_tenant_ledger_keep_one_valid_chain(
        assurance_server: tuple[Server, Path]) -> None:
    server, data = assurance_server
    (acct, key), = _mint(data / "accounts.db", 1)
    headers = {"X-API-Key": key}
    posted = 0

    def batch() -> None:
        nonlocal posted
        calls = []
        for n in range(posted, posted + 48):
            calls.append(lambda c, n=n: c.post(f"/v1/cases/probe-{n}/signal", json=_signal_body(n),
                                               headers=headers))
        for r in _blast(server, calls):
            assert r.status_code == 201, (r.status_code, r.text[:300])
        posted += 48

    _ensure_spread(server, batch)
    server.stop()

    from assurance.evidence.ledger import EvidenceLedger
    ledger = EvidenceLedger.open_readonly(data / "tenants" / f"{acct}.db")
    entries = ledger.entries()
    seqs = [e.seq for e in entries]
    assert len(entries) == posted, "an append was lost or duplicated"
    assert seqs == list(range(1, posted + 1)), "sequence numbers have a gap or a duplicate"
    assert len({e.subject for e in entries}) == posted, "two appends landed on one case"
    ok, problems = ledger.verify_chain()
    assert ok, problems
    # the file itself agrees (independent of the library's own reader)
    with sqlite3.connect(f"file:{data / 'tenants' / (acct + '.db')}?mode=ro", uri=True) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT COUNT(*), COUNT(DISTINCT seq), COUNT(DISTINCT prev_hash) "
                          "FROM chain").fetchone() == (posted,) * 3


def test_concurrent_first_writes_to_new_tenant_ledgers_do_not_corrupt(
        assurance_server: tuple[Server, Path]) -> None:
    server, data = assurance_server
    per_account = 6
    accounts: list[tuple[str, str]] = []

    # A brand-new ledger can only be raced once, so each attempt uses fresh accounts. An attempt
    # counts only if at least two worker processes served it; otherwise try again (bounded).
    for _attempt in range(5):
        fresh = _mint(data / "accounts.db", 8)
        assert not any((data / "tenants" / f"{a}.db").exists() for a, _ in fresh)
        before = {pid: server.cpu_ticks(pid) for pid in server.worker_pids()}
        calls = []
        for _acct, key in fresh:
            for i in range(per_account):
                calls.append(lambda c, key=key, i=i: c.post(
                    f"/v1/cases/first-{uuid.uuid4().hex[:8]}/signal", json=_signal_body(i),
                    headers={"X-API-Key": key}))
        results = _blast(server, calls, threads=48)
        assert Counter(r.status_code for r in results) == {201: len(calls)}, \
            Counter((r.status_code, r.text[:120]) for r in results if r.status_code != 201)
        accounts += fresh
        if _workers_that_worked(server, before) >= 2:
            break
    else:
        pytest.fail("fewer than two worker processes served the first writes")
    server.stop()

    from assurance.evidence.ledger import EvidenceLedger
    ids = set()
    for acct, _ in accounts:
        path = data / "tenants" / f"{acct}.db"
        ledger = EvidenceLedger.open_readonly(path)
        entries = ledger.entries()
        assert [e.seq for e in entries] == list(range(1, per_account + 1)), acct
        ok, problems = ledger.verify_chain()
        assert ok, (acct, problems)
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            meta = db.execute("SELECT value FROM meta WHERE key='ledger_id'").fetchall()
            assert len(meta) == 1, f"{acct}: {len(meta)} ledger ids minted"
            ids.add(meta[0][0])
    assert len(ids) == len(accounts), "two tenants share a ledger id"


def test_free_allowance_counter_is_exact_across_processes(
        assurance_server: tuple[Server, Path]) -> None:
    server, data = assurance_server
    limit = 20  # free tier validations_per_day (billing/plans.py)
    extra = 28
    payload = {"payload": {}, "track": "actively_exploited_vulnerability", "stage": "early_warning"}

    def validate(c: httpx.Client) -> httpx.Response:
        return c.post("/v1/spec/validate", json=payload)

    pids = server.worker_pids()
    before = {pid: server.cpu_ticks(pid) for pid in pids}
    results = _blast(server, [validate] * (limit + extra), threads=40)
    codes = Counter(r.status_code for r in results)
    assert codes == {200: limit, 429: extra}, (codes, [r.text[:200] for r in results
                                                       if r.status_code not in (200, 429)][:2])
    assert _workers_that_worked(server, before) >= 2, "only one worker process served the burst"
    server.stop()
    with sqlite3.connect(f"file:{data / 'accounts.db'}?mode=ro", uri=True) as db:
        rows = db.execute("SELECT scope, SUM(count) FROM usage GROUP BY scope").fetchall()
    assert dict(rows).get("validate") == limit, rows


# ---------------------------------------------------------------------------------------------
# /ai: the platform image (`neuralbridge.main:app`, four workers) with a real PostgreSQL target
# ---------------------------------------------------------------------------------------------
PG = {
    "HOST": os.environ.get("NEURALBRIDGE_AI_PG_HOST", ""),
    "PORT": os.environ.get("NEURALBRIDGE_AI_PG_PORT", "5432"),
    "USER": os.environ.get("NEURALBRIDGE_AI_PG_USER", ""),
    "PASSWORD": os.environ.get("NEURALBRIDGE_AI_PG_PASSWORD", ""),
    "DATABASE": os.environ.get("NEURALBRIDGE_AI_PG_TEST_DATABASE", ""),
}


def _pg_reachable() -> bool:
    if not (PG["HOST"] and PG["USER"] and PG["DATABASE"]):
        return False
    try:
        with socket.create_connection((PG["HOST"], int(PG["PORT"])), timeout=2):
            return True
    except OSError:
        return False


async def _pg(sql: str, *args: Any) -> list[Any]:
    import asyncpg
    conn = await asyncpg.connect(host=PG["HOST"], port=int(PG["PORT"]), user=PG["USER"],
                                 password=PG["PASSWORD"], database=PG["DATABASE"])
    try:
        return list(await conn.fetch(sql, *args))
    finally:
        await conn.close()


@pytest.fixture
def ai_server(tmp_path: Path) -> Iterator[tuple[Server, Path, str]]:
    if not _pg_reachable():
        pytest.skip("No reachable PostgreSQL (NEURALBRIDGE_AI_PG_*) - skipped honestly")
    data = tmp_path / "data"
    data.mkdir()
    table = "mw_" + uuid.uuid4().hex[:10]
    asyncio.run(_pg(f"CREATE TABLE {table} (plan text)"))
    env = {
        "ASSURANCE_API_KEYS": OPERATOR_KEY,
        "ASSURANCE_ACCOUNTS": str(data / "accounts.db"),
        "ASSURANCE_LEDGER": str(data / "art14-register.db"),
        "NEURALBRIDGE_AI_STORE": str(data / "ai.db"),
        # Local-development switch (tenancy.py): lets a paid account write the SEEDED connection, so
        # the test needs no per-worker credential binding. Set for this subprocess only.
        "NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID": "1",
        "NEURALBRIDGE_ENV": "development",
        **{f"NEURALBRIDGE_AI_PG_{k}": v for k, v in PG.items()},
    }
    from assurance.billing.accounts import AccountStore
    AccountStore(env["ASSURANCE_ACCOUNTS"])
    server = Server("neuralbridge.main:app", env, tmp_path, "/api/v1/health").start()
    try:
        yield server, data, table
    finally:
        server.stop()
        asyncio.run(_pg(f"DROP TABLE IF EXISTS {table}"))


def _first(client: httpx.Client, headers: dict[str, str]) -> str:
    r = client.get("/api/v1/ai/connections", headers=headers)
    assert r.status_code == 200, r.text
    seeded = [c for c in r.json() if c["source"] == "seeded_from_env"]
    assert seeded, r.json()
    return str(seeded[0]["id"])


def test_seeded_connection_is_usable_from_every_worker(ai_server: tuple[Server, Path, str]) -> None:
    """A connection record is shared (SQLite) but its live adapter is per process. A worker that
    has never been asked to LIST connections must still be able to READ the seeded one."""
    server, data, _ = ai_server
    (acct, key), = _mint(data / "accounts.db", 1)
    headers = {"X-API-Key": key}
    with httpx.Client(base_url=server.base, timeout=60) as c:
        conn_id = _first(c, headers)
    body = {"connection_id": conn_id, "operation": "health_check", "params": {}}
    results = _blast(server, [lambda c: c.post("/api/v1/ai/read", json=body, headers=headers)] * 60,
                     threads=40)
    codes = Counter((r.status_code, r.text[:90] if r.status_code != 200 else "") for r in results)
    assert {code for code, _ in codes} == {200}, codes


def test_concurrent_approvals_across_workers_execute_each_plan_exactly_once(
        ai_server: tuple[Server, Path, str]) -> None:
    server, data, table = ai_server
    (acct, key), = _mint(data / "accounts.db", 1)
    headers = {"X-API-Key": key}
    plans = 12
    contenders = 6
    with httpx.Client(base_url=server.base, timeout=60) as c:
        conn_id = _first(c, headers)
        ids = []
        for i in range(plans):
            r = c.post("/api/v1/ai/plan", headers=headers, json={
                "connection_id": conn_id, "operation": "execute_sql",
                "params": {"sql": f"INSERT INTO {table} VALUES ('plan-{i}')"}})
            assert r.status_code == 200, r.text
            ids.append(r.json()["plan"]["id"])
    assert len(set(ids)) == plans

    pids = server.worker_pids()
    before = {pid: server.cpu_ticks(pid) for pid in pids}
    calls = []
    for pid in ids:  # every plan is approved by `contenders` simultaneous requests
        calls += [lambda c, pid=pid: c.post(f"/api/v1/ai/plan/{pid}/approve", headers=headers)] * contenders
    results = _blast(server, calls, threads=48)
    assert _workers_that_worked(server, before) >= 2, "only one worker process served the approvals"

    by_plan: dict[str, Counter[int]] = {p: Counter() for p in ids}
    for call_idx, r in enumerate(results):
        by_plan[ids[call_idx // contenders]][r.status_code] += 1
    for pid, codes in by_plan.items():
        # exactly one request wins; every loser is a 409, never a second 200 or a 5xx
        assert codes.get(200, 0) == 1, (pid, codes)
        assert set(codes) <= {200, 409}, (pid, codes)

    rows = asyncio.run(_pg(f"SELECT plan, count(*) AS n FROM {table} GROUP BY plan"))
    assert {r["plan"]: r["n"] for r in rows} == {f"plan-{i}": 1 for i in range(plans)}
    server.stop()
    with sqlite3.connect(f"file:{data / 'ai.db'}?mode=ro", uri=True) as db:
        statuses = Counter(s for (s,) in db.execute("SELECT status FROM plans"))
    assert statuses == {"executed": plans}, statuses


def test_log_shows_no_secret_or_traceback(assurance_server: tuple[Server, Path]) -> None:
    server, data = assurance_server
    (acct, key), = _mint(data / "accounts.db", 1)
    _blast(server, [lambda c: c.post("/v1/cases/p-1/signal", json=_signal_body(1),
                                     headers={"X-API-Key": key})] * 8)
    server.stop()
    text = server.log.read_text()
    assert key not in text and OPERATOR_KEY not in text
    assert not re.search(r"Traceback|Error", text), text[-1500:]
