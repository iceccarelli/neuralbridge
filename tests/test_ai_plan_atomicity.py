"""Plan approval is a compare-and-set, not read-then-write.

The deployed image runs several uvicorn workers; each has its own ``AiStore``
object over the one SQLite file, so a Python-level check of ``record.status``
proves nothing about what another worker is doing. Before the fix, N
concurrent approvals of one plan all passed the ``pending_approval`` check and
each executed the (non-idempotent) WRITE, and a deny could overwrite
``executed``. These tests hold the invariant: **a plan's operation runs at
most once, and a terminal state is never overwritten.**

The plan store is SQLite on every deployment; PostgreSQL is the *target* the
plan writes to. So the race is exercised (a) against the store with many
independent ``AiStore`` instances and real OS processes, and (b) end to end
against a real PostgreSQL, counting rows the executed plans actually wrote.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import multiprocessing as mp
import os
import threading
from collections import Counter
from typing import Any

import pytest

from neuralbridge.ai import orchestrator as o
from neuralbridge.ai.identity import Actor
from neuralbridge.ai.schemas import PlanStatus
from neuralbridge.ai.store import AiStore, ConnectionRecord
from neuralbridge.ai.tenancy import Scope

OWNER = "acc_aaaaaaaaaaaaaaaa"
SCOPE = Scope(owner=OWNER)
ACTOR = Actor("agent", "s1")
REGISTRY: dict[str, Any] = {"k": object()}


class _Resp:
    success = True
    data: Any = {}
    error = None
    request_id = "r"
    metadata: dict[str, Any] = {}

    def __init__(self) -> None:
        self.timestamp = dt.datetime.now(dt.UTC)


class CountingRouter:
    """Counts executions per ``params['pid']`` (thread-safe)."""

    def __init__(self, delay: float = 0.0) -> None:
        self.counts: Counter[Any] = Counter()
        self._lock = threading.Lock()
        self.delay = delay

    async def route(self, **kw: Any) -> dict[str, Any]:
        with self._lock:
            self.counts[kw["params"].get("pid")] += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        return {"data": _Resp()}


def _seed(path: Any) -> AiStore:
    store = AiStore(path)
    store.create_connection(
        ConnectionRecord(id="c1", name="n", adapter_type="postgres", registry_key="k",
                         source="user", owner=OWNER)
    )
    return store


def _propose(store: AiStore, **params: Any) -> str:
    card = o.create_plan(store, SCOPE, ACTOR, "c1", "execute_sql", {"sql": "DELETE FROM t", **params})
    return card.plan.id


def _outcome(fn: Any) -> str:
    try:
        asyncio.run(fn())
    except o.OrchestratorError as exc:
        return f"err{exc.status_code}"
    return "ok"


# -- store primitive ---------------------------------------------------------------


def test_transition_is_compare_and_set(tmp_path: Any) -> None:
    store = _seed(tmp_path / "ai.db")
    pid = _propose(store)
    first = store.transition_plan(pid, expected="pending_approval", status="approved", decided_by="a")
    assert first is not None and first.status == "approved"
    # Wrong precondition: refused, row untouched.
    assert store.transition_plan(pid, expected="pending_approval", status="denied", decided_by="b") is None
    again = store.get_plan(pid)
    assert again is not None and again.status == "approved" and again.decided_by == "a"
    with pytest.raises(KeyError):
        store.transition_plan("missing", expected="pending_approval", status="denied")


# -- approve vs approve ------------------------------------------------------------


def test_concurrent_approves_with_independent_stores_execute_once(tmp_path: Any) -> None:
    """Six 'workers' (own AiStore each, same file) race 40 plans."""
    path = tmp_path / "ai.db"
    seed = _seed(path)
    router = CountingRouter()
    results: dict[str, list[str]] = {}
    plan_ids = [_propose(seed, pid=i) for i in range(40)]

    def worker(pid: str, bar: threading.Barrier, out: list[str]) -> None:
        store = AiStore(path)  # a separate 'worker process' view of the file
        bar.wait()
        out.append(_outcome(lambda: o.approve_and_execute(router, REGISTRY, store, SCOPE, ACTOR, pid)))

    for pid in plan_ids:
        bar = threading.Barrier(6)
        results[pid] = []
        ts = [threading.Thread(target=worker, args=(pid, bar, results[pid])) for _ in range(6)]
        [t.start() for t in ts]
        [t.join() for t in ts]

    for i, pid in enumerate(plan_ids):
        assert router.counts[i] == 1, f"plan {i} executed {router.counts[i]} times"
        assert sorted(results[pid]) == ["err409"] * 5 + ["ok"], results[pid]
        rec = seed.get_plan(pid)
        assert rec is not None and rec.status == PlanStatus.EXECUTED.value


def _proc_worker(path: str, pid: str, marker_dir: str, start: Any) -> None:
    store = AiStore(path)

    class FileRouter:
        async def route(self, **kw: Any) -> dict[str, Any]:
            # O_EXCL-free append: one line per execution, counted by the parent.
            with open(os.path.join(marker_dir, "exec.log"), "a", encoding="utf-8") as fh:
                fh.write(f"{kw['params']['pid']}\n")
            return {"data": _Resp()}

    start.wait()
    _outcome(lambda: o.approve_and_execute(FileRouter(), REGISTRY, store, SCOPE, ACTOR, pid))


def test_concurrent_approves_across_processes_execute_once(tmp_path: Any) -> None:
    path = str(tmp_path / "ai.db")
    seed = _seed(path)
    ctx = mp.get_context("spawn")
    plan_ids = [_propose(seed, pid=i) for i in range(8)]
    for pid in plan_ids:
        start = ctx.Barrier(4)
        procs = [ctx.Process(target=_proc_worker, args=(path, pid, str(tmp_path), start)) for _ in range(4)]
        [p.start() for p in procs]
        [p.join(60) for p in procs]
        assert all(p.exitcode == 0 for p in procs)
    log = (tmp_path / "exec.log").read_text().split()
    assert Counter(log) == {str(i): 1 for i in range(8)}


# -- deny vs approve ---------------------------------------------------------------


def test_deny_never_overwrites_an_executed_plan(tmp_path: Any) -> None:
    path = tmp_path / "ai.db"
    seed = _seed(path)
    router = CountingRouter()
    for i in range(30):
        pid = _propose(seed, pid=i)
        bar = threading.Barrier(2)
        out: dict[str, str] = {}

        def approve(pid: str = pid, bar: threading.Barrier = bar, out: dict[str, str] = out) -> None:
            store = AiStore(path)
            bar.wait()
            out["approve"] = _outcome(lambda: o.approve_and_execute(router, REGISTRY, store, SCOPE, ACTOR, pid))

        def deny(pid: str = pid, bar: threading.Barrier = bar, out: dict[str, str] = out) -> None:
            store = AiStore(path)
            bar.wait()
            try:
                o.deny_plan(store, SCOPE, ACTOR, pid, "no")
                out["deny"] = "ok"
            except o.OrchestratorError as exc:
                out["deny"] = f"err{exc.status_code}"

        ts = [threading.Thread(target=approve), threading.Thread(target=deny)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        rec = seed.get_plan(pid)
        assert rec is not None
        if out["approve"] == "ok":
            assert out["deny"] == "err409" and rec.status == "executed" and router.counts[i] == 1
        else:
            assert out["approve"] == "err409" and out["deny"] == "ok"
            assert rec.status == "denied" and router.counts[i] == 0


def test_deny_after_executed_is_409_and_keeps_executed(tmp_path: Any) -> None:
    store = _seed(tmp_path / "ai.db")
    pid = _propose(store)
    asyncio.run(o.approve_and_execute(CountingRouter(), REGISTRY, store, SCOPE, ACTOR, pid))
    with pytest.raises(o.OrchestratorError) as err:
        o.deny_plan(store, SCOPE, ACTOR, pid, "late")
    assert err.value.status_code == 409
    rec = store.get_plan(pid)
    assert rec is not None and rec.status == "executed" and rec.deny_reason is None


# -- failure after the claim -------------------------------------------------------


class _FailingRouter:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc
        self.calls = 0

    async def route(self, **kw: Any) -> dict[str, Any]:
        self.calls += 1
        raise self.exc


@pytest.mark.parametrize("exc", [RuntimeError("driver blew up"), asyncio.CancelledError()])
def test_failure_after_claim_is_terminal_and_never_rerun(tmp_path: Any, exc: BaseException) -> None:
    """The write may or may not have landed: the plan becomes ``failed`` (not
    pending, not approved) and a second approve is refused rather than re-running it."""
    store = _seed(tmp_path / "ai.db")
    pid = _propose(store)
    router = _FailingRouter(exc)
    with pytest.raises((o.OrchestratorError, asyncio.CancelledError)):
        asyncio.run(o.approve_and_execute(router, REGISTRY, store, SCOPE, ACTOR, pid))
    rec = store.get_plan(pid)
    assert rec is not None and rec.status == PlanStatus.FAILED.value
    with pytest.raises(o.OrchestratorError) as err:
        asyncio.run(o.approve_and_execute(router, REGISTRY, store, SCOPE, ACTOR, pid))
    assert err.value.status_code == 409
    assert router.calls == 1


def test_precondition_failure_leaves_plan_pending(tmp_path: Any) -> None:
    """Nothing was claimed or run (adapter gone): the plan stays approvable."""
    store = _seed(tmp_path / "ai.db")
    pid = _propose(store)
    with pytest.raises(o.OrchestratorError):
        asyncio.run(o.approve_and_execute(CountingRouter(), {}, store, SCOPE, ACTOR, pid))
    rec = store.get_plan(pid)
    assert rec is not None and rec.status == "pending_approval"


# -- end to end against a real PostgreSQL ------------------------------------------

try:  # same reachability probe + env as tests/test_ai.py
    from tests.test_ai import (  # type: ignore[import-not-found]
        PG_DATABASE,
        PG_HOST,
        PG_PASSWORD,
        PG_PORT,
        PG_USER,
        _postgres_reachable,
    )

    _PG = _postgres_reachable()
except Exception:  # pragma: no cover
    _PG = False


@pytest.mark.skipif(not _PG, reason="No reachable PostgreSQL (NEURALBRIDGE_AI_PG_*) - skipped honestly")
def test_concurrent_approves_write_exactly_one_row_in_real_postgres(tmp_path: Any) -> None:
    import asyncpg

    async def pg(sql: str, *args: Any) -> Any:
        c = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER,
                                  password=PG_PASSWORD, database=PG_DATABASE)
        try:
            return await c.fetch(sql, *args)
        finally:
            await c.close()

    asyncio.run(pg("DROP TABLE IF EXISTS ai_atomicity"))
    asyncio.run(pg("CREATE TABLE ai_atomicity (plan int)"))

    class PgRouter:  # the real non-idempotent write, one connection per call
        async def route(self, **kw: Any) -> dict[str, Any]:
            await pg("INSERT INTO ai_atomicity VALUES ($1)", kw["params"]["pid"])
            return {"data": _Resp()}

    path = tmp_path / "ai.db"
    seed = _seed(path)
    try:
        plan_ids = [_propose(seed, pid=i) for i in range(25)]
        for pid in plan_ids:
            bar = threading.Barrier(6)

            def worker(pid: str = pid, bar: threading.Barrier = bar) -> None:
                store = AiStore(path)
                bar.wait()
                _outcome(lambda: o.approve_and_execute(PgRouter(), REGISTRY, store, SCOPE, ACTOR, pid))

            ts = [threading.Thread(target=worker) for _ in range(6)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        rows = asyncio.run(pg("SELECT plan, count(*) AS n FROM ai_atomicity GROUP BY plan"))
        assert {r["plan"]: r["n"] for r in rows} == dict.fromkeys(range(25), 1)
    finally:
        asyncio.run(pg("DROP TABLE IF EXISTS ai_atomicity"))
