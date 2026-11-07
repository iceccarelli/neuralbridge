# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Rate limits across worker processes.

The per-tenant adapter-call limit used to be a per-process sliding window, so ``--workers N``
admitted N times the configured rate. It is now counted in the shared ``/ai`` store (one atomic
upsert per call), so the limit is exact across processes on one host. What stays per process is
listed in ``neuralbridge.security.limits`` and reported by ``/health/ready``; these tests pin both
the shared behaviour and the honest labelling of the rest.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from collections import Counter
from pathlib import Path

import pytest

from neuralbridge.ai.store import AiStore
from neuralbridge.security.limits import (
    RateLimitedError,
    SharedWindowLimiter,
    SlidingWindowLimiter,
)

from .credential_support import ROLE_A, bind_as, roles, whoami, workers
from .platform_support import (
    API,
    Keys,
    client,
    env,
    h,
    keys,
    read,
    requires_postgres,
)

SRC = Path(__file__).resolve().parents[1] / "src"


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def admitted(limiter, key: str, n: int) -> int:
    ok = 0
    for _ in range(n):
        try:
            limiter.check(key)
            ok += 1
        except RateLimitedError:
            pass
    return ok


# ───────────────────────────── the shared counter ─────────────────────────────


class TestSharedWindowLimiter:
    def test_two_workers_share_one_limit(self, tmp_path) -> None:
        path = tmp_path / "s.db"
        w1 = SharedWindowLimiter(AiStore(path), 10, scope="adapter_call")
        w2 = SharedWindowLimiter(AiStore(path), 10, scope="adapter_call")  # another process' view of the file
        assert admitted(w1, "t", 6) + admitted(w2, "t", 6) == 10
        local = SlidingWindowLimiter(10)
        assert admitted(local, "t", 6) + admitted(SlidingWindowLimiter(10), "t", 6) == 12, \
            "the process-local limiter admits the limit once per worker (the defect this fixes)"

    def test_exact_under_threads_and_real_processes(self, tmp_path) -> None:
        path = tmp_path / "s.db"
        AiStore(path)
        limit = 60
        code = (
            "import sys; sys.path.insert(0, " + repr(str(SRC)) + "); "
            "from neuralbridge.ai.store import AiStore; "
            "from neuralbridge.security.limits import SharedWindowLimiter, RateLimitedError; "
            "lim = SharedWindowLimiter(AiStore(" + repr(str(path)) + "), " + str(limit) + ", 3600.0, scope='adapter_call'); "
            "ok = 0\n"
            "for _ in range(40):\n"
            "    try:\n        lim.check('tenant'); ok += 1\n"
            "    except RateLimitedError:\n        pass\n"
            "print(ok)"
        )
        procs = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)  # noqa: S603
                 for _ in range(4)]
        shared = SharedWindowLimiter(AiStore(path), limit, 3600.0, scope="adapter_call")
        results: list[int] = []
        threads = [threading.Thread(target=lambda: results.append(admitted(shared, "tenant", 40))) for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        total = sum(results) + sum(int(p.communicate()[0]) for p in procs)
        assert total == limit, f"{total} calls admitted across 4 processes and 4 threads, limit {limit}"

    def test_tenants_and_scopes_do_not_share_a_bucket(self, tmp_path) -> None:
        store = AiStore(tmp_path / "s.db")
        a = SharedWindowLimiter(store, 3, scope="adapter_call")
        b = SharedWindowLimiter(store, 3, scope="other_route")
        assert admitted(a, "tenant-1", 5) == 3
        assert admitted(a, "tenant-2", 5) == 3
        assert admitted(b, "tenant-1", 5) == 3

    def test_the_window_rolls_over_and_retry_after_is_honest(self, tmp_path) -> None:
        clock = Clock(1_000_040.0)  # 20 s into a 60 s window (1_000_020 is a multiple of 60)
        lim = SharedWindowLimiter(AiStore(tmp_path / "s.db"), 2, 60.0, scope="r", clock=clock)
        lim.check("k")
        lim.check("k")
        with pytest.raises(RateLimitedError) as exc:
            lim.check("k")
        # both calls sit in the window that ends in 40 s; the next window starts with half of them
        # still weighing on it, so one more call is admitted 30 s after that, i.e. 70 s from now
        assert exc.value.status_code == 429 and exc.value.retry_after == 70
        clock.t += 41  # the next window has begun, but the previous one still weighs
        with pytest.raises(RateLimitedError):
            lim.check("k")
        clock.t += 29 + 1  # the advertised wait has passed
        lim.check("k")
        clock.t += 125  # a full window of silence: the whole budget is back
        lim.check("k")
        lim.check("k")

    def test_old_windows_are_pruned(self, tmp_path) -> None:
        store = AiStore(tmp_path / "s.db")
        clock = Clock(1_000_000.0)
        lim = SharedWindowLimiter(store, 5, 60.0, scope="r", clock=clock)
        for i in range(5):
            lim.check(f"k{i}")
            clock.t += 61
        db = store._connect()
        assert db.execute("SELECT COUNT(*) FROM rate_windows").fetchone()[0] <= 3
        db.close()

    def test_a_disabled_limit_never_refuses(self, tmp_path) -> None:
        assert admitted(SharedWindowLimiter(AiStore(tmp_path / "s.db"), 0, scope="r"), "k", 50) == 50

    def test_a_burst_across_a_window_boundary_is_not_admitted_twice(self, tmp_path) -> None:
        clock = Clock(1_000_079.0)  # one second before a window boundary (multiple of 60 is 1_000_080)
        lim = SharedWindowLimiter(AiStore(tmp_path / "s.db"), 10, 60.0, scope="r", clock=clock)
        assert admitted(lim, "k", 10) == 10
        clock.t += 2  # just after the boundary: a fixed window would hand out a fresh 10
        assert admitted(lim, "k", 10) <= 1

    def test_refused_calls_are_not_counted_so_a_flood_does_not_extend_its_own_penalty(self, tmp_path) -> None:
        store = AiStore(tmp_path / "s.db")
        clock = Clock(1_000_000.0)
        lim = SharedWindowLimiter(store, 3, 60.0, scope="r", clock=clock)
        assert admitted(lim, "k", 500) == 3
        db = store._connect()
        assert db.execute("SELECT SUM(hits) FROM rate_windows").fetchone()[0] == 3
        db.close()

    def test_a_failing_store_falls_back_to_the_process_local_limiter_and_says_so(self) -> None:
        class Broken:
            def rate_hit(self, *a, **k):
                raise OSError("disk I/O error")

        lim = SharedWindowLimiter(Broken(), 3, scope="r")
        assert lim.mode == "shared" and admitted(lim, "k", 10) == 3
        assert lim.fallbacks == 10 and lim.mode == "shared_with_local_fallback"

    def test_a_refusal_from_the_shared_counter_is_never_overridden_by_the_local_one(self, tmp_path) -> None:
        store = AiStore(tmp_path / "s.db")
        lim = SharedWindowLimiter(store, 1, scope="r")
        lim.check("k")
        for _ in range(3):
            with pytest.raises(RateLimitedError):
                lim.check("k")
        assert lim.fallbacks == 0


# ───────────────────────────── wired into the service ─────────────────────────────


@requires_postgres
class TestServiceWiring:
    def test_the_limit_holds_across_two_simulated_workers(self, client, keys: Keys, roles, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "5")
        conn = bind_as(client, keys.a)
        with workers() as w:
            codes = []
            for name in ("w1", "w2", "w1", "w2", "w1", "w2", "w1", "w2"):
                w.use(name)
                codes.append(read(client, keys.a, conn["id"]).status_code)
        assert Counter(codes) == {200: 5, 429: 3}, codes

    def test_without_sharing_each_worker_has_its_own_budget(self, client, keys: Keys, roles, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "5")
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_SHARED", "0")
        conn = bind_as(client, keys.a)
        with workers() as w:
            codes = []
            for name in ("w1", "w2", "w1", "w2", "w1", "w2", "w1", "w2"):
                w.use(name)
                codes.append(read(client, keys.a, conn["id"]).status_code)
        assert Counter(codes) == {200: 8}, "4 + 4 calls: each process counted only its own"

    def test_one_tenant_exhausting_the_limit_does_not_starve_another(self, client, keys: Keys, roles, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "3")
        a, b = bind_as(client, keys.a, "a"), bind_as(client, keys.b, "b")
        assert Counter(read(client, keys.a, a["id"]).status_code for _ in range(5)) == {200: 3, 429: 2}
        assert read(client, keys.b, b["id"]).status_code == 200

    def test_the_429_names_the_limit_and_retry_after(self, client, keys: Keys, roles, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "1")
        conn = bind_as(client, keys.a)
        read(client, keys.a, conn["id"])
        r = read(client, keys.a, conn["id"])
        assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 120  # up to two windows: the previous one still weighs
        assert "rate limit of 1 calls per 60s" in r.json()["detail"]

    def test_readiness_labels_what_is_shared_and_what_is_not(self, client, keys: Keys, monkeypatch) -> None:
        ready = client.get("/api/v1/health/ready").json()
        assert ready["rate_limits"]["adapter_calls"] == {"mode": "shared", "per_minute": 120}
        assert set(ready["rate_limits"]["process_local"]) == {
            "concurrency_gate", "audit_refusal_limiter", "assurance_billing_throttles"}
        assert ready["rate_limits"]["declared_workers"] == 1
        assert not any(w.startswith("process_local_limiters") for w in ready.get("warnings", []))

    def test_readiness_warns_when_several_workers_share_process_local_limiters(self, client, keys: Keys, monkeypatch) -> None:
        monkeypatch.setenv("WEB_CONCURRENCY", "4")
        ready = client.get("/api/v1/health/ready").json()
        warning = [w for w in ready["warnings"] if w.startswith("process_local_limiters")]
        assert warning and "WEB_CONCURRENCY=4" in warning[0] and "4x" in warning[0]
        assert ready["rate_limits"]["declared_workers"] == 4

    def test_readiness_reports_a_fallback_to_process_local_counting(self, client, keys: Keys, monkeypatch) -> None:
        from neuralbridge.api.dependencies import get_adapter_registry, get_audit_logger, get_request_router

        router = get_request_router(get_adapter_registry(), get_audit_logger())
        monkeypatch.setattr(router._rate, "store", type("B", (), {"rate_hit": lambda *a, **k: (_ for _ in ()).throw(OSError())})())
        router._rate.check("someone")  # falls back; must not raise
        ready = client.get("/api/v1/health/ready").json()
        assert ready["rate_limits"]["adapter_calls"]["mode"] == "shared_with_local_fallback"
        assert any(w.startswith("rate_limit_fallback") for w in ready["warnings"])
