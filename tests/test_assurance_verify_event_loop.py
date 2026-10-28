"""``POST /v1/machine/verify`` must not run the engine on the event loop.

The route parses a trace of up to ``MAX_SAMPLES`` samples and runs the whole
verification engine over it. Done inline in an ``async def`` handler that is seconds
of CPU during which *no other request on the process is served* -- liveness
included, for every tenant. The free bundle checker already hands the same kind of
work to a worker thread; this pins the verify route to the same rule.

Two independent checks, because each can be fooled alone: where the work runs
(deterministic), and whether the server stays responsive while it runs (end to end,
on a real socket, with a deliberately generous bound).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import httpx

from assurance.machine import bundle as bundle_module
from assurance.machine.trace import Trace

from . import interfaces_fixtures as fx
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_machine_provenance import envelope

client, store = _client, _store
live_api = fx.live_api


def _trace_payload(samples: int) -> dict:
    return {
        "trace_id": "BIG", "provenance": "field", "source_system": "fw",
        "started_at": "2026-09-12T04:31:00Z", "sample_rate_hz": 50.0, "conditions": {},
        "samples": [{"t": i / 50.0, "tcp": [0.0, 0.0, 1000.0], "tcp_speed": 300.0,
                     "mode": "ssm", "separation": 3000.0} for i in range(samples)],
    }


def _body(samples: int) -> dict:
    return {"envelope": envelope().to_dict(), "trace": _trace_payload(samples),
            "actor": "ci", "seal": False}


class TestWhereTheEngineRuns:
    def test_parsing_the_trace_and_building_the_bundle_run_off_the_event_loop(
            self, client, store, monkeypatch):
        """Both calls are the real functions, wrapped only to record the thread they ran
        on and whether that thread was running an event loop."""
        seen: dict[str, tuple[bool, str]] = {}

        def watched(name, real):
            def inner(*args, **kwargs):
                try:
                    asyncio.get_running_loop()
                    on_loop = True
                except RuntimeError:
                    on_loop = False
                seen[name] = (on_loop, threading.current_thread().name)
                return real(*args, **kwargs)
            return inner

        monkeypatch.setattr(Trace, "from_dict",
                            staticmethod(watched("parse", Trace.from_dict)))
        monkeypatch.setattr("assurance.api.machine_routes.build_bundle",
                            watched("build", bundle_module.build_bundle))
        headers = keyed(store, "cell")
        r = client.post("/v1/machine/verify", headers=headers, json=_body(40))
        assert r.status_code == 200
        assert r.json()["verdict"] == "pass"
        assert set(seen) == {"parse", "build"}
        assert seen["parse"][0] is False, "Trace.from_dict ran on the event loop"
        assert seen["build"][0] is False, "build_bundle ran on the event loop"

    def test_the_sealing_variant_is_off_the_loop_too_and_still_seals(
            self, client, store, monkeypatch):
        seen: list[bool] = []
        real = bundle_module.build_bundle

        def inner(*args, **kwargs):
            try:
                asyncio.get_running_loop()
                seen.append(True)
            except RuntimeError:
                seen.append(False)
            return real(*args, **kwargs)

        monkeypatch.setattr("assurance.api.machine_routes.build_bundle", inner)
        headers = keyed(store, "cell")
        body = _body(40)
        body["seal"] = True
        body["subject"] = "Acme/AR-7#0412"
        r = client.post("/v1/machine/verify", headers=headers, json=body)
        assert r.status_code == 200
        assert r.json()["sealed"] is True
        assert seen == [False]

    def test_a_trace_over_the_cap_is_still_refused_with_413(self, client, store):
        headers = keyed(store, "cell")
        body = _body(1)
        body["trace"]["samples"] = [0] * 200_001
        r = client.post("/v1/machine/verify", headers=headers, json=body)
        assert r.status_code == 413
        assert r.json()["detail"]["error"] == "trace_too_large"

    def test_a_malformed_trace_is_still_a_422_naming_the_trace(self, client, store):
        headers = keyed(store, "cell")
        body = _body(1)
        body["trace"] = {"trace_id": "x"}
        r = client.post("/v1/machine/verify", headers=headers, json=body)
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_trace"


SAMPLES = 100_000


class TestTheServerStaysResponsive:
    def test_liveness_is_answered_while_a_large_verification_runs(self, live_api):
        _, headers = live_api.account("loop@example.de")
        body = json.dumps(_body(SAMPLES))
        probes: list[tuple[float, float]] = []      # (started_at, latency)
        verify: dict[str, float] = {}
        stop = threading.Event()

        def post() -> None:
            with httpx.Client(base_url=live_api.url, timeout=300.0) as c:
                started = time.monotonic()
                r = c.post("/v1/machine/verify", content=body,
                           headers={**headers, "Content-Type": "application/json"})
                verify["status"] = r.status_code
                verify["start"], verify["end"] = started, time.monotonic()

        def probe() -> None:
            with httpx.Client(base_url=live_api.url, timeout=300.0) as c:
                while not stop.is_set():
                    t0 = time.monotonic()
                    c.get("/healthz")
                    probes.append((t0, time.monotonic() - t0))
                    time.sleep(0.02)

        prober = threading.Thread(target=probe, daemon=True)
        poster = threading.Thread(target=post, daemon=True)
        prober.start()
        time.sleep(0.3)                  # the prober is warm before the work arrives
        poster.start()
        poster.join(timeout=300)
        stop.set()
        prober.join(timeout=60)

        assert verify.get("status") == 200
        duration = verify["end"] - verify["start"]
        # a probe that STARTED while the verification ran, however late it was answered
        during = [lat for began, lat in probes if verify["start"] <= began <= verify["end"]]
        assert during, "no liveness probe was sent while the verification ran"
        worst = max(during)
        # Unblocked, a probe takes milliseconds; blocked, it waits for the whole run.
        # Half the run (and never less than a second of slack) cannot be passed by a
        # server that was blocked for the run.
        assert worst < max(1.0, duration * 0.5), (
            f"liveness stalled {worst:.2f}s of a {duration:.2f}s verification")


class TestAtMostAFewRunAtOnce:
    """Moving the engine off the event loop must not let a crowd of maximum-size traces
    sit in memory at once (the blocked loop used to serialise them by accident)."""

    def test_concurrent_engine_runs_never_exceed_the_documented_bound(
            self, live_api, monkeypatch):
        from assurance.api import machine_routes

        # the documented bound (docs/claims-registry.md), not read back from the code
        bound = 4
        assert machine_routes.MAX_CONCURRENT_VERIFICATIONS == bound
        real = machine_routes.build_bundle
        lock = threading.Lock()
        over_bound = threading.Event()
        state = {"inside": 0, "max": 0}

        def spy(*args, **kwargs):
            with lock:
                state["inside"] += 1
                state["max"] = max(state["max"], state["inside"])
                if state["inside"] > bound:
                    over_bound.set()
            try:
                # hold the run open until one MORE than the bound is inside, or give up
                over_bound.wait(timeout=0.8)
                return real(*args, **kwargs)
            finally:
                with lock:
                    state["inside"] -= 1

        monkeypatch.setattr(machine_routes, "build_bundle", spy)
        _, headers = live_api.account("bound@example.de")
        statuses: list[int] = []

        def post() -> None:
            with httpx.Client(base_url=live_api.url, timeout=120.0) as c:
                statuses.append(c.post("/v1/machine/verify", json=_body(40),
                                       headers=headers).status_code)

        threads = [threading.Thread(target=post, daemon=True) for _ in range(bound * 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        assert statuses == [200] * (bound * 2)
        assert state["max"] == bound


class TestTheMachineryRoutesAreOffTheLoopToo:
    """Reading a ledger, verifying its chain and hashing manifests is disk and CPU work.
    The machinery handlers are plain ``def`` routes, which FastAPI runs in a worker thread."""

    def test_the_ledger_work_behind_each_route_runs_off_the_event_loop(
            self, client, store, monkeypatch):
        from datetime import UTC, datetime

        from assurance.api import machinery_routes as routes

        from .test_assurance_staleness_integrity import KEY, manifest, update

        seen: dict[str, bool] = {}

        def watched(name, real):
            def inner(*args, **kwargs):
                try:
                    asyncio.get_running_loop()
                    seen[name] = True
                except RuntimeError:
                    seen[name] = False
                return real(*args, **kwargs)
            return inner

        for name in ("record_manifest", "check_intervention", "assess_coverage",
                     "build_passport"):
            monkeypatch.setattr(routes, name, watched(name, getattr(routes, name)))
        headers = keyed(store, "cell")
        m = manifest().to_dict()
        assert client.post("/v1/machinery/manifest", headers=headers,
                           json={"manifest": m}).status_code == 200
        iv = update(when=datetime(2026, 10, 1, tzinfo=UTC), key=KEY)
        assert client.post("/v1/machinery/intervention", headers=headers, json={
            "intervention": iv.to_dict(), "actor": "t"}).status_code == 200
        assert client.post("/v1/machinery/coverage", headers=headers,
                           json={"manifest": m}).status_code == 200
        assert client.post("/v1/machinery/passport", headers=headers, json={
            "manifest": m, "actor": "t", "seal": False}).status_code == 200
        assert seen == {"record_manifest": False, "check_intervention": False,
                        "assess_coverage": False, "build_passport": False}
