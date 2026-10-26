"""``live_api`` must not depend on a fixed port range being free.

It used to probe 18400-18499 for a free port and bind it later. Two test runs on one
machine (two worktrees, two CI shards) could pick the same port in the gap between the
probe and the bind, and one run's client then talked to the other run's server: its
accounts, its keys, its ledgers. The fixtures now listen on a socket they bound
themselves, on a port the kernel chose, and hand that socket to the server
(``interfaces_fixtures.serve``).

These tests do not occupy the old range: a test that listened on every port in it could
itself break a neighbour (``test_interfaces_offline`` treats 18499 as "nothing listening").
They prove the property directly instead.
"""

from __future__ import annotations

import socket
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from . import interfaces_fixtures as fx

live_api = fx.live_api

FORMER_RANGE = range(18400, 18500)


def ephemeral_range() -> range:
    try:
        lo, hi = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
        return range(int(lo), int(hi) + 1)
    except (OSError, ValueError):
        return range(1024, 65536)


def whoami(name: str) -> FastAPI:
    app = FastAPI()

    @app.get("/whoami")
    def _whoami() -> dict[str, str]:
        return {"server": name}
    return app


def port_of(url: str) -> int:
    return int(url.rsplit(":", 1)[1])


def test_the_probe_then_bind_helper_is_gone():
    """Nothing is left that could pick a port from a fixed range and bind it later."""
    assert not hasattr(fx, "free_port") and not hasattr(fx, "PORT_RANGE")


def test_two_servers_run_at_once_and_each_answers_for_itself():
    with fx.serve(whoami("one")) as one, fx.serve(whoami("two")) as two:
        assert port_of(one) != port_of(two)
        assert httpx.get(f"{one}/whoami", timeout=10.0).json() == {"server": "one"}
        assert httpx.get(f"{two}/whoami", timeout=10.0).json() == {"server": "two"}
        # the socket the server listens on is the one the fixture bound: nobody else can
        # take the port while it is up
        for url in (one, two):
            with socket.socket() as probe, pytest.raises(OSError):
                probe.bind(("127.0.0.1", port_of(url)))


def test_ports_are_assigned_by_the_kernel_not_taken_from_the_old_range():
    seen = []
    for n in range(4):
        with fx.serve(whoami(str(n))) as url:
            seen.append(port_of(url))
    assert all(p in ephemeral_range() and p not in FORMER_RANGE for p in seen), seen


def test_a_small_squatter_on_the_old_range_changes_nothing():
    held = []
    try:
        for port in range(18400, 18410):
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", port))
                s.listen()
            except OSError:
                s.close()
                continue
            held.append(s)
        with fx.serve(whoami("ours")) as url:
            assert httpx.get(f"{url}/whoami", timeout=10.0).json() == {"server": "ours"}
    finally:
        for s in held:
            s.close()


def test_the_port_is_released_when_the_server_stops():
    with fx.serve(whoami("gone")) as url:
        port = port_of(url)
    with socket.socket() as probe:
        probe.settimeout(1.0)
        assert probe.connect_ex(("127.0.0.1", port)) != 0


def test_a_server_that_cannot_start_leaks_no_socket(monkeypatch):
    made: list[socket.socket] = []
    real = fx.listening_socket

    def spy() -> socket.socket:
        made.append(real())
        return made[-1]

    monkeypatch.setattr(fx, "listening_socket", spy)

    class Broken:
        def __getattr__(self, name):          # uvicorn's config loading touches the app
            raise RuntimeError("cannot start")

    with pytest.raises(Exception), fx.serve(Broken(), startup_timeout=3.0):  # noqa: B017
        pass
    assert made and all(s.fileno() == -1 for s in made), "the listening socket leaked"


def test_live_api_is_served_from_a_kernel_port(live_api):
    assert port_of(live_api.url) in ephemeral_range()
    _, headers = live_api.account("ports@example.de", "cell")
    me = httpx.get(f"{live_api.url}/v1/me", headers=headers, timeout=10.0)
    assert me.status_code == 200 and me.json()["tier"] == "cell"
