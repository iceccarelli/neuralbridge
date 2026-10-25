"""``live_api`` must not depend on a fixed port range being free.

It used to probe 18400-18499 for a free port and bind it later. Two test runs on one
machine (two worktrees, two CI shards) could pick the same port in the gap between the
probe and the bind, and one run's client then talked to the other run's server: its
accounts, its keys, its ledgers. The fixture now listens on a socket it bound itself, on
a port the kernel chose, and hands that socket to the server.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import httpx
import pytest

from . import interfaces_fixtures as fx

live_api = fx.live_api

FORMER_RANGE = range(18400, 18500)


@pytest.fixture
def former_range_taken() -> Iterator[list[int]]:
    """Every port the fixture used to be willing to use is held by somebody else."""
    held: list[socket.socket] = []
    for port in FORMER_RANGE:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            s.listen()
        except OSError:
            s.close()          # already someone else's: that is the situation anyway
            continue
        held.append(s)
    try:
        yield [s.getsockname()[1] for s in held]
    finally:
        for s in held:
            s.close()


def test_live_api_comes_up_when_the_old_fixed_range_is_taken(former_range_taken, live_api):
    port = int(live_api.url.rsplit(":", 1)[1])
    assert port not in FORMER_RANGE
    # It is OUR server: an account made through our store authenticates against it.
    _, headers = live_api.account("ports@example.de", "cell")
    me = httpx.get(f"{live_api.url}/v1/me", headers=headers, timeout=10.0)
    assert me.status_code == 200 and me.json()["tier"] == "cell"


def test_two_servers_never_share_a_port(live_api):
    """The socket the server listens on is the one the fixture bound: nothing else can
    have it, so a second bind of the same port is refused for as long as it is up."""
    host, port = live_api.url.removeprefix("http://").split(":")
    with socket.socket() as probe:
        with pytest.raises(OSError):
            probe.bind((host, int(port)))
