"""``LiveApi.client()`` hands out httpx clients that most callers never close.

An unclosed ``httpx.Client`` keeps its pooled TCP socket until it is garbage collected, which
CPython 3.13 reports as ``ResourceWarning: unclosed <socket.socket ...>`` (dozens per run). The
``live_api`` fixture therefore closes every client it handed out, whether or not the test did.
"""

from __future__ import annotations

from . import interfaces_fixtures as fx
from .interfaces_fixtures import LiveApi

live_api = fx.live_api


def test_every_client_handed_out_is_closed_when_the_fixture_closes_them(live_api: LiveApi) -> None:
    a, b = live_api.client(), live_api.client()
    assert a.get("/v1/plans").status_code == 200      # opens a real pooled connection
    assert not a.is_closed and not b.is_closed
    live_api.close_clients()
    assert a.is_closed and b.is_closed
    live_api.close_clients()                          # idempotent
