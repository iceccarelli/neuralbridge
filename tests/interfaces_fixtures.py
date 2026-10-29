"""A real assurance API on a real socket, for the cross-interface tests.

Each server listens on a socket this module binds itself, to a port the kernel chooses
(loopback only), and hands that socket to uvicorn: there is no probe-then-bind gap, so
two runs on one machine cannot end up talking to each other's server. Accounts, keys and
per-account ledgers are the real ones (``assurance.api.deps``), in a temp directory;
nothing about the domain or the HTTP layer is mocked.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

from .support_recorder import server_trust


def listening_socket() -> socket.socket:
    """A loopback socket, bound and listening on a port the kernel picked, owned by the caller."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
    except OSError:
        sock.close()
        raise
    return sock


@dataclass
class LiveApi:
    url: str
    accounts: Any
    root: Path

    def account(self, email: str, tier: str = "cell") -> tuple[str, dict[str, str]]:
        """A real account on ``tier`` and the header that authenticates it."""
        acct = self.accounts.upsert_account(email=email, tier=tier)
        return acct.id, {"X-API-Key": self.accounts.issue_key(acct.id)}

    def operator_headers(self, account_id: str, name: str) -> dict[str, str]:
        """The header of a key issued to a ``decider`` operator called ``name``."""
        _, key = self.accounts.create_operator(account_id, name, "decider")
        return {"X-API-Key": key}

    def tenant_ledger(self, account_id: str):
        from assurance.api import deps

        return deps._tenant_register_for(str(deps.tenant_ledger_path(account_id))).ledger

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.url, timeout=30.0)


@contextmanager
def serve(app: Any, *, startup_timeout: float = 15.0) -> Iterator[str]:
    """Serve ``app`` on a loopback port the kernel chose and yield its base URL.

    The listening socket is bound here and handed to uvicorn, and it is released (and the
    server thread joined) on every exit path, including a server that never starts.
    """
    sock = listening_socket()
    server: uvicorn.Server | None = None
    thread: threading.Thread | None = None
    try:
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error"))
        failures: list[BaseException] = []

        def run() -> None:
            try:
                server.run(sockets=[sock])
            except BaseException as exc:  # noqa: BLE001  (reported to the caller below)
                failures.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        deadline = time.monotonic() + startup_timeout
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("the server did not come up") from (
                    failures[0] if failures else None)
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        if server is not None:
            server.should_exit = True
        if thread is not None:
            thread.join(timeout=10)
        sock.close()


@pytest.fixture
def live_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LiveApi]:
    from assurance.api import deps
    from assurance.api.service import create_app

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "operator.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    # the hosted service's OWN recorder trust list (a file the operator configures)
    server_trust(monkeypatch, tmp_path)
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)

    def clear() -> None:
        deps._register_for.cache_clear()
        deps._accounts_for.cache_clear()
        deps._tenant_register_for.cache_clear()

    clear()
    try:
        with serve(create_app()) as url:
            yield LiveApi(url=url, accounts=deps.get_accounts(), root=tmp_path)
    finally:
        clear()
