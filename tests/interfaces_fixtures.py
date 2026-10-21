"""A real assurance API on a real socket, for the cross-interface tests.

Servers here use ports 18400-18499 only. Accounts, keys and per-account ledgers
are the real ones (``assurance.api.deps``), in a temp directory; nothing about
the domain or the HTTP layer is mocked.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

PORT_RANGE = range(18400, 18500)


def free_port() -> int:
    for port in PORT_RANGE:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port in 18400-18499")


@dataclass
class LiveApi:
    url: str
    accounts: Any
    root: Path

    def account(self, email: str, tier: str = "cell") -> tuple[str, dict[str, str]]:
        """A real account on ``tier`` and the header that authenticates it."""
        acct = self.accounts.upsert_account(email=email, tier=tier)
        return acct.id, {"X-API-Key": self.accounts.issue_key(acct.id)}

    def tenant_ledger(self, account_id: str):
        from assurance.api import deps

        return deps._tenant_register_for(str(deps.tenant_ledger_path(account_id))).ledger

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.url, timeout=30.0)


@pytest.fixture
def live_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LiveApi]:
    from assurance.api import deps
    from assurance.api.service import create_app

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "operator.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    deps._tenant_register_for.cache_clear()

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(
        create_app(), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(f"{url}/healthz", timeout=0.5)
            break
        except httpx.TransportError:
            time.sleep(0.1)
    else:
        raise RuntimeError("assurance API did not come up")
    try:
        yield LiveApi(url=url, accounts=deps.get_accounts(), root=tmp_path)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        deps._register_for.cache_clear()
        deps._accounts_for.cache_clear()
        deps._tenant_register_for.cache_clear()
