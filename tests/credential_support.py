"""Helpers for the credential-custody tests (not a test module).

* two real database roles on the shared dev cluster, so "which credential did this worker use?" is
  observable (``SELECT current_user``) without a password-checking cluster;
* ``as_other_worker`` — a fresh adapter registry and router over the SAME store, audit sink and
  environment: what another uvicorn worker process is, minus the process boundary (the real
  process boundary is exercised in ``test_platform_multiworker_custody.py``).
"""

from __future__ import annotations

import base64
import contextlib
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from .platform_support import API, PG_DATABASE, PG_HOST, PG_PORT, h, pg_run

ROLE_A = "nbcc_alpha"
ROLE_B = "nbcc_beta"
SECRET_1 = "Pw-CUSTODY-first-4471-qz"
SECRET_2 = "Pw-CUSTODY-second-9035-wk"


@pytest.fixture(scope="module")
def roles() -> Iterator[None]:
    for role, password in ((ROLE_A, SECRET_1), (ROLE_B, SECRET_2)):
        pg_run(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') "
               f"THEN CREATE ROLE {role} LOGIN; END IF; END $$",
               f"ALTER ROLE {role} LOGIN PASSWORD '{password}'")
    yield


def body(name: str, user: str = ROLE_A, password: str = SECRET_1, **extra) -> dict:
    return {"name": name, "host": PG_HOST, "port": PG_PORT, "user": user, "password": password,
            "database": PG_DATABASE, **extra}


def bind_as(client, key: str, name: str = "cust", user: str = ROLE_A, password: str = SECRET_1):
    r = client.post(f"{API}/connections", headers=h(key), json=body(name, user, password))
    assert r.status_code == 200, r.text
    return r.json()


def rotate_to(client, key: str, cid: str, user: str = ROLE_B, password: str = SECRET_2):
    return client.post(f"{API}/connections/{cid}/rotate", headers=h(key), json={"user": user, "password": password})


def whoami(client, key: str, cid: str):
    return client.post(f"{API}/read", headers=h(key), json={
        "connection_id": cid, "operation": "query", "params": {"sql": "SELECT current_user AS u"}})


def store_path() -> Path:
    return Path(os.environ["NEURALBRIDGE_AI_STORE"])


def sql(query: str, *args):
    db = sqlite3.connect(store_path())
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(query, args).fetchall()
        db.commit()
        return rows
    finally:
        db.close()


@contextlib.contextmanager
def as_other_worker() -> Iterator[object]:
    """Swap in a fresh registry + router (per-process state), keep the shared store/audit/env."""
    import neuralbridge.api.dependencies as deps

    saved = (deps._adapter_registry, deps._request_router)
    deps._adapter_registry = None
    deps._request_router = None
    try:
        yield deps.get_adapter_registry()
    finally:
        fresh = deps._adapter_registry
        deps._adapter_registry, deps._request_router = saved
        if fresh is not None:
            for key in fresh.list_all():
                fresh.unregister(key)


def new_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


class Workers:
    """Named per-process states (adapter registry + router) over one shared store; ``use`` switches the
    process-wide singletons to that worker's. ``"w1"`` is the state the test started in."""

    def __init__(self) -> None:
        import neuralbridge.api.dependencies as deps

        self._deps = deps
        self.current = "w1"
        self._sets: dict[str, tuple[object, object]] = {}

    def use(self, name: str):
        d = self._deps
        self._sets[self.current] = (d._adapter_registry, d._request_router)
        d._adapter_registry, d._request_router = self._sets.get(name, (None, None))
        self.current = name
        return d.get_adapter_registry()

    def registry(self, name: str):
        d = self._deps
        return d._adapter_registry if name == self.current else self._sets[name][0]


@contextlib.contextmanager
def workers() -> Iterator[Workers]:
    w = Workers()
    try:
        yield w
    finally:
        w.use("w1")
