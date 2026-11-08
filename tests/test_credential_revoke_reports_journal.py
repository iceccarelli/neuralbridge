# ruff: noqa: F811, F401  (fixtures are imported by name)
"""A revoke or delete says whether the anti-rollback journal took it.

Revocation must take effect immediately even when the journal cannot be written, so it still does.
But an independent review found it answered a plain 200 either way: after a failed journal write, a
restored older backup brought the credential back and nobody had been told the guard was not armed.
"""

from __future__ import annotations

import pytest

from .credential_support import bind_as, roles
from .platform_support import API, audit_events, client, env, h, keys, read, requires_postgres

pytestmark = requires_postgres


def _break_journal(monkeypatch, ops):
    from neuralbridge.ai import credentials as cred

    real = cred.RollbackJournal.append

    def failing(self, op, **kw):
        if op in ops:
            raise cred.CustodyError(503, "credential_journal_unavailable", "disk full")
        return real(self, op, **kw)

    monkeypatch.setattr(cred.RollbackJournal, "append", failing)


def test_a_revoke_the_journal_took_says_so(client, keys, roles):
    conn = bind_as(client, keys.a)
    r = client.post(f"{API}/connections/{conn['id']}/revoke", headers=h(keys.a))
    assert r.status_code == 200
    assert r.json() == {"revoked": conn["id"], "already_revoked": False}, "the success body is unchanged"
    events = [e for e in audit_events(client, keys.a) if e.get("action") == "revoke"]
    assert any(e["result"] == "success" and e["details"].get("rollback_guard") == "recorded"
               for e in events), events


def test_a_revoke_the_journal_could_not_take_still_revokes_but_says_the_guard_is_off(
        client, keys, roles, monkeypatch):
    conn = bind_as(client, keys.a)
    _break_journal(monkeypatch, {"revoke"})
    r = client.post(f"{API}/connections/{conn['id']}/revoke", headers=h(keys.a))
    assert r.status_code == 200, "revocation must take effect even when the journal cannot be written"
    body = r.json()
    assert body["rollback_guard"] == "not_recorded"
    assert "older backup" in body["warning"]
    # in service no more: the very next call from any worker is refused
    assert read(client, keys.a, conn["id"]).status_code == 409
    events = [e for e in audit_events(client, keys.a) if e.get("action") == "revoke"]
    assert any(e["result"] == "success_unjournaled" for e in events), events


def test_a_delete_the_journal_could_not_take_says_so_too(client, keys, roles, monkeypatch):
    conn = bind_as(client, keys.a)
    _break_journal(monkeypatch, {"delete"})
    r = client.delete(f"{API}/connections/{conn['id']}", headers=h(keys.a))
    assert r.status_code == 200
    assert r.json()["rollback_guard"] == "not_recorded" and "warning" in r.json()
