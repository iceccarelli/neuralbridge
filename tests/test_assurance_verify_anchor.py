"""GET /v1/ledger/verify answers completeness against the service's own counter-signature.

Real Ed25519 keys, real per-account ledgers, throwaway data. The anchor is used only if
every record in the account's attestation log verifies against the *service's* key.
"""

from __future__ import annotations

import json
import os
import sqlite3
from types import SimpleNamespace

from assurance.api import attest_routes, deps
from assurance.attest import AttestationLog, SigningKey, attest
from assurance.attest.anchor import choose_anchor
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import cli as art14_cli

from .test_assurance_export_api import _account, _read_sign, _signal, api  # noqa: F401


def _verify(client, headers):
    r = client.get("/v1/ledger/verify", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _cut(account, keep):
    db = sqlite3.connect(deps.tenant_ledger_path(account.id))
    db.execute("DELETE FROM chain WHERE seq > ?", (keep,))
    db.commit()
    db.close()


def _log_path(account):
    return attest_routes._log_for(SimpleNamespace(subject=account.id)).path


def _seeded(api, email="a@example.de", n=3):  # noqa: F811
    account, headers = _account(email)
    for i in range(n):
        _signal(api, headers, f"C{i}")
    return account, headers


def test_untouched_ledger_with_counter_signed_head_is_checked_against_anchor(api):  # noqa: F811
    account, headers = _seeded(api)
    signed = _read_sign(account)
    body = _verify(api, headers)
    assert body["completeness"] == "checked_against_anchor" and body["verified"] is True
    a = body["anchor"]
    assert a["sequence"] == signed["sequence"] and a["attested_at"] == signed["attested_at"]
    assert a["key_fingerprint"] == signed["key_fingerprint"]
    assert a["head_link_hash"] == signed["head_link_hash"]
    assert "covers nothing appended after" in body["anchor_meaning"]
    assert "not that the records behind it are true" in body["anchor_meaning"]
    assert any("appended after the anchor" in s for s in body["not_checked"])
    assert not any("was not verified by this call" in s for s in body["not_checked"])


def test_tail_truncated_after_attestation_is_contradicted(api):  # noqa: F811
    account, headers = _seeded(api)
    _read_sign(account)
    _cut(account, 1)
    body = _verify(api, headers)
    assert body["completeness"] == "contradicted_by_anchor"
    assert body["verified"] is False and body["problems"]
    assert body["anchor"] is not None


def test_no_key_configured_is_not_checked_with_reason(api, monkeypatch):  # noqa: F811
    account, headers = _seeded(api)
    _read_sign(account)
    monkeypatch.delenv("ASSURANCE_ATTEST_KEY")
    body = _verify(api, headers)
    assert body["completeness"] == "not_checked" and body["verified"] is True
    assert body["anchor"] is None
    assert any("no service signing key is configured" in s for s in body["not_checked"])


def test_no_log_is_not_checked_with_reason(api):  # noqa: F811
    _account_row, headers = _seeded(api)
    body = _verify(api, headers)
    assert body["completeness"] == "not_checked"
    assert any("holds no attestations" in s for s in body["not_checked"])


def test_log_signed_by_a_different_key_is_not_used(api):  # noqa: F811
    account, headers = _seeded(api)
    other = SigningKey.generate()
    attest(EvidenceLedger(deps.tenant_ledger_path(account.id)), other,
           attest_routes._log_for(SimpleNamespace(subject=account.id)))
    _cut(account, 1)                    # would be a contradiction if the log were trusted
    body = _verify(api, headers)
    assert body["completeness"] == "not_checked" and body["anchor"] is None
    assert any("does not verify against the service key" in s for s in body["not_checked"])


def test_tampered_log_record_is_not_used(api):  # noqa: F811
    account, headers = _seeded(api)
    _read_sign(account)
    path = _log_path(account)
    rec = json.loads(path.read_text().splitlines()[0])
    rec["ledger_length"] = 1             # edited after signing, so it would "match" a cut
    rec["head_seq"] = 1
    path.write_text(json.dumps(rec, sort_keys=True) + "\n")
    _cut(account, 1)
    body = _verify(api, headers)
    assert body["completeness"] == "not_checked" and body["anchor"] is None
    assert any("does not verify" in s for s in body["not_checked"])


def test_declared_heads_never_anchor_the_hosted_ledger(api):  # noqa: F811
    account, headers = _seeded(api)
    r = api.post("/v1/ledger/attest", headers=headers, json={
        "ledger_length": 9, "head_seq": 9, "head_link_hash": "a" * 64})
    assert r.status_code == 200, r.text
    body = _verify(api, headers)
    assert body["completeness"] == "not_checked" and body["verified"] is True
    assert any("declared by the account holder" in s for s in body["not_checked"])


def test_ledger_grown_after_the_anchor_is_checked_and_says_later_records_uncovered(api):  # noqa: F811
    account, headers = _seeded(api)
    _read_sign(account)
    _signal(api, headers, "LATER")
    body = _verify(api, headers)
    assert body["completeness"] == "checked_against_anchor" and body["verified"] is True
    assert body["attestation"]["length"] > body["anchor"]["ledger_length"]
    assert any("appended after the anchor" in s for s in body["not_checked"])


def test_a_torn_log_tail_is_not_used(api):  # noqa: F811
    account, headers = _seeded(api)
    _read_sign(account)
    with open(_log_path(account), "ab") as f:
        f.write(b'{"sequence": 2')
    body = _verify(api, headers)
    assert body["completeness"] == "not_checked"
    assert any("unfinished line" in s for s in body["not_checked"])


def test_second_tenant_is_not_anchored_by_the_first_tenants_log(api):  # noqa: F811
    a, ha = _seeded(api, "a@example.de")
    b, hb = _seeded(api, "b@example.de", n=1)
    _read_sign(a)
    assert _verify(api, ha)["completeness"] == "checked_against_anchor"
    body_b = _verify(api, hb)
    assert body_b["completeness"] == "not_checked" and body_b["anchor"] is None
    _cut(a, 1)
    assert _verify(api, ha)["completeness"] == "contradicted_by_anchor"
    assert _verify(api, hb)["verified"] is True


def test_unauthenticated_is_still_401(api):  # noqa: F811
    assert api.get("/v1/ledger/verify", headers={"X-API-Key": "nb_bad"}).status_code == 401


# --- the shared chooser, directly: an unverifiable signature is never an anchor --------
def test_choose_anchor_refuses_wrong_key_and_missing_key(tmp_path):
    led = EvidenceLedger(tmp_path / "l.db")
    log = AttestationLog(tmp_path / "log.jsonl")
    key = SigningKey.generate()
    attest(led, key, log)
    recs = log.read()
    assert choose_anchor(recs, key.verifying).anchor is not None
    assert choose_anchor(recs, SigningKey.generate().verifying).anchor is None
    assert choose_anchor(recs, None).anchor is None
    assert choose_anchor(recs, key.verifying, torn=True).anchor is None


# --- CLI: art14 verify --attestations/--public-key --------------------------------------
def _cli_setup(tmp_path):
    from assurance.core import Actor, Evidence, Origin

    led = EvidenceLedger(tmp_path / "cli.db")
    for i in range(3):
        led.append(Evidence(kind="t.r", body={"n": i}, actor=Actor("a.p", "eng"),
                            origin=Origin("t")).seal(), subject="C")
    key = SigningKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_text(key.verifying.pem())
    log = AttestationLog(tmp_path / "log.jsonl")
    attest(led, key, log)
    return led, key, pub, log


def _run(led, *extra):
    return art14_cli.main(["--ledger", str(led.path), "verify", *extra])


def test_cli_verify_exit_codes(tmp_path, capsys):
    led, key, pub, log = _cli_setup(tmp_path)
    assert _run(led) == 0                                         # unchanged
    assert _run(led, "--attestations", str(log.path), "--public-key", str(pub)) == 0
    assert "completeness checked" in capsys.readouterr().out
    other = tmp_path / "other.pem"
    other.write_text(SigningKey.generate().verifying.pem())
    assert _run(led, "--attestations", str(log.path), "--public-key", str(other)) == 1
    db = sqlite3.connect(led.path)
    db.execute("DELETE FROM chain WHERE seq > 1")
    db.commit()
    db.close()
    assert _run(led, "--attestations", str(log.path), "--public-key", str(pub)) == 1
    assert _run(led, "--attestations", str(log.path)) == 2        # key required: usage error
    assert os.path.exists(log.path)
