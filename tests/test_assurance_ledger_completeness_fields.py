"""What a passing chain walk does NOT show, said in the result itself.

An adversarial review found that ``verify_chain`` / ``GET /v1/ledger/verify`` returned a plain
``verified: true`` after the newest records were deleted, with nothing in the response saying
completeness was never compared with anything; that a file copy of a ledger can be written to
twice with both copies verifying (no lineage id); and that ``backup`` of an already-damaged
source reported ok.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from assurance.api.deps import tenant_ledger_path
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger, restore_check

from .test_assurance_export_api import _account, api  # noqa: F401  (fixture)
from .test_assurance_restore_manifest import data  # noqa: F401  (fixture)


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


def _cut(path: Path, keep: int) -> None:
    db = sqlite3.connect(path)
    db.execute("DELETE FROM chain WHERE seq > ?", (keep,))
    db.commit()
    db.close()


def _ledger(tmp_path, n=5, name="a.db"):
    led = EvidenceLedger(tmp_path / name)
    for i in range(n):
        led.append(_ev(i), subject="CASE-1")
    return led


# --- (1) completeness is stated, not implied ---------------------------------------------
def test_a_truncated_chain_verifies_but_says_completeness_was_not_checked(tmp_path):
    led = _ledger(tmp_path)
    _cut(led.path, 3)
    assert led.verify_chain() == (True, [])          # existing contract unchanged
    rep = led.verify_report()
    assert rep["verified"] is True and rep["completeness"] == "not_checked"
    assert any("does not detect deletion" in s for s in rep["not_checked"])


def test_a_signed_head_turns_truncation_into_a_contradiction(tmp_path):
    led = _ledger(tmp_path)
    anchor = {"ledger_length": 5, "head_seq": 5, "attested_at": "t",
              "head_link_hash": led.entries()[-1].link_hash}
    assert led.verify_report(anchor=anchor)["completeness"] == "checked_against_anchor"
    _cut(led.path, 3)
    rep = led.verify_report(anchor=anchor)
    assert rep["completeness"] == "contradicted_by_anchor" and rep["verified"] is False
    assert rep["problems"]


def test_the_http_verify_response_carries_the_unchecked_fields(api):  # noqa: F811
    _row, headers = _account("c@x.invalid")
    r = api.get("/v1/ledger/verify", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True and body["completeness"] == "not_checked"
    assert body["not_checked"] and "attestation" in body and body["ledger_id"]


# --- (2) lineage ids ---------------------------------------------------------------------
def test_a_new_ledger_gets_a_random_id_and_keeps_it(tmp_path):
    a, b = _ledger(tmp_path, name="a.db"), _ledger(tmp_path, name="b.db")
    assert a.ledger_id() and a.ledger_id() != b.ledger_id()
    assert EvidenceLedger(a.path).ledger_id() == a.ledger_id()


def test_an_existing_ledger_gets_an_id_without_touching_the_chain(tmp_path):
    led = _ledger(tmp_path)
    before = [(e.seq, e.link_hash) for e in led.entries()]
    db = sqlite3.connect(led.path)
    db.execute("DELETE FROM meta WHERE key = 'ledger_id'")
    db.commit()
    db.close()
    assert EvidenceLedger(led.path, mint_id=False).ledger_id() is None
    reopened = EvidenceLedger(led.path)
    assert reopened.ledger_id()
    assert [(e.seq, e.link_hash) for e in reopened.entries()] == before
    assert reopened.verify_chain() == (True, [])


def test_the_manifest_and_the_verify_report_name_the_ledger(data, tmp_path):  # noqa: F811
    root, first, _ = data
    led = EvidenceLedger(tenant_ledger_path(first))
    assert led.verify_report()["ledger_id"] == led.ledger_id()
    # the export bundle is deliberately unchanged: verify_export rejects unknown top-level fields
    assert "ledger_id" not in led.export()
    out = tmp_path / "bk"
    restore_check.backup(root, out)
    entry = json.loads((out / "backup-manifest.json").read_text())["files"][f"tenants/{first}.db"]
    assert entry["ledger_id"] == led.ledger_id()


def test_restore_flags_a_ledger_that_forked_from_one_the_live_volume_holds(data, tmp_path):  # noqa: F811
    root, first, _ = data
    bk = tmp_path / "bk"
    restore_check.backup(root, bk)
    restored = tmp_path / "restored"
    shutil.copytree(bk, restored)
    # both copies are written to afterwards: two writable lineages from one file
    EvidenceLedger(tenant_ledger_path(first)).append(_ev(100), subject="CASE-1")
    EvidenceLedger(restored / "tenants" / f"{first}.db", mint_id=False).append(
        _ev(200), subject="CASE-1")
    res = restore_check.verify(restored, live_dir=root)
    assert any("forked" in p and "ledger_id" in p for p in res["problems"]), res["problems"]
    assert res["ok"] is False


def test_a_restore_that_is_merely_behind_the_live_volume_is_not_a_fork(data, tmp_path):  # noqa: F811
    root, first, _ = data
    bk = tmp_path / "bk"
    restore_check.backup(root, bk)
    EvidenceLedger(tenant_ledger_path(first)).append(_ev(100), subject="CASE-1")
    res = restore_check.verify(bk, live_dir=root)
    assert not any("forked" in p for p in res["problems"])


def test_a_replaced_ledger_is_not_a_grown_one(data, tmp_path):  # noqa: F811
    root, first, _ = data
    bk = tmp_path / "bk"
    restore_check.backup(root, bk)
    db = sqlite3.connect(root / "tenants" / f"{first}.db")
    db.execute("UPDATE meta SET value = 'someoneelse' WHERE key = 'ledger_id'")
    db.commit()
    db.close()
    shutil.copy(bk / "backup-manifest.json", root / "backup-manifest.json")
    res = restore_check.verify(root, allow_growth=True)
    assert any("different ledger" in p for p in res["problems"]), res["problems"]


# --- (5) backup of a damaged source ------------------------------------------------------
def test_backup_of_a_source_truncated_below_its_attestation_is_degraded(data, tmp_path):  # noqa: F811
    root, first, _ = data
    _cut(root / "tenants" / f"{first}.db", 2)
    out = tmp_path / "bk"
    restore_check.backup(root, out)
    manifest = json.loads((out / "backup-manifest.json").read_text())
    assert manifest["degraded"] is True and manifest["source_findings"]
    res = restore_check.verify(out)
    assert res["ok"] is False and any("damaged source" in p for p in res["problems"])


def test_backup_of_a_source_with_a_broken_chain_is_degraded(data, tmp_path):  # noqa: F811
    root, _, second = data
    db = sqlite3.connect(root / "tenants" / f"{second}.db")
    db.execute("DELETE FROM chain WHERE seq = 2")
    db.commit()
    db.close()
    out = tmp_path / "bk"
    restore_check.backup(root, out)
    assert json.loads((out / "backup-manifest.json").read_text())["degraded"] is True
    assert restore_check.verify(out)["status"] == "failed"


def test_a_healthy_backup_is_not_degraded_and_exits_zero(data, tmp_path):  # noqa: F811
    root, _, _ = data
    out = tmp_path / "bk"
    assert restore_check.main(["backup", str(root), str(out)]) == 0
    assert json.loads((out / "backup-manifest.json").read_text())["degraded"] is False


def test_a_ledger_with_no_attestation_log_is_listed_as_not_shown_complete(data, tmp_path):  # noqa: F811
    root, first, second = data
    out = tmp_path / "bk"
    restore_check.backup(root, out)
    text = " ".join(restore_check.verify(out)["not_established"])
    assert "cannot be shown complete" in text and second in text and first not in text


def test_a_degraded_backup_cli_exits_one(data, tmp_path):  # noqa: F811
    root, first, _ = data
    _cut(root / "tenants" / f"{first}.db", 2)
    assert restore_check.main(["backup", str(root), str(tmp_path / "bk")]) == 1
