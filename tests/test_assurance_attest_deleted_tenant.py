"""A tenant an operator deleted is gone from the attestation store too.

``tenant delete --execute`` leaves ``<acc>.deleted`` beside the removed ledger and every
register route answers 410 (``deps.get_register``). The attestation log lives elsewhere
(``ASSURANCE_ATTEST_LOGS``) and ``_log_for`` did not look at the marker: ``GET
/v1/ledger/attest/log`` still answered 200 with the account's records, and ``POST
/v1/ledger/attest`` could write to (re-create) the log. Both now answer the same 410.
"""

from __future__ import annotations

import json
from pathlib import Path

from assurance.api import deps

from .test_assurance_export_api import _account, api  # noqa: F401


def _head(n: int = 3) -> dict:
    return {"ledger_length": n, "head_seq": n, "head_link_hash": "a" * 64}


def _mark_deleted(account_id: str) -> Path:
    marker = deps.tenant_ledger_path(account_id).with_suffix(".deleted")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"deleted_at": "2026-10-01T00:00:00Z"}), encoding="utf-8")
    return marker


def _log_files(api) -> list[Path]:  # noqa: F811
    import os

    root = Path(os.environ["ASSURANCE_ATTEST_LOGS"])
    return sorted(root.glob("*")) if root.exists() else []


def test_attest_log_is_410_once_the_account_is_deleted(api):  # noqa: F811
    account, headers = _account("gone@example.de")
    assert api.post("/v1/ledger/attest", json=_head(), headers=headers).status_code == 200
    assert api.get("/v1/ledger/attest/log", headers=headers).status_code == 200
    _mark_deleted(account.id)
    r = api.get("/v1/ledger/attest/log", headers=headers)
    assert r.status_code == 410
    assert r.json()["detail"]["error"] == "account_data_deleted"
    assert "records" not in json.dumps(r.json())


def test_attest_post_cannot_recreate_the_log_of_a_deleted_account(api):  # noqa: F811
    account, headers = _account("gone2@example.de")
    _mark_deleted(account.id)
    before = _log_files(api)
    r = api.post("/v1/ledger/attest", json=_head(), headers=headers)
    assert r.status_code == 410
    assert r.json()["detail"]["error"] == "account_data_deleted"
    assert _log_files(api) == before == []


def test_other_accounts_and_the_operator_are_unaffected(api):  # noqa: F811
    gone, _ = _account("gone3@example.de")
    _, live = _account("live@example.de")
    _mark_deleted(gone.id)
    assert api.post("/v1/ledger/attest", json=_head(), headers=live).status_code == 200
    assert api.get("/v1/ledger/attest/log", headers=live).status_code == 200


def test_register_and_attest_agree_on_the_marker(api):  # noqa: F811
    account, headers = _account("gone4@example.de")
    _mark_deleted(account.id)
    assert api.get("/v1/cases", headers=headers).status_code == 410
    assert api.get("/v1/ledger/attest/log", headers=headers).status_code == 410
