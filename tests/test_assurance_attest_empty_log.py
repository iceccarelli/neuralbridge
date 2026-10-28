"""An attestation log with nothing in it must not verify.

Whoever can roll a ledger back can also delete or empty its attestation log. If that read
as a pass, deleting the witness would hide the rollback.
"""
from __future__ import annotations

import json

import pytest

from assurance.attest import VerifyingKey, verify_log
from assurance.attest.cli import main


@pytest.fixture()
def keys(tmp_path):
    out = tmp_path / "keys"
    out.mkdir()
    assert main(["keygen", "--out", str(out / "k.key"), "--public-out",
                 str(out / "k.pub")]) == 0
    return out / "k.pub"


def test_verify_log_of_no_records_is_not_ok(keys):
    verdict = verify_log([], VerifyingKey.from_file(keys))
    assert verdict.ok is False
    assert verdict.checked == 0
    assert any("no attestations" in p for p in verdict.problems)


@pytest.mark.parametrize("how", ["missing", "empty"])
def test_cli_verify_of_missing_or_empty_log_is_not_a_pass(keys, tmp_path, capsys, how):
    log = tmp_path / "att.log"
    if how == "empty":
        log.write_bytes(b"")
    rc = main(["verify", "--log", str(log), "--public-key", str(keys), "--json"])
    body = json.loads(capsys.readouterr().out)
    assert rc != 0
    assert body["ok"] is False
    assert body["checked"] == 0
