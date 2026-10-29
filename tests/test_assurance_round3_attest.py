"""Round-3 review of the attestation layer: a torn tail is damage for an export.

Each class pins one proved finding, with the reproduction that was run against the
committed code. The discriminating assertion is the one that fails when the guard
under it is removed (see the mutation table in HANDOFF.md).

M1  a hosted export must not anchor to a stale record when the log's newest record was cut off
M2  ``assurance attest verify`` must not say ok when the newest attestation is missing
L2  an unterminated but valid final line must not be glued to the next record
L3  a record the JSON parser accepts but ``int()`` cannot is a damaged log, not a traceback
L1  ``rotating`` is the operator's flag; a tenant request cannot turn the key guard off
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time

import pytest

from assurance.api import attest_routes, deps
from assurance.attest import (
    AttestationBasis,
    AttestationError,
    AttestationLog,
    HeadAttestation,
    SigningKey,
    attest,
)
from assurance.attest import attestation as att
from assurance.attest.cli import main as attest_cli
from assurance.evidence.ledger import EvidenceLedger

from .test_assurance_attest import _ledger, attest_env, client  # noqa: F401
from .test_assurance_attest_hardening import (
    _acct_log,
    _body,
    _declared,
    _mk_account,
    _tear,
)
from .test_assurance_export_api import _account, _read_sign, _signal, api  # noqa: F401

DECLARED = AttestationBasis.DECLARED_BY_HOLDER


def _two_record_log(tmp_path, name="a.jsonl"):
    key, log = SigningKey.generate(), AttestationLog(tmp_path / name)
    attest(_declared(3), key, log)
    attest(_declared(4, "b"), key, log)
    return key, log


def _cut_last_record(path, keep_bytes=25):
    """What a crash inside the last write leaves: the newest record, cut off."""
    raw = path.read_bytes()
    path.write_bytes(raw[:-keep_bytes])
    return raw


# ---------------------------------------------------------------------------
# M1. A hosted export is never anchored to a stale record because the newest was cut off
# ---------------------------------------------------------------------------
def _rewind_account_ledger(account, keep=1):
    db = sqlite3.connect(deps.tenant_ledger_path(account.id))
    db.execute("DELETE FROM chain WHERE seq > ?", (keep,))
    db.commit()
    db.close()


class TestAHostedExportRefusesATornLog:
    def _signed_twice(self, api):  # noqa: F811
        account, headers = _account("m1@example.de")
        _signal(api, headers, "T1")
        _read_sign(account)                       # attestation 1: one record
        _signal(api, headers, "T2")
        _signal(api, headers, "T3")
        _read_sign(account)                       # attestation 2: three records
        return account, headers

    def test_a_rewind_hidden_by_a_torn_newest_record_is_not_a_200_with_a_stale_anchor(
            self, api):  # noqa: F811
        # The reviewer's reproduction. With the log intact this is 409; with the newest
        # record cut off it used to be 200, anchored to attestation 1, no warning.
        account, headers = self._signed_twice(api)
        log = _acct_log(account)
        raw = log.path.read_bytes()
        _rewind_account_ledger(account, keep=1)
        assert api.get("/v1/cases/T1/export", headers=headers).status_code == 409   # control
        log.path.write_bytes(raw[:-25])
        r = api.get("/v1/cases/T1/export", headers=headers)
        assert r.status_code == 500, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "attestation_log_damaged"
        assert "unterminated" in detail["finding"]
        assert "anchor" not in r.json()                 # no bundle at all
        assert str(deps.tenant_ledger_path(account.id)) not in r.text
        assert ".jsonl" not in r.text

    def test_a_torn_log_with_nothing_rewound_is_refused_too(self, api):  # noqa: F811
        account, headers = self._signed_twice(api)
        _tear(_acct_log(account).path)                # junk after the last full record
        r = api.get("/v1/cases/T1/export", headers=headers)
        assert r.status_code == 500, r.text
        assert r.json()["detail"]["error"] == "attestation_log_damaged"

    def test_the_explicit_unanchored_export_still_works_and_says_it_has_no_anchor(
            self, api):  # noqa: F811
        account, headers = self._signed_twice(api)
        _cut_last_record(_acct_log(account).path)
        r = api.get("/v1/cases/T1/export?anchor=false", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json().get("anchor") is None

    def test_a_writer_that_is_mid_append_is_a_retryable_503_not_damage(
            self, api):  # noqa: F811
        account, headers = self._signed_twice(api)
        log = _acct_log(account)
        _cut_last_record(log.path)
        with log.locked():                            # a signer holds the lock: not debris
            r = api.get("/v1/cases/T1/export", headers=headers)
        assert r.status_code == 503, r.text
        assert r.json()["detail"]["error"] == "attestation_busy"
        assert r.headers["retry-after"] == "2"

    def test_a_write_that_finishes_inside_the_short_wait_is_exported_normally(
            self, api):  # noqa: F811
        account, headers = self._signed_twice(api)
        log = _acct_log(account)
        raw = log.path.read_bytes()
        log.path.write_bytes(raw[:-25])

        def finish():
            time.sleep(0.05)
            with log.path.open("ab") as handle:
                handle.write(raw[-25:])

        t = threading.Thread(target=finish)
        t.start()
        try:
            r = api.get("/v1/cases/T1/export", headers=headers)
        finally:
            t.join()
        assert r.status_code == 200, r.text
        assert r.json()["anchor"]["sequence"] == 2

    def test_get_log_still_tolerates_and_warns(self, api):  # noqa: F811
        account, headers = self._signed_twice(api)
        _cut_last_record(_acct_log(account).path)
        r = api.get("/v1/ledger/attest/log", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["count"] == 1
        assert any("unterminated" in w for w in r.json()["warnings"])

    def test_latest_anchor_itself_raises_rather_than_returning_a_stale_record(
            self, api):  # noqa: F811
        account, _ = self._signed_twice(api)
        _cut_last_record(_acct_log(account).path)
        principal = type("P", (), {"subject": account.id})()
        with pytest.raises(Exception) as exc:
            attest_routes.latest_anchor(principal)
        assert getattr(exc.value, "status_code", None) == 500


class TestAnOfflineExportRefusesATornLog:
    def test_anchor_and_require_anchor_raise_on_a_torn_tail(self, tmp_path):
        _, log = _two_record_log(tmp_path)
        _cut_last_record(log.path)
        assert [r.sequence for r in log.read()] == [1]        # read stays tolerant
        with pytest.raises(att.AttestationLogDamagedError, match="unterminated"):
            log.anchor(accept_declared=True)
        with pytest.raises(att.AttestationLogDamagedError, match="unterminated"):
            log.require_anchor()

    def test_a_complete_final_record_without_its_newline_still_anchors(self, tmp_path):
        _, log = _two_record_log(tmp_path)
        log.path.write_bytes(log.path.read_bytes().rstrip(b"\n"))
        assert log.require_anchor().sequence == 2

    def test_the_evidence_cli_will_not_anchor_to_a_torn_log(self, tmp_path, capsys):
        from assurance.evidence.cli import main as evidence_cli

        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(_ledger(tmp_path / "l.db", 3), key, log)
        attest(_ledger(tmp_path / "l.db", 3), key, log)
        _cut_last_record(log.path)
        pub = tmp_path / "k.pub"
        pub.write_text(key.verifying.pem())
        bundle = tmp_path / "b.json"
        bundle.write_text(json.dumps({"entries": []}))
        rc = evidence_cli(["verify", str(bundle), "--public-key", str(pub),
                           "--attestations", str(log.path)])
        assert rc == 2
        assert "unterminated" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# M2. `assurance attest verify` says not-ok when the newest attestation was cut off
# ---------------------------------------------------------------------------
class TestVerifyDoesNotPassACutOffLog:
    def _setup(self, tmp_path):
        led = _ledger(tmp_path / "l.db", 3)
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "log.jsonl")
        attest(led, key, log)
        attest(led, key, log)
        pub = tmp_path / "k.pub"
        pub.write_text(key.verifying.pem())
        return led, key, log, pub

    def test_json_is_not_ok_and_exit_is_the_torn_tail_code(self, tmp_path, capsys):
        _, _, log, pub = self._setup(tmp_path)
        assert attest_cli(["verify", "--log", str(log.path), "--public-key", str(pub),
                           "--json"]) == 0                                      # control
        capsys.readouterr()
        _cut_last_record(log.path)
        rc = attest_cli(["verify", "--log", str(log.path), "--public-key", str(pub), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 3
        assert out["ok"] is False
        assert out["torn_tail"] is True
        assert any("unterminated" in p for p in out["problems"])

    def test_text_output_says_so_and_exits_with_the_same_code(self, tmp_path, capsys):
        _, _, log, pub = self._setup(tmp_path)
        _cut_last_record(log.path)
        rc = attest_cli(["verify", "--log", str(log.path), "--public-key", str(pub),
                         "--ledger", str(tmp_path / "l.db")])
        out = capsys.readouterr().out
        assert rc == 3
        assert "unterminated" in out
        assert "problem" in out.splitlines()[0]          # the headline is not 'verify'

    def test_a_real_finding_keeps_exit_1_even_when_the_tail_is_torn(self, tmp_path, capsys):
        led, _, log, pub = self._setup(tmp_path)
        db = sqlite3.connect(tmp_path / "l.db")
        db.execute("DELETE FROM chain WHERE seq > 1")
        db.commit()
        db.close()
        _cut_last_record(log.path)
        rc = attest_cli(["verify", "--log", str(log.path), "--public-key", str(pub),
                         "--ledger", str(tmp_path / "l.db"), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 1 and out["ok"] is False and out["torn_tail"] is True

    def test_the_reviewers_rewind_hidden_by_a_torn_tail_no_longer_exits_0(self, tmp_path, capsys):
        led, _, log, pub = self._setup(tmp_path)
        # attacker: rewinds the ledger to what attestation 1 signed, cuts attestation 2
        led2 = EvidenceLedger(tmp_path / "l.db")
        assert len(led2.entries()) == 3
        _cut_last_record(log.path, keep_bytes=30)
        rc = attest_cli(["verify", "--log", str(log.path), "--public-key", str(pub),
                         "--ledger", str(tmp_path / "l.db")])
        capsys.readouterr()
        assert rc != 0

    def test_a_clean_log_still_exits_0(self, tmp_path, capsys):
        _, _, log, pub = self._setup(tmp_path)
        assert attest_cli(["verify", "--log", str(log.path), "--public-key", str(pub),
                           "--ledger", str(tmp_path / "l.db")]) == 0
        capsys.readouterr()

    def test_signing_onto_a_torn_log_has_the_same_distinct_code(self, tmp_path, capsys):
        led, key, log, _ = self._setup(tmp_path)
        _cut_last_record(log.path)
        keyfile = tmp_path / "secrets" / "k.pem"
        key.save(keyfile)
        rc = attest_cli(["sign", "--ledger", str(tmp_path / "l.db"), "--key", str(keyfile),
                         "--log", str(log.path)])
        assert rc == 3
        assert "unterminated" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# L2. An unterminated but valid final line is not glued to the next record
# ---------------------------------------------------------------------------
class TestAppendNeverGluesOntoAnUnterminatedLine:
    def test_signing_after_a_missing_final_newline_keeps_the_log_readable(self, tmp_path):
        key, log = _two_record_log(tmp_path)
        log.path.write_bytes(log.path.read_bytes()[:-1])     # remove only the final newline
        record = attest(_declared(5, "c"), key, log)
        assert record.sequence == 3
        assert log.path.read_bytes().endswith(b"\n")
        records = log.read()                                 # used to raise: lines glued
        assert [r.sequence for r in records] == [1, 2, 3]
        assert att.verify_log(records, key.verifying).ok
        assert len(log.path.read_bytes().splitlines()) == 3  # one record per line

    def test_append_itself_repairs_rather_than_relying_on_its_caller(self, tmp_path):
        key, log = _two_record_log(tmp_path)
        records = log.read()
        log.path.write_bytes(log.path.read_bytes()[:-1])
        nxt = att.replace(
            records[-1], sequence=3, previous=records[-1].content_hash(), signature="")
        nxt = att.replace(nxt, signature=_sign(key, nxt))
        log.append(nxt)
        assert [r.sequence for r in log.read()] == [1, 2, 3]

    def test_an_unparseable_unterminated_tail_is_still_refused_by_append(self, tmp_path):
        key, log = _two_record_log(tmp_path)
        records = log.read()
        _tear(log.path)
        before = log.path.read_bytes()
        with pytest.raises(att.AttestationLogDamagedError):
            log.append(records[-1])
        assert log.path.read_bytes() == before                # evidence left as found

    def test_the_api_signs_after_a_missing_final_newline(self, client, attest_env):  # noqa: F811
        acct, headers = _mk_account(attest_env)
        assert client.post("/v1/ledger/attest", json=_body(4), headers=headers).status_code == 200
        path = _acct_log(acct).path
        path.write_bytes(path.read_bytes()[:-1])
        r = client.post("/v1/ledger/attest", json=_body(5, "b"), headers=headers)
        assert r.status_code == 200, r.text
        assert client.get("/v1/ledger/attest/log", headers=headers).json()["count"] == 2


def _sign(key, record):
    import base64

    return base64.b64encode(key.sign(record.signed_payload())).decode("ascii")


# ---------------------------------------------------------------------------
# L3. A number the JSON parser accepts and int() cannot is a damaged log
# ---------------------------------------------------------------------------
REC = {"format": "assurance.head-attestation.v1", "sequence": 1, "ledger_length": 1,
       "head_seq": 1, "head_link_hash": "a" * 64, "basis": "declared_by_holder",
       "attested_at": "2026-10-01T00:00:00Z", "key_fingerprint": "x", "previous": "",
       "signature": ""}


def _overflow_line() -> str:
    line = json.dumps(REC).replace('"sequence": 1', '"sequence": 1e999')
    assert "1e999" in line
    return line


class TestAnOverflowingNumberIsADamagedLogNotATraceback:
    def test_from_dict_raises_an_attestation_error(self):
        with pytest.raises(AttestationError):
            HeadAttestation.from_dict({**REC, "sequence": float("inf")})

    def test_read_raises_the_log_damaged_error(self, tmp_path):
        path = tmp_path / "x.jsonl"
        path.write_text(_overflow_line() + "\n")
        with pytest.raises(att.AttestationLogDamagedError):
            AttestationLog(path).read()

    def test_a_deeply_nested_line_is_damage_too(self, tmp_path):
        path = tmp_path / "x.jsonl"
        path.write_text("[" * 200_000 + "\n")
        with pytest.raises(att.AttestationLogDamagedError):
            AttestationLog(path).read()

    def test_get_log_post_and_a_hosted_export_answer_500_log_damaged(self, api):  # noqa: F811
        account, headers = _account("l3@example.de")
        _signal(api, headers, "T1")
        _read_sign(account)
        path = _acct_log(account).path
        path.write_text(path.read_text() + _overflow_line() + "\n")
        for r in (api.get("/v1/ledger/attest/log", headers=headers),
                  api.post("/v1/ledger/attest", json=_body(3), headers=headers),
                  api.get("/v1/cases/T1/export", headers=headers)):
            assert r.status_code == 500, r.text
            assert r.json()["detail"]["error"] == "attestation_log_damaged"

    def test_the_cli_reports_it_without_a_traceback(self, tmp_path, capsys):
        path = tmp_path / "x.jsonl"
        path.write_text(_overflow_line() + "\n")
        pub = tmp_path / "k.pub"
        pub.write_text(SigningKey.generate().verifying.pem())
        for argv in (["verify", "--log", str(path), "--public-key", str(pub)],
                     ["log", "--log", str(path)]):
            assert attest_cli(argv) == 1
            assert "finding:" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# L1. `rotating` belongs to the operator CLI
# ---------------------------------------------------------------------------
class TestATenantCannotSwitchOffTheKeyGuard:
    def test_the_request_model_has_no_rotating_field(self):
        assert "rotating" not in attest_routes.AttestIn.model_fields

    def test_rotating_in_a_request_is_refused_and_signs_nothing(
            self, client, attest_env, monkeypatch):  # noqa: F811
        acct, headers = _mk_account(attest_env)
        assert client.post("/v1/ledger/attest", json=_body(3, "a"), headers=headers).status_code == 200
        k2 = attest_env / "k2.pem"
        SigningKey.generate().save(k2)
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(k2))
        before = _acct_log(acct).path.read_bytes()
        r = client.post("/v1/ledger/attest", json=_body(3, "a", rotating=True), headers=headers)
        assert r.status_code == 422, r.text
        assert _acct_log(acct).path.read_bytes() == before
        r = client.post("/v1/ledger/attest", json=_body(3, "a"), headers=headers)
        assert r.status_code == 409                          # still the key guard
        assert len({x.key_fingerprint for x in _acct_log(acct).read()}) == 1

    def test_the_operator_cli_can_still_rotate(self, tmp_path, capsys):
        led = _ledger(tmp_path / "l.db", 2)
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, SigningKey.generate(), log)
        second = tmp_path / "second.pem"
        SigningKey.generate().save(second)
        base = ["sign", "--ledger", str(tmp_path / "l.db"), "--key", str(second),
                "--log", str(log.path)]
        assert attest_cli(base) == 1
        assert attest_cli([*base, "--rotating"]) == 0
        capsys.readouterr()
