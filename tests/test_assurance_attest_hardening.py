"""The attestation layer under review: bases, locks, torn files, anchors, notes.

Each class pins one finding from the review of the attestation layer, with the
reproduction that was run against the committed code. The discriminating
assertion is the one that fails when the guard under it is removed.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from assurance.api import attest_routes, deps
from assurance.attest import (
    AttestationBasis,
    AttestationError,
    AttestationLog,
    HeadAttestation,
    LedgerHead,
    SigningKey,
    attest,
    verify_log,
)
from assurance.attest import attestation as att
from assurance.cli import main as cli_main
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger

from .test_assurance_attest import OPERATOR_KEY, _ledger, attest_env, client  # noqa: F401
from .test_assurance_export_api import _account, _signal, api, tenants  # noqa: F401

DECLARED = AttestationBasis.DECLARED_BY_HOLDER
READ = AttestationBasis.READ_FROM_LEDGER


def _hex(c: str) -> str:
    return (c * 64)[:64]


def _declared(n: int, seed: str = "a") -> LedgerHead:
    return LedgerHead(length=n, head_seq=n, head_link_hash=_hex(seed), basis=DECLARED)


def _body(n: int, seed: str = "a", **extra) -> dict:
    return {"ledger_length": n, "head_seq": n, "head_link_hash": _hex(seed), **extra}


def _sign_by_hand(key, records, *, length, basis, head_seq=None, link="b"):
    """Append a record the way a signer that skipped attest()'s checks could."""
    previous = records[-1] if records else None
    rec = HeadAttestation(
        format=att.ATTESTATION_FORMAT, sequence=len(records) + 1, ledger_length=length,
        head_seq=length if head_seq is None else head_seq, head_link_hash=_hex(link),
        basis=basis, attested_at="2026-10-01T00:00:00Z", key_fingerprint=key.fingerprint,
        previous=previous.content_hash() if previous else "")
    return [*records, replace(rec, signature=base64.b64encode(
        key.sign(rec.signed_payload())).decode("ascii"))]


def _mk_account(attest_env, email="a@b.de", tier="cell"):  # noqa: F811
    from assurance.billing.accounts import AccountStore

    store = AccountStore(str(attest_env / "accounts.db"))
    acct = store.upsert_account(email=email, tier=tier, stripe_customer_id="cus_" + email)
    return acct, {"X-API-Key": store.issue_key(acct.id)}


def _acct_log(acct) -> AttestationLog:
    return attest_routes._log_for(SimpleNamespace(subject=acct.id))


HOLDER = (
    "import fcntl, sys, time\n"
    "f = open(sys.argv[1], 'a+'); fcntl.flock(f, fcntl.LOCK_EX)\n"
    "print('held', flush=True); time.sleep(float(sys.argv[2]))\n"
)


def _hold(lockfile: Path, seconds: float) -> subprocess.Popen:
    lockfile.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(  # noqa: S603 - our own interpreter, our own script
        [sys.executable, "-c", HOLDER, str(lockfile), str(seconds)],
        stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "held"
    return proc


# ---------------------------------------------------------------------------
# 1. One per-account log, two bases (B-F5, C-H2, A-M5)
# ---------------------------------------------------------------------------
class TestTwoBasesInOneLog:
    def test_a_read_attestation_after_a_declared_one_is_accepted(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(10**6), key, log)                 # the tenant's own, long ledger
        hosted = _ledger(tmp_path / "hosted.db", 4)        # the hosted ledger, 4 records
        record = attest(hosted, key, log)
        assert record.sequence == 2 and record.basis is READ

    def test_a_declared_head_after_a_read_one_is_not_a_removal(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_ledger(tmp_path / "hosted.db", 50), key, log)       # hosted: 50
        record = attest(_declared(30), key, log)                     # theirs: 30
        assert record.sequence == 2 and record.basis is DECLARED

    def test_declared_heads_still_cannot_go_backwards_among_themselves(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(30), key, log)
        attest(_ledger(tmp_path / "hosted.db", 50), key, log)
        with pytest.raises(AttestationError, match="does not get shorter"):
            attest(_declared(20), key, log)

    def test_read_heads_still_cannot_go_backwards_after_a_declared_one(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        path = tmp_path / "hosted.db"
        attest(_ledger(path, 4), key, log)
        attest(_declared(10**6), key, log)
        import sqlite3

        db = sqlite3.connect(path)
        db.execute("DELETE FROM chain WHERE seq > 2")
        db.commit()
        db.close()
        with pytest.raises(AttestationError, match="does not get shorter"):
            attest(EvidenceLedger(path), key, log)

    def test_a_fork_is_checked_against_the_same_basis_only(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        hosted = _ledger(tmp_path / "hosted.db", 4)
        attest(hosted, key, log)
        # A declared head at seq 4 with another link: it is about another ledger.
        attest(_declared(4, "c"), key, log)
        assert attest(hosted, key, log).sequence == 3      # hosted still resolves

    def test_the_key_check_spans_both_bases(self, tmp_path):
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(3), SigningKey.generate(), log)
        with pytest.raises(AttestationError, match="rotation"):
            attest(_ledger(tmp_path / "hosted.db", 4), SigningKey.generate(), log)

    def test_the_hash_chain_spans_both_bases(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(3), key, log)
        attest(_ledger(tmp_path / "hosted.db", 4), key, log)
        attest(_declared(5), key, log)
        records = log.read()
        assert verify_log(records, key.verifying).ok
        assert [r.sequence for r in records] == [1, 2, 3]

    def test_verifying_a_mixed_log_does_not_call_a_basis_switch_a_shortening(self, tmp_path):
        key = SigningKey.generate()
        records = _sign_by_hand(key, [], length=10**6, basis=DECLARED)
        records = _sign_by_hand(key, records, length=4, basis=READ)
        verdict = verify_log(records, key.verifying)
        assert verdict.ok, verdict.problems

    def test_a_shortening_within_one_basis_is_still_found_by_verification(self, tmp_path):
        key = SigningKey.generate()
        records = _sign_by_hand(key, [], length=9, basis=READ)
        records = _sign_by_hand(key, records, length=100, basis=DECLARED)
        records = _sign_by_hand(key, records, length=5, basis=READ)
        verdict = verify_log(records, key.verifying)
        assert any("shortened" in p for p in verdict.problems)

    def test_joining_a_ledger_checks_only_the_records_that_describe_it(self, tmp_path):
        """A declared head describes the customer's ledger; against the hosted one it
        would read as 999996 removed records."""
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        hosted = _ledger(tmp_path / "hosted.db", 4)
        attest(_declared(10**6), key, log)
        attest(hosted, key, log)
        verdict = verify_log(log.read(), key.verifying, ledger=hosted)
        assert verdict.ok, verdict.problems
        assert any("describe a different ledger" in s for s in verdict.checks_skipped)

    def test_joining_a_ledger_still_finds_a_rewind_of_the_read_records(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        path = tmp_path / "hosted.db"
        attest(_ledger(path, 4), key, log)
        attest(_declared(7), key, log)
        import sqlite3

        db = sqlite3.connect(path)
        db.execute("DELETE FROM chain WHERE seq > 2")
        db.commit()
        db.close()
        verdict = verify_log(log.read(), key.verifying, ledger=EvidenceLedger(path))
        assert any("were removed after being attested" in p for p in verdict.problems)


class TestDeclaredHeadsAreBounded:
    def test_an_inflated_length_is_a_422_not_a_poisoned_log(self, client, attest_env):  # noqa: F811
        r = client.post("/v1/ledger/attest", json=_body(10**9),
                        headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 422
        assert not (attest_env / "attestations").exists() or not list(
            (attest_env / "attestations").glob("*.jsonl"))

    def test_an_inflated_length_alone_is_a_422(self, client):  # noqa: F811
        body = {"ledger_length": 10**9, "head_seq": 5, "head_link_hash": _hex("a")}
        r = client.post("/v1/ledger/attest", json=body, headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 422

    def test_an_inflated_head_seq_is_a_422(self, client):  # noqa: F811
        body = {"ledger_length": 5, "head_seq": 10**9, "head_link_hash": _hex("a")}
        r = client.post("/v1/ledger/attest", json=body, headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 422

    def test_the_bound_itself_is_accepted_and_one_past_it_is_not(self, client):  # noqa: F811
        top = attest_routes.MAX_DECLARED_LEDGER
        ok = client.post("/v1/ledger/attest", json=_body(top),
                         headers={"X-API-Key": OPERATOR_KEY})
        assert ok.status_code == 200
        over = client.post("/v1/ledger/attest", json=_body(top + 1),
                           headers={"X-API-Key": OPERATOR_KEY})
        assert over.status_code == 422

    def test_a_tenant_at_the_bound_does_not_stop_hosted_signing(self, client, tmp_path):  # noqa: F811
        top = attest_routes.MAX_DECLARED_LEDGER
        r = client.post("/v1/ledger/attest", json=_body(top),
                        headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 200
        log = attest_routes._log_for(SimpleNamespace(subject="operator"))
        key = SigningKey.generate()
        key_path = Path(os.environ["ASSURANCE_ATTEST_KEY"])
        key = SigningKey.load(key_path)
        assert attest(_ledger(tmp_path / "h.db", 4), key, log).basis is READ

    def test_a_customer_is_not_told_records_were_removed(self, client, attest_env):  # noqa: F811
        acct, headers = _mk_account(attest_env)
        key = SigningKey.load(os.environ["ASSURANCE_ATTEST_KEY"])
        attest(_ledger(attest_env / "hosted.db", 50), key, _acct_log(acct))
        r = client.post("/v1/ledger/attest", json=_body(30), headers=headers)
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# 2. Event-loop stall and the lock deadline (B-F3)
# ---------------------------------------------------------------------------
class TestTheLockHasADeadline:
    def test_a_foreign_lock_holder_makes_locked_raise_busy_not_wait_forever(self, tmp_path):
        log = AttestationLog(tmp_path / "a.jsonl")
        holder = _hold(Path(os.path.realpath(log.path) + ".lock"), 3)
        try:
            t0 = time.monotonic()
            with pytest.raises(att.AttestationBusyError):
                with log.locked(timeout=0.4):
                    pass
            assert time.monotonic() - t0 < 2.0
        finally:
            holder.kill()
            holder.wait()

    def test_a_busy_lock_is_not_an_attestation_finding(self):
        assert not issubclass(att.AttestationBusyError, AttestationError)

    def test_a_thread_holding_the_lock_makes_a_second_locked_raise_busy(self, tmp_path):
        log = AttestationLog(tmp_path / "a.jsonl")
        with log.locked():
            with pytest.raises(att.AttestationBusyError):
                with log.locked(timeout=0.3):
                    pass

    def test_the_deadline_is_documented_and_short(self):
        assert 1 <= att.LOCK_TIMEOUT_SECONDS <= 30

    def test_the_event_loop_keeps_running_and_the_caller_gets_503_retry_after(
            self, attest_env, monkeypatch):  # noqa: F811
        monkeypatch.setattr(att, "LOCK_TIMEOUT_SECONDS", 1.5)
        service = importlib.import_module("assurance.api.service")
        app = service.create_app()
        acct, headers = _mk_account(attest_env)
        holder = _hold(Path(os.path.realpath(_acct_log(acct).path) + ".lock"), 5)

        async def main():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                pending = asyncio.create_task(
                    c.post("/v1/ledger/attest", json=_body(4), headers=headers))
                await asyncio.sleep(0)            # let the request reach the lock
                t = time.monotonic()
                await asyncio.sleep(0.3)
                slept = time.monotonic() - t
                health = await asyncio.wait_for(c.get("/healthz"), timeout=20)
                return slept, health.status_code, await pending

        try:
            slept, health, response = asyncio.run(main())
        finally:
            holder.kill()
            holder.wait()
        assert slept < 0.9, f"asyncio.sleep(0.3) took {slept:.2f}s: the loop was blocked"
        assert health == 200
        assert response.status_code == 503, response.text
        assert response.json()["detail"]["error"] == "attestation_busy"
        assert int(response.headers["retry-after"]) >= 1

    def test_the_handler_runs_in_the_threadpool(self):
        import inspect

        assert not inspect.iscoroutinefunction(attest_routes.counter_sign)

    def test_reading_the_log_never_waits_for_the_writer_lock(self, attest_env, monkeypatch):  # noqa: F811
        """GET /log and the export anchor read without the lock, so they never wait."""
        service = importlib.import_module("assurance.api.service")
        acct, headers = _mk_account(attest_env)
        holder = _hold(Path(os.path.realpath(_acct_log(acct).path) + ".lock"), 3)
        try:
            with TestClient(service.create_app()) as c:
                t = time.monotonic()
                r = c.get("/v1/ledger/attest/log", headers=headers)
                assert r.status_code == 200 and time.monotonic() - t < 2.0
        finally:
            holder.kill()
            holder.wait()


# ---------------------------------------------------------------------------
# 3. Torn tail, unlocked readers, path leaks (B-F11, A-L8b)
# ---------------------------------------------------------------------------
def _tear(path: Path) -> None:
    data = path.read_bytes()
    path.write_bytes(data + data[:80])           # a crash mid-append: no newline


class TestATornTail:
    def _log_with_two(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(3), key, log)
        attest(_declared(4, "b"), key, log)
        return key, log

    def test_reading_ignores_an_unterminated_unparseable_final_line(self, tmp_path):
        _, log = self._log_with_two(tmp_path)
        _tear(log.path)
        assert [r.sequence for r in log.read()] == [1, 2]
        assert log.has_torn_tail()

    def test_a_complete_final_record_without_its_newline_is_still_a_record(self, tmp_path):
        _, log = self._log_with_two(tmp_path)
        log.path.write_bytes(log.path.read_bytes().rstrip(b"\n"))
        assert [r.sequence for r in log.read()] == [1, 2]
        assert not log.has_torn_tail()

    def test_a_damaged_line_in_the_middle_is_still_an_error(self, tmp_path):
        _, log = self._log_with_two(tmp_path)
        lines = log.path.read_bytes().splitlines()
        log.path.write_bytes(lines[0][:40] + b"\n" + lines[1] + b"\n")
        with pytest.raises(att.AttestationLogDamagedError):
            log.read()

    def test_a_terminated_unparseable_final_line_is_an_error_not_a_torn_tail(self, tmp_path):
        _, log = self._log_with_two(tmp_path)
        with log.path.open("ab") as handle:
            handle.write(b"{not json}\n")
        with pytest.raises(att.AttestationLogDamagedError):
            log.read()

    def test_a_reader_racing_a_half_written_append_sees_the_earlier_records(self, tmp_path):
        key, log = self._log_with_two(tmp_path)
        line = log.path.read_bytes().splitlines()[-1]
        started, resume = threading.Event(), threading.Event()

        def writer():
            with log.path.open("ab") as handle:
                handle.write(line[:60])
                handle.flush()
                started.set()
                resume.wait(5)
                handle.write(line[60:] + b"\n")

        t = threading.Thread(target=writer)
        t.start()
        started.wait(5)
        try:
            assert [r.sequence for r in log.read()] == [1, 2]
        finally:
            resume.set()
            t.join()

    def test_signing_onto_a_torn_tail_is_refused_not_merged_into_it(self, tmp_path):
        key, log = self._log_with_two(tmp_path)
        _tear(log.path)
        before = log.path.read_bytes()
        with pytest.raises(att.AttestationLogDamagedError):
            attest(_declared(9, "c"), key, log)
        assert log.path.read_bytes() == before

    def test_api_post_on_a_torn_tail_is_500_log_damaged_not_a_409_refusal(
            self, client, attest_env):  # noqa: F811
        acct, headers = _mk_account(attest_env)
        assert client.post("/v1/ledger/attest", json=_body(4), headers=headers).status_code == 200
        _tear(_acct_log(acct).path)
        r = client.post("/v1/ledger/attest", json=_body(5, "b"), headers=headers)
        assert r.status_code == 500, r.text
        assert r.json()["detail"]["error"] == "attestation_log_damaged"
        assert str(attest_env) not in r.text

    def test_get_log_answers_200_with_the_good_records_and_says_the_tail_is_torn(
            self, client, attest_env):  # noqa: F811
        acct, headers = _mk_account(attest_env)
        client.post("/v1/ledger/attest", json=_body(4), headers=headers)
        _tear(_acct_log(acct).path)
        r = client.get("/v1/ledger/attest/log", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["count"] == 1
        assert any("unterminated" in w for w in body["warnings"])
        assert str(attest_env) not in r.text

    def test_a_default_export_survives_a_torn_tail(self, tenants):  # noqa: F811
        web, (a, ha), _, anchor = tenants
        _tear(_acct_log(a).path)
        r = web.get("/v1/cases/C1/export", headers=ha)
        assert r.status_code == 200, r.text
        assert r.json()["anchor"]["sequence"] == anchor["sequence"]

    def test_a_middle_line_damage_does_not_leak_the_server_path(self, client, attest_env):  # noqa: F811
        acct, headers = _mk_account(attest_env)
        for n in (4, 5):
            client.post("/v1/ledger/attest", json=_body(n, "b"), headers=headers)
        path = _acct_log(acct).path
        lines = path.read_bytes().splitlines()
        path.write_bytes(b"garbage\n" + lines[1] + b"\n")
        for r in (client.get("/v1/ledger/attest/log", headers=headers),
                  client.post("/v1/ledger/attest", json=_body(6, "c"), headers=headers)):
            assert r.status_code == 500, r.text
            assert r.json()["detail"]["error"] == "attestation_log_damaged"
            assert str(attest_env) not in r.text and ".jsonl" not in r.text

    def test_the_key_endpoint_does_not_leak_the_key_path(self, client, attest_env, monkeypatch):  # noqa: F811
        missing = attest_env / "secrets" / "gone.pem"
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(missing))
        r = client.get("/v1/ledger/attest/key")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "attestation_key_unusable"
        assert str(attest_env) not in r.text and "gone.pem" not in r.text

    def test_an_unreadable_key_file_does_not_leak_the_path_either(
            self, client, attest_env, monkeypatch):  # noqa: F811
        bad = attest_env / "secrets" / "bad.pem"
        bad.write_text("not a key")
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(bad))
        r = client.post("/v1/ledger/attest", json=_body(3), headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 503
        assert str(attest_env) not in r.text and "bad.pem" not in r.text

    def test_the_cli_still_names_the_path_it_was_given(self, tmp_path, capsys):
        log = AttestationLog(tmp_path / "a.jsonl")
        log.path.write_text("garbage\n{}\n")
        with pytest.raises(AttestationError) as exc:
            log.read()
        assert str(log.path) in str(exc.value)


# ---------------------------------------------------------------------------
# 4. Lock keyed by spelling (B-F12) and 8c
# ---------------------------------------------------------------------------
class TestTheLockIsKeyedByRealPath:
    def test_both_spellings_of_one_file_share_one_sidecar_and_one_thread_lock(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        (tmp_path / "alias").symlink_to(real)
        l1, l2 = AttestationLog(real / "x.jsonl"), AttestationLog(tmp_path / "alias" / "x.jsonl")
        assert l1.lock_path() == l2.lock_path()
        assert att._thread_lock_for(l1) is att._thread_lock_for(l2)

    def test_a_symlink_to_the_file_shares_the_sidecar_of_its_target(self, tmp_path):
        (tmp_path / "t.jsonl").write_text("")
        (tmp_path / "link.jsonl").symlink_to(tmp_path / "t.jsonl")
        assert (AttestationLog(tmp_path / "link.jsonl").lock_path()
                == AttestationLog(tmp_path / "t.jsonl").lock_path())

    def test_another_process_via_the_other_spelling_is_excluded(self, tmp_path):
        (tmp_path / "t.jsonl").write_text("")
        (tmp_path / "link.jsonl").symlink_to(tmp_path / "t.jsonl")
        holder = _hold(Path(os.path.realpath(tmp_path / "t.jsonl") + ".lock"), 3)
        try:
            with pytest.raises(att.AttestationBusyError):
                with AttestationLog(tmp_path / "link.jsonl").locked(timeout=0.4):
                    pass
        finally:
            holder.kill()
            holder.wait()

    def test_two_spellings_serialise_in_one_process(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        (tmp_path / "alias").symlink_to(real)
        l1, l2 = AttestationLog(real / "x.jsonl"), AttestationLog(tmp_path / "alias" / "x.jsonl")
        with l1.locked():
            with pytest.raises(att.AttestationBusyError):
                with l2.locked(timeout=0.3):
                    pass


# ---------------------------------------------------------------------------
# 5. One anchor selector for CLI, API and MCP (B-F13)
# ---------------------------------------------------------------------------
class TestOneAnchorSelector:
    def _mixed(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "m.jsonl")
        attest(_ledger(tmp_path / "hosted.db", 4), key, log)        # 1 read
        attest(_declared(9, "d"), key, log)                          # 2 declared (newest)
        return key, log

    def test_the_default_selection_skips_declared_heads(self, tmp_path):
        _, log = self._mixed(tmp_path)
        assert att.select_anchor(log.read()).sequence == 1

    def test_no_read_record_means_no_anchor_by_default(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "d.jsonl")
        attest(_declared(4), key, log)
        assert att.select_anchor(log.read()) is None

    def test_an_explicit_offline_choice_may_fall_back_to_a_declared_head(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "d.jsonl")
        attest(_declared(4), key, log)
        chosen = att.select_anchor(log.read(), accept_declared=True)
        assert chosen.basis is DECLARED

    def test_a_read_record_still_wins_over_a_newer_declared_one_when_declared_is_allowed(
            self, tmp_path):
        _, log = self._mixed(tmp_path)
        assert att.select_anchor(log.read(), accept_declared=True).sequence == 1

    def test_a_declared_head_over_zero_records_anchors_nothing(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "z.jsonl")
        attest(LedgerHead(length=0, head_seq=0, head_link_hash="0" * 64, basis=DECLARED),
               key, log)
        with pytest.raises(AttestationError, match="anchors nothing"):
            att.select_anchor(log.read(), accept_declared=True)

    def test_the_api_cli_and_mcp_pick_the_same_record(self, tmp_path, api):  # noqa: F811
        """API and MCP go through latest_anchor; the CLI through require_anchor."""
        a, _ = _account("sel@example.de")
        key = SigningKey.load(os.environ["ASSURANCE_ATTEST_KEY"])
        log = _acct_log(a)
        attest(EvidenceLedger(deps.tenant_ledger_path(a.id)), key, log)
        attest(_declared(9, "d"), key, log)
        assert attest_routes.latest_anchor(SimpleNamespace(subject=a.id))["sequence"] == 1
        assert log.require_anchor().sequence == 1

    def _case_ledger(self, tmp_path):
        from assurance.change.store import OPENED_KIND

        led = EvidenceLedger(tmp_path / "case.db")
        for _ in range(4):
            led.append(Evidence(kind=OPENED_KIND, body={"case_id": "CASE-A"},
                                actor=Actor("a.person", "engineer"),
                                origin=Origin("unit-test")).seal(), subject="CASE-A")
        return led

    def test_a_cli_export_over_a_declared_anchor_says_so_and_never_claims_a_signed_head(
            self, tmp_path, capsys):
        led = self._case_ledger(tmp_path)
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "d.jsonl")
        head = led.entries()[-1]
        attest(LedgerHead(length=4, head_seq=head.seq, head_link_hash=head.link_hash,
                          basis=DECLARED), key, log)
        out = tmp_path / "b.json"
        for argv in (
            ["art14", "--ledger", str(led.path), "export", "--case", "CASE-A",
             "-o", str(out), "--attestations", str(log.path)],
            ["change", "export", "--ledger", str(led.path), "CASE-A",
             "--out", str(out), "--attestations", str(log.path)],
        ):
            assert cli_main(argv) == 0
            said = capsys.readouterr().out
            assert "declared by the holder" in said and "not read from the ledger" in said
            assert "anchored to attestation" not in said
            assert json.loads(out.read_text())["anchor"]["basis"] == "declared_by_holder"

    def test_a_cli_export_over_a_read_anchor_still_says_anchored(self, tmp_path, capsys):
        led = self._case_ledger(tmp_path)
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "r.jsonl")
        attest(led, key, log)
        out = tmp_path / "b.json"
        assert cli_main(["art14", "--ledger", str(led.path), "export", "--case", "CASE-A",
                         "-o", str(out), "--attestations", str(log.path)]) == 0
        assert "anchored to attestation 1" in capsys.readouterr().out

    def test_a_cli_export_with_a_mixed_log_embeds_the_read_record(self, tmp_path, capsys):
        led = self._case_ledger(tmp_path)
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "m.jsonl")
        attest(led, key, log)
        attest(_declared(99, "d"), key, log)
        out = tmp_path / "b.json"
        assert cli_main(["art14", "--ledger", str(led.path), "export", "--case", "CASE-A",
                         "-o", str(out), "--attestations", str(log.path)]) == 0
        anchor = json.loads(out.read_text())["anchor"]
        assert anchor["sequence"] == 1 and anchor["basis"] == "read_from_ledger"

    def test_a_cli_export_still_fails_closed_on_a_contradicting_anchor(self, tmp_path, capsys):
        led = self._case_ledger(tmp_path)
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "d.jsonl")
        attest(LedgerHead(length=40, head_seq=40, head_link_hash=_hex("d"), basis=DECLARED),
               key, log)
        out = tmp_path / "b.json"
        assert cli_main(["art14", "--ledger", str(led.path), "export", "--case", "CASE-A",
                         "-o", str(out), "--attestations", str(log.path)]) == 2
        assert not out.exists()

    def test_the_evidence_verifier_uses_the_same_selector(self, tmp_path, capsys):
        led = self._case_ledger(tmp_path)
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "m.jsonl")
        attest(led, key, log)
        attest(_declared(99, "d"), key, log)         # newest, about another ledger
        pub = tmp_path / "k.pub"
        pub.write_text(key.verifying.pem())
        out = tmp_path / "b.json"
        out.write_text(json.dumps(led.export(subject="CASE-A", skeleton=True)))
        assert cli_main(["evidence", "verify", str(out), "--public-key", str(pub),
                         "--attestations", str(log.path)]) == 0
        capsys.readouterr()


# ---------------------------------------------------------------------------
# 6. The note is the requester's text (A-M4)
# ---------------------------------------------------------------------------
class TestTheNoteIsNotTheSignersStatement:
    NOTE = "Ledger audited and pristine - signed off by the notified body"

    def test_the_counter_sign_response_marks_the_note(self, client):  # noqa: F811
        r = client.post("/v1/ledger/attest", json=_body(4, note=self.NOTE),
                        headers={"X-API-Key": OPERATOR_KEY})
        assert r.status_code == 200
        body = r.json()
        assert body["note_is_tenant_supplied"] is True
        assert any("requester's free text" in c for c in body["checks_skipped"])
        assert body["attestation"]["note"] == self.NOTE      # format unchanged

    def test_no_note_no_marker(self, client):  # noqa: F811
        body = client.post("/v1/ledger/attest", json=_body(4),
                           headers={"X-API-Key": OPERATOR_KEY}).json()
        assert body["note_is_tenant_supplied"] is False

    def test_free_verification_says_the_note_is_not_a_statement_by_the_key_holder(
            self, client):  # noqa: F811
        record = client.post("/v1/ledger/attest", json=_body(4, note=self.NOTE),
                             headers={"X-API-Key": OPERATOR_KEY}).json()["attestation"]
        v = client.post("/v1/ledger/attest/verify", json={"attestations": [record]}).json()
        assert v["ok"] is True
        assert v["notes"] == [{"sequence": 1, "note": self.NOTE,
                               "note_is_tenant_supplied": True}]
        assert any("requester's free text" in c and "not a statement by the key holder" in c
                   for c in v["checks_skipped"])

    def test_the_signature_format_is_unchanged(self):
        assert att.ATTESTATION_FORMAT == "assurance.head-attestation.v1"

    def test_a_note_on_a_server_read_record_is_not_marked(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        record = attest(_ledger(tmp_path / "l.db", 2), key, log, note="weekly run")
        verdict = verify_log([record], key.verifying)
        assert verdict.notes == [{"sequence": 1, "note": "weekly run",
                                  "note_is_tenant_supplied": False}]
        assert not any("free text" in s for s in verdict.checks_skipped)

    def test_the_cli_verify_prints_the_marker(self, tmp_path, capsys):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(4), key, log, note=self.NOTE)
        pub = tmp_path / "k.pub"
        pub.write_text(key.verifying.pem())
        assert cli_main(["attest", "verify", "--log", str(log.path),
                         "--public-key", str(pub)]) == 0
        said = capsys.readouterr().out
        assert "requester's free text" in said and "not a statement by the key holder" in said
        assert cli_main(["attest", "verify", "--log", str(log.path),
                         "--public-key", str(pub), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["notes"][0]["note_is_tenant_supplied"]


# ---------------------------------------------------------------------------
# 7. The private key is never world-readable, not even for an instant (A-L8a)
# ---------------------------------------------------------------------------
class TestKeyCreationMode:
    def test_the_file_is_created_0600_under_umask_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "chmod", lambda self, mode, **kw: None)  # no after-the-fact fix
        old = os.umask(0)
        try:
            path = SigningKey.generate().save(tmp_path / "k.pem")
        finally:
            os.umask(old)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_an_existing_file_is_never_opened_or_truncated(self, tmp_path):
        target = tmp_path / "k.pem"
        target.write_text("keep me")
        with pytest.raises(Exception, match="already exists"):
            SigningKey.generate().save(target)
        assert target.read_text() == "keep me"

    def test_the_create_is_exclusive_even_if_the_file_appears_after_the_check(
            self, tmp_path, monkeypatch):
        target = tmp_path / "k.pem"
        real_exists = Path.exists

        def late(self):
            if self == target.resolve():
                target.write_text("raced in")
                return False                       # the check said no; the file now exists
            return real_exists(self)

        monkeypatch.setattr(Path, "exists", late)
        with pytest.raises(Exception, match="already exists"):
            SigningKey.generate().save(target)
        assert target.read_text() == "raced in"


# ---------------------------------------------------------------------------
# 8. Guards that had no test
# ---------------------------------------------------------------------------
class TestGuardsThatHadNoTest:
    def test_a_damaged_log_fails_the_hosted_export_it_does_not_silently_unanchor_it(
            self, tenants):  # noqa: F811
        web, (a, ha), _, _ = tenants
        path = _acct_log(a).path
        path.write_bytes(b"garbage\n" + path.read_bytes())
        for url in ("/v1/cases/C1/export", "/v1/change/cases/CH-1/export"):
            r = web.get(url, headers=ha)
            assert r.status_code == 500, (url, r.text)
            assert r.json()["detail"]["error"] == "attestation_log_damaged"
        # ?anchor=false is the explicit, visible way to export without it.
        assert "anchor" not in web.get("/v1/cases/C1/export?anchor=false", headers=ha).json()

    def test_export_reads_in_one_snapshot(self, tmp_path):
        led = _ledger(tmp_path / "l.db", 4)
        original = led._connect
        state = {"appended": False}

        def interposed():
            db = original()

            class Conn:
                def __getattr__(self, name):
                    return getattr(db, name)

                def execute(self, sql, *args):
                    result = db.execute(sql, *args)
                    if "COUNT(*) FROM chain" in sql and "subject !=" not in sql \
                            and not state["appended"]:
                        state["appended"] = True       # a concurrent writer, other connection
                        EvidenceLedger(led.path).append(
                            Evidence(kind="test.record", body={"n": 99},
                                     actor=Actor(identifier="t"),
                                     origin=Origin(system="p")).seal(), subject="machine-0")
                    return result

            return Conn()

        led._connect = interposed
        bundle = led.export(subject="machine-0", skeleton=True)
        att = bundle["attestation"]
        assert state["appended"]
        assert att["head_seq"] <= att["length"] == 4
        seen = [e["seq"] for e in bundle["entries"]] + [s["seq"] for s in bundle["skeleton"]]
        assert max(seen) <= att["head_seq"]

    def test_two_declared_heads_at_one_seq_with_different_links_are_a_fork(self, tmp_path):
        key, log = SigningKey.generate(), AttestationLog(tmp_path / "a.jsonl")
        attest(_declared(5, "a"), key, log)
        with pytest.raises(AttestationError, match="fork, not a gap"):
            attest(_declared(5, "b"), key, log)
        assert attest(_declared(5, "a"), key, log).sequence == 2   # the same head again is fine


# ---------------------------------------------------------------------------
# 9. The contract says what the routes can answer (C-M1)
# ---------------------------------------------------------------------------
class TestOpenApiDocumentsTheRefusals:
    @pytest.fixture()
    def spec(self, attest_env):  # noqa: F811
        return importlib.import_module("assurance.api.service").create_app().openapi()

    @pytest.mark.parametrize("path,method,codes", [
        ("/v1/cases/{case_id}/export", "get", {"401", "402", "404", "409", "500"}),
        ("/v1/change/cases/{case_id}/export", "get", {"401", "402", "404", "409", "500"}),
        ("/v1/ledger/attest", "post", {"401", "402", "409", "422", "500", "503"}),
        ("/v1/ledger/attest/log", "get", {"401", "402", "500"}),
        ("/v1/ledger/attest/key", "get", {"503"}),
    ])
    def test_the_refusals_are_in_the_contract(self, spec, path, method, codes):
        declared = set(spec["paths"][path][method]["responses"])
        assert codes <= declared, (path, codes - declared)

    def test_the_409_names_the_anchor_finding(self, spec):
        text = json.dumps(spec["paths"]["/v1/cases/{case_id}/export"]["get"]["responses"]["409"])
        assert "anchor_contradicts_ledger" in text

    def test_blocked_reason_and_completeness_are_described(self, spec):
        export = spec["paths"]["/v1/change/cases/{case_id}/export"]["get"]["description"]
        assert "completeness" in export and "anchor" in export
        reverify = spec["paths"]["/v1/change/cases/{case_id}/reverification"]["post"]["description"]
        assert "blocked_reason" in reverify
