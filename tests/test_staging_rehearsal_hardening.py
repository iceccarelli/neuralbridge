"""The rehearsal tool, attacked: what an independent review found, pinned.

``tests/test_staging_rehearsal.py`` is the contract; this file is what a reviewer showed it
did not yet hold:

* a test key left live on the host when anything fails after the handover;
* a production host reached through a trailing dot, a full-width dot or an odd encoding;
* a report that trusted stale, partial, hand-written or crashed records;
* self-attested items scored as PASS (they are ATTESTED, and ATTESTED blocks exit 0);
* a redirect check that accepted ``https://host.evil.net/``, a proxy taken from the
  environment, a restore drill that opened the live source, a redactor that missed encoded
  forms, live-key refusal gaps, and a Dockerfile test with blind spots (the last in
  ``tests/test_assurance_dockerfile_deps.py``).

Same rules: loopback servers on kernel-assigned ports, no network, no node_modules.
"""

from __future__ import annotations

import ast
import base64
import json
import socket
import sqlite3
import stat
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote, quote_plus

import httpx
import pytest

from . import interfaces_fixtures as fx
from . import test_staging_rehearsal as base
from .test_staging_rehearsal import (  # noqa: F401  (fixtures are imported by name)
    ALL_PHASES,
    FAKE_KEY,
    OPERATOR_KEY,
    REGISTER_KEY_ENV,
    SK_TEST,
    WHSEC,
    all_records,
    all_secret_env,
    assert_no_secrets,
    cli,
    drill,
    fake_checkout,
    fake_service,
    full_env,
    iso,
    make_data_dir,
    phase_steps,
    record,
    report,
    run_smoke,
    run_webhook,
    serving,
    sha,
    statuses,
    webhook_env,
    write_record,
)

# fixtures shared with the contract tests
live_api = fx.live_api
sr = base.sr
staging_like = base.staging_like
_scratch_cwd = base._scratch_cwd

REPO = Path(__file__).resolve().parents[1]


def fingerprint(root: Path) -> dict[str, str]:
    """Every path under ``root`` (files and directories) with a content hash for files."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        out[str(path.relative_to(root))] = sha(path) if path.is_file() else "<dir>"
    return out


# ---------------------------------------------------------------------------
# H1, L8: the test key is revoked whatever goes wrong after the handover
# ---------------------------------------------------------------------------

def trip(sr, monkeypatch: pytest.MonkeyPatch, exc: BaseException, on: str = "/v1/me") -> None:
    """Make the first request to ``on`` raise ``exc`` (a failure no HTTP client would raise)."""
    real = sr.Http.request
    seen = {"n": 0}

    def wrapper(self, method, target, **kwargs):
        if target == on:
            seen["n"] += 1
            if seen["n"] == 1:
                raise exc
        return real(self, method, target, **kwargs)

    monkeypatch.setattr(sr.Http, "request", wrapper)


@pytest.mark.parametrize("defect,extra", [
    ({"me_hang": True}, ["--timeout", "1"]),        # a timeout between handover and cleanup
    ({"me_list": True}, []),                        # a JSON list where an object was expected
])
def test_the_test_key_is_revoked_even_when_a_step_after_the_handover_fails(
        sr, capsys, tmp_path, defect, extra):
    app = fake_checkout(**defect)
    ran, found = run_webhook(sr, capsys, tmp_path, app, *extra)
    assert app.state.log["revoke_calls"] == 1, (found, ran.text)
    assert found["webhook.key_works"] == "FAIL"
    assert found["webhook.cleanup"] == "PASS" and ran.code == 1
    assert found["webhook.forged_rejected"] == "PASS"            # earlier steps are kept


def test_a_non_http_exception_still_revokes_and_keeps_the_steps_already_taken(
        sr, capsys, tmp_path, monkeypatch):
    app = fake_checkout()
    trip(sr, monkeypatch, RuntimeError(f"boom {SK_TEST} {FAKE_KEY}"))
    ran, found = run_webhook(sr, capsys, tmp_path, app)
    assert ran.code == 1 and app.state.log["revoke_calls"] == 1
    for step in ("webhook.forged_rejected", "webhook.delivered", "webhook.key_handover_once",
                 "webhook.cleanup"):
        assert found[step] == "PASS", (step, found)
    assert found["webhook.internal_error"] == "FAIL"
    assert "RuntimeError" in ran.err
    assert_no_secrets(ran.text, (tmp_path / "webhook-test.json").read_text())
    assert FAKE_KEY not in ran.text


def test_ctrl_c_after_the_handover_revokes_the_key_and_exits_130(
        sr, capsys, tmp_path, monkeypatch):
    app = fake_checkout()
    trip(sr, monkeypatch, KeyboardInterrupt())
    ran, found = run_webhook(sr, capsys, tmp_path, app)
    assert ran.code == 130 and app.state.log["revoke_calls"] == 1
    assert found["webhook.cleanup"] == "PASS" and found["webhook.delivered"] == "PASS"
    assert "INTERRUPTED" in ran.err
    assert record(tmp_path, "webhook-test")["state"] == "interrupted"


@pytest.mark.parametrize("defect", [{"revoke_500": True}, {"no_revoke": True}])
def test_a_revoke_that_cannot_be_confirmed_fails_and_names_the_key_by_prefix_only(
        sr, capsys, tmp_path, defect):
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout(**defect))
    assert found["webhook.cleanup"] == "FAIL" and ran.code == 1
    detail = next(s["detail"] for s in record(tmp_path, "webhook-test")["steps"]
                  if s["id"] == "webhook.cleanup")
    assert "a live test key may remain on the host" in detail
    assert FAKE_KEY[:10] in detail and FAKE_KEY not in ran.text     # the prefix, never the key
    assert FAKE_KEY not in (tmp_path / "webhook-test.json").read_text()


@pytest.mark.parametrize("exc", [httpx.ConnectError("down"), RuntimeError("boom")])
def test_a_cleanup_whose_requests_raise_fails_with_the_warning_and_the_prefix(
        sr, capsys, tmp_path, monkeypatch, exc):
    trip(sr, monkeypatch, exc, on="/v1/keys/revoke")
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout())
    detail = next(s["detail"] for s in record(tmp_path, "webhook-test")["steps"]
                  if s["id"] == "webhook.cleanup")
    assert found["webhook.cleanup"] == "FAIL" and ran.code == 1
    assert "a live test key may remain on the host" in detail and FAKE_KEY[:10] in detail
    assert type(exc).__name__ in detail and FAKE_KEY not in ran.text


def test_the_note_does_not_claim_a_cleanup_that_has_not_happened(sr, capsys, tmp_path):
    ran, _ = run_webhook(sr, capsys, tmp_path, fake_checkout())
    assert "no key after cleanup" not in ran.text


def test_a_key_handed_out_before_any_delivery_fails_and_is_still_revoked(
        sr, capsys, tmp_path):
    app = fake_checkout(early_key=True)
    ran, found = run_webhook(sr, capsys, tmp_path, app)
    assert found["webhook.pending_before"] == "FAIL" and ran.code == 1
    assert app.state.log["revoke_calls"] == 1


def test_a_host_that_grants_again_on_replay_fails_the_duplicate_check(sr, capsys, tmp_path):
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout(regrant=True))
    assert found["webhook.replay_duplicate"] == "FAIL" and ran.code == 1


@pytest.mark.parametrize("defect", [{"me_tier": "cell"}, {"me_dead": True}])
def test_a_key_that_is_the_wrong_tier_or_dead_fails_key_works(sr, capsys, tmp_path, defect):
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout(**defect))
    assert found["webhook.key_works"] == "FAIL" and found["webhook.cleanup"] == "PASS"


def test_a_handed_over_key_with_no_known_shape_is_still_redacted(sr, capsys, tmp_path):
    key = "KEYWITHNOSHAPE_abcdefghijklmnopqrstuvwxyz0123456789"
    ran, found = run_webhook(sr, capsys, tmp_path, fake_checkout(key=key, me_echo_key=True))
    assert found["webhook.key_works"] == "FAIL"           # its tier "is" the key: printed
    assert key not in ran.text and key not in (tmp_path / "webhook-test.json").read_text()


# ---------------------------------------------------------------------------
# M1: the host deny list, and what counts as the same host
# ---------------------------------------------------------------------------

BYPASSES = [
    "https://neuralbridge.io./", "https://www.neuralbridge.io./",
    "https://assurance-register.fly.dev./", "https://neuralbridge。io/",
    "https://NEURALBRIDGE.IO/", "https://neuralbridge.io:443/", "https://neuralbridge.io%2e/",
    "https://neuralbridge.io．/",
]


@pytest.mark.parametrize("base", BYPASSES)
def test_no_spelling_of_a_production_host_reaches_the_network(
        sr, capsys, tmp_path, monkeypatch, base):
    calls: list[str] = []
    monkeypatch.setattr(httpx.Client, "request", lambda self, *a, **k: calls.append("x"))
    monkeypatch.setattr(httpx.Client, "send", lambda self, *a, **k: calls.append("x"))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: calls.append("c"))
    host = base.split("//")[1].rstrip("/").split(":")[0]
    ran = cli(sr, capsys, "webhook-test", "--base-url", base, "--i-am-testing-staging",
              "--record-dir", str(tmp_path), env=webhook_env(STAGING_CONFIRM=host))
    assert ran.code == 1 and "REFUSED" in ran.err and calls == []
    assert record(tmp_path, "webhook-test")["steps"][0]["status"] == "FAIL"


@pytest.mark.parametrize("base", ["https://staging.example.test./", "http://localhost./",
                                  "https://stäging.example.test/", "https://a。b/"])
def test_a_trailing_dot_or_a_non_ascii_host_is_not_a_usable_base_url(sr, base):
    parts, why = sr.parse_base_url(base)
    assert parts is None and why


def test_each_layer_of_the_host_spelling_defence_speaks_for_itself(sr, monkeypatch):
    assert "ends with a dot" in sr.parse_base_url("https://staging.test./")[1]
    assert "non-ASCII" in sr.parse_base_url("https://st\u00e4ging.test/")[1]
    assert "characters a hostname does not" in sr.parse_base_url("https://staging.test%2e/")[1]
    assert sr.parse_base_url("https://xn--bcher-kva.example/")[0] is not None   # IDN, as ASCII

    class Elsewhere:
        host = "other.test"

    monkeypatch.setattr(sr.httpx, "URL", lambda *a, **k: Elsewhere())
    assert "ambiguous" in sr.parse_base_url("https://staging.test/")[1]


def test_the_deny_list_from_the_environment_is_normalised_the_same_way(
        sr, capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(httpx.Client, "request", lambda *a, **k: pytest.fail("a request"))
    ran = cli(sr, capsys, "webhook-test", "--base-url", "https://api.prod.example.test",
              "--i-am-testing-staging", "--record-dir", str(tmp_path),
              env=webhook_env(STAGING_CONFIRM="api.prod.example.test",
                              REHEARSAL_PRODUCTION_HOSTS="X.example.test,  API.Prod.Example.Test. "))
    assert ran.code == 1 and "REFUSED" in ran.err


# ---------------------------------------------------------------------------
# M2: the report trusts only a complete, current, consistent set of records
# ---------------------------------------------------------------------------

def test_a_phase_always_leaves_a_record_so_a_later_failure_replaces_an_earlier_pass(
        sr, capsys, tmp_path):
    ran = cli(sr, capsys, "config-check", env=full_env())
    first = json.loads((tmp_path / ".rehearsal" / "config-check.json").read_text())
    assert first["state"] == "complete" and first["exit_code"] == 3, ran.text
    ran = cli(sr, capsys, "config-check", env=full_env(STRIPE_SECRET_KEY="sk_live_" + "x" * 24))
    again = json.loads((tmp_path / ".rehearsal" / "config-check.json").read_text())
    assert ran.code == 1 and again["exit_code"] == 1
    assert again["run_id"] != first["run_id"]
    assert report(sr, capsys, tmp_path / ".rehearsal", tmp_path / "out").code == 1


def test_records_carry_the_script_version_and_a_fresh_run_id(sr, capsys, tmp_path):
    cli(sr, capsys, "config-check", "--record-dir", str(tmp_path / "a"), env=full_env())
    cli(sr, capsys, "config-check", "--record-dir", str(tmp_path / "b"), env=full_env())
    a, b = record(tmp_path / "a", "config-check"), record(tmp_path / "b", "config-check")
    assert a["script_version"] == sr.VERSION and a["run_id"] and a["run_id"] != b["run_id"]


def test_a_phase_that_is_interrupted_invalidates_the_record_it_replaces(
        sr, capsys, tmp_path, monkeypatch):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    seen: dict[str, Any] = {}

    def smoke(ctx, args):
        seen["during"] = json.loads((rec / "smoke.json").read_text())["state"]
        raise KeyboardInterrupt

    monkeypatch.setitem(sr.PHASES, "smoke", smoke)
    ran = cli(sr, capsys, "smoke", "--record-dir", str(rec), env={})
    assert ran.code == 130 and seen["during"] == "in_progress"
    assert record(rec, "smoke")["state"] == "interrupted"
    assert report(sr, capsys, rec, tmp_path / "out").code == 1


@pytest.mark.parametrize("state", ["in_progress", "interrupted", "crashed", ""])
@pytest.mark.parametrize("steps", [[], None])        # None: every step present and PASS
def test_a_record_that_did_not_finish_is_a_failure_whatever_it_contains(
        sr, capsys, tmp_path, state, steps):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    write_record(sr, rec, "smoke", steps, state=state)
    assert report(sr, capsys, rec, tmp_path / "out").code == 1


def test_the_four_hand_written_one_step_records_of_the_review_are_not_a_pass(
        sr, capsys, tmp_path):
    rec = tmp_path / "rec"
    for phase in ALL_PHASES:
        write_record(sr, rec, phase, [{"id": f"{phase}.x", "status": "PASS", "detail": ""}],
                     hours_ago=24 * 365 * 27, host=f"{phase}.example.test")
    ran = report(sr, capsys, rec, tmp_path / "out")
    assert ran.code == 1


def test_a_record_missing_any_step_of_its_phase_is_a_failure(sr, capsys, tmp_path):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    steps = phase_steps(sr, "smoke")[:-1]
    write_record(sr, rec, "smoke", steps)
    ran = report(sr, capsys, rec, tmp_path / "out")
    assert ran.code == 1 and "smoke.no_secret_shapes" in ran.text


def test_a_stale_record_fails_unless_the_bound_is_widened_on_purpose(sr, capsys, tmp_path):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    write_record(sr, rec, "restore-drill", hours_ago=8)
    assert report(sr, capsys, rec, tmp_path / "out").code == 1
    assert report(sr, capsys, rec, tmp_path / "out", "--max-age-hours", "12").code == 0
    write_record(sr, rec, "restore-drill", hours_ago=24 * 365)
    assert report(sr, capsys, rec, tmp_path / "out", "--max-age-hours", "12").code == 1


def test_records_must_name_one_host_across_smoke_and_webhook_test(sr, capsys, tmp_path):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    write_record(sr, rec, "webhook-test", host="another-host.example.test")
    ran = report(sr, capsys, rec, tmp_path / "out")
    assert ran.code == 1 and "another-host.example.test" in ran.text


def test_records_must_come_from_one_rehearsal_in_order(sr, capsys, tmp_path):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    assert report(sr, capsys, rec, tmp_path / "out").code == 0
    write_record(sr, rec, "config-check", hours_ago=0)          # config re-run AFTER the smoke
    write_record(sr, rec, "smoke", hours_ago=3)
    write_record(sr, rec, "webhook-test", hours_ago=2)
    ran = report(sr, capsys, rec, tmp_path / "out")
    assert ran.code == 1 and "out of order" in ran.text.lower()


def test_records_from_another_version_of_the_script_are_a_failure(sr, capsys, tmp_path):
    rec = tmp_path / "rec"
    all_records(sr, rec)
    write_record(sr, rec, "smoke", version="0-ancient")
    assert report(sr, capsys, rec, tmp_path / "out").code == 1


def test_the_report_names_the_run_of_every_phase_and_its_hosts(sr, capsys, tmp_path):
    rec, out = tmp_path / "rec", tmp_path / "out"
    all_records(sr, rec)
    report(sr, capsys, rec, out)
    data = json.loads((out / "rehearsal-report.json").read_text())
    assert data["target_host"] == "staging.example.test"
    assert data["phases"]["smoke"]["run_id"] == "run-smoke"
    assert data["phases"]["smoke"]["target_host"] == "staging.example.test"


# ---------------------------------------------------------------------------
# M3: what the founder states, or what a shell lacks, is ATTESTED and blocks exit 0
# ---------------------------------------------------------------------------

def test_attested_never_counts_as_a_pass_and_a_failure_still_wins(sr):
    step = sr.Step
    assert sr.exit_code([step("a", "PASS", ""), step("b", "ATTESTED", "")]) == 3
    assert sr.exit_code([step("a", "ATTESTED", "")]) == 3
    assert sr.exit_code([step("a", "ATTESTED", ""), step("b", "FAIL", "")]) == 1


def test_the_report_lists_attested_items_apart_from_measured_ones(sr, capsys, tmp_path):
    rec, out = tmp_path / "rec", tmp_path / "out"
    all_records(sr, rec)
    steps = phase_steps(sr, "webhook-test")
    steps[1]["status"] = "ATTESTED"
    assert steps[1]["id"] == "webhook.secret_is_test"
    write_record(sr, rec, "webhook-test", steps)
    ran = report(sr, capsys, rec, out)
    data = json.loads((out / "rehearsal-report.json").read_text())
    markdown = (out / "rehearsal-report.md").read_text()
    assert ran.code == 3 and data["attested"] == ["webhook.secret_is_test"]
    assert "attested by the operator, not measured" in markdown.lower()


# ---------------------------------------------------------------------------
# config-check: the site origin (a placeholder must not be settable literally)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,value", [
    ("ASSURANCE_MARKETING_URL", "REPLACE_WITH_STAGING_SITE_ORIGIN"),
    ("ASSURANCE_MARKETING_URL", "<the staging site origin>"),
    ("ASSURANCE_MARKETING_URL", "https://neuralbridge.io"),
    ("ASSURANCE_MARKETING_URL", "http://stage.fly.dev"),
    ("ASSURANCE_ALLOWED_ORIGINS", "https://site.vercel.app/path"),
    ("ASSURANCE_ALLOWED_ORIGINS", "https://ok.vercel.app,REPLACE_ME"),
])
def test_a_placeholder_or_production_site_origin_fails(sr, capsys, tmp_path, name, value):
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path),
              env=full_env(**{name: value}))
    assert ran.code == 1 and statuses(tmp_path, "config-check")["config.site_origin"] == "FAIL"


def test_a_well_formed_origin_that_is_a_placeholder_says_so(sr, capsys, tmp_path):
    cli(sr, capsys, "config-check", "--record-dir", str(tmp_path),
        env=full_env(ASSURANCE_MARKETING_URL="https://REPLACE-ME.vercel.app"))
    step = next(s for s in record(tmp_path, "config-check")["steps"]
                if s["id"] == "config.site_origin")
    assert step["status"] == "FAIL" and "placeholder" in step["detail"]


def test_an_absent_site_origin_is_unchecked_or_a_failure_when_checkout_is_expected(
        sr, capsys, tmp_path):
    env = full_env()
    del env["ASSURANCE_MARKETING_URL"], env["ASSURANCE_ALLOWED_ORIGINS"]
    cli(sr, capsys, "config-check", "--record-dir", str(tmp_path), env=env)
    assert statuses(tmp_path, "config-check")["config.site_origin"] == "UNCHECKED"
    ran = cli(sr, capsys, "config-check", "--checkout-expected", "--record-dir",
              str(tmp_path), env=env)
    assert ran.code == 1 and statuses(tmp_path, "config-check")["config.site_origin"] == "FAIL"


# ---------------------------------------------------------------------------
# L1: the redirect check, and what is loopback
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,location,expected", [
    (301, "https://staging.test/healthz", "PASS"),
    (308, "https://STAGING.test", "PASS"),
    (301, "https://staging.test.evil.net/", "FAIL"),
    (301, "https://evil.net/https://staging.test/", "FAIL"),
    (301, "https://staging.testing/", "FAIL"),
    (301, "http://staging.test/", "FAIL"),
    (301, "/healthz", "FAIL"),
    (301, "", "FAIL"),
    (200, "", "FAIL"),
])
def test_the_redirect_must_go_to_https_on_exactly_the_same_host(sr, status, location, expected):
    assert sr.judge_redirect(status, location, "staging.test")[0] == expected


def test_the_one_cleartext_request_to_a_hosted_host_carries_no_credentials(sr):
    sent: list[tuple[str, str, dict[str, Any]]] = []

    class Stub:
        def request(self, method, target, **kwargs):
            sent.append((method, target, kwargs))
            return SimpleNamespace(status_code=301, headers={"location": "https://staging.test/"})

    status, _ = sr.check_https_redirect(Stub(), "staging.test")
    assert status == "PASS" and sent == [("GET", "http://staging.test/healthz", {})]


@pytest.mark.parametrize("host,expected", [
    ("localhost", True), ("127.0.0.1", True), ("127.9.9.9", True), ("::1", True),
    ("localhost.evil.com", False), ("127.0.0.1.evil.com", False), ("xlocalhost", False),
    ("evil-localhost", False), ("localhost.localdomain", False), ("0.0.0.0", False),
    ("10.0.0.1", False), ("", False),
])
def test_only_real_loopback_hosts_may_be_spoken_to_in_clear(sr, host, expected):
    assert sr.is_loopback(host) is expected
    if not expected and host:
        assert sr.parse_base_url(f"http://{host}")[0] is None


# ---------------------------------------------------------------------------
# L2: proxies are not taken from the environment
# ---------------------------------------------------------------------------

def test_an_http_proxy_in_the_environment_never_sees_the_key(
        sr, capsys, tmp_path, monkeypatch):
    sniffer = fx.listening_socket()
    sniffer.settimeout(0.2)
    connections: list[bytes] = []
    stop = threading.Event()

    def listen() -> None:
        while not stop.is_set():
            try:
                conn, _ = sniffer.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.settimeout(1)
                try:
                    connections.append(conn.recv(65536))
                except OSError:
                    connections.append(b"")

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    proxy = f"http://127.0.0.1:{sniffer.getsockname()[1]}"
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "HTTPS_PROXY",
                 "https_proxy"):
        monkeypatch.setenv(name, proxy)
    try:
        with serving(fake_service(register_key=REGISTER_KEY_ENV)) as url:
            _, found = run_smoke(sr, capsys, url, tmp_path,
                                 {"REHEARSAL_REGISTER_KEY": REGISTER_KEY_ENV})
    finally:
        stop.set()
        thread.join(timeout=5)
        sniffer.close()
    assert connections == [], "the tool talked to a proxy from the environment"
    assert found["smoke.healthz"] == "PASS" and found["smoke.register_key_402"] == "PASS"


# ---------------------------------------------------------------------------
# L3: restore-drill works on a copy and leaves the source alone
# ---------------------------------------------------------------------------

def wal_data_dir(root: Path) -> list[str]:
    ids = make_data_dir(root)
    for db in (root / "accounts.db", *(root / "tenants").glob("*.db")):
        con = sqlite3.connect(db)
        con.execute("PRAGMA journal_mode=WAL")
        con.close()
    return ids


def test_a_wal_mode_source_is_left_byte_for_byte_and_listing_for_listing(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    wal_data_dir(data)
    before = fingerprint(data)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    assert ran.code == 0, (found, ran.text)
    assert found["restore.source_untouched"] == "PASS"
    assert fingerprint(data) == before          # no -wal, no -shm, no changed byte


def test_the_check_that_the_source_is_untouched_can_fail(sr, capsys, tmp_path, monkeypatch):
    data = tmp_path / "data"
    make_data_dir(data)
    real = sr.restore_check.verify

    def writes_to_the_source(root):
        (data / "accounts.db-shm").write_bytes(b"x")
        return real(root)

    monkeypatch.setattr(sr.restore_check, "verify", writes_to_the_source)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    assert found["restore.source_untouched"] == "FAIL" and ran.code == 1


def test_a_source_that_looks_live_is_refused_unless_the_service_is_said_to_be_stopped(
        sr, capsys, tmp_path):
    data = tmp_path / "data"
    make_data_dir(data)
    (data / "accounts.db-wal").write_bytes(b"")
    before = fingerprint(data)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    assert ran.code == 1 and "REFUSED" in ran.err and found["restore.source"] == "FAIL"
    assert fingerprint(data) == before
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data),
                       "--i-know-the-service-is-stopped")
    assert found["restore.source"] == "PASS" and ran.code == 0, (found, ran.text)


@pytest.mark.parametrize("where", ["data", "backup"])
def test_a_symlink_is_refused_not_followed(sr, capsys, tmp_path, where):
    data = tmp_path / "data"
    ids = make_data_dir(data)
    outside = tmp_path / "outside.db"
    outside.write_bytes((data / "tenants" / f"{ids[0]}.db").read_bytes())
    root = data
    args = ["--data-dir", str(data)]
    if where == "backup":
        root = tmp_path / "bk"
        __import__("shutil").copytree(data, root)
        args = ["--backup-dir", str(root), "--data-dir", str(data)]
    (root / "tenants" / "acc_00000000000000aa.db").symlink_to(outside)
    ran, found = drill(sr, capsys, tmp_path, *args)
    assert ran.code == 1 and "REFUSED" in ran.err and "FAIL" in found.values()


def test_the_wipe_is_real_and_a_wipe_that_leaves_files_is_a_failure(
        sr, capsys, tmp_path, monkeypatch):
    data = tmp_path / "data"
    make_data_dir(data)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    detail = next(s["detail"] for s in record(tmp_path / "rec", "restore-drill")["steps"]
                  if s["id"] == "restore.wipe_restore")
    assert found["restore.wipe_restore"] == "PASS" and "wiped" in detail
    held = int(detail.split("held ")[1].split(" ")[0])
    assert held >= 3, detail            # the scratch volume really held the data it then lost
    monkeypatch.setattr(sr, "_wipe_dir", lambda path: None)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    detail = next(s["detail"] for s in record(tmp_path / "rec", "restore-drill")["steps"]
                  if s["id"] == "restore.wipe_restore")
    assert found["restore.wipe_restore"] == "FAIL" and ran.code == 1
    assert "survived the wipe" in detail, detail


def test_a_restored_file_that_differs_from_the_backup_is_a_failure(
        sr, capsys, tmp_path, monkeypatch):
    data = tmp_path / "data"
    make_data_dir(data)
    real = sr.shutil.copytree

    def corrupting(src, dst, *a, **kw):
        out = real(src, dst, *a, **kw)
        if Path(dst).name == "volume":
            (Path(dst) / "accounts.db").write_bytes(b"changed in the copy")
        return out

    monkeypatch.setattr(sr.shutil, "copytree", corrupting)
    ran, found = drill(sr, capsys, tmp_path, "--data-dir", str(data))
    assert found["restore.wipe_restore"] == "FAIL" and ran.code == 1


# ---------------------------------------------------------------------------
# L4: the redactor and what is written to disk
# ---------------------------------------------------------------------------

SPECIAL = 'p/a+s=s:w0rd&x y"q\\z'


def forms(secret: str) -> list[str]:
    raw = secret.encode()
    return [secret, quote(secret, safe=""), quote(secret), quote_plus(secret),
            base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
            base64.urlsafe_b64encode(raw).decode().rstrip("="), raw.hex(), raw.hex().upper(),
            json.dumps(secret)[1:-1]]


@pytest.mark.parametrize("form", forms(SPECIAL))
def test_every_encoding_of_a_secret_is_redacted(sr, form):
    redact = sr.Redactor({"MY_PASSWORD": SPECIAL})
    assert redact(f"before {form} after") == "before [REDACTED] after"


def test_a_registered_secret_is_redacted_in_every_encoding_too(sr):
    redact = sr.Redactor({})
    redact.add(SPECIAL)
    assert all(redact(f"[{f}]") == "[[REDACTED]]" for f in forms(SPECIAL))


def test_short_secrets_and_other_names_are_covered_but_plain_words_are_not(sr):
    redact = sr.Redactor({
        "DB_PASSWORD": "abc12", "AUTH_HEADER": "Bearer zzzzzzzz1", "SESSION_COOKIE": "c00kie77",
        "SENTRY_DSN": "https://abcdef12@o1.example/7",
        "DATABASE_URL": "postgres://app:Sup3rS3cret@db.internal:5432/app",
        "SOME_KEY": "true", "OTHER_SECRET": "none", "PLAIN_URL": "https://example.test/x"})
    text = "abc12 Bearer zzzzzzzz1 c00kie77 Sup3rS3cret https://abcdef12@o1.example/7"
    assert "abc12" not in redact(text) and "Sup3rS3cret" not in redact(text)
    assert "zzzzzzzz1" not in redact(text) and "c00kie77" not in redact(text)
    assert redact("true none https://example.test/x db.internal") \
        == "true none https://example.test/x db.internal"


def test_a_long_secret_is_redacted_when_only_the_front_of_it_is_shown(sr):
    secret = "UNSHAPEDSECRETVALUE0123456789abcdefABCDEF"
    assert secret[:12] not in sr.Redactor({"X_TOKEN": secret})(f"leaked {secret[:20]}...")


def test_redaction_reaches_dictionary_keys_and_nested_values(sr):
    redact = sr.Redactor({"X_TOKEN": "TOKENVALUE-1234567890"})
    out = redact.obj({"TOKENVALUE-1234567890": ["a TOKENVALUE-1234567890 b", {"k": "v"}]})
    assert out == {"[REDACTED]": ["a [REDACTED] b", {"k": "v"}]}


def test_records_and_reports_are_private_files_in_a_private_directory(sr, capsys, tmp_path):
    rec, out = tmp_path / "newdir" / "rec", tmp_path / "newdir" / "out"
    cli(sr, capsys, "config-check", "--record-dir", str(rec), env=full_env())
    assert stat.S_IMODE(rec.stat().st_mode) == 0o700
    assert stat.S_IMODE((rec / "config-check.json").stat().st_mode) == 0o600
    all_records(sr, rec)
    report(sr, capsys, rec, out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for name in ("rehearsal-report.json", "rehearsal-report.md"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600, name


@pytest.mark.parametrize("encode", [
    lambda s: quote(s, safe=""), lambda s: base64.b64encode(s.encode()).decode(),
    lambda s: s.encode().hex()])
def test_smoke_finds_a_provided_secret_in_an_encoded_form_too(sr, capsys, tmp_path, encode):
    key = "asr_REG/ISTER+KEY=abcdef0123456789"
    app = fake_service(register_key=key, leak="seen: " + encode(key))
    with serving(app) as url:
        ran, found = run_smoke(sr, capsys, url, tmp_path, {"REHEARSAL_REGISTER_KEY": key})
    assert found["smoke.provided_secrets_absent"] == "FAIL"
    assert key not in ran.text and encode(key) not in ran.text


def test_a_full_looking_api_key_in_a_response_is_found_and_never_printed(sr, capsys, tmp_path):
    leak = "asr_" + "Z" * 30
    with serving(fake_service(leak=leak)) as url:
        ran, found = run_smoke(sr, capsys, url, tmp_path)
    assert found["smoke.no_secret_shapes"] == "FAIL" and "Z" * 30 not in ran.text


# ---------------------------------------------------------------------------
# L5: live-mode refusal, in every disguise
# ---------------------------------------------------------------------------

LIVE_BODY = "AAAAAAAAAAAAAAAAAAAAAAAA"
DISGUISED = [
    f"xsk_live_{LIVE_BODY}", f"sk-live-{LIVE_BODY}", f"SK_LIVE_{LIVE_BODY}",
    f"ek_live_{LIVE_BODY}", f"rk-live-{LIVE_BODY}", f"whsec_live_{LIVE_BODY}",
    f"sk%5Flive%5F{LIVE_BODY}", f"sk%5flive%5f{LIVE_BODY}", f"sk%2Dlive%2D{LIVE_BODY}",
    f"sk%255Flive%255F{LIVE_BODY}", f"https://u:p@h/?k=pk%5Flive%5F{LIVE_BODY}",
    base64.b64encode(f"sk_live_{LIVE_BODY}".encode()).decode(),
    base64.urlsafe_b64encode(f"pk_live_{LIVE_BODY}".encode()).decode(),
    f"sk_live_{LIVE_BODY}".encode().hex(),
    "Basic " + base64.b64encode(f"sk_live_{LIVE_BODY}:".encode()).decode(),
    json.dumps({"key": f"sk_live_{LIVE_BODY}"}),
]


@pytest.mark.parametrize("value", DISGUISED)
def test_a_live_key_is_refused_in_every_disguise(sr, capsys, tmp_path, value):
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path),
              env=full_env(UNUSED_VARIABLE=value))
    assert ran.code == 1 and "REFUSED" in ran.err and "UNUSED_VARIABLE" in ran.err
    assert value not in ran.text and LIVE_BODY not in ran.text


@pytest.mark.parametrize("name,value", [
    ("STRIPE_MODE", "live"), ("STAGING_STRIPE_MODE", "LIVE"), ("STRIPE_ENV", "live"),
    ("STRIPE_ACCOUNT_MODE", " live "),
])
def test_a_stripe_variable_that_says_live_is_refused(sr, capsys, name, value):
    ran = cli(sr, capsys, "webhook-test", env={name: value})
    assert ran.code == 1 and "REFUSED" in ran.err and name in ran.err


@pytest.mark.parametrize("value", [f"sk_test_{LIVE_BODY}", f"rk_test_{LIVE_BODY}",
                                   "live_music_stream", "delivery", "olive_oil_sk"])
def test_test_keys_and_ordinary_words_are_not_refused(sr, capsys, tmp_path, value):
    ran = cli(sr, capsys, "config-check", "--record-dir", str(tmp_path),
              env=full_env(UNUSED_VARIABLE=value))
    assert "REFUSED" not in ran.err
    assert cli(sr, capsys, "webhook-test", env={"STAGING_STRIPE_MODE": "test"}).code == 3


# ---------------------------------------------------------------------------
# survivors: nothing in the tool reaches the network except through its one client
# ---------------------------------------------------------------------------

SCRIPT_SOURCE = (REPO / "scripts" / "staging_rehearsal.py").read_text(encoding="utf-8")
NETWORK_VERBS = {"request", "send", "urlopen", "post", "put", "patch", "delete", "head",
                 "options", "create_connection", "connect", "sendmail", "send_message",
                 "getaddrinfo", "sendall", "run", "system", "Popen", "check_output"}


def test_no_call_in_the_tool_reaches_a_network_except_the_one_client_and_the_tls_read():
    tree = ast.parse(SCRIPT_SOURCE)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    # every top-level import is a module with no way to talk to anything but through the
    # reviewed paths below (httpx and socket/ssl are used in exactly two places)
    assert imported <= {
        "__future__", "argparse", "base64", "binascii", "collections", "dataclasses",
        "datetime", "hashlib", "hmac", "httpx", "ipaddress", "json", "os", "pathlib", "re",
        "secrets", "shutil", "socket", "sqlite3", "ssl", "stat", "sys", "tempfile", "time",
        "typing", "urllib", "uuid", "assurance",
    }, imported
    assert "smtplib" not in imported and "subprocess" not in imported
    assert "http" not in imported and "requests" not in imported

    where: dict[str, set[str]] = {}

    def visit(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, ast.FunctionDef | ast.ClassDef) else scope
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                if child.value.id == "httpx" and child.attr not in {
                        "Client", "HTTPError", "Response", "InvalidURL"}:
                    where.setdefault(f"httpx.{child.attr}", set()).add(inner)
                if child.value.id == "urllib" and child.attr != "parse":
                    where.setdefault(f"urllib.{child.attr}", set()).add(inner)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) \
                    and child.func.attr in NETWORK_VERBS:
                receiver = ast.unparse(child.func.value)
                where.setdefault(f"{receiver}.{child.func.attr}", set()).add(inner)
            visit(child, inner)

    visit(tree, "<module>")
    allowed = {
        "self._client.request": {"request"},             # class Http: the one client
        "http.request": None,                           # callers of that client (any function)
        "socket.create_connection": {"check_tls"},      # the read-only certificate handshake
        "sqlite3.connect": None,                        # local files (restore-drill)
        "httpx.URL": None,                              # parsing a URL, no I/O
    }
    for call, scopes in where.items():
        assert call in allowed, f"unexpected network-capable call {call} in {sorted(scopes)}"
        if allowed[call] is not None:
            assert scopes <= allowed[call], (call, scopes)
    # the substring tripwire stays, but it is no longer the whole check
    for forbidden in ("api.stripe.com", "checkout/sessions", "/v1/prices", "smtplib"):
        assert forbidden not in SCRIPT_SOURCE


# ---------------------------------------------------------------------------
# docs that must not regress to what a reviewer found wrong
# ---------------------------------------------------------------------------

def doc(name: str) -> str:
    return (REPO / name).read_text(encoding="utf-8")


def test_no_doc_or_config_puts_a_secret_on_a_fly_command_line():
    import re
    for name in ("DEPLOY_NOW.md", "deploy/assurance/README.md", "deploy/assurance/fly.toml"):
        for line in doc(name).splitlines():
            assert not re.match(r"^\s*(#\s*)?fly secrets set\b", line), (name, line)
        assert "fly secrets import" in doc(name), name


def test_the_founder_steps_pipe_secrets_from_the_environment_not_through_a_heredoc():
    text = doc("DEPLOY_NOW.md")
    assert "<<EOF" not in text and "<<'EOF'" not in text      # a heredoc can be staged on disk
    assert "env | grep -E" in text and "read -rs" in text
    assert "<the staging site origin>" not in text
    assert text.count("REPLACE_WITH_STAGING_SITE_ORIGIN") >= 2
    assert "mkdir -p" in text            # the directory the backup is fetched into must exist


def test_smoke_md_states_every_kind_of_request_the_tool_sends():
    text = doc("SMOKE.md")
    assert "reads the host only" not in text
    for needle in ("POST", "/v1/machine/verify", "OPTIONS", "port 80", "no credentials"):
        assert needle in text, needle


def test_the_docs_say_the_deny_list_is_a_speed_bump_and_a_proxy_is_ignored():
    text = doc("DEPLOY_NOW.md")
    assert "speed bump" in text and "CNAME" in text
    assert "proxy" in text.lower()
    assert "placeholder price" in text.lower()
