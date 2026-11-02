"""``ops`` notifications: a minimal, signed, idempotent webhook after a cycle (operator path).

Everything that stands in for the receiver is a CONTRACT FIXTURE: an in-memory transport that
records the request it was handed, or the real ``UrllibTransport`` driven by a scripted opener.
This proves how the sender behaves toward a receiver of that shape. It is NOT live integration,
no vendor endpoint was contacted, and nothing here shows that any receiver exists. An autouse
fixture makes any socket operation raise, so "nothing was sent" is also "nothing opened a socket".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import urllib.request
import uuid
from pathlib import Path

import pytest

from assurance.cli import main as assurance_main
from assurance.intel.transport import RedirectRefused, TransportError
from assurance.intel.transport_urllib import UrllibTransport, _NoRedirect
from assurance.ops import notify
from assurance.ops import record as rec
from assurance.ops.config import OpsConfigError, load_config

from .test_intel_transport import Opener, Resp, headers, http_error
from .test_ops_cycle import Site, _break_chain, _cycle, _guard

SECRET = "ZZ-FAKE-HMAC-SECRET-0123456789abcdef"
EXTRA = "Authorization: Bearer ZZ-FAKE-BEARER-TOKEN-9f8e7d6c"
TOKEN = "ZZ-FAKE-BEARER-TOKEN-9f8e7d6c"
URL_TOKEN = "ZZ-FAKE-URL-TOKEN-4b3a2c1d"
HOST = "hooks.example.invalid"
URL = f"https://{HOST}/services/{URL_TOKEN}"


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise OSError("NO NETWORK in this test: a socket was opened")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture()
def site(tmp_path):
    return Site(tmp_path / "site")


class Contract:
    """CONTRACT FIXTURE transport: records every POST; answers from a script (default 200)."""

    label = "contract-fixture (not live integration)"

    def __init__(self, *script):
        self.script = list(script)
        self.calls: list[dict] = []

    def post(self, url, hdrs, body, timeout):
        self.calls.append({"url": url, "headers": dict(hdrs), "body": body, "timeout": timeout})
        item = self.script.pop(0) if self.script else 200
        if isinstance(item, Exception):
            raise item
        return item, b""


def target(name="oncall", **kw) -> dict:
    return {"name": name, "url": URL, "allow_host": HOST, "secret_env": "NB_SECRET",
            "headers_env": "NB_HDRS", **kw}


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("NB_SECRET", SECRET)
    monkeypatch.setenv("NB_HDRS", EXTRA)


def wire(monkeypatch, transport):
    """Make every target use ``transport``; return the list of hosts it was asked for."""
    hosts: list[str] = []

    def factory(host):
        hosts.append(host)
        return transport

    monkeypatch.setattr(notify, "make_transport", factory)
    return hosts


def configure(site: Site, *targets: dict) -> None:
    site.cfg["notify"] = list(targets)
    site.write()


def hdr(call: dict, name: str) -> str:
    return {k.lower(): v for k, v in call["headers"].items()}[name.lower()]


def independent_hmac(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def fake_doc(status="flagged", actions=(), steps=()) -> dict:
    return {"format": rec.FORMAT, "ops_id": "test-ops", "started_at": "2026-11-02T03:15:00Z",
            "finished_at": "2026-11-02T03:16:00Z", "status": status, "exit_code": 1,
            "steps": list(steps), "human_actions": list(actions)}


# ============================================================================================
# the message
# ============================================================================================
def test_the_signature_verifies_against_an_independent_hmac_of_the_exact_body(
        site, env, monkeypatch, capsys):
    configure(site, target())
    fx = Contract()
    hosts = wire(monkeypatch, fx)
    code, _, _ = _cycle(site, capsys)
    assert code == 1 and len(fx.calls) == 1 and hosts == [HOST]
    call = fx.calls[0]
    assert call["url"] == URL
    assert hdr(call, "X-NeuralBridge-Signature") == independent_hmac(SECRET, call["body"])
    assert hdr(call, "Content-Type") == "application/json"
    uuid.UUID(hdr(call, "X-NeuralBridge-Delivery"))
    payload = json.loads(call["body"])
    cid = payload["cycle_id"]
    assert hdr(call, "Idempotency-Key") == f"{cid}:oncall"
    assert hdr(call, "Authorization") == f"Bearer {TOKEN}"
    # the body is canonical: exactly what a receiver re-hashing the raw bytes sees
    assert call["body"] == json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    # and record_sha256 is the hash of the stored line without its `notifications` field
    stored = json.loads(site.record.read_text().splitlines()[-1])
    assert stored["status"] == payload["status"] == "flagged"
    bare = {k: v for k, v in stored.items() if k != "notifications"}
    assert payload["record_sha256"] == hashlib.sha256(
        json.dumps(bare, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_a_wrong_secret_does_not_verify():
    body = b'{"a":1}'
    assert independent_hmac("one", body) != notify.sign("two", body)
    assert independent_hmac("one", body) == notify.sign("one", body)


def test_the_payload_carries_no_secret_path_ledger_or_step_detail(
        site, env, monkeypatch, capsys):
    monkeypatch.setenv("ASSURANCE_ATTEST_PASSPHRASE", "ZZ-FAKE-PASSPHRASE-7f3a91")
    site.cfg["attest"]["passphrase_env"] = "ASSURANCE_ATTEST_PASSPHRASE"
    configure(site, target())
    fx = Contract()
    wire(monkeypatch, fx)
    _cycle(site, capsys)
    body = fx.calls[0]["body"].decode()
    key_lines = [ln.strip() for ln in site.key.read_text().splitlines()
                 if len(ln.strip()) > 8 and not ln.startswith("-----")]
    assert key_lines
    planted = [*key_lines, SECRET, TOKEN, URL_TOKEN, "ZZ-FAKE-PASSPHRASE-7f3a91",
               str(site.root), str(site.key), str(site.data), str(site.keydir),
               site.accounts[0], "acc_", "tenants", "service.pem", "backups", "attestations",
               "PRIVATE KEY", "/srv", "manifest_sha256", "key_fingerprint", "duration_s",
               "exit_code", "command", "detail", "info"]
    for needle in planted:
        assert needle not in body, needle
    payload = json.loads(body)
    assert set(payload) == {"schema", "kind", "cycle_id", "ops_id", "started_at", "finished_at",
                            "status", "steps", "human_actions", "human_actions_omitted",
                            "record_sha256", "not_established"}
    assert all(set(s) == {"name", "status"} for s in payload["steps"])
    assert [s["name"] for s in payload["steps"]] == [
        s["name"] for s in json.loads(site.record.read_text())["steps"]]


def test_finding_text_is_neutralised_path_masked_and_truncated():
    hostile = {"step": "watch.run:w.json", "ref": "SN-1\x1b[31m\nINJECT",
               "action": "see /home/ops/keys/service.pem and /var/lib/x/acc_0123456789abcdef.db"
                         " then " + "A" * 900 + "\r\nforged: line"}
    payload = notify.build_payload(fake_doc(actions=[hostile] * 60))
    assert payload["human_actions_omitted"] == 10 and len(payload["human_actions"]) == 50
    a = payload["human_actions"][0]
    blob = json.dumps(payload)
    assert "service.pem" not in blob and "/home/" not in blob and "acc_0123" not in blob
    assert "<path>" in a["action"] and len(a["action"]) <= 400 and len(a["ref"]) <= 120
    for text in (a["action"], a["ref"]):
        assert not any(ord(c) < 32 for c in text)
    # a field that is not on the allow-list never travels
    doc = fake_doc(steps=[{"name": "backup", "status": "ok", "detail": "SECRET-DETAIL",
                           "info": {"directory": "/srv/b"}, "command": "x --key /k.pem"}])
    assert "SECRET-DETAIL" not in json.dumps(notify.build_payload(doc))


def test_the_extra_header_value_never_reaches_the_record_output_outbox_or_an_error(
        site, env, monkeypatch, capsys):
    configure(site, target())
    wire(monkeypatch, Contract(RuntimeError(f"boom {TOKEN} {SECRET} {URL_TOKEN}")))
    code, out, err = _cycle(site, capsys, "--json")
    assert code == 1
    everything = out + err + site.record.read_text() + (
        site.record.with_name("cycles.jsonl.outbox.jsonl").read_text())
    for needle in (TOKEN, SECRET, URL_TOKEN):
        assert needle not in everything
    note = site.cycles()[-1]["notifications"][0]
    assert note["status"] == "failed" and note["error_class"] == "RuntimeError"
    assert note["http_status"] is None and note["attempts"] == 1


# ============================================================================================
# configuration
# ============================================================================================
@pytest.mark.parametrize("mutate, message", [
    (lambda t: t.update(url=f"http://{HOST}/x"), "https URL"),
    (lambda t: t.update(url=f"https://user:pw@{HOST}/x"), "https URL"),
    (lambda t: t.update(url=f"https://{HOST}:8443/x"), "https URL"),
    (lambda t: t.update(allow_host="other.example.invalid"), "equal the host"),
    (lambda t: t.update(allow_host=f"x.{HOST}"), "equal the host"),
    (lambda t: t.update(allow_host="example.invalid"), "equal the host"),
    (lambda t: t.update(allow_host="*.example.invalid"), "allow_host"),
    (lambda t: t.pop("allow_host"), "allow_host"),
    (lambda t: t.pop("secret_env"), "secret_env"),
    (lambda t: t.update(on=["ok"]), "notify[0].on"),
    (lambda t: t.update(on=[]), "notify[0].on"),
    (lambda t: t.update(format="slack"), "format"),
    (lambda t: t.update(colour="red"), "unknown key"),
    (lambda t: t.update(secret_env="sk_live_abcdefghijklmnop"),  # noqa: S106
     "secret_env"),
    (lambda t: t.update(headers_env="Bearer abc def"), "headers_env"),
])
def test_a_bad_notify_block_is_refused_without_echoing_a_value(site, capsys, mutate, message):
    t = target()
    mutate(t)
    configure(site, t)
    before = site.tree()
    capsys.readouterr()
    code = assurance_main(["ops", "cycle", "--config", str(site.cfg_path)])
    out = capsys.readouterr()
    assert code == 2 and message in out.err
    for needle in (URL_TOKEN, "sk_live_abcdefghijklmnop", "pw@"):
        assert needle not in out.err + out.out
    assert site.tree() == before            # nothing was run or written


def test_duplicate_target_names_are_refused(site):
    configure(site, target(), target())
    with pytest.raises(OpsConfigError, match="duplicates"):
        load_config(site.cfg_path)


def test_defaults_on_both_statuses_and_json_format(site):
    configure(site, target())
    t = load_config(site.cfg_path).notify[0]
    assert t.on == ("flagged", "degraded") and t.format == "json"
    assert URL_TOKEN not in repr(t)


# ============================================================================================
# the real transport: POST rules (scripted opener = contract fixture)
# ============================================================================================
class PostOpener(Opener):
    def open(self, request, timeout=None):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        self.methods = getattr(self, "methods", []) + [request.get_method()]
        self.bodies = getattr(self, "bodies", []) + [request.data]
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def real(opener, **kw):
    sleeps: list[float] = []
    t = UrllibTransport(allowed_hosts=[HOST], opener=opener, sleep=sleeps.append, retries=2,
                        backoff=2.0, max_wait=30.0, **kw)
    t.sleeps = sleeps
    return t


def test_post_sends_the_exact_body_with_method_post_and_returns_status():
    op = PostOpener(Resp(b"ok", status=202))
    assert real(op).post(URL, {"X-A": "1"}, b'{"x":1}', 5) == (202, b"ok")
    assert op.methods == ["POST"] and op.bodies == [b'{"x":1}'] and op.requests[0][2] == 5


@pytest.mark.parametrize("url", [f"http://{HOST}/x", "https://other.example.invalid/x",
                                 f"https://{HOST}.evil.example/x", f"https://u:p@{HOST}/x",
                                 f"https://{HOST}:8443/x"])
def test_post_to_anything_but_the_exact_https_host_is_refused_before_a_request(url):
    op = PostOpener()
    with pytest.raises(TransportError):
        real(op).post(url, {}, b"{}", 5)
    assert op.requests == []


def test_a_redirect_is_never_followed_for_post():
    op = PostOpener(http_error(307, Location="https://evil.example/x"), Resp())
    with pytest.raises(RedirectRefused):
        real(op).post(URL, {}, b"{}", 5)
    assert len(op.requests) == 1
    # the real default handler (not the scripted opener) refuses outright, even same-host
    for target_url in ("https://evil.example/x", f"https://{HOST}/other"):
        with pytest.raises(RedirectRefused):
            _NoRedirect().redirect_request(urllib.request.Request(URL, data=b"x"), None, 307,
                                           "Temporary", headers(), target_url)
    assert any(isinstance(h, _NoRedirect) for h in UrllibTransport(
        allowed_hosts=[HOST])._post_opener.handlers)


def test_429_retry_after_is_honoured_and_bounded():
    op = PostOpener(http_error(429, Retry_After="7"), Resp(b"", status=200))
    t = real(op)
    assert t.post(URL, {}, b"{}", 5)[0] == 200 and t.sleeps == [7.0]
    op = PostOpener(http_error(429, b"slow", Retry_After="3600"), Resp())
    t = real(op)
    assert t.post(URL, {}, b"{}", 5) == (429, b"slow")      # told to wait longer than we will
    assert t.sleeps == [] and len(op.requests) == 1


def test_a_response_larger_than_the_cap_does_not_hide_a_2xx_delivery():
    cfg_t = type("T", (), {"url": URL, "name": "n"})()
    big = UrllibTransport(allowed_hosts=[HOST], opener=PostOpener(Resp(b"x" * 100)),
                          max_bytes=10, sleep=lambda s: None)
    res = notify._post(big, cfg_t, b"{}", "k", SECRET, {})
    assert res.ok and res.http_status == 200


def test_a_transport_error_message_carries_no_header_or_body(site, env, monkeypatch, capsys):
    op = PostOpener(*[__import__("urllib").error.URLError(TimeoutError("t")) for _ in range(3)])
    t = real(op)
    with pytest.raises(TransportError) as exc:
        t.post(URL, {"Authorization": f"Bearer {TOKEN}"}, b'{"secret":"S"}', 5)
    assert TOKEN not in str(exc.value) and '"S"' not in str(exc.value)


# ============================================================================================
# delivery semantics
# ============================================================================================
def outbox(site: Site) -> Path:
    return Path(f"{site.record}.outbox.jsonl")


def test_5xx_is_retried_then_owed_then_delivered_next_cycle_with_the_same_key(
        site, env, monkeypatch, capsys):
    configure(site, target())
    op = PostOpener(*[http_error(503, b"busy") for _ in range(3)])
    sleeps: list[float] = []
    monkeypatch.setattr(notify, "make_transport", lambda host: UrllibTransport(
        allowed_hosts=[host], opener=op, sleep=sleeps.append, retries=2, backoff=2.0))
    code, _, _ = _cycle(site, capsys)
    assert code == 1                                         # the cycle result is untouched
    n1 = site.cycles()[-1]["notifications"][0]
    assert (n1["status"], n1["http_status"], n1["attempts"], n1["retry"]) == ("failed", 503, 1,
                                                                             False)
    assert n1["error_class"] == "HttpStatus" and len(op.requests) == 3 and sleeps == [2.0, 4.0]
    first_key = {k.lower(): v for k, v in op.requests[0][1].items()}["idempotency-key"]
    first_body = op.bodies[0]
    assert notify.outbox_state(load_config(site.cfg_path))["open"][0]["attempts"] == 1

    op2 = PostOpener(Resp(b"", status=200))
    monkeypatch.setattr(notify, "make_transport", lambda host: UrllibTransport(
        allowed_hosts=[host], opener=op2, sleep=lambda s: None, retries=2))
    code, _, _ = _cycle(site, capsys)
    assert code == 0                                         # quiet cycle; the retry still goes
    sent = {k.lower(): v for k, v in op2.requests[0][1].items()}
    assert sent["idempotency-key"] == first_key and op2.bodies[0] == first_body
    assert sent["x-neuralbridge-signature"] == independent_hmac(SECRET, first_body)
    n2 = site.cycles()[-1]["notifications"][0]
    assert (n2["status"], n2["attempts"], n2["retry"]) == ("delivered", 2, True)
    assert notify.outbox_state(load_config(site.cfg_path)) == {"open": [], "abandoned": []}
    # a third cycle owes and sends nothing
    _cycle(site, capsys)
    assert len(op2.requests) == 1 and site.cycles()[-1]["notifications"] == []


def test_a_message_is_abandoned_after_five_attempts_and_status_says_so(
        site, env, monkeypatch, capsys):
    configure(site, target())
    cfg = load_config(site.cfg_path)
    fx = Contract(*[500] * 20)
    outs = []
    outs.append(notify.deliver(cfg, fake_doc(), transport_factory=lambda h: fx, environ={
        "NB_SECRET": SECRET, "NB_HDRS": EXTRA}))
    for _ in range(6):
        outs.append(notify.deliver(cfg, fake_doc("ok"), transport_factory=lambda h: fx,
                                   environ={"NB_SECRET": SECRET, "NB_HDRS": EXTRA}))
    assert len(fx.calls) == notify.MAX_ATTEMPTS == 5        # no sixth attempt
    assert [o[0]["attempts"] for o in outs[:5]] == [1, 2, 3, 4, 5]
    assert outs[4][0].get("abandoned") is True and outs[5] == [] and outs[6] == []
    assert {c["headers"]["Idempotency-Key"] for c in fx.calls} == {"test-ops-20261102T031500Z:oncall"}
    state = notify.outbox_state(cfg)
    assert state["open"] == [] and state["abandoned"][0]["attempts"] == 5
    capsys.readouterr()
    assert assurance_main(["ops", "status", "--config", str(site.cfg_path)]) == 2
    text = capsys.readouterr().out
    assert "ABANDONED after 5 attempts" in text and "oncall" in text


def test_a_failure_never_changes_the_exit_code_or_hides_the_cycle(
        site, env, monkeypatch, capsys):
    configure(site, target())
    wire(monkeypatch, Contract(*[ConnectionResetError("x")] * 3))
    code, out, _ = _cycle(site, capsys)
    assert code == 1 and "cycle FLAGGED" in out and "NOTIFICATIONS" in out
    assert "failed" in out and "ConnectionResetError" in out
    doc = site.cycles()[-1]
    assert (doc["status"], doc["exit_code"]) == ("flagged", 1) and doc["human_actions"]
    # even if the messenger itself blows up, the record is written and the code is unchanged
    monkeypatch.setattr(notify, "deliver", lambda *a, **k: (_ for _ in ()).throw(KeyError("k")))
    _break_chain(site)
    code, _, _ = _cycle(site, capsys)
    assert code == 2 and site.cycles()[-1]["status"] == "degraded"
    assert site.cycles()[-1]["notifications"][0]["error_class"] == "KeyError"


def test_an_unset_secret_skips_that_target_and_the_others_are_still_sent(
        site, monkeypatch, capsys):
    monkeypatch.setenv("NB_OTHER", "another-secret-value-1234")
    monkeypatch.delenv("NB_SECRET", raising=False)
    monkeypatch.delenv("NB_HDRS", raising=False)
    configure(site, target("first"),
              target("second", secret_env="NB_OTHER", headers_env=None))  # noqa: S106
    fx = Contract()
    wire(monkeypatch, fx)
    code, out, _ = _cycle(site, capsys)
    assert code == 1
    notes = {n["target"]: n for n in site.cycles()[-1]["notifications"]}
    assert notes["first"]["status"] == "skipped"
    assert notes["first"]["reason"] == "secret_env not set" and notes["first"]["attempts"] == 0
    assert notes["second"]["status"] == "delivered" and len(fx.calls) == 1
    assert hdr(fx.calls[0], "Idempotency-Key").endswith(":second")
    assert not outbox(site).exists()                         # a skip is not owed a retry
    assert "skipped" in out


def test_an_unset_headers_env_is_skipped_not_sent_unauthenticated(site, monkeypatch, capsys):
    monkeypatch.setenv("NB_SECRET", SECRET)
    monkeypatch.delenv("NB_HDRS", raising=False)
    configure(site, target())
    fx = Contract()
    wire(monkeypatch, fx)
    _cycle(site, capsys)
    note = site.cycles()[-1]["notifications"][0]
    assert note["status"] == "skipped" and note["reason"] == "headers_env not set"
    assert fx.calls == []


@pytest.mark.parametrize("bad", ["no colon line", "Content-Type: text/plain",
                                 "Idempotency-Key: x", "X-NeuralBridge-Signature: y",
                                 "Bad Name: v", "Authorization:"])
def test_malformed_or_reserved_extra_headers_are_skipped(site, monkeypatch, capsys, bad):
    monkeypatch.setenv("NB_SECRET", SECRET)
    monkeypatch.setenv("NB_HDRS", bad)
    configure(site, target())
    fx = Contract()
    wire(monkeypatch, fx)
    _cycle(site, capsys)
    assert site.cycles()[-1]["notifications"][0]["reason"] == "headers_env malformed"
    assert fx.calls == []


def test_the_on_filter_is_respected_and_quiet_cycles_send_nothing(
        site, env, monkeypatch, capsys):
    configure(site, target("only_degraded", on=["degraded"]), target("both"))
    fx = Contract()
    wire(monkeypatch, fx)
    _cycle(site, capsys)                                     # flagged
    assert [hdr(c, "Idempotency-Key").rsplit(":", 1)[1] for c in fx.calls] == ["both"]
    fx.calls.clear()
    _cycle(site, capsys)                                     # ok
    assert fx.calls == [] and site.cycles()[-1]["notifications"] == []
    _break_chain(site)
    _cycle(site, capsys)                                     # degraded
    assert sorted(hdr(c, "Idempotency-Key").rsplit(":", 1)[1] for c in fx.calls) == [
        "both", "only_degraded"]


def test_a_dry_run_cycle_sends_and_writes_nothing(site, env, monkeypatch, capsys):
    configure(site, target())
    fx = Contract()
    wire(monkeypatch, fx)
    before = site.tree()
    code, out, _ = _cycle(site, capsys, "--dry-run")
    assert code == 0 and fx.calls == [] and site.tree() == before
    assert "oncall" in out and "nothing is sent" in out and URL_TOKEN not in out


def test_the_record_gains_notifications_and_earlier_lines_stay_byte_identical(
        site, env, monkeypatch, capsys):
    _cycle(site, capsys)                                     # before any notify config
    first = site.record.read_bytes()
    assert "notifications" not in json.loads(first)
    configure(site, target())
    wire(monkeypatch, Contract())
    _break_chain(site)
    _cycle(site, capsys)
    after = site.record.read_bytes()
    assert after.startswith(first) and len(after.splitlines()) == 2
    second = json.loads(after.splitlines()[1])
    assert second["notifications"][0]["status"] == "delivered"
    assert set(second["notifications"][0]) >= {"target", "status", "http_status", "attempts",
                                              "delivery_id", "error_class"}
    assert rec.read(site.record).unreadable_lines == []


# ============================================================================================
# ops status
# ============================================================================================
def test_status_shows_notification_failures_and_what_is_owed(site, env, monkeypatch, capsys):
    configure(site, target())
    wire(monkeypatch, Contract(503))
    _cycle(site, capsys)
    capsys.readouterr()
    code = assurance_main(["ops", "status", "--config", str(site.cfg_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 1                                         # status exit code is unchanged
    nf = doc["notifications"]
    assert nf["last_cycle_failures"][0]["http_status"] == 503
    assert nf["retry_pending"][0]["target"] == "oncall" and nf["abandoned"] == []
    assert SECRET not in json.dumps(doc) and URL_TOKEN not in json.dumps(doc)
    assurance_main(["ops", "status", "--config", str(site.cfg_path)])
    text = capsys.readouterr().out
    assert "NOTIFICATIONS" in text and "owed, retried next cycle" in text


# ============================================================================================
# check and notify-test
# ============================================================================================
def test_check_validates_notify_and_lists_what_it_does_not_check(site, monkeypatch, capsys):
    monkeypatch.delenv("NB_SECRET", raising=False)
    monkeypatch.setenv("NB_HDRS", "Authorization: Bearer x")
    configure(site, target())
    site.cfg_path.chmod(0o600)
    capsys.readouterr()
    code = assurance_main(["ops", "check", "--config", str(site.cfg_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    by = {c["name"]: c for c in doc["checks"]}
    assert code == 0
    assert by["notify.oncall.url"]["status"] == "ok"
    assert by["notify.oncall.secret_env"]["status"] == "warn"
    assert "not set" in by["notify.oncall.secret_env"]["detail"]
    assert by["notify.oncall.headers_env"]["status"] == "ok"
    assert by["notify.oncall.url_secret"]["status"] == "warn"      # the path looks like a token
    joined = " ".join(doc["not_checked"])
    for needle in ("receiver exists", "authenticates", "anyone reads"):
        assert needle in joined
    assert URL_TOKEN not in json.dumps(doc) and "Bearer x" not in json.dumps(doc)


def test_check_fails_on_a_malformed_headers_env(site, monkeypatch, capsys):
    monkeypatch.setenv("NB_SECRET", SECRET)
    monkeypatch.setenv("NB_HDRS", "no colon here")
    configure(site, target())
    capsys.readouterr()
    code = assurance_main(["ops", "check", "--config", str(site.cfg_path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 1 and any(c["name"] == "notify.oncall.headers_env_format"
                             and c["status"] == "fail" for c in doc["checks"])
    assert "no colon here" not in json.dumps(doc)


def test_notify_test_is_a_dry_run_unless_live_and_masks_the_signature(
        site, env, monkeypatch, capsys):
    configure(site, target())
    fx = Contract()
    wire(monkeypatch, fx)
    capsys.readouterr()
    code = assurance_main(["ops", "notify-test", "--config", str(site.cfg_path),
                           "--target", "oncall"])
    out = capsys.readouterr().out
    assert code == 0 and fx.calls == [] and "DRY RUN" in out
    assert re.search(r"sha256=<hmac of \d+ bytes>", out)
    for needle in (SECRET, TOKEN, URL_TOKEN):
        assert needle not in out
    assert '"status":"test"' in out and "TEST message" in out


def test_notify_test_live_sends_a_labelled_test_without_record_contents(
        site, env, monkeypatch, capsys):
    configure(site, target())
    wire(monkeypatch, Contract())
    _cycle(site, capsys)                                     # a record with real contents exists
    fx = Contract()
    wire(monkeypatch, fx)
    capsys.readouterr()
    code = assurance_main(["ops", "notify-test", "--config", str(site.cfg_path),
                           "--target", "oncall", "--live"])
    out = capsys.readouterr().out
    assert code == 0 and len(fx.calls) == 1 and "TEST to oncall: delivered" in out
    call = fx.calls[0]
    payload = json.loads(call["body"])
    assert payload["kind"] == "test" and payload["status"] == "test"
    assert "steps" not in payload and "human_actions" not in payload
    assert hdr(call, "X-NeuralBridge-Signature") == independent_hmac(SECRET, call["body"])
    assert not outbox(site).exists()                         # a test is never retried


def test_notify_test_failure_unknown_target_and_unset_secret(site, env, monkeypatch, capsys):
    configure(site, target())
    wire(monkeypatch, Contract(500))
    argv = ["ops", "notify-test", "--config", str(site.cfg_path), "--target", "oncall",
            "--live"]
    assert assurance_main(argv) == 1
    assert assurance_main(["ops", "notify-test", "--config", str(site.cfg_path),
                           "--target", "nope"]) == 2
    monkeypatch.delenv("NB_SECRET")
    capsys.readouterr()
    assert assurance_main(argv) == 2
    assert "secret_env not set" in capsys.readouterr().out


# ============================================================================================
# no socket, no network client at import
# ============================================================================================
def test_the_real_transport_under_a_blocked_socket_fails_closed_with_a_class_only(
        site, env, monkeypatch, capsys):
    configure(site, target())
    monkeypatch.setattr(notify, "make_transport", lambda host: UrllibTransport(
        allowed_hosts=[host], sleep=lambda s: None, retries=1))
    code, out, err = _cycle(site, capsys)
    assert code == 1                                         # unchanged
    note = site.cycles()[-1]["notifications"][0]
    assert note["status"] == "failed" and note["error_class"] == "TransportError"
    assert URL_TOKEN not in out + err + site.record.read_text()


def test_a_subprocess_cycle_with_the_network_blocked_and_no_secret_sends_nothing(
        site, tmp_path):
    configure(site, target())
    r = site.sh("ops", "cycle", "--config", site.cfg_path, guard=_guard(tmp_path))
    assert r.returncode == 1, r.stdout + r.stderr
    note = json.loads(site.record.read_text().splitlines()[0])["notifications"][0]
    assert note["status"] == "skipped" and note["reason"] == "secret_env not set"
    assert "NO NETWORK" not in r.stdout + r.stderr


def test_importing_ops_and_notify_loads_no_network_client():
    import os
    import subprocess
    import sys

    src = str(Path(__file__).resolve().parents[1] / "src")
    code = ("import sys; import assurance.ops.cli, assurance.ops.cycle, assurance.ops.check, "
            "assurance.ops.notify; "
            "bad = [m for m in ('socket','ssl','http.client','urllib.request','httpx','requests',"
            "'urllib3') if m in sys.modules]; print(bad)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,  # noqa: S603
                       env={"PYTHONPATH": src, "PATH": os.environ.get("PATH", "")}, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "[]", r.stdout
