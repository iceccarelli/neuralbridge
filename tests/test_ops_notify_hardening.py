"""Webhook hardening: path masking, the signed timestamp (replay window), outbox compaction.

All transports are CONTRACT FIXTURES (in-memory); nothing here opens a socket or reaches a vendor.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from assurance.core.identity import format_utc, utc_now
from assurance.ops import notify
from assurance.ops.config import load_config

from .test_ops_notify import SECRET, Contract, fake_doc, hdr, independent_hmac, site  # noqa: F401
from .test_ops_notify_formats import cfg_for, doc_with, env_for, send

# ------------------------------------------------------------------ path masking
HOSTILE = [
    "./secrets/attest.key",
    "../keys/a.pem",
    "C:\\keys\\svc.pem",
    "c:/keys/svc.pem",
    "\\\\fileserver\\share\\ledger.jsonl",
    "tenants/acc_0123456789abcdef.db",
    "/srv/data/tenants/acc_0123456789abcdef.db",
    "~/keys/attest.key",
    "/var/lib/my keys/svc.key",
    "attest.key",
    "store.sqlite",
    "cert.p12",
    "cert.pfx",
    "ledger.jsonl",
    "/etc/passwd",
]


@pytest.mark.parametrize("path", HOSTILE)
def test_each_path_form_is_masked_in_finding_text(path):
    action = f"read {path} then close"
    payload = notify.build_payload(fake_doc(actions=[
        {"step": "s", "ref": "r", "action": action}]))
    text = json.dumps(payload)
    # no distinctive fragment of the path survives
    for frag in ("secrets", "keys", "attest", "acc_0123", "fileserver", "svc.", "ledger",
                 "passwd", "cert.", "store."):
        if frag in path:
            assert frag not in text.replace("not_established", ""), (path, text)
    assert "<path>" in payload["human_actions"][0]["action"]
    assert payload["human_actions"][0]["action"].startswith("read ")
    assert payload["human_actions"][0]["action"].endswith(" then close")


def test_a_path_with_a_space_is_masked_through_every_token():
    out = notify.mask_paths("see /var/lib/my keys/svc.key now")
    assert "keys" not in out and "svc" not in out and out.startswith("see ")
    assert out.endswith(" now")


def test_a_quoted_path_with_spaces_is_masked_whole():
    assert notify.mask_paths('open "/var/lib/my secret dir/x" ok') == 'open "<path>" ok'
    assert notify.mask_paths("open 'C:\\Program Files\\NB\\a b.key' ok") == "open '<path>' ok"


def test_urls_and_plain_prose_are_left_alone():
    text = "read new finding ADV-2026-001 (watch w1); see https://vendor.example/advisory/1."
    assert notify.mask_paths(text) == text


# ------------------------------------------------------------------ timestamped signature
def test_json_slack_and_teams_are_signed_over_timestamp_dot_body(site):  # noqa: F811
    for fmt in ("json", "slack", "teams"):
        _, t, _ = send(site, fmt, doc_with({"step": "s", "ref": "r", "action": "a"}))
        call = t.calls[0]
        ts = hdr(call, "X-NeuralBridge-Timestamp")
        assert ts.isdigit()
        assert abs(int(ts) - utc_now().timestamp()) < 60
        sig = hdr(call, "X-NeuralBridge-Signature")
        assert sig == independent_hmac(SECRET, call["body"], ts)
        # the old body-only scheme must NOT verify
        import hashlib
        import hmac
        body_only = "sha256=" + hmac.new(SECRET.encode(), call["body"], hashlib.sha256).hexdigest()
        assert sig != body_only


def test_pagerduty_has_no_signature_or_timestamp_and_keeps_its_dedup_key(site):  # noqa: F811
    _, t, _ = send(site, "pagerduty", doc_with({"step": "s", "ref": "r", "action": "a"}))
    names = {k.lower() for k in t.calls[0]["headers"]}
    assert "x-neuralbridge-signature" not in names and "x-neuralbridge-timestamp" not in names
    assert json.loads(t.calls[0]["body"])["dedup_key"]


def test_the_receiver_check_rejects_a_stale_future_or_forged_timestamp():
    body = b'{"a":1}'
    now = 1_800_000_000
    ts = now - 10
    sig = independent_hmac("k", body, ts)
    assert notify.verify("k", body, sig, str(ts), now)
    assert not notify.verify("other", body, sig, str(ts), now)
    # a captured request replayed later
    assert not notify.verify("k", body, sig, str(ts), now + 301)
    assert notify.verify("k", body, sig, str(ts), now + 290)
    # a replayer who refreshes the header cannot also refresh the MAC
    assert not notify.verify("k", body, sig, str(now), now)
    # a far-future timestamp, junk, empty
    far = now + 10_000
    assert not notify.verify("k", body, independent_hmac("k", body, far), str(far), now)
    for junk in ("", "abc", "-5", "1.5", " 12", "9" * 40):
        assert not notify.signature_fresh(junk, now)


def test_a_retry_is_signed_with_a_fresh_timestamp_but_the_same_body_and_key(site, monkeypatch):  # noqa: F811
    monkeypatch.setenv("NB_SECRET", SECRET)
    cfg = cfg_for(site, "json")
    env = env_for("json")
    failing = Contract(503)
    notify.deliver(cfg, doc_with({"step": "s", "ref": "r", "action": "a"}),
                   transport_factory=lambda h: failing, environ=env)
    ok = Contract(200)
    notify.deliver(cfg, fake_doc(status="ok"), transport_factory=lambda h: ok, environ=env)
    first, second = failing.calls[0], ok.calls[0]
    assert first["body"] == second["body"]
    assert hdr(first, "Idempotency-Key") == hdr(second, "Idempotency-Key")
    ts2 = hdr(second, "X-NeuralBridge-Timestamp")
    assert hdr(second, "X-NeuralBridge-Signature") == independent_hmac(SECRET, second["body"], ts2)
    assert notify.verify(SECRET, second["body"], hdr(second, "X-NeuralBridge-Signature"), ts2,
                         utc_now().timestamp())


def test_the_timestamp_header_name_is_reserved_for_operators():
    with pytest.raises(ValueError):
        notify.parse_header_lines("X-NeuralBridge-Timestamp: 1")


# ------------------------------------------------------------------ outbox compaction
def _line(**kw) -> str:
    return json.dumps(kw, sort_keys=True, separators=(",", ":"))


def _item(key: str, at, final: str | None) -> list[str]:
    lines = [_line(o="pending", key=key, target="oncall", cycle_id=key, body="{}", at=at),
             _line(o="attempt", key=key, status="failed", attempts=1, at=at)]
    if final == "delivered":
        lines.append(_line(o="attempt", key=key, status="delivered", attempts=2, at=at))
    elif final == "abandoned":
        lines.append(_line(o="abandoned", key=key, reason="max_attempts", at=at))
    return lines


def test_old_delivered_and_abandoned_items_are_dropped_everything_else_is_kept(tmp_path):
    now = utc_now()
    old = format_utc(now - timedelta(days=31))
    recent = format_utc(now - timedelta(days=29))
    path = tmp_path / "rec.jsonl.outbox.jsonl"
    lines = (_item("old-del", old, "delivered") + _item("old-aban", old, "abandoned")
             + _item("old-open", old, None) + _item("new-del", recent, "delivered")
             + _item("new-aban", recent, "abandoned") + ["not json {{{"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert notify.compact_outbox(path, now) == 2
    kept = path.read_text(encoding="utf-8").splitlines()
    assert kept == [ln for ln in lines
                    if not ('"old-del"' in ln or '"old-aban"' in ln)]
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert not list(tmp_path.glob("*.tmp"))
    # idempotent
    assert notify.compact_outbox(path, now) == 0


def test_compaction_never_touches_an_outbox_with_nothing_old(tmp_path):
    now = utc_now()
    path = tmp_path / "o.jsonl"
    path.write_text("\n".join(_item("a", format_utc(now), "delivered")) + "\n")
    before = path.read_bytes()
    assert notify.compact_outbox(path, now) == 0 and path.read_bytes() == before
    assert notify.compact_outbox(tmp_path / "missing.jsonl", now) == 0
    assert not (tmp_path / "missing.jsonl").exists()


def test_the_next_cycle_compacts_the_outbox(site, monkeypatch):  # noqa: F811
    monkeypatch.setenv("NB_SECRET", SECRET)
    cfg = cfg_for(site, "json")
    old = format_utc(utc_now() - timedelta(days=45))
    cfg.outbox.parent.mkdir(parents=True, exist_ok=True)
    cfg.outbox.write_text("\n".join(_item("old-del", old, "delivered")
                                    + _item("open-one", old, None)) + "\n")
    t = Contract(200)
    notify.deliver(load_config(site.cfg_path), fake_doc(status="ok"),
                   transport_factory=lambda h: t, environ=env_for("json"))
    text = cfg.outbox.read_text()
    assert "old-del" not in text
    # the still-open old item was retried (not dropped); its delivery is appended afterwards
    assert "open-one" in text
