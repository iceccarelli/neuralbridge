"""``notify`` format adapters: slack, teams, pagerduty (and json unchanged).

The golden files under ``tests/fixtures/ops_notify/`` are CONTRACT FIXTURES derived from the
vendors' PUBLISHED request schemas (Slack incoming webhooks: ``{"text"}``; Microsoft Teams
webhook/Workflows: ``{"text"}``; PagerDuty Events API v2 enqueue: ``routing_key``, ``event_action``,
``dedup_key``, ``payload{summary, source, severity, custom_details}``). They have NOT been verified
against a live Slack, Teams or PagerDuty account; no vendor endpoint was contacted. The transport
is an in-memory recorder and an autouse fixture makes any socket operation raise.
"""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path

import pytest

from assurance.ops import formats, notify
from assurance.ops.config import OpsConfigError, load_config

from .test_ops_cycle import Site
from .test_ops_notify import (
    EXTRA,
    SECRET,
    Contract,
    configure,
    fake_doc,
    hdr,
    independent_hmac,
    target,
)

FIX = Path(__file__).parent / "fixtures" / "ops_notify"
RKEY = "ZZ-FAKE-ROUTING-KEY-0123456789ab"        # 32 characters, fake
HOSTILE = ("<!channel> <!here> <!everyone> <@U123> @channel @here [click](http://evil.example/x) "
           "![i](https://evil.example/i.png) <http://evil.example|login> `rm -rf` *b* _i_ ~s~ "
           "www.evil.example & more\nnewline\r\n# heading | table | www.x.io")


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


def env_for(fmt: str) -> dict[str, str]:
    return {"NB_SECRET": RKEY if fmt == "pagerduty" else SECRET, "NB_HDRS": EXTRA}


def cfg_for(site: Site, fmt: str, **kw):
    configure(site, target(format=fmt, **kw))
    return load_config(site.cfg_path)


def doc_with(*actions, status="flagged", steps=None):
    steps = steps if steps is not None else [{"name": "ledger.verify", "status": "ok"},
                                             {"name": "watch.run_x", "status": status}]
    return fake_doc(status=status, steps=steps, actions=list(actions))


ACTION = {"step": "watch.run_x", "ref": "ADV-1",
          "action": "read new finding ADV-1. Nothing was opened"}


def send(site, fmt, doc, *, transport=None, environ=None):
    cfg = cfg_for(site, fmt)
    t = transport or Contract()
    entries = notify.deliver(cfg, doc, transport_factory=lambda h: t,
                             environ=environ or env_for(fmt))
    return cfg, t, entries


def golden(name: str, message: dict) -> dict:
    text = (FIX / name).read_text(encoding="utf-8")
    text = text.replace("@SHA@", message["record_sha256"]).replace("@NE@",
                                                                   message["not_established"])
    return json.loads(text)


# ============================================================================================
# golden bodies
# ============================================================================================
@pytest.mark.parametrize("fmt, fixture", [("slack", "slack_cycle.golden.json"),
                                          ("teams", "teams_cycle.golden.json")])
def test_chat_bodies_match_the_golden_contract_fixture(site, fmt, fixture):
    _, t, _ = send(site, fmt, doc_with(ACTION))
    body = json.loads(t.calls[0]["body"])
    assert set(body) == {"text"}
    assert body == json.loads((FIX / fixture).read_text(encoding="utf-8"))
    assert hdr(t.calls[0], "content-type") == "application/json"


def test_pagerduty_body_matches_the_golden_contract_fixture_and_has_exactly_the_documented_keys(
        site):
    doc = doc_with(ACTION)
    _, t, _ = send(site, "pagerduty", doc)
    body = json.loads(t.calls[0]["body"])
    assert set(body) == {"routing_key", "event_action", "dedup_key", "payload"}
    assert set(body["payload"]) == {"summary", "source", "severity", "custom_details"}
    message = notify.build_payload(doc)
    assert body == golden("pagerduty_cycle.golden.json", message)
    assert body["dedup_key"] == hdr(t.calls[0], "idempotency-key")
    assert set(body["payload"]["custom_details"]) == set(message) - {"schema"}


def test_json_format_is_unchanged(site):
    doc = doc_with(ACTION)
    _, t, _ = send(site, "json", doc)
    assert t.calls[0]["body"] == notify.encode(notify.build_payload(doc))


def test_no_new_data_enters_any_vendor_body(site):
    doc = doc_with(ACTION)
    doc["steps"][0]["detail"] = "SECRET-STEP-DETAIL /etc/assurance/keys/anchor.pem"
    doc["steps"][0]["command"] = "run --secret SECRET-COMMAND"
    doc["backup_dir"] = "/srv/assurance/backups"
    for fmt in formats.FORMATS:
        _, t, _ = send(site, fmt, doc)
        raw = t.calls[0]["body"].decode()
        for needle in ("SECRET-STEP-DETAIL", "SECRET-COMMAND", "anchor.pem", "/srv/assurance"):
            assert needle not in raw, (fmt, needle)


# ============================================================================================
# auth model
# ============================================================================================
@pytest.mark.parametrize("fmt", ["json", "slack", "teams"])
def test_json_slack_teams_still_hmac_sign_the_exact_body(site, fmt):
    _, t, _ = send(site, fmt, doc_with(ACTION))
    c = t.calls[0]
    assert hdr(c, "x-neuralbridge-signature") == independent_hmac(SECRET, c["body"], hdr(c, "x-neuralbridge-timestamp"))


def test_pagerduty_sends_no_signature_header_and_the_key_is_only_in_the_body(site):
    _, t, entries = send(site, "pagerduty", doc_with(ACTION))
    c = t.calls[0]
    assert "x-neuralbridge-signature" not in {k.lower() for k in c["headers"]}
    assert json.loads(c["body"])["routing_key"] == RKEY
    assert RKEY not in json.dumps(c["headers"]) and RKEY not in json.dumps(entries)
    assert hdr(c, "idempotency-key") and hdr(c, "x-neuralbridge-delivery")


@pytest.mark.parametrize("status, severity", [("flagged", "warning"), ("degraded", "error")])
def test_pagerduty_severity_mapping(site, status, severity):
    _, t, _ = send(site, "pagerduty", doc_with(ACTION, status=status))
    assert json.loads(t.calls[0]["body"])["payload"]["severity"] == severity
    assert formats.severity_for("test") == "info"


# ============================================================================================
# injection
# ============================================================================================
def hostile_doc():
    return doc_with({"step": HOSTILE, "ref": HOSTILE, "action": HOSTILE + HOSTILE},
                    steps=[{"name": HOSTILE, "status": "flagged"}])


def test_slack_text_has_no_mention_link_or_unescaped_markup(site):
    _, t, _ = send(site, "slack", hostile_doc())
    text = json.loads(t.calls[0]["body"])["text"]
    assert "<" not in text and ">" not in text                  # nothing can open <...> syntax
    assert not re.search(r"&(?!(amp|lt|gt);)", text)            # every & is an entity
    assert not re.search(r"@(?!\s)", text)                      # no @mention survives
    assert "://" not in text and "www." not in text            # no auto-link
    assert not any(c in text for c in "`*~_")                   # no mrkdwn formatting
    assert "&lt;!channel&gt;" in text                           # shown, inert
    assert "\r" not in text and text.count("\n") <= 6           # hostile newlines were escaped


def test_teams_text_has_no_mention_link_or_unescaped_markup(site):
    _, t, _ = send(site, "teams", hostile_doc())
    text = json.loads(t.calls[0]["body"])["text"]
    assert not re.search(r"@(?!\s)", text) and "://" not in text and "www." not in text
    for ch in "`*_[]()<>&|~#":
        for m in re.finditer(re.escape(ch), text):
            assert text[m.start() - 1] == "\\", (ch, text[max(0, m.start() - 5):m.start() + 5])
    assert "\r" not in text and text.count("\n") <= 6


def test_a_ten_thousand_character_finding_cannot_exceed_the_caps(site):
    big = "A" * 10_000
    doc = doc_with(*[{"step": "s", "ref": f"R{i}", "action": big} for i in range(60)])
    for fmt, cap in (("slack", formats.SLACK_TEXT_MAX), ("teams", formats.TEAMS_TEXT_MAX)):
        _, t, _ = send(site, fmt, doc)
        text = json.loads(t.calls[0]["body"])["text"]
        assert len(text) <= cap and re.search(r"… \(\d+ more\)", text), fmt
        assert text.endswith("it decides nothing.")             # the footer survives truncation
    _, t, _ = send(site, "pagerduty", doc)
    summary = json.loads(t.calls[0]["body"])["payload"]["summary"]
    assert len(summary) <= formats.PD_SUMMARY_MAX and re.search(r"… \(\d+ more\)$", summary)


def test_the_more_marker_counts_actions_dropped_and_those_omitted_by_the_payload():
    doc = doc_with(*[{"step": "s", "ref": f"R{i}", "action": "x" * 100} for i in range(60)])
    msg = notify.build_payload(doc)
    assert msg["human_actions_omitted"] == 10
    text = json.loads(formats.render("slack", msg, key="k").body)["text"]
    shown = text.count("•")
    assert f"… ({50 - shown + 10} more)" in text and shown < 50


def test_a_short_message_is_not_marked_truncated(site):
    for fmt in ("slack", "teams", "pagerduty"):
        _, t, _ = send(site, fmt, doc_with(ACTION))
        assert "more)" not in t.calls[0]["body"].decode()


# ============================================================================================
# the routing key is never persisted; the outbox retries per format
# ============================================================================================
@pytest.mark.parametrize("fmt", ["json", "slack", "teams", "pagerduty"])
def test_a_failed_send_is_owed_with_the_minimal_message_and_retried_with_the_same_key(site, fmt):
    doc = doc_with(ACTION)
    cfg, t, entries = send(site, fmt, doc, transport=Contract(503))
    assert entries[0]["status"] == "failed"
    first = t.calls[0]
    stored = cfg.outbox.read_text(encoding="utf-8")
    for secret in (RKEY, SECRET, EXTRA.split()[-1]):
        assert secret not in stored
    pending = json.loads(stored.splitlines()[0])
    assert json.loads(pending["body"])["schema"] == notify.PAYLOAD_SCHEMA   # canonical message
    t2 = Contract(200)
    entries2 = notify.deliver(cfg, fake_doc(status="ok"), transport_factory=lambda h: t2,
                              environ=env_for(fmt))
    assert entries2[0]["status"] == "delivered" and entries2[0]["retry"] is True
    again = t2.calls[0]
    assert hdr(again, "idempotency-key") == hdr(first, "idempotency-key")
    assert again["body"] == first["body"]                       # rebuilt identically
    if fmt == "pagerduty":
        b = json.loads(again["body"])
        assert b["dedup_key"] == hdr(first, "idempotency-key") and b["routing_key"] == RKEY
        assert "x-neuralbridge-signature" not in {k.lower() for k in again["headers"]}
    else:
        assert hdr(again, "x-neuralbridge-signature") == independent_hmac(SECRET, again["body"], hdr(again, "x-neuralbridge-timestamp"))


def test_the_routing_key_is_in_no_record_status_log_or_outbox_even_on_failure(site):
    cfg, t, entries = send(site, "pagerduty", doc_with(ACTION),
                           transport=Contract(RuntimeError(RKEY)))
    blob = json.dumps(entries) + json.dumps(notify.outbox_state(cfg)) + cfg.outbox.read_text()
    assert RKEY not in blob
    shown = notify.dry_run_request(cfg, cfg.notify[0], env_for("pagerduty"))
    assert RKEY not in json.dumps(shown)


def test_a_finding_text_equal_to_the_routing_key_is_scrubbed_from_the_message(site):
    doc = doc_with({"step": "s", "ref": "r", "action": f"leak {RKEY} here"})
    _, t, _ = send(site, "pagerduty", doc)
    body = json.loads(t.calls[0]["body"])
    assert RKEY not in json.dumps(body["payload"])
    assert body["routing_key"] == RKEY


# ============================================================================================
# config, check, dry run
# ============================================================================================
@pytest.mark.parametrize("fmt", ["json", "slack", "teams", "pagerduty"])
def test_the_four_formats_load(site, fmt):
    assert cfg_for(site, fmt).notify[0].format == fmt


@pytest.mark.parametrize("bad", ["servicenow_json", "xml", "Slack", "", 7, None])
def test_an_unknown_format_is_refused_at_config_without_echoing_it(site, bad):
    configure(site, target(format=bad))
    with pytest.raises(OpsConfigError, match="format must be one of") as exc:
        load_config(site.cfg_path)
    assert "servicenow_json is not built" in str(exc.value)


def test_a_vendor_host_is_not_trusted_the_url_host_must_still_equal_allow_host(site):
    configure(site, target(format="slack", url="https://hooks.slack.com/services/T/B/x",
                           allow_host="hooks.slack.com"))
    assert load_config(site.cfg_path).notify[0].allow_host == "hooks.slack.com"
    configure(site, target(format="slack", url="https://hooks.slack.com/services/T/B/x",
                           allow_host="other.example.invalid"))
    with pytest.raises(OpsConfigError, match="allow_host"):
        load_config(site.cfg_path)


def test_notify_test_dry_run_shows_format_and_shape_with_secrets_masked(site, monkeypatch,
                                                                         capsys):
    from assurance.cli import main

    for k, v in env_for("pagerduty").items():
        monkeypatch.setenv(k, v)
    configure(site, target(format="pagerduty"))
    capsys.readouterr()
    code = main(["ops", "notify-test", "--config", str(site.cfg_path), "--target", "oncall"])
    out = capsys.readouterr().out
    assert code == 0 and "format pagerduty" in out and "routing_key" in out
    assert RKEY not in out and "no X-NeuralBridge-Signature" in out
    assert "<routing key from $NB_SECRET: not shown>" in out and "TEST" in out


def test_notify_test_live_pagerduty_sends_a_test_event_without_signature(site):
    cfg = cfg_for(site, "pagerduty")
    t = Contract()
    out = notify.send_test(cfg, cfg.notify[0], transport_factory=lambda h: t,
                           environ=env_for("pagerduty"))
    b = json.loads(t.calls[0]["body"])
    assert out["status"] == "delivered" and b["payload"]["severity"] == "info"
    assert b["routing_key"] == RKEY and b["dedup_key"].startswith("test-")
    assert "x-neuralbridge-signature" not in {k.lower() for k in t.calls[0]["headers"]}


@pytest.mark.parametrize("fmt", ["slack", "teams"])
def test_notify_test_live_chat_formats_sign_and_say_test(site, fmt):
    cfg = cfg_for(site, fmt)
    t = Contract()
    notify.send_test(cfg, cfg.notify[0], transport_factory=lambda h: t, environ=env_for(fmt))
    c = t.calls[0]
    assert "TEST message" in json.loads(c["body"])["text"]
    assert hdr(c, "x-neuralbridge-signature") == independent_hmac(SECRET, c["body"], hdr(c, "x-neuralbridge-timestamp"))


def test_check_shows_the_format_and_warns_on_a_wrong_length_routing_key(site, monkeypatch,
                                                                         capsys):
    from assurance.cli import main

    configure(site, target(format="pagerduty"))
    monkeypatch.setenv("NB_SECRET", "too-short")
    monkeypatch.setenv("NB_HDRS", EXTRA)
    capsys.readouterr()
    main(["ops", "check", "--config", str(site.cfg_path), "--json"])
    out = capsys.readouterr().out
    assert "notify.oncall.format" in out and "pagerduty" in out
    assert "too-short" not in out
    checks = json.loads(out)["checks"]
    sec = next(c for c in checks if c["name"] == "notify.oncall.secret_env")
    assert sec["status"] == "warn"


def test_render_is_pure_and_refuses_what_it_does_not_know():
    msg = notify.build_payload(doc_with(ACTION))
    assert formats.render("slack", msg, key="k") == formats.render("slack", msg, key="k")
    with pytest.raises(ValueError):
        formats.render("servicenow_json", msg, key="k")
    with pytest.raises(ValueError):
        formats.render("pagerduty", msg, key="k")           # no routing key, no body
    assert "servicenow_json" not in formats.FORMATS
