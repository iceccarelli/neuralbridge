"""Body adapters for ``notify``: the SAME allow-listed message, shaped for the receiver.

Pure functions, no I/O, no network, no environment: ``render(format, message, key=..., routing_key=...)``
returns ``(body bytes, content_type, extra headers)``. ``message`` is the dict
``assurance.ops.notify.build_payload`` / ``build_test_payload`` already produced; nothing is added
to it here, so no new data can reach any vendor body. Text that came from a finding was already
neutralised, path-masked and clipped; this module only makes it inert for the receiver.

Formats (built from the vendors' published request shapes; NOT verified against a live account):

* ``json``      the generic body, unchanged (HMAC-signed by the sender).
* ``slack``     ``{"text": ...}`` incoming-webhook body (HMAC header is sent but Slack ignores it).
* ``teams``     ``{"text": ...}`` plain-text/markdown-subset body (same remark).
* ``pagerduty`` Events API v2 ``{"routing_key", "event_action", "dedup_key", "payload"}``. The
  routing key is PagerDuty's credential and REPLACES the HMAC secret; NO signature is sent.
  ``servicenow_json`` is not built.

Making text inert (untrusted = step names, refs, action text, ops id):

* ``@`` becomes ``@ `` (so ``@channel``/``@here``/``<@U123>`` cannot notify anyone);
* ``://`` becomes ``:/ /`` and ``www.`` becomes ``www .`` (so no auto-link is formed);
* Slack: ``&`` ``<`` ``>`` become ``&amp;`` ``&lt;`` ``&gt;`` (Slack's documented escaping, which also
  defuses ``<!channel>``/``<http://x|y>``); ``*``, ``_``, ``~`` and the backtick are replaced by
  look-alike characters because mrkdwn has no escape for them;
* Teams: ``\\ ` * _ [ ] ( ) < > & | ~ #`` are backslash-escaped (CommonMark escapes), so no link,
  image, code span, emphasis, table or HTML can be formed.

Size caps are explicit, never silent: a message over the cap loses whole trailing bullets and says
``… (N more)``; a PagerDuty summary over 1024 characters is cut and ends ``… (N more)``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple

__all__ = ["FORMATS", "SIGNED_FORMATS", "SLACK_TEXT_MAX", "TEAMS_TEXT_MAX", "PD_SUMMARY_MAX",
           "Rendered", "body_shape", "render", "severity_for"]

FORMATS = ("json", "slack", "teams", "pagerduty")
#: formats whose request carries the X-NeuralBridge-Signature HMAC. PagerDuty does not.
SIGNED_FORMATS = ("json", "slack", "teams")
SLACK_TEXT_MAX = 3000          # Slack documents ~40,000 for text; 3000 is the readable cap
TEAMS_TEXT_MAX = 3000          # chosen by us, well inside Teams' message-size limit
PD_SUMMARY_MAX = 1024          # Events API v2 payload.summary maximum
_FOOTER = "Drafted by software from an unsigned operator log; it decides nothing."


class Rendered(NamedTuple):
    body: bytes
    content_type: str
    headers: dict[str, str]


def _encode(doc: Mapping[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def severity_for(status: str) -> str:
    """PagerDuty severity: flagged -> warning, degraded -> error, a test -> info."""
    return {"flagged": "warning", "degraded": "error", "test": "info"}.get(status, "warning")


# --------------------------------------------------------------------------------------------
# making text inert
# --------------------------------------------------------------------------------------------
def _defang(text: str) -> str:
    return text.replace("@", "@ ").replace("://", ":/ /").replace("www.", "www .")


_SLACK_MAP = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;", "`": "ʼ", "*": "∗",
                            "~": "∼", "_": "＿"})
_TEAMS_ESCAPE = frozenset("\\`*_[]()<>&|~#")


def _slack(text: object) -> str:
    return _defang(str(text)).translate(_SLACK_MAP)


def _teams(text: object) -> str:
    return "".join("\\" + c if c in _TEAMS_ESCAPE else c for c in _defang(str(text)))


# --------------------------------------------------------------------------------------------
# the shared human text
# --------------------------------------------------------------------------------------------
def _assemble(head: list[str], bullets: list[str], omitted: int, tail: list[str],
              limit: int) -> str:
    n = len(bullets)
    for keep in range(n, -1, -1):
        more = n - keep + omitted
        lines = head + bullets[:keep] + ([f"… ({more} more)"] if more else []) + tail
        text = "\n".join(lines)
        if len(text) <= limit:
            return text
    text = "\n".join(head + tail)           # head and tail alone are over the cap: cut, say so
    excess = len(text) - (limit - 24)
    return text[: limit - 24] + f"… ({excess} more)"


def _lines(message: Mapping[str, Any], esc: Callable[[object], str], bullet: str
           ) -> tuple[list[str], list[str], int, list[str]]:
    ops = esc(message.get("ops_id", ""))
    status = esc(message.get("status", ""))
    if message.get("kind") != "cycle":
        return ([f"NeuralBridge ops {ops}: TEST message", esc(message.get("message", ""))], [], 0,
                [_FOOTER])
    steps = [s for s in message.get("steps", []) if isinstance(s, Mapping)]
    bad = [f"{esc(s.get('name', ''))}={esc(s.get('status', ''))}" for s in steps
           if s.get("status") != "ok"]
    head = [f"NeuralBridge ops {ops}: cycle {status}",
            f"Steps: {len(steps)} total" + (f"; not ok: {', '.join(bad)}" if bad else "")]
    acts = [a for a in message.get("human_actions", []) if isinstance(a, Mapping)]
    head.append(f"Human actions: {len(acts) + int(message.get('human_actions_omitted', 0) or 0)}"
                if acts else "Human actions: none recorded")
    bullets = [f"{bullet} {esc(a.get('step', ''))} / {esc(a.get('ref', ''))}: "
               f"{esc(a.get('action', ''))}" for a in acts]
    return head, bullets, int(message.get("human_actions_omitted", 0) or 0), [_FOOTER]


def _chat_text(message: Mapping[str, Any], esc: Callable[[object], str], bullet: str,
               limit: int) -> str:
    head, bullets, omitted, tail = _lines(message, esc, bullet)
    return _assemble(head, bullets, omitted, tail, limit)


def _summary(message: Mapping[str, Any]) -> str:
    ops, status = str(message.get("ops_id", "")), str(message.get("status", ""))
    if message.get("kind") != "cycle":
        s = f"NeuralBridge ops {ops}: TEST message; no action is required"
    else:
        acts = [a for a in message.get("human_actions", []) if isinstance(a, Mapping)]
        s = f"NeuralBridge ops {ops}: cycle {status}; {len(acts)} human action(s)"
        if acts:
            s += ": " + " | ".join(f"{a.get('step', '')} / {a.get('ref', '')}: "
                                   f"{a.get('action', '')}" for a in acts)
    if len(s) <= PD_SUMMARY_MAX:
        return s
    keep = PD_SUMMARY_MAX - 24
    return s[:keep] + f"… ({len(s) - keep} more)"


# --------------------------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------------------------
def render(fmt: str, message: Mapping[str, Any], *, key: str,
           routing_key: str | None = None) -> Rendered:
    """``(body, content_type, extra_headers)`` for ``fmt``. ``key`` is the idempotency key.

    ``routing_key`` is used by ``pagerduty`` only (it is that format's credential).
    """
    if fmt == "json":
        return Rendered(_encode(message), "application/json", {})
    if fmt == "slack":
        return Rendered(_encode({"text": _chat_text(message, _slack, "•", SLACK_TEXT_MAX)}),
                        "application/json", {})
    if fmt == "teams":
        return Rendered(_encode({"text": _chat_text(message, _teams, "-", TEAMS_TEXT_MAX)}),
                        "application/json", {})
    if fmt == "pagerduty":
        if not routing_key:
            raise ValueError("pagerduty needs a routing key")
        status = str(message.get("status", ""))
        return Rendered(_encode({
            "routing_key": routing_key, "event_action": "trigger", "dedup_key": key,
            "payload": {"summary": _summary(message), "source": str(message.get("ops_id", "")),
                        "severity": severity_for(status),
                        "custom_details": {k: v for k, v in message.items()
                                           if k != "schema"}}}),
                        "application/json", {})
    raise ValueError("unknown notify format")


def body_shape(fmt: str) -> str:
    """One line for ``ops check`` / ``notify-test``: the top-level shape and the auth model."""
    return {
        "json": 'generic body {schema, kind, cycle_id, ...}; auth: HMAC-SHA256 header',
        "slack": '{"text"}; auth: the webhook URL is the credential (the HMAC header is sent '
                 'but Slack does not check it)',
        "teams": '{"text"}; auth: the webhook URL is the credential (the HMAC header is sent '
                 'but Teams does not check it)',
        "pagerduty": '{routing_key, event_action, dedup_key, payload{summary, source, severity, '
                     'custom_details}}; auth: the routing key (secret_env), NO HMAC header',
    }[fmt]
