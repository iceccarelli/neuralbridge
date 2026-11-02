"""Telling a person: a minimal, signed, idempotent webhook after each cycle (operator path only).

What this is: after ``ops cycle`` finishes, for every configured ``notify`` target whose ``on``
list contains the cycle's status, POST one small JSON body (status, step names and statuses, the
human-action strings the record already holds, the record's SHA-256) to an HTTPS endpoint the
operator named. The body is signed with HMAC-SHA256 over ``"<unix seconds>." + body`` (the
timestamp travels in ``X-NeuralBridge-Timestamp``; a receiver rejects a stale one, see
:func:`signature_fresh`). Enterprise
ticketing, chat and on-call tools accept an authenticated inbound webhook; this is the generic
sender; ``format`` may also shape the same message for Slack, Teams or PagerDuty
(``assurance.ops.formats``, contract-checked against vendor docs only, never a live account).

What it is not: delivery is not acknowledgement by a person; nothing here decides, opens a case
or closes anything. It lives ONLY in the hosted/operator ``ops`` path, is off unless a ``notify``
list is configured, and is never reached by the offline kit.

Hard rules kept here:

* this module imports no network client. The one real sender is
  ``assurance.intel.transport_urllib.UrllibTransport.post``, imported lazily by
  :func:`make_transport` and only when something is actually sent;
* the payload is built from an allow-list of record fields. Step ``detail``/``info``/``command``,
  key file paths, backup directories and ledger contents are never copied; text that came from a
  finding is neutralised, path-masked and truncated; the secret and extra headers are scrubbed by
  value before signing. Path masking is a HEURISTIC (see :func:`mask_paths`): ``human_actions``
  text is operator-derived, so it is neutralised and truncated, not guaranteed redacted;
* secrets (the HMAC key, ``headers_env`` lines) are read from the environment at send time and
  held in memory only. They are never written to the record, the outbox, stdout/stderr or an
  exception; an error is recorded as its CLASS name only;
* a failed delivery never changes the cycle's exit code (the caller guarantees that).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from assurance.core.identity import format_utc, utc_now
from assurance.core.text import neutralise
from assurance.ops import formats
from assurance.ops import record as rec
from assurance.ops.config import NotifyCfg, OpsConfig

__all__ = ["MAX_ATTEMPTS", "PAYLOAD_SCHEMA", "build_payload", "deliver", "dry_run_request",
           "make_transport", "outbox_state", "record_sha256", "send_test", "sign"]

PAYLOAD_SCHEMA = "neuralbridge-ops-notify/1"
MAX_ATTEMPTS = 5
TIMEOUT_S = 10.0
_MAX_ACTIONS = 50
_RESERVED = {"content-type", "content-length", "host", "idempotency-key", "user-agent",
             "accept-encoding", "x-neuralbridge-signature", "x-neuralbridge-delivery",
             "transfer-encoding", "connection", "x-neuralbridge-timestamp"}
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
#: Files that are secrets or stores whatever directory they are named in.
_SENSITIVE_EXT = (".key", ".pem", ".db", ".jsonl", ".sqlite", ".p12", ".pfx")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_QUOTED = re.compile(r"""(['"`])([^'"`\n]{1,300}?)\1""")
_TRIM_L = "([{<'\"`"
_TRIM_R = ".,;:)]}>'\"`!?"
REPLAY_WINDOW_S = 300
OUTBOX_RETENTION_DAYS = 30
_NOT_ESTABLISHED = ("A webhook delivery is not acknowledgement by a person. This message is "
                    "drafted by software from an unsigned operator log; it decides nothing.")

Transport = Any            # an object with post(url, headers, body, timeout) -> (status, bytes)
TransportFactory = Callable[[str], Transport]


def make_transport(allow_host: str) -> Transport:
    """The real sender for one target: exact-host allow-list, no redirects, response capped."""
    from assurance.intel.transport_urllib import UrllibTransport  # lazy: loads urllib

    return UrllibTransport(allowed_hosts=[allow_host], max_bytes=64 * 1024, retries=2,
                           backoff=2.0, max_wait=30.0)


# --------------------------------------------------------------------------------------------
# the payload
# --------------------------------------------------------------------------------------------
def _is_pathlike(core: str) -> bool:
    if not core or _URL.match(core):
        return False
    low = core.lower()
    return ("/" in core or "\\" in core or low.startswith(("~", "\\\\"))
            or bool(_DRIVE.match(core)) or "tenants/acc_" in low
            or low.endswith(_SENSITIVE_EXT))


def _mask_token(match: re.Match[str]) -> str:
    token = match.group(0)
    start, end = 0, len(token)
    while start < end and token[start] in _TRIM_L:
        start += 1
    while end > start and token[end - 1] in _TRIM_R:
        end -= 1
    core = token[start:end]
    if not _is_pathlike(core):
        return token
    return token[:start] + "<path>" + token[end:]


def mask_paths(text: str) -> str:
    """Replace anything path-like with ``<path>``. Deliberately over-masks.

    Masked: absolute and relative (``./``, ``../``, ``a/b``) POSIX paths, ``~`` paths, Windows
    drive and UNC paths, anything containing ``tenants/acc_``, and any token ending in
    ``.key .pem .db .jsonl .sqlite .p12 .pfx``. A quoted span that looks like a path is masked
    whole (so a space inside quotes does not leak the tail). Unquoted paths with a space are
    masked token by token (``/var/lib/my keys/svc.key`` -> ``<path> <path>``): masking runs
    through the end of each whitespace-delimited token, never past it. URLs are left alone, and
    so is prose with no separator. LIMIT: this is a heuristic, not redaction; ``human_actions``
    text is operator-derived and is neutralised and truncated, so an operator must not put
    secrets in it.
    """
    text = _QUOTED.sub(lambda m: m.group(1) + "<path>" + m.group(1)
                       if _is_pathlike(m.group(2).strip()) else m.group(0), text)
    return re.sub(r"\S+", _mask_token, text)


def _clip(value: object, limit: int) -> str:
    text = mask_paths(neutralise(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def cycle_id(doc: Mapping[str, Any]) -> str:
    stamp = re.sub(r"[^0-9TZ]", "", str(doc.get("started_at", "")))
    return f"{doc.get('ops_id', 'ops')}-{stamp}"


def record_sha256(doc: Mapping[str, Any]) -> str:
    """SHA-256 of the record as canonical JSON (sorted keys, compact), WITHOUT ``notifications``.

    The delivery outcome cannot be part of what it reports on, so it is excluded; every other
    field of the stored line is covered.
    """
    body = {k: v for k, v in doc.items() if k != "notifications"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def build_payload(doc: Mapping[str, Any]) -> dict[str, Any]:
    """The minimal body for one cycle record. An allow-list: nothing else is copied."""
    actions = [a for a in doc.get("human_actions", []) if isinstance(a, dict)]
    steps = [s for s in doc.get("steps", []) if isinstance(s, dict)]
    return {
        "schema": PAYLOAD_SCHEMA, "kind": "cycle",
        "cycle_id": cycle_id(doc), "ops_id": _clip(doc.get("ops_id", ""), 64),
        "started_at": _clip(doc.get("started_at", ""), 32),
        "finished_at": _clip(doc.get("finished_at", ""), 32),
        "status": _clip(doc.get("status", ""), 16),
        "steps": [{"name": _clip(s.get("name", ""), 80), "status": _clip(s.get("status", ""), 16)}
                  for s in steps],
        "human_actions": [{"step": _clip(a.get("step", ""), 80), "ref": _clip(a.get("ref", ""), 120),
                           "action": _clip(a.get("action", ""), 400)}
                          for a in actions[:_MAX_ACTIONS]],
        "human_actions_omitted": max(0, len(actions) - _MAX_ACTIONS),
        "record_sha256": record_sha256(doc),
        "not_established": _NOT_ESTABLISHED,
    }


def build_test_payload(cfg: OpsConfig, target: NotifyCfg) -> dict[str, Any]:
    return {"schema": PAYLOAD_SCHEMA, "kind": "test", "status": "test",
            "ops_id": _clip(cfg.ops_id, 64), "target": target.name,
            "message": "TEST message from `assurance ops notify-test`. It carries no cycle "
                       "record, no finding and no ledger content. No action is required.",
            "not_established": _NOT_ESTABLISHED}


def encode(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(secret: str, body: bytes, timestamp: int) -> str:
    """``sha256=<hex>``: HMAC-SHA256 of ``b"<unix seconds>." + body`` (exact body bytes).

    Binding the timestamp means a captured body+signature cannot be replayed with a fresh
    timestamp; the receiver also rejects an old one (:func:`signature_fresh`).
    """
    message = str(int(timestamp)).encode("ascii") + b"." + body
    return "sha256=" + hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def signature_fresh(timestamp_header: str, now: float, window_s: int = REPLAY_WINDOW_S) -> bool:
    """Receiver-side replay check: ``|now - ts| <= window`` and ``ts`` is plain digits."""
    if not re.fullmatch(r"[0-9]{1,12}", timestamp_header or ""):
        return False
    return abs(now - int(timestamp_header)) <= window_s


def verify(secret: str, body: bytes, signature: str, timestamp_header: str, now: float,
           window_s: int = REPLAY_WINDOW_S) -> bool:
    """What a receiver does: fresh timestamp, then constant-time compare of the HMAC."""
    return (signature_fresh(timestamp_header, now, window_s)
            and hmac.compare_digest(sign(secret, body, int(timestamp_header)), signature))


# --------------------------------------------------------------------------------------------
# secrets, read at send time only
# --------------------------------------------------------------------------------------------
class _Unusable(Exception):  # noqa: N818
    """A target cannot be sent to. The message is a fixed phrase, never a value."""


def parse_header_lines(text: str) -> dict[str, str]:
    """``Name: value`` lines -> dict. Raises ``ValueError`` with a fixed message (no value)."""
    out: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        name, sep, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if (not sep or not _HEADER_NAME.fullmatch(name) or not value
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError("a header line is malformed")
        if name.lower() in _RESERVED:
            raise ValueError("a header name is reserved")
        out[name] = value
    return out


def _credentials(target: NotifyCfg, environ: Mapping[str, str]) -> tuple[str, dict[str, str]]:
    secret = environ.get(target.secret_env, "")
    if not secret:
        raise _Unusable("secret_env not set")
    extra: dict[str, str] = {}
    if target.headers_env:
        raw = environ.get(target.headers_env, "")
        if not raw:
            raise _Unusable("headers_env not set")
        try:
            extra = parse_header_lines(raw)
        except ValueError:
            raise _Unusable("headers_env malformed") from None
    return secret, extra


def _secret_strings(cfg: OpsConfig, environ: Mapping[str, str]) -> list[str]:
    found: set[str] = set()
    for t in cfg.notify:
        for name in (t.secret_env, t.headers_env):
            value = environ.get(name or "", "")
            if len(value) >= 4:
                found.add(value)
        try:
            found.update(v for v in parse_header_lines(environ.get(t.headers_env or "", ""))
                         .values() if len(v) >= 4)
        except ValueError:
            pass
    return sorted(found | set(rec.secrets_for(cfg.secret_env_names(),
                                              [cfg.attest.key] if cfg.attest else [])),
                  key=len, reverse=True)


# --------------------------------------------------------------------------------------------
# one send
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class _Result:
    ok: bool
    http_status: int | None
    delivery_id: str
    error_class: str | None


def _headers(target: NotifyCfg, secret: str, extra: Mapping[str, str], req: formats.Rendered,
             key: str, delivery_id: str) -> dict[str, str]:
    out = {**extra, **req.headers, "Content-Type": req.content_type,
           "X-NeuralBridge-Delivery": delivery_id, "Idempotency-Key": key}
    if target.format in formats.SIGNED_FORMATS:      # PagerDuty authenticates by routing key
        ts = int(utc_now().timestamp())      # fresh per attempt: a retry is not a replay
        out["X-NeuralBridge-Timestamp"] = str(ts)
        out["X-NeuralBridge-Signature"] = sign(secret, req.body, ts)
    return out


def _render(target: NotifyCfg, message: Mapping[str, Any], key: str, secret: str
            ) -> formats.Rendered:
    """The vendor body, built at send time so a routing key is never persisted."""
    return formats.render(target.format, message, key=key,
                          routing_key=secret if target.format == "pagerduty" else None)


def _post(transport: Transport, target: NotifyCfg, req: formats.Rendered, key: str,
          secret: str, extra: Mapping[str, str]) -> _Result:
    delivery_id = str(uuid.uuid4())
    try:
        status, _ = transport.post(target.url, _headers(target, secret, extra, req, key,
                                                        delivery_id), req.body, TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 - a delivery problem is recorded, never raised
        status_attr = getattr(exc, "status", None)
        if type(exc).__name__ == "ResponseTooLarge" and isinstance(status_attr, int) \
                and 200 <= status_attr < 300:
            return _Result(True, status_attr, delivery_id, None)    # accepted; reply was large
        return _Result(False, None, delivery_id, type(exc).__name__)    # CLASS only
    if 200 <= status < 300:
        return _Result(True, status, delivery_id, None)
    return _Result(False, status, delivery_id, "HttpStatus")


def _entry(target: str, cid: str, status: str, res: _Result | None, attempts: int, *,
           retry: bool, reason: str | None = None, abandoned: bool = False) -> dict[str, Any]:
    e: dict[str, Any] = {
        "target": target, "cycle_id": cid, "status": status,
        "http_status": res.http_status if res else None, "attempts": attempts,
        "delivery_id": res.delivery_id if res else None,
        "error_class": res.error_class if res else None, "retry": retry}
    if reason:
        e["reason"] = reason
    if abandoned:
        e["abandoned"] = True
    return e


# --------------------------------------------------------------------------------------------
# the outbox: append-only JSONL, one writer (the cycle holds the lock)
# --------------------------------------------------------------------------------------------
def _read_outbox(path: Path) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return lines
    for line in text.splitlines():
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("key"), str):
            lines.append(doc)
    return lines


def _fold(lines: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}
    for ln in lines:
        key, kind = ln["key"], ln.get("o")
        if kind == "pending":
            items[key] = {"key": key, "target": ln.get("target"), "cycle_id": ln.get("cycle_id"),
                          "body": ln.get("body", ""), "attempts": 0, "state": "open",
                          "http_status": None, "error_class": None, "last_at": ln.get("at")}
        elif key in items:
            it = items[key]
            if kind == "attempt":
                it["attempts"] = int(ln.get("attempts", it["attempts"]))
                it["http_status"] = ln.get("http_status")
                it["error_class"] = ln.get("error_class")
                it["last_at"] = ln.get("at")
                if ln.get("status") == "delivered":
                    it["state"] = "delivered"
            elif kind == "abandoned":
                it["state"] = "abandoned"
                it["last_at"] = ln.get("at")
    return items


def outbox_state(cfg: OpsConfig) -> dict[str, list[dict[str, Any]]]:
    """``{"open": [...], "abandoned": [...]}`` for ``ops status``. No body, no secret."""
    items = _fold(_read_outbox(cfg.outbox))
    pick = ("target", "cycle_id", "attempts", "http_status", "error_class", "last_at")
    return {st: [{k: it[k] for k in pick} for it in items.values() if it["state"] == st]
            for st in ("open", "abandoned")}


def compact_outbox(path: Path, now: datetime | None = None,
                   retention_days: int = OUTBOX_RETENTION_DAYS) -> int:
    """Drop every line of a delivered or abandoned item last touched over ``retention_days`` ago.

    Open items are never dropped, nor is anything inside the window, nor a line that cannot be
    read (kept verbatim). Inside the window the file is append-only; compaction only runs at
    the start of a cycle, which holds the single-writer lock, and replaces the file atomically
    (temp file in the same directory, fsync, ``os.replace``). Returns the number of items
    dropped. A problem is never raised: the outbox is then left as it was.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    cutoff = format_utc((now or utc_now()) - timedelta(days=retention_days))
    parsed: list[tuple[str, dict[str, Any] | None]] = []
    for line in raw.splitlines():
        try:
            doc = json.loads(line)
        except ValueError:
            doc = None
        parsed.append((line, doc if isinstance(doc, dict) and isinstance(doc.get("key"), str)
                       else None))
    items = _fold([d for _, d in parsed if d is not None])
    drop = {k for k, it in items.items()
            if it["state"] in ("delivered", "abandoned")
            and isinstance(it.get("last_at"), str) and it["last_at"] < cutoff}
    if not drop:
        return 0
    kept = [line for line, d in parsed if d is None or d["key"] not in drop]
    tmp = path.with_name(path.name + ".compact.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, ("\n".join(kept) + "\n" if kept else "").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return 0
    return len(drop)


def _log(path: Path, **fields: Any) -> None:
    rec.append(path, {**fields, "at": format_utc(utc_now())})


# --------------------------------------------------------------------------------------------
# after a cycle
# --------------------------------------------------------------------------------------------
def deliver(cfg: OpsConfig, doc: Mapping[str, Any], *,
            transport_factory: TransportFactory | None = None,
            environ: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    """Retry what is owed from earlier cycles, then send this cycle's targets. Never raises.

    Returns the ``notifications`` entries for the record. ``doc`` is not modified.
    """
    env = os.environ if environ is None else environ
    factory = transport_factory or make_transport
    by_name = {t.name: t for t in cfg.notify}
    secrets = _secret_strings(cfg, env)
    entries: list[dict[str, Any]] = []
    compact_outbox(cfg.outbox)

    def run(target: NotifyCfg, message: Mapping[str, Any], key: str) -> _Result | None:
        try:
            secret, extra = _credentials(target, env)
        except _Unusable:
            return None
        return _post(factory(target.allow_host), target, _render(target, message, key, secret),
                     key, secret, extra)

    # 1. owed from earlier cycles (same body, same Idempotency-Key)
    for it in _fold(_read_outbox(cfg.outbox)).values():
        if it["state"] != "open":
            continue
        name, cid, key = str(it["target"]), str(it["cycle_id"]), it["key"]
        target = by_name.get(name)
        if target is None:
            _log(cfg.outbox, o="abandoned", key=key, reason="target_removed")
            entries.append(_entry(name, cid, "failed", None, it["attempts"], retry=True,
                                  reason="target no longer configured", abandoned=True))
            continue
        try:
            message = json.loads(str(it["body"]))
            if not isinstance(message, dict):
                raise ValueError
        except ValueError:
            _log(cfg.outbox, o="abandoned", key=key, reason="corrupt_body")
            entries.append(_entry(name, cid, "failed", None, it["attempts"], retry=True,
                                  reason="stored message unreadable", abandoned=True))
            continue
        res = run(target, message, key)
        if res is None:
            entries.append(_entry(name, cid, "skipped", None, it["attempts"], retry=True,
                                  reason=_why_unusable(target, env)))
            continue
        n = it["attempts"] + 1
        _log(cfg.outbox, o="attempt", key=key, status="delivered" if res.ok else "failed",
             attempts=n, http_status=res.http_status, error_class=res.error_class,
             delivery_id=res.delivery_id)
        gave_up = (not res.ok) and n >= MAX_ATTEMPTS
        if gave_up:
            _log(cfg.outbox, o="abandoned", key=key, reason="max_attempts")
        entries.append(_entry(name, cid, "delivered" if res.ok else "failed", res, n, retry=True,
                              abandoned=gave_up))

    # 2. this cycle
    wanted = [t for t in cfg.notify if str(doc.get("status")) in t.on]
    if wanted:
        payload = rec.scrub(build_payload(doc), secrets)
        body = encode(payload)       # the vendor-free canonical message: this is what is stored
        cid = payload["cycle_id"]
        for target in wanted:
            key = f"{cid}:{target.name}"
            res = run(target, payload, key)
            if res is None:
                entries.append(_entry(target.name, cid, "skipped", None, 0, retry=False,
                                      reason=_why_unusable(target, env)))
                continue
            if not res.ok:
                _log(cfg.outbox, o="pending", key=key, target=target.name, cycle_id=cid,
                     body=body.decode("utf-8"))
                _log(cfg.outbox, o="attempt", key=key, status="failed", attempts=1,
                     http_status=res.http_status, error_class=res.error_class,
                     delivery_id=res.delivery_id)
            entries.append(_entry(target.name, cid, "delivered" if res.ok else "failed", res, 1,
                                  retry=False))
    return rec.scrub(entries, secrets)


def _why_unusable(target: NotifyCfg, env: Mapping[str, str]) -> str:
    try:
        _credentials(target, env)
    except _Unusable as exc:
        return f"{exc}"
    return "unusable"


# --------------------------------------------------------------------------------------------
# notify-test
# --------------------------------------------------------------------------------------------
def dry_run_request(cfg: OpsConfig, target: NotifyCfg, environ: Mapping[str, str] | None = None
                    ) -> dict[str, Any]:
    """What a live test would send, with every secret masked. Reads the environment, sends nothing."""
    env = os.environ if environ is None else environ
    key = f"test-{cfg.ops_id}:{target.name}:<uuid>"
    req = formats.render(target.format, build_test_payload(cfg, target), key=key,
                         routing_key="<routing key from $" + target.secret_env + ": not shown>")
    body = req.body
    headers = [f"Content-Type: {req.content_type}"]
    if target.format in formats.SIGNED_FORMATS:
        headers.append("X-NeuralBridge-Timestamp: <unix seconds at send>")
        headers.append(f"X-NeuralBridge-Signature: sha256=<hmac of '<timestamp>.' + {len(body)} "
                       "body bytes>")
    else:
        headers.append("(no X-NeuralBridge-Signature: this format authenticates by its routing "
                       "key)")
    headers += ["X-NeuralBridge-Delivery: <uuid, new per attempt>", f"Idempotency-Key: {key}"]
    if target.headers_env:
        headers.append(f"<extra header lines from ${target.headers_env}: names and values not "
                       "shown>")
    return {"method": "POST", "format": target.format, "body_shape": formats.body_shape(
        target.format), "host": target.allow_host, "url": "<the configured URL: path not "
            "shown, it may be a bearer token>", "headers": headers,
            "body": body.decode("utf-8"),
            "secret_env_set": bool(env.get(target.secret_env)),
            "headers_env_set": None if not target.headers_env
            else bool(env.get(target.headers_env))}


def send_test(cfg: OpsConfig, target: NotifyCfg, *,
              transport_factory: TransportFactory | None = None,
              environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """One live TEST delivery. Not recorded in the cycle record or the outbox."""
    env = os.environ if environ is None else environ
    try:
        secret, extra = _credentials(target, env)
    except _Unusable as exc:
        return {"status": "skipped", "reason": str(exc), "http_status": None, "attempts": 0,
                "delivery_id": None, "error_class": None}
    key = f"test-{cfg.ops_id}:{target.name}:{uuid.uuid4()}"
    res = _post((transport_factory or make_transport)(target.allow_host), target,
                _render(target, build_test_payload(cfg, target), key, secret), key, secret, extra)
    return {"status": "delivered" if res.ok else "failed", "http_status": res.http_status,
            "attempts": 1, "delivery_id": res.delivery_id, "error_class": res.error_class}
