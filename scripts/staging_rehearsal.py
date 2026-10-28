#!/usr/bin/env python3
"""Go-live rehearsal for the assurance service: one command per phase, Stripe TEST mode only.

This is PREPARATION. Nothing in this repository has been deployed, and this tool has not
been run against a hosted staging host. It exists so the founder can do that, with
credentials only the founder holds, and get an honest PASS / FAIL / UNCHECKED / ATTESTED per step.

    python scripts/staging_rehearsal.py config-check [--checkout-expected]
    python scripts/staging_rehearsal.py smoke        [--base-url URL] [--expect-purchasable register,cell]
    python scripts/staging_rehearsal.py webhook-test [--base-url URL] --i-am-testing-staging
    python scripts/staging_rehearsal.py restore-drill --data-dir DIR   (or --backup-dir DIR)
    python scripts/staging_rehearsal.py report       --records DIR --out DIR

Every phase leaves a redacted ``<phase>.json`` (0600, in a 0700 directory) in ``--record-dir``,
else ``$REHEARSAL_RECORD_DIR``, else ``./.rehearsal``. It writes an ``in_progress`` record when
it starts, so a run that fails, is interrupted or is killed replaces an earlier pass rather than
leaving it standing. ``report`` trusts only a complete, current (``--max-age-hours``, default 6),
same-version, in-order set of records that names one host.

Rules the tool keeps, each pinned by ``tests/test_staging_rehearsal.py``:

* **Credentials only through the environment.** Nothing secret is accepted on the command
  line, printed, logged, recorded or reported; every line of output passes through a
  redactor holding every secret-looking environment value plus the shapes of Stripe keys,
  webhook secrets and API keys. A bad command line is reported without echoing it.
* **Live mode is refused before anything runs.** Any variable whose value holds ``sk_live_``,
  ``rk_live_``, ``pk_live_``, ``ek_live_`` or ``whsec_live``, any ``STRIPE*LIVE*`` variable,
  and ``ASSURANCE_PAYG_ALLOW_LIVE`` stops every subcommand with exit 1. Stripe gives test and
  live webhook signing secrets the same ``whsec_`` shape, so a secret's mode cannot be read
  from the string; ``webhook-test`` therefore also needs ``STAGING_STRIPE_MODE=test`` as the
  founder's statement, and says that is what it rests on.
* **Only the host it was given.** All HTTP goes through one client that raises if a request
  names any other host, does not follow redirects and ignores proxies named in the environment
  (``trust_env=False``: a proxy would receive the register key). The one plain-http request,
  to a hosted host's port 80, is a bare ``GET /healthz`` with no credentials. It never calls Stripe, never creates a price, product, customer,
  charge or checkout session, and never sends mail.
* **A missing prerequisite is UNCHECKED, never a pass; a statement is ATTESTED, never a
  measurement.** Exit 0 only if every step PASSed; 3 if any step is UNCHECKED or ATTESTED and
  none FAILed; 1 if any FAILed (or the tool itself broke); 130 if interrupted. ATTESTED marks
  what the founder states (a webhook secret is a TEST secret) or what a shell merely lacks
  (``ASSURANCE_ALLOW_UNAUTHENTICATED`` unset here says nothing about the host).
* **No live test key is left on the host.** ``webhook-test`` revokes the key it was handed in a
  ``finally`` (also on Ctrl-C or any error) and, if it cannot confirm that, FAILs naming the
  key by its first ten characters only.
* **restore-drill never opens the source.** It copies the data directory (refusing symlinks, and
  a directory with -wal/-shm/-journal files unless ``--i-know-the-service-is-stopped``), works on
  the copy, and checks that the source's listing and every file hash are unchanged afterwards.

Environment (names only; values are never shown):
    REHEARSAL_BASE_URL         the host under test (or --base-url); https, or http on loopback
    REHEARSAL_REGISTER_KEY     a Register-only TEST key, for the 402 check on a Cell route
    REHEARSAL_ORIGIN           CORS origin to preflight (default https://neuralbridge.io)
    REHEARSAL_CA_BUNDLE        extra CA file for a private CA (optional)
    REHEARSAL_DATA_DIR         the data directory for restore-drill (or --data-dir)
    REHEARSAL_PRODUCTION_HOSTS comma-separated hosts webhook-test must never target
    REHEARSAL_RECORD_DIR       where phases leave their redacted record
    STAGING_CONFIRM            must equal the base URL's hostname (webhook-test)
    STAGING_STRIPE_MODE        must be ``test`` (webhook-test)
    STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, ASSURANCE_API_KEYS, ASSURANCE_PRICE_*,
    ASSURANCE_PUBLIC_URL, ASSURANCE_ALLOW_UNAUTHENTICATED   (config-check; webhook secret too)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlsplit

# The checkout this script lives in decides which catalogue and which restore check it
# uses: the comparison "does the host serve what billing/plans.py says" is only meaningful
# against the same commit that was deployed.
_SRC = Path(__file__).resolve().parents[1] / "src"
if (_SRC / "assurance").is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import httpx  # noqa: E402

from assurance.billing.plans import PLANS, public_catalogue  # noqa: E402
from assurance.evidence import restore_check  # noqa: E402

#: Stamped on every record; ``report`` refuses records written by another version.
VERSION = "staging-rehearsal/2"

PASS, FAIL, UNCHECKED, ATTESTED = "PASS", "FAIL", "UNCHECKED", "ATTESTED"
#: ATTESTED is what the operator states or what a shell merely lacks: it was not measured on
#: the host, so it blocks exit 0 exactly as UNCHECKED does, and the report lists it apart.
VALID_STATUSES = (PASS, FAIL, UNCHECKED, ATTESTED)
REDACTED = "[REDACTED]"

#: Ids of each phase's steps, in order. A phase that cannot start marks all of them
#: UNCHECKED, so the report always lists everything that was not established, and a record
#: that lacks any of them is not a record of that phase.
STEP_IDS: dict[str, tuple[str, ...]] = {
    "config-check": (
        "config.no_live_keys", "config.stripe_secret_key", "config.stripe_webhook_secret",
        "config.api_keys", "config.allow_unauthenticated", "config.public_url",
        "config.site_origin", "config.price_register", "config.price_cell"),
    "smoke": (
        "smoke.base_url", "smoke.healthz", "smoke.plans", "smoke.plans_purchasable",
        "smoke.no_key_401", "smoke.bad_key_401", "smoke.register_key_402", "smoke.cors",
        "smoke.https_redirect", "smoke.tls_cert", "smoke.provided_secrets_absent",
        "smoke.no_secret_shapes"),
    "webhook-test": (
        "webhook.preconditions", "webhook.secret_is_test", "webhook.forged_rejected",
        "webhook.pending_before", "webhook.delivered", "webhook.replay_duplicate",
        "webhook.key_handover_once", "webhook.key_works", "webhook.cleanup"),
    "restore-drill": (
        "restore.source", "restore.backup", "restore.wipe_restore", "restore.verify",
        "restore.counts_match", "restore.negative_control", "restore.source_untouched"),
}
PHASE_PREFIX = {"config-check": "config", "smoke": "smoke", "webhook-test": "webhook",
                "restore-drill": "restore", "report": "report"}
REPORT_ORDER = ("config-check", "smoke", "webhook-test", "restore-drill")
#: Phases that must have been run in this order for one rehearsal to be one rehearsal.
SEQUENCE = ("config-check", "smoke", "webhook-test")
ORDER_SKEW_SECONDS = 60

#: Hosts webhook-test refuses outright: the marketing site and the Fly app name
#: deploy/assurance/fly.toml would deploy a production service under. A speed bump, not a
#: guarantee: it compares hostnames and cannot see a CNAME, an alias or a vanity domain.
PRODUCTION_HOSTS = frozenset({"neuralbridge.io", "www.neuralbridge.io",
                              "assurance-register.fly.dev"})

NOT_ESTABLISHED = (
    "Nothing in this repository has been deployed, and this rehearsal does not deploy "
    "anything. A PASS here is about the host named in the record and the moment it ran.",
    "Real Stripe delivery to the endpoint, the dashboard's endpoint configuration, the "
    "price ids actually existing in the Stripe test account, and a test-card checkout in a "
    "browser are founder steps this tool cannot perform (see DEPLOY_NOW.md).",
    "A webhook signing secret's mode (test or live) cannot be read from the string; "
    "STAGING_STRIPE_MODE=test is the founder's statement, not a measurement (ATTESTED).",
    "Whether open mode is off on the host is observed only by smoke's /healthz auth_mode; "
    "an unset variable in the founder's shell proves nothing about the host (ATTESTED).",
    "A restore drill proves that this backup restores and that its hash chains verify and "
    "counts match; it cannot show that nothing was removed by someone who rebuilt a chain "
    "(only a signed head attestation shows that).",
    "The production-host deny list compares hostnames; it cannot see a CNAME, an alias or a "
    "vanity domain that points at production.",
)


# ---------------------------------------------------------------------------
# redaction: nothing secret leaves the process
# ---------------------------------------------------------------------------

_SECRET_NAME = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|PEM|CREDENTIAL|AUTH|COOKIE|DSN|PRIVATE"
    r"|SIGNATURE|BEARER)", re.I)
_NOT_SECRET_NAME = re.compile(
    r"(_URL|_URI|_HOST|_HOSTS|_PORT|_PATH|_DIR|_FILE|_BUNDLE|_NAME|_MODE|_ORIGIN|_ORIGINS|_ID)$",
    re.I)
#: a password inside any URL-shaped value, whatever the variable is called
_USERINFO = re.compile(r"://[^/\s:@]*:([^@\s/]+)@")
_SHAPES = re.compile(
    r"(?:sk|rk|pk|ek)_(?:test|live)_[A-Za-z0-9]{6,}"
    r"|whsec_[A-Za-z0-9_+/=-]{6,}"
    r"|asr_[A-Za-z0-9_-]{10,}")
_LIVE_VALUE = re.compile(r"(?:sk|rk|pk|ek)[_-]live[_-]|whsec[_-]live", re.I)
_LIVE_NAME = re.compile(r"(STRIPE.*LIVE|LIVE.*STRIPE)", re.I)
_LIVE_WORDS = frozenset({"live", "livemode", "production"})
_PLACEHOLDER = re.compile(r"REPLACE|CHANGEME|CHANGE_ME|EXAMPLE|XXXX|YOUR_", re.I)
_MIN_SECRET_LEN = 4
#: a hostname as spelled in a URL: letters, digits, dots, hyphens, underscores; or an IP literal
_HOSTNAME = re.compile(r"[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?|[0-9a-f:.]+")
#: values of secret-named variables that are plain words, not secrets
_PLAIN_WORDS = frozenset({"true", "false", "none", "null", "yes", "no", "on", "off", "test",
                          "dev", "prod", "live", "enabled", "disabled"})
_TRUNCATED = 12            # a long secret is also redacted when only its front is shown
_TRUNCATED_FROM = 24


def _secret_values(env: Mapping[str, str]) -> list[tuple[str, str]]:
    """(name, value) for every environment value that must never be shown."""
    items: list[tuple[str, str]] = []

    def keep(name: str, value: str) -> None:
        if len(value) >= _MIN_SECRET_LEN and value.strip().lower() not in _PLAIN_WORDS:
            items.append((name, value))

    for name, value in env.items():
        if not value:
            continue
        for password in _USERINFO.findall(value):
            keep(name, password)
        if not _SECRET_NAME.search(name) or _NOT_SECRET_NAME.search(name):
            continue
        parts = [value] if "\n" in value else [p.strip() for p in value.split(",")]
        for part in parts:
            keep(name, part)
        if value not in parts:
            keep(name, value)
    return items


def variants(value: str, *, truncated: bool = True) -> set[str]:
    """``value`` and the encodings it is likely to turn up in (URL, base64, hex, JSON)."""
    raw = value.encode("utf-8", "replace")
    std, urlsafe = base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()
    out = {value, quote(value, safe=""), quote(value), quote_plus(value),
           json.dumps(value)[1:-1], raw.hex(), raw.hex().upper(), std, urlsafe,
           std.rstrip("="), urlsafe.rstrip("=")}
    if truncated and len(value) >= _TRUNCATED_FROM:
        out.add(value[:_TRUNCATED])
    return {v for v in out if len(v) >= _MIN_SECRET_LEN}


class Redactor:
    """Replaces every known secret (and its encodings), and anything shaped like a credential."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self._needles: set[str] = set()
        for _, value in _secret_values(env):
            self.add(value)

    def add(self, value: str) -> None:
        if len(value) >= _MIN_SECRET_LEN:
            self._needles |= variants(value)

    def __call__(self, text: str) -> str:
        for needle in sorted(self._needles, key=len, reverse=True):
            text = text.replace(needle, REDACTED)
        return _SHAPES.sub(REDACTED, text)

    def obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self(value)
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        if isinstance(value, dict):
            return {self(str(k)): self.obj(v) for k, v in value.items()}
        return value


def _decoded_forms(value: str) -> set[str]:
    """``value`` and what it decodes to (percent-encoding, base64, hex), a few layers deep."""
    seen = {value}
    todo = [value]
    while todo and len(seen) < 64:
        current = todo.pop()
        outs = [unquote(current), unquote_plus(current)]
        for token in re.findall(r"[A-Za-z0-9+/_=-]{16,}", current):
            padded = token + "=" * (-len(token) % 4)
            for decode in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    outs.append(decode(padded).decode("utf-8", "ignore"))
                except (binascii.Error, ValueError):
                    pass
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", token):
                outs.append(bytes.fromhex(token).decode("utf-8", "ignore"))
        for out in outs:
            if out and out not in seen:
                seen.add(out)
                todo.append(out)
    return seen


def live_findings(env: Mapping[str, str]) -> list[str]:
    """Names (never values) of variables that look like live-mode Stripe configuration."""
    found: list[str] = []
    for name, value in env.items():
        if not value:
            continue
        if any(_LIVE_VALUE.search(form) for form in _decoded_forms(value)):
            found.append(f"{name} (value looks like a live-mode Stripe credential)")
        elif _LIVE_NAME.search(name):
            found.append(f"{name} (a Stripe live-mode variable is set)")
        elif "STRIPE" in name.upper() and value.strip().lower() in _LIVE_WORDS:
            found.append(f"{name} (a Stripe variable says live mode)")
        elif name == "ASSURANCE_PAYG_ALLOW_LIVE" and value.strip().lower() not in {
                "0", "false", "no"}:
            found.append(f"{name} (allows pay-as-you-go against live mode)")
    return sorted(set(found))


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------

@dataclass
class Step:
    id: str
    status: str
    detail: str


class Ctx:
    """The environment, the redactor, the two output streams and the runs, for one invocation."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = dict(env)
        self.redact = Redactor(self.env)
        self.run_id = uuid.uuid4().hex
        self.started_at = _now()
        self.runs: list[Run] = []

    def out(self, text: str) -> None:
        sys.stdout.write(self.redact(text) + "\n")

    def err(self, text: str) -> None:
        sys.stderr.write(self.redact(text) + "\n")

    def secrets(self) -> list[tuple[str, str]]:
        return _secret_values(self.env)


@dataclass
class Run:
    phase: str
    ctx: Ctx
    steps: list[Step] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    target_host: str = ""

    def __post_init__(self) -> None:
        self.ctx.runs.append(self)

    def add(self, step_id: str, status: str, detail: str) -> str:
        self.steps.append(Step(step_id, status, detail))
        self.ctx.out(f"{status:<9} {step_id:<34} {detail}")
        return status

    def next_id(self) -> str:
        """The first step of this phase that has not been reported yet."""
        have = {s.id for s in self.steps}
        return next((i for i in STEP_IDS.get(self.phase, ()) if i not in have), f"{self.phase}.end")

    def unchecked_rest(self, reason: str) -> None:
        """Mark every step of this phase not yet reported as UNCHECKED."""
        have = {s.id for s in self.steps}
        for step_id in STEP_IDS.get(self.phase, ()):
            if step_id not in have:
                self.add(step_id, UNCHECKED, reason)

    def note(self, what: str, **info: Any) -> None:
        self.observations.append({"what": what, **info})
        self.ctx.out(f"NOTE      {what}: " + ", ".join(f"{k}={v}" for k, v in info.items()))


def exit_code(steps: Iterable[Step]) -> int:
    statuses = [s.status for s in steps]
    if any(s == FAIL or s not in VALID_STATUSES for s in statuses):
        return 1
    if not statuses or any(s in (UNCHECKED, ATTESTED) for s in statuses):
        return 3
    return 0


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_of(run: Run, state: str = "complete") -> dict[str, Any]:
    redact = run.ctx.redact
    return redact.obj({
        "tool": "staging_rehearsal", "script_version": VERSION, "run_id": run.ctx.run_id,
        "phase": run.phase, "state": state, "started_at": run.ctx.started_at,
        "generated_at": _now(), "mode": "stripe-test-only", "target_host": run.target_host,
        "steps": [{"id": s.id, "status": s.status, "detail": s.detail} for s in run.steps],
        "observations": run.observations, "exit_code": exit_code(run.steps), **run.data})


def _private_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` readable by this user only (0600), in a 0700 directory
    when this call creates the directory."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def write_record(ctx: Ctx, record_dir: str, run: Run, state: str = "complete") -> None:
    _private_write(Path(record_dir) / f"{run.phase}.json",
                   json.dumps(record_of(run, state), indent=2, sort_keys=True) + "\n")


def write_progress(ctx: Ctx, record_dir: str, phase: str) -> None:
    """Replace the previous record at once, so a run that dies leaves no stale PASS behind."""
    doc = {"tool": "staging_rehearsal", "script_version": VERSION, "run_id": ctx.run_id,
           "phase": phase, "state": "in_progress", "started_at": ctx.started_at,
           "generated_at": _now(), "target_host": "", "steps": [], "observations": []}
    _private_write(Path(record_dir) / f"{phase}.json", json.dumps(doc, indent=2) + "\n")


# ---------------------------------------------------------------------------
# HTTP, restricted to the one host it was given
# ---------------------------------------------------------------------------

class RefusedHostError(Exception):
    """A request named a host other than the one under test."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def canonical_host(raw: str) -> str:
    """The host as the HTTP client will use it: lower case, IDNA, no trailing dot."""
    text = raw.strip().lower()
    try:
        text = httpx.URL(f"https://{text}").host
    except (httpx.InvalidURL, ValueError):
        pass
    return text.rstrip(".").lower()


def parse_base_url(raw: str) -> tuple[Any | None, str]:
    """``(parts, "")`` for a usable base URL, else ``(None, why)``. Never echoes the URL."""
    try:
        parts = urlsplit(raw.strip())
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        return None, "the base URL does not parse"
    if parts.scheme not in {"http", "https"} or not host:
        return None, "the base URL must be http(s)://host[:port]"
    if not host.isascii():
        return None, ("the host has non-ASCII characters (a look-alike dot or an IDN); "
                      "give the plain ASCII hostname")
    if host.endswith("."):
        return None, "the host ends with a dot; give the plain hostname"
    if not _HOSTNAME.fullmatch(host):
        return None, ("the host has characters a hostname does not (an encoded form such as "
                      "%2e?); spell it plainly")
    if parts.username is not None or parts.password is not None:
        return None, ("the base URL carries credentials; credentials go in the environment "
                      "only, never in a URL")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        return None, "the base URL must be the bare host, with no path, query or fragment"
    try:
        normalised = httpx.URL(f"{parts.scheme}://{parts.netloc}").host
    except (httpx.InvalidURL, ValueError):
        return None, "the base URL does not parse as a URL"
    try:
        normalised = normalised.encode("idna").decode("ascii")     # xn-- form, as spelled
    except UnicodeError:
        return None, "the host does not survive IDNA normalisation; spell it plainly"
    if normalised != host:
        return None, "the host is ambiguous (an encoded or normalised form differs); spell it plainly"
    if parts.scheme == "http" and not is_loopback(host):
        return None, ("refusing plain http to a non-loopback host: keys and signatures "
                      "would cross the network in clear")
    return parts, ""


class Http:
    """One client, one host. Records every response so it can be searched for secrets.

    ``trust_env=False``: a proxy named in the environment (``HTTP_PROXY`` and friends) would
    receive the register key and every signature. A private CA goes in ``REHEARSAL_CA_BUNDLE``.
    """

    def __init__(self, base_url: str, *, timeout: float, ca_bundle: str = "") -> None:
        self.base = base_url.rstrip("/")
        self.host = (urlsplit(self.base).hostname or "").lower()
        verify: Any = True
        if ca_bundle and self.base.startswith("https"):
            verify = ssl.create_default_context(cafile=ca_bundle)
        self._client = httpx.Client(timeout=timeout, follow_redirects=False, verify=verify,
                                    trust_env=False)
        self.seen: list[str] = []
        self.last_headers: dict[str, str] = {}

    def request(self, method: str, target: str, **kwargs: Any) -> httpx.Response:
        url = target if "://" in target else self.base + target
        host = (urlsplit(url).hostname or "").lower()
        if host != self.host:
            raise RefusedHostError(f"refusing a request to {host or 'an unnamed host'}: "
                                   f"only {self.host} was given")
        response = self._client.request(method, url, **kwargs)
        header_text = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        self.seen.append(header_text + "\n" + response.text)
        self.last_headers = {k.lower(): v for k, v in response.headers.items()}
        return response

    def close(self) -> None:
        self._client.close()


def _problem(exc: BaseException) -> str:
    """A short, safe description of a transport failure: the class, never the message."""
    return type(exc).__name__


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _json_dict(response: httpx.Response) -> dict[str, Any]:
    """The JSON object of a response, or ``{}`` for anything else (a list, text, nothing)."""
    body = _json(response)
    return body if isinstance(body, dict) else {}


# ---------------------------------------------------------------------------
# config-check
# ---------------------------------------------------------------------------

_TEST_KEY = re.compile(r"^(?:sk|rk)_test_[A-Za-z0-9]{16,}$")
_WEBHOOK_SECRET = re.compile(r"^whsec_[A-Za-z0-9_+/=-]{16,}$")
_PRICE = re.compile(r"^price_[A-Za-z0-9]{8,}$")


def phase_config_check(ctx: Ctx, args: argparse.Namespace) -> Run:
    run = Run("config-check", ctx)
    env, expected = ctx.env, bool(args.checkout_expected)
    scanned = len(env)
    run.add("config.no_live_keys", PASS,
            f"no live-mode Stripe marker among {scanned} variables (names and shapes only)")

    def absent(step: str, what: str, *, checkout: bool = True) -> None:
        if expected and checkout:
            run.add(step, FAIL, f"{what} is not set and checkout is expected")
        else:
            run.add(step, UNCHECKED, f"{what} is not set in this environment; nothing can "
                                     "be said about it")

    key = env.get("STRIPE_SECRET_KEY", "")
    if not key:
        absent("config.stripe_secret_key", "STRIPE_SECRET_KEY")
    elif _PLACEHOLDER.search(key):
        run.add("config.stripe_secret_key", FAIL, "STRIPE_SECRET_KEY is still a placeholder")
    elif _TEST_KEY.match(key):
        run.add("config.stripe_secret_key", PASS, "a Stripe test-mode key (sk_test_/rk_test_)")
    else:
        run.add("config.stripe_secret_key", FAIL,
                "STRIPE_SECRET_KEY is not a Stripe test-mode key (expected sk_test_ or rk_test_)")

    whsec = env.get("STRIPE_WEBHOOK_SECRET", "")
    if not whsec:
        absent("config.stripe_webhook_secret", "STRIPE_WEBHOOK_SECRET")
    elif _PLACEHOLDER.search(whsec) or not _WEBHOOK_SECRET.match(whsec):
        run.add("config.stripe_webhook_secret", FAIL,
                "STRIPE_WEBHOOK_SECRET is a placeholder or not a whsec_ signing secret")
    else:
        run.add("config.stripe_webhook_secret", PASS,
                "whsec_ shape ok; Stripe gives test and live signing secrets the same shape, "
                "so confirm in the dashboard that it belongs to the TEST endpoint")

    api_keys = [k.strip() for k in env.get("ASSURANCE_API_KEYS", "").split(",") if k.strip()]
    if not api_keys:
        absent("config.api_keys", "ASSURANCE_API_KEYS", checkout=False)
    elif any(len(k) < 32 for k in api_keys):
        run.add("config.api_keys", FAIL,
                "an operator key is shorter than 32 characters (use `openssl rand -hex 24`)")
    elif any(_PLACEHOLDER.search(k) for k in api_keys):
        run.add("config.api_keys", FAIL, "an operator key is still a placeholder")
    else:
        run.add("config.api_keys", PASS, f"{len(api_keys)} operator key(s), each 32+ characters")

    if env.get("ASSURANCE_ALLOW_UNAUTHENTICATED", "") == "1":
        run.add("config.allow_unauthenticated", FAIL,
                "ASSURANCE_ALLOW_UNAUTHENTICATED=1 opens every write to anyone")
    else:
        run.add("config.allow_unauthenticated", ATTESTED,
                "ASSURANCE_ALLOW_UNAUTHENTICATED is not set in THIS shell. That says nothing "
                "about the host (only `fly secrets list` shows names; smoke's /healthz "
                "auth_mode observes it): attested, not measured")

    public = env.get("ASSURANCE_PUBLIC_URL", "")
    if not public:
        absent("config.public_url", "ASSURANCE_PUBLIC_URL", checkout=False)
    else:
        parts = urlsplit(public)
        if parts.scheme != "https" or not parts.hostname or _PLACEHOLDER.search(public):
            run.add("config.public_url", FAIL,
                    "ASSURANCE_PUBLIC_URL must be the real https hostname, not a placeholder")
        else:
            run.add("config.public_url", PASS, f"https host {parts.hostname}")

    marketing = env.get("ASSURANCE_MARKETING_URL", "")
    origins = [o.strip() for o in env.get("ASSURANCE_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if not marketing and not origins:
        absent("config.site_origin", "ASSURANCE_MARKETING_URL / ASSURANCE_ALLOWED_ORIGINS")
    else:
        problems = []
        for label, value in (("ASSURANCE_MARKETING_URL", marketing),
                             *(("ASSURANCE_ALLOWED_ORIGINS", o) for o in origins)):
            if not value:
                continue
            site = urlsplit(value)
            site_host = (site.hostname or "").lower()
            if _PLACEHOLDER.search(value) or "<" in value or ">" in value:
                problems.append(f"{label} is a placeholder")
            elif site.scheme not in {"http", "https"} or not site_host or site.query \
                    or site.path not in {"", "/"} or (site.scheme == "http"
                                                      and not is_loopback(site_host)):
                problems.append(f"{label} is not a bare https origin (scheme://host[:port])")
            elif canonical_host(site_host) in PRODUCTION_HOSTS:
                problems.append(f"{label} points at the production site, not a staging site")
        run.add("config.site_origin", FAIL if problems else PASS,
                "; ".join(problems) if problems else
                "the site origin(s) are staging https origins: "
                + ", ".join(sorted({urlsplit(v).hostname or "" for v in [marketing, *origins]
                                    if v})))

    purchasable: dict[str, bool] = {}
    prices: dict[str, str] = {}
    for tier in ("register", "cell"):
        name = PLANS[tier].price_env            # the env name plans.py reads, not a copy of it
        value = env.get(name, "")
        prices[tier] = value
        purchasable[tier] = bool(value)         # the rule Plan.purchasable applies
        step = f"config.price_{tier}"
        if not value:
            absent(step, name)
        elif _PLACEHOLDER.search(value) or not _PRICE.match(value):
            run.add(step, FAIL, f"{name} is a placeholder or not a Stripe price id (price_...)")
        elif tier == "cell" and value == prices["register"]:
            run.add(step, FAIL, f"{name} equals the Register price id: two SKUs, one price")
        else:
            run.add(step, PASS, f"{name} is set and shaped like a price id; it was not "
                                "looked up or created (Stripe price ids carry no mode)")
    run.data["purchasable"] = purchasable
    run.data["payg"] = {
        "price_env_set": bool(env.get(PLANS["payg"].price_env, "")),
        "meter_event_set": bool(env.get("ASSURANCE_PAYG_METER_EVENT", ""))}
    names = [t for t, ok in purchasable.items() if ok] or ["none"]
    ctx.out("NOTE      purchasable SKUs (price env set; nothing was created at Stripe): "
            + ", ".join(names))
    return run


# ---------------------------------------------------------------------------
# smoke
# ---------------------------------------------------------------------------

_GATED = ("POST", "/v1/machine/verify")     # a Cell-gated route (require_machine)
_OBSERVED_HEADERS = ("strict-transport-security", "x-content-type-options",
                     "x-frame-options", "content-security-policy", "referrer-policy")


def _strip(plan: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in plan.items() if k != "purchasable"}


def _differs(remote: dict[str, Any], local: dict[str, Any]) -> list[str]:
    keys = sorted(set(remote) | set(local))
    return [k for k in keys if remote.get(k) != local.get(k)]


def check_plans(http: Http, run: Run) -> dict[str, bool] | None:
    try:
        response = http.request("GET", "/v1/plans")
    except httpx.HTTPError as exc:
        run.add("smoke.plans", FAIL, f"GET /v1/plans did not complete ({_problem(exc)})")
        return None
    body = _json(response)
    if response.status_code != 200 or not isinstance(body, list):
        run.add("smoke.plans", FAIL, f"GET /v1/plans answered {response.status_code}, "
                                      "not a 200 list")
        return None
    local = {p["tier"]: _strip(json.loads(json.dumps(p))) for p in public_catalogue()
             if p["tier"] in {"free", "register", "cell"}}
    local["payg"] = _strip(json.loads(json.dumps(PLANS["payg"].to_public_dict())))
    remote: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for item in body:
        if not isinstance(item, dict) or not isinstance(item.get("tier"), str):
            problems.append("an entry has no tier")
            continue
        remote[item["tier"]] = item
    order = [t for t in (i.get("tier") for i in body if isinstance(i, dict))
             if t in {"free", "register", "cell"}]
    if order != ["free", "register", "cell"][:len(order)] or len(order) != 3:
        problems.append(f"tiers are {order}, expected free, register, cell")
    for tier, plan in remote.items():
        if tier not in local:
            problems.append(f"tier {tier!r} is listed but is not on sale")
        elif (diff := _differs(_strip(plan), local[tier])):
            problems.append(f"{tier} differs from billing/plans.py in: {', '.join(diff)}")
        if not isinstance(plan.get("purchasable"), bool):
            problems.append(f"{tier} has no boolean purchasable")
    if problems:
        run.add("smoke.plans", FAIL, "; ".join(problems))
        return None
    run.add("smoke.plans", PASS,
            f"GET /v1/plans lists {', '.join(remote)}; every field but `purchasable` "
            "equals billing/plans.py public_catalogue()")
    return {t: bool(p["purchasable"]) for t, p in remote.items()}


def check_tls(host: str, port: int, *, cafile: str, min_days: int,
              timeout: float) -> tuple[str, str]:
    """Read-only: handshake, verify, read notAfter. Returns (status, detail)."""
    context = ssl.create_default_context(cafile=cafile or None)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, \
                context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return FAIL, f"certificate verification failed: {exc.verify_message}"
    except ssl.SSLError as exc:
        return FAIL, f"TLS handshake failed ({exc.reason or type(exc).__name__})"
    except OSError as exc:
        return UNCHECKED, f"could not connect to {host}:{port} ({_problem(exc)}); " \
                          "certificate not read"
    if not cert or "notAfter" not in cert:
        return FAIL, "the server presented no readable certificate"
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(str(cert["notAfter"])), dt.UTC)
    days = (expires - dt.datetime.now(dt.UTC)).total_seconds() / 86400
    if days < min_days:
        return FAIL, (f"certificate expires {expires:%Y-%m-%d}, in {days:.1f} days; "
                      f"minimum is {min_days}")
    return PASS, f"certificate verifies and expires {expires:%Y-%m-%d} ({days:.0f} days left)"


def judge_redirect(status_code: int, location: str, host: str) -> tuple[str, str]:
    """Is this answer to ``http://host/`` a redirect to https on exactly the same host?"""
    if status_code not in {301, 302, 307, 308}:
        return FAIL, f"http://{host}/ answered {status_code} and does not redirect to https"
    try:
        target = urlsplit(location)
        target_host = (target.hostname or "").lower().rstrip(".")
    except ValueError:
        return FAIL, "the Location header does not parse"
    if target.scheme != "https" or target_host != host.lower().rstrip("."):
        return FAIL, (f"http://{host}/ answered {status_code} but the Location is not https on "
                      f"{host} (scheme {target.scheme or 'none'!r}, a different or missing host)")
    return PASS, f"http://{host}/ answers {status_code} to https on the same host"


def check_https_redirect(http: Any, host: str) -> tuple[str, str]:
    """The one cleartext request to a hosted host: a bare GET, no key, no signature, no body."""
    try:
        got = http.request("GET", f"http://{host}/healthz")
    except httpx.HTTPError as exc:
        return UNCHECKED, f"port 80 did not answer ({_problem(exc)}); redirect not observed"
    return judge_redirect(got.status_code, got.headers.get("location", ""), host)


def phase_smoke(ctx: Ctx, args: argparse.Namespace) -> Run:
    run = Run("smoke", ctx)
    raw = args.base_url or ctx.env.get("REHEARSAL_BASE_URL", "")
    if not raw:
        run.unchecked_rest("no base URL: set REHEARSAL_BASE_URL or pass --base-url")
        return run
    parts, why = parse_base_url(raw)
    if parts is None:
        run.add("smoke.base_url", FAIL, why)
        run.unchecked_rest("not attempted: the base URL was refused")
        return run
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    run.target_host = host
    ca = ctx.env.get("REHEARSAL_CA_BUNDLE", "")
    if ca and not Path(ca).is_file():
        run.add("smoke.base_url", FAIL, "REHEARSAL_CA_BUNDLE is not a readable file")
        run.unchecked_rest("not attempted: the CA bundle was refused")
        return run
    run.add("smoke.base_url", PASS, f"{parts.scheme}://{host}"
            + (f":{parts.port}" if parts.port else ""))
    http = Http(f"{parts.scheme}://{parts.netloc}", timeout=float(args.timeout), ca_bundle=ca)
    try:
        _smoke_checks(ctx, run, http, args, host, port, parts.scheme, ca)
    finally:
        http.close()
    return run


def _smoke_checks(ctx: Ctx, run: Run, http: Http, args: argparse.Namespace, host: str,
                  port: int, scheme: str, ca: str) -> None:
    reachable = True
    try:
        response = http.request("GET", "/healthz")
    except httpx.HTTPError as exc:
        run.add("smoke.healthz", FAIL, f"GET /healthz did not complete ({_problem(exc)})")
        reachable = False
    else:
        body = _json(response)
        problems = []
        if response.status_code != 200 or not isinstance(body, dict):
            problems.append(f"answered {response.status_code}, not a 200 object")
        else:
            if body.get("status") != "ok":
                problems.append(f"status is {body.get('status')!r}")
            if body.get("ledger_ok") is not True or body.get("accounts_ok") is not True:
                problems.append("a store does not open")
            if body.get("auth_mode") != "api_key":
                problems.append(f"auth_mode is {body.get('auth_mode')!r}, not 'api_key'")
        if problems:
            run.add("smoke.healthz", FAIL, "; ".join(problems))
        else:
            run.add("smoke.healthz", PASS, "ok; both stores open; auth_mode is api_key")
        seen = dict(http.last_headers)
        run.note("response headers on /healthz (observed, not gated: the API sets none of "
                 "these itself)",
                 present=",".join(h for h in _OBSERVED_HEADERS if h in seen) or "none",
                 absent=",".join(h for h in _OBSERVED_HEADERS if h not in seen) or "none")

    not_attempted = "not attempted: /healthz was unreachable"
    remote_purchasable = check_plans(http, run) if reachable else None
    if not reachable:
        run.add("smoke.plans", UNCHECKED, not_attempted)
    expect = [t for t in (args.expect_purchasable or "").split(",") if t]
    if not expect:
        run.add("smoke.plans_purchasable", UNCHECKED,
                "no expectation given (--expect-purchasable register,cell)")
    elif remote_purchasable is None:
        run.add("smoke.plans_purchasable", UNCHECKED, "the plan catalogue was not read")
    else:
        missing = [t for t in expect if not remote_purchasable.get(t)]
        run.add("smoke.plans_purchasable", FAIL if missing else PASS,
                f"not purchasable: {', '.join(missing)} (its ASSURANCE_PRICE_* is unset on "
                "the host)" if missing else f"purchasable as expected: {', '.join(expect)}")

    def gated(headers: dict[str, str]) -> httpx.Response:
        return http.request(_GATED[0], _GATED[1], json={}, headers=headers)

    for step, label, headers, want in (
            ("smoke.no_key_401", "no key", {}, 401),
            ("smoke.bad_key_401", "a made-up key", {"X-API-Key": "asr_" + secrets.token_hex(16)},
             401)):
        if not reachable:
            run.add(step, UNCHECKED, not_attempted)
            continue
        try:
            got = gated(headers).status_code
        except httpx.HTTPError as exc:
            run.add(step, FAIL, f"the request did not complete ({_problem(exc)})")
            continue
        run.add(step, PASS if got == want else FAIL,
                f"{_GATED[1]} with {label} answered {got}" + ("" if got == want
                                                              else f", expected {want}"))

    register_key = ctx.env.get("REHEARSAL_REGISTER_KEY", "")
    if not register_key:
        run.add("smoke.register_key_402", UNCHECKED,
                "REHEARSAL_REGISTER_KEY is not set: the 402 for an authenticated but "
                "unentitled caller was not exercised")
    elif not reachable:
        run.add("smoke.register_key_402", UNCHECKED, not_attempted)
    else:
        try:
            got = gated({"X-API-Key": register_key}).status_code
            if got == 402:
                run.add("smoke.register_key_402", PASS,
                        f"a Register key on {_GATED[1]} answered 402")
            elif got == 401:
                run.add("smoke.register_key_402", FAIL,
                        "the host does not recognise this key (401): it is not a valid key "
                        "on this host")
            elif got == 200:
                me = http.request("GET", "/v1/me", headers={"X-API-Key": register_key})
                tier = (_json(me) or {}).get("tier") if me.status_code == 200 else None
                run.add("smoke.register_key_402", FAIL,
                        f"the key was ADMITTED to a Cell-gated route (200); its tier is "
                        f"{tier!r} - either entitlements are not enforced or this is not a "
                        "Register-only key")
            else:
                run.add("smoke.register_key_402", FAIL, f"answered {got}, expected 402")
        except httpx.HTTPError as exc:
            run.add("smoke.register_key_402", FAIL,
                    f"the request did not complete ({_problem(exc)})")

    origin = ctx.env.get("REHEARSAL_ORIGIN", "https://neuralbridge.io")
    if not reachable:
        run.add("smoke.cors", UNCHECKED, not_attempted)
    else:
        try:
            def preflight(o: str) -> dict[str, str]:
                http.request("OPTIONS", "/v1/plans", headers={
                    "Origin": o, "Access-Control-Request-Method": "GET"})
                return http.last_headers
            allowed = preflight(origin)
            hostile = preflight("https://evil.invalid")
            problems = []
            if allowed.get("access-control-allow-origin") != origin:
                problems.append("the marketing origin is not echoed exactly "
                                f"({allowed.get('access-control-allow-origin')!r})")
            if hostile.get("access-control-allow-origin") in {"*", "https://evil.invalid"}:
                problems.append("an unlisted origin is allowed")
            if allowed.get("access-control-allow-credentials", "").lower() == "true":
                problems.append("credentialed CORS is on")
            run.add("smoke.cors", FAIL if problems else PASS,
                    "; ".join(problems) if problems else
                    f"preflight echoes {origin} and refuses an unlisted origin")
        except httpx.HTTPError as exc:
            run.add("smoke.cors", FAIL, f"the preflight did not complete ({_problem(exc)})")

    if scheme != "https":
        run.add("smoke.https_redirect", UNCHECKED, "not an https target (plain http loopback)")
        run.add("smoke.tls_cert", UNCHECKED, "not an https target (plain http loopback)")
    else:
        if port != 443:
            run.add("smoke.https_redirect", UNCHECKED,
                    f"non-default port {port}: the port-80 redirect is not this endpoint")
        else:
            run.add("smoke.https_redirect", *check_https_redirect(http, host))
        status, detail = check_tls(host, port, cafile=ca, min_days=int(args.min_cert_days),
                                   timeout=float(args.timeout))
        run.add("smoke.tls_cert", status, detail)

    provided = ctx.secrets()
    blob = "\n".join(http.seen)
    if not http.seen:
        run.add("smoke.provided_secrets_absent", UNCHECKED, "no response was received")
    elif not provided:
        run.add("smoke.provided_secrets_absent", UNCHECKED,
                "no secret was provided in the environment, so there was nothing to search for")
    else:
        leaked = sorted({name for name, value in provided
                         if any(v in blob for v in variants(value, truncated=False))})
        run.add("smoke.provided_secrets_absent", FAIL if leaked else PASS,
                f"a provided secret appeared in a response: {', '.join(leaked)}" if leaked
                else f"none of {len({n for n, _ in provided})} provided secret variable(s) "
                     "appeared in any response body or header")
    if not http.seen:
        run.add("smoke.no_secret_shapes", UNCHECKED, "no response was received")
    else:
        kinds = sorted({m.group(0).split("_")[0] + "_" for m in _SHAPES.finditer(blob)})
        run.add("smoke.no_secret_shapes", FAIL if kinds else PASS,
                f"credential-shaped strings in a response: {', '.join(kinds)}" if kinds
                else "no Stripe-key, webhook-secret or API-key shaped string in any response")


# ---------------------------------------------------------------------------
# webhook-test
# ---------------------------------------------------------------------------

def sign_event(payload: bytes, secret: str, *, at: int | None = None) -> str:
    stamp = str(int(time.time()) if at is None else at)
    mac = hmac.new(secret.encode(), f"{stamp}.".encode() + payload, hashlib.sha256)
    return f"t={stamp},v1={mac.hexdigest()}"


def phase_webhook(ctx: Ctx, args: argparse.Namespace) -> Run:
    run = Run("webhook-test", ctx)
    env = ctx.env
    raw = args.base_url or env.get("REHEARSAL_BASE_URL", "")
    if not raw:
        run.unchecked_rest("no base URL: set REHEARSAL_BASE_URL or pass --base-url")
        return run
    parts, why = parse_base_url(raw)
    if parts is None:
        run.add("webhook.preconditions", FAIL, f"REFUSED: {why}")
        ctx.err(f"REFUSED: {why}")
        run.unchecked_rest("not attempted: the base URL was refused")
        return run
    host = canonical_host(parts.hostname or "")
    run.target_host = host
    deny = PRODUCTION_HOSTS | {canonical_host(h) for h in
                               env.get("REHEARSAL_PRODUCTION_HOSTS", "").split(",") if h.strip()}
    refusal = ""
    if not args.i_am_testing_staging:
        refusal = ("webhook-test posts a synthetic signed checkout event and creates a test "
                   "account on the host; pass --i-am-testing-staging to say that host is staging")
    elif host in deny:
        refusal = f"{host} is on the production deny list"
    if refusal:
        run.add("webhook.preconditions", FAIL, f"REFUSED: {refusal}")
        ctx.err(f"REFUSED: {refusal}")
        run.unchecked_rest("not attempted: preconditions refused")
        return run
    confirm = canonical_host(env.get("STAGING_CONFIRM", ""))
    if not confirm:
        run.add("webhook.preconditions", UNCHECKED,
                f"STAGING_CONFIRM is not set; set it to {host} to confirm this host is staging")
        run.unchecked_rest("not attempted: staging was not confirmed")
        return run
    if confirm != host:
        run.add("webhook.preconditions", FAIL,
                "REFUSED: STAGING_CONFIRM does not equal the base URL's hostname")
        ctx.err("REFUSED: STAGING_CONFIRM does not equal the base URL's hostname")
        run.unchecked_rest("not attempted: staging confirmation mismatch")
        return run
    run.add("webhook.preconditions", PASS,
            f"--i-am-testing-staging given and STAGING_CONFIRM equals {host}, which is not on "
            "the production deny list (a speed bump: it cannot see a CNAME or an alias)")

    secret = env.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        run.add("webhook.secret_is_test", UNCHECKED, "STRIPE_WEBHOOK_SECRET is not set")
        run.unchecked_rest("not attempted: no webhook signing secret")
        return run
    if not _WEBHOOK_SECRET.match(secret) or _PLACEHOLDER.search(secret):
        run.add("webhook.secret_is_test", FAIL,
                "STRIPE_WEBHOOK_SECRET is a placeholder or not a whsec_ signing secret")
        run.unchecked_rest("not attempted: the signing secret was refused")
        return run
    if env.get("STAGING_STRIPE_MODE", "").strip().lower() != "test":
        run.add("webhook.secret_is_test", UNCHECKED,
                "STAGING_STRIPE_MODE=test is not set. A whsec_ string does not reveal its mode; "
                "this is your statement that it comes from the TEST-mode endpoint")
        run.unchecked_rest("not attempted: test mode was not stated")
        return run
    run.add("webhook.secret_is_test", ATTESTED,
            "whsec_ shaped; that it is a TEST-mode secret is STAGING_STRIPE_MODE=test, your "
            "statement, not a measurement (blocks exit 0)")

    ca = env.get("REHEARSAL_CA_BUNDLE", "")
    http = Http(f"{parts.scheme}://{parts.netloc}", timeout=float(args.timeout), ca_bundle=ca)
    try:
        _webhook_steps(ctx, run, http, secret, float(args.poll_seconds))
    except httpx.HTTPError as exc:
        run.add(run.next_id(), FAIL, f"the host did not answer ({_problem(exc)})")
    finally:
        http.close()
        run.unchecked_rest("not attempted: an earlier step did not complete")
    return run


def _cleanup_key(run: Run, http: Http, api_key: str) -> None:
    """Revoke the test key and show it no longer authenticates; say so loudly if it cannot."""
    prefix = api_key[:10]
    warning = (f"a live test key may remain on the host; revoke it by prefix {prefix} "
               "(POST /v1/keys/revoke with that key_prefix), or disable the account in the "
               "staging account store")
    try:
        revoked = http.request("POST", "/v1/keys/revoke", headers={"X-API-Key": api_key}, json={})
        after = http.request("GET", "/v1/me", headers={"X-API-Key": api_key})
    except Exception as exc:  # noqa: BLE001 - whatever failed, the key may still be live
        run.add("webhook.cleanup", FAIL, f"{warning} ({_problem(exc)})")
        return
    if revoked.status_code == 200 and _json_dict(revoked).get("revoked") is True \
            and after.status_code == 401:
        run.add("webhook.cleanup", PASS,
                "the test key was revoked and no longer authenticates (401)")
    else:
        run.add("webhook.cleanup", FAIL,
                f"{warning}: revoking answered {revoked.status_code} and the key then "
                f"answered {after.status_code}")


def _webhook_steps(ctx: Ctx, run: Run, http: Http, secret: str, poll_seconds: float) -> None:
    tag = secrets.token_hex(6)
    session, customer = f"cs_test_rehearsal_{tag}", f"cus_rehearsal_{tag}"
    email = f"rehearsal-{tag}@example.invalid"
    event = {"id": f"evt_rehearsal_{tag}", "created": int(time.time()),
             "type": "checkout.session.completed",
             "data": {"object": {
                 "id": session, "payment_status": "paid", "customer": customer,
                 "subscription": f"sub_rehearsal_{tag}",
                 "customer_details": {"email": email},
                 "metadata": {"tier": "register", "company": "Rehearsal (synthetic)"}}}}
    raw = json_bytes(event)
    api_key = ""

    def post(payload: bytes, header: str) -> httpx.Response:
        return http.request("POST", "/v1/billing/webhook", content=payload, headers={
            "stripe-signature": header, "content-type": "application/json"})

    def take(response: httpx.Response) -> None:
        """Remember a key a host handed over, so that it is always revoked."""
        nonlocal api_key
        found = _json_dict(response).get("api_key")
        if response.status_code == 200 and isinstance(found, str) and found:
            api_key = found
            ctx.redact.add(found)

    try:
        # 1. a forged signature must be refused, using a harmless event that grants nothing
        ping = json_bytes({"id": f"evt_rehearsal_forged_{tag}", "created": int(time.time()),
                           "type": "rehearsal.forged_ping", "data": {"object": {}}})
        forged = post(ping, sign_event(ping, "whsec_" + secrets.token_hex(16)))
        detail = _json_dict(forged).get("detail")
        error = detail.get("error") if isinstance(detail, dict) else None
        if forged.status_code == 400 and error == "signature_rejected":
            run.add("webhook.forged_rejected", PASS, "a wrong-secret signature was refused (400)")
        else:
            run.add("webhook.forged_rejected", FAIL,
                    f"a forged signature was answered {forged.status_code}, not refused with "
                    "400 signature_rejected: the endpoint may not verify signatures")
            return

        # 2. nothing is claimable before delivery
        before = http.request("GET", "/v1/checkout/complete", params={"session_id": session})
        if before.status_code == 202:
            run.add("webhook.pending_before", PASS, "the session is pending (202) before delivery")
        else:
            take(before)            # a key for a session nobody paid for: still ours to revoke
            run.add("webhook.pending_before", FAIL,
                    f"before delivery the session answered {before.status_code}, expected 202")
            return

        # 3. deliver the real (synthetic) event, correctly signed with the TEST secret
        header = sign_event(raw, secret)
        delivered = post(raw, header)
        body = _json_dict(delivered)
        if delivered.status_code == 200 and body.get("tier") == "register" \
                and body.get("account_id"):
            run.add("webhook.delivered", PASS,
                    "a signed checkout.session.completed (tier register) was accepted (200)")
        else:
            error = (body.get("detail") or {}).get("error") \
                if isinstance(body.get("detail"), dict) else None
            run.add("webhook.delivered", FAIL,
                    f"the signed event was answered {delivered.status_code}"
                    + (f" ({error})" if error else "")
                    + "; the host's STRIPE_WEBHOOK_SECRET may differ from yours")
            return
        run.note("synthetic test account created on the host (staging only)", email=email,
                 stripe_customer=customer,
                 reconcile="reports it as unknown_in_stripe",
                 key="revoked at the end of this phase; see webhook.cleanup")

        # 4. the same event again is a duplicate, not a second grant
        again = post(raw, header)
        if again.status_code == 200 and _json_dict(again).get("duplicate") is True:
            run.add("webhook.replay_duplicate", PASS,
                    "the same event again was a duplicate (200)")
        else:
            run.add("webhook.replay_duplicate", FAIL,
                    f"redelivery answered {again.status_code} and was not marked duplicate")

        # 5. the key is handed over exactly once
        deadline = time.monotonic() + poll_seconds
        while True:
            handed = http.request("GET", "/v1/checkout/complete",
                                  params={"session_id": session})
            if handed.status_code != 202 or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        take(handed)
        payload = _json_dict(handed)
        if api_key:
            problems = []
            if "no-store" not in handed.headers.get("cache-control", "").lower():
                problems.append("the response carrying the key is cacheable (no "
                                "Cache-Control: no-store)")
            if payload.get("tier") != "register":
                problems.append(f"the key's tier is {payload.get('tier')!r}")
            second = http.request("GET", "/v1/checkout/complete",
                                  params={"session_id": session})
            if second.status_code != 202:
                problems.append(f"a second collection answered {second.status_code}: the key "
                                "was handed over more than once")
            run.add("webhook.key_handover_once", FAIL if problems else PASS,
                    "; ".join(problems) if problems else
                    "the key was collected once (200, no-store) and a second collection was 202")
        else:
            run.add("webhook.key_handover_once", FAIL,
                    f"no key was handed over within {poll_seconds:g}s (last answer "
                    f"{handed.status_code}); the webhook may not have been processed")
            return

        # 6. the key works (what happens next must not depend on this)
        me = http.request("GET", "/v1/me", headers={"X-API-Key": api_key})
        tier = _json_dict(me).get("tier") if me.status_code == 200 else None
        run.add("webhook.key_works", PASS if tier == "register" else FAIL,
                "the handed-over key authenticates and is on the Register plan"
                if tier == "register" else
                f"GET /v1/me with the new key answered {me.status_code}, tier {tier!r}")
    finally:
        # 7. whatever happened above, including an interrupt, no live test key is left behind
        if api_key:
            _cleanup_key(run, http, api_key)


def json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


# ---------------------------------------------------------------------------
# restore-drill
# ---------------------------------------------------------------------------

def _ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=10)


def read_counts(root: Path) -> dict[str, int]:
    """Row counts from a data directory, keyed as restore_check's ``checked``.

    Only ever called on the drill's own scratch copy: SQLite leaves ``-wal`` and ``-shm``
    files beside a write-ahead-log database it merely reads, and that must never be the source.
    """
    counts: dict[str, int] = {}

    def count(path: Path, sql: str) -> int:
        db = _ro(path)
        try:
            return int(db.execute(sql).fetchone()[0])
        finally:
            db.close()

    counts["accounts.db"] = count(root / "accounts.db", "SELECT COUNT(*) FROM accounts")
    if (root / "art14-register.db").exists():
        counts["art14-register.db"] = count(root / "art14-register.db",
                                            "SELECT COUNT(*) FROM chain")
    for path in sorted((root / "tenants").glob("*.db")) if (root / "tenants").is_dir() else []:
        counts[f"tenants/{path.name}"] = count(path, "SELECT COUNT(*) FROM chain")
    for name in ("attestations", "supplier-feeds"):
        if (root / name).is_dir():
            counts[f"{name}/"] = sum(1 for _ in (root / name).glob("*"))
    return counts


def _overlaps(a: Path, b: Path) -> bool:
    a, b = a.resolve(), b.resolve()
    return a == b or a in b.parents or b in a.parents


def _fingerprint(root: Path) -> dict[str, str]:
    """Every path under ``root`` with a content hash for files: listing and bytes in one."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            out[rel] = "<symlink>"
        elif path.is_dir():
            out[rel] = "<dir>"
        else:
            out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _symlinks(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_symlink())


def _sidecars(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.name.endswith(("-wal", "-shm", "-journal")))


def _wipe_dir(path: Path) -> None:
    """Remove everything inside ``path`` (never ``path`` itself)."""
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _changed(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))


def phase_restore(ctx: Ctx, args: argparse.Namespace) -> Run:
    run = Run("restore-drill", ctx)
    data_raw = args.data_dir or ctx.env.get("REHEARSAL_DATA_DIR", "")
    if not data_raw and not args.backup_dir:
        run.unchecked_rest("no data directory: pass --data-dir (or --backup-dir), or set "
                           "REHEARSAL_DATA_DIR")
        return run
    data = Path(data_raw) if data_raw else None
    supplied = Path(args.backup_dir) if args.backup_dir else None

    def refuse(step: str, why: str) -> Run:
        run.add(step, FAIL, f"REFUSED: {why}")
        ctx.err(f"REFUSED: {why}")
        run.unchecked_rest("not attempted: refused before anything was written")
        return run

    # everything that decides whether to run at all happens before a single write
    if data is not None:
        if not data.is_dir():
            run.add("restore.source", FAIL, "the data directory does not exist")
            run.unchecked_rest("not attempted: no source")
            return run
        if not (data / "accounts.db").is_file():
            run.add("restore.source", FAIL, "accounts.db is missing from the data directory")
            run.unchecked_rest("not attempted: no source")
            return run
        if links := _symlinks(data):
            return refuse("restore.source", f"the data directory holds {len(links)} symlink(s) "
                                            "(first: " + links[0] + "); a copy would follow them")
        if (live := _sidecars(data)) and not args.i_know_the_service_is_stopped:
            return refuse("restore.source", (
                f"{live[0]} exists, so a service may have this database open and a file copy "
                "could be torn; stop the service or pass --i-know-the-service-is-stopped"))
    if supplied is not None:
        if not supplied.is_dir():
            run.add("restore.backup", FAIL, "the supplied backup directory does not exist")
            run.unchecked_rest("not attempted: no backup")
            return run
        if links := _symlinks(supplied):
            return refuse("restore.backup", f"the backup directory holds {len(links)} "
                                            "symlink(s); a copy would follow them")
    work_parent = Path(args.work_dir) if args.work_dir else None
    for guarded in (data, supplied):
        if guarded is not None and work_parent is not None and _overlaps(work_parent, guarded):
            return refuse("restore.backup", "--work-dir overlaps a directory this drill must "
                                            "not write to or wipe")

    before = {label: _fingerprint(root) for label, root in (("data", data), ("backup", supplied))
              if root is not None}
    if work_parent is not None:
        work_parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="rehearsal-restore-",
                                    dir=str(work_parent) if work_parent else None))
    try:
        _restore_steps(run, data, supplied, scratch)
    except (OSError, sqlite3.Error) as exc:
        run.add(run.next_id(), FAIL, f"the drill could not finish ({_problem(exc)})")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        touched = [f"{label}: {', '.join(_changed(before[label], _fingerprint(root))[:5])}"
                   for label, root in (("data", data), ("backup", supplied))
                   if root is not None and _changed(before[label], _fingerprint(root))]
        n_paths = sum(len(v) for v in before.values())
        run.add("restore.source_untouched", FAIL if touched else PASS,
                "the source changed during the drill (" + "; ".join(touched) + ")" if touched
                else f"{n_paths} path(s) in the source listing and every file hash are identical "
                     "before and after (no -wal or -shm was left behind)")
        run.unchecked_rest("not attempted: an earlier step did not complete")
    return run


def _restore_steps(run: Run, data: Path | None, supplied: Path | None, scratch: Path) -> None:
    source_counts: dict[str, int] | None = None
    source_copy: Path | None = None
    if data is None:
        run.add("restore.source", UNCHECKED, "no --data-dir: there is no source to compare "
                                              "restored counts with")
    else:
        # SQLite never opens the source: everything below works on this copy
        source_copy = scratch / "source"
        shutil.copytree(data, source_copy, symlinks=True)
        try:
            source_counts = read_counts(source_copy)
        except sqlite3.Error as exc:
            run.add("restore.source", FAIL, f"a source database cannot be read ({_problem(exc)})")
            return
        run.add("restore.source", PASS, "counts from a scratch copy (the source is never opened "
                                        "by SQLite): " + ", ".join(
                                            f"{k}={v}" for k, v in sorted(source_counts.items())))

    if supplied is not None:
        backup = supplied
        run.add("restore.backup", PASS, "using the supplied backup directory (not taken by "
                                        "this drill)")
    else:
        assert source_copy is not None
        backup = scratch / "backup"
        taken = restore_check.backup(source_copy, backup)
        run.add("restore.backup", PASS, f"consistent snapshot of {len(taken)} item(s) of the "
                                        "scratch copy: " + ", ".join(taken))

    # a scratch volume that really held something, really wiped, really restored byte for byte
    volume = scratch / "volume"
    shutil.copytree(source_copy or backup, volume, symlinks=True)
    held = sum(1 for p in volume.rglob("*") if p.is_file())
    _wipe_dir(volume)
    left = sorted(p.name for p in volume.iterdir())
    if left:
        run.add("restore.wipe_restore", FAIL,
                f"the scratch volume held {held} file(s) and {len(left)} item(s) survived the "
                "wipe, so nothing was restored into an empty volume")
        return
    shutil.copytree(backup, volume, symlinks=True, dirs_exist_ok=True)
    differing = _changed(_fingerprint(backup), _fingerprint(volume))
    if differing:
        run.add("restore.wipe_restore", FAIL, "restored files differ from the backup: "
                + ", ".join(differing[:5]))
        return
    run.add("restore.wipe_restore", PASS,
            f"scratch volume held {held} file(s), was wiped (empty), then "
            f"{sum(1 for p in volume.rglob('*') if p.is_file())} file(s) were restored from the "
            "backup and match it byte for byte")

    result = restore_check.verify(volume)
    problems = [str(p) for p in result.get("problems", [])]  # type: ignore[attr-defined]
    if result.get("status") == "unchecked":
        run.add("restore.verify", UNCHECKED,
                "the backup has no manifest (taken by an older build): consistent as far as it "
                "can be read, but nothing says no ledger or file is missing")
    else:
        run.add("restore.verify", PASS if result.get("ok") else FAIL,
                "integrity_check ok, every hash chain verifies, every tenant ledger has an "
                "account, every manifest file present with its recorded hash"
                if result.get("ok") else "; ".join(problems)
                or "the restored volume does not verify")
    checked: dict[str, int] = dict(result.get("checked", {}))  # type: ignore[call-overload]

    if source_counts is None:
        run.add("restore.counts_match", UNCHECKED,
                "no --data-dir: restored counts could not be compared with a source")
    else:
        mismatched = [k for k in sorted(set(source_counts) | set(checked))
                      if source_counts.get(k) != checked.get(k)]
        entries = sum(v for k, v in checked.items() if k.endswith(".db") and k != "accounts.db")
        if mismatched:
            run.add("restore.counts_match", FAIL,
                    "source and restored counts differ for: " + ", ".join(mismatched))
        elif entries == 0:
            run.add("restore.counts_match", UNCHECKED,
                    "counts match but no ledger holds an entry, so nothing about a hash chain "
                    "was proven")
        else:
            run.add("restore.counts_match", PASS,
                    f"{len(checked)} count(s) equal the source; {entries} ledger entries restored")

    # a verifier that cannot see tampering proves nothing: tamper with a copy and look
    target = next((k for k, v in sorted(checked.items(), key=lambda kv: -kv[1])
                   if k.endswith(".db") and k != "accounts.db" and v > 0), None)
    if target is None:
        run.add("restore.negative_control", UNCHECKED,
                "no ledger holds an entry to tamper with, so the verifier's sensitivity "
                "was not shown")
        return
    control = scratch / "control"
    shutil.copytree(volume, control, symlinks=True)
    db = sqlite3.connect(control / target)
    try:
        db.execute("UPDATE chain SET content_hash = 'ff' || substr(content_hash, 3) "
                   "WHERE seq = (SELECT MIN(seq) FROM chain)")
        db.commit()
    finally:
        db.close()
    tampered = restore_check.verify(control)
    if tampered.get("ok"):
        run.add("restore.negative_control", FAIL,
                f"a deliberately tampered copy of {target} still verified: the check cannot "
                "be relied on")
    else:
        run.add("restore.negative_control", PASS,
                f"a deliberately tampered copy of {target} was detected")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def _parse_when(text: Any) -> dt.datetime | None:
    try:
        return dt.datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def phase_report(ctx: Ctx, args: argparse.Namespace) -> Run:
    """Assemble the phase records, trusting only a complete, current, consistent set."""
    run = Run("report", ctx)
    records = Path(args.records or ctx.env.get("REHEARSAL_RECORD_DIR", "") or ".rehearsal")
    out_dir = Path(args.out) if args.out else records
    max_age = dt.timedelta(hours=float(args.max_age_hours))
    now = dt.datetime.now(dt.UTC)
    hosts: dict[str, str] = {}
    meta: dict[str, dict[str, str]] = {}
    when: dict[str, dt.datetime] = {}
    for phase in REPORT_ORDER:
        path = records / f"{phase}.json"
        if not path.is_file():
            run.add(f"{phase}.not_run", UNCHECKED, f"no record for {phase}: the phase was not "
                                                   "run, so nothing is established by it")
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            steps = doc["steps"]
            if not isinstance(doc, dict) or doc.get("phase") != phase or not isinstance(
                    steps, list):
                raise ValueError("not a record of this phase")
        except (OSError, ValueError, KeyError, TypeError):
            run.add(f"{phase}.record_invalid", FAIL,
                    f"{path.name} is not a readable record of the {phase} phase")
            continue
        made = _parse_when(doc.get("generated_at"))
        have = {str(s.get("id")) for s in steps if isinstance(s, dict)}
        missing = [i for i in STEP_IDS[phase] if i not in have]
        refusal, why = "", ""
        if doc.get("state") != "complete":
            refusal, why = "record_incomplete", (
                f"the record's state is {doc.get('state')!r}: the run did not finish, so no "
                "earlier result stands either")
        elif doc.get("script_version") != VERSION:
            refusal, why = "record_version", "the record was written by another version of this script"
        elif made is None:
            refusal, why = "record_stale", "the record has no readable generated_at"
        elif now - made > max_age:
            refusal, why = "record_stale", (
                f"the record is {(now - made).total_seconds() / 3600:.1f} h old, older than the "
                f"{float(args.max_age_hours):g} h bound (--max-age-hours)")
        elif missing:
            refusal, why = "record_incomplete", ("the record lacks steps of its phase: "
                                                 + ", ".join(missing))
        if refusal:
            run.add(f"{phase}.{refusal}", FAIL, why)
            continue
        assert made is not None
        when[phase] = made
        hosts[phase] = str(doc.get("target_host", ""))
        meta[phase] = {"target_host": hosts[phase], "generated_at": str(doc["generated_at"]),
                       "run_id": str(doc.get("run_id", "")),
                       "script_version": str(doc.get("script_version", ""))}
        run.observations.extend(o for o in doc.get("observations", []) if isinstance(o, dict))
        for item in steps:
            step_id = str(item.get("id", "")) if isinstance(item, dict) else ""
            status = item.get("status") if isinstance(item, dict) else None
            detail = str(item.get("detail", "")) if isinstance(item, dict) else ""
            if status not in VALID_STATUSES or not step_id:
                run.add(step_id or f"{phase}.invalid_step", FAIL,
                        f"unknown status or missing id in the {phase} record")
            else:
                run.add(step_id, status, detail)

    named = {p: h for p, h in hosts.items() if p in ("smoke", "webhook-test") and h}
    if len(set(named.values())) > 1:
        run.add("report.host_mismatch", FAIL, "the records name different hosts: " + ", ".join(
            f"{p} ran against {h}" for p, h in sorted(named.items())))
    present = [p for p in SEQUENCE if p in when]
    for earlier, later in zip(present, present[1:], strict=False):
        if when[later] < when[earlier] - dt.timedelta(seconds=ORDER_SKEW_SECONDS):
            run.add("report.out_of_order", FAIL,
                    f"{later} was recorded before {earlier}: these are not one rehearsal in "
                    "order (config-check, smoke, webhook-test); the earlier result may not "
                    "describe what the later one ran against. Re-run in order (out of order).")
    run.data.update({"phases": meta, "not_established": list(NOT_ESTABLISHED)})
    run.target_host = ",".join(sorted({h for h in hosts.values() if h}))
    doc = record_of(run)
    doc["overall"] = {0: PASS, 1: FAIL, 3: UNCHECKED}[exit_code(run.steps)]
    doc["unchecked"] = [s.id for s in run.steps if s.status == UNCHECKED]
    doc["attested"] = [s.id for s in run.steps if s.status == ATTESTED]
    doc["failed"] = [s.id for s in run.steps if s.status == FAIL]
    doc["phase"] = "report"
    doc["steps"] = [{"phase": s.id.split(".")[0], **step} for s, step in zip(
        run.steps, doc["steps"], strict=True)]
    _private_write(out_dir / "rehearsal-report.json",
                   json.dumps(doc, indent=2, sort_keys=True) + "\n")
    _private_write(out_dir / "rehearsal-report.md", ctx.redact(render_markdown(doc)))
    ctx.out(f"NOTE      wrote {out_dir / 'rehearsal-report.json'} and "
            f"{out_dir / 'rehearsal-report.md'}")
    return run


def render_markdown(doc: dict[str, Any]) -> str:
    lines = [
        "# Staging rehearsal report", "",
        f"Generated {doc['generated_at']}. Mode: Stripe TEST only. Overall: **{doc['overall']}** "
        f"(exit {doc['exit_code']}). Hosts exercised: {doc.get('target_host') or 'none'}.", "",
        "| Step | Status | Detail |", "|---|---|---|"]
    for step in doc["steps"]:
        detail = str(step["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{step['id']}` | {step['status']} | {detail} |")
    lines += ["", "## Not established (UNCHECKED)", ""]
    lines += [f"- `{i}`" for i in doc["unchecked"]] or ["- nothing is unchecked"]
    lines += ["", "## Attested by the operator, not measured", ""]
    lines += [f"- `{i}`" for i in doc["attested"]] or ["- nothing is attested"]
    lines += ["", "## Failed", ""]
    lines += [f"- `{i}`" for i in doc["failed"]] or ["- nothing failed"]
    lines += ["", "## What this report cannot show", ""]
    lines += [f"- {text}" for text in doc["not_established"]]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

PHASES: dict[str, Callable[[Ctx, argparse.Namespace], Run]] = {
    "config-check": phase_config_check,
    "smoke": phase_smoke,
    "webhook-test": phase_webhook,
    "restore-drill": phase_restore,
    "report": phase_report,
}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:     # noqa: ARG002 - withheld on purpose
        """A bad command line is reported without echoing it: it may contain a credential."""
        self.print_usage(sys.stderr)
        sys.stderr.write("usage error: the arguments were rejected (they are not repeated "
                         "here, in case one is a credential; credentials go in the "
                         "environment only)\n")
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="staging_rehearsal", description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="phase", required=True, parser_class=_Parser)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--record-dir", default="", help="where this phase leaves its redacted "
                       "<phase>.json (default: $REHEARSAL_RECORD_DIR, else ./.rehearsal); a "
                       "phase always leaves one, so a failed or interrupted run replaces an "
                       "earlier pass")

    p = sub.add_parser("config-check", help="env var names/shapes for a Stripe TEST deploy")
    common(p)
    p.add_argument("--checkout-expected", action="store_true",
                   help="a missing key, secret, price id or site origin is a FAIL, not UNCHECKED")

    p = sub.add_parser("smoke", help="read-only checks of a host: GET /healthz and /v1/plans; "
                       "POST {} to /v1/machine/verify with no key, a made-up key and your "
                       "Register key (expecting 401/401/402); two CORS preflights; a TLS "
                       "handshake; and one credential-free GET to http://host/healthz on port 80")
    common(p)
    p.add_argument("--base-url", default="")
    p.add_argument("--expect-purchasable", default="", help="e.g. register,cell")
    p.add_argument("--min-cert-days", type=int, default=14)
    p.add_argument("--timeout", type=float, default=15.0)

    p = sub.add_parser("webhook-test", help="signed TEST checkout event, staging only")
    common(p)
    p.add_argument("--base-url", default="")
    p.add_argument("--i-am-testing-staging", action="store_true")
    p.add_argument("--poll-seconds", type=float, default=30.0)
    p.add_argument("--timeout", type=float, default=15.0)

    p = sub.add_parser("restore-drill", help="copy a data dir (or take a fetched backup), "
                       "wipe a scratch volume, restore, verify; never opens the source")
    common(p)
    p.add_argument("--data-dir", default="", help="a data directory to copy (the service "
                   "must be stopped; the source is only read as files)")
    p.add_argument("--backup-dir", default="", help="restore this backup instead of taking one")
    p.add_argument("--work-dir", default="", help="where the scratch volume lives")
    p.add_argument("--i-know-the-service-is-stopped", action="store_true",
                   help="copy a data dir that has -wal/-shm/-journal files beside its databases")

    p = sub.add_parser("report", help="assemble the phase records into JSON and Markdown")
    p.add_argument("--records", default="")
    p.add_argument("--out", default="")
    p.add_argument("--max-age-hours", type=float, default=6.0,
                   help="records older than this are a failure (default 6)")
    return parser


def _crashed(ctx: Ctx, phase: str, record_dir: str, *, interrupted: bool, exc: BaseException) -> int:
    """Keep what the phase had already established, add the failure, leave the record."""
    kind = "interrupted" if interrupted else "internal_error"
    if interrupted:
        ctx.err(f"INTERRUPTED in {phase}: the run was cancelled; the steps already taken are "
                "in the record and no earlier record stands")
    else:
        ctx.err(f"INTERNAL ERROR in {phase}: {type(exc).__name__}: {exc}")
    run = next((r for r in reversed(ctx.runs) if r.phase == phase), None) or Run(phase, ctx)
    run.add(f"{PHASE_PREFIX[phase]}.{kind}", FAIL,
            f"the run was interrupted ({type(exc).__name__})" if interrupted
            else f"the tool failed with {type(exc).__name__}")
    if record_dir:
        try:
            write_record(ctx, record_dir, run, "interrupted" if interrupted else "crashed")
        except OSError:
            ctx.err("COULD NOT WRITE the record of this failure")
    return 130 if interrupted else 1


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    ctx = Ctx(os.environ if environ is None else environ)
    try:
        args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    phase = args.phase
    record_dir = "" if phase == "report" else (
        getattr(args, "record_dir", "") or ctx.env.get("REHEARSAL_RECORD_DIR", "")
        or ".rehearsal")

    live = live_findings(ctx.env)
    if live:
        ctx.err("REFUSED: this rehearsal is Stripe TEST mode only, and the environment holds "
                "what looks like live-mode configuration:")
        for finding in live:
            ctx.err(f"  - {finding}")
        ctx.err("Unset it (the value is never printed) and run again from a shell that holds "
                "only test credentials. Nothing was run.")
        if record_dir:
            run = Run(phase, ctx)
            run.add(f"{PHASE_PREFIX[phase]}.no_live_keys", FAIL,
                    f"REFUSED: {len(live)} live-mode marker(s): "
                    + ", ".join(f.split(" ")[0] for f in live))
            write_record(ctx, record_dir, run)
        return 1

    try:
        if record_dir:
            try:
                write_progress(ctx, record_dir, phase)
            except OSError as exc:
                ctx.err(f"COULD NOT WRITE to the record directory ({type(exc).__name__}); "
                        "nothing was run")
                return 1
        run = PHASES[phase](ctx, args)
    except KeyboardInterrupt as exc:
        return _crashed(ctx, phase, record_dir, interrupted=True, exc=exc)
    except Exception as exc:  # noqa: BLE001 - the tool must report, never traceback with a secret
        return _crashed(ctx, phase, record_dir, interrupted=False, exc=exc)

    code = exit_code(run.steps)
    counts = {s: sum(1 for st in run.steps if st.status == s) for s in VALID_STATUSES}
    ctx.out(f"SUMMARY   {phase}: {counts[PASS]} PASS, {counts[FAIL]} FAIL, "
            f"{counts[UNCHECKED]} UNCHECKED, {counts[ATTESTED]} ATTESTED -> exit {code}")
    if record_dir:
        try:
            write_record(ctx, record_dir, run)
        except OSError as exc:
            ctx.err(f"COULD NOT WRITE the record ({type(exc).__name__}): report cannot see this run")
            return 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
