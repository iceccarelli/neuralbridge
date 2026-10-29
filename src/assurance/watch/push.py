"""``assurance watch push`` — report what your own Watch saw, if you choose to.

The offline kit and ``assurance watch run`` stay offline. They never import this
module, and nothing here runs unless an operator types ``watch push`` with an
explicit ``--api-url`` and the name of an environment variable that holds their
key. The key is never an argument, never printed, never written.

What leaves the plant, precisely (``deploy/assurance/WATCH.md`` repeats this):

* the watch id, the start time of the latest sealed run, its verdict, and the
  cadence the configuration declares;
* per machine: serial, machine key, status (``unchanged`` | ``changed`` |
  ``uncollectable`` | ``incomplete``), when it was observed, whether the
  collection was complete, a one-line detail, and the ids of any plan items an
  incomplete look did not find;
* for a machine that was collected: its **SafetyManifest** — item ids, names,
  versions, content hashes, supplier names, safety-function ids, site, country
  and the collection provenance — and nothing else.

Never sent: any export file, program, firmware image or configuration; the plan;
local file system paths (the collection root, the plan path); the reason a
collection failed (it can contain a path — it stays in the local ledger and the
hosted record says only that the look failed); the ledger itself.

``--dry-run`` prints exactly the request bodies and opens no connection.

Failure to observe is reported as exactly that. An ``uncollectable`` or
``incomplete`` machine is sent as such, with the last *successful* observation
beside it so the workspace can say how long it has been blind; it is never sent
as unchanged. Reports are idempotent on the server, so a timeout or a 5xx is
retried and a retry cannot duplicate anything. Redirects are never followed:
the key is sent to the host the operator named and to no other.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import manifests_from_ledger
from assurance.watch.config import WatchConfig
from assurance.watch.observations import (
    NOT_A_LOOK_STATUSES,
    OBSERVATION_KIND,
    observation_succeeded,
    observed_at_of,
)
from assurance.watch.runner import last_run

__all__ = [
    "DEFAULT_MAX_BODY_BYTES",
    "ENDPOINT",
    "PushError",
    "PushPlan",
    "build_plan",
    "main_push",
    "run_push",
]

ENDPOINT = "/v1/watch/report"
#: Below the server's 1 MiB default so the request body, headers and a margin fit.
DEFAULT_MAX_BODY_BYTES = 900_000
MAX_MACHINES_PER_REQUEST = 200
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
#: Reasons the server gives that are not a failure of this push: the hosted
#: ledger already holds this observation, or holds a newer one.
_BENIGN_REFUSALS = frozenset({"superseded_by_newer_observation"})


class PushError(AssuranceError):
    """The push could not be built or sent. Never raised with a key in its text."""


# -- building the report ---------------------------------------------------


@dataclass(frozen=True)
class PushPlan:
    """Everything one push would send, split into requests that fit the cap."""

    watch_id: str
    run_started_at: str
    bodies: tuple[dict[str, Any], ...]
    #: Machines that could not be put in a report, and why. Never silent.
    unsendable: tuple[str, ...] = ()
    machines: int = 0

    @property
    def batched(self) -> bool:
        return len(self.bodies) > 1


def _wire_status(local: str) -> str:
    return "unchanged" if local == "observed" else "changed"


def _manifest_for(
    ledger: EvidenceLedger, key: str, configuration_hash: str, observed_at: Any,
) -> dict[str, Any] | None:
    """The sealed manifest for that configuration, taken at or before the look."""
    candidates = [m for m in manifests_from_ledger(ledger, key)
                  if m.configuration_hash() == configuration_hash]
    on_time = [m for m in candidates if m.taken_at <= observed_at + timedelta(minutes=5)]
    pool = on_time or []
    return pool[-1].to_dict() if pool else None


#: How far before a look its manifest may be taken and still be that look's own
#: collection (the same tolerance ``_manifest_for`` allows after it). Older than
#: this, the manifest is a sealed earlier one for an unchanged configuration.
_OWN_COLLECTION_TOLERANCE = timedelta(minutes=5)


def _relayed(manifest: Mapping[str, Any], observed_at: Any) -> bool:
    try:
        taken = parse_utc(str(manifest.get("taken_at", "")))
    except (ValueError, TypeError):
        return False
    return observed_at - taken > _OWN_COLLECTION_TOLERANCE


def _anchor_entry(
    ledger: EvidenceLedger, key: str, serial: str, manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """The local look at which this manifest was first sealed, as its own entry.

    The hosted side honours ``manifest_relayed`` only for a manifest its ledger
    already holds. An unchanged machine is reported with the manifest sealed when its
    configuration last changed, which may be weeks old and which the hosted ledger
    has never seen on a first push. This is that earlier look, sent as it was: its
    own ``observed_at``, a manifest as old as the look and not a relayed one. Sent
    beside the relayed entry, it lets the hosted ledger hold the manifest the relayed
    entry points at; once held, the server reads it as already recorded. It adds
    nothing the local ledger does not say, and nothing a reporter could not also
    fabricate: it makes the honest history reachable, not the claim true.
    """
    try:
        taken = parse_utc(str(manifest.get("taken_at", "")))
    except (ValueError, TypeError):
        return None
    from assurance.machinery.manifest import SafetyManifest

    try:
        want = SafetyManifest.from_dict(dict(manifest)).configuration_hash()
    except (AssuranceError, KeyError, ValueError, TypeError):
        return None
    for at, body in _local_observations(ledger, key):
        if body.get("status") not in ("first_seen", "changed"):
            continue
        if str(body.get("configuration_hash", "")) != want or not observation_succeeded(body):
            continue
        if abs(at - taken) > _OWN_COLLECTION_TOLERANCE:
            continue
        return {
            "serial": serial, "machine_key": key, "status": "changed",
            "observed_at": str(body.get("observed_at")), "collection_complete": True,
            "manifest": dict(manifest), "manifest_relayed": False,
            "detail": str(body.get("detail", ""))[:2000], "missing_items": [],
        }
    return None


def _local_observations(ledger: EvidenceLedger, key: str) -> list[tuple[Any, dict[str, Any]]]:
    out = []
    for entry in ledger.entries(subject=key, kind=OBSERVATION_KIND):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        at = observed_at_of(evidence.body, entry.at)
        if at is not None:
            out.append((at, evidence.body))
    return out


def _entries_for(
    ledger: EvidenceLedger, outcome: Mapping[str, Any], started: Any, problems: list[str],
) -> list[dict[str, Any]]:
    serial = str(outcome.get("serial", ""))
    key = str(outcome.get("machine") or serial)
    status = str(outcome.get("status", ""))
    complete = bool(outcome.get("collection_complete", True))
    stamp = str(outcome.get("_started_at"))
    entries: list[dict[str, Any]] = []

    if status == "uncollectable" or not complete:
        wire = "uncollectable" if status == "uncollectable" else "incomplete"
        missing: list[str] = []
        for at, body in _local_observations(ledger, key):
            if at == started and body.get("missing"):
                missing = [str(m) for m in body["missing"]]
        entries.append({
            "serial": serial, "machine_key": key, "status": wire,
            "observed_at": stamp, "collection_complete": False, "manifest": None,
            # The reason a collection failed can carry a local path; it stays in
            # the local ledger and the hosted record says only that it failed.
            "detail": ("could not be collected; the reason is in the local ledger"
                       if wire == "uncollectable" else
                       "the collection did not find or read every plan item"),
            "missing_items": missing,
        })
        # The last look that did succeed, so the workspace can say how long this
        # machine has been unobserved instead of "never".
        earlier = [(at, b) for at, b in _local_observations(ledger, key)
                   if at < started and observation_succeeded(b)]
        if earlier:
            at, body = max(earlier, key=lambda p: p[0])
            manifest = _manifest_for(ledger, key, str(body.get("configuration_hash", "")), at)
            if manifest is None:
                problems.append(
                    f"{key}: the last successful observation ({body.get('observed_at')}) "
                    "has no matching manifest in this ledger, so it was not sent; "
                    "the hosted record will not show when the machine was last seen.")
            else:
                relayed = _relayed(manifest, at)
                anchor = _anchor_entry(ledger, key, serial, manifest) if relayed else None
                if anchor is not None:
                    entries.append(anchor)
                entries.append({
                    "serial": serial, "machine_key": key,
                    "status": _wire_status(str(body.get("status", ""))),
                    "observed_at": str(body.get("observed_at")),
                    "collection_complete": True, "manifest": manifest,
                    "manifest_relayed": relayed,
                    "detail": str(body.get("detail", ""))[:2000],
                    "missing_items": [],
                })
        return entries

    manifest = _manifest_for(ledger, key, str(outcome.get("configuration_hash", "")), started)
    if manifest is None:
        problems.append(
            f"{key}: no sealed manifest for configuration "
            f"{str(outcome.get('configuration_hash', ''))[:12]} was found in this ledger "
            "(was the run a --dry-run?). It was not reported — a machine that is not "
            "reported will show as stale, which is the honest reading.")
        return entries
    relayed = _relayed(manifest, started)
    anchor = _anchor_entry(ledger, key, serial, manifest) if relayed else None
    if anchor is not None:
        entries.append(anchor)
    entries.append({
        "serial": serial, "machine_key": key, "status": _wire_status(status),
        "observed_at": stamp, "collection_complete": True, "manifest": manifest,
        "manifest_relayed": relayed,
        "detail": str(outcome.get("detail", ""))[:2000], "missing_items": [],
    })
    return entries


def run_summary(run: Mapping[str, Any]) -> dict[str, Any]:
    """What the local run found beyond per-machine observations, for the hosted record.

    Client-reported and labelled so on the server. Deliberately carries no Article 14
    awareness time, classification or draft: an advisory arriving is not awareness,
    and the drafts stay in the local ledger for a person to determine.
    """
    adv = run.get("advisories") or {}
    findings = [{
        "advisory_id": str(f.get("advisory_id", ""))[:200],
        "supplier_id": str(f.get("supplier_id", ""))[:200],
        "severity": str(f.get("severity", ""))[:40],
        "state": str(f.get("state", ""))[:40],
        "impact": str(f.get("impact", ""))[:40],
        "machines": [str(m)[:400] for m in (f.get("machines") or [])][:200],
        "functions_in_question": [str(m)[:200] for m in
                                  (f.get("functions_in_question") or [])][:200],
        "trust_basis": str(f.get("trust_basis", ""))[:60],
        "trust_state": str(f.get("trust_state", ""))[:80],
        "inspect_only": bool(f.get("inspect_only", False)),
        "case_id": str(f.get("case_id", ""))[:200],
    } for f in (adv.get("findings") or [])][:100]
    feeds = [{"supplier_id": str(f.get("supplier_id", ""))[:200],
              "status": str(f.get("status", ""))[:40],
              "trust_basis": str(f.get("trust_basis", ""))[:60]}
             for f in (adv.get("feeds") or [])][:50]
    cases = sorted({str(o.get("case_id")) for o in run.get("outcomes", []) if o.get("case_id")}
                   | {f["case_id"] for f in findings if f["case_id"]})[:200]
    return {
        "local_finished_at": str(run.get("finished_at", ""))[:40],
        "stale_observations": [str(s)[:400] for s in (run.get("stale_observations") or [])][:100],
        "feeds": feeds,
        "advisory_findings": findings,
        "local_case_ids": cases,
        "checks_skipped": [str(c)[:500] for c in (run.get("checks_skipped") or [])
                           if "art. 14" not in str(c).lower()
                           and "article 14" not in str(c).lower()][:50],
    }


def _size(body: Mapping[str, Any]) -> int:
    return len(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())


def wire_bytes(body: Mapping[str, Any]) -> bytes:
    """The exact request body: compact, key-sorted JSON."""
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def build_plan(
    config: WatchConfig, ledger: EvidenceLedger, *,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> PushPlan:
    """Read the latest sealed run from the local ledger and shape it into requests."""
    run = last_run(ledger, config.watch_id)
    if run is None:
        raise PushError(
            f"{config.watch_id}: this watch has never run against this ledger, so "
            "there is nothing to report. Run `assurance watch run` first.")
    started_text = str(run.get("started_at", ""))
    started = parse_utc(started_text)
    problems: list[str] = []
    entries: list[dict[str, Any]] = []
    for outcome in run.get("outcomes", []):
        entries.extend(_entries_for(
            ledger, {**outcome, "_started_at": started_text}, started, problems))
    if not entries:
        raise PushError(
            f"{config.watch_id}: nothing in the latest run could be put in a report. "
            + " ".join(problems))
    entries.sort(key=lambda e: (e["observed_at"], e["serial"]))

    base: dict[str, Any] = {
        "watch_id": config.watch_id, "run_started_at": started_text,
        "max_age_hours": config.max_age_hours, "verdict": run.get("verdict"),
        "run_summary": run_summary(run),
    }
    if base["verdict"] not in ("quiet", "findings", "degraded"):
        base.pop("verdict")

    # Greedy partition. A placeholder batch header is included in the size so the
    # real header (which is never longer) cannot push a request over the cap.
    reserve = {"batch_index": 9999, "batch_count": 9999}
    groups: list[list[dict[str, Any]]] = [[]]
    for entry in entries:
        candidate = [*groups[-1], entry]
        if _size({**base, **reserve, "machines": candidate}) <= max_body_bytes \
                and len(candidate) <= MAX_MACHINES_PER_REQUEST:
            groups[-1] = candidate
            continue
        if not groups[-1]:
            problems.append(
                f"{entry['machine_key']}: its report alone is larger than the "
                f"{max_body_bytes}-byte request limit and was not sent.")
            continue
        if _size({**base, **reserve, "machines": [entry]}) > max_body_bytes:
            problems.append(
                f"{entry['machine_key']}: its report alone is larger than the "
                f"{max_body_bytes}-byte request limit and was not sent.")
            continue
        groups.append([entry])
    groups = [g for g in groups if g]
    if not groups:
        raise PushError("no machine's report fits in a request. " + " ".join(problems))

    bodies = []
    for i, group in enumerate(groups, start=1):
        body = {**base, "machines": group}
        if len(groups) > 1:
            body.update(batch_index=i, batch_count=len(groups))
        bodies.append(body)
    return PushPlan(watch_id=config.watch_id, run_started_at=started_text,
                    bodies=tuple(bodies), unsendable=tuple(problems),
                    machines=len({e["machine_key"] for e in entries}))


# -- sending ---------------------------------------------------------------


def check_url(api_url: str) -> str:
    """The base URL to post to, or a refusal. Loopback may be plain http; nothing else."""
    parts = urlsplit(api_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise PushError("--api-url must be an http(s) URL, e.g. https://api.example.com")
    if parts.username or parts.password:
        raise PushError("--api-url must not contain credentials. The key comes from "
                        "an environment variable.")
    if parts.query or parts.fragment:
        raise PushError("--api-url must be a base URL without a query or fragment.")
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
        raise PushError(
            "refusing to send a key over plain http to a non-loopback host. Use "
            "https (plain http is accepted only for localhost).")
    return api_url.strip().rstrip("/")


_SECRET_PREFIXES = ("asr_", "sk_", "sk-", "pk_", "rk_", "whsec_", "ghp_", "gho_", "xoxb-", "xoxp-")
_TOKEN = re.compile(r"[A-Za-z0-9_\-]+")


def looks_secret(value: str) -> bool:
    """Whether a user-supplied string is shaped like a credential.

    Used to decide what must never be echoed in an error message: a known key
    prefix, or one long unbroken token mixing letters and digits (a path has a
    separator or an extension; an environment variable name is upper case).
    """
    v = (value or "").strip()
    if not v:
        return False
    if v.lower().startswith(_SECRET_PREFIXES):
        return True
    return (len(v) >= 24 and _TOKEN.fullmatch(v) is not None
            and any(c.isdigit() for c in v) and any(c.isalpha() for c in v)
            and not v.isupper())


def check_env_name(env_name: str) -> None:
    # Never echo the name when it looks like a key: an operator who pasted the
    # key where the NAME belongs must not see it printed back.
    if (not _ENV_NAME.match(env_name or "") or len(env_name) > 64
            or looks_secret(env_name)):
        raise PushError("--key-env must be the NAME of an environment variable "
                        "(letters, digits, underscore), not the key itself.")


def read_key(env_name: str) -> str:
    check_env_name(env_name)
    value = os.environ.get(env_name, "").strip()
    if not value:
        raise PushError(f"environment variable {env_name} is not set or is empty.")
    if not (value.isascii() and value.isprintable()) or " " in value:
        # Say what is wrong with it, never what it is.
        raise PushError(f"the value of {env_name} is not a usable API key "
                        "(it contains spaces or non-printable/non-ASCII characters).")
    return value


def make_client(timeout: float) -> Any:
    """An httpx client that never follows a redirect. httpx is imported here, lazily."""
    try:
        import httpx
    except ImportError as exc:
        raise PushError(
            "`assurance watch push` needs httpx (`pip install httpx`). The offline "
            "kit and `watch run` do not.") from exc
    return httpx.Client(timeout=timeout, follow_redirects=False)


@dataclass
class _Totals:
    recorded: int = 0
    already: int = 0
    failed_recorded: int = 0
    superseded: int = 0
    refused: list[str] = field(default_factory=list)
    cases_opened: list[str] = field(default_factory=list)
    cases_touched: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _scrub(text: str, key: str) -> str:
    return text.replace(key, "***") if key else text


def _post(
    client: Any, url: str, key: str, body: Mapping[str, Any], *, retries: int,
    wait: float, sleep: Callable[[float], None],
) -> tuple[int, Any]:
    """POST one body, retrying transport errors and 5xx. Safe because it is idempotent."""
    import httpx

    last = ""
    for attempt in range(retries + 1):
        if attempt:
            sleep(wait * (2 ** (attempt - 1)))
        try:
            response = client.post(
                url, content=wire_bytes(body),
                headers={"X-API-Key": key, "content-type": "application/json"})
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last = f"{type(exc).__name__}"
            continue
        if 300 <= response.status_code < 400:
            target = response.headers.get("location", "")
            host = urlsplit(target).hostname or "another location"
            raise PushError(
                f"the server answered HTTP {response.status_code} redirecting to "
                f"{host}. Redirects are never followed — the key is sent only to "
                "the host you named. Check --api-url.")
        if response.status_code >= 500:
            last = f"HTTP {response.status_code}"
            continue
        try:
            data = response.json()
        except ValueError:
            data = None
        return response.status_code, data
    raise PushError(
        f"could not complete the request after {retries + 1} attempt(s) ({last}). "
        "Nothing was lost: reports are idempotent, so running the same command again "
        "is safe.")


def _detail_of(data: Any, status: int) -> str:
    detail = data.get("detail") if isinstance(data, dict) else None
    if isinstance(detail, dict):
        return str(detail.get("remedy") or detail.get("detail") or detail.get("error")
                   or f"HTTP {status}")
    if isinstance(detail, list):
        return "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d)
                         for d in detail[:3])
    return str(detail or f"HTTP {status}")


def run_push(
    config: WatchConfig, ledger: EvidenceLedger, *, api_url: str, key: str,
    client: Any, retries: int = 2, wait: float = 1.0,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    sleep: Callable[[float], None] = time.sleep, out: Callable[[str], None] = print,
) -> int:
    """Send the latest run. 0 reported, 1 refused or partial, 2 could not run."""
    base = check_url(api_url)
    plan = build_plan(config, ledger, max_body_bytes=max_body_bytes)
    host = urlsplit(base)
    target = f"{host.scheme}://{host.netloc}"
    url = base + ENDPOINT
    out(f"{plan.watch_id} → {target}: {plan.machines} machine(s), run started "
        f"{plan.run_started_at}")
    if plan.batched:
        out(f"  sent as {len(plan.bodies)} requests: the report is larger than one "
            f"request may be ({max_body_bytes} bytes), so machines were split into batches.")

    totals = _Totals()
    transport_error = ""
    for body in plan.bodies:
        try:
            status, data = _post(client, url, key, body, retries=retries,
                                 wait=wait, sleep=sleep)
        except PushError as exc:
            transport_error = _scrub(str(exc), key)
            break
        if status != 200 or not isinstance(data, dict):
            reason = _scrub(_detail_of(data, status), key)
            hint = (" Lower --max-body-bytes." if status == 413 else "")
            totals.refused.append(f"HTTP {status}: {reason}{hint}")
            out(f"  request {body.get('batch_index', 1)}: REFUSED — HTTP {status}: {reason}{hint}")
            continue
        for m in data.get("machines", []):
            outcome = m.get("outcome")
            reported = m.get("reported_status", "")
            recorded = m.get("recorded_status", "")
            label = f"{m.get('serial', '')}".ljust(8)
            if outcome == "refused" and m.get("reason") in _BENIGN_REFUSALS:
                totals.superseded += 1
                totals.lines.append(
                    f"  [ignored ] {label} {reported}: the hosted ledger already holds "
                    "a newer observation")
            elif outcome == "refused":
                totals.refused.append(f"{m.get('machine_key')}: {m.get('reason')} — "
                                      f"{m.get('detail')}")
                totals.lines.append(
                    f"  [REFUSED ] {label} {reported}: {m.get('reason')} — {m.get('detail')}")
            elif outcome == "already_recorded":
                totals.already += 1
                totals.lines.append(
                    f"  [already ] {label} {reported}: already in the hosted ledger; "
                    "nothing written")
            else:
                totals.recorded += 1
                if recorded in NOT_A_LOOK_STATUSES:
                    totals.failed_recorded += 1
                    totals.lines.append(
                        f"  [FAILED  ] {label} {recorded}: recorded as a failed "
                        "attempt — not an observation, and the machine is not "
                        "shown as current")
                else:
                    totals.lines.append(
                        f"  [recorded] {label} {reported} → hosted: {recorded}"
                        + (f"; case {m['case_id']} ({m['case_status']})"
                           if m.get("case_id") else ""))
        totals.cases_opened.extend(data.get("cases_opened", []))
        totals.cases_touched.extend(data.get("cases_touched", []))
        totals.limitations = list(data.get("limitations", totals.limitations))

    for line in totals.lines:
        out(line)
    if totals.cases_opened:
        out(f"  cases opened: {', '.join(dict.fromkeys(totals.cases_opened))}")
    out(f"  {totals.recorded} recorded, {totals.already} already recorded, "
        f"{totals.superseded} ignored as older, {len(totals.refused)} refused")
    if totals.failed_recorded:
        out(f"  {totals.failed_recorded} machine(s) were reported as NOT observed. "
            "The workspace shows them as failed/stale until a look succeeds.")
    for problem in plan.unsendable:
        out(f"  ! not sent: {problem}")
    if totals.limitations:
        out("  not established:")
        for line in totals.limitations[:3]:
            out(f"    - {line}")
    if transport_error:
        out(f"  could not complete: {transport_error}")
        return 2
    return 1 if (totals.refused or plan.unsendable) else 0


# -- the command -----------------------------------------------------------


def _dry_run(plan: PushPlan, *, api_url: str, key_env: str, out: Callable[[str], None]) -> int:
    base = check_url(api_url)
    parts = urlsplit(base)
    out("DRY RUN — nothing was sent and no connection was opened.")
    out(f"Would POST {len(plan.bodies)} request(s) to {parts.scheme}://{parts.netloc}{ENDPOINT}")
    set_note = "is set" if os.environ.get(key_env, "").strip() else "is NOT set (a real push would stop)"
    out(f"Key: read from the environment variable {key_env}, which {set_note}. "
        "It is sent as the X-API-Key header and never printed.")
    if plan.batched:
        out("The report is split into batches to fit the request limit.")
    out("The request bodies follow, exactly as they would be sent "
        "(formatted here for reading; compact on the wire, same content):")
    for body in plan.bodies:
        out(json.dumps(body, indent=2, sort_keys=True))
    for problem in plan.unsendable:
        out(f"! would not be sent: {problem}")
    return 1 if plan.unsendable else 0


def main_push(args: Any, *, client: Any = None, sleep: Callable[[float], None] = time.sleep) -> int:
    """The ``watch push`` command. ``client`` is injectable for tests only."""
    ledger_path = Path(args.ledger)
    key = ""
    # Whatever the operator typed into an option that looks like a credential is
    # never printed back: a key pasted into the wrong option is named by option.
    options = {"--config": str(args.config), "--ledger": str(args.ledger),
               "--key-env": str(args.key_env), "--api-url": str(args.api_url)}
    secrets = {opt: v for opt, v in options.items() if looks_secret(v)}

    def say(message: str) -> None:
        message = _scrub(message, key)
        for opt, value in secrets.items():
            message = message.replace(value, f"<the value given to {opt}>")
        print(f"error: {message}", file=sys.stderr)

    if not ledger_path.is_file():
        say("the file given as --ledger does not exist." if "--ledger" in secrets
            else f"ledger {ledger_path} does not exist.")
        return 2
    try:
        check_env_name(args.key_env)
        config = WatchConfig.from_json(args.config)
        ledger = EvidenceLedger(ledger_path)
        if args.dry_run:
            plan = build_plan(config, ledger, max_body_bytes=args.max_body_bytes)
            return _dry_run(plan, api_url=args.api_url, key_env=args.key_env, out=print)
        key = read_key(args.key_env)
        check_url(args.api_url)
        http = client if client is not None else make_client(args.timeout)
        return run_push(config, ledger, api_url=args.api_url, key=key, client=http,
                        retries=args.retries, wait=args.retry_wait,
                        max_body_bytes=args.max_body_bytes, sleep=sleep)
    except (PushError, AssuranceError, ValueError, OSError) as exc:
        say(str(exc))
        return 2
