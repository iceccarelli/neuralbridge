#!/usr/bin/env python3
"""Smoke-check a running assurance service over HTTP: ``smoke_assurance_service.py BASE_URL``.

Used by the ``assurance-image`` CI job against a container built from
``deploy/assurance/Dockerfile`` that was started with NO API keys, no Stripe keys and no
attestation key. It asserts the *honest unconfigured state*, not a green light:

* ``/livez`` answers 200 ``{"status": "alive"}`` (the process is up and nothing else);
* ``/healthz`` answers 200 with ``status == "degraded"``, ``auth_mode == "unconfigured"``,
  ``attestation_key == "not_configured"`` and a warning that says no API keys are set,
  with both stores open. A service that reported ``ok`` here would be overstating itself.

Standard library only. Exit 0 on success, 1 with the reason on stderr otherwise.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request


def get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - URL given by CI
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def wait_for(url: str, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    last: object = None
    while time.monotonic() < deadline:
        try:
            get(url)
            return
        except (OSError, ValueError) as exc:
            last = exc
            time.sleep(1)
    raise SystemExit(f"FAIL: {url} did not answer within {seconds}s: {last}")


EXPECTED_HEALTHZ = {
    "status": "degraded",
    "auth_mode": "unconfigured",
    "attestation_key": "not_configured",
    "ledger_ok": True,
    "accounts_ok": True,
    "storage_ok": True,
}


def check(base: str) -> list[str]:
    problems: list[str] = []
    code, live = get(f"{base}/livez")
    if code != 200 or live != {"status": "alive"}:
        problems.append(f"/livez: expected 200 {{'status': 'alive'}}, got {code} {live}")
    code, health = get(f"{base}/healthz")
    if code != 200:
        problems.append(f"/healthz: expected 200, got {code} {health}")
    for key, want in EXPECTED_HEALTHZ.items():
        if health.get(key) != want:
            problems.append(f"/healthz[{key!r}]: expected {want!r}, got {health.get(key)!r}")
    if "No API keys configured" not in str(health.get("warning", "")):
        problems.append(f"/healthz does not warn that no API keys are set: {health.get('warning')!r}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    base = argv[1].rstrip("/")
    wait_for(f"{base}/livez")
    problems = check(base)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print(f"ok: {base} is alive and reports its unconfigured state honestly")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
