"""Would the two paid capabilities work in this environment? Answered without a key leaving it.

``assurance attest preflight`` reads exactly what the hosted service reads --
``ASSURANCE_ATTEST_KEY_PEM`` (else ``ASSURANCE_ATTEST_KEY``, a path), its passphrase, and
``ASSURANCE_RECORDER_TRUST`` -- and reports, per capability, whether it would work and why
not. It is a check of *configuration*, not of custody: the list of what it did not check is
part of every report.

Secret handling is structural: key material is held only inside :func:`_load_key` and only
the public fingerprint leaves it. Error text is built from the exception *class* and from
messages this module writes, never from ``str(exc)`` of a parser that has seen the key.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from assurance.attest.custody import key_file_problems
from assurance.attest.keys import SigningKey, SigningKeyError
from assurance.attest.trustlist import summarise, trust_file_problems
from assurance.machine.recorder_attestation import RecorderTrust

__all__ = ["ANCHOR_PREFLIGHT_NOT_CHECKED", "NOT_CHECKED", "Check", "PreflightReport",
           "run_preflight"]

KEY_PEM_ENV = "ASSURANCE_ATTEST_KEY_PEM"
KEY_PATH_ENV = "ASSURANCE_ATTEST_KEY"
PASSPHRASE_ENV = "ASSURANCE_ATTEST_PASSPHRASE"
LOGS_ENV = "ASSURANCE_ATTEST_LOGS"
TRUST_ENV = "ASSURANCE_RECORDER_TRUST"

#: What no environment inspection can establish. Printed with every report.
NOT_CHECKED = (
    "Key custody: where the private key is stored, who can read it, and whether it was ever "
    "copied, pasted or logged. A key file's mode is checked; the host and its backups are not.",
    "Backup of the private key. Losing it means no further attestations under this identity; "
    "nothing here can see whether a recoverable copy exists.",
    "That the public fingerprint is the one customers were told, unless --expect-fingerprint "
    "was given, and even then only that it matches the value you typed, not that you told "
    "anybody.",
    "That the deployed process sees this environment. This checked the environment of the "
    "process that ran it; run it where the service runs.",
    "That the plan entitlements are in force: counter-signing is only served to Cell accounts "
    "and hosted verification to accounts whose plan includes it.",
    "That each recorder key belongs to the party its label says, or that its holder is "
    "honest. A trust list is a decision, not a fact.",
    "That the clock of this host is right, which attestation dates and expiry depend on.",
)

#: Added to the report when ``--anchors`` was given.
ANCHOR_PREFLIGHT_NOT_CHECKED = (
    "Custody of the key that signed the anchors, and that it is the key customers were told.",
    "That the anchor job actually runs on a schedule: this reads the anchors that exist, so a "
    "job that stopped yesterday looks fine until the newest anchor passes --max-age.",
    "An operator who controls the deployment can rewrite a ledger and its attestation log "
    "together; an anchor is as independent of the operator as the key's custody is.",
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str            # "ok" | "fail" | "warn" | "info"
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class PreflightReport:
    checks: list[Check] = field(default_factory=list)
    counter_signing: bool = False
    validated_verification: bool = False
    service_fingerprint: str = ""
    trust: list[dict[str, Any]] = field(default_factory=list)
    key_source: str = "none"
    trust_status: str = "unset"
    anchors_checked: bool = False

    def add(self, name: str, status: str, detail: str) -> None:
        self.checks.append(Check(name, status, detail))

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == "fail"]

    def exit_code(self, require: str = "both") -> int:
        wanted = {"both": (True, True), "counter-signing": (True, False),
                  "validated": (False, True), "none": (False, False)}[require]
        if self.failures:
            return 1
        if wanted[0] and not self.counter_signing:
            return 1
        return 1 if wanted[1] and not self.validated_verification else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "counter_signing": {
                "available": self.counter_signing, "key_source": self.key_source,
                "service_fingerprint": self.service_fingerprint,
                "without_it": "POST /v1/ledger/attest answers 503",
            },
            "validated_verification": {
                "available": self.validated_verification, "trust_status": self.trust_status,
                "recorders": self.trust,
                "without_it": "hosted evidence stays 'community' (declared by its filer)",
            },
            "checks": [c.to_dict() for c in self.checks],
            "not_checked": [*NOT_CHECKED,
                            *(ANCHOR_PREFLIGHT_NOT_CHECKED if self.anchors_checked else ())],
        }


def _load_key(pem: str | None, path: str | None, passphrase: str,
              report: PreflightReport) -> SigningKey | None:
    """Load the key the way the service does; report the class of failure, never the text."""
    try:
        if pem:
            return SigningKey.from_pem(pem, passphrase=passphrase)
        assert path is not None
        return SigningKey.load(path, passphrase=passphrase, label="the key file")
    except SigningKeyError as exc:
        text = str(exc).lower()
        if "encrypted and no passphrase" in text:
            why = "the key is encrypted and no passphrase is set (ASSURANCE_ATTEST_PASSPHRASE)"
        elif "passphrase is wrong" in text:
            why = "the key could not be read: malformed, or the passphrase is wrong"
        elif "not an ed25519" in text:
            why = "the key is not an Ed25519 private key"
        elif "does not exist" in text:
            why = "the key file does not exist"
        else:
            why = "the key could not be used"
        report.add("key.load", "fail", why + "; the service would answer 503 "
                   "attestation_key_unusable")
    except Exception as exc:  # noqa: BLE001 - never surface a parser's text next to key bytes
        report.add("key.load", "fail", f"the key could not be used ({type(exc).__name__})")
    return None


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def run_preflight(
    env: Mapping[str, str] | None = None,
    *,
    key_file: str | Path | None = None,
    trust_file: str | Path | None = None,
    expect_fingerprint: str = "",
    must_be_revoked: tuple[str, ...] = (),
    today: date | None = None,
    anchors: str | Path | None = None,
    anchor_max_age_hours: float | None = None,
    anchor_tenants_dir: str | Path | None = None,
    anchor_logs_dir: str | Path | None = None,
) -> PreflightReport:
    """Inspect an environment. ``key_file`` / ``trust_file`` stand in for the path variables."""
    e = os.environ if env is None else env
    now = today or datetime.now(UTC).date()
    rep = PreflightReport()

    # -- the service key ---------------------------------------------------------------
    pem = e.get(KEY_PEM_ENV, "").strip()
    path = str(key_file) if key_file else e.get(KEY_PATH_ENV, "")
    passphrase = e.get(PASSPHRASE_ENV, "")
    key: SigningKey | None = None
    if pem:
        rep.key_source = "environment (ASSURANCE_ATTEST_KEY_PEM)"
        rep.add("key.source", "info", "the key is read from ASSURANCE_ATTEST_KEY_PEM; custody "
                "is the secrets manager's, and its file mode cannot be checked")
        if path:
            rep.add("key.shadowed", "warn", "a key file path is also set; the service ignores "
                    "it while ASSURANCE_ATTEST_KEY_PEM is set")
        key = _load_key(pem, None, passphrase, rep)
    elif path:
        rep.key_source = "file (ASSURANCE_ATTEST_KEY)"
        problems = key_file_problems(path)
        for problem in problems:
            rep.add("key.permissions", "fail", problem)
        if not problems:
            rep.add("key.permissions", "ok", "owner-only regular file")
        key = _load_key(None, path, passphrase, rep)
        beside = [Path(e[v]).parent for v in ("ASSURANCE_LEDGER",) if e.get(v)]
        beside += [Path(e[v]) for v in ("ASSURANCE_TENANT_LEDGERS", LOGS_ENV) if e.get(v)]
        for data_dir in beside:
            if _inside(Path(path).parent, data_dir):
                rep.add("key.apart_from_data", "fail",
                        f"the key file sits in {data_dir}, with the data it vouches for; "
                        "whoever can rewrite the ledger can re-sign it")
                break
        else:
            rep.add("key.apart_from_data", "ok", "the key file is not under a configured "
                    "ledger or attestation-log directory")
    else:
        rep.add("key.source", "info", f"neither {KEY_PEM_ENV} nor {KEY_PATH_ENV} is set; "
                "counter-signing answers 503 no_attestation_key_configured")
    if key is not None:
        rep.service_fingerprint = key.fingerprint
        rep.add("key.load", "ok", f"Ed25519 key loads; public fingerprint {key.fingerprint}")
        if expect_fingerprint:
            if expect_fingerprint.strip().lower() == key.fingerprint:
                rep.add("key.expected_fingerprint", "ok", "matches --expect-fingerprint")
            else:
                rep.add("key.expected_fingerprint", "fail",
                        f"the key's fingerprint is {key.fingerprint}, not the "
                        f"{expect_fingerprint} expected; do not tell any customer it is "
                        "counter-signed")
        logs = e.get(LOGS_ENV, "")
        if not logs:
            rep.add("logs.dir", "warn", f"{LOGS_ENV} is unset; attestation logs would go to a "
                    "relative 'attestations' directory beside the process's working directory")
        elif not os.path.isdir(logs):
            rep.add("logs.dir", "warn", f"{LOGS_ENV} names a directory that does not exist yet; "
                    "it must be on persistent storage and writable by the service")
        elif not os.access(logs, os.W_OK):
            rep.add("logs.dir", "fail", f"{LOGS_ENV} is not writable by this user")
        else:
            rep.add("logs.dir", "ok", "attestation log directory exists and is writable")
    rep.counter_signing = key is not None and not any(
        c.status == "fail" and c.name.startswith(("key.", "logs.")) for c in rep.checks)

    # -- the recorder trust list --------------------------------------------------------
    tpath = str(trust_file) if trust_file else e.get(TRUST_ENV, "")
    trust: RecorderTrust | None = None
    if not tpath:
        rep.add("trust.source", "info", f"{TRUST_ENV} is unset: nobody is trusted, every hosted "
                "trace stays declared by its filer and capped at community. This is the safe "
                "default, not a fault")
    else:
        try:
            trust = RecorderTrust.from_json(tpath)
            rep.trust_status = "configured"
        except Exception as exc:  # noqa: BLE001 - the service fails closed on anything
            rep.trust_status = "unreadable"
            rep.add("trust.parse", "fail", f"the trust file cannot be used "
                    f"({type(exc).__name__}); the service fails closed and trusts nobody")
    if trust is not None:
        for problem in trust_file_problems(tpath):
            rep.add("trust.permissions", "fail", problem)
        entries = summarise(trust)
        rep.trust = [{"label": x.label, "fingerprint": x.fingerprint,
                      "provenance": list(x.provenance), "revoked": x.revoked,
                      "revoked_on": x.revoked_on} for x in entries]
        live = [x for x in entries if not x.revoked]
        rep.add("trust.parse", "ok", f"{len(entries)} recorder key(s), {len(live)} not revoked")
        if not live:
            rep.add("trust.live_keys", "warn", "no recorder key is trusted (empty, or every key "
                    "is revoked), so nothing can reach validated")
        for x in entries:
            if x.revoked and x.revoked_on and date.fromisoformat(x.revoked_on) > now:
                rep.add("trust.revoked_future", "warn",
                        f"{x.fingerprint} is revoked as of {x.revoked_on}, a future date; the "
                        "revocation is already in force, the date is not a schedule")
            if "field" in x.provenance and not x.revoked:
                rep.add("trust.field", "info",
                        f"{x.fingerprint} ({x.label or 'unlabelled'}) is believed when a trace "
                        "claims to be a field recording")
        by_fp = {x.fingerprint: x for x in entries}
        for fp in must_be_revoked:
            hit = by_fp.get(fp.strip().lower())
            if hit is not None and not hit.revoked:
                rep.add("trust.revoked_but_trusted", "fail",
                        f"{hit.fingerprint} must be revoked but is still trusted")
            else:
                rep.add("trust.revoked_but_trusted", "ok",
                        f"{fp} is revoked or absent, as required")
        if rep.service_fingerprint in by_fp:
            rep.add("trust.service_key_is_recorder", "fail",
                    "the service's own signing key is also a trusted recorder; the service "
                    "could vouch for traces it did not witness. Use separate keys")
        rep.add("trust.scope", "info", "the list is server-wide: every account's evidence is "
                "judged against it")
        rep.validated_verification = bool(live) and not any(
            c.status == "fail" and c.name.startswith("trust.") for c in rep.checks)
    if anchors is not None:
        _check_anchors(rep, key, anchors, anchor_max_age_hours, anchor_tenants_dir,
                       anchor_logs_dir)
    return rep


def _check_anchors(rep: PreflightReport, key: SigningKey | None, data_dir: str | Path,
                   max_age_hours: float | None, tenants_dir: str | Path | None,
                   logs_dir: str | Path | None) -> None:
    """Every tenant ledger needs a verified, young anchor. Read-only: nothing is signed."""
    from datetime import timedelta

    from assurance.attest.anchor_all import (
        DEFAULT_MAX_AGE_HOURS,
        _enumerate,
        anchor_status,
        layout,
    )
    from assurance.attest.attestation import AttestationLog
    from assurance.core.identity import utc_now
    from assurance.evidence.ledger import EvidenceLedger

    rep.anchors_checked = True
    if key is None:
        rep.add("anchors.key", "fail", "no usable service key, so no anchor can be verified; "
                "anchors are not read on trust")
        return
    hours = DEFAULT_MAX_AGE_HOURS if max_age_hours is None else max_age_hours
    try:
        tenants, logs = layout(data_dir, tenants_dir, logs_dir)
    except (OSError, ValueError) as exc:
        rep.add("anchors.layout", "fail", f"{exc}")
        return
    found, skipped = _enumerate(tenants)
    now = utc_now()
    ok = 0
    for account, path in found:
        try:
            state, reason, _ = anchor_status(
                EvidenceLedger(path, mint_id=False), AttestationLog(logs / f"{account}.jsonl"),
                key, max_age=timedelta(hours=hours), now=now)
        except Exception as exc:  # noqa: BLE001 - a broken ledger or log is a finding, not a crash
            rep.add(f"anchors.{account}", "fail", f"cannot be assessed ({type(exc).__name__})")
            continue
        if state in ("fresh", "grown"):
            ok += 1
            rep.add(f"anchors.{account}", "ok" if state == "fresh" else "info",
                    reason + ("" if state == "fresh" else "; completeness holds up to that anchor"))
        else:
            rep.add(f"anchors.{account}", "fail",
                    ("no verified anchor: " if state == "none" else "stale anchor: ") + reason
                    + "; GET /v1/ledger/verify cannot state completeness past it")
    for o in skipped:
        rep.add(f"anchors.skipped.{o.name}", "fail" if o.anomaly else "info", o.detail)
    rep.add("anchors.summary", "info", f"{ok} of {len(found)} tenant ledger(s) have a verified "
            f"anchor within {hours:g}h")
