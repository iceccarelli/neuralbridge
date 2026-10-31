"""Counter-sign the head of every hosted tenant ledger, so ``GET /v1/ledger/verify`` has an anchor.

``choose_anchor`` only trusts a ``read_from_ledger`` head signed by the *service* key, and a
hosted account has one only after somebody runs ``attest sign`` against its ledger. This is
that somebody, on a timer, for every account: ``assurance attest anchor-all``. Operator
tooling only; there is no HTTP surface, and the private key never leaves the operator's
machine.

Layout it reads (the same one the service uses; see ``assurance.api.deps``):

    <data-dir>/tenants/acc_<16 hex>.db        one ledger per account
    <data-dir>/attestations/acc_<16 hex>.jsonl  one attestation log per account

The operator's shared ledger is *not* a tenant: it sits beside ``tenants/``, is never
listed, and a file of that name inside ``tenants/`` is reported as skipped.

Per ledger, in this order:

1. the entry must be a regular file named exactly like an account ledger. A symlink, a
   directory or any other name is skipped and reported; nothing is followed;
2. the chain is verified in full. A ledger whose chain fails is **refused**: nothing is
   signed, because a signature over a broken history converts a detected break into a
   signed statement that all is well;
3. a newest verified anchor that is younger than ``--max-age`` and already names the current
   head means the ledger is **fresh** and nothing is written;
4. otherwise :func:`assurance.attest.attest` appends a counter-signed, ``read_from_ledger``
   head under the log's own single-writer lock. That function re-verifies the chain, refuses
   a ledger that became shorter than an earlier anchor, a rebuilt history, and a different
   key, so those surface here as refusals, not as new anchors.

What an anchor proves is :data:`assurance.attest.anchor.ANCHOR_MEANING`; what this job cannot
establish is :data:`ANCHOR_NOT_CHECKED`.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from assurance.attest.anchor import choose_anchor
from assurance.attest.attestation import (
    AttestationBusyError,
    AttestationError,
    AttestationLog,
    attest,
)
from assurance.attest.keys import SigningKey
from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger

__all__ = [
    "ANCHOR_NOT_CHECKED",
    "DEFAULT_MAX_AGE_HOURS",
    "AnchorAllReport",
    "LedgerOutcome",
    "anchor_all",
    "anchor_status",
    "layout",
]

DEFAULT_MAX_AGE_HOURS = 24.0

#: The same shape ``assurance.api.deps`` accepts for an account id.
_LEDGER_NAME = re.compile(r"(acc_[0-9a-f]{16})\.db")
#: SQLite's own companions of a ledger file; they are not ledgers and are not reported.
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")

ANCHOR_NOT_CHECKED = (
    "Key custody: who holds the private key, whether it was copied, and that the key used "
    "here is the service key customers were told.",
    "That this job runs on a schedule. A missed run is a stale anchor, found only by the next "
    "run or by `attest preflight --anchors`.",
    "An operator who controls the deployment can rewrite a ledger and its attestation log "
    "together; the anchor is as independent of the operator as the key's custody is.",
    "That the records behind a head are true. An anchor shows the ledger is not shorter than, "
    "and agrees with, a head that was signed; it covers nothing appended afterwards.",
)


@dataclass(frozen=True)
class LedgerOutcome:
    name: str
    #: anchored | fresh | would_anchor | refused | skipped | error
    status: str
    detail: str
    account_id: str = ""
    ledger_length: int | None = None
    head_seq: int | None = None
    sequence: int | None = None
    #: A skipped entry that looks like a tenant ledger (right name, unsafe type) is an
    #: anomaly that leaves an account unanchored, so it fails the run.
    anomaly: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "account_id": self.account_id, "status": self.status,
            "detail": self.detail, "ledger_length": self.ledger_length,
            "head_seq": self.head_seq, "anchor_sequence": self.sequence,
        }


@dataclass
class AnchorAllReport:
    key_fingerprint: str
    dry_run: bool
    max_age_hours: float
    outcomes: list[LedgerOutcome] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for o in self.outcomes if o.status == status)

    @property
    def exit_code(self) -> int:
        if self.count("refused") or any(o.anomaly for o in self.outcomes):
            return 1
        return 2 if self.count("error") else 0

    def summary(self) -> dict[str, int]:
        keys = ("anchored", "fresh", "would_anchor", "refused", "skipped", "error")
        return {k: self.count(k) for k in keys}

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.exit_code == 0, "dry_run": self.dry_run,
            "key_fingerprint": self.key_fingerprint, "max_age_hours": self.max_age_hours,
            "summary": self.summary(),
            "ledgers": [o.to_dict() for o in self.outcomes],
            "not_checked": list(ANCHOR_NOT_CHECKED),
        }


def layout(data_dir: str | Path, tenants_dir: str | Path | None = None,
           logs_dir: str | Path | None = None) -> tuple[Path, Path]:
    """``(tenant ledgers dir, attestation logs dir)`` for a deployment data directory.

    Defaults match the service: ``<data>/tenants`` and ``<data>/attestations``. A directory
    that is a symlink, or that resolves outside *data_dir* when it was not named
    explicitly, is refused with ``ValueError`` (the caller reports a usage error): the job
    must never be steered to another tree through a link.
    """
    data = Path(data_dir)
    if not data.is_dir():
        raise FileNotFoundError(f"{data} is not a directory. Nothing was read.")
    real_data = Path(os.path.realpath(data))
    resolved: list[Path] = []
    for explicit, default in ((tenants_dir, "tenants"), (logs_dir, "attestations")):
        p = Path(explicit) if explicit else data / default
        try:
            info = os.lstat(p)
        except FileNotFoundError:
            resolved.append(p)
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{p} is a symbolic link; refusing to follow it. Name the real "
                             "directory.")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{p} is not a directory.")
        if explicit is None and Path(os.path.realpath(p)).parent != real_data:
            raise ValueError(f"{p} resolves outside {data}; refusing.")
        resolved.append(p)
    return resolved[0], resolved[1]


def _is_plain_file(path: Path) -> tuple[bool, str]:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True, ""            # absent is the caller's concern
    if stat.S_ISLNK(info.st_mode):
        return False, "is a symbolic link; not followed"
    if not stat.S_ISREG(info.st_mode):
        return False, "is not a regular file"
    return True, ""


def anchor_status(
    ledger: EvidenceLedger, log: AttestationLog, key: SigningKey, *,
    max_age: timedelta, now: datetime,
) -> tuple[str, str, dict[str, Any] | None]:
    """``(state, reason, anchor)`` for one ledger. The ledger's chain is NOT checked here.

    ``state`` is ``fresh`` (a verified anchor within *max_age* already names the current
    head), ``grown`` (verified and young, but the ledger has records after it), ``stale``
    (verified, older than *max_age*), or ``none`` (no usable anchor; ``reason`` says why).
    """
    records, torn = log.scan()
    choice = choose_anchor(records, key.verifying, torn=torn, log_label="the attestation log")
    if choice.anchor is None:
        return "none", "; ".join(choice.reasons), None
    anchor = choice.anchor
    entries = ledger.entries()
    head = entries[-1] if entries else None
    covers = (anchor["ledger_length"] == len(entries)
              and anchor["head_seq"] == (head.seq if head else 0)
              and (head is None or anchor["head_link_hash"] == head.link_hash))
    age = now - parse_utc(anchor["attested_at"])
    if age >= max_age:
        return "stale", f"newest verified anchor is {_hours(age)} old", anchor
    if not covers:
        return "grown", "records exist that the newest anchor does not cover", anchor
    return "fresh", f"anchor {anchor['sequence']} is {_hours(age)} old and covers the head", anchor


def _hours(delta: timedelta) -> str:
    return f"{delta.total_seconds() / 3600:.1f}h"


def _enumerate(tenants: Path) -> tuple[list[tuple[str, Path]], list[LedgerOutcome]]:
    found: list[tuple[str, Path]] = []
    skipped: list[LedgerOutcome] = []
    if not tenants.is_dir():
        return found, skipped
    for name in sorted(os.listdir(tenants)):
        path = tenants / name
        match = _LEDGER_NAME.fullmatch(name)
        if match is None:
            base = next((name[: -len(s)] for s in _SQLITE_SIDECARS if name.endswith(s)), None)
            if base is not None and _LEDGER_NAME.fullmatch(base):
                continue
            skipped.append(LedgerOutcome(name, "skipped", "not an account ledger name "
                                         "(acc_ + 16 lowercase hex + .db); not touched"))
            continue
        ok, why = _is_plain_file(path)
        if not ok:
            skipped.append(LedgerOutcome(name, "skipped", f"{why}; not touched",
                                         account_id=match.group(1), anomaly=True))
            continue
        found.append((match.group(1), path))
    return found, skipped


def _one(account: str, path: Path, logs: Path, key: SigningKey, *, max_age: timedelta,
         dry_run: bool, now: datetime) -> LedgerOutcome:
    name = path.name
    log_path = logs / f"{account}.jsonl"
    ok, why = _is_plain_file(log_path)
    if not ok:
        return LedgerOutcome(name, "skipped", f"attestation log {why}; not touched",
                             account_id=account, anomaly=True)
    lock_side = Path(str(log_path) + ".lock")
    ok, why = _is_plain_file(lock_side)
    if not ok:
        return LedgerOutcome(name, "skipped", f"the log's lock file {why}; not touched",
                             account_id=account, anomaly=True)
    try:
        ledger = EvidenceLedger(path, mint_id=False)
        chain_ok, problems = ledger.verify_chain()
    except (sqlite3.DatabaseError, AssuranceError) as exc:
        return LedgerOutcome(name, "refused", "the ledger cannot be opened or verified "
                             f"({type(exc).__name__}); nothing was signed", account_id=account)
    if not chain_ok:
        return LedgerOutcome(
            name, "refused", f"chain does not verify ({problems[0] if problems else 'unknown'})"
            "; nothing was signed", account_id=account)
    entries = ledger.entries()
    length, head_seq = len(entries), (entries[-1].seq if entries else 0)
    log = AttestationLog(log_path, label=f"the attestation log for {account}")
    try:
        state, reason, _anchor = anchor_status(ledger, log, key, max_age=max_age, now=now)
        if state == "fresh":
            return LedgerOutcome(name, "fresh", reason, account, length, head_seq,
                                 _anchor["sequence"] if _anchor else None)
        if dry_run:
            return LedgerOutcome(name, "would_anchor",
                                 f"{state}: {reason}; dry run, nothing written",
                                 account, length, head_seq)
        record = attest(ledger, key, log, note="anchor-all", now=now)
    except AttestationBusyError as exc:
        return LedgerOutcome(name, "error", f"log busy; nothing signed ({type(exc).__name__})",
                             account_id=account)
    except AttestationError as exc:
        first = str(exc).splitlines()[0][:300]
        return LedgerOutcome(name, "refused", f"{first} Nothing was signed.", account_id=account)
    except (OSError, sqlite3.DatabaseError) as exc:
        return LedgerOutcome(name, "error", f"{type(exc).__name__}; nothing signed",
                             account_id=account)
    return LedgerOutcome(name, "anchored", f"attestation {record.sequence} appended",
                         account, record.ledger_length, record.head_seq, record.sequence)


def anchor_all(
    data_dir: str | Path, key: SigningKey, *,
    tenants_dir: str | Path | None = None, logs_dir: str | Path | None = None,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS, dry_run: bool = False,
    now: datetime | None = None,
) -> AnchorAllReport:
    """Anchor every tenant ledger under *data_dir*; see the module docstring."""
    tenants, logs = layout(data_dir, tenants_dir, logs_dir)
    moment = now or utc_now()
    max_age = timedelta(hours=max_age_hours)
    report = AnchorAllReport(key.fingerprint, dry_run, max_age_hours)
    found, skipped = _enumerate(tenants)
    for account, path in found:
        report.outcomes.append(
            _one(account, path, logs, key, max_age=max_age, dry_run=dry_run, now=moment))
    report.outcomes.extend(skipped)
    return report


def render(report: AnchorAllReport, *, extra: Sequence[str] = ()) -> str:
    """The per-ledger table and summary. Carries the public fingerprint, never key bytes."""
    lines = [f"anchor-all with key {report.key_fingerprint}"
             + ("  (dry run: nothing written)" if report.dry_run else "")]
    width = max([len(o.name) for o in report.outcomes] + [6])
    for o in report.outcomes:
        lines.append(f"  {o.name:<{width}}  {o.status:<12} {o.detail}")
    if not report.outcomes:
        lines.append("  no tenant ledgers found")
    s = report.summary()
    lines.append("")
    lines.append("  " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in s.items() if v
                                  or k in ("anchored", "fresh", "refused", "skipped")))
    lines.extend(extra)
    lines.append("\n  NOT checked:")
    lines.extend(f"    - {item}" for item in ANCHOR_NOT_CHECKED)
    return "\n".join(lines)
