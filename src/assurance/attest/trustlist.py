"""Operator workflow for the recorder trust file (``ASSURANCE_RECORDER_TRUST``).

Thin, file-level wrappers over :class:`~assurance.machine.recorder_attestation.RecorderTrust`,
which stays the only reader and writer of the format. Nothing here invents a field: the file
written is exactly the ``assurance.machine.recorder-trust.v1`` document the server loads, and
every operation re-reads what it wrote through the server's own loader before it returns.

Facts about the format that the operator must not be surprised by, all enforced by the
domain code and merely surfaced here:

* A trust entry has no validity window. The window of a *recording* is bounded by the
  attestation (``expires_on``) and by ``MAX_LAG_DAYS``; a *key* is trusted until it is revoked
  or removed.
* Revocation is total and immediate. ``revoked_on`` is recorded for people; the verifier
  rejects every attestation of a revoked key, whatever date the attestation states, because
  the signer chooses that date.
* The file holds public keys only. A private key in it, or offered to ``add``, is refused
  without being read back or echoed.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any

from assurance.attest.keys import SigningKeyError, VerifyingKey
from assurance.machine.recorder_attestation import (
    LIFTABLE_PROVENANCE,
    MAX_TRUST_BYTES,
    RecorderAttestationError,
    RecorderTrust,
    TrustedRecorder,
)

__all__ = [
    "PRIVATE_KEY_REFUSAL",
    "TrustEntry",
    "add_recorder",
    "create_trust_file",
    "entries_as_json",
    "load_trust",
    "revoke_recorder",
    "summarise",
    "trust_file_problems",
]

PRIVATE_KEY_REFUSAL = (
    "that file holds a PRIVATE key. The trust list takes public keys only, and a private key "
    "that has been sent to anybody else is burned: tell its owner to generate a new pair. "
    "Nothing was read from it, written, or printed.")

_FPR = re.compile(r"^[0-9a-f]{16}$")
_MAX_PUBLIC_BYTES = 16 * 1024


@dataclass(frozen=True)
class TrustEntry:
    """What the list says about one key. Public information only."""

    label: str
    fingerprint: str
    provenance: tuple[str, ...]
    revoked: bool
    revoked_on: str


def _fingerprint(value: str) -> str:
    fp = value.strip().lower()
    if not _FPR.match(fp):
        raise RecorderAttestationError(
            "a fingerprint is 16 lowercase hex characters, as `attest keygen` prints it.")
    return fp


def load_trust(path: str | Path) -> RecorderTrust:
    """Read the file exactly as the server does."""
    return RecorderTrust.from_json(path)


def summarise(trust: RecorderTrust) -> list[TrustEntry]:
    return [TrustEntry(r.label, r.fingerprint, tuple(sorted(r.provenance)), r.revoked,
                       r.revoked_on) for r in trust.recorders]


def trust_file_problems(path: str | Path) -> list[str]:
    """Who else can change this file. A trust list others can write is a list others control."""
    p = Path(path)
    try:
        info = os.stat(p)
    except OSError as exc:
        return [f"{p} cannot be inspected ({type(exc).__name__})"]
    if os.name == "posix" and info.st_mode & 0o022:
        return [f"{p} is writable by group or other (mode {info.st_mode & 0o777:04o}); "
                "whoever can write it decides which recorders the server believes"]
    return []


def _write(path: Path, trust: RecorderTrust, *, create: bool) -> None:
    """Write atomically, 0644, then prove the server's loader accepts the result."""
    text = json.dumps(trust.to_dict(), indent=2) + "\n"
    if len(text.encode("utf-8")) > MAX_TRUST_BYTES:
        raise RecorderAttestationError("the trust list would exceed the size the server reads.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if create:
        # Exclusive: never replace a file somebody else made between the check and now.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".trust-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    load_trust(path)                      # what was written must be what the server accepts


def create_trust_file(path: str | Path) -> Path:
    """Start an empty trust list. Refuses to replace one that exists."""
    p = Path(path)
    if p.exists() or p.is_symlink():
        raise RecorderAttestationError(
            f"{p} already exists; refusing to replace a trust list. Use `add` / `revoke`.")
    _write(p, RecorderTrust(), create=True)
    return p


def _read_public_key(path: Path) -> VerifyingKey:
    if path.stat().st_size > _MAX_PUBLIC_BYTES:
        raise RecorderAttestationError("that file is too large to be a public key.")
    data = path.read_bytes()
    if b"PRIVATE KEY" in data.upper():
        raise RecorderAttestationError(PRIVATE_KEY_REFUSAL)
    try:
        return VerifyingKey.from_pem(data)
    except SigningKeyError as exc:
        raise RecorderAttestationError(f"{path.name}: {exc}") from exc


def add_recorder(
    trust_path: str | Path,
    public_key_file: str | Path,
    *,
    label: str,
    provenance: frozenset[str],
    expected_fingerprint: str,
) -> TrustEntry:
    """Trust one recorder key for the named provenance classes.

    ``expected_fingerprint`` is required: the fingerprint the recorder operator read to you
    by a route other than the one the key arrived on. A key that does not hash to it is
    refused, so a key swapped in transit is not trusted.
    """
    if not provenance or not provenance <= LIFTABLE_PROVENANCE:
        raise RecorderAttestationError(
            f"provenance must name one or more of {', '.join(sorted(LIFTABLE_PROVENANCE))}; "
            "'simulation' is never liftable.")
    if not label.strip():
        raise RecorderAttestationError("a label is required: say whose recorder this is.")
    key = _read_public_key(Path(public_key_file))
    wanted = _fingerprint(expected_fingerprint)
    if key.fingerprint != wanted:
        raise RecorderAttestationError(
            f"the key in {Path(public_key_file).name} has fingerprint {key.fingerprint}, not "
            f"the {wanted} you were given. Do not trust it until the difference is explained.")
    p = Path(trust_path)
    existing = load_trust(p).recorders
    entry = TrustedRecorder(label=label.strip(), key=key, provenance=provenance)
    _write(p, RecorderTrust([*existing, entry]), create=False)   # duplicate key: refused
    return TrustEntry(entry.label, entry.fingerprint, tuple(sorted(provenance)), False, "")


def revoke_recorder(trust_path: str | Path, fingerprint: str, *, effective: str) -> TrustEntry:
    """Revoke a key. ``effective`` is an explicit ``YYYY-MM-DD``; there is no default.

    The date is recorded for the humans who read the list. The verifier does not use it to
    keep older attestations: every attestation of a revoked key is rejected.
    """
    try:
        when = date.fromisoformat(effective)
    except ValueError as exc:
        raise RecorderAttestationError(
            "--effective must be an explicit date, YYYY-MM-DD.") from exc
    if when.isoformat() != effective:
        raise RecorderAttestationError("--effective must be an explicit date, YYYY-MM-DD.")
    fp = _fingerprint(fingerprint)
    p = Path(trust_path)
    current = load_trust(p).recorders
    target = next((r for r in current if r.fingerprint == fp), None)
    if target is None:
        raise RecorderAttestationError(f"no recorder with fingerprint {fp} is in this list.")
    if target.revoked:
        raise RecorderAttestationError(
            f"{fp} is already revoked"
            + (f" as of {target.revoked_on}" if target.revoked_on else "")
            + "; the recorded date is not rewritten.")
    changed = replace(target, revoked=True, revoked_on=effective)
    _write(p, RecorderTrust([changed if r is target else r for r in current]), create=False)
    return TrustEntry(changed.label, fp, tuple(sorted(changed.provenance)), True, effective)


def entries_as_json(entries: list[TrustEntry]) -> list[dict[str, Any]]:
    return [{"label": e.label, "fingerprint": e.fingerprint, "provenance": list(e.provenance),
             "revoked": e.revoked, "revoked_on": e.revoked_on} for e in entries]
