"""Key custody guards and the rotation-aware verifier.

Two things live here because both are about *which key* a signature is allowed to be
checked against:

* :func:`key_file_problems` / :func:`require_private_key_file` refuse a private key file
  that anybody but its owner can read. A signing key readable by another account on the
  host is not held apart from anything.
* :func:`verify_log_across_rotation` checks one attestation log against a set of public
  keys the **verifier** pinned, so a log that spans a rotation verifies without any key
  being taken from the log. A record names the fingerprint it claims; the claim only picks
  *among the pinned keys*. A key that arrived with an artefact is never a candidate.

Neither function prints, returns or raises key material: messages carry paths, modes and
fingerprints only.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from assurance.attest.attestation import HeadAttestation, LogVerdict, verify_log
from assurance.attest.keys import SigningKeyError, VerifyingKey

__all__ = [
    "key_file_problems",
    "require_private_key_file",
    "verify_log_across_rotation",
]

#: Any permission bit for group or other. A private key file allows none.
_LOOSE = stat.S_IRWXG | stat.S_IRWXO


def key_file_problems(path: str | Path) -> list[str]:
    """Why this private key file is not safe to use, or ``[]`` if it is.

    A symlink is refused outright (so the file that is checked is the file that is read),
    the target must be a regular file, and neither group nor other may have any access.
    Not checkable off POSIX, which is said rather than passed.
    """
    p = Path(path)
    try:
        info = os.lstat(p)
    except FileNotFoundError:
        return [f"{p} does not exist"]
    except OSError as exc:
        return [f"{p} cannot be inspected ({type(exc).__name__})"]
    if stat.S_ISLNK(info.st_mode):
        return [f"{p} is a symbolic link; point at the key file itself, so the file that is "
                "checked is the file that is read"]
    if not stat.S_ISREG(info.st_mode):
        return [f"{p} is not a regular file"]
    if os.name != "posix":
        return [f"{p}: file permissions cannot be checked on this platform"]
    if info.st_mode & _LOOSE:
        return [f"{p} has mode {stat.S_IMODE(info.st_mode):04o}; a private key must be "
                "readable by its owner alone (chmod 600)"]
    return []


def require_private_key_file(path: str | Path) -> None:
    """Raise :class:`SigningKeyError` unless the key file is owner-only."""
    problems = key_file_problems(path)
    if problems:
        raise SigningKeyError("; ".join(problems))


class _KeySet:
    """Duck-typed stand-in for :class:`VerifyingKey` over several pinned keys.

    ``verify`` is true only if some pinned key made the signature. ``fingerprint`` is the
    pinned set, so the verdict's "obtain this fingerprint elsewhere" note names all of them.
    """

    def __init__(self, keys: Iterable[VerifyingKey]) -> None:
        self.by_fp = {k.fingerprint: k for k in keys}

    @property
    def fingerprint(self) -> str:
        return ", ".join(sorted(self.by_fp))

    def verify(self, message: bytes, signature: bytes) -> bool:
        return any(k.verify(message, signature) for k in self.by_fp.values())


#: ``verify_log`` reports a log naming several fingerprints as a problem because it checks
#: against one key. Across a rotation that is expected; every other finding is kept.
_MULTI_KEY_MARKER = "the log names more than one signing key"


def verify_log_across_rotation(
    records: Iterable[HeadAttestation],
    keys: Iterable[VerifyingKey],
    **kwargs: Any,
) -> LogVerdict:
    """Verify a log that may span key rotations against the verifier's pinned *keys*.

    Every record must (a) name a fingerprint that is one of the pinned keys, and (b) carry a
    signature made by *that* key, not merely by some pinned key. Sequence, predecessor and
    shrinkage checks are ``verify_log``'s own. A record signed by a key that is not pinned
    is a problem, however valid its signature is under the key it names.
    """
    recs = list(records)
    pinned = _KeySet(keys)
    verdict = verify_log(recs, cast(VerifyingKey, pinned), **kwargs)
    problems = [p for p in verdict.problems if not p.startswith(_MULTI_KEY_MARKER)]
    for r in recs:
        key = pinned.by_fp.get(r.key_fingerprint)
        if key is None:
            problems.append(
                f"attestation {r.sequence}: signed under key {r.key_fingerprint}, which is "
                "not one of the keys you pinned. A key is never taken from the log; pin the "
                "retired key's public half if this span predates a rotation")
        elif not r.verified_by(key):
            problems.append(
                f"attestation {r.sequence}: signature does not verify under pinned key "
                f"{key.fingerprint}")
    return LogVerdict(
        ok=not problems, checked=verdict.checked, problems=problems,
        checks_skipped=verdict.checks_skipped, key_fingerprint=pinned.fingerprint,
        latest=verdict.latest, notes=verdict.notes)
