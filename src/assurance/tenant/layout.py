"""Where one account's files live, and the checks that keep a command inside them.

The account id is validated against the strict ``acc_`` + 16 lowercase hex shape BEFORE any
filesystem access, and every path is then built from fixed suffixes of that id. Nothing here
globs, lists a directory or follows a symbolic link.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from assurance.attest.anchor_all import layout as _data_layout
from assurance.core.errors import AssuranceError

__all__ = ["AccountFiles", "TenantError", "account_files", "check_account_id", "plain_file",
           "sha256_file", "OPERATOR_LEDGER_NAME"]

OPERATOR_LEDGER_NAME = "art14-register.db"
_ACCOUNT_ID = re.compile(r"acc_[0-9a-f]{16}")
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")


class TenantError(AssuranceError):
    """A request this tool refuses (exit 1) or cannot run (exit 2); see ``exit_code``."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def check_account_id(value: str) -> str:
    if not isinstance(value, str) or not _ACCOUNT_ID.fullmatch(value):
        raise TenantError("not an account id: expected acc_ followed by 16 lowercase hex digits. "
                          "Nothing was read.", exit_code=2)
    return value


def plain_file(path: Path) -> bool:
    """True for a regular file, False if absent. A symlink or anything else raises."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise TenantError(f"{path} is a symbolic link; refusing to follow it. Nothing was "
                          "changed.")
    if not stat.S_ISREG(info.st_mode):
        raise TenantError(f"{path} is not a regular file; refusing. Nothing was changed.")
    return True


def sha256_file(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class AccountFiles:
    account_id: str
    data_dir: Path
    ledger: Path
    ledger_exists: bool
    #: SQLite companions of the ledger that exist (each a plain file)
    sidecars: tuple[Path, ...]
    log: Path
    log_exists: bool
    log_lock: Path
    log_lock_exists: bool

    def planned(self) -> list[Path]:
        """Exactly the files a deletion would remove, in removal order. Only existing ones.

        Built from fixed names derived from the validated id; never from a directory listing.
        """
        out: list[Path] = []
        if self.ledger_exists:
            out.append(self.ledger)
        out.extend(self.sidecars)
        if self.log_exists:
            out.append(self.log)
        if self.log_lock_exists:
            out.append(self.log_lock)
        return out


def account_files(data_dir: str | Path, account_id: str) -> AccountFiles:
    check_account_id(account_id)
    try:
        tenants, logs = _data_layout(data_dir)
    except (FileNotFoundError, ValueError) as exc:
        raise TenantError(str(exc), exit_code=2) from exc
    ledger = tenants / f"{account_id}.db"
    sidecars = tuple(p for s in _SQLITE_SIDECARS if plain_file(p := Path(f"{ledger}{s}")))
    log = logs / f"{account_id}.jsonl"
    lock = Path(f"{log}.lock")
    return AccountFiles(
        account_id=account_id, data_dir=Path(data_dir), ledger=ledger,
        ledger_exists=plain_file(ledger), sidecars=sidecars, log=log,
        log_exists=plain_file(log), log_lock=lock, log_lock_exists=plain_file(lock))
