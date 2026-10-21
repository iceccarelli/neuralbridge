"""Back up the service's data directory consistently, and prove a restore.

The hosted service keeps three kinds of state, all SQLite, all on one volume:

* ``accounts.db`` — accounts, key hashes, usage, processed billing events;
* the operator ledger (``art14-register.db``) — the shared, operator-only chain;
* ``tenants/<account id>.db`` — one hash-chained ledger per customer account;
* ``attestations/`` and ``supplier-feeds/`` — append-only JSONL logs, copied as
  files (they are written by single appends and are not SQLite).

A plain file copy of a WAL-mode database can lose its newest records, and
``sqlite3 .dump`` of only the operator ledger — what the deploy README used to
suggest — silently skips every customer's evidence. ``backup`` takes a
transactionally consistent snapshot of **all** of it; ``verify`` opens a backup
(or a restored volume) and checks what can be checked from the files alone.

What ``verify`` establishes: each database passes SQLite's integrity check, each
ledger's hash chain verifies, every tenant ledger belongs to a known account.
What it cannot: that nothing was *removed* from a ledger by someone who rebuilt
the chain — only a signed head attestation closes that (``ATTEST.md``). It says
so in its output.

    python -m assurance.evidence.restore_check backup  <data dir> <backup dir>
    python -m assurance.evidence.restore_check verify  <data or backup dir>

Exit codes: 0 verified, 1 a finding, 2 could not run.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from assurance.evidence.ledger import EvidenceLedger

__all__ = ["backup", "verify", "main"]

_OPERATOR_LEDGER = "art14-register.db"
_ACCOUNTS = "accounts.db"
_TENANT = re.compile(r"^acc_[0-9a-f]{16}\.db$")
_LOG_DIRS = ("attestations", "supplier-feeds")


#: Longest a snapshot waits for a source that stays locked, in seconds. sqlite3's
#: ``backup()`` retries a busy source for ever on its own.
BACKUP_DEADLINE = 30.0


def _ro_uri(path: Path) -> str:
    """A read-only SQLite URI for ``path``, percent-encoded.

    ``f"file:{path}?mode=ro"`` ends the URI at a ``#`` or ``?`` in the path: the
    "source" became a different, nonexistent file that SQLite then created empty,
    and the backup reported success with an empty snapshot.
    """
    return f"{Path(path).resolve().as_uri()}?mode=ro"


def _snapshot(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    # A short busy timeout on the source: each backup step then returns BUSY after about
    # a second instead of waiting out 30 s inside SQLite, so ``bounded`` below gets to
    # enforce BACKUP_DEADLINE at that granularity.
    source = sqlite3.connect(_ro_uri(src), uri=True, timeout=min(1.0, BACKUP_DEADLINE))
    started = time.monotonic()

    def bounded(status: int, remaining: int, total: int) -> None:
        # Called after every step, including the ones that found the source busy.
        if status in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) \
                and time.monotonic() - started >= BACKUP_DEADLINE:
            raise sqlite3.OperationalError(
                f"database is locked: gave up after {BACKUP_DEADLINE:g}s waiting to "
                f"snapshot {src.name}")

    try:
        target = sqlite3.connect(dest)
        try:
            source.backup(target, progress=bounded)
        finally:
            target.close()
    finally:
        source.close()


def backup(data_dir: Path, out_dir: Path) -> list[str]:
    """Snapshot every database under ``data_dir`` into ``out_dir``. Returns names."""
    if not data_dir.is_dir():
        raise FileNotFoundError(f"{data_dir} is not a directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    taken: list[str] = []
    for name in (_ACCOUNTS, _OPERATOR_LEDGER):
        if (data_dir / name).exists():
            _snapshot(data_dir / name, out_dir / name)
            taken.append(name)
    tenants = data_dir / "tenants"
    if tenants.is_dir():
        for path in sorted(tenants.glob("*.db")):
            _snapshot(path, out_dir / "tenants" / path.name)
            taken.append(f"tenants/{path.name}")
    for name in _LOG_DIRS:
        if (data_dir / name).is_dir():
            shutil.copytree(data_dir / name, out_dir / name, dirs_exist_ok=True)
            taken.append(f"{name}/")
    return taken


def _integrity(path: Path) -> str:
    db = sqlite3.connect(_ro_uri(path), uri=True, timeout=30)
    try:
        return str(db.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        db.close()


def _account_ids(accounts: Path) -> set[str]:
    db = sqlite3.connect(_ro_uri(accounts), uri=True, timeout=30)
    try:
        return {r[0] for r in db.execute("SELECT id FROM accounts")}
    finally:
        db.close()


def verify(root: Path) -> dict[str, object]:
    """Check a data directory or backup. Never raises on a corrupt database."""
    problems: list[str] = []
    checked: dict[str, int] = {}

    def check_ledger(path: Path, label: str) -> None:
        try:
            if (res := _integrity(path)) != "ok":
                problems.append(f"{label}: SQLite integrity_check says {res}")
                return
            ledger = EvidenceLedger(path)
            ok, found = ledger.verify_chain()
            checked[label] = len(ledger.entries())
            if not ok:
                problems.extend(f"{label}: {p}" for p in found)
        except Exception as exc:  # noqa: BLE001 - a corrupt file is a finding
            problems.append(f"{label}: unreadable ({type(exc).__name__})")

    accounts = root / _ACCOUNTS
    known: set[str] = set()
    if not accounts.exists():
        problems.append(f"{_ACCOUNTS} is missing — keys and entitlements cannot be restored")
    else:
        try:
            if (res := _integrity(accounts)) != "ok":
                problems.append(f"{_ACCOUNTS}: SQLite integrity_check says {res}")
            else:
                known = _account_ids(accounts)
                checked[_ACCOUNTS] = len(known)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{_ACCOUNTS}: unreadable ({type(exc).__name__})")

    if (root / _OPERATOR_LEDGER).exists():
        check_ledger(root / _OPERATOR_LEDGER, _OPERATOR_LEDGER)

    tenants = root / "tenants"
    if tenants.is_dir():
        for path in sorted(tenants.glob("*.db")):
            label = f"tenants/{path.name}"
            if not _TENANT.match(path.name):
                problems.append(f"{label}: not a tenant ledger name")
                continue
            if known and path.stem not in known:
                problems.append(f"{label}: belongs to no account in {_ACCOUNTS}")
            check_ledger(path, label)

    for name in _LOG_DIRS:
        if (root / name).is_dir():
            checked[f"{name}/"] = sum(1 for _ in (root / name).glob("*"))

    return {
        "ok": not problems,
        "checked": checked,
        "problems": problems,
        "not_established": [
            "That nothing was removed from a ledger by someone who rebuilt its "
            "chain. Only a signed head attestation shows that (assurance attest verify).",
            "That this backup is recent: the files carry no proof of when they were taken.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(argv) == 3 and argv[0] == "backup":
            names = backup(Path(argv[1]), Path(argv[2]))
            print(json.dumps({"backed_up": names}, indent=2))
            return 0
        if len(argv) == 2 and argv[0] == "verify":
            result = verify(Path(argv[1]))
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
    except (OSError, sqlite3.Error) as exc:
        print(f"could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
