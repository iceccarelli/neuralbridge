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

``backup`` also writes ``backup-manifest.json``: every file with its size and SHA-256, each
ledger's length and head link hash, the attestation logs' record counts and the list of
accounts. Without it ``verify`` could only look at the files that happen to be present, and a
restore that had lost a ledger — or all of them — read "ok". The backup directory is created
``0700`` and its files ``0600``, and the ``pending_keys`` rows (API keys minted by a checkout
and not yet collected, held in plaintext for up to 24 hours) are **not copied**: a customer
whose key was still unclaimed at backup time must be issued a new one after a restore.

What ``verify`` establishes: each database passes SQLite's integrity check, each ledger's
hash chain verifies, every tenant ledger belongs to a known account, every file the manifest
lists is present with the recorded hash (or, with ``--live``, a ledger only ever grew past the
recorded head), nothing unlisted appeared, and every attestation log still fits the ledger it
was signed over (a ledger shorter than its own attestation log has lost evidence).
What it cannot: that nothing was *removed* by someone who also rewrote the manifest and the
attestation log (the manifest is not signed; keep ``manifest_sha256`` from the ``backup``
output somewhere else), or that a log's records are genuine (the signing key is not in a
backup: ``attest verify`` with the public key does that). It says so in its output.

    python -m assurance.evidence.restore_check backup  <data dir> <backup dir>
    python -m assurance.evidence.restore_check verify  [--live] [--against-live <live data dir>] <dir>

``backup`` exits 1 and writes ``degraded: true`` when the source already fails a check (a
broken chain, or an attestation log that claims more than its ledger holds); the snapshot is
kept, and ``verify`` fails it. Every ledger carries a random ``ledger_id`` (its lineage, kept
by a file copy); ``--against-live`` fails a restored ledger that shares an id with one on the
live volume but disagrees with it, i.e. a fork. A hash chain alone does not detect removal
of the newest records: without an attestation log ``verify`` says so under ``not_established``.

Exit codes: 0 verified, 1 a finding, 2 could not run, 3 **unchecked** — there is no manifest
(a backup taken by an older build, or a live data directory without ``--live`` context), so
the files are consistent as far as they can be read and nothing says nothing is missing.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from assurance.attest import AttestationBasis, AttestationLog, check_log_against_ledger
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger

__all__ = ["MANIFEST_NAME", "backup", "verify", "main"]

MANIFEST_NAME = "backup-manifest.json"
MANIFEST_FORMAT = "neuralbridge-backup-manifest/1"

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


def _private_dir(path: Path) -> None:
    """Create ``path`` (and parents) and make it 0700 NOW.

    The umask is only the first line of defence: a default ACL on the parent, or a filesystem
    that ignores the umask, hands a new directory group/world access anyway (observed: a
    Codespace's /tmp gives 0756 under umask 077). An explicit chmod is not subject to either, and
    a 0700 directory shuts everyone else out of whatever is created inside it.
    """
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _snapshot(src: Path, dest: Path) -> None:
    _private_dir(dest.parent)
    # Create the file 0600 before SQLite does: SQLite asks for 0644 and leaves the rest to the
    # umask, which an ACL can override. An existing file is left to _tighten.
    try:
        os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError:
        pass
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


def _strip_pending_keys(path: Path) -> int:
    """Delete the unclaimed plaintext checkout keys from a backup copy. Returns how many.

    ``secure_delete`` and a ``VACUUM`` afterwards, so the key bytes are not left in a free
    page of the file (they would also be in any page the live database had freed earlier).
    """
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA secure_delete=ON")
        try:
            count = int(db.execute("SELECT COUNT(*) FROM pending_keys").fetchone()[0])
            db.execute("DELETE FROM pending_keys")
            db.commit()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
            count = 0
        db.execute("VACUUM")
        return count
    finally:
        db.close()


def _sha256(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = limit
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20 if remaining is None else min(1 << 20, remaining))
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
                if remaining <= 0:
                    break
    return digest.hexdigest()


def _tighten(root: Path) -> None:
    """0700 directories, 0600 files, whatever the source or the umask said."""
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            continue
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _ledger_facts(path: Path) -> dict[str, Any]:
    ledger = EvidenceLedger(path, mint_id=False)
    entries = ledger.entries()
    last = entries[-1] if entries else None
    return {"entries": len(entries), "head_seq": last.seq if last else 0,
            "head_link_hash": last.link_hash if last else "",
            "ledger_id": ledger.ledger_id()}


def _read_attestations(path: Path) -> tuple[list[Any], bool]:
    """``(records, torn_tail)`` of an attestation log; raises on a log that cannot be read."""
    return AttestationLog(path).scan()


def _is_ledger(rel: str) -> bool:
    return rel == _OPERATOR_LEDGER or (rel.startswith("tenants/") and rel.endswith(".db"))


def _write_manifest(
    out_dir: Path, pending_not_copied: int, findings: list[str] | None = None
) -> dict[str, Any]:
    files: dict[str, Any] = {}
    for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(out_dir).as_posix()
        if rel == MANIFEST_NAME:
            continue
        entry: dict[str, Any] = {"size": path.stat().st_size, "sha256": _sha256(path)}
        if _is_ledger(rel):
            entry.update(_ledger_facts(path))
        elif rel.startswith("attestations/") and rel.endswith(".jsonl"):
            try:
                entry["records"] = len(_read_attestations(path)[0])
            except Exception:  # noqa: BLE001 - a damaged log is recorded as unreadable
                entry["records"] = None
        files[rel] = entry
    accounts = sorted(_account_ids(out_dir / _ACCOUNTS)) if (out_dir / _ACCOUNTS).exists() else []
    manifest = {
        "format": MANIFEST_FORMAT,
        "taken_at": format_utc(utc_now()),
        "files": files,
        "accounts": accounts,
        "pending_keys_not_copied": pending_not_copied,
        # A snapshot of a source that already failed its own checks is still a snapshot
        # (it is evidence), but it must not read as a good backup.
        "degraded": bool(findings),
        "source_findings": list(findings or []),
        "note": ("Checksums, not signatures: anyone who can rewrite this file can rewrite the "
                 "backup. Keep its SHA-256 (printed by `backup`) somewhere the volume is not."),
    }
    path = out_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return manifest


def _source_findings(root: Path) -> list[str]:
    """Findings in a fresh snapshot: a ledger whose chain breaks, or an attestation log that
    claims more than its ledger holds (the only way a truncated tail shows)."""
    found: list[str] = []
    ledgers = [p for p in (root / _OPERATOR_LEDGER,) if p.is_file()]
    if (root / "tenants").is_dir():
        ledgers += sorted((root / "tenants").glob("*.db"))
    for path in ledgers:
        label = path.relative_to(root).as_posix()
        try:
            ok, problems = EvidenceLedger(path, mint_id=False).verify_chain()
        except Exception as exc:  # noqa: BLE001 - unreadable is a finding
            found.append(f"{label}: unreadable ({type(exc).__name__})")
            continue
        if not ok:
            found.extend(f"{label}: {p}" for p in problems)
    _check_attestation_logs(root, found, {})
    return found


def backup(data_dir: Path, out_dir: Path) -> list[str]:
    """Snapshot every database under ``data_dir`` into ``out_dir``. Returns names.

    Also writes the manifest (``MANIFEST_NAME``), which is not in the returned names. Each
    ledger is chain-verified and every attestation log is compared with its ledger after the
    snapshot; any finding is kept (``degraded: true``, ``source_findings``) rather than
    refusing, because a damaged source is still worth keeping. ``verify`` then fails it. The
    result is private to its owner and carries no unclaimed plaintext API keys. ``out_dir``
    must not exist or be empty (``FileExistsError``).
    """
    if not data_dir.is_dir():
        raise FileNotFoundError(f"{data_dir} is not a directory")
    if out_dir.is_dir() and any(out_dir.iterdir()):
        # A snapshot written over an earlier one would list, and vouch for, files it did not
        # write. Take it into a directory of its own.
        raise FileExistsError(f"{out_dir} already holds files; back up into an empty directory")
    previous = os.umask(0o077)
    try:
        _private_dir(out_dir)
        taken: list[str] = []
        pending = 0
        # Tenant ledgers first, the account list after them: a customer who signs up while the
        # backup runs then has an account row without a ledger (harmless), never a ledger in
        # the backup whose account is not (a spurious `belongs to no account`).
        tenants = data_dir / "tenants"
        if tenants.is_dir():
            for path in sorted(tenants.glob("*.db")):
                EvidenceLedger(path)    # gives a pre-id ledger its lineage id before the copy
                _snapshot(path, out_dir / "tenants" / path.name)
                taken.append(f"tenants/{path.name}")
        for name in (_ACCOUNTS, _OPERATOR_LEDGER):
            if (data_dir / name).exists():
                if name == _OPERATOR_LEDGER:
                    EvidenceLedger(data_dir / name)
                _snapshot(data_dir / name, out_dir / name)
                taken.append(name)
        if (out_dir / _ACCOUNTS).exists():
            pending = _strip_pending_keys(out_dir / _ACCOUNTS)
        for name in _LOG_DIRS:
            if (data_dir / name).is_dir():
                shutil.copytree(data_dir / name, out_dir / name, dirs_exist_ok=True)
                taken.append(f"{name}/")
        _tighten(out_dir)
        _write_manifest(out_dir, pending, _source_findings(out_dir))
        return taken
    finally:
        os.umask(previous)


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


def _symlinks(root: Path) -> list[str]:
    """Every symbolic link under ``root`` (not followed), relative to it."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in (*dirnames, *filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def _safe_rel(rel: object) -> bool:
    return (isinstance(rel, str) and bool(rel) and not rel.startswith("/")
            and ".." not in Path(rel).parts)


def _check_manifest(
    root: Path, manifest: dict[str, Any], known: set[str], allow_growth: bool,
    problems: list[str],
) -> None:
    """Compare what is on disk with what the backup recorded."""
    files = manifest.get("files")
    if not isinstance(files, dict):
        problems.append(f"{MANIFEST_NAME}: has no file list")
        return
    for rel, entry in sorted(files.items()):
        if not _safe_rel(rel) or not isinstance(entry, dict):
            problems.append(f"{MANIFEST_NAME}: refusing the entry {str(rel)[:60]!r}")
            continue
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel}: missing — the manifest lists it ({entry.get('size')} bytes)"
                            + (", a ledger" if _is_ledger(rel) else ""))
            continue
        size, digest = entry.get("size"), entry.get("sha256")
        if allow_growth and _is_ledger(rel):
            _ledger_only_grew(path, rel, entry, problems)
        elif allow_growth and rel.startswith(("attestations/", "supplier-feeds/")):
            # append-only logs: the recorded bytes must still be the start of the file
            if not isinstance(size, int) or path.stat().st_size < size \
                    or _sha256(path, size) != digest:
                problems.append(f"{rel}: is not an extension of the backed-up log (sha256 of "
                                "its first bytes differs, or it is shorter)")
        elif allow_growth:
            continue    # accounts.db and the like move on a live service; nothing to compare
        elif path.stat().st_size != size or _sha256(path) != digest:
            problems.append(f"{rel}: size or sha256 differs from the manifest — modified, "
                            "truncated or replaced since the backup was taken")
    listed = set(files)
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel == MANIFEST_NAME or rel in listed:
            continue
        if allow_growth and (rel.startswith(("tenants/", "attestations/", "supplier-feeds/"))
                             or rel == _OPERATOR_LEDGER):
            continue
        problems.append(f"{rel}: not in the manifest — added since the backup was taken")
    recorded = manifest.get("accounts")
    if isinstance(recorded, list) and known:
        gone = sorted(set(map(str, recorded)) - known)
        if gone:
            problems.append("accounts.db no longer lists account(s) the backup recorded: "
                            + ", ".join(gone[:5]))
        extra = sorted(known - set(map(str, recorded)))
        if extra and not allow_growth:
            problems.append("accounts.db lists account(s) the backup did not record: "
                            + ", ".join(extra[:5]))


def _ledger_only_grew(path: Path, rel: str, entry: dict[str, Any], problems: list[str]) -> None:
    try:
        ledger = EvidenceLedger(path, mint_id=False)
        entries = ledger.entries()
    except Exception as exc:  # noqa: BLE001
        problems.append(f"{rel}: unreadable ({type(exc).__name__})")
        return
    recorded_id, now_id = entry.get("ledger_id"), ledger.ledger_id()
    if recorded_id and now_id and recorded_id != now_id:
        problems.append(f"{rel}: is a different ledger from the one backed up (ledger_id "
                        f"{now_id[:8]} where {recorded_id[:8]} was recorded) — replaced, "
                        "not grown")
    want = entry.get("entries")
    if not isinstance(want, int):
        return
    if len(entries) < want:
        problems.append(f"{rel}: holds {len(entries)} record(s); the backup held {want}. "
                        f"{want - len(entries)} record(s) were removed since.")
        return
    if want:
        at = {e.seq: e.link_hash for e in entries}.get(entry.get("head_seq"))
        if at != entry.get("head_link_hash"):
            problems.append(f"{rel}: the record at seq {entry.get('head_seq')} is not the one "
                            "the backup held — the history was rewritten")


def _safe_records(path: Path) -> list[Any]:
    try:
        return _read_attestations(path)[0] if path.is_file() else []
    except Exception:  # noqa: BLE001 - an unreadable log is reported by _check_attestation_logs
        return []


def _check_attestation_logs(
    root: Path, problems: list[str], records_seen: dict[str, int]
) -> None:
    """Every attestation log must still fit the ledger it was signed over.

    This compares what each record states (length, head, link hash) with the ledger beside
    it; the signing key is not in a backup, so it does not prove the log is genuine.
    """
    logs = root / "attestations"
    if not logs.is_dir():
        return
    for log_path in sorted(logs.glob("*.jsonl")):
        label = f"attestations/{log_path.name}"
        try:
            records, _torn = _read_attestations(log_path)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{label}: cannot be read as an attestation log "
                            f"({type(exc).__name__}) — the cross-check against its ledger "
                            "could not be made")
            continue
        records_seen[label] = len(records)
        mine = [r for r in records if r.basis is AttestationBasis.READ_FROM_LEDGER]
        if not mine:
            continue
        ledger_path = root / "tenants" / f"{log_path.stem}.db"
        if not ledger_path.is_file():
            problems.append(f"{label}: attests {mine[-1].ledger_length} record(s) of "
                            f"tenants/{log_path.stem}.db, which is missing — that evidence "
                            "was lost")
            continue
        try:
            found, _ = check_log_against_ledger(
                mine, EvidenceLedger(ledger_path, mint_id=False), basis=AttestationBasis.READ_FROM_LEDGER,
                chain=False)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{label}: cross-check against its ledger failed "
                            f"({type(exc).__name__})")
            continue
        problems.extend(f"{label} vs tenants/{log_path.name[:-6]}.db: {p}" for p in found)


def _ledger_files(root: Path) -> dict[str, Path]:
    out = {_OPERATOR_LEDGER: root / _OPERATOR_LEDGER} if (root / _OPERATOR_LEDGER).is_file() else {}
    if (root / "tenants").is_dir():
        out.update({f"tenants/{p.name}": p for p in sorted((root / "tenants").glob("*.db"))})
    return out


def _check_lineage(root: Path, live: Path, problems: list[str]) -> None:
    """A restored ledger must not be a second writable copy of one the live volume holds.

    Same ``ledger_id`` and the same records up to the shorter of the two is one lineage
    (the restore is behind, or equal): fine to inspect, and say nothing. Same id and a
    different link hash at a shared position is a fork: both verify on their own, and
    neither can tell it lost.
    """
    held: dict[str, tuple[str, dict[int, str]]] = {}
    for rel, path in _ledger_files(live).items():
        try:
            lg = EvidenceLedger(path, mint_id=False)
            if (lid := lg.ledger_id()):
                held[lid] = (rel, {e.seq: e.link_hash for e in lg.entries()})
        except Exception:  # noqa: BLE001, S112 - the live volume's own problem
            continue
    for rel, path in _ledger_files(root).items():
        try:
            lg = EvidenceLedger(path, mint_id=False)
            lid = lg.ledger_id()
            mine = {e.seq: e.link_hash for e in lg.entries()}
        except Exception:  # noqa: BLE001, S112 - reported by check_ledger
            continue
        if lid and lid in held:
            where, theirs = held[lid]
            forked = sorted(q for q in mine.keys() & theirs.keys() if mine[q] != theirs[q])
            if forked:
                problems.append(
                    f"{rel}: carries ledger_id {lid[:8]}, which the live volume already holds "
                    f"as {where}, but the two disagree from seq {forked[0]} — one ledger forked "
                    "into two lineages. Only one may stay writable; the other's records after "
                    "the fork point are not in the first.")


def verify(
    root: Path, *, allow_growth: bool = False, live_dir: Path | None = None,
) -> dict[str, object]:
    """Check a data directory or backup. Never raises on a corrupt database.

    ``status`` is ``ok`` (checked against the backup's manifest), ``failed`` (a finding) or
    ``unchecked`` (no manifest: nothing says nothing is missing). ``allow_growth`` is for a
    volume that has been running since the backup: ledgers and logs may be longer, never
    shorter or different.
    """
    problems: list[str] = []
    checked: dict[str, int] = {}

    def check_ledger(path: Path, label: str) -> None:
        try:
            if (res := _integrity(path)) != "ok":
                problems.append(f"{label}: SQLite integrity_check says {res}")
                return
            ledger = EvidenceLedger(path, mint_id=False)
            ok, found = ledger.verify_chain()
            checked[label] = len(ledger.entries())
            if not ok:
                problems.extend(f"{label}: {p}" for p in found)
        except Exception as exc:  # noqa: BLE001 - a corrupt file is a finding
            problems.append(f"{label}: unreadable ({type(exc).__name__})")

    for link in _symlinks(root):
        # `is_file()` and every open follow a link, so a file (or a whole directory) that lives
        # elsewhere would pass its hash and its database checks. A backup is regular files.
        problems.append(f"{link}: is a symbolic link; a backup holds regular files, and what "
                        "this points at is not part of the backup")

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

    attestation_records: dict[str, int] = {}
    _check_attestation_logs(root, problems, attestation_records)

    unchecked: list[str] = []
    manifest_path = root / MANIFEST_NAME
    manifest: dict[str, Any] | None = None
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict) or loaded.get("format") != MANIFEST_FORMAT:
                raise ValueError("unknown format")
            manifest = loaded
        except (OSError, ValueError) as exc:
            problems.append(f"{MANIFEST_NAME}: unreadable ({type(exc).__name__}: {exc})")
    else:
        unchecked.append(
            "no manifest (backup-manifest.json): this backup was taken by a build that did "
            "not write one, or is not a backup. Whatever is here is consistent as far as it "
            "can be read, but nothing says that no ledger or file is missing.")
    if manifest is not None:
        _check_manifest(root, manifest, known, allow_growth, problems)

    if manifest is not None and manifest.get("degraded"):
        found = manifest.get("source_findings")
        problems.extend(f"taken from a damaged source: {p}" for p in
                        (found if isinstance(found, list) and found else ["(no detail recorded)"]))
    if live_dir is not None:
        _check_lineage(root, live_dir, problems)

    not_established = [
        "That nothing was removed by someone who also rewrote the manifest and the "
        "attestation log: the manifest holds checksums, not signatures. Keep the "
        "manifest_sha256 that `backup` printed somewhere else.",
        "That an attestation log's records are genuine: the signing key is not in a "
        "backup. `assurance attest verify --ledger` with the public key does that.",
        "That this backup is recent: the files carry no proof of when they were taken.",
    ]
    bare = sorted(
        rel for rel in _ledger_files(root) if rel.startswith("tenants/")
        and not any(r.basis is AttestationBasis.READ_FROM_LEDGER
                    for r in _safe_records(root / "attestations" / f"{Path(rel).stem}.jsonl")))
    if bare:
        not_established.append(
            "A ledger with no attestation log cannot be shown complete: a hash chain "
            "verifies after records are removed from its end. No attestation log covers "
            + ", ".join(bare[:5]) + (" and others" if len(bare) > 5 else "") + ".")

    status = "failed" if problems else ("ok" if manifest is not None else "unchecked")
    return {
        "ok": status == "ok",
        "status": status,
        "checked": checked,
        "attestation_records": attestation_records,
        "problems": problems,
        "unchecked": unchecked,
        "not_established": not_established,
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(argv) == 3 and argv[0] == "backup":
            out = Path(argv[2])
            names = backup(Path(argv[1]), out)
            digest = _sha256(out / MANIFEST_NAME)
            degraded = bool(json.loads((out / MANIFEST_NAME).read_text()).get("degraded"))
            print(json.dumps({"backed_up": names, "manifest": MANIFEST_NAME,
                              "degraded": degraded,
                              "manifest_sha256": digest,
                              "note": "unclaimed checkout keys are not copied: re-issue after a "
                                      "restore"}, indent=2))
            return 1 if degraded else 0
        live = "--live" in argv
        rest = [a for a in argv if a != "--live"]
        live_dir: Path | None = None
        if "--against-live" in rest:
            k = rest.index("--against-live")
            if k + 1 >= len(rest):
                print(__doc__, file=sys.stderr)
                return 2
            live_dir = Path(rest[k + 1])
            del rest[k:k + 2]
        if len(rest) == 2 and rest[0] == "verify":
            result = verify(Path(rest[1]), allow_growth=live, live_dir=live_dir)
            print(json.dumps(result, indent=2))
            return {"ok": 0, "failed": 1}.get(str(result["status"]), 3)
    except (OSError, sqlite3.Error) as exc:
        print(f"could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
