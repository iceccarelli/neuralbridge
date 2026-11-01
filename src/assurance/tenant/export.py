"""Export one account's data into a self-describing directory, and verify such a directory.

``export`` writes, into a NEW empty ``0700`` directory (files ``0600``):

    ledger.db            transactionally consistent snapshot of the account's ledger
    evidence-bundle.json the whole ledger as a verifiable export bundle (``evidence verify``)
    attestations.jsonl   the account's signed attestation log, if it has one
    VERIFY.txt           how a third party checks all of it with no access to this system
    MANIFEST.json        account, ledger id, record count, head hash, sha256 + size of every
                         file, time, actor, the verify result, and what is NOT included and
                         what the export does NOT establish

The chain is verified in full first. A broken chain is refused unless ``accept_damaged``; then
the snapshot is kept (it is the evidence of the damage), no bundle is written (a bundle
asserts a verified chain) and the manifest says so in ``verify`` and ``accept_damaged``.

Nothing from outside the account is read: no accounts store (so no API keys, hashes or billing
identifiers), no other tenant, not the operator ledger, no key material.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from assurance.attest.attestation import AttestationLog
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import GENESIS, EvidenceLedger
from assurance.evidence.verify_export import verify_export_file
from assurance.tenant.layout import TenantError, account_files, plain_file, sha256_file

__all__ = ["MANIFEST_NAME", "MANIFEST_FORMAT", "NOT_INCLUDED", "DOES_NOT_ESTABLISH",
           "export_account", "verify_export_dir", "load_manifest"]

MANIFEST_NAME = "MANIFEST.json"
MANIFEST_FORMAT = "neuralbridge-tenant-export/1"
LEDGER_FILE = "ledger.db"
BUNDLE_FILE = "evidence-bundle.json"
LOG_FILE = "attestations.jsonl"
VERIFY_FILE = "VERIFY.txt"

NOT_INCLUDED = (
    "API keys and their hashes (the accounts store is never opened)",
    "billing and Stripe identifiers, subscription state and usage counters",
    "any other tenant's ledger or attestation log",
    "the operator's shared ledger",
    "the service's private signing key (only signatures made with it are in the log)",
    "supplier feeds and any other file outside the ledger and the attestation log",
)

DOES_NOT_ESTABLISH = (
    "that the records are true: an export shows what the ledger held when it was taken, not "
    "that what was written into it was correct",
    "that the ledger is complete beyond its newest signed anchor: records removed before that "
    "were never anchored cannot be detected, and a hash chain alone does not show removal",
    "who exported it, beyond the actor name given on the command line",
    "that no other copy exists: backups, replicas and earlier exports are outside this tool",
)

_VERIFY_TEXT = """\
How to check this export without access to the system that produced it
=======================================================================

1. Re-hash every file against MANIFEST.json:
       python -m assurance tenant verify-export <this directory>
   Exit 0 = every file matches and the copied ledger's hash chain verifies; 1 = a mismatch or
   a damaged chain; 3 = no manifest, nothing could be checked. (A reader without this software
   can run `sha256sum` on each file and compare with the manifest.)

2. Verify the evidence bundle on its own, offline:
       python -m assurance evidence verify evidence-bundle.json
   To check it is not SHORTER than what the service signed, also supply the signer's PUBLIC key
   (obtained from the operator separately, never from this directory) and the signed log:
       python -m assurance evidence verify evidence-bundle.json \\
           --attestations attestations.jsonl --public-key service.pub
   Only a head the service READ from the ledger and that covers the last record is a pass; a
   weaker result exits 3.

3. For a ledger opened as an Article 14 register:
       python -m assurance art14 verify --ledger ledger.db \\
           --attestations attestations.jsonl --public-key service.pub

What this does not show: that the records are true, or that nothing was removed after the
newest signed anchor. See "does_not_establish" in MANIFEST.json.
"""


def load_manifest(directory: Path) -> tuple[dict[str, Any], str]:
    """``(manifest, sha256 of MANIFEST.json)``. Raises ``TenantError`` when unusable."""
    path = directory / MANIFEST_NAME
    if not plain_file(path):
        raise TenantError(f"{path} does not exist", exit_code=3)
    digest, _size = sha256_file(path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise TenantError(f"{MANIFEST_NAME} cannot be read as JSON ({type(exc).__name__})") \
            from exc
    if not isinstance(doc, dict) or doc.get("format") != MANIFEST_FORMAT:
        raise TenantError(f"{MANIFEST_NAME} is not a {MANIFEST_FORMAT} manifest")
    return doc, digest


# --------------------------------------------------------------------------------------------
@contextmanager
def _scratch_copy(src: Path) -> Iterator[Path]:
    """A private temporary copy of one ledger file, so opening it (which sets WAL mode and so
    rewrites the header) never changes the bytes that were hashed."""
    work = Path(tempfile.mkdtemp(prefix="tenant-verify-"))
    try:
        os.chmod(work, 0o700)
        dest = work / "ledger.db"
        shutil.copyfile(src, dest)
        yield dest
    finally:
        shutil.rmtree(work, ignore_errors=True)


def inspect_ledger(path: Path, *, want_bundle: bool = False) -> dict[str, Any]:
    """Verify the chain of a COPY of *path* and describe it. Never raises on damage."""
    out: dict[str, Any] = {"verified": False, "problems": [], "record_count": None,
                           "head_seq": None, "head_hash": None, "ledger_id": None,
                           "bundle": None}
    with _scratch_copy(path) as copy:
        try:
            ledger = EvidenceLedger(copy, mint_id=False)
            ok, problems = ledger.verify_chain()
            out["verified"], out["problems"] = ok, list(problems)[:20]
            entries = ledger.entries()
            out["record_count"] = len(entries)
            out["head_seq"] = entries[-1].seq if entries else 0
            out["head_hash"] = entries[-1].link_hash if entries else GENESIS
            out["ledger_id"] = ledger.ledger_id()
            if ok and want_bundle:
                out["bundle"] = ledger.export()
        except (sqlite3.DatabaseError, ValueError) as exc:
            out["verified"] = False
            out["problems"].append(f"the ledger cannot be read ({type(exc).__name__}: {exc})")
    return out


def live_head(path: Path) -> tuple[int, str]:
    """``(record count, head link hash)`` of a live ledger. Raises ``TenantError`` on damage."""
    try:
        entries = EvidenceLedger(path, mint_id=False).entries()
    except (sqlite3.DatabaseError, ValueError) as exc:
        raise TenantError(f"the live ledger cannot be read ({type(exc).__name__}); it is "
                          "damaged. Nothing was changed.") from exc
    return len(entries), (entries[-1].link_hash if entries else GENESIS)


def _create_private_file(path: Path) -> None:
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    os.chmod(path, 0o600)


def _write_private(path: Path, data: bytes) -> None:
    _create_private_file(path)
    with path.open("wb") as handle:
        handle.write(data)


def _prepare_out(out: Path, files_dirs: tuple[Path, ...]) -> bool:
    """Validate the destination. Returns whether it has to be created."""
    if out.is_symlink():
        raise TenantError(f"{out} is a symbolic link; refusing to write through it.", exit_code=2)
    real = Path(os.path.realpath(out))
    for d in files_dirs:
        root = Path(os.path.realpath(d))
        if real == root or root in real.parents:
            raise TenantError(f"{out} is inside the live data ({d}); name a directory elsewhere.",
                              exit_code=2)
    if out.exists():
        if not out.is_dir():
            raise TenantError(f"{out} exists and is not a directory.", exit_code=2)
        if any(out.iterdir()):
            raise TenantError(f"{out} is not empty. An export goes into a new, empty directory "
                              "so nothing is mixed with an earlier one.", exit_code=2)
        return False
    return True


def export_account(data_dir: str | Path, account_id: str, out: str | Path, *, actor: str,
                   accept_damaged: bool = False, lock_timeout: float = 10.0) -> dict[str, Any]:
    """Write the export; return the manifest. Raises ``TenantError`` (nothing written) to refuse."""
    if not actor or not actor.strip():
        raise TenantError("--actor is required: an export records who took it.", exit_code=2)
    files = account_files(data_dir, account_id)
    if not files.ledger_exists:
        raise TenantError(f"no ledger exists for {account_id} under {data_dir}. Nothing was "
                          "exported and none was created.")
    out_dir = Path(out)
    tenants = files.ledger.parent
    create = _prepare_out(out_dir, (tenants, files.log.parent))

    try:
        live = EvidenceLedger(files.ledger, mint_id=False)
        live_ok, live_problems = live.verify_chain()
    except (sqlite3.DatabaseError, ValueError) as exc:
        live_ok, live_problems = False, [f"the ledger cannot be read ({type(exc).__name__})"]
    if not live_ok and not accept_damaged:
        raise TenantError(
            f"the chain of {account_id} does not verify; nothing was exported:\n  "
            + "\n  ".join(live_problems[:5])
            + "\nRe-run with --accept-damaged to keep a record of the damaged state; the "
              "manifest will say so.")

    created: list[Path] = []
    try:
        if create:
            out_dir.mkdir(parents=True)
        os.chmod(out_dir, 0o700)
        ledger_copy = out_dir / LEDGER_FILE
        _create_private_file(ledger_copy)
        created.append(ledger_copy)
        try:
            live.snapshot_to(ledger_copy)
            conn = sqlite3.connect(ledger_copy)
            try:
                conn.execute("PRAGMA journal_mode=DELETE")
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise TenantError(f"the ledger could not be snapshotted ({type(exc).__name__}: "
                              f"{exc}); nothing was exported.", exit_code=2) from exc
        os.chmod(ledger_copy, 0o600)

        log_records: int | None = None
        if files.log_exists:
            log = AttestationLog(files.log, label=f"the attestation log for {account_id}")
            with log.locked(timeout=lock_timeout):
                data = files.log.read_bytes()
            _write_private(out_dir / LOG_FILE, data)
            created.append(out_dir / LOG_FILE)
            log_records = sum(1 for line in data.splitlines() if line.strip())

        facts = inspect_ledger(ledger_copy, want_bundle=True)
        if not facts["verified"] and not accept_damaged:
            raise TenantError("the snapshot does not verify (the ledger changed while it was "
                              "copied); nothing was exported. Retry.")
        if facts["bundle"] is not None:
            _write_private(out_dir / BUNDLE_FILE, json.dumps(
                facts["bundle"], indent=2, sort_keys=True).encode("utf-8"))
            created.append(out_dir / BUNDLE_FILE)
        _write_private(out_dir / VERIFY_FILE, _VERIFY_TEXT.encode("utf-8"))
        created.append(out_dir / VERIFY_FILE)

        manifest = _manifest(account_id, facts, out_dir, actor, accept_damaged,
                             has_bundle=facts["bundle"] is not None, log_records=log_records)
        _write_private(out_dir / MANIFEST_NAME, (json.dumps(
            manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        return manifest
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        (out_dir / MANIFEST_NAME).unlink(missing_ok=True)
        if create:
            try:
                out_dir.rmdir()
            except OSError:
                pass
        raise


def _manifest(account_id: str, facts: dict[str, Any], out_dir: Path, actor: str,
              accept_damaged: bool, *, has_bundle: bool, log_records: int | None) -> dict[str, Any]:
    names = [(LEDGER_FILE, "ledger snapshot")]
    if has_bundle:
        names.append((BUNDLE_FILE, "evidence export bundle"))
    if log_records is not None:
        names.append((LOG_FILE, "attestation log"))
    names.append((VERIFY_FILE, "verification instructions"))
    entries = []
    for name, role in names:
        digest, size = sha256_file(out_dir / name)
        entries.append({"name": name, "role": role, "size": size, "sha256": digest})
    damaged = not facts["verified"]
    return {
        "format": MANIFEST_FORMAT,
        "account_id": account_id,
        "ledger_id": facts["ledger_id"],
        "record_count": facts["record_count"],
        "head_seq": facts["head_seq"],
        "head_hash": facts["head_hash"],
        "exported_at": format_utc(utc_now()),
        "actor": actor.strip(),
        "accept_damaged": bool(accept_damaged),
        "verify": {
            "status": "damaged_accepted" if damaged else "verified",
            "chain_verified": not damaged,
            "problems": facts["problems"],
            "evidence_bundle": ("written" if has_bundle else
                                "NOT written: a bundle asserts a verified chain and this one "
                                "does not verify"),
            "completeness": "not_checked",
        },
        "attestation_log": {"included": log_records is not None, "records": log_records},
        "files": entries,
        "not_included": list(NOT_INCLUDED),
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }


# --------------------------------------------------------------------------------------------
def verify_export_dir(directory: str | Path) -> dict[str, Any]:
    """Check an export directory. ``exit_code``: 0 ok, 1 mismatch or damaged, 2 unusable,
    3 unchecked (no manifest). Writes nothing."""
    root = Path(directory)
    result: dict[str, Any] = {"directory": str(root), "status": "failed", "exit_code": 1,
                              "problems": [], "checked": [], "account_id": None,
                              "head_hash": None, "record_count": None,
                              "manifest_sha256": None,
                              "not_established": list(DOES_NOT_ESTABLISH)}
    if root.is_symlink() or not root.is_dir():
        result.update(status="unusable", exit_code=2,
                      problems=[f"{root} is not a directory (or is a symbolic link)"])
        return result
    try:
        manifest, digest = load_manifest(root)
    except TenantError as exc:
        if exc.exit_code == 3:
            result.update(status="unchecked", exit_code=3,
                          problems=["there is no MANIFEST.json: nothing says what should be "
                                    "here, so nothing was checked"])
        else:
            result["problems"].append(str(exc))
        return result
    problems: list[str] = result["problems"]
    result.update(manifest_sha256=digest, account_id=manifest.get("account_id"),
                  head_hash=manifest.get("head_hash"), record_count=manifest.get("record_count"))
    listed: set[str] = set()
    for item in manifest.get("files", []) if isinstance(manifest.get("files"), list) else []:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name or "/" in name or "\\" in name \
                or name in (".", "..", MANIFEST_NAME):
            problems.append(f"manifest lists an unsafe file name {name!r}")
            continue
        listed.add(name)
        path = root / name
        try:
            present = plain_file(path)
        except TenantError as exc:
            problems.append(str(exc))
            continue
        if not present:
            problems.append(f"{name}: listed in the manifest but missing")
            continue
        sha, size = sha256_file(path)
        if size != item.get("size") or sha != item.get("sha256"):
            problems.append(f"{name}: does not match the manifest (size or sha256 differs)")
        else:
            result["checked"].append(name)
    for entry in sorted(os.listdir(root)):
        if entry != MANIFEST_NAME and entry not in listed:
            problems.append(f"{entry}: present but not listed in the manifest")
    if LEDGER_FILE not in listed:
        problems.append(f"{LEDGER_FILE} is not listed in the manifest")
    elif LEDGER_FILE in result["checked"]:
        facts = inspect_ledger(root / LEDGER_FILE)
        for key, label in (("record_count", "record count"), ("head_hash", "head hash"),
                           ("ledger_id", "ledger id")):
            if facts[key] != manifest.get(key):
                problems.append(f"the copied ledger's {label} differs from the manifest")
        declared = (manifest.get("verify") or {}).get("status")
        if facts["verified"]:
            if declared != "verified":
                problems.append("the manifest records a damaged chain but the ledger verifies")
        elif declared == "damaged_accepted" and not manifest.get("accept_damaged"):
            problems.append("the manifest records a damaged chain without accept_damaged")
        else:
            problems.append("the copied ledger's hash chain does NOT verify: "
                            + "; ".join(facts["problems"][:3]))
        if BUNDLE_FILE in result["checked"]:
            bundle = verify_export_file(root / BUNDLE_FILE)
            problems.extend(f"{BUNDLE_FILE}: {p}" for p in bundle.problems)
    if problems:
        damaged_only = (manifest.get("accept_damaged") is True and len(problems) == 1
                        and problems[0].startswith("the copied ledger's hash chain does NOT"))
        result["status"] = "damaged_accepted" if damaged_only else "failed"
        result["exit_code"] = 1
        return result
    result.update(status="ok", exit_code=0)
    return result
