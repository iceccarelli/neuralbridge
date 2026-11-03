"""``restore_check verify`` is read-only: it leaves the directory it checks exactly as found.

Issue #80: on a volume the real service had opened (SQLite in WAL mode) ``verify`` created
``accounts.db-wal`` / ``-shm`` beside the database, then listed them as "not in the manifest"
and exited 1 on a healthy volume. The contract asserted here, byte for byte: after ``verify``
(strict and ``--live``) the directory has the same names, sizes, mtimes (ns), modes and SHA-256
as before, whether the outcome is ok or a finding; sidecars of a LISTED database are not
"added files"; every real finding still fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from assurance.billing.accounts import AccountStore
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger, restore_check

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


def snapshot(root: Path) -> dict[str, tuple]:
    """Everything observable about a tree: names (files, dirs, links), sizes, mtimes, modes,
    sha256 of every file."""
    out: dict[str, tuple] = {".": (root.stat().st_mtime_ns, root.stat().st_mode)}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""
        out[p.relative_to(root).as_posix()] = (st.st_size, st.st_mtime_ns, st.st_mode, digest)
    return out


@pytest.fixture()
def volume(tmp_path):
    """A backed-up volume: accounts.db, operator ledger, two tenant ledgers. Returns
    (restored directory, account ids)."""
    src = tmp_path / "data"
    (src / "tenants").mkdir(parents=True)
    store = AccountStore(src / "accounts.db")
    ids = [store.upsert_account(email=f"{n}@x.invalid", tier="cell").id for n in "ab"]
    for acct, count in zip(ids, (4, 2), strict=True):
        led = EvidenceLedger(src / "tenants" / f"{acct}.db")
        for i in range(count):
            led.append(_ev(i), subject="CASE-1")
    EvidenceLedger(src / "art14-register.db").append(_ev(0))
    bk = tmp_path / "bk"
    restore_check.backup(src, bk)
    restored = tmp_path / "restored"
    shutil.copytree(bk, restored)
    for p in restored.rglob("*-[sw][ha][ml]"):
        p.unlink()          # a backup has no sidecars; the tests add them like the service does
    return restored, ids


def _service_opens(restored: Path, *, write_to_wal: bool = False) -> sqlite3.Connection:
    """What the real service leaves: accounts.db in WAL mode with -wal and -shm present, the
    connection still open. With ``write_to_wal`` a committed write sits in the -wal only."""
    db = sqlite3.connect(restored / "accounts.db", isolation_level=None)
    assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("SELECT count(*) FROM accounts").fetchone()
    if write_to_wal:
        db.execute("CREATE TABLE IF NOT EXISTS service_touch (n)")
        db.execute("INSERT INTO service_touch VALUES (1)")
    return db


def _rerecord(restored: Path, rel: str) -> None:
    """Re-record ``rel``'s size/sha256 in the manifest as it is on disk now. Switching a file
    to WAL (what the service does on first open) rewrites header bytes 18-19, so a strict
    comparison against the original manifest would rightly say "modified"; this isolates the
    sidecar behaviour under test from that."""
    path = restored / rel
    manifest_path = restored / restore_check.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    entry = manifest["files"][rel]
    entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    entry["size"] = path.stat().st_size
    manifest_path.write_text(json.dumps(manifest))


def _cli(args: list[str], cwd: Path, **kw):
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": SRC,
           "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run([sys.executable, "-m", "assurance.evidence.restore_check", *args],  # noqa: S603
                          cwd=cwd, env=env, text=True, capture_output=True, timeout=120,
                          check=False, **kw)
    body = json.loads(done.stdout) if done.stdout.startswith("{") else {}
    return done.returncode, body, done.stderr


# ---------------------------------------------------------------------------
# a healthy volume the service has opened passes, and nothing changes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("live", [False, True])
def test_verify_of_a_wal_volume_changes_nothing_and_passes(volume, live):
    restored, _ = volume
    db = _service_opens(restored)
    _rerecord(restored, "accounts.db")
    try:
        assert (restored / "accounts.db-wal").exists() and (restored / "accounts.db-shm").exists()
        before = snapshot(restored)
        result = restore_check.verify(restored, allow_growth=live)
        after = snapshot(restored)
    finally:
        db.close()
    assert after == before
    assert result["status"] == "ok", result["problems"]
    assert not any("accounts.db-" in p for p in result["problems"])


@pytest.mark.parametrize("flags", [[], ["--live"]])
def test_cli_verify_exit_zero_and_directory_untouched(volume, flags, tmp_path):
    restored, _ = volume
    db = _service_opens(restored)
    _rerecord(restored, "accounts.db")
    try:
        before = snapshot(restored)
        code, body, err = _cli(["verify", *flags, str(restored)], tmp_path)
        after = snapshot(restored)
    finally:
        db.close()
    assert code == 0, (body.get("problems"), err)
    assert after == before


def test_verify_on_a_volume_with_no_sidecars_does_not_create_any(volume):
    restored, _ = volume
    before = snapshot(restored)
    for live in (False, True):
        assert restore_check.verify(restored, allow_growth=live)["status"] == "ok"
    assert snapshot(restored) == before
    assert not list(restored.rglob("*-wal")) and not list(restored.rglob("*-shm"))


def test_verify_of_a_wal_mode_ledger_does_not_create_its_sidecars(volume):
    """A tenant ledger left in WAL mode by the service (the header says so) and no sidecars:
    opening it in place would create them; verify must not."""
    restored, ids = volume
    ledger = restored / "tenants" / f"{ids[0]}.db"
    c = sqlite3.connect(ledger)
    c.execute("PRAGMA journal_mode=WAL")
    c.close()                           # checkpoints and removes the sidecars on close
    assert not list(restored.rglob("*-wal"))
    assert ledger.read_bytes()[18:20] == b"\x02\x02"
    _rerecord(restored, f"tenants/{ids[0]}.db")
    before = snapshot(restored)
    result = restore_check.verify(restored)
    assert snapshot(restored) == before
    assert result["status"] == "ok", result["problems"]


# ---------------------------------------------------------------------------
# a -wal with content is read and said, not ignored and not claimed away
# ---------------------------------------------------------------------------
def test_uncheckpointed_wal_content_is_a_finding_in_strict_mode_and_a_note_under_live(volume):
    restored, _ = volume
    db = _service_opens(restored, write_to_wal=True)
    _rerecord(restored, "accounts.db")
    try:
        assert (restored / "accounts.db-wal").stat().st_size > 0
        before = snapshot(restored)
        strict = restore_check.verify(restored)
        live = restore_check.verify(restored, allow_growth=True)
        assert snapshot(restored) == before
    finally:
        db.close()
    assert strict["status"] == "failed"
    assert any("accounts.db-wal" in p and "manifest" in p for p in strict["problems"])
    assert "-wal" in strict["sidecars"]["accounts.db"]
    assert live["status"] == "ok", live["problems"]
    assert any("accounts.db" in n and "not covered by the manifest" in n
               for n in live["not_established"])


def test_content_that_is_only_in_the_wal_is_actually_read(volume):
    """A ledger record deleted in the WAL (never checkpointed) is a finding even though the
    main file still holds it: the checks run over what the next opener would see."""
    restored, ids = volume
    ledger = restored / "tenants" / f"{ids[0]}.db"
    db = sqlite3.connect(ledger, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("DELETE FROM chain WHERE seq=(SELECT MAX(seq) FROM chain)")
    try:
        main_hash = hashlib.sha256(ledger.read_bytes()).hexdigest()
        before = snapshot(restored)
        result = restore_check.verify(restored, allow_growth=True)
        assert snapshot(restored) == before
        assert hashlib.sha256(ledger.read_bytes()).hexdigest() == main_hash
    finally:
        db.close()
    assert result["status"] == "failed"
    assert any("removed since" in p for p in result["problems"])


# ---------------------------------------------------------------------------
# every real finding still fails, and still leaves the directory alone
# ---------------------------------------------------------------------------
def _fails(restored: Path, *, live: bool = False, needle: str = "") -> dict:
    before = snapshot(restored)
    result = restore_check.verify(restored, allow_growth=live)
    assert snapshot(restored) == before, "verify wrote while reporting a finding"
    assert result["status"] == "failed", result
    assert any(needle in p for p in result["problems"]), result["problems"]
    return result


def test_unlisted_non_sidecar_file_still_fails(volume):
    restored, _ = volume
    (restored / "stray.txt").write_text("x")
    _fails(restored, needle="stray.txt: not in the manifest")


def test_a_sidecar_of_an_unlisted_database_still_fails(volume):
    restored, _ = volume
    (restored / "other.db-wal").write_bytes(b"")
    _fails(restored, needle="other.db-wal: not in the manifest")


def test_a_sidecar_is_not_a_license_for_other_suffixes(volume):
    restored, _ = volume
    (restored / "accounts.db-backup").write_bytes(b"x")
    _fails(restored, needle="accounts.db-backup: not in the manifest")


def test_missing_ledger_still_fails(volume):
    restored, ids = volume
    (restored / "tenants" / f"{ids[1]}.db").unlink()
    _fails(restored, needle="missing")


def test_modified_ledger_file_still_fails(volume):
    restored, ids = volume
    path = restored / "tenants" / f"{ids[0]}.db"
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF
    path.write_bytes(bytes(data))
    _fails(restored, needle=f"tenants/{ids[0]}.db")


def test_truncated_ledger_file_still_fails(volume):
    restored, ids = volume
    path = restored / "tenants" / f"{ids[0]}.db"
    path.write_bytes(path.read_bytes()[:4096])
    _fails(restored, needle=f"tenants/{ids[0]}.db")


def test_shortened_ledger_still_fails_under_live(volume):
    restored, ids = volume
    c = sqlite3.connect(restored / "tenants" / f"{ids[0]}.db")
    c.execute("DELETE FROM chain WHERE seq=(SELECT MAX(seq) FROM chain)")
    c.commit()
    c.close()
    _fails(restored, live=True, needle="removed since")


def test_forked_ledger_still_fails_against_live(volume, tmp_path):
    restored, ids = volume
    live = tmp_path / "live"
    shutil.copytree(restored, live)
    # same ledger_id, a different record at a shared position
    c = sqlite3.connect(live / "tenants" / f"{ids[0]}.db")
    c.execute("UPDATE chain SET link_hash = 'f' || substr(link_hash, 2) WHERE seq = 1")
    c.commit()
    c.close()
    before, before_live = snapshot(restored), snapshot(live)
    result = restore_check.verify(restored, live_dir=live)
    assert snapshot(restored) == before and snapshot(live) == before_live
    assert any("forked" in p for p in result["problems"]), result["problems"]


def test_ledger_with_a_broken_chain_still_fails(volume):
    restored, ids = volume
    c = sqlite3.connect(restored / "tenants" / f"{ids[0]}.db")
    c.execute("UPDATE chain SET kind = kind || 'x' WHERE seq = 2")
    c.commit()
    c.close()
    before = snapshot(restored)
    result = restore_check.verify(restored, allow_growth=True)
    assert snapshot(restored) == before
    assert result["status"] == "failed"


def test_missing_attestation_target_still_fails(volume):
    from assurance.attest import AttestationLog, SigningKey, attest, head_of

    restored, ids = volume
    log_dir = restored / "attestations"
    log_dir.mkdir()
    attest(head_of(EvidenceLedger(restored / "tenants" / f"{ids[0]}.db", mint_id=False)),
           SigningKey.generate(), AttestationLog(log_dir / f"{ids[0]}.jsonl"), note="")
    (restored / "tenants" / f"{ids[0]}.db").unlink()
    _fails(restored, live=True, needle="which is missing")


# ---------------------------------------------------------------------------
# a directory the process cannot write to
# ---------------------------------------------------------------------------
def test_verify_works_on_a_directory_its_process_cannot_write(volume):
    """Real permissions, not a mock: every directory 0555 and file 0444, and the process runs
    as an unprivileged user (root ignores mode bits, so as root the CLI is run as uid 65534)."""
    restored, _ = volume
    root = Path(tempfile.mkdtemp(prefix="nb-ro-"))
    try:
        target = root / "vol"
        shutil.copytree(restored, target)
        os.chmod(root, 0o755)  # noqa: S103
        for p in [target, *target.rglob("*")]:
            os.chmod(p, 0o555 if p.is_dir() else 0o444)
        unprivileged = {"user": 65534, "group": 65534} if os.geteuid() == 0 else {}
        if unprivileged:
            probe = subprocess.run(  # noqa: S603
                [sys.executable, "-c", f"open({str(target / 'probe')!r}, 'w')"],
                capture_output=True, check=False, **unprivileged)
            assert probe.returncode != 0, "the directory is writable by the test user"
        before = snapshot(target)
        for flags in ([], ["--live"]):
            code, body, err = _cli(["verify", *flags, str(target)], root, **unprivileged)
            assert code == 0, (body.get("problems"), err)
        assert snapshot(target) == before
    finally:
        for p in [root, *root.rglob("*")]:
            if not p.is_symlink():
                os.chmod(p, 0o755 if p.is_dir() else 0o644)
        shutil.rmtree(root, ignore_errors=True)
