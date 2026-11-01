"""``ops check``: a preflight of the configuration, before the first cycle and after any change.

It inspects files and the filesystem only. It writes nothing, opens no socket, needs no
Postgres, and does not run a step. Its report always lists what it did NOT check: a green
preflight says the configuration is usable, not that the operation is sound.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any

from assurance.ops.config import OpsConfig

__all__ = ["NOT_CHECKED", "run_check"]

NOT_CHECKED = (
    "That a scheduler (cron, a systemd timer, a loop container) is installed and enabled. "
    "`ops status` going stale is the only signal of a timer that stopped.",
    "Key custody: where the private key is stored, who can read it, whether it was copied. "
    "Only the file's mode and that it sits outside the data directory are checked.",
    "Off-box backup. Backups are written under backup_dir on this host; a second copy elsewhere "
    "(and the manifest hash stored apart from it) is the operator's to arrange and to prove.",
    "That a restore works. Only a RESTORE DRILL shows that (OPS.md, section 4).",
    "That any source host is reachable or that an API key is valid: no network is used here.",
    "That a watch config describes the real fleet, or that its ledger is the one a case would "
    "be opened in.",
    "Backup retention: nothing prunes old backups; free disk is checked once, now.",
    "The clock of this host, which every timestamp in the cycle record depends on.",
    "The hosted API process itself (this does not call it), and Postgres (not required).",
)


def _nearest_existing(path: Path) -> Path:
    p = path.resolve() if path.exists() else path.absolute()
    while not p.exists() and p != p.parent:
        p = p.parent
    return p


def _tree_bytes(root: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def run_check(cfg: OpsConfig) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    # -- the data directory ------------------------------------------------------------------
    data = cfg.data_dir
    if not data.is_dir():
        add("data_dir", "fail", f"{data} is not a directory")
    else:
        add("data_dir", "ok", f"{data} exists")
        try:
            from assurance.attest.anchor_all import layout

            tenants, _ = layout(data)
            add("data_dir.layout", "ok", "tenants/ and attestations/ resolve inside the data "
                "directory (no symbolic link)")
        except (ValueError, OSError) as exc:
            tenants = data / "tenants"
            add("data_dir.layout", "fail", str(exc))
        if tenants.is_dir():
            import re

            odd = [p.name for p in tenants.iterdir()
                   if not re.fullmatch(r"acc_[0-9a-f]{16}\.db(-wal|-shm|-journal)?", p.name)]
            n = len([p for p in tenants.iterdir() if re.fullmatch(r"acc_[0-9a-f]{16}\.db", p.name)])
            add("data_dir.tenants", "warn" if odd else "ok",
                f"{n} tenant ledger(s)" + (f"; {len(odd)} file(s) not named acc_<16 hex>.db "
                                           "(anchor-all will not touch them)" if odd else ""))
        else:
            add("data_dir.tenants", "info", "no tenants/ directory yet (no hosted account has "
                "written a ledger)")
        for name, why in (("accounts.db", "backup verify cannot check that tenant ledgers "
                           "belong to known accounts without it"),
                          ("art14-register.db", "no operator ledger yet")):
            add(f"data_dir.{name}", "ok" if (data / name).is_file() else "info",
                "present" if (data / name).is_file() else f"absent: {why}")

    # -- watch -------------------------------------------------------------------------------
    if not cfg.watch:
        add("watch", "info", "no watch is configured: the cycle's watch step is skipped")
    for i, w in enumerate(cfg.watch):
        label = f"watch[{i}]"
        try:
            from assurance.watch.config import WatchConfig

            WatchConfig.from_json(w.config)
            add(f"{label}.config", "ok", f"{w.config.name} loads")
        except Exception as exc:  # noqa: BLE001
            add(f"{label}.config", "fail", f"{w.config.name}: {type(exc).__name__}: "
                f"{str(exc)[:160]}")
        if not w.ledger.parent.is_dir():
            add(f"{label}.ledger", "fail", f"the directory for {w.ledger.name} does not exist")
        elif w.ledger.exists() and not os.access(w.ledger, os.R_OK | os.W_OK):
            add(f"{label}.ledger", "fail", f"{w.ledger.name} is not readable and writable")
        elif not w.ledger.exists() and not os.access(w.ledger.parent, os.W_OK):
            add(f"{label}.ledger", "fail", f"{w.ledger.name} cannot be created here")
        else:
            add(f"{label}.ledger", "ok", f"{w.ledger.name}: usable")

    # -- intel -------------------------------------------------------------------------------
    if cfg.intel is None or not cfg.intel.sources:
        add("intel", "info", "no intel sources configured: the store is not refreshed by the "
            "cycle (a watch with max_age_hours will report it stale)")
    else:
        i = cfg.intel
        add("intel.store", "ok" if i.store.exists() else "warn",
            f"{i.store.name} " + ("exists" if i.store.exists() else
                                  "does not exist yet; the first live refresh creates it"))
        if not i.store.parent.is_dir():
            add("intel.store_dir", "fail", "the store's directory does not exist")
        add("intel.live", "info", (
            "config live: true, so a cycle refreshes only when also given --live" if i.live else
            "config live: false: every cycle skips the refresh ('not refreshed')"))
        for s in i.sources:
            if s.api_key_env:
                add(f"intel.{s.source}.api_key_env", "ok" if os.environ.get(s.api_key_env)
                    else "info", f"${s.api_key_env} is "
                    f"{'set' if os.environ.get(s.api_key_env) else 'not set'} in this "
                    "environment (the value is never read into the record)")

    # -- attest key --------------------------------------------------------------------------
    if cfg.attest is None:
        add("attest", "info", "no key path configured: the cycle skips anchor-all and says so")
    else:
        from assurance.attest.preflight import run_preflight

        env: dict[str, str] = {}
        if cfg.attest.passphrase_env and os.environ.get(cfg.attest.passphrase_env):
            env["ASSURANCE_ATTEST_PASSPHRASE"] = os.environ[cfg.attest.passphrase_env]
        report = run_preflight(env, key_file=cfg.attest.key)
        for c in report.checks:
            if c.name.startswith("key."):
                add(f"attest.{c.name}", c.status, c.detail)
        if data.is_dir() and _inside(cfg.attest.key.parent, data):
            add("attest.key_apart_from_data", "fail", "the key file sits inside the data "
                "directory it signs for; anchor-all would refuse it")
        elif data.is_dir():
            add("attest.key_apart_from_data", "ok", "the key file is outside the data directory")

    # -- backup, disk, record ----------------------------------------------------------------
    bdir = cfg.backup_dir
    anc = _nearest_existing(bdir)
    if data.is_dir() and _inside(bdir, data):
        add("backup_dir", "fail", "the backup directory is inside the data directory")
    elif not os.access(anc, os.W_OK | os.X_OK):
        add("backup_dir", "fail", f"{bdir} cannot be created or written ({anc} is not writable)")
    else:
        add("backup_dir", "ok", f"{bdir} " + ("exists and is writable" if bdir.is_dir()
                                              else "will be created (parent is writable)"))
    if data.is_dir():
        try:
            need = max(cfg.min_free_disk_mb * 1024 * 1024, 2 * _tree_bytes(data))
            free = shutil.disk_usage(anc).free
            same = os.stat(anc).st_dev == os.stat(data).st_dev
            add("disk.free", "ok" if free >= need else "fail",
                f"{free // (1024 * 1024)} MiB free where backups go; one cycle needs at least "
                f"{int(need) // (1024 * 1024)} MiB (the larger of min_free_disk_mb and twice "
                "the data size)")
            add("backup.same_filesystem", "warn" if same else "info", (
                "backups are on the same filesystem as the data: one disk failure loses both"
                if same else "backups are on a different filesystem from the data"))
        except OSError as exc:
            add("disk.free", "fail", f"could not measure free space ({type(exc).__name__})")
    rec_anc = _nearest_existing(cfg.record.parent)
    if not os.access(rec_anc, os.W_OK | os.X_OK) or (
            cfg.record.exists() and not os.access(cfg.record, os.W_OK)):
        add("record", "fail", f"{cfg.record} cannot be written")
    else:
        add("record", "ok", f"{cfg.record.name} can be appended to")
    if cfg.record.exists():
        mode = stat.S_IMODE(cfg.record.stat().st_mode)
        if mode & 0o022:
            add("record.mode", "warn", f"the cycle record is writable by group/other "
                f"(mode {mode:04o}); anyone who can write it can rewrite the history")
    lock_anc = _nearest_existing(cfg.lock.parent)
    add("lock", "ok" if os.access(lock_anc, os.W_OK | os.X_OK) else "fail",
        f"{cfg.lock.name} " + ("can be created" if os.access(lock_anc, os.W_OK | os.X_OK)
                               else "cannot be created"))
    if os.name != "posix":
        add("platform", "fail", "the cycle lock uses flock and needs a POSIX host")
    add("postgres", "info", "Postgres is not required by the cycle and was not checked")

    failed = [c for c in checks if c["status"] == "fail"]
    return {"ok": not failed, "checks": checks, "not_checked": list(NOT_CHECKED),
            "note": "This inspected configuration and the filesystem only. Nothing was run, "
                    "signed, backed up or changed."}
