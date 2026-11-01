"""``assurance ops``: one auditable cycle of the unattended steps, a status, a preflight.

Real ledgers, real throwaway Ed25519 keys, the real ``attest anchor-all`` and ``restore_check``,
the real ``watch run`` over the recorded/synthetic intel fixtures. Subprocess runs start with a
``sitecustomize`` that makes any socket connect raise, so "the intel step was skipped" is also
"nothing opened a socket". The one networked step (``intel refresh --live``) is exercised only
through a contract-fixture transport and is NOT live integration.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import sqlite3
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.attest import SigningKey
from assurance.billing.accounts import AccountStore
from assurance.capabilities import discover_cli
from assurance.cli import main as assurance_main
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger, restore_check
from assurance.ops import record as rec
from assurance.ops.config import OpsConfigError, load_config

from .intel_support import Clock, ContractFixtureTransport, kev_doc
from .test_assurance_watch_intel import CVE, _fill, _plant

pytestmark = pytest.mark.skipif(os.name != "posix", reason="flock and file modes are POSIX")

SRC = str(Path(__file__).resolve().parents[1] / "src")
ROOT = Path(__file__).resolve().parents[1]
OPS_DIR = ROOT / "deploy" / "assurance" / "ops"
FAKE_PASSPHRASE = "ZZ-FAKE-PASSPHRASE-7f3a91"
FAKE_API_KEY = "ZZ-FAKE-NVD-API-KEY-55d0c2"

_GUARD = textwrap.dedent('''
    # SYNTHETIC test guard: this process may not touch a network.
    import socket

    def _refuse(*args, **kwargs):
        raise OSError("NO NETWORK in this scenario: a socket was opened")

    socket.socket.connect = _refuse
    socket.socket.connect_ex = _refuse
    socket.create_connection = _refuse
    socket.getaddrinfo = _refuse
''')


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


class Site:
    """A plant, a hosted data directory, a signing key kept outside it, and an ops.json."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        plant = _plant(root)                     # watch.json, plans, exports, intel.db, ev.db
        _fill(plant["store"])
        self.data = root / "data"
        self.data.mkdir()
        store = AccountStore(self.data / "accounts.db")
        self.accounts = [store.upsert_account(email=f"{n}@x.invalid", tier="cell",
                                              stripe_customer_id=f"cus_{n}").id
                         for n in ("a", "b")]
        (self.data / "tenants").mkdir()
        for acct in self.accounts:
            led = EvidenceLedger(self.data / "tenants" / f"{acct}.db")
            for i in range(3):
                led.append(_ev(i), subject="CASE-1")
        EvidenceLedger(self.data / "art14-register.db").append(_ev(0))
        self.keydir = root.parent / f"{root.name}-keys"
        self.keydir.mkdir()
        self.key = self.keydir / "service.pem"
        SigningKey.generate().save(self.key)
        self.cfg_path = root / "ops.json"
        self.cfg = {
            "ops_id": "test-ops", "data_dir": "data", "record": "ops/cycles.jsonl",
            "backup_dir": "backups", "max_cycle_age_hours": 26,
            "intel": {"live": False, "store": "intel.db",
                      "sources": [{"source": "kev"}]},
            "watch": [{"config": "watch.json", "ledger": "ev.db"}],
            "attest": {"key": str(self.key), "max_age_hours": 24},
        }
        self.write()

    def write(self) -> Path:
        self.cfg_path.write_text(json.dumps(self.cfg), encoding="utf-8")
        return self.cfg_path

    @property
    def record(self) -> Path:
        return self.root / "ops" / "cycles.jsonl"

    def cycles(self) -> list[dict]:
        return rec.read(self.record).cycles

    def env(self, guard: Path | None = None, **extra: str) -> dict[str, str]:
        parts = ([str(guard)] if guard else []) + [SRC]
        return {"PYTHONPATH": os.pathsep.join(parts), "PYTHONDONTWRITEBYTECODE": "1",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"), **extra}

    def sh(self, *argv: object, guard: Path | None = None,
           **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "assurance", *map(str, argv)], capture_output=True,
            text=True, cwd=self.root, env=self.env(guard, **env), check=False)

    def tree(self) -> list[tuple[str, int, int]]:
        return sorted((str(p.relative_to(self.root)), p.stat().st_size, p.stat().st_mtime_ns)
                      for p in self.root.rglob("*") if p.is_file())


@pytest.fixture()
def site(tmp_path):
    return Site(tmp_path / "site")


def _guard(tmp_path: Path) -> Path:
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(_GUARD, encoding="utf-8")
    return guard


def _by_name(doc: dict) -> dict[str, dict]:
    return {s["name"]: s for s in doc["steps"]}


def _cycle(site: Site, capsys, *flags: str) -> tuple[int, str, str]:
    capsys.readouterr()
    code = assurance_main(["ops", "cycle", "--config", str(site.cfg_path), *flags])
    out = capsys.readouterr()
    return code, out.out, out.err


def _break_chain(site: Site) -> None:
    db = sqlite3.connect(site.data / "tenants" / f"{site.accounts[0]}.db")
    db.execute("UPDATE chain SET payload = replace(payload, 'engineer', 'intruder') "
               "WHERE seq = 1")
    db.commit()
    db.close()


def _old_record(site: Site, *, hours_ago: float, status: str = "ok", actions=()) -> None:
    done = datetime.now(UTC) - timedelta(hours=hours_ago)
    rec.append(site.record, {
        "format": rec.FORMAT, "ops_id": "test-ops",
        "started_at": done.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_at": done.strftime("%Y-%m-%dT%H:%M:%SZ"), "duration_s": 1.0,
        "live_requested": False, "status": status, "exit_code": {"ok": 0, "flagged": 1,
                                                                   "degraded": 2}[status],
        "steps": [], "human_actions": list(actions), "not_established": "x"})


# ============================================================================================
# the whole cycle, as a subprocess with the network blocked
# ============================================================================================
def test_a_full_cycle_with_the_network_blocked(site, tmp_path):
    guard = _guard(tmp_path)
    r = site.sh("ops", "cycle", "--config", site.cfg_path, guard=guard)
    # the watch has a new finding for a person -> flagged, which is NOT a failure
    assert r.returncode == 1, r.stdout + r.stderr
    lines = site.record.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["format"] == rec.FORMAT and doc["status"] == "flagged" and doc["exit_code"] == 1
    for key in ("started_at", "finished_at"):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", doc[key])
    assert doc["started_at"] <= doc["finished_at"]
    # the real clock, not a fixed one
    assert abs((datetime.now(UTC) - datetime.strptime(
        doc["finished_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)).total_seconds()) < 300

    steps = _by_name(doc)
    assert list(steps) == ["intel.refresh:kev", "watch.run:watch.json", "ledger.verify",
                           "attest.anchor_all", "backup", "backup.verify"]
    s = steps["intel.refresh:kev"]
    assert s["status"] == "skipped" and "not refreshed" in s["detail"]
    assert "--live" in s["detail"] or "live: false" in s["detail"]
    assert steps["watch.run:watch.json"]["status"] == "flagged"
    assert steps["watch.run:watch.json"]["exit_code"] == 1
    assert steps["ledger.verify"]["status"] == "ok"
    assert steps["attest.anchor_all"]["status"] == "ok"
    assert steps["backup"]["status"] == "ok" and steps["backup.verify"]["status"] == "ok"
    for s in doc["steps"]:
        assert set(s) >= {"name", "command", "status", "exit_code", "duration_s", "detail"}
    assert "watch run" in steps["watch.run:watch.json"]["command"]
    assert "<configured key file>" in steps["attest.anchor_all"]["command"]
    assert str(site.key) not in lines[0]

    # a person is told what to read, derived from the finding
    actions = doc["human_actions"]
    assert any(CVE in a["action"] and a["step"] == "watch.run:watch.json" for a in actions)
    assert all("Nothing was opened" in a["action"] or "STOP-USE" in a["action"]
               or "awareness" in a["action"] or "machine" in a["action"] or "degraded" in
               a["action"] or "flagged" in a["action"] for a in actions)

    # anchors are present, and the backup really verifies when verified independently
    logs = sorted(p.name for p in (site.data / "attestations").glob("*.jsonl"))
    assert logs == sorted(f"{a}.jsonl" for a in site.accounts)
    backup = Path(steps["backup"]["info"]["directory"])
    assert backup.parent == site.root / "backups" and re.fullmatch(r"\d{8}T\d{6}Z", backup.name)
    assert restore_check.main(["verify", str(backup)]) == 0
    assert len(steps["backup"]["info"]["manifest_sha256"]) == 64


def test_exit_mapping_is_zero_quiet_one_flagged_two_degraded(site, capsys):
    code, _, _ = _cycle(site, capsys)
    assert code == 1                                     # first look: a finding for a person
    code, out, _ = _cycle(site, capsys)
    assert (code, site.cycles()[-1]["status"]) == (0, "ok")   # nothing moved since
    assert "HUMAN ACTIONS" not in out
    _break_chain(site)
    code, _, _ = _cycle(site, capsys)
    assert (code, site.cycles()[-1]["status"]) == (2, "degraded")


def test_the_record_is_append_only(site, capsys):
    _cycle(site, capsys)
    first = site.record.read_bytes()
    _cycle(site, capsys)
    after = site.record.read_bytes()
    assert after.startswith(first) and len(after) > len(first)
    assert len(after.splitlines()) == 2
    assert after.splitlines()[0] + b"\n" == first
    backups = sorted(p.name for p in (site.root / "backups").iterdir())
    assert len(backups) == 2                             # a new directory each cycle


def test_a_torn_last_line_is_kept_and_the_next_record_starts_on_its_own_line(site, capsys):
    site.record.parent.mkdir(parents=True)
    site.record.write_bytes(b'{"format": "neuralbridge-ops-cycle/1", "stat')
    _cycle(site, capsys)
    raw = site.record.read_bytes()
    assert raw.startswith(b'{"format": "neuralbridge-ops-cycle/1", "stat\n')
    got = rec.read(site.record)
    assert len(got.cycles) == 1 and got.unreadable_lines == [1]


# ============================================================================================
# preconditions, isolation, and a backup that must verify
# ============================================================================================
def test_a_broken_chain_degrades_the_cycle_skips_the_anchor_and_flags_the_backup(site, capsys):
    _break_chain(site)
    code, out, _ = _cycle(site, capsys)
    doc = site.cycles()[-1]
    steps = _by_name(doc)
    assert code == 2 and doc["status"] == "degraded"
    assert steps["ledger.verify"]["status"] == "failed"
    anchor = steps["attest.anchor_all"]
    assert anchor["status"] == "skipped" and "precondition ledger.verify failed" in anchor["detail"]
    assert not (site.data / "attestations").exists()     # nothing was anchored over the break
    assert steps["backup"]["status"] == "flagged"        # a damaged source is still kept
    assert steps["backup.verify"]["status"] == "flagged"
    assert "expected" in steps["backup.verify"]["detail"]
    # the other independent steps still ran
    assert steps["watch.run:watch.json"]["status"] in ("flagged", "ok")
    assert any(a["step"] == "ledger.verify" for a in doc["human_actions"])
    assert "HUMAN ACTIONS REQUIRED" in out


def test_a_backup_that_does_not_verify_fails_the_cycle(site, capsys, monkeypatch):
    real = restore_check.verify

    def fail(*a, **k):
        res = real(*a, **k)
        res["ok"], res["status"] = False, "failed"
        res["problems"] = ["tenants/x.db: modified since the backup was taken"]
        return res

    monkeypatch.setattr(restore_check, "verify", fail)
    code, _, _ = _cycle(site, capsys)
    doc = site.cycles()[-1]
    steps = _by_name(doc)
    assert code == 2 and doc["status"] == "degraded"
    assert steps["backup"]["status"] == "ok"
    assert steps["backup.verify"]["status"] == "failed"
    assert any(a["step"] == "backup.verify" and "does NOT verify" in a["action"]
               for a in doc["human_actions"])


def test_an_unchecked_backup_is_not_taken_as_verified(site, capsys, monkeypatch):
    monkeypatch.setattr(restore_check, "verify",
                        lambda *a, **k: {"status": "unchecked", "problems": [], "checked": 0})
    code, _, _ = _cycle(site, capsys)
    assert code == 2 and _by_name(site.cycles()[-1])["backup.verify"]["status"] == "failed"


def test_one_step_raising_is_recorded_and_the_rest_still_run(site, capsys, monkeypatch):
    import assurance.watch.cli as watch_cli

    def boom(argv):
        raise RuntimeError("watch exploded")

    monkeypatch.setattr(watch_cli, "main", boom)
    code, _, _ = _cycle(site, capsys)
    steps = _by_name(site.cycles()[-1])
    assert code == 2
    assert steps["watch.run:watch.json"]["status"] == "failed"
    assert "watch exploded" in steps["watch.run:watch.json"]["detail"]
    assert all(steps[n]["status"] == "ok"
               for n in ("ledger.verify", "attest.anchor_all", "backup", "backup.verify"))


def test_no_key_configured_means_anchor_is_skipped_and_says_so(site, capsys):
    del site.cfg["attest"]
    site.write()
    _cycle(site, capsys)
    s = _by_name(site.cycles()[-1])["attest.anchor_all"]
    assert s["status"] == "skipped" and "no attest key path is configured" in s["detail"]
    assert not (site.data / "attestations").exists()


def test_an_unusable_key_fails_the_anchor_step_but_not_the_backup(site, capsys):
    os.chmod(site.key, 0o644)
    code, _, _ = _cycle(site, capsys)
    steps = _by_name(site.cycles()[-1])
    assert code == 2 and steps["attest.anchor_all"]["status"] == "failed"
    assert steps["backup.verify"]["status"] == "ok"


# ============================================================================================
# the lock
# ============================================================================================
def test_a_second_cycle_is_refused_while_one_holds_the_lock(site, tmp_path):
    lock = site.root / "ops" / "cycles.jsonl.lock"
    lock.parent.mkdir(parents=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        before = site.tree()
        r = site.sh("ops", "cycle", "--config", site.cfg_path)
        assert r.returncode == 2 and "cycle already running" in r.stderr
        assert not site.record.exists() and not (site.root / "backups").exists()
        assert site.tree() == before                     # not a byte moved
    finally:
        os.close(fd)
    # released: the next one runs
    r = site.sh("ops", "cycle", "--config", site.cfg_path, guard=_guard(tmp_path))
    assert r.returncode in (0, 1) and len(site.cycles()) == 1


def test_the_lock_is_released_when_a_cycle_ends(site, capsys):
    _cycle(site, capsys)
    code, _, err = _cycle(site, capsys)
    assert code in (0, 1) and "already running" not in err


# ============================================================================================
# status
# ============================================================================================
def _status(site: Site, capsys, *flags: str) -> tuple[int, str]:
    capsys.readouterr()
    code = assurance_main(["ops", "status", "--config", str(site.cfg_path), *flags])
    return code, capsys.readouterr().out


def test_status_with_no_record_is_not_healthy(site, capsys):
    code, out = _status(site, capsys)
    assert code == 2 and "NO CYCLE RECORDED" in out


def test_status_fresh_ok_is_zero_and_stale_is_two(site, capsys):
    _old_record(site, hours_ago=1)
    assert _status(site, capsys)[0] == 0
    site.record.unlink()
    _old_record(site, hours_ago=27)                      # max_cycle_age_hours is 26
    code, out = _status(site, capsys)
    assert code == 2 and "STALE" in out
    code, out = _status(site, capsys, "--json")
    assert json.loads(out)["state"] == "stale"


def test_status_mirrors_the_last_cycles_status(site, capsys):
    _old_record(site, hours_ago=1, status="flagged")
    assert _status(site, capsys)[0] == 1
    _old_record(site, hours_ago=0.5, status="degraded")
    assert _status(site, capsys)[0] == 2


def test_status_lists_outstanding_human_actions_and_earlier_ones(site, capsys):
    a = {"step": "watch.run:watch.json", "ref": "nvd:CVE-2026-0001",
         "action": "read new finding nvd:CVE-2026-0001"}
    b = {"step": "backup", "ref": "d", "action": "the backup was taken from a failing source"}
    _old_record(site, hours_ago=3, status="flagged", actions=[a])
    _old_record(site, hours_ago=1, status="flagged", actions=[b])
    code, out = _status(site, capsys)
    assert code == 1
    assert "human actions raised by the last cycle: 1" in out and "failing source" in out
    assert "earlier cycles" in out and "nvd:CVE-2026-0001" in out
    assert "cannot show whether a person handled them" in out


def test_status_after_a_real_cycle(site, capsys):
    _cycle(site, capsys)
    code, out = _status(site, capsys, "--json")
    doc = json.loads(out)
    assert code == 1 and doc["state"] == "flagged" and doc["age_hours"] < 1
    assert doc["actions"]["this_cycle"]


# ============================================================================================
# no secret in the record or the output
# ============================================================================================
def _key_body(path: Path) -> list[str]:
    return [ln for ln in path.read_text().splitlines() if ln and not ln.startswith("-----")]


def test_scrub_removes_configured_secrets_pem_markers_and_long_base64():
    secrets = [FAKE_PASSPHRASE]
    out = rec.scrub({"a": f"x {FAKE_PASSPHRASE} y", "b": ["-----BEGIN PRIVATE KEY-----"],
                     "c": "Q" * 12 + "A1b2" * 12, "hash": "ab12" * 16,
                     "path": "/var/lib/assurance-ops/backups/20261101T061500Z"}, secrets)
    text = json.dumps(out)
    assert FAKE_PASSPHRASE not in text and "BEGIN" not in text and "A1b2A1b2" not in text
    assert out["hash"] == "ab12" * 16                    # a sha256 is not a secret
    assert out["path"].endswith("20261101T061500Z")


def test_secrets_never_reach_the_record_or_the_output(site, capsys, monkeypatch):
    import assurance.attest.cli as attest_cli

    body = _key_body(site.key)
    assert body
    site.cfg["attest"]["passphrase_env"] = "OPS_TEST_PASSPHRASE"
    site.cfg["intel"]["sources"] = [{"source": "kev", "api_key_env": "OPS_TEST_API_KEY"}]
    site.write()
    monkeypatch.setenv("OPS_TEST_PASSPHRASE", FAKE_PASSPHRASE)
    monkeypatch.setenv("OPS_TEST_API_KEY", FAKE_API_KEY)

    def leaky(argv):
        # a failure whose message carries every secret the cycle holds
        raise RuntimeError(f"bad key {body[0]} / {FAKE_PASSPHRASE} / {FAKE_API_KEY} "
                           f"-----BEGIN PRIVATE KEY-----")

    monkeypatch.setattr(attest_cli, "main", leaky)
    code, out, err = _cycle(site, capsys, "--json")
    assert code == 2
    everything = site.record.read_text() + out + err
    assert _by_name(site.cycles()[-1])["attest.anchor_all"]["status"] == "failed"
    for secret in (*body, FAKE_PASSPHRASE, FAKE_API_KEY, "BEGIN PRIVATE KEY"):
        assert secret not in everything, secret
    assert "[redacted]" in everything
    # the names of the variables are configuration and may appear; their values may not
    assert "--passphrase-env OPS_TEST_PASSPHRASE" in everything


def test_a_real_cycle_prints_no_key_material(site, tmp_path, monkeypatch):
    body = _key_body(site.key)
    r = site.sh("ops", "cycle", "--config", site.cfg_path, "--json", guard=_guard(tmp_path))
    everything = site.record.read_text() + r.stdout + r.stderr
    assert r.returncode == 1
    assert "PRIVATE KEY" not in everything
    assert all(line not in everything for line in body)
    c = site.sh("ops", "check", "--config", site.cfg_path)
    assert "PRIVATE KEY" not in c.stdout + c.stderr
    assert all(line not in c.stdout + c.stderr for line in body)


def test_a_secret_pasted_into_an_env_name_field_is_refused_without_being_shown(site, capsys):
    site.cfg["attest"]["passphrase_env"] = FAKE_PASSPHRASE + " with spaces!"
    site.write()
    before = site.tree()
    code, out, err = _cycle(site, capsys)
    assert code == 2 and "NAME of an environment variable" in err
    assert FAKE_PASSPHRASE not in out + err
    assert site.tree() == before


# ============================================================================================
# dry-run, config errors, and the intel gate
# ============================================================================================
def test_dry_run_writes_nothing_and_opens_no_lock(site, tmp_path, capsys):
    before = site.tree()
    code, out, _ = _cycle(site, capsys, "--dry-run")
    assert code == 0 and "DRY RUN" in out and "nothing was run" in out
    assert site.tree() == before
    assert not site.record.exists() and not (site.root / "backups").exists()
    assert not (site.root / "ops").exists()
    r = site.sh("ops", "cycle", "--config", site.cfg_path, "--dry-run", "--json",
                guard=_guard(tmp_path))
    plan = json.loads(r.stdout)
    assert r.returncode == 0 and plan["dry_run"] is True
    names = [s["name"] for s in plan["steps"]]
    assert names[-2:] == ["backup", "backup.verify"] and "attest.anchor_all" in names
    assert site.tree() == before


@pytest.mark.parametrize("mutate, message", [
    (lambda c: c.update(surprise=1), "unknown key"),
    (lambda c: c.pop("data_dir"), "'data_dir' is required"),
    (lambda c: c["intel"]["sources"].append({"source": "nvd"}), "named CVEs"),
    (lambda c: c["intel"].update(live="yes"), "intel.live must be true or false"),
    (lambda c: c.update(max_cycle_age_hours=0), "max_cycle_age_hours"),
    (lambda c: c.update(ops_id="bad id!"), "ops_id"),
    (lambda c: c["watch"][0].pop("ledger"), "needs 'config' and 'ledger'"),
    (lambda c: c["attest"].pop("key"), "attest.key"),
])
def test_a_bad_config_exits_two_and_has_no_side_effects(site, capsys, mutate, message):
    mutate(site.cfg)
    site.write()
    before = site.tree()
    for verb in ("cycle", "status", "check"):
        capsys.readouterr()
        code = assurance_main(["ops", verb, "--config", str(site.cfg_path)])
        err = capsys.readouterr().err
        assert code == 2 and message in err and "Nothing was run" in err, (verb, err)
    assert site.tree() == before


def test_a_missing_or_garbled_config_exits_two(tmp_path, capsys):
    assert assurance_main(["ops", "cycle", "--config", str(tmp_path / "nope.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert assurance_main(["ops", "status", "--config", str(bad)]) == 2
    arr = tmp_path / "arr.json"
    arr.write_text("[]", encoding="utf-8")
    assert assurance_main(["ops", "check", "--config", str(arr)]) == 2
    with pytest.raises(OpsConfigError):
        load_config(arr)


def test_the_intel_gate_needs_both_the_config_and_the_flag(site, capsys, monkeypatch):
    import assurance.intel.cli as intel_cli

    clock = Clock()
    transport = ContractFixtureTransport({
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
            (200, json.dumps(kev_doc("CVE-2026-4242", version="2026.11.01")).encode())})
    made: list[str] = []

    def fake(source_id):
        made.append(source_id)
        return transport

    monkeypatch.setattr(intel_cli, "_make_transport", fake)
    import assurance.intel.fetch as fetch_mod

    monkeypatch.setattr(fetch_mod, "utc_now", clock, raising=False)

    # config live:false + --live  -> skipped
    _cycle(site, capsys, "--live")
    s = _by_name(site.cycles()[-1])["intel.refresh:kev"]
    assert s["status"] == "skipped" and "live: false" in s["detail"] and not made
    # config live:true, no --live -> skipped
    site.cfg["intel"]["live"] = True
    site.write()
    _cycle(site, capsys)
    s = _by_name(site.cycles()[-1])["intel.refresh:kev"]
    assert s["status"] == "skipped" and "--live was not passed" in s["detail"] and not made
    # both -> runs, through the contract-fixture transport (NOT the network)
    _cycle(site, capsys, "--live")
    doc = site.cycles()[-1]
    s = _by_name(doc)["intel.refresh:kev"]
    assert made == ["cisa_kev"] and len(transport.calls) == 1
    assert doc["live_requested"] is True
    assert s["status"] in ("ok", "flagged"), s
    assert "--live" in s["command"] and "intel refresh --source kev" in s["command"]


def test_no_intel_configured_is_a_skipped_step_not_a_silent_one(site, capsys):
    del site.cfg["intel"]
    site.write()
    _cycle(site, capsys)
    s = _by_name(site.cycles()[-1])["intel.refresh"]
    assert s["status"] == "skipped" and "not refreshed" in s["detail"]


# ============================================================================================
# check (preflight)
# ============================================================================================
def _check(site: Site, capsys, *flags: str) -> tuple[int, dict | str]:
    capsys.readouterr()
    code = assurance_main(["ops", "check", "--config", str(site.cfg_path), *flags])
    out = capsys.readouterr().out
    return code, (json.loads(out) if "--json" in flags else out)


def test_check_passes_a_good_config_writes_nothing_and_lists_what_it_did_not_check(site, capsys):
    before = site.tree()
    code, doc = _check(site, capsys, "--json")
    assert code == 0 and doc["ok"] is True, [c for c in doc["checks"] if c["status"] == "fail"]
    names = {c["name"] for c in doc["checks"]}
    assert {"data_dir", "data_dir.layout", "backup_dir", "disk.free", "record", "lock",
            "attest.key.permissions", "watch[0].config", "postgres"} <= names
    pg = next(c for c in doc["checks"] if c["name"] == "postgres")
    assert "not required" in pg["detail"]
    text = " ".join(doc["not_checked"])
    for needle in ("scheduler", "Key custody", "Off-box backup", "restore"):
        assert needle in text
    assert site.tree() == before


def test_check_text_output_has_a_not_checked_section(site, capsys):
    code, out = _check(site, capsys)
    assert code == 0 and "NOT checked:" in out and "scheduler" in out


def test_check_fails_on_a_loose_key_a_key_inside_the_data_dir_and_a_bad_backup_dir(site, capsys):
    os.chmod(site.key, 0o644)
    code, doc = _check(site, capsys, "--json")
    assert code == 1
    bad = [c for c in doc["checks"] if c["status"] == "fail"]
    assert any("chmod 600" in c["detail"] for c in bad)
    os.chmod(site.key, 0o600)
    site.cfg["backup_dir"] = "data/backups"
    inside = site.data / "inside.pem"
    inside.write_bytes(site.key.read_bytes())
    os.chmod(inside, 0o600)
    site.cfg["attest"]["key"] = str(inside)
    site.write()
    code, doc = _check(site, capsys, "--json")
    failed = {c["name"] for c in doc["checks"] if c["status"] == "fail"}
    assert code == 1 and {"backup_dir", "attest.key_apart_from_data"} <= failed


def test_check_fails_when_free_disk_is_short(site, capsys):
    site.cfg["min_free_disk_mb"] = 10 ** 12
    site.write()
    code, doc = _check(site, capsys, "--json")
    assert code == 1
    assert any(c["name"] == "disk.free" and c["status"] == "fail" for c in doc["checks"])


def test_check_fails_for_a_missing_data_dir_and_a_broken_watch_config(site, capsys):
    (site.root / "watch.json").write_text("{}", encoding="utf-8")
    site.cfg["data_dir"] = "nowhere"
    site.write()
    code, doc = _check(site, capsys, "--json")
    failed = {c["name"] for c in doc["checks"] if c["status"] == "fail"}
    assert code == 1 and {"data_dir", "watch[0].config"} <= failed


# ============================================================================================
# the examples: documentation files that must stay true
# ============================================================================================
def test_the_example_config_loads_and_has_no_secret_values():
    cfg = load_config(OPS_DIR / "ops.example.json")
    assert cfg.attest is not None and cfg.intel is not None and cfg.intel.live is False
    raw = (OPS_DIR / "ops.example.json").read_text()
    assert "PRIVATE KEY" not in raw and "sk_live" not in raw


def _commands_in(text: str) -> set[str]:
    verbs = set(discover_cli())
    found: set[str] = set()
    text = re.sub(r"--ledger \S+ ", "", text)          # art14's option sits before its verb
    for m in re.finditer(r"python -m assurance ((?:[a-z0-9-]+ ?){1,3})", text):
        words = m.group(1).split()
        hit = [" ".join(words[:n]) for n in (3, 2, 1) if " ".join(words[:n]) in verbs]
        assert hit, f"{m.group(0)!r} is not a verb in the capabilities catalogue"
        found.add(hit[0])
    return found


def test_the_compose_example_parses_and_every_command_it_runs_is_a_real_verb():
    yaml = pytest.importorskip("yaml")
    text = (OPS_DIR / "docker-compose.ops.yml").read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    assert set(doc["services"]) >= {"api", "ops-cycle"}
    assert "EXAMPLE" in text.splitlines()[0].upper() or "EXAMPLE" in text[:400].upper()
    commands = []
    for svc in doc["services"].values():
        for key in ("command", "entrypoint"):
            value = svc.get(key)
            if value:
                commands.append(value if isinstance(value, str) else " ".join(value))
        hc = (svc.get("healthcheck") or {}).get("test")
        if hc:
            commands.append(" ".join(hc[1:] if isinstance(hc, list) else [hc]))
    joined = "\n".join(commands)
    assert _commands_in(joined) >= {"ops cycle", "ops status"}
    # no secret values: only ${VAR} placeholders for anything key-like
    for line in text.splitlines():
        if re.search(r"(KEY|SECRET|PASSPHRASE|TOKEN)\s*[:=]", line, re.I):
            assert "${" in line or line.lstrip().startswith("#"), line


def test_the_cron_and_systemd_examples_name_real_verbs_and_install_nothing():
    for name in ("cron.example", "assurance-ops.service.example", "assurance-ops.timer.example"):
        text = (OPS_DIR / name).read_text(encoding="utf-8")
        assert "EXAMPLE" in text.upper()
        _commands_in(text)
    service = (OPS_DIR / "assurance-ops.service.example").read_text()
    assert "ops cycle" in service and "SuccessExitStatus=1" in service
    assert "[Timer]" in (OPS_DIR / "assurance-ops.timer.example").read_text()
    assert not list(OPS_DIR.glob("*.service")) and not list(OPS_DIR.glob("*.timer"))


def test_the_ops_runbook_names_real_verbs():
    text = (ROOT / "deploy" / "assurance" / "OPS.md").read_text(encoding="utf-8")
    assert _commands_in(text) >= {"ops cycle", "ops status", "ops check", "art14 verify"}
    for needle in ("RESTORE DRILL", "restore_check verify", "Not established",
                   "KEY-CEREMONY.md"):
        assert needle in text, needle


def test_importing_ops_loads_no_network_client():
    code = ("import sys; import assurance.ops.cli, assurance.ops.cycle, assurance.ops.check; "
            "bad = [m for m in ('socket','ssl','http.client','urllib.request','httpx','requests',"
            "'urllib3') if m in sys.modules]; print(bad)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,  # noqa: S603
                       env={"PYTHONPATH": SRC, "PATH": os.environ.get("PATH", "")}, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "[]", r.stdout
