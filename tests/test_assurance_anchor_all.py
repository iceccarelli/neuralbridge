"""``attest anchor-all``: the operator job that gives every hosted account an anchor.

Real Ed25519 throwaway keys, real per-account ledgers made through the real API, and the real
``GET /v1/ledger/verify`` route reading what the job wrote.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.api import attest_routes, deps
from assurance.attest import AttestationLog, SigningKey, VerifyingKey, attest, verify_log
from assurance.attest.cli import main
from assurance.evidence import EvidenceLedger

from .test_assurance_export_api import _account, _signal, api  # noqa: F401

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes and flock are POSIX")


@pytest.fixture()
def opkey(api, tmp_path_factory, monkeypatch):  # noqa: F811
    """The service key, kept outside the data directory (as the job insists)."""
    path = tmp_path_factory.mktemp("opkey") / "service.pem"
    key = SigningKey.generate()
    key.save(path)
    monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(path))
    return path, key


def data_dir() -> Path:
    return Path(os.environ["ASSURANCE_LEDGER"]).parent


def run(capsys, *args):
    capsys.readouterr()
    code = main(["anchor-all", "--data-dir", str(data_dir()), *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def run_json(capsys, key, *args):
    code, out, _ = run(capsys, "--key", str(key), "--json", *args)
    return code, json.loads(out)


def log_of(account) -> AttestationLog:
    return attest_routes._log_for(type("P", (), {"subject": account.id})())


def verify(client, headers):
    r = client.get("/v1/ledger/verify", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def seeded(api, email, n=2):  # noqa: F811
    account, headers = _account(email)
    for i in range(n):
        _signal(api, headers, f"C{i}")
    return account, headers


def mutate(account, sql, *params):
    db = sqlite3.connect(deps.tenant_ledger_path(account.id))
    db.execute(sql, params)
    db.commit()
    db.close()


def snapshot(root: Path):
    return sorted((str(p), p.stat().st_size, p.stat().st_mtime_ns)
                  for p in root.rglob("*") if p.is_file() and p.name != "accounts.db")


def by_name(report):
    return {row["account_id"] or row["name"]: row for row in report["ledgers"]}


def test_anchors_a_healthy_ledger_and_verify_reports_checked_against_anchor(
        api, opkey, capsys):  # noqa: F811
    account, headers = seeded(api, "a@example.de")
    before = verify(api, headers)
    assert before["completeness"] == "not_checked" and before["anchor"] is None

    code, report = run_json(capsys, opkey[0])
    assert code == 0 and report["ok"] is True
    assert report["summary"]["anchored"] == 1
    assert by_name(report)[account.id]["status"] == "anchored"
    assert report["key_fingerprint"] == opkey[1].fingerprint
    assert any("runs on a schedule" in s for s in report["not_checked"])

    after = verify(api, headers)
    assert after["completeness"] == "checked_against_anchor" and after["verified"] is True
    assert after["anchor"]["key_fingerprint"] == opkey[1].fingerprint
    assert after["anchor"]["basis"] == "read_from_ledger"


def test_text_output_has_table_summary_and_no_key_material(api, opkey, capsys):  # noqa: F811
    seeded(api, "a@example.de")
    code, out, err = run(capsys, "--key", str(opkey[0]))
    assert code == 0
    assert "anchored" in out and "1 anchored" in out and "NOT checked" in out
    assert opkey[1].fingerprint in out
    body = "".join(opkey[0].read_text().splitlines()[1:-1])
    assert "PRIVATE KEY" not in out + err and body[:40] not in out + err


def test_broken_chain_is_refused_and_no_anchor_written(api, opkey, capsys):  # noqa: F811
    bad, _ = seeded(api, "bad@example.de")
    good, _ = seeded(api, "good@example.de")
    mutate(bad, "UPDATE chain SET payload = replace(payload, 'Integrator', 'Intruder') WHERE seq = 1")
    code, report = run_json(capsys, opkey[0])
    rows = by_name(report)
    assert code == 1 and report["ok"] is False
    assert rows[bad.id]["status"] == "refused" and "chain" in rows[bad.id]["detail"]
    assert rows[good.id]["status"] == "anchored"
    assert not log_of(bad).path.exists()
    assert not Path(str(log_of(bad).path) + ".lock").exists()
    assert log_of(good).path.exists()


def test_fresh_anchor_is_skipped_and_stale_one_is_reanchored(api, opkey, capsys):  # noqa: F811
    account, _ = seeded(api, "a@example.de")
    assert run_json(capsys, opkey[0])[0] == 0
    n = len(log_of(account).read())
    code, report = run_json(capsys, opkey[0], "--max-age", "24")
    assert code == 0 and by_name(report)[account.id]["status"] == "fresh"
    assert len(log_of(account).read()) == n
    # Same head, but the anchor is older than the allowed age.
    code, report = run_json(capsys, opkey[0], "--max-age", "0")
    assert by_name(report)[account.id]["status"] == "anchored"
    assert len(log_of(account).read()) == n + 1


def test_an_old_anchor_on_an_unchanged_head_is_reanchored(api, opkey, capsys):  # noqa: F811
    account, _ = seeded(api, "a@example.de")
    old = datetime.now(UTC) - timedelta(hours=48)
    attest(EvidenceLedger(deps.tenant_ledger_path(account.id)), opkey[1], log_of(account),
           now=old)
    code, report = run_json(capsys, opkey[0], "--max-age", "24")
    assert by_name(report)[account.id]["status"] == "anchored" and code == 0
    assert len(log_of(account).read()) == 2


def test_a_ledger_that_grew_since_the_anchor_is_reanchored(api, opkey, capsys):  # noqa: F811
    account, headers = seeded(api, "a@example.de")
    run_json(capsys, opkey[0])
    _signal(api, headers, "NEW")
    code, report = run_json(capsys, opkey[0], "--max-age", "24")
    row = by_name(report)[account.id]
    assert code == 0 and row["status"] == "anchored" and row["ledger_length"] == 3
    assert log_of(account).read()[-1].ledger_length == 3


def test_truncation_after_anchor_all_is_contradicted_and_not_re_anchored(
        api, opkey, capsys):  # noqa: F811
    account, headers = seeded(api, "a@example.de", n=3)
    run_json(capsys, opkey[0])
    mutate(account, "DELETE FROM chain WHERE seq > 1")
    assert verify(api, headers)["completeness"] == "contradicted_by_anchor"
    n = len(log_of(account).read())
    code, report = run_json(capsys, opkey[0], "--max-age", "0")
    row = by_name(report)[account.id]
    assert code == 1 and row["status"] == "refused"
    assert "ledger holds" in row["detail"] and "Nothing was signed" in row["detail"]
    assert len(log_of(account).read()) == n          # the evidence of the rewind is kept


def test_dry_run_writes_nothing(api, opkey, capsys):  # noqa: F811
    seeded(api, "a@example.de")
    before = snapshot(data_dir())
    code, report = run_json(capsys, opkey[0], "--dry-run")
    assert code == 0 and report["dry_run"] is True
    assert report["summary"]["would_anchor"] == 1 and report["summary"]["anchored"] == 0
    assert snapshot(data_dir()) == before
    assert not (data_dir() / "attestations").exists()


def test_symlinks_and_out_of_pattern_entries_are_skipped_and_reported(
        api, opkey, capsys, tmp_path_factory):  # noqa: F811
    real, _ = seeded(api, "a@example.de")
    tenants = data_dir() / "tenants"
    outside = tmp_path_factory.mktemp("outside")
    secret_db = outside / "victim.db"
    EvidenceLedger(secret_db)
    victim_bytes = secret_db.read_bytes()
    link_id = "acc_" + "0123456789abcdef"
    (tenants / f"{link_id}.db").symlink_to(secret_db)
    (tenants / "operator.db").write_bytes(b"not a tenant")
    (tenants / "notes.txt").write_text("x")
    (tenants / ("acc_" + "A" * 16 + ".db")).write_bytes(b"")        # upper-case: not an id
    (tenants / f"{real.id}.db-wal").write_bytes(b"")               # sqlite sidecar: ignored
    # a log that is a symlink to a file elsewhere must not be appended through
    victim_log = outside / "victim.jsonl"
    victim_log.write_text("keep\n")
    other, _ = seeded(api, "b@example.de")
    logs = data_dir() / "attestations"
    logs.mkdir(exist_ok=True)
    log_of(other).path.symlink_to(victim_log)

    code, report = run_json(capsys, opkey[0])
    rows = by_name(report)
    assert code == 1
    assert rows[real.id]["status"] == "anchored"
    assert rows[link_id]["status"] == "skipped" and "symbolic link" in rows[link_id]["detail"]
    assert rows[other.id]["status"] == "skipped"
    for n in ("operator.db", "notes.txt", "acc_" + "A" * 16 + ".db"):
        assert rows[n]["status"] == "skipped"
    assert not any(".db-wal" in r["name"] for r in report["ledgers"])
    assert victim_log.read_text() == "keep\n" and secret_db.read_bytes() == victim_bytes
    assert not (logs / f"{link_id}.jsonl").exists()
    # junk alone does not fail the run
    (tenants / f"{link_id}.db").unlink()
    log_of(other).path.unlink()
    assert run_json(capsys, opkey[0])[0] == 0


def test_a_symlinked_tenants_directory_is_refused(api, opkey, capsys,  # noqa: F811
                                                  tmp_path_factory):  # noqa: F811
    seeded(api, "a@example.de")
    real = tmp_path_factory.mktemp("elsewhere")
    root = tmp_path_factory.mktemp("deploy")
    (root / "tenants").symlink_to(real)
    capsys.readouterr()
    code = main(["anchor-all", "--data-dir", str(root), "--key", str(opkey[0])])
    assert code == 2 and "symbolic link" in capsys.readouterr().err


def test_operator_shared_ledger_is_not_a_tenant(api, opkey, capsys):  # noqa: F811
    _, headers = seeded(api, "a@example.de")
    operator = Path(os.environ["ASSURANCE_LEDGER"])
    EvidenceLedger(operator)                          # the shared ledger exists beside tenants/
    assert operator.is_file()
    code, report = run_json(capsys, opkey[0])
    assert code == 0 and len(report["ledgers"]) == 1
    assert not any("operator" in r["name"] for r in report["ledgers"])
    assert not any("operator" in p.name for p in (data_dir() / "attestations").iterdir())


def test_wrong_key_is_refused_without_touching_the_log(api, opkey, capsys,  # noqa: F811
                                                       tmp_path_factory):  # noqa: F811
    account, _ = seeded(api, "a@example.de")
    run_json(capsys, opkey[0])
    before = log_of(account).path.read_bytes()
    other = tmp_path_factory.mktemp("otherkey") / "other.pem"
    SigningKey.generate().save(other)
    code, report = run_json(capsys, other, "--max-age", "0")
    row = by_name(report)[account.id]
    assert code == 1 and row["status"] == "refused" and "key" in row["detail"]
    assert log_of(account).path.read_bytes() == before


def test_unreadable_key_fails_without_printing_key_material(api, opkey, capsys,  # noqa: F811
                                                            tmp_path_factory):  # noqa: F811
    seeded(api, "a@example.de")
    bad = tmp_path_factory.mktemp("badkey") / "bad.pem"
    bad.write_text("-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
                   "-----END PRIVATE KEY-----\n")
    bad.chmod(0o600)
    code, out, err = run(capsys, "--key", str(bad))
    assert code == 2
    assert "QUJDREVGR0hJ" not in out + err and "Nothing was signed" in err
    code, out, err = run(capsys, "--key", str(data_dir() / "missing.pem"))
    assert code == 2 and not (data_dir() / "attestations").exists()
    enc = tmp_path_factory.mktemp("enc") / "enc.pem"
    SigningKey.generate().save(enc, passphrase="correct horse")  # noqa: S106
    code, out, err = run(capsys, "--key", str(enc), "--passphrase-env", "NB_NO_SUCH_VAR_XYZ")
    assert code in (1, 2) and "correct horse" not in out + err
    code, out, err = run(capsys, "--key", str(enc))               # encrypted, no passphrase
    assert code == 2 and "passphrase" in err
    loose = tmp_path_factory.mktemp("loose") / "k.pem"
    SigningKey.generate().save(loose)
    loose.chmod(0o644)
    assert run(capsys, "--key", str(loose))[0] == 2
    assert not (data_dir() / "attestations").exists()


def test_a_key_inside_the_data_directory_is_refused(api, opkey, capsys):  # noqa: F811
    seeded(api, "a@example.de")
    inside = data_dir() / "keys" / "k.pem"
    SigningKey.generate().save(inside)
    code, out, err = run(capsys, "--key", str(inside))
    assert code == 2 and "inside the data directory" in err
    assert not (data_dir() / "attestations").exists()


def test_concurrent_runs_leave_a_valid_unforked_log(api, opkey):  # noqa: F811
    accounts = [seeded(api, f"u{i}@example.de")[0] for i in range(3)]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    cmd = [sys.executable, "-m", "assurance", "attest", "anchor-all",
           "--data-dir", str(data_dir()), "--key", str(opkey[0]), "--max-age", "0", "--json"]
    procs = [
        subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,  # noqa: S603
                         stderr=subprocess.PIPE, text=True)
        for _ in range(4)]
    results = []
    for p in procs:
        out, err = p.communicate(timeout=180)
        results.append((p.returncode, out, err))
    assert all(code == 0 for code, _, _ in results), results
    pub = VerifyingKey.from_pem(opkey[1].verifying.pem())
    for account in accounts:
        records, torn = log_of(account).scan()
        assert not torn and 1 <= len(records) <= 4
        assert [r.sequence for r in records] == list(range(1, len(records) + 1))
        assert verify_log(records, pub, ledger=EvidenceLedger(
            deps.tenant_ledger_path(account.id))).ok


def test_preflight_anchors_reports_missing_and_stale_and_what_it_cannot_check(
        api, opkey, capsys):  # noqa: F811
    account, _ = seeded(api, "a@example.de")
    before = snapshot(data_dir())

    def pre(*extra):
        capsys.readouterr()
        code = main(["preflight", "--key", str(opkey[0]), "--require", "counter-signing",
                     "--anchors", str(data_dir()), "--json", *extra])
        rep = json.loads(capsys.readouterr().out)
        row = next(c for c in rep["checks"] if c["name"] == f"anchors.{account.id}")
        return code, rep, row

    code, rep, row = pre()
    assert code == 1 and row["status"] == "fail" and "no verified anchor" in row["detail"]
    text = " ".join(rep["not_checked"])
    assert "runs on a schedule" in text and "rewrite a ledger and its attestation log" in text
    assert "Custody" in text
    assert snapshot(data_dir()) == before            # read-only

    run_json(capsys, opkey[0])
    code, rep, row = pre()
    assert code == 0 and row["status"] == "ok"
    code, rep, row = pre("--max-age", "0")
    assert code == 1 and row["status"] == "fail" and "stale anchor" in row["detail"]
    capsys.readouterr()
    main(["preflight", "--key", str(opkey[0]), "--require", "counter-signing", "--json"])
    plain = json.loads(capsys.readouterr().out)
    assert not any(c["name"].startswith("anchors") for c in plain["checks"])
    assert "schedule" not in " ".join(plain["not_checked"])
