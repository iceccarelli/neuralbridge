"""``assurance tenant``: export, verify-export and the guarded removal of one account.

Real ledgers, a real attestation log signed with a throwaway key, real files on a tmp data
directory. Deletion code only ever runs on those tmp directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from assurance.attest import AttestationLog, SigningKey, attest
from assurance.cli import main as top_main
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger
from assurance.tenant.cli import main

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes and flock are POSIX")

ACC_A = "acc_" + "a1" * 8
ACC_B = "acc_" + "b2" * 8
SECRET_A = "ACME-CUSTOMER-CONTENT-7f3a"
SECRET_B = "GLOBEX-CUSTOMER-CONTENT-91cc"
FAKE_KEYS = ("sk_live_FAKEKEY_do_not_leak_01", "nb_live_FAKEAPIKEY_do_not_leak_02",
             "whsec_FAKEWEBHOOK_do_not_leak_03")
PERSON = "Maria Example"


def _ev(text: str, n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n, "note": text},
                    actor=Actor("a.engineer", "engineer"), origin=Origin("unit-test")).seal()


@pytest.fixture()
def data(tmp_path):
    root = tmp_path / "data"
    (root / "tenants").mkdir(parents=True)
    (root / "attestations").mkdir()
    for acc, secret in ((ACC_A, SECRET_A), (ACC_B, SECRET_B)):
        led = EvidenceLedger(root / "tenants" / f"{acc}.db")
        for i in range(4):
            led.append(_ev(secret, i), subject=f"case-{i % 2}")
    key = SigningKey.generate()
    for acc in (ACC_A, ACC_B):
        led = EvidenceLedger(root / "tenants" / f"{acc}.db", mint_id=False)
        attest(led, key, AttestationLog(root / "attestations" / f"{acc}.jsonl"), note="t")
    op = EvidenceLedger(root / "art14-register.db")
    op.append(_ev("operator-own-record", 1), subject="operator")
    # an accounts store with secrets in it, and a file that merely mentions them
    db = sqlite3.connect(root / "accounts.db")
    db.execute("CREATE TABLE keys (account TEXT, secret TEXT)")
    for k in FAKE_KEYS:
        db.execute("INSERT INTO keys VALUES (?, ?)", (ACC_A, k))
    db.commit()
    db.close()
    (root / "attestations" / f"{ACC_A}.note").write_text(FAKE_KEYS[0])
    return root


def tree(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def run(capsys, *args):
    capsys.readouterr()
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def do_export(capsys, data, out, acc=ACC_A, *extra):
    return run(capsys, "export", "--data-dir", str(data), "--account", acc, "--out", str(out),
               "--actor", PERSON, *extra)


def do_delete(capsys, data, acc=ACC_A, *extra):
    return run(capsys, "delete", "--data-dir", str(data), "--account", acc, *extra)


def execute(capsys, data, export, acc=ACC_A, *extra, actor=PERSON, confirm=None):
    return do_delete(capsys, data, acc, "--execute", "--confirm-account", confirm or acc,
                     "--export", str(export), "--actor", actor, *extra)


def break_chain(path: Path) -> None:
    db = sqlite3.connect(path)
    db.execute("UPDATE chain SET kind = 'tampered.kind' WHERE seq = 2")
    db.commit()
    db.close()


# ---------------------------------------------------------------------------------- export
def test_export_of_populated_tenant_verifies(capsys, data, tmp_path):
    out = tmp_path / "export"
    code, stdout, _ = do_export(capsys, data, out)
    assert code == 0, stdout
    manifest = json.loads((out / "MANIFEST.json").read_text())
    assert manifest["account_id"] == ACC_A and manifest["record_count"] == 4
    assert manifest["actor"] == PERSON and manifest["exported_at"].endswith("Z")
    assert manifest["verify"]["status"] == "verified" and manifest["accept_damaged"] is False
    live = EvidenceLedger(data / "tenants" / f"{ACC_A}.db", mint_id=False)
    assert manifest["ledger_id"] == live.ledger_id()
    assert manifest["head_hash"] == live.entries()[-1].link_hash
    assert {f["name"] for f in manifest["files"]} == {
        "ledger.db", "evidence-bundle.json", "attestations.jsonl", "VERIFY.txt"}
    assert manifest["not_included"] and manifest["does_not_establish"]
    assert (out.stat().st_mode & 0o777) == 0o700
    assert {(p.stat().st_mode & 0o777) for p in out.iterdir()} == {0o600}
    for f in manifest["files"]:
        blob = (out / f["name"]).read_bytes()
        assert f["size"] == len(blob) and f["sha256"] == hashlib.sha256(blob).hexdigest()
    code, stdout, _ = run(capsys, "verify-export", str(out))
    assert code == 0 and "OK" in stdout
    # the bundle stands on its own for a third party
    from assurance.evidence.cli import main as evidence_main
    assert evidence_main(["verify", str(out / "evidence-bundle.json")]) in (0, 3)


def test_export_without_attestation_log(capsys, data, tmp_path):
    (data / "attestations" / f"{ACC_A}.jsonl").unlink()
    out = tmp_path / "export"
    assert do_export(capsys, data, out)[0] == 0
    manifest = json.loads((out / "MANIFEST.json").read_text())
    assert manifest["attestation_log"]["included"] is False
    assert not (out / "attestations.jsonl").exists()
    assert run(capsys, "verify-export", str(out))[0] == 0


def test_export_excludes_other_tenant_operator_and_secrets(capsys, data, tmp_path):
    out = tmp_path / "export"
    assert do_export(capsys, data, out)[0] == 0
    blob = b"".join(p.read_bytes() for p in out.iterdir())
    assert SECRET_A.encode() in blob
    for needle in (SECRET_B, ACC_B, "operator-own-record", *FAKE_KEYS):
        assert needle.encode() not in blob, needle


def test_export_refuses_nonempty_or_symlinked_or_inside_data_out(capsys, data, tmp_path):
    full = tmp_path / "full"
    full.mkdir()
    (full / "x").write_text("x")
    assert do_export(capsys, data, full)[0] == 2
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert do_export(capsys, data, link)[0] == 2 and not list(real.iterdir())
    assert do_export(capsys, data, data / "tenants" / "out")[0] == 2
    assert not (data / "tenants" / "out").exists()


def test_broken_chain_refused_without_accept_damaged(capsys, data, tmp_path):
    break_chain(data / "tenants" / f"{ACC_A}.db")
    out = tmp_path / "export"
    code, _, err = do_export(capsys, data, out)
    assert code == 1 and "does not verify" in err and not out.exists()
    code, _, _ = do_export(capsys, data, out, ACC_A, "--accept-damaged")
    assert code == 0
    manifest = json.loads((out / "MANIFEST.json").read_text())
    assert manifest["accept_damaged"] is True
    assert manifest["verify"]["status"] == "damaged_accepted"
    assert manifest["verify"]["chain_verified"] is False and manifest["verify"]["problems"]
    assert not (out / "evidence-bundle.json").exists()
    code, stdout, _ = run(capsys, "verify-export", str(out))
    assert code == 1 and "DAMAGED_ACCEPTED" in stdout


def test_verify_export_detects_tampering(capsys, data, tmp_path):
    out = tmp_path / "export"
    assert do_export(capsys, data, out)[0] == 0
    for name, mutate in (
        ("ledger.db", lambda p: p.write_bytes(p.read_bytes() + b"\0")),
        ("evidence-bundle.json", lambda p: p.write_text(p.read_text().replace("seq", "sEq", 1))),
        ("attestations.jsonl", lambda p: p.write_text("")),
        ("VERIFY.txt", lambda p: p.write_text("hello")),
    ):
        target = out / name
        original = target.read_bytes()
        mutate(target)
        assert run(capsys, "verify-export", str(out))[0] == 1, name
        target.write_bytes(original)
    assert run(capsys, "verify-export", str(out))[0] == 0
    (out / "extra.txt").write_text("unlisted")
    code, stdout, _ = run(capsys, "verify-export", str(out))
    assert code == 1 and "not listed" in stdout
    (out / "extra.txt").unlink()
    (out / "VERIFY.txt").unlink()
    assert run(capsys, "verify-export", str(out))[0] == 1


def test_verify_export_rechecks_the_chain_not_just_hashes(capsys, data, tmp_path):
    """A forger who edits the ledger copy AND the manifest hash is still caught by the chain."""
    out = tmp_path / "export"
    assert do_export(capsys, data, out)[0] == 0
    break_chain(out / "ledger.db")
    manifest = json.loads((out / "MANIFEST.json").read_text())
    blob = (out / "ledger.db").read_bytes()
    for f in manifest["files"]:
        if f["name"] == "ledger.db":
            f["size"], f["sha256"] = len(blob), hashlib.sha256(blob).hexdigest()
    (out / "MANIFEST.json").write_text(json.dumps(manifest))
    code, stdout, _ = run(capsys, "verify-export", str(out))
    assert code == 1 and "does NOT verify" in stdout


def test_verify_export_exit_codes(capsys, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run(capsys, "verify-export", str(empty))[0] == 3
    assert run(capsys, "verify-export", str(tmp_path / "nope"))[0] == 2
    (empty / "MANIFEST.json").write_text("{not json")
    assert run(capsys, "verify-export", str(empty))[0] == 1
    (empty / "MANIFEST.json").write_text(json.dumps({"format": "x"}))
    assert run(capsys, "verify-export", str(empty))[0] == 1


def test_usage_error_is_exit_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["export"])
    assert exc.value.code == 2


def test_symlinked_tenant_files_are_refused(capsys, data, tmp_path):
    before = tree(data)
    ledger = data / "tenants" / f"{ACC_A}.db"
    real = tmp_path / "elsewhere.db"
    ledger.rename(real)
    ledger.symlink_to(real)
    code, _, err = do_export(capsys, data, tmp_path / "e1")
    assert code == 1 and "symbolic link" in err and not (tmp_path / "e1").exists()
    code, _, err = do_delete(capsys, data, ACC_A)
    assert code == 1 and "symbolic link" in err
    ledger.unlink()
    real.rename(ledger)
    assert tree(data) == before
    # a symlinked attestation log, a symlinked sidecar
    log = data / "attestations" / f"{ACC_A}.jsonl"
    stash = tmp_path / "log.jsonl"
    log.rename(stash)
    log.symlink_to(stash)
    assert do_export(capsys, data, tmp_path / "e2")[0] == 1
    log.unlink()
    stash.rename(log)
    wal = Path(f"{ledger}-wal")
    wal.symlink_to(tmp_path / "anything")
    assert do_export(capsys, data, tmp_path / "e3")[0] == 1
    wal.unlink()


def test_symlinked_tenants_directory_is_refused(capsys, data, tmp_path):
    real = tmp_path / "real-tenants"
    (data / "tenants").rename(real)
    (data / "tenants").symlink_to(real)
    assert do_export(capsys, data, tmp_path / "e")[0] == 2
    assert do_delete(capsys, data, ACC_A)[0] == 2
    assert not (tmp_path / "e").exists()


@pytest.mark.parametrize("bad", [
    "../tenants/acc_" + "a1" * 8, "acc_" + "A1" * 8, "acc_abc", "acc_" + "a1" * 8 + "0",
    "acc_" + "a1" * 8 + "/../..", "", "acc_" + "g1" * 8, " acc_" + "a1" * 8, "ACC_" + "a1" * 8,
    "acc_" + "a1" * 8 + "\n",
])
def test_bad_account_ids_refused_without_touching_the_filesystem(capsys, tmp_path, bad):
    missing = tmp_path / "does-not-exist"
    before = sorted(os.listdir(tmp_path))
    for args in (("export", "--data-dir", str(missing), "--account", bad, "--out",
                  str(tmp_path / "out"), "--actor", PERSON),
                 ("delete", "--data-dir", str(missing), "--account", bad),
                 ("delete", "--data-dir", str(missing), "--account", bad, "--execute",
                  "--confirm-account", bad, "--export", str(tmp_path), "--actor", PERSON)):
        code, _, err = run(capsys, *args)
        assert code == 2 and "not an account id" in err, (bad, args)
    assert sorted(os.listdir(tmp_path)) == before


def test_nothing_is_created_on_a_typo(capsys, data, tmp_path):
    before = tree(data)
    listing = sorted(os.listdir(data / "tenants"))
    unknown = "acc_" + "c3" * 8
    assert do_export(capsys, data, tmp_path / "e", unknown)[0] == 1
    assert do_delete(capsys, data, unknown)[0] == 0          # a plan for nothing
    assert execute(capsys, data, tmp_path, unknown)[0] == 1  # already removed
    assert sorted(os.listdir(data / "tenants")) == listing and tree(data) == before
    assert run(capsys, "export", "--data-dir", str(tmp_path / "nodata"), "--account", ACC_A,
               "--out", str(tmp_path / "e"), "--actor", PERSON)[0] == 2
    assert not (tmp_path / "nodata").exists() and not (tmp_path / "e").exists()


# ---------------------------------------------------------------------------------- delete
def test_delete_plan_writes_nothing(capsys, data, tmp_path):
    backups = tmp_path / "backups"
    (backups / "tenants").mkdir(parents=True)
    (backups / "tenants" / f"{ACC_A}.db").write_bytes(b"x")
    before = tree(data)
    code, stdout, _ = do_delete(capsys, data, ACC_A, "--backup-dir", str(backups))
    assert code == 0 and "PLAN" in stdout and "nothing was removed" in stdout
    assert f"{ACC_A}.db" in stdout and f"{ACC_A}.jsonl" in stdout
    assert ACC_B not in stdout
    assert "NOT removed" in stdout and "accounts.db" in stdout and "Stripe" in stdout
    assert "backups still hold" in stdout and str(backups / "tenants" / f"{ACC_A}.db") in stdout
    assert tree(data) == before
    code, stdout, _ = do_delete(capsys, data, ACC_A, "--json")
    plan = json.loads(stdout)
    assert plan["mode"] == "plan" and plan["not_established"]
    assert tree(data) == before


def good_export(capsys, data, tmp_path, name="export"):
    out = tmp_path / name
    assert do_export(capsys, data, out)[0] == 0
    return out


def test_execute_requires_every_guard(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    before = tree(data)
    refusals = [
        do_delete(capsys, data, ACC_A, "--execute", "--export", str(export), "--actor", PERSON),
        execute(capsys, data, export, confirm=ACC_B),
        do_delete(capsys, data, ACC_A, "--execute", "--confirm-account", ACC_A, "--actor",
                  PERSON),
        execute(capsys, data, tmp_path / "missing-export"),
        execute(capsys, data, export, actor=""),
        execute(capsys, data, export, actor="automation"),
        execute(capsys, data, export, actor="watch-bot"),
        execute(capsys, data, export, actor="!!!"),
    ]
    codes = [r[0] for r in refusals]
    assert codes[:3] == [1, 1, 1] and all(c in (1, 2) for c in codes), refusals
    assert 0 not in codes
    assert tree(data) == before


def test_execute_refuses_export_for_another_account(capsys, data, tmp_path):
    other = tmp_path / "export-b"
    assert do_export(capsys, data, other, ACC_B)[0] == 0
    before = tree(data)
    code, _, err = execute(capsys, data, other, ACC_A)
    assert code == 1 and ACC_B in err
    assert tree(data) == before


def test_execute_refuses_tampered_export(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    (export / "VERIFY.txt").write_text("changed")
    before = tree(data)
    code, _, err = execute(capsys, data, export)
    assert code == 1 and "verify-export" in err and tree(data) == before


def test_execute_refuses_stale_export(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    EvidenceLedger(data / "tenants" / f"{ACC_A}.db").append(_ev("newer", 99), subject="late")
    before = tree(data)
    code, _, err = execute(capsys, data, export)
    assert code == 1 and "export" in err and "again" in err
    assert tree(data) == before
    assert (data / "tenants" / f"{ACC_A}.db").exists()


def test_execute_removes_exactly_the_planned_files(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    ledger = data / "tenants" / f"{ACC_A}.db"
    Path(f"{ledger}-journal").write_bytes(b"")          # a companion that exists
    lock = Path(f"{data / 'attestations' / (ACC_A + '.jsonl')}.lock")
    lock.write_text("")
    # a decoy sharing the prefix that a glob would take
    decoy = data / "tenants" / f"{ACC_A}.db.keep"
    decoy.write_text("decoy")
    op = EvidenceLedger(data / "art14-register.db", mint_id=False)
    op_before = [e.link_hash for e in op.entries()]
    files_before = tree(data)
    code, stdout, _ = do_delete(capsys, data, ACC_A, "--json")
    plan = {Path(f["path"]).name for f in json.loads(stdout)["would_remove"]}
    assert plan == {f"{ACC_A}.db", f"{ACC_A}.db-journal", f"{ACC_A}.jsonl", f"{ACC_A}.jsonl.lock"}

    code, stdout, _ = execute(capsys, data, export, ACC_A, "--json")
    assert code == 0, stdout
    done = json.loads(stdout)
    assert {Path(r["path"]).name for r in done["removed"]} == plan
    after = tree(data)
    gone = set(files_before) - set(after)
    assert {Path(p).name for p in gone} - {"art14-register.db"} == plan
    # everything else is byte-identical: the other tenant, accounts.db, the decoy and note
    kept = {k: v for k, v in files_before.items() if k not in gone and "art14-register" not in k}
    assert {k: after[k] for k in kept} == kept
    assert any("art14-register" in k for k in after)
    assert decoy.exists() and (data / "tenants" / f"{ACC_B}.db").exists()
    assert (data / "accounts.db").exists()
    # the operator chain still verifies, only grew by the tombstone, and kept its old entries
    op = EvidenceLedger(data / "art14-register.db", mint_id=False)
    assert op.verify_chain()[0]
    entries = op.entries()
    assert [e.link_hash for e in entries[:-1]] == op_before and len(entries) == len(op_before) + 1
    tomb = entries[-1]
    assert tomb.kind == "tenant.deletion" and tomb.subject == f"tenant/{ACC_A}"
    body = tomb.payload["body"]
    assert body["account_id"] == ACC_A and body["actor"] == PERSON
    assert body["export"]["manifest_sha256"] == done["export_manifest_sha256"]
    assert body["export"]["head_hash"] == json.loads(
        (export / "MANIFEST.json").read_text())["head_hash"]
    assert {r["name"] for r in body["removed_files"]} == plan
    raw = json.dumps(tomb.payload)
    assert SECRET_A not in raw and SECRET_B not in raw
    # the other tenant still verifies
    assert EvidenceLedger(data / "tenants" / f"{ACC_B}.db", mint_id=False).verify_chain()[0]
    assert done["accounts_db"].startswith("not touched")


def test_second_delete_refuses_cleanly(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    assert execute(capsys, data, export)[0] == 0
    op_before = tree(data)["art14-register.db"]
    code, _, err = execute(capsys, data, export)
    assert code == 1 and "already removed" in err
    assert tree(data)["art14-register.db"] == op_before
    code, stdout, _ = do_delete(capsys, data, ACC_A)
    assert code == 0 and "already removed" in stdout


def test_execute_without_operator_ledger_removes_nothing(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    (data / "art14-register.db").unlink()
    before = tree(data)
    code, _, err = execute(capsys, data, export)
    assert code == 2 and "operator ledger" in err
    assert tree(data) == before and not (data / "art14-register.db").exists()


def test_execute_refuses_when_operator_chain_is_broken(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    break_chain_op = data / "art14-register.db"
    EvidenceLedger(break_chain_op).append(_ev("second", 2), subject="operator")
    break_chain(break_chain_op)
    before = tree(data)
    assert execute(capsys, data, export)[0] == 1
    assert tree(data) == before


def test_execute_respects_a_held_attestation_lock(capsys, data, tmp_path):
    export = good_export(capsys, data, tmp_path)
    log = AttestationLog(data / "attestations" / f"{ACC_A}.jsonl")
    held, release = threading.Event(), threading.Event()

    def hold():
        with log.locked():
            held.set()
            release.wait(10)

    t = threading.Thread(target=hold)
    t.start()
    try:
        assert held.wait(5)
        before = tree(data)
        code, _, err = execute(capsys, data, export, ACC_A, "--lock-timeout", "0.3")
        assert code == 2 and "Nothing" in err
        assert (data / "tenants" / f"{ACC_A}.db").exists() and tree(data) == before
    finally:
        release.set()
        t.join()


def test_damaged_tenant_can_be_offboarded_only_with_the_explicit_flag(capsys, data, tmp_path):
    break_chain(data / "tenants" / f"{ACC_A}.db")
    export = tmp_path / "damaged"
    assert do_export(capsys, data, export, ACC_A, "--accept-damaged")[0] == 0
    assert execute(capsys, data, export)[0] == 1
    assert (data / "tenants" / f"{ACC_A}.db").exists()
    assert execute(capsys, data, export, ACC_A, "--accept-damaged")[0] == 0
    assert not (data / "tenants" / f"{ACC_A}.db").exists()


def test_domain_is_registered_in_the_top_level_cli(capsys, tmp_path):
    assert top_main(["tenant", "verify-export", str(tmp_path / "nope")]) == 2
    assert "tenant" in __import__("assurance.cli", fromlist=["_DOMAINS"])._DOMAINS
