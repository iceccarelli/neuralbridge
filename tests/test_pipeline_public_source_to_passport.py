"""The public-source pipeline, run end to end the way an operator runs it.

Public-source fixtures -> intel store -> watch -> a person opens a case -> the ``change`` verbs
-> a fresh verification -> a named person closes -> passport -> anchor -> verify, and then the
ways it must refuse to look healthy (a stale store, a tampered store, a truncated ledger).

Every step is a ``python -m assurance`` SUBPROCESS over real files in a temp directory. Nothing
is mocked and nothing reaches a network: the store is filled from the minimized / SYNTHETIC
payloads in ``tests/fixtures/intel`` (the equivalent of the contract-fixture transport, but with
no transport at all), and every subprocess starts with a ``sitecustomize`` that makes any socket
connect or DNS lookup raise, so an accidental fetch is a failing exit code, not a pass.

The one clock the CLI does not expose (``watch run`` has no ``--now``) is advanced the way the
runner's own tests do it: a subprocess whose ``assurance.watch.runner.utc_now`` is shifted
forward, running the same CLI entry point. It is used only with ``--dry-run`` so nothing it
writes carries a future timestamp.

What this proves: the pieces hand each other the right objects, each human act stays a human
act, and every "not established" statement the CLI makes is still made. What it does NOT prove:
that any advisory is true, that any machine is safe, anything about the live NVD / KEV / EPSS
services (``intel refresh --live`` is deliberately not exercised), or a deployed service. The
machines, trace, recorder and keys are throwaway synthetic ones.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import time
from datetime import UTC, datetime
from pathlib import Path

from assurance.change.store import CaseStore
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import manifests_from_ledger

from .intel_support import FIXTURES
from .interfaces_support import envelope, envelope_dict, trace
from .support_recorder import RECORDER
from .test_assurance_watch_intel import CVE, _plant

SRC = str(Path(__file__).resolve().parents[1] / "src")
ADVISORY_ID = f"nvd:{CVE}"
KEYS = ("Grimaldi/AR-7#CELL-0412", "Grimaldi/AR-7#CELL-0501")
DANA = ("--actor", "Dana Reviewer", "--role", "safety engineer")
GAP = 1.1          # manifests, cases and verifications are stamped to the second

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

#: The CLI entry point with only the watch's wall clock moved forward.
_SHIFTED = textwrap.dedent('''
    import datetime, sys
    import assurance.watch.runner as runner
    _real, _by = runner.utc_now, datetime.timedelta(hours=float(sys.argv.pop(1)))
    runner.utc_now = lambda: _real() + _by
    from assurance.cli import main
    raise SystemExit(main(sys.argv[1:]))
''')


class Operator:
    """A person at a shell in ``root``: every method is one command, run as a subprocess."""

    def __init__(self, root: Path, guard: Path) -> None:
        self.root, self.guard = root, guard

    def env(self) -> dict[str, str]:
        return {"PYTHONPATH": os.pathsep.join([str(self.guard), SRC]),
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"}

    def sh(self, *argv: object, expect: int | None = None,
           shift_hours: float | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-m", "assurance", *map(str, argv)]
        if shift_hours is not None:
            cmd = [sys.executable, "-c", _SHIFTED, str(shift_hours), *map(str, argv)]
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=self.root,  # noqa: S603
                           env=self.env(), check=False)
        if expect is not None:
            assert r.returncode == expect, (
                f"{' '.join(map(str, argv))}: exit {r.returncode}, wanted {expect}\n"
                f"--- stdout\n{r.stdout[-3000:]}\n--- stderr\n{r.stderr[-1500:]}")
        return r


def _guard(tmp_path: Path) -> Path:
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(_GUARD, encoding="utf-8")
    return guard


def _config(root: Path, *, sources: list[str], store: str = "intel.db",
            max_age_hours: float | None = 24, name: str = "watch.json") -> Path:
    body = json.loads((root / "watch.json").read_text(encoding="utf-8"))
    sub: dict = {"kind": "intel_store", "store": store, "sources": sources}
    if max_age_hours is not None:
        sub["max_age_hours"] = max_age_hours
    body["intel"] = [sub]
    (root / name).write_text(json.dumps(body), encoding="utf-8")
    return root / name


def _finding(run_json: str, advisory_id: str = ADVISORY_ID) -> dict:
    doc = json.loads(run_json)
    return next(f for f in doc["advisories"]["findings"] if f["advisory_id"] == advisory_id)


def _entries(ledger: Path) -> int:
    return len(EvidenceLedger(ledger).entries())


def _case_id(stdout: str) -> str:
    m = re.search(r"case (case-[0-9a-f]+): ", stdout)
    assert m, stdout
    return m.group(1)


def _item(ledger: Path, key: str) -> dict:
    items = manifests_from_ledger(EvidenceLedger(ledger), key)[-1].to_dict()["items"]
    return next(i for i in items if i["item_id"].endswith("ITM-PARAMS"))


def _remedy(root: Path, version: str) -> None:
    """The technician changes the parameter export on both machines."""
    for serial in ("CELL-0412", "CELL-0501"):
        f = root / "exports" / serial / "robot-params.json"
        body = json.loads(f.read_text(encoding="utf-8"))
        body["firmware"]["version"] = version
        f.write_text(json.dumps(body), encoding="utf-8")


# =====================================================================
def test_the_whole_pipeline(tmp_path):
    guard = _guard(tmp_path)
    root = tmp_path / "plant"
    root.mkdir()
    _plant(root, create_store=False)
    (root / "ev.db").unlink(missing_ok=True)          # the helper's unused ledger
    op = Operator(root, guard)
    ledger = root / "data" / "tenants" / "acc_0123456789abcdef.db"   # the layout anchor-all reads
    ledger.parent.mkdir(parents=True)
    keys = tmp_path / "keys"                                          # the signer's key, elsewhere
    keys.mkdir()
    led = ("--ledger", str(ledger))

    # -- 0. nothing fetches unless it is told to ---------------------------------------------
    r = op.sh("intel", "refresh", "--source", "kev", "--store", "intel.db", expect=2)
    assert "--live" in r.stderr and not (root / "intel.db").exists()

    # -- 1. intel ingest: local files into a store, with no network ---------------------------
    r = op.sh("intel", "ingest", "--store", "intel.db",
              "--nvd", FIXTURES / "nvd_synthetic.json", "--csaf", FIXTURES / "csaf_synthetic.json",
              "--kev", FIXTURES / "kev_min.json", "--epss", FIXTURES / "epss_min.json", expect=0)
    assert r.stdout.split().count("first") == 4
    r = op.sh("intel", "ingest", "--store", "intel.db", "--kev", FIXTURES / "kev_min.json",
              expect=0)
    assert "unchanged" in r.stdout                        # a byte-identical refresh is not news
    r = op.sh("intel", "show", "--store", "intel.db", "--cve", CVE, expect=0)
    assert "kev:  not_listed_in_kev" in r.stdout and "does not establish" in r.stdout
    assert "epss: unavailable" in r.stdout                # unknown, not zero
    _config(root, sources=["nvd", "csaf", "kev", "epss"])

    # -- 3. watch run: a finding for a person, inspect-only ------------------------------------
    # an empty fleet clears nothing: before any machine is sealed the watch is DEGRADED
    r = op.sh("watch", "run", "watch.json", *led, "--dry-run", "--json", expect=2)
    f = _finding(r.stdout)
    assert json.loads(r.stdout)["verdict"] == "degraded"
    assert (f["state"], f["impact"]) == ("not_assessed", "not_assessed")

    r = op.sh("watch", "run", "watch.json", *led, "--out", "run1.json", expect=1)
    run1 = (root / "run1.json").read_text(encoding="utf-8")
    assert json.loads(run1)["verdict"] == "findings"
    f = _finding(run1)
    assert (f["state"], f["inspect_only"]) == ("new", True)
    assert (f["trust_basis"], f["trust_state"]) == ("none", "unauthenticated_public_source")
    assert f["machines"] == [] and f["case_id"] == ""      # no consequence, no case
    assert set(f["inspect_machines"]) == set(KEYS)         # the machines a human must look at
    enrich = f["intel"]["enrichment"][0]                   # context, carried with citations
    assert enrich["kev"]["status"] == "not_listed_in_kev"
    assert "does not establish" in enrich["kev"]["not_established"]
    assert enrich["epss"]["status"] == "unavailable" and enrich["epss"]["score"] is None
    assert "did not change" in f["intel"]["enrichment_note"]
    assert CaseStore(EvidenceLedger(ledger)).list() == []
    for phrase in (
            "NOT TRUSTED", "inspect only, no consequence", f"new        {ADVISORY_ID}",
            "needs_review", "sealed: manifest PLAN-AR7-CELL-0412",
            "not that the fleet is unaffected",
            "absence from the KEV catalogue does not establish",
            "an unknown probability, not a score of 0.0",
            "unauthenticated public-source store read offline",
            "cause no stop-use, no intake and no automatic case",
            "No Article 14 duty is declared"):
        assert phrase in r.stdout, phrase
    assert CaseStore(EvidenceLedger(ledger)).list() == []   # the watch opened nothing

    # -- 4. watch open-case: only a named person --------------------------------------------
    open_args = ("watch", "open-case", "--config", "watch.json", *led, "--advisory-id", ADVISORY_ID)
    n0 = _entries(ledger)
    for who in ("automation", "watch", "system"):
        r = op.sh(*open_args, "--actor", who, "--role", "scheduler", expect=1)
        assert "named person" in r.stderr and "Nothing was opened" in r.stderr
    assert _entries(ledger) == n0 and CaseStore(EvidenceLedger(ledger)).list() == []

    r = op.sh(*open_args, *DANA, expect=0)
    assert "opened, status open" in r.stdout and "unauthenticated_public_source" in r.stdout
    for phrase in ("NOT established", "that the advisory is genuine",
                   "that a machine NOT listed is unaffected", "this command never does"):
        assert phrase in r.stdout, phrase
    cid = _case_id(r.stdout)
    n1 = _entries(ledger)
    assert n1 == n0 + 1                                     # exactly the case-opening record

    r = op.sh(*open_args, *DANA, expect=0)                  # idempotent
    assert "already open (nothing written)" in r.stdout and cid in r.stdout
    r = op.sh(*open_args, "--actor", "Eli Second", "--role", "lead", expect=0)
    assert cid in r.stdout and "Dana Reviewer" in r.stdout  # a second person: no re-attribution
    assert _entries(ledger) == n1
    shown = json.loads(op.sh("change", "show", cid, "--json", *led).stdout)
    assert shown["provenance"]["advisory_accepted_by"] == "Dana Reviewer"
    assert shown["provenance"]["advisory_trust"] == "unauthenticated_public_source"
    assert set(shown["machines"]) == set(KEYS) and shown["decision"] == ""
    r = op.sh("watch", "run", "watch.json", *led, "--json", expect=0)   # now outstanding, not new
    assert _finding(r.stdout)["state"] == "outstanding"

    # -- 5. the change verbs: claim -> advance -> intervention -> re-verify -> a person closes --
    r = op.sh("change", "decide", cid, "--disposition", "closed", "--reason", "too early",
              "--actor", "Eli Decider", *led, expect=1)
    assert r.stderr.startswith("finding:") and "ready_to_close" in r.stderr
    op.sh("change", "claim", cid, "--owner", "Dana Reviewer", "--actor", "Dana Reviewer", *led,
          expect=0)
    r = op.sh("change", "advance", cid, "--actor", "Dana Reviewer", *led, expect=0)
    assert "awaiting_action" in r.stdout
    r = op.sh("change", "advance", cid, "--actor", "Dana Reviewer", *led, expect=0)
    assert "awaiting_reverification" in r.stdout
    for key in KEYS:
        for fn in ("SF-01", "SF-02"):
            assert f"{key}/{fn}" in r.stdout            # four entries owed, by name

    time.sleep(GAP)
    before = {k: _item(ledger, k) for k in KEYS}
    assert {i["version"] for i in before.values()} == {"v2.001"}
    _remedy(root, "v2.002")
    op.sh("watch", "run", "watch.json", *led, expect=1)    # looks at the changed machines, seals
    after = {k: _item(ledger, k) for k in KEYS}
    assert all(after[k]["content_hash"] != before[k]["content_hash"] for k in KEYS)
    for n, key in enumerate(KEYS):
        (root / f"intervention-{n}.json").write_text(json.dumps({
            "intervention_id": f"INT-PIPE-{n}", "machine_key": key, "item_id": "ITM-PARAMS",
            "kind": "update", "occurred_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "performed_by": {"identifier": "m.tech", "role": "service technician",
                             "kind": "person"},
            "reason": "SYNTHETIC: apply the update the advisory points at",
            "from_hash": before[key]["content_hash"], "to_hash": after[key]["content_hash"],
            "affects_functions": ["SF-01", "SF-02"], "authorization": None,
            "revalidation": None, "notes": ""}), encoding="utf-8")
        r = op.sh("machinery", "record-change", *led, "--actor", "m.tech",
                  f"intervention-{n}.json", expect=0)
        assert "revalidated: NO" in r.stdout and "nothing was re-run" in r.stdout

    time.sleep(GAP)                                    # the verification must postdate the change
    (root / "envelope.json").write_text(json.dumps(envelope_dict()), encoding="utf-8")
    trust = RECORDER.write_trust(root / "recorder-trust.json")
    verdicts = []
    for n, key in enumerate(KEYS):
        serial = key.rpartition("#")[2]
        run = trace(datetime.now(UTC), trace_id=f"RUN-{serial}")
        (root / f"trace-{n}.json").write_text(json.dumps(run.hashable_payload()),
                                              encoding="utf-8")
        att = RECORDER.write_attestation(root / f"attestation-{n}.json", envelope(), run,
                                         machine_serial=serial)
        v = op.sh("machine", "verify", "--envelope", "envelope.json", "--trace",
                  f"trace-{n}.json", "--recorder-attestation", att, "--recorder-trust", trust,
                  "--actor", "Dana Reviewer", *led, "--subject", key, "--json", expect=0)
        bundle = json.loads(v.stdout)
        assert '"tier": "validated"' in v.stdout and '"verdict": "pass"' in v.stdout
        vhash = bundle["evidence"]["content_hash"]
        manifest = manifests_from_ledger(EvidenceLedger(ledger), key)[-1].to_dict()
        (root / f"manifest-{n}.json").write_text(json.dumps(manifest), encoding="utf-8")
        verdicts.append(op.sh(
            "change", "reverify", cid, "--manifest", f"manifest-{n}.json",
            "--verification-hash", vhash, "--actor", "Dana Reviewer", *led))
    first, second = verdicts
    assert first.returncode == 3                       # recorded, cleared nothing for 0501 yet
    assert "still outstanding: Grimaldi/AR-7#CELL-0501/SF-01" in first.stdout
    assert "blocked: evidence_not_current" in first.stdout
    assert second.returncode == 0 and "ready_to_close" in second.stdout, second.stdout

    ready = json.loads(op.sh("change", "show", cid, "--json", *led).stdout)
    assert ready["status"] == "ready_to_close" and ready["required_reverifications"] == []
    assert ready["decision"] == "" and ready["closed_at"] == ""   # re-verifying decided nothing
    assert ready["provenance"]["advisory_trust"] == "unauthenticated_public_source"
    for who in ((), ("--actor", "automation"), ("--actor", "bot")):
        r = op.sh("change", "decide", cid, "--disposition", "closed", "--reason", "auto-closed",
                  *who, *led, expect=1)
        assert "needs a named person" in r.stderr
    assert json.loads(op.sh("change", "show", cid, "--json", *led).stdout)["status"] \
        == "ready_to_close"
    r = op.sh("change", "decide", cid, "--disposition", "closed", "--reason",
              "Update applied and re-verified; advisory read against the publisher's page.",
              "--actor", "Eli Decider", *led, expect=0)
    assert "closed by Eli Decider" in r.stdout
    closed = json.loads(op.sh("change", "show", cid, "--json", *led).stdout)
    assert closed["status"] == "closed" and closed["decision_by"] == "Eli Decider"
    op.sh("change", "decide", cid, "--disposition", "closed", "--reason", "again",
          "--actor", "Eli Decider", *led, expect=1)
    r = op.sh("change", "show", cid, *led)
    assert "not established by this case" in r.stdout
    op.sh("change", "replay", cid, *led, expect=0)         # the ledger alone rebuilds the case

    # -- 6. passport, outsider check, bundle, art14 verify --------------------------------------
    for n, key in enumerate(KEYS):
        r = op.sh("machinery", "passport", *led, "--actor", "Dana Reviewer", f"manifest-{n}.json",
                  "--out", f"passport-{n}.json", expect=0)
        assert f"{key} — COVERED" in r.stdout and "at tier validated" in r.stdout
        assert "not checked:" in r.stdout and "does not confirm the manifest is complete" \
            in r.stdout
        r = op.sh("machinery", "check", *led, f"passport-{n}.json", expect=0)
        assert "OK" in r.stdout
    forged = json.loads((root / "passport-0.json").read_text(encoding="utf-8"))
    forged["evidence"]["body"]["coverage_verdict"] = "gaps"
    (root / "forged.json").write_text(json.dumps(forged), encoding="utf-8")
    assert op.sh("machinery", "check", *led, "forged.json").returncode != 0

    op.sh("change", "export", cid, *led, "--out", "case.json", expect=0)
    r = op.sh("evidence", "verify", "case.json", expect=0)
    assert "COMPLETENESS NOT CHECKED" in r.stdout        # unsigned: it says so
    r = op.sh("art14", *led, "verify", expect=0)
    assert "chain verified" in r.stdout and "detects accident, not a determined insider" in r.stdout

    # anchor: the signer's head is kept apart from the ledger, and the bundle is anchored
    op.sh("attest", "keygen", "--out", keys / "anchor.pem", expect=0)
    pub, log = keys / "anchor.pem.pub", root / "data" / "attestations" / "acc_0123456789abcdef.jsonl"
    r = op.sh("attest", "anchor-all", "--data-dir", root / "data", "--key", keys / "anchor.pem",
              expect=0)
    assert "anchored" in r.stdout and "NOT checked" in r.stdout
    r = op.sh("art14", *led, "verify", "--attestations", log, "--public-key", pub, expect=0)
    assert "completeness checked" in r.stdout
    op.sh("change", "export", cid, *led, "--attestations", log, "--out", "case-anchored.json",
          expect=0)
    r = op.sh("evidence", "verify", "case-anchored.json", "--public-key", pub,
              "--attestations", log, expect=3)         # a signed head alone is not completeness
    assert "NOT ESTABLISHED" in r.stdout and "carries no skeleton" in r.stdout
    op.sh("change", "export", cid, *led, "--attestations", log, "--skeleton", "--out",
          "case-complete.json", expect=0)
    r = op.sh("evidence", "verify", "case-complete.json", "--public-key", pub,
              "--attestations", log, expect=0)
    assert "NOT CHECKED" in r.stdout                   # and it still lists what it did not check

    # -- 7. staleness: the same watch, a clock past max_age_hours --------------------------------
    n_anchor = _entries(ledger)
    r = op.sh("watch", "run", "watch.json", *led, "--dry-run", "--json", shift_hours=1)
    assert r.returncode in (0, 1)                        # an hour on: fresh, not degraded
    r = op.sh("watch", "run", "watch.json", *led, "--dry-run", "--json", shift_hours=30, expect=2)
    doc = json.loads(r.stdout)
    feed = doc["advisories"]["feeds"][0]
    assert doc["verdict"] == "degraded" and feed["status"] == "stale"
    stale = " ".join(feed["problems"])
    assert "STALE" in stale and "limit is 24 h" in stale
    for source in ("'nvd'", "'csaf'", "'kev'", "'epss'"):
        assert source in stale
    r = op.sh("watch", "run", "watch.json", *led, "--dry-run", shift_hours=30, expect=2)
    assert "DEGRADED" in r.stdout and "STALE" in r.stdout

    # -- 8a. a tampered intel store is degraded, never quiet ------------------------------------
    shutil.copy(root / "intel.db", root / "intel-bad.db")
    db = sqlite3.connect(root / "intel-bad.db")
    # Chosen in Python: SQLite's LIKE on a BLOB column behaves differently across the SQLite
    # builds bundled with Python 3.11 and 3.13 (it matched nothing on 3.11).
    sha, body = next((r[0], bytes(r[1])) for r in db.execute("SELECT sha256, body FROM blobs")
                     if b"vulnerabilities" in bytes(r[1]) and b"CVE-2026-0001" in bytes(r[1]))
    broken = bytearray(body)
    broken[0] ^= 0x40                                    # '{' -> ';': no longer a document
    db.execute("DROP TRIGGER blobs_no_update")           # what bit-rot or an editor does
    db.execute("UPDATE blobs SET body = ? WHERE sha256 = ?", (bytes(broken), sha))
    db.commit()
    db.close()
    _config(root, sources=["nvd", "csaf", "kev", "epss"], store="intel-bad.db",
            name="watch-bad.json")
    r = op.sh("watch", "run", "watch-bad.json", *led, "--dry-run", "--json", expect=2)
    doc = json.loads(r.stdout)
    assert doc["verdict"] == "degraded"
    assert doc["advisories"]["feeds"][0]["status"] == "unreadable"
    assert any("could not be re-read" in p for p in doc["advisories"]["feeds"][0]["problems"])
    r = op.sh("watch", "run", "watch-bad.json", *led, "--dry-run", expect=2)
    assert "DEGRADED" in r.stdout

    # -- 8b. a truncated ledger after the anchor -------------------------------------------------
    assert _entries(ledger) == n_anchor                  # the dry runs above wrote nothing
    op.sh("art14", *led, "verify", "--attestations", log, "--public-key", pub, expect=0)
    db = sqlite3.connect(ledger)
    db.execute("DELETE FROM chain WHERE seq > ?", (n_anchor - 3,))
    db.commit()
    db.close()
    r = op.sh("art14", *led, "verify", "--attestations", log, "--public-key", pub, expect=1)
    assert "removed after they were signed for" in r.stderr and "Nothing was exported" in r.stderr
    r = op.sh("art14", *led, "verify", expect=0)           # the bare chain cannot see a cut tail:
    assert "detects accident, not a determined insider" in r.stdout   # and says so
    op.sh("art14", *led, "verify", "--attestations", log, expect=2)      # a key is required


# =====================================================================
def test_the_csaf_route_needs_the_unsigned_override_and_a_reason(tmp_path):
    root = tmp_path / "plant"
    root.mkdir()
    _plant(root, create_store=False, supplier="Example Controls GmbH", name="EX-100",
           version="V2.001", sources=("csaf",))
    (root / "ev.db").unlink(missing_ok=True)
    op = Operator(root, _guard(tmp_path))
    led = ("--ledger", str(root / "ledger.db"))
    op.sh("intel", "ingest", "--store", "intel.db", "--csaf", FIXTURES / "csaf_synthetic.json",
          expect=0)
    _config(root, sources=["csaf"], max_age_hours=None)
    op.sh("watch", "run", "watch.json", *led, expect=1)
    r = op.sh("watch", "run", "watch.json", *led, "--dry-run", "--json")
    finding = next(f for f in json.loads(r.stdout)["advisories"]["findings"] if f["inspect_only"])
    aid = finding["advisory_id"]
    assert finding["trust_basis"] == "none" and finding["machines"] == []
    # the store has no max_age_hours here: the run says that age was not judged
    assert "age of the intel store was NOT checked" in " ".join(
        json.loads(r.stdout)["checks_skipped"])

    args = ("watch", "open-case", "--config", "watch.json", *led, "--advisory-id", aid, *DANA)
    n0 = _entries(root / "ledger.db")
    assert "override explicitly" in op.sh(*args, expect=1).stderr
    assert "reason" in op.sh(*args, "--accept-unsigned", expect=1).stderr
    op.sh(*args, "--accept-unsigned", "--reason", "   ", expect=1)
    assert _entries(root / "ledger.db") == n0
    r = op.sh(*args, "--accept-unsigned", "--reason", "read against the vendor page", expect=0)
    assert "unsigned" in r.stdout.lower()
    shown = json.loads(op.sh("change", "show", _case_id(r.stdout), "--json", *led).stdout)
    assert shown["provenance"]["advisory_accept_reason"] == "read against the vendor page"
    assert shown["provenance"]["advisory_accepted_by"] == "Dana Reviewer"


# =====================================================================
def test_a_payload_bit_flip_that_stays_valid_json_is_degraded(tmp_path):
    root = tmp_path / "plant"
    root.mkdir()
    _plant(root, create_store=False)
    (root / "ev.db").unlink(missing_ok=True)
    op = Operator(root, _guard(tmp_path))
    led = ("--ledger", str(root / "ledger.db"))
    op.sh("intel", "ingest", "--store", "intel.db", "--nvd", FIXTURES / "nvd_synthetic.json",
          expect=0)
    _config(root, sources=["nvd"])
    op.sh("watch", "run", "watch.json", *led, expect=1)    # announced and sealed once
    db = sqlite3.connect(root / "intel.db")
    sha, body = db.execute("SELECT sha256, body FROM blobs").fetchone()
    flipped = bytearray(body)
    at = body.index(b"v2.001") + 5                       # the version digit: '1' -> '0'
    flipped[at] ^= 0x01
    json.loads(bytes(flipped))                           # still a valid document
    db.execute("DROP TRIGGER blobs_no_update")
    db.execute("UPDATE blobs SET body = ? WHERE sha256 = ?", (bytes(flipped), sha))
    db.commit()
    db.close()
    op.sh("watch", "run", "watch.json", *led, "--dry-run", expect=2)
