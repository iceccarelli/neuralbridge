"""The stateless check verbs on the command line: they say what the API says.

``check services | machine | fleet-machine``, ``fleet advisory-check`` and ``supplier trust
baseline`` call the same domain functions as ``POST /v1/check/...``, ``POST
/v1/fleet/advisory/check`` and ``POST /v1/supplier/trust/feed-baseline``. Each verb is run as a
real ``python -m assurance`` subprocess here, and its ``--json`` is compared with the body a real
server returns for the same input (the volatile ``assessed_at`` aside). Exit codes: 0 clear,
1 a finding, 2 could not run or could not vouch, 3 not established.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from assurance.attest.keys import SigningKey
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    IMPORT_ORIGINS,
    SEVERITY_SOURCES,
    TRUST_UNSIGNED_INSPECT_ONLY,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    ImportRecord,
)
from assurance.supplier.publish import AdvisoryFeed, SupplierIdentity, publish
from assurance.supplier.trust import SupplierTrustStore

from . import interfaces_fixtures as fx
from .interfaces_scenario import KEY, OTHER, Plant, cli_env

live_api = fx.live_api

CANARY = "sk-live-CANARY-0000-do-not-print"
NOW = datetime(2026, 9, 12, tzinfo=UTC)


# ------------------------------------------------------------------ helpers
def run(*argv: Any, stdin: str | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", *map(str, argv)], input=stdin, capture_output=True,
        text=True, cwd=cwd, env=cli_env(ASSURANCE_API_KEY=CANARY, ASSURANCE_KEY=CANARY),
        check=False)


def clean(done: subprocess.CompletedProcess[str]) -> None:
    """A refusal is a message, never a traceback, and never echoes a secret in the environment."""
    assert "Traceback" not in done.stderr + done.stdout, done.stderr
    assert CANARY not in done.stdout + done.stderr


def body(done: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert done.stdout.strip(), (done.returncode, done.stderr)
    return json.loads(done.stdout)


def volatile(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k != "assessed_at"}


def write(path: Path, doc: Any) -> Path:
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


def advisory_for(item: dict[str, Any], **over: Any) -> dict[str, Any]:
    """An advisory naming exactly this manifest item, hash and all: a match settled by hash."""
    adv = ComponentAdvisory(
        advisory_id="ROBO-2026-77", issued_by=item["supplier"], issued_at=NOW,
        title="Parameter export may omit the stop category", summary="s",
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(supplier=item["supplier"], name=item["name"],
                                   versions=(item["version"],) if item["version"] else (),
                                   content_hashes=(item["content_hash"],)),),
        remedy="Re-export with the 3.9.0 tool.", reference="https://roboco.example/a",
        fixed_versions=("3.9.0",), fixed_hashes=("f" * 64,))
    return {**adv.to_dict(), **over}


def unrelated_advisory(item: dict[str, Any]) -> dict[str, Any]:
    adv = ComponentAdvisory(
        advisory_id="ROBO-2026-78", issued_by=item["supplier"], issued_at=NOW, title="t",
        summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(supplier=item["supplier"], name=item["name"],
                                   versions=("9.9.9",), content_hashes=("d" * 64,)),),
        reference="https://roboco.example/b")
    return adv.to_dict()


def partial_advisory(item: dict[str, Any]) -> dict[str, Any]:
    record = ImportRecord(
        origin=IMPORT_ORIGINS[0], trust=TRUST_UNSIGNED_INSPECT_ONLY, partial=True, dropped=(),
        severity_source=SEVERITY_SOURCES[0], tlp="", tracking_status="draft",
        document_category="", document_date="", partial_reasons=("draft status",))
    # names a component this machine does not have, so nothing matches: the only reason the
    # answer is not a clear is that the translation dropped something
    base = ComponentAdvisory.from_dict({
        **unrelated_advisory(item),
        "affected": [{"supplier": "Nobody GmbH", "name": "Unrelated gizmo", "versions": ["1.0"],
                      "content_hashes": ["c" * 64]}]})
    return replace(base, import_record=record).to_dict()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def host(live: fx.LiveApi, ledger: Path, email: str) -> tuple[Any, dict[str, str], str]:
    """An account on the live API holding the same ledger bytes the CLI reads."""
    from assurance.api import deps

    account_id, headers = live.account(email)
    dest = deps.tenant_ledger_path(account_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ledger, dest)
    client = live.client()
    client.headers.update(headers)
    return client, headers, account_id


# ------------------------------------------------------------------ the plant
@pytest.fixture(scope="module")
def plant(tmp_path_factory) -> Plant:
    """Two enrolled machines, one drifted. Read-only for every test below."""
    p = Plant(tmp_path_factory.mktemp("check-verbs") / "plant")
    p.enrol_and_change("cli")
    return p


@pytest.fixture
def manifest(plant) -> dict[str, Any]:
    return plant.manifest_dict()


@pytest.fixture
def item(manifest) -> dict[str, Any]:
    return next(i for i in manifest["items"] if i["item_id"] == "ITM-PARAMS")


@pytest.fixture
def work(tmp_path) -> Path:
    d = tmp_path / "work"
    d.mkdir()
    return d


# ================================================================== check services
def test_services_lists_both_services_and_the_verdicts(work):
    done = run("check", "services", cwd=work)
    assert done.returncode == 0, done.stderr
    clean(done)
    for needle in ("machine_assurance_check", "fleet_machine_assurance", "no_impact_found",
                   "requires_human_review", "POST /v1/check/machine"):
        assert needle in done.stdout
    assert tree(work) == []                       # nothing was written anywhere


def test_services_json_is_the_api_body(live_api, work):
    done = run("check", "services", "--json", cwd=work)
    assert done.returncode == 0, done.stderr
    api = live_api.client().get("/v1/check/services")
    assert api.status_code == 200
    assert body(done) == api.json()
    assert tree(work) == []


def test_services_without_pydantic_is_could_not_run_not_a_traceback(monkeypatch, capsys):
    """The catalogue is generated from the request models. Without pydantic it says so (2)."""
    from assurance.check import cli as check_cli

    monkeypatch.setitem(sys.modules, "pydantic", None)
    monkeypatch.delitem(sys.modules, "assurance.check.schemas", raising=False)
    assert check_cli.main(["services"]) == 2
    err = capsys.readouterr().err
    assert "pydantic" in err and "Traceback" not in err


# ================================================================== check machine
def test_machine_a_match_is_a_finding(work, manifest, item):
    m, a = write(work / "m.json", manifest), write(work / "a.json", advisory_for(item))
    done = run("check", "machine", m, "--advisory", a, cwd=work)
    clean(done)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "ITM-PARAMS" in done.stdout and "hash" in done.stdout
    assert "not established:" in done.stdout
    assert "cannot say whether standing safety evidence" in done.stdout


def test_machine_no_match_is_clear_but_still_says_what_it_did_not_check(work, manifest, item):
    m, a = write(work / "m.json", manifest), write(work / "a.json", unrelated_advisory(item))
    done = run("check", "machine", m, "--advisory", a, cwd=work)
    clean(done)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "no_impact_found" in done.stdout
    assert "not established:" in done.stdout and "no ledger was supplied" in done.stdout
    assert "not a statement that the machine is safe" in done.stdout


def test_machine_a_partial_translation_is_not_established_not_clear(work, manifest, item):
    m, a = write(work / "m.json", manifest), write(work / "a.json", partial_advisory(item))
    done = run("check", "machine", m, "--advisory", a, cwd=work)
    clean(done)
    assert done.returncode == 3, done.stdout + done.stderr
    assert "cannot_determine" in done.stdout and "PARTIAL" in done.stdout


@pytest.mark.parametrize("which", ["manifest", "advisory"])
def test_machine_stdin_mode(work, manifest, item, which):
    m, a = write(work / "m.json", manifest), write(work / "a.json", advisory_for(item))
    if which == "manifest":
        done = run("check", "machine", "-", "--advisory", a, stdin=m.read_text(), cwd=work)
    else:
        done = run("check", "machine", m, "--advisory", "-", stdin=a.read_text(), cwd=work)
    clean(done)
    assert done.returncode == 1 and "ITM-PARAMS" in done.stdout


def test_machine_two_stdin_inputs_are_refused(work):
    done = run("check", "machine", "-", "--advisory", "-", stdin="{}", cwd=work)
    clean(done)
    assert done.returncode == 2 and "standard input can be read once" in done.stderr


@pytest.mark.parametrize("content", [
    '{"api_key": "' + CANARY,                  # truncated JSON that carries a secret
    "", "   \n", "[1, 2]", "null", "\xff\xfe not text",
    '{"items": []}',                           # valid JSON, not a manifest
])
def test_machine_malformed_manifest_is_refused_with_2_and_no_traceback(work, item, content):
    m = work / "m.json"
    m.write_bytes(content.encode("latin-1", "replace")) if content.startswith("\xff") \
        else write(m, content)
    a = write(work / "a.json", unrelated_advisory(item))
    done = run("check", "machine", m, "--advisory", a, cwd=work)
    clean(done)
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr.startswith("error:") and done.stdout == ""


def test_machine_malformed_advisory_and_missing_file_are_2(work, manifest):
    m = write(work / "m.json", manifest)
    bad = write(work / "bad.json", '{"advisory_id": "X"}')
    done = run("check", "machine", m, "--advisory", bad, cwd=work)
    clean(done)
    assert done.returncode == 2 and "not a valid advisory" in done.stderr
    done = run("check", "machine", m, "--advisory", work / "nope.json", cwd=work)
    clean(done)
    assert done.returncode == 2 and "cannot read the advisory" in done.stderr
    assert tree(work) == ["bad.json", "m.json"]


def test_machine_json_is_the_api_body(live_api, work, manifest, item):
    m, a = write(work / "m.json", manifest), write(work / "a.json", advisory_for(item))
    client = live_api.client()
    for adv in (advisory_for(item), unrelated_advisory(item), partial_advisory(item)):
        write(a, adv)
        done = run("check", "machine", m, "--advisory", a, "--json", cwd=work)
        clean(done)
        api = client.post("/v1/check/machine", json={"manifest": manifest, "advisory": adv})
        assert api.status_code == 200, api.text
        assert volatile(body(done)) == volatile(api.json())
        assert body(done)["checks_skipped"]                    # the "not established" list
    assert tree(work) == ["a.json", "m.json"]                  # no ledger, no report, no cache


# ================================================================== check fleet-machine
@pytest.fixture
def ledger(plant, tmp_path) -> Path:
    dest = tmp_path / "evidence.db"
    shutil.copy(plant.ledger_path, dest)
    return dest


def test_fleet_machine_a_finding_with_the_fleet_fan_out(work, ledger, item):
    a = write(work / "a.json", advisory_for(item))
    done = run("check", "fleet-machine", "--ledger", ledger, "--machine-key", KEY,
               "--advisory", a, cwd=work)
    clean(done)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "enrolled            yes" in done.stdout
    assert "enrolled machine(s) affected" in done.stdout
    assert "not established:" in done.stdout


def test_fleet_machine_without_an_advisory_reads_the_standing_evidence_only(work, ledger):
    done = run("check", "fleet-machine", "--ledger", ledger, "--machine-key", KEY, "--json",
               cwd=work)
    clean(done)
    doc = body(done)
    assert doc["enrolled"] is True and doc["advisory_evaluated"] is False
    # this plant has no verification on file: insufficient evidence is a finding, never a pass
    assert doc["verdict"] == "insufficient_evidence" and done.returncode == 1


def test_fleet_machine_stdin_advisory(work, ledger, item):
    done = run("check", "fleet-machine", "--ledger", ledger, "--machine-key", KEY,
               "--advisory", "-", stdin=json.dumps(advisory_for(item)), cwd=work)
    clean(done)
    assert done.returncode == 1 and "ITM-PARAMS" in done.stdout


def test_fleet_machine_not_enrolled_is_could_not_vouch(work, ledger):
    done = run("check", "fleet-machine", "--ledger", ledger, "--machine-key", "Nobody/X#1",
               cwd=work)
    clean(done)
    assert done.returncode == 2 and "is not enrolled" in done.stderr


def test_fleet_machine_missing_ledger_is_2_and_creates_nothing(work):
    nowhere = work / "sub" / "nothing.db"
    done = run("check", "fleet-machine", "--ledger", nowhere, "--machine-key", KEY, cwd=work)
    clean(done)
    assert done.returncode == 2 and "no ledger was created" in done.stderr
    assert tree(work) == []                                    # not even the parent directory


def test_fleet_machine_ledger_that_is_not_a_ledger_is_2(work):
    junk = write(work / "junk.db", "this is not a database")
    done = run("check", "fleet-machine", "--ledger", junk, "--machine-key", KEY, cwd=work)
    clean(done)
    assert done.returncode == 2


def test_fleet_machine_malformed_advisory_is_2(work, ledger):
    bad = write(work / "bad.json", "[]")
    done = run("check", "fleet-machine", "--ledger", ledger, "--machine-key", KEY,
               "--advisory", bad, cwd=work)
    clean(done)
    assert done.returncode == 2 and "must be a JSON object" in done.stderr


def test_fleet_machine_a_broken_chain_clears_nothing(work, plant, tmp_path, item):
    """A tampered ledger: an advisory that matches is still a finding (a broken chain can hide a
    record, never invent a match), but a check that found nothing must not read as clear."""
    broken = tmp_path / "broken.db"
    shutil.copy(plant.ledger_path, broken)
    db = sqlite3.connect(broken)
    try:
        with db:
            db.execute("UPDATE chain SET actor = 'mallory' WHERE seq = 3")
    finally:
        db.close()
    quiet = write(work / "quiet.json", unrelated_advisory(item))
    done = run("check", "fleet-machine", "--ledger", broken, "--machine-key", KEY,
               "--advisory", quiet, cwd=work)
    clean(done)
    assert done.returncode == 2, done.stdout + done.stderr
    assert "LEDGER CHAIN DOES NOT VERIFY" in done.stderr + done.stdout
    loud = write(work / "loud.json", advisory_for(item))
    done = run("check", "fleet-machine", "--ledger", broken, "--machine-key", KEY,
               "--advisory", loud, cwd=work)
    assert done.returncode == 1, done.stdout + done.stderr


def test_fleet_machine_reads_without_writing(work, ledger, item):
    a = write(work / "a.json", advisory_for(item))
    before = sha(ledger)
    for extra in ([], ["--json"]):
        done = run("check", "fleet-machine", "--ledger", ledger, "--machine-key", KEY,
                   "--advisory", a, *extra, cwd=work)
        clean(done)
    assert sha(ledger) == before                               # the ledger is not touched
    assert tree(work) == ["a.json"]


def test_fleet_machine_json_is_the_api_body(live_api, work, ledger, item):
    client, _, _ = host(live_api, ledger, "check-verbs@example.de")
    trust = live_api.root / "recorder-trust.json"               # the server's own trust list
    for adv in (None, advisory_for(item), unrelated_advisory(item)):
        argv: list[Any] = ["check", "fleet-machine", "--ledger", ledger, "--machine-key", KEY,
                           "--recorder-trust", trust, "--json"]
        payload: dict[str, Any] = {"machine_key": KEY}
        if adv is not None:
            argv += ["--advisory", write(work / "a.json", adv)]
            payload["advisory"] = adv
        done = run(*argv, cwd=work)
        clean(done)
        api = client.post("/v1/check/fleet-machine", json=payload)
        assert api.status_code == 200, api.text
        assert volatile(body(done)) == volatile(api.json())
        assert body(done)["checks_skipped"]
    other = client.post("/v1/check/fleet-machine", json={"machine_key": OTHER})
    assert other.status_code == 200


# ================================================================== fleet advisory-check
def test_advisory_check_a_match_is_a_finding(work, manifest, item):
    a, m = write(work / "a.json", advisory_for(item)), write(work / "m.json", manifest)
    done = run("fleet", "advisory-check", a, "--manifest", m, cwd=work)
    clean(done)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "AFFECTED" in done.stdout and "ITM-PARAMS" in done.stdout
    assert "not established:" in done.stdout and "that needs the ledger" in done.stdout


def test_advisory_check_no_match_is_clear(work, manifest, item):
    a, m = write(work / "a.json", unrelated_advisory(item)), write(work / "m.json", manifest)
    done = run("fleet", "advisory-check", a, "--manifest", m, cwd=work)
    clean(done)
    assert done.returncode == 0 and "no match" in done.stdout
    assert "not established:" in done.stdout


def test_advisory_check_an_unhashed_item_means_not_established_not_clear(work, manifest, item):
    """No match, but one item carries no hash: an affected component could be hiding in it."""
    m2 = json.loads(json.dumps(manifest))
    other = next(i for i in m2["items"] if i["item_id"] == "ITM-PLC")
    other["content_hash"], other["hash_source"] = "", "declared"
    a, m = write(work / "a.json", unrelated_advisory(item)), write(work / "m.json", m2)
    done = run("fleet", "advisory-check", a, "--manifest", m, cwd=work)
    clean(done)
    assert done.returncode == 3, done.stdout + done.stderr
    assert "NOT ESTABLISHED" in done.stdout and "carry no hash" in done.stdout


def test_advisory_check_a_partial_translation_is_not_established(work, manifest, item):
    a, m = write(work / "a.json", partial_advisory(item)), write(work / "m.json", manifest)
    done = run("fleet", "advisory-check", a, "--manifest", m, cwd=work)
    clean(done)
    assert done.returncode == 3 and "PARTIAL translation" in done.stdout


def test_advisory_check_stdin(work, manifest, item):
    m = write(work / "m.json", manifest)
    done = run("fleet", "advisory-check", "-", "--manifest", m,
               stdin=json.dumps(advisory_for(item)), cwd=work)
    clean(done)
    assert done.returncode == 1
    done = run("fleet", "advisory-check", "-", "--manifest", "-", stdin="{}", cwd=work)
    assert done.returncode == 2 and "standard input can be read once" in done.stderr


@pytest.mark.parametrize("content", ['{"advisory_id": "' + CANARY, "", "[]", "7", '{"x": 1}'])
def test_advisory_check_malformed_input_is_2_no_traceback(work, manifest, content):
    a, m = write(work / "a.json", content), write(work / "m.json", manifest)
    done = run("fleet", "advisory-check", a, "--manifest", m, cwd=work)
    clean(done)
    assert done.returncode == 2 and done.stdout == "" and done.stderr.startswith("error:")
    bad_manifest = write(work / "m2.json", content)
    done = run("fleet", "advisory-check", a, "--manifest", bad_manifest, cwd=work)
    clean(done)
    assert done.returncode == 2


def test_advisory_check_json_is_the_api_body_and_writes_nothing(live_api, work, manifest, item):
    _, headers = live_api.account("advisory-check@example.de")
    client = live_api.client()
    client.headers.update(headers)
    m = write(work / "m.json", manifest)
    for adv in (advisory_for(item), unrelated_advisory(item), partial_advisory(item)):
        a = write(work / "a.json", adv)
        done = run("fleet", "advisory-check", a, "--manifest", m, "--json", cwd=work)
        clean(done)
        api = client.post("/v1/fleet/advisory/check", json={"advisory": adv, "manifest": manifest})
        assert api.status_code == 200, api.text
        assert body(done) == api.json()
        assert body(done)["checks_skipped"]
    assert tree(work) == ["a.json", "m.json"]


# ================================================================== supplier trust baseline
IDENT = SupplierIdentity("controlco", "ControlCo GmbH", "the 2025 supply contract")


def adv(n: int) -> ComponentAdvisory:
    return ComponentAdvisory(
        advisory_id=f"ADV-{n}", issued_by="ControlCo GmbH", issued_at=NOW, title="t", summary="s",
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact("ControlCo GmbH", "SafeScan", versions=("4.0",)),),
        reference="https://example.invalid/x")


class Reissue:
    """An account that remembers a feed head 5 records long, and a feed re-issued shorter."""

    def __init__(self, root: Path) -> None:
        self.key = SigningKey.generate()
        self.ledger = root / "account.db"
        store = SupplierTrustStore(EvidenceLedger(self.ledger))
        store.pin("controlco", self.key.verifying.pem(), actor="a.engineer",
                  obtained_via="read aloud by ControlCo PSIRT on the phone",
                  effective_from=datetime(2020, 1, 1, tzinfo=UTC))
        store.record_feed_head("controlco", 5, "h" * 64)
        self.feed = AdvisoryFeed(root / "reissued.jsonl")
        for n in (1, 2, 3):
            publish(adv(n), IDENT, self.key, self.feed, now=NOW)
        self.root = root

    def head(self) -> tuple[int, str] | None:
        return SupplierTrustStore(EvidenceLedger.open_existing(self.ledger)).feed_head("controlco")


@pytest.fixture
def reissue(tmp_path) -> Reissue:
    root = tmp_path / "acct"
    root.mkdir()
    return Reissue(root)


def baseline_argv(r: Reissue, *extra: Any) -> list[Any]:
    return ["supplier", "trust", "baseline", "--ledger", r.ledger, "--feed", r.feed.path,
            "--actor", "m.braun", "--reason", "supplier re-issued its feed", *extra]


def test_baseline_before_the_reset_the_reissued_feed_is_not_trusted(reissue, work):
    done = run("supplier", "trust", "check", "--ledger", reissue.ledger, "--feed",
               reissue.feed.path, cwd=work)
    assert done.returncode == 1                           # rolled back against the remembered head


def test_baseline_accepts_a_trusted_reissued_feed(reissue, work):
    done = run(*baseline_argv(reissue), cwd=work)
    clean(done)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "baseline for controlco is now record 3" in done.stdout
    assert "does not make an untrusted feed trusted" in done.stdout
    head = reissue.head()
    assert head is not None and head[0] == 3
    # the feed is now judged on the new history
    again = run("supplier", "trust", "check", "--ledger", reissue.ledger, "--feed",
                reissue.feed.path, cwd=work)
    assert again.returncode == 0, again.stdout


def test_baseline_refuses_a_feed_that_would_not_be_trusted(reissue, tmp_path, work):
    """Signed by a key nobody pinned: never becomes the baseline, and nothing is written."""
    stranger = SigningKey.generate()
    feed = AdvisoryFeed(tmp_path / "stranger.jsonl")
    publish(adv(1), IDENT, stranger, feed, now=NOW)
    before = sha(reissue.ledger)
    done = run("supplier", "trust", "baseline", "--ledger", reissue.ledger, "--feed",
               feed.path, "--actor", "m.braun", "--reason", "r", cwd=work)
    clean(done)
    assert done.returncode == 1 and "cannot become the baseline" in done.stderr
    assert sha(reissue.ledger) == before and reissue.head() == (5, "h" * 64)
    # --public-key shows signatures are valid; it can never make an unpinned key eligible
    pub = write(tmp_path / "stranger.pub", stranger.verifying.pem())
    done = run("supplier", "trust", "baseline", "--ledger", reissue.ledger, "--feed",
               feed.path, "--actor", "m.braun", "--reason", "r", "--public-key", pub, cwd=work)
    assert done.returncode == 1 and sha(reissue.ledger) == before


def test_baseline_needs_a_reason(reissue, work):
    done = run("supplier", "trust", "baseline", "--ledger", reissue.ledger, "--feed",
               reissue.feed.path, "--actor", "m.braun", "--reason", "  ", cwd=work)
    clean(done)
    assert done.returncode == 1 and "needs a reason" in done.stderr
    assert reissue.head() == (5, "h" * 64)


def test_baseline_stdin_feed(reissue, work):
    done = run("supplier", "trust", "baseline", "--ledger", reissue.ledger, "--feed", "-",
               "--actor", "m.braun", "--reason", "re-issued", stdin=reissue.feed.path.read_text(),
               cwd=work)
    clean(done)
    assert done.returncode == 0, done.stdout + done.stderr
    head = reissue.head()
    assert head is not None and head[0] == 3


@pytest.mark.parametrize("content", ['{"sequence": "' + CANARY, "not json at all", '{"a": 1}\n[2]'])
def test_baseline_unreadable_feed_is_2_and_writes_nothing(reissue, work, content):
    bad = write(work / "bad.jsonl", content)
    before = sha(reissue.ledger)
    done = run("supplier", "trust", "baseline", "--ledger", reissue.ledger, "--feed", bad,
               "--actor", "m.braun", "--reason", "r", cwd=work)
    clean(done)
    assert done.returncode == 2 and "unreadable feed" in done.stderr
    assert sha(reissue.ledger) == before


def test_baseline_missing_ledger_is_2_and_creates_none(reissue, work):
    nowhere = work / "deep" / "nope.db"
    done = run("supplier", "trust", "baseline", "--ledger", nowhere, "--feed", reissue.feed.path,
               "--actor", "m.braun", "--reason", "r", cwd=work)
    clean(done)
    assert done.returncode == 2 and "no ledger was created" in done.stderr
    assert tree(work) == []


def test_baseline_json_is_the_api_body(live_api, reissue, work):
    client, _, account_id = host(live_api, reissue.ledger, "baseline@example.de")
    client.headers.update(live_api.operator_headers(account_id, "m.braun"))
    done = run(*baseline_argv(reissue, "--json"), cwd=work)
    clean(done)
    assert done.returncode == 0, done.stdout + done.stderr
    api = client.post("/v1/supplier/trust/feed-baseline", json={
        "feed": reissue.feed.path.read_text(encoding="utf-8"),
        "reason": "supplier re-issued its feed"})
    assert api.status_code == 200, api.text
    assert body(done) == api.json()
    assert body(done)["previous"] == {"sequence": 5, "head_hash": "h" * 64}
    assert "untrusted feed trusted" in body(done)["note"]
