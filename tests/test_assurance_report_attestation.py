"""The report never calls a ledger attested because its own chain verifies."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

from assurance.attest.attestation import AttestationBasis, AttestationLog, attest, head_of
from assurance.attest.keys import SigningKey
from assurance.machinery.record import record_manifest
from assurance.report.cli import main as report_main
from assurance.report.render import ReportInput, render_report

from .test_assurance_change import fw, manifest
from .test_assurance_change import ledger as ledger  # noqa: F401  (fixture)


def _page(ledger, **kw):
    return render_report(ReportInput(ledger=ledger, **kw))


def _seed(ledger):
    record_manifest(ledger, manifest(fw(), manifest_id="M1"))


def test_a_chain_that_verifies_is_not_called_independently_attested(ledger):
    _seed(ledger)
    page = _page(ledger)
    assert "Ledger chain verifies" in page
    assert "No head attestation supplied" in page and "not independently attested" in page


def test_attestations_without_a_key_are_not_checked_and_say_so(ledger, tmp_path):
    _seed(ledger)
    log = AttestationLog(tmp_path / "att.jsonl")
    attest(ledger, SigningKey.generate(), log)
    page = _page(ledger, attestations=tuple(log.read()))
    assert "signatures NOT checked" in page
    assert "Head attestation verifies" not in page


def test_a_valid_attestation_under_a_supplied_key_is_reported_with_its_basis(
        ledger, tmp_path):
    _seed(ledger)
    key = SigningKey.generate()
    log = AttestationLog(tmp_path / "att.jsonl")
    attest(ledger, key, log)
    page = _page(ledger, attestations=tuple(log.read()), attestation_key=key.verifying)
    assert "Head attestation verifies" in page
    assert key.fingerprint in page
    assert "signer read from the ledger" in page
    assert "does not:</b> that the key belongs" in page


def test_a_counter_signature_is_labelled_as_a_declared_head(ledger, tmp_path):
    _seed(ledger)
    key = SigningKey.generate()
    log = AttestationLog(tmp_path / "att.jsonl")
    declared = replace(head_of(ledger), basis=AttestationBasis.DECLARED_BY_HOLDER)
    attest(declared, key, log)
    page = _page(ledger, attestations=tuple(log.read()), attestation_key=key.verifying)
    assert "declared to the signer (the signer did not read the ledger)" in page
    assert "signer read from the ledger" not in page


def test_a_ledger_rewound_after_attestation_makes_the_page_say_so(ledger, tmp_path):
    _seed(ledger)
    record_manifest(ledger, manifest(fw(), manifest_id="M2"))
    key = SigningKey.generate()
    log = AttestationLog(tmp_path / "att.jsonl")
    attest(ledger, key, log)
    db = sqlite3.connect(ledger.path)
    db.execute("DELETE FROM chain WHERE seq = (SELECT MAX(seq) FROM chain)")
    db.commit()
    db.close()
    from assurance.evidence.ledger import EvidenceLedger
    page = _page(EvidenceLedger(ledger.path), attestations=tuple(log.read()),
                 attestation_key=key.verifying)
    assert "DOES NOT VERIFY" in page and "removed after being attested" in page


def test_a_different_key_fails_closed(ledger, tmp_path):
    _seed(ledger)
    log = AttestationLog(tmp_path / "att.jsonl")
    attest(ledger, SigningKey.generate(), log)
    page = _page(ledger, attestations=tuple(log.read()),
                 attestation_key=SigningKey.generate().verifying)
    assert "HEAD ATTESTATION DOES NOT VERIFY" in page


def test_the_cli_takes_the_log_and_an_independent_key(ledger, tmp_path):
    _seed(ledger)
    key = SigningKey.generate()
    log = AttestationLog(tmp_path / "att.jsonl")
    attest(ledger, key, log)
    pub = tmp_path / "pub.pem"
    pub.write_text(key.verifying.pem())
    out = tmp_path / "r.html"
    assert report_main(["build", "--ledger", str(ledger.path), "--out", str(out),
                        "--attestations", str(tmp_path / "att.jsonl"),
                        "--attest-key", str(pub)]) == 0
    assert "Head attestation verifies" in out.read_text()
