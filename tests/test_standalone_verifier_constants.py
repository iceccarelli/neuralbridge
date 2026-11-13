"""``scripts/verify_export_standalone.py`` restates the product's hashing recipe and vocabularies so an
auditor can run it with no NeuralBridge code. Restating invites drift: this fails the moment the
product changes one of them without the standalone file. The adversarial behaviour of the file
is tested independently in ``neuralbridge-stress-test`` (``tests/test_standalone_verifier.py``).
"""
# ruff: noqa: S603  (runs this repository's own shipped script)
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from assurance.attest.attestation import ATTESTATION_FORMAT, AttestationBasis
from assurance.core.evidence import Confidence, ValidationState
from assurance.core.identity import HASH_PRECISION, content_hash_of
from assurance.evidence.ledger import GENESIS, LEDGER_SCHEMA_VERSION, EvidenceLedger
from assurance.evidence.verify_export import _ATTESTATION_FIELDS, _ENTRY_FIELDS, _TOP_LEVEL_FIELDS

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_export_standalone.py"


def _standalone():
    spec = importlib.util.spec_from_file_location("verify_export_standalone", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_standalone_file_restates_the_products_constants_exactly():
    s = _standalone()
    assert s.GENESIS == GENESIS and s.LEDGER_SCHEMA_VERSION == LEDGER_SCHEMA_VERSION
    assert s.HASH_PRECISION == HASH_PRECISION and s.ATTESTATION_FORMAT == ATTESTATION_FORMAT
    assert s.VALIDATION_STATES == {v.value for v in ValidationState}
    assert s.CONFIDENCES == {v.value for v in Confidence}
    assert s.BASES == {v.value for v in AttestationBasis}
    assert s.ENTRY_FIELDS == set(_ENTRY_FIELDS)
    assert s.HEAD_FIELDS == set(_ATTESTATION_FIELDS)
    # the standalone knows every top-level field except the skeleton ones, on purpose (exit 3)
    assert s.TOP_FIELDS == set(_TOP_LEVEL_FIELDS) - {"skeleton", "skeleton_truncated"}


def test_the_standalone_hash_is_the_products_hash_on_awkward_values():
    s = _standalone()
    for value in ({"a": 1, "b": [1.0, 2, {"c": -0.0}]}, {"x": 0.1 + 0.2}, {"n": 10**15}, [], {}):
        assert s.content_hash(value) == content_hash_of(value)


def test_it_verifies_a_real_export_and_refuses_the_same_export_edited(tmp_path):
    ledger = EvidenceLedger(tmp_path / "l.db")
    from assurance.core.evidence import Actor, Evidence, Origin
    for n in range(3):
        ledger.append(Evidence(
            kind="signal", body={"n": n, "note": f"synthetic {n}"},
            actor=Actor("t.analyst", "analyst", "person"), origin=Origin("test")).seal(),
            subject=f"C{n}")
    out = tmp_path / "e.json"
    out.write_text(json.dumps(ledger.export()), encoding="utf-8")
    run = subprocess.run([sys.executable, str(SCRIPT), str(out)], capture_output=True, text=True)
    assert run.returncode == 3 and "COMPLETENESS NOT CHECKED" in run.stdout     # honest, not a pass
    doc = json.loads(out.read_text())
    doc["entries"][1]["evidence"]["body"]["note"] = "edited"
    out.write_text(json.dumps(doc))
    run = subprocess.run([sys.executable, str(SCRIPT), str(out)], capture_output=True, text=True)
    assert run.returncode == 1 and "edited" in run.stdout


def test_the_standalone_file_accepts_a_v2_anchor_and_says_what_it_could_not_bind(tmp_path):
    """A head attested for a ledger that has an id is v2. The standalone verifier must verify it (it used to
    reject every such anchor) and must say a bundle cannot show which ledger the anchor was signed for."""
    from assurance.attest import AttestationLog, SigningKey, attest
    from assurance.core.evidence import Actor, Evidence, Origin

    ledger = EvidenceLedger(tmp_path / "l.db")
    for n in range(3):
        ledger.append(Evidence(
            kind="signal", body={"n": n, "note": f"synthetic {n}"},
            actor=Actor("t.analyst", "analyst", "person"), origin=Origin("test")).seal(), subject=f"C{n}")
    key = SigningKey.generate()
    att = attest(ledger, key, AttestationLog(tmp_path / "log.jsonl"))
    assert att.format.endswith(".v2")
    pub = tmp_path / "signer.pub"
    pub.write_text(key.verifying.pem(), encoding="ascii")
    out = tmp_path / "e.json"
    out.write_text(json.dumps(ledger.export(anchor=att.to_dict())), encoding="utf-8")
    run = subprocess.run([sys.executable, str(SCRIPT), str(out), "--public-key", str(pub), "--json"],
                         capture_output=True, text=True)
    doc = json.loads(run.stdout)
    assert run.returncode == 0, run.stdout
    assert any("NOT checked" in a for a in doc["assumed"]), doc["assumed"]
    # editing the signed ledger_id is a forged anchor, not a quiet downgrade
    bundle = json.loads(out.read_text())
    bundle["anchor"]["ledger_id"] = "someone-else"
    out.write_text(json.dumps(bundle))
    run = subprocess.run([sys.executable, str(SCRIPT), str(out), "--public-key", str(pub)],
                         capture_output=True, text=True)
    assert run.returncode == 1


# --- the canonicalisation recipe documented in ATTEST.md is the recipe the code implements -------
_VECTORS = [
    ({"b": 1, "a": [2.5, -0.0, "é"], "c": {"z": 0.1234567}, "t": True},
     '{"a":[2.5,0.0,"\\u00e9"],"b":1.0,"c":{"z":0.123457},"t":true}',
     "8f45042f5f1c62124bab8111f7f69d43b09553a944a0e2fa41111f314e802bf8"),
    ({"x": 10**16, "y": 1e-07, "n": None},
     '{"n":null,"x":1e+16,"y":0.0}',
     "fefde0fdef586a2ed3a1f5dcd293f7e26be012ae91936b7f0b56300945bf43fc"),
]


def test_the_documented_test_vectors_are_what_both_implementations_produce():
    from assurance.core.identity import canonical_json
    from assurance.evidence.ledger import LedgerEntry

    s = _standalone()
    doc = (Path(__file__).resolve().parents[1] / "deploy" / "assurance" / "ATTEST.md").read_text(
        encoding="utf-8")
    for value, canon, digest in _VECTORS:
        assert canonical_json(value) == canon
        assert content_hash_of(value) == digest == s.content_hash(value)
        assert digest in doc and canon in doc
    link = LedgerEntry(seq=1, at="2026-01-02T03:04:05Z", kind="t.record", subject="CASE-A",
                       content_hash="a" * 64, prev_hash=GENESIS, link_hash="", actor="", payload={})
    assert link.expected_link_hash() == "9a3020f18b95f8c255564b171c7a4f7e61d4fed65627009f87380457446aa613"
    assert link.expected_link_hash() in doc


def test_the_documented_attestation_bytes_are_what_the_signer_signs():
    from assurance.attest.attestation import HeadAttestation

    att = HeadAttestation(
        format=ATTESTATION_FORMAT, sequence=1, ledger_length=3, head_seq=3, head_link_hash="b" * 64,
        basis=AttestationBasis.READ_FROM_LEDGER, attested_at="2026-01-02T03:04:05Z",
        key_fingerprint="0123456789abcdef", previous="", note="")
    doc = (Path(__file__).resolve().parents[1] / "deploy" / "assurance" / "ATTEST.md").read_text(
        encoding="utf-8")
    shown = att.signed_payload().decode().replace("b" * 64, "bbbb...b (64)")
    assert shown in doc
