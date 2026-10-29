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
