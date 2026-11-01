"""The whole key ceremony, on throwaway keys in a temp directory, then the hosted API.

This is the rehearsal the founder approves before any real key exists. It runs the operator
workflow of ``deploy/assurance/KEY-CEREMONY.md`` through the real CLI, points a real server
on a real socket at what the ceremony produced, and shows both paid capabilities:

* NOT configured: counter-signing answers 503 ``no_attestation_key_configured`` and a
  hosted verification stays ``community`` however good the attestation is;
* configured: the same two requests are counter-signed and ``validated``; the signature
  checks against the public key the ceremony wrote, not against anything the server sent;
* then revoked: the same attestation stops lifting the tier.

It proves the software on invented inputs. It says nothing about any deployment, any real
key, or a customer: no key here is, or ever becomes, a production key.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.attest import HeadAttestation, SigningKey, VerifyingKey
from assurance.attest.cli import main
from assurance.machine.recorder_attestation import RecorderAttestation

from .interfaces_fixtures import LiveApi, live_api  # noqa: F401  (pytest fixture)
from .interfaces_support import envelope, envelope_dict, trace

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")

SERIAL = "0412"
KEY = f"Acme/AR-7#{SERIAL}"
PEM_VARS = ("ASSURANCE_ATTEST_KEY_PEM", "ASSURANCE_ATTEST_KEY", "ASSURANCE_ATTEST_PASSPHRASE")


class Ceremony:
    """The operator's steps, as commands, in a directory that is thrown away."""

    def __init__(self, root: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self.root, self.capsys = root, capsys
        self.service_key = root / "secrets" / "attest-service.pem"
        self.service_pub = root / "public" / "attest-service.pub"
        self.recorder_key = root / "recorder" / "recorder.pem"
        self.recorder_pub = root / "recorder" / "recorder.pub"
        self.trust = root / "config" / "recorder-trust.json"
        self.logs = root / "attestation-logs"
        self.outputs: list[str] = []

    def cli(self, *argv: object) -> tuple[int, str]:
        code = main([str(a) for a in argv])
        captured = self.capsys.readouterr()
        self.outputs += [captured.out, captured.err]
        return code, captured.out

    def keygen(self, priv: Path, pub: Path) -> str:
        code, out = self.cli("keygen", "--out", priv, "--public-out", pub, "--json")
        assert code == 0
        return str(json.loads(out)["fingerprint"])

    def run(self) -> tuple[str, str]:
        """Steps 1-5 of the ceremony. Returns (service fingerprint, recorder fingerprint)."""
        service_fp = self.keygen(self.service_key, self.service_pub)       # step 1, operator
        recorder_fp = self.keygen(self.recorder_key, self.recorder_pub)    # step 2, recorder side
        assert self.cli("trust-list", "create", "--trust", self.trust)[0] == 0        # step 3
        assert self.cli("trust-list", "add", "--trust", self.trust, "--public-key",
                        self.recorder_pub, "--label", "Rehearsal recorder", "--provenance",
                        "field", "--fingerprint", recorder_fp)[0] == 0                # step 4
        assert self.cli("trust-list", "verify-file", "--trust", self.trust)[0] == 0
        return service_fp, recorder_fp

    def configure(self, monkeypatch: pytest.MonkeyPatch, *, key: bool, trust: bool) -> None:
        for var in PEM_VARS:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)
        monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(self.logs))
        if key:
            # what a secrets manager does with the file: the PEM becomes the variable
            monkeypatch.setenv("ASSURANCE_ATTEST_KEY_PEM", self.service_key.read_text())
        if trust:
            monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(self.trust))

    def attestation_for(self, run_trace) -> dict:
        env = envelope()
        return RecorderAttestation.sign(
            run_trace, SigningKey.load(self.recorder_key), recorder_id="REC-REHEARSAL-1",
            product=env.product, product_version=env.product_version, machine_serial=SERIAL,
            attested_on=run_trace.started_at.date().isoformat()).to_dict()


@pytest.fixture
def ceremony(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Ceremony:
    return Ceremony(tmp_path / "ceremony", capsys)


def _verify(api: LiveApi, headers: dict[str, str], run_trace, attestation: dict | None):
    body = {"envelope": envelope_dict(), "trace": run_trace.hashable_payload(),
            "actor": "rehearsal engineer", "subject": KEY, "seal": False,
            "recorder_attestations": [attestation] if attestation else []}
    with api.client() as http:
        return http.post("/v1/machine/verify", json=body, headers=headers)


def _tier(response) -> str:
    assert response.status_code == 200, response.text
    return str(response.json()["tier"])


def _head() -> dict[str, int | str]:
    return {"ledger_length": 4, "head_seq": 4, "head_link_hash": "ab" * 32}


def test_the_ceremony_then_the_hosted_api_configured_and_not(
        ceremony: Ceremony, live_api: LiveApi, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    service_fp, recorder_fp = ceremony.run()
    started = datetime.now(UTC) - timedelta(days=2)
    run_trace = trace(started)
    attestation = ceremony.attestation_for(run_trace)
    _, headers = live_api.account("cell@example.invalid", "cell")

    # -- NOT configured: the documented 503 and the community cap ---------------------
    ceremony.configure(monkeypatch, key=False, trust=False)
    with live_api.client() as http:
        pre_key = http.get("/v1/ledger/attest/key")
        pre_sign = http.post("/v1/ledger/attest", json=_head(), headers=headers)
    assert pre_key.status_code == 503 and pre_sign.status_code == 503
    assert pre_sign.json()["detail"]["error"] == "no_attestation_key_configured"
    unconfigured = _verify(live_api, headers, run_trace, attestation)
    assert _tier(unconfigured) == "community", unconfigured.text

    # -- preflight on the same environment says so before a customer finds out ---------
    assert ceremony.cli("preflight", "--json")[0] == 1

    # -- configured by the ceremony ----------------------------------------------------
    ceremony.configure(monkeypatch, key=True, trust=True)
    code, out = ceremony.cli("preflight", "--expect-fingerprint", service_fp, "--json")
    report = json.loads(out)
    assert code == 0 and report["counter_signing"]["available"]
    assert report["validated_verification"]["available"]

    with live_api.client() as http:
        served = http.get("/v1/ledger/attest/key")
        signed = http.post("/v1/ledger/attest", json=_head(), headers=headers)
    assert served.status_code == 200 and served.json()["fingerprint"] == service_fp
    assert signed.status_code == 200, signed.text
    record = HeadAttestation.from_dict(signed.json()["attestation"])
    # checked against the key the ceremony WROTE, never one the server handed back
    assert record.verified_by(VerifyingKey.from_file(ceremony.service_pub))
    assert not record.verified_by(VerifyingKey.from_file(ceremony.recorder_pub))
    assert record.key_fingerprint == service_fp
    # the account's log, as the customer would be given it, verifies offline with the CLI
    [log_file] = list(ceremony.logs.glob("*.jsonl"))
    assert ceremony.cli("verify", "--log", log_file, "--public-key",
                        ceremony.service_pub)[0] == 0

    configured = _verify(live_api, headers, run_trace, attestation)
    assert _tier(configured) == "validated", configured.text
    assert configured.json()["recorder_attestation"]["status"] == "accepted"
    assert configured.json()["recorder_trust"]["status"] == "configured"
    # a trace nobody attested stays community even on a configured server
    assert _tier(_verify(live_api, headers, run_trace, None)) == "community"
    # an attestation by a key outside the list does not lift it
    stranger = SigningKey.generate()
    forged = RecorderAttestation.sign(
        run_trace, stranger, recorder_id="REC-X-0001", product=envelope().product,
        product_version=envelope().product_version, machine_serial=SERIAL,
        attested_on=started.date().isoformat()).to_dict()
    assert _tier(_verify(live_api, headers, run_trace, forged)) == "community"

    # -- revoked: the same attestation no longer lifts the tier ------------------------
    assert ceremony.cli("trust-list", "revoke", "--trust", ceremony.trust, "--fingerprint",
                        recorder_fp, "--effective", datetime.now(UTC).date().isoformat())[0] == 0
    revoked = _verify(live_api, headers, run_trace, attestation)
    assert _tier(revoked) == "community", revoked.text
    assert ceremony.cli("preflight", "--require", "validated")[0] == 1

    # -- nothing the ceremony printed contains either private key ----------------------
    everything = "\n".join(ceremony.outputs)
    for path in (ceremony.service_key, ceremony.recorder_key):
        assert "PRIVATE KEY" not in everything
        for line in path.read_text().splitlines():
            if line and not line.startswith("-----"):
                assert line not in everything


def test_a_broken_trust_file_on_the_server_fails_closed_and_preflight_agrees(
        ceremony: Ceremony, live_api: LiveApi, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    ceremony.run()
    run_trace = trace(datetime.now(UTC) - timedelta(days=2))
    attestation = ceremony.attestation_for(run_trace)
    _, headers = live_api.account("cell2@example.invalid", "cell")
    ceremony.configure(monkeypatch, key=True, trust=True)
    assert _tier(_verify(live_api, headers, run_trace, attestation)) == "validated"
    ceremony.trust.write_text("{ this is not a trust list")
    assert _tier(_verify(live_api, headers, run_trace, attestation)) == "community"
    assert ceremony.cli("preflight", "--require", "validated", "--json")[0] == 1
