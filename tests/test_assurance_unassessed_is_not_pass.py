"""An evidence position nobody assessed must never read as one that passed.

Regression (independent review of a135c0e, finding H1): ``check_declaration`` fell through to
``describes_the_machine`` with the fixed statement "... and every declared safety function
has evidence that still stands" when its ``coverage`` argument was ``None`` -- and the
anonymous, ungated ``POST /v1/fleet/declaration/check`` passes ``None`` by default
(``with_coverage`` is false), and also when ``with_coverage`` is true but the caller has no
plan that reads the ledger. The same sentence was produced for a manifest that declares no
safety function at all (vacuous truth) and for a coverage report over zero functions.

``unchecked`` is a valid outcome; "described" is not. The verdict for "the configuration is
the declared one and the evidence was not assessed" is its own value, it is not ``is_sound``,
it says plainly that the evidence was not assessed, and the CLI exits 2 ("could not vouch")
for it, not 0.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.fleet.cli import main as fleet_cli
from assurance.fleet.declaration import (
    DeclarationOfConformity,
    DeclarationVerdict,
    check_declaration,
)
from assurance.machinery.record import interventions_from_ledger, record_manifest
from assurance.machinery.staleness import VerificationRecord, assess_coverage

from .support_recorder import server_trust, with_attestation
from .support_trust_hardening import KEY, attested_bundle, ledger, manifest
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_recorder_attestation import envelope as att_envelope
from .test_assurance_recorder_attestation import make_trace

client, store = _client, _store

NOT_ASSESSED = "configuration_matches_coverage_not_assessed"
URL = "/v1/fleet/declaration/check"


def _doc(man):
    return DeclarationOfConformity.bind(
        man, doc_id="DOC-1", issued_by="Grimaldi",
        issued_at=datetime(2026, 1, 20, tzinfo=UTC),
        legislation=("Regulation (EU) 2023/1230",))


def _payload(man, **extra):
    return {"declaration": _doc(man).to_dict(), "manifest": man.to_dict(), **extra}


def _assert_not_a_pass(d: dict) -> None:
    assert d["verdict"] == NOT_ASSESSED
    assert d["evidence_assessed"] is False
    assert d["coverage_assessed"] is False
    # the fixed sentence of the old pass verdict is not said about evidence nobody looked at
    assert "still stands" not in d["statement"]
    assert "evidence that still stands" not in d["statement"]
    assert d["lapsed_functions"] == []


class TestTheLibrary:
    def test_no_coverage_is_its_own_verdict_and_not_sound(self):
        man = manifest()
        s = check_declaration(_doc(man), man, None)
        assert s.verdict.value == NOT_ASSESSED
        assert s.verdict is not DeclarationVerdict.DESCRIBES_THE_MACHINE
        assert s.is_sound is False
        assert s.evidence_assessed is False
        assert s.to_dict()["evidence_assessed"] is False
        assert "still stands" not in s.statement

    def test_a_manifest_with_no_functions_has_nothing_to_stand(self):
        """Vacuous truth: 'every declared function has evidence' over zero functions."""
        man = manifest(functions=False)
        for coverage in (None, assess_coverage(man, [], [])):
            s = check_declaration(_doc(man), man, coverage)
            assert s.verdict.value == NOT_ASSESSED
            assert s.is_sound is False
            assert s.evidence_assessed is False
            assert "still stands" not in s.statement

    def test_a_coverage_report_over_zero_functions_assesses_nothing(self):
        man = manifest()
        empty = assess_coverage(manifest(functions=False), [], [])
        s = check_declaration(_doc(man), man, empty)
        assert s.verdict.value == NOT_ASSESSED
        assert s.evidence_assessed is False

    def test_a_coverage_report_for_another_configuration_assesses_nothing(self):
        man = manifest()
        other = manifest(serial="0002")
        s = check_declaration(_doc(man), man, assess_coverage(other, [], []))
        assert s.verdict.value == NOT_ASSESSED
        assert s.evidence_assessed is False

    def test_a_coverage_report_for_the_same_machine_at_another_configuration_is_not_used(self):
        man = manifest()
        other_config = assess_coverage(manifest(fw="b" * 64), [], [])
        assert other_config.machine_key == man.machine.key
        s = check_declaration(_doc(man), man, other_config)
        assert s.verdict.value == NOT_ASSESSED
        assert s.evidence_assessed is False

    def test_a_changed_configuration_says_whether_the_evidence_was_assessed(self):
        man, changed = manifest(), manifest(fw="b" * 64)
        none = check_declaration(_doc(man), changed, None)
        assert none.verdict.value == "configuration_changed"
        assert none.evidence_assessed is False
        looked = check_declaration(_doc(man), changed, assess_coverage(changed, [], []))
        assert looked.verdict.value == "configuration_changed"
        assert looked.evidence_assessed is True
        assert looked.lapsed_functions == ("SF-1",)

    def test_the_other_verdicts_are_unchanged(self):
        man = manifest()
        changed = check_declaration(_doc(man), manifest(fw="b" * 64), None)
        assert changed.verdict.value == "configuration_changed"
        wrong = check_declaration(_doc(man), manifest(serial="0002"), None)
        assert wrong.verdict.value == "wrong_machine"

    def test_the_not_assessed_statement_names_what_was_not_done(self):
        man = manifest()
        s = check_declaration(_doc(man), man, None)
        assert s.checks_skipped
        assert any("coverage" in c for c in s.checks_skipped)


class TestTheAnonymousRoute:
    """Reachable with no key, by default."""

    def test_default_request_is_not_a_pass(self, client):
        r = client.post(URL, json=_payload(manifest()))
        assert r.status_code == 200
        _assert_not_a_pass(r.json())

    def test_anonymous_with_coverage_requested_is_not_a_pass(self, client):
        r = client.post(URL, json=_payload(manifest(), with_coverage=True))
        assert r.status_code == 200
        _assert_not_a_pass(r.json())

    def test_authenticated_without_a_plan_that_reads_the_ledger_is_not_a_pass(
            self, client, store):
        r = client.post(URL, json=_payload(manifest(), with_coverage=True),
                        headers=keyed(store, "register"))
        assert r.status_code == 200
        _assert_not_a_pass(r.json())
        assert any("needs a plan" in c for c in r.json()["checks_skipped"])

    def test_entitled_but_manifest_declares_no_function_is_not_a_pass(self, client, store):
        r = client.post(URL, json=_payload(manifest(functions=False), with_coverage=True),
                        headers=keyed(store, "cell"))
        assert r.status_code == 200
        d = r.json()
        assert d["verdict"] == NOT_ASSESSED
        assert d["evidence_assessed"] is False
        assert "still stands" not in d["statement"]

    def test_entitled_with_no_evidence_in_the_ledger_is_lapsed_not_described(
            self, client, store):
        """The ledger was read and holds nothing: that IS an assessment, and it is a lapse."""
        man = manifest()
        h = keyed(store, "cell")
        r = client.post(URL, json=_payload(man, with_coverage=True), headers=h)
        d = r.json()
        assert d["evidence_assessed"] is True
        assert d["verdict"] == "configuration_intact_evidence_lapsed"
        assert d["lapsed_functions"] == ["SF-1"]

    def test_control_assessed_and_standing_evidence_is_still_described(
            self, client, store, monkeypatch, tmp_path):
        """The honest pass still exists: a ledger read, a function covered at 'validated'."""
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        man = manifest()
        assert client.post("/v1/machinery/manifest", json={"manifest": man.to_dict()},
                           headers=h).status_code == 200
        env, tr = att_envelope(), make_trace()
        v = client.post("/v1/machine/verify", json=with_attestation({
            "envelope": env.to_dict(), "trace": tr.hashable_payload(),
            "actor": "a.integrator", "subject": KEY}, env, tr, machine_serial="0001"),
            headers=h)
        assert v.status_code == 200, v.text
        assert v.json()["tier"] == "validated"
        r = client.post(URL, json=_payload(man, with_coverage=True), headers=h)
        d = r.json()
        assert d["evidence_assessed"] is True and d["coverage_assessed"] is True
        assert d["verdict"] == "describes_the_machine"
        assert d["lapsed_functions"] == []


class TestTheCli:
    def _files(self, tmp_path: Path, man) -> tuple[Path, Path]:
        m, d = tmp_path / "manifest.json", tmp_path / "doc.json"
        m.write_text(json.dumps(man.to_dict()), encoding="utf-8")
        d.write_text(json.dumps(_doc(man).to_dict()), encoding="utf-8")
        return m, d

    def test_without_a_ledger_it_exits_2_not_0(self, tmp_path, capsys):
        m, d = self._files(tmp_path, manifest())
        rc = fleet_cli(["declaration", str(d), "--manifest", str(m), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["verdict"] == NOT_ASSESSED
        assert out["evidence_assessed"] is False
        assert rc == 2

    def test_control_with_a_ledger_holding_validated_evidence_exits_0(
            self, tmp_path, capsys):
        man = manifest()
        m, d = self._files(tmp_path, man)
        led = ledger(tmp_path)
        record_manifest(led, man)
        attested_bundle(KEY, file_under=led)
        rc = fleet_cli(["declaration", str(d), "--manifest", str(m),
                        "--ledger", str(tmp_path / "ledger.db"), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["verdict"] == "describes_the_machine"
        assert out["evidence_assessed"] is True
        assert rc == 0
        # and the ledger really did hold covered evidence
        cov = assess_coverage(man, VerificationRecord.from_ledger(led, subject=KEY),
                              interventions_from_ledger(led, KEY))
        assert cov.verdict == "covered"


@pytest.mark.parametrize("coverage_present", [False, True])
def test_describes_the_machine_requires_assessed_nonempty_evidence(coverage_present):
    man = manifest()
    cov = assess_coverage(man, [], []) if coverage_present else None
    s = check_declaration(_doc(man), man, cov)
    assert s.verdict is not DeclarationVerdict.DESCRIBES_THE_MACHINE
