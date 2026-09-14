"""The command line, driven the way it will be used.

These run the real entry point against a real ledger on disk. The CLI is what
somebody operates at 02:00 with a clock running, so "it imports" is not a
sufficient standard for it.
"""

from __future__ import annotations

import json

import pytest

from assurance.cli import main as top_main
from assurance.security.art14.cli import main as art14_main


@pytest.fixture()
def ledger_path(tmp_path):
    return str(tmp_path / "art14.db")


def run(ledger_path: str, *args: str) -> int:
    return art14_main(["--ledger", ledger_path, *args])


def _signal(ledger_path: str, case: str = "C1") -> int:
    return run(
        ledger_path,
        "signal",
        case,
        "--at",
        "2026-09-18T21:40:00Z",
        "--channel",
        "customer_or_integrator",
        "--description",
        "Integrator observed exploitation on a live line",
        "--reference",
        "TICKET-8812",
        "--by",
        "m.braun:Entwicklungsleitung",
    )


def _awareness(ledger_path: str, case: str = "C1") -> int:
    return run(
        ledger_path,
        "awareness",
        case,
        "--at",
        "2026-09-19T06:30:00Z",
        "--started",
        "2026-09-18T22:05:00Z",
        "--completed",
        "2026-09-19T06:30:00Z",
        "--track",
        "actively_exploited_vulnerability",
        "--because",
        "SIEM export shows a shell spawned from the service port",
        "--by",
        "m.braun:Entwicklungsleitung",
    )


def _triage(ledger_path: str, case: str = "C1") -> int:
    return run(
        ledger_path,
        "triage",
        case,
        "--answer",
        "is_our_product_with_digital_elements_on_the_eu_market=yes",
        "--answer",
        "reliable_evidence_of_malicious_exploitation=yes",
        "--answer",
        "exploited_in_our_product_not_merely_in_a_component=yes",
        "--answer",
        "awareness_of_active_exploitation_on_or_after_2026_09_11=yes",
        "--by",
        "m.braun:Entwicklungsleitung",
    )


def _payload(tmp_path, **overrides) -> str:
    payload = {
        "notification_type": "Vulnerability",
        "title": "Unauthenticated command injection on the service port",
        "summary": "Reachable on FW 2.1.0-2.4.6.",
        "product_name": "SK-4200 Palletising Cell",
        "product_version": "FW 2.1.0-2.4.6",
        "member_states_available": ["DE", "AT", "NL"],
        "awareness_datetime": "2026-09-19T06:30:00Z",
    }
    payload.update(overrides)
    path = tmp_path / "payload.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


class TestWorkflow:
    def test_full_case_through_the_cli(self, ledger_path, tmp_path, capsys):
        assert _signal(ledger_path) == 0
        assert "no deadline is running yet" in capsys.readouterr().out

        assert _awareness(ledger_path) == 0
        out = capsys.readouterr().out
        assert "2026-09-20T06:30:00Z" in out  # 24 h, Art. 14(2)(a)
        assert "2026-09-22T06:30:00Z" in out  # 72 h, Art. 14(2)(b)

        assert _triage(ledger_path) == 0
        assert "REPORTABLE" in capsys.readouterr().out

        assert (
            run(
                ledger_path,
                "file",
                "C1",
                "--stage",
                "early_warning",
                "--at",
                "2026-09-19T11:15:00Z",
                "--payload",
                _payload(tmp_path),
                "--reference",
                "SRP-2026-000123",
                "--by",
                "m.braun:Entwicklungsleitung",
            )
            == 0
        )
        assert "ready to submit" in capsys.readouterr().out

        assert run(ledger_path, "verify") == 0
        assert "chain verified" in capsys.readouterr().out

    def test_filing_with_a_bad_payload_exits_non_zero(self, ledger_path, tmp_path, capsys):
        _signal(ledger_path)
        _awareness(ledger_path)
        _triage(ledger_path)
        capsys.readouterr()
        # Switzerland is not a Member State. It matters for Art. 14(8), but it
        # is not what field 5 asks for.
        code = run(
            ledger_path,
            "file",
            "C1",
            "--stage",
            "early_warning",
            "--at",
            "2026-09-19T11:15:00Z",
            "--payload",
            _payload(tmp_path, member_states_available=["DE", "CH"]),
            "--by",
            "m.braun:Entwicklungsleitung",
        )
        assert code == 2
        assert "NOT submittable" in capsys.readouterr().out

    def test_measure_starts_the_final_clock(self, ledger_path, capsys):
        _signal(ledger_path)
        _awareness(ledger_path)
        _triage(ledger_path)
        capsys.readouterr()
        assert (
            run(
                ledger_path,
                "measure",
                "C1",
                "--at",
                "2026-09-30T16:00:00Z",
                "--description",
                "Documented workaround published",
                "--by",
                "m.braun:Entwicklungsleitung",
            )
            == 0
        )
        assert "2026-10-14T16:00:00Z" in capsys.readouterr().out

    def test_register_exits_non_zero_when_a_deadline_is_breached(self, ledger_path, capsys):
        # Anchored on 11 September 2026, the first day Article 14 applied. Its
        # 24-hour deadline is permanently in the past, so this test does not
        # change meaning as the wall clock moves.
        run(
            ledger_path,
            "signal",
            "OLD",
            "--at",
            "2026-09-11T00:00:00Z",
            "--channel",
            "national_csirt",
            "--description",
            "CSIRT notified us of exploitation in the field",
            "--by",
            "m.braun:Entwicklungsleitung",
        )
        run(
            ledger_path,
            "awareness",
            "OLD",
            "--at",
            "2026-09-11T02:00:00Z",
            "--started",
            "2026-09-11T00:10:00Z",
            "--completed",
            "2026-09-11T02:00:00Z",
            "--track",
            "actively_exploited_vulnerability",
            "--because",
            "CSIRT supplied indicators matching our telemetry",
            "--by",
            "m.braun:Entwicklungsleitung",
        )
        _triage(ledger_path, "OLD")
        capsys.readouterr()
        assert run(ledger_path, "register") == 1
        assert "BREACHES" in capsys.readouterr().out

    def test_register_exits_zero_when_nothing_is_overdue(self, ledger_path, capsys):
        assert run(ledger_path, "register") == 0
        assert "chain verified       yes" in capsys.readouterr().out


class TestStandaloneCommands:
    def test_fields_prints_the_specification(self, ledger_path, capsys):
        assert (
            run(
                ledger_path,
                "fields",
                "--track",
                "actively_exploited_vulnerability",
                "--stage",
                "early_warning",
            )
            == 0
        )
        out = capsys.readouterr().out
        assert "member_states_available" in out
        assert "platform gap" in out  # v26 is flagged

    def test_fields_json_is_machine_readable(self, ledger_path, capsys):
        run(
            ledger_path,
            "fields",
            "--track",
            "severe_incident",
            "--stage",
            "early_warning",
            "--json",
        )
        specs = json.loads(capsys.readouterr().out)
        assert any(s["number"] == "i31" and s["early_warning"] == "required" for s in specs)

    def test_validate_needs_no_ledger_state(self, ledger_path, tmp_path, capsys):
        assert (
            run(
                ledger_path,
                "validate",
                "--track",
                "actively_exploited_vulnerability",
                "--stage",
                "early_warning",
                "--payload",
                _payload(tmp_path),
            )
            == 0
        )
        assert "ready to submit" in capsys.readouterr().out


class TestGuardRails:
    def test_recording_without_an_attributed_actor_is_refused(self, ledger_path):
        with pytest.raises(SystemExit, match="not evidence"):
            run(
                ledger_path,
                "signal",
                "C1",
                "--description",
                "something happened",
            )

    def test_a_missing_payload_file_is_a_clear_error(self, ledger_path, tmp_path):
        with pytest.raises(SystemExit, match="does not exist"):
            run(
                ledger_path,
                "validate",
                "--track",
                "actively_exploited_vulnerability",
                "--stage",
                "early_warning",
                "--payload",
                str(tmp_path / "nope.json"),
            )

    def test_malformed_json_is_a_clear_error(self, ledger_path, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(SystemExit, match="not valid JSON"):
            run(
                ledger_path,
                "validate",
                "--track",
                "actively_exploited_vulnerability",
                "--stage",
                "early_warning",
                "--payload",
                str(bad),
            )


class TestExport:
    def test_export_writes_a_verifiable_bundle(self, ledger_path, tmp_path, capsys):
        _signal(ledger_path)
        _awareness(ledger_path)
        capsys.readouterr()
        out = tmp_path / "bundle.json"
        assert run(ledger_path, "export", "--case", "C1", "-o", str(out)) == 0
        bundle = json.loads(out.read_text(encoding="utf-8"))
        assert bundle["chain_verified"] is True
        assert len(bundle["entries"]) == 2


class TestTopLevel:
    def test_help_lists_the_domains(self, capsys):
        assert top_main([]) == 0
        assert "art14" in capsys.readouterr().out

    def test_unknown_domain_exits_non_zero(self, capsys):
        assert top_main(["nope"]) == 2
        assert "unknown domain" in capsys.readouterr().err
