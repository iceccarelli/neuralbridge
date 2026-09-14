"""The kit that runs inside somebody else's plant, and the claim it has to prove.

Two things here are load-bearing and neither is about collection. The first is
that the airgap guard actually catches a real HTTP client rather than a
hand-rolled socket call, because a guard that only stops the calls you thought
of is worse than none. The second is the whole commercial loop end to end: an
offline run produces three numbers, a party who has never seen the ledger signs
them, and a rewind of that ledger afterwards is caught by joining the two back
together.
"""

from __future__ import annotations

import json
import socket
import urllib.request

import pytest

from assurance.attest import (
    AttestationLog,
    HeadAttestation,
    SigningKey,
    attest,
    verify_log,
)
from assurance.evidence.ledger import EvidenceLedger
from assurance.kit.airgap import AIRGAP_LIMITS, AirgapError, no_network
from assurance.kit.enrol import (
    AIRGAP_KIND,
    KIT_RUN_KIND,
    KitConfig,
    KitError,
    MachineEntry,
    run_kit,
    starter_config,
)

from .test_assurance_collect import plan_dict, write_export


def _plan_file(tmp_path, **over):
    d = plan_dict()
    d["manufacturer"] = "Grimaldi"
    d["model"] = "AR-7"
    d.update(over)
    p = tmp_path / "plans" / "cell.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d), encoding="utf-8")
    return p


def _kit(tmp_path, serials=("CELL-0412",), **over):
    _plan_file(tmp_path)
    for n, serial in enumerate(serials):
        write_export(tmp_path / "exports" / serial,
                     stamp="2026-09-14T06:02:11Z", operator="m.keller",
                     seq=f"004{n}")
    body = {
        "kit_id": "test-kit",
        "organisation": "Grimaldi Engineering S.r.l.",
        "site": "Plant 1",
        "country": "IT",
        "prepared_by": "v.grimaldi@example.com",
        "role": "integrator",
        "machines": [
            {"serial": s, "plan": "plans/cell.json", "exports": f"exports/{s}"}
            for s in serials
        ],
    }
    body.update(over)
    path = tmp_path / "kit.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


# =====================================================================
class TestAirgap:
    def test_a_real_http_client_is_stopped_not_just_a_raw_socket(self):
        """urllib, not socket.connect by hand. A guard that only catches the
        obvious call is a guard nobody should trust."""
        with no_network() as result:
            # Not URLError: the refusal is not an OSError, so urllib does not
            # wrap it and no client can mistake it for a transient failure and
            # retry. That is the point — see AirgapError's docstring.
            with pytest.raises(AirgapError):
                urllib.request.urlopen("http://example.com", timeout=1)
        assert not result.held
        assert len(result.attempts) == 1
        assert "example.com" in result.attempts[0].target

    def test_the_attempt_names_the_line_that_made_it(self):
        with no_network() as result:
            with pytest.raises(AirgapError):
                socket.create_connection(("192.0.2.1", 443), timeout=1)
        caller = result.attempts[0].caller
        assert "test_assurance_kit.py" in caller

    def test_name_resolution_alone_is_refused(self):
        """Resolving a name has already told a DNS server something."""
        with no_network() as result:
            with pytest.raises(AirgapError):
                socket.getaddrinfo("telemetry.example.com", 443)
        assert result.attempts[0].api == "socket.getaddrinfo"

    def test_a_quiet_run_holds(self):
        with no_network() as result:
            sum(range(1000))
        assert result.held
        assert "No outbound connection was attempted" in result.summary()

    def test_the_guard_is_released_even_when_the_block_raises(self):
        with pytest.raises(ValueError):
            with no_network():
                raise ValueError("boom")
        # If the guard leaked, this would raise instead of resolving.
        assert socket.getaddrinfo("localhost", 80)

    def test_loopback_can_be_allowed_and_is_recorded_either_way(self):
        with no_network(allow_loopback=True) as result:
            with pytest.raises(AirgapError):
                socket.getaddrinfo("elsewhere.example.com", 443)
            try:
                socket.create_connection(("127.0.0.1", 1), timeout=0.1)
            except OSError:
                pass  # nothing listening; the guard let it through, which is the point
        assert result.loopback_allowed
        assert result.loopback_used
        assert len(result.attempts) == 1

    def test_the_limits_travel_with_the_result(self):
        with no_network() as result:
            pass
        assert result.to_dict()["limits"] == list(AIRGAP_LIMITS)
        assert any("subprocess" in limit for limit in AIRGAP_LIMITS)
        assert any("firewall" in limit for limit in AIRGAP_LIMITS)


# =====================================================================
class TestConfig:
    def test_a_template_value_never_reaches_a_report(self, tmp_path):
        path = _kit(tmp_path, organisation="YOUR COMPANY GmbH")
        with pytest.raises(KitError, match="placeholder"):
            KitConfig.from_json(path)

    def test_an_unattributed_kit_is_refused(self, tmp_path):
        path = _kit(tmp_path, prepared_by="")
        with pytest.raises(KitError, match="prepared_by"):
            KitConfig.from_json(path)

    def test_two_machines_may_not_share_a_serial(self, tmp_path):
        path = _kit(tmp_path)
        body = json.loads(path.read_text())
        body["machines"].append(dict(body["machines"][0]))
        path.write_text(json.dumps(body))
        with pytest.raises(KitError, match="twice"):
            KitConfig.from_json(path)

    def test_a_malformed_country_is_refused_because_it_moves_a_deadline(self, tmp_path):
        path = _kit(tmp_path, country="ITA")
        with pytest.raises(KitError, match="alpha-2"):
            KitConfig.from_json(path)

    def test_paths_resolve_against_the_config_so_the_kit_can_be_copied(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path))
        assert config.resolve("plans/cell.json") == tmp_path / "plans" / "cell.json"

    def test_a_machine_entry_needs_a_serial(self):
        with pytest.raises(KitError, match="serial"):
            MachineEntry.from_dict({"plan": "p.json", "exports": "e"})

    def test_the_starter_config_is_shaped_like_a_real_one(self):
        body = starter_config("demo")
        assert body["kit_id"] == "demo"
        assert body["machines"][0]["serial"]


# =====================================================================
class TestRun:
    def test_a_clean_run_is_complete_and_writes_four_files(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path, ("CELL-0412", "CELL-0501")))
        run = run_kit(config, tmp_path / "out")

        assert run.verdict == "complete"
        assert len(run.enrolled) == 2
        for name in ("report.html", "evidence.db", "run.json",
                     "attestation-request.json"):
            assert (tmp_path / "out" / name).exists(), name

    def test_the_standing_collection_caveat_does_not_degrade_the_verdict(self, tmp_path):
        """Every collection carries it, so letting it force PARTIAL every time
        would teach the reader that the verdict means nothing."""
        config = KitConfig.from_json(_kit(tmp_path))
        run = run_kit(config, tmp_path / "out")
        assert run.machines[0].warnings  # the caveat is still reported
        assert run.verdict == "complete"

    def test_nothing_reached_the_network(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path))
        run = run_kit(config, tmp_path / "out")
        assert run.airgap.held
        assert run.airgap.attempts == []

    def test_the_airgap_record_is_sealed_into_the_customers_own_ledger(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path))
        run = run_kit(config, tmp_path / "out")
        ledger = EvidenceLedger(run.ledger_path)
        kinds = [e.kind for e in ledger.entries()]
        assert AIRGAP_KIND in kinds
        assert KIT_RUN_KIND in kinds
        record = next(e for e in ledger.entries() if e.kind == AIRGAP_KIND)
        assert record.payload["body"]["held"] is True
        assert "after the guard released" in record.payload["body"]["covers"]

    def test_the_attested_head_covers_every_record_including_the_run_record(
            self, tmp_path):
        """A head read before the last append is stale the moment it is written,
        and an attestation of a stale head looks like coverage and is not."""
        config = KitConfig.from_json(_kit(tmp_path))
        run = run_kit(config, tmp_path / "out")
        ledger = EvidenceLedger(run.ledger_path)
        entries = ledger.entries()

        assert run.head["length"] == len(entries)
        assert run.head["head_link_hash"] == entries[-1].link_hash
        request = json.loads(
            (tmp_path / "out" / "attestation-request.json").read_text())
        assert request["ledger_length"] == len(entries)
        assert request["head_link_hash"] == entries[-1].link_hash
        assert entries[-1].kind == KIT_RUN_KIND

    def test_the_ledger_verifies_and_the_report_carries_the_limits(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path))
        run = run_kit(config, tmp_path / "out")
        assert EvidenceLedger(run.ledger_path).verify_chain()[0] is True
        html = (tmp_path / "out" / "report.html").read_text()
        assert "socket module" in html
        assert "hash chain detects editing, not deletion" in html

    def test_a_missing_export_folder_is_a_named_failure_not_a_crash(self, tmp_path):
        path = _kit(tmp_path, ("CELL-0412",))
        body = json.loads(path.read_text())
        body["machines"].append({"serial": "CELL-9999", "plan": "plans/cell.json",
                                 "exports": "exports/CELL-9999"})
        path.write_text(json.dumps(body))
        run = run_kit(KitConfig.from_json(path), tmp_path / "out")

        assert run.verdict == "partial"
        failed = next(m for m in run.machines if m.serial == "CELL-9999")
        assert failed.status == "failed"
        assert "does not exist" in failed.detail
        # and the machine that worked still produced evidence
        assert len(run.enrolled) == 1

    def test_a_plan_still_carrying_a_template_value_is_refused(self, tmp_path):
        _kit(tmp_path)
        _plan_file(tmp_path, manufacturer="CHANGE ME")
        run = run_kit(KitConfig.from_json(tmp_path / "kit.json"), tmp_path / "out")
        assert run.verdict == "failed"
        assert "manufacturer" in run.machines[0].detail

    def test_every_run_states_what_it_did_not_establish(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path))
        run = run_kit(config, tmp_path / "out")
        joined = " ".join(run.checks_skipped)
        assert "not signed" in joined
        assert "No supplier advisory" in joined
        assert "No physical behaviour" in joined


# =====================================================================
class TestTheWholeLoop:
    """Offline run -> three numbers -> counter-signature -> rewind caught.

    This is the product in one test. If it passes, an integrator with no
    account and no network produced evidence that a second party can vouch for
    and that its own holder cannot quietly shorten.
    """

    def test_a_rewind_after_counter_signature_is_caught(self, tmp_path):
        config = KitConfig.from_json(_kit(tmp_path, ("CELL-0412", "CELL-0501")))
        run = run_kit(config, tmp_path / "out")

        # The customer sends three numbers. Nothing else leaves.
        request = json.loads(
            (tmp_path / "out" / "attestation-request.json").read_text())
        assert set(request) == {"ledger_length", "head_seq", "head_link_hash",
                                "note", "how"}

        # A party who has never seen the ledger signs them.
        from assurance.attest import LedgerHead

        service_key = SigningKey.generate().save(tmp_path / "service.pem")
        signer = SigningKey.load(tmp_path / "service.pem")
        service_log = AttestationLog(tmp_path / "service-attestations.jsonl")
        signed = attest(
            LedgerHead(length=request["ledger_length"],
                       head_seq=request["head_seq"],
                       head_link_hash=request["head_link_hash"]),
            signer, service_log, note=request["note"])
        assert signed.basis.value == "declared_by_holder"
        assert service_key.exists()

        ledger = EvidenceLedger(run.ledger_path)
        good = verify_log([signed], signer.verifying, ledger=ledger)
        assert good.ok, good.problems

        # Now the holder removes a record and rebuilds the chain.
        import sqlite3

        db = sqlite3.connect(run.ledger_path)
        db.execute("DELETE FROM chain WHERE seq > 2")
        db.commit()
        db.close()
        rewound = EvidenceLedger(run.ledger_path)
        assert rewound.verify_chain()[0] is True   # the chain is happy

        caught = verify_log(
            [HeadAttestation.from_dict(signed.to_dict())],
            signer.verifying, ledger=rewound)
        assert not caught.ok
        assert any("were removed after being attested" in p
                   for p in caught.problems)


# =====================================================================
class TestCli:
    def _run(self, *argv) -> int:
        from assurance.kit.cli import main

        return main(list(argv))

    def test_init_writes_a_kit_and_refuses_a_non_empty_folder(self, tmp_path, capsys):
        assert self._run("init", str(tmp_path / "plant"), "--kit-id", "p1") == 0
        for name in ("kit.json", "plans/cell.json", "README.md"):
            assert (tmp_path / "plant" / name).exists(), name
        capsys.readouterr()
        assert self._run("init", str(tmp_path / "plant")) == 2
        assert "not empty" in capsys.readouterr().err

    def test_check_refuses_the_freshly_written_kit_until_it_is_filled_in(
            self, tmp_path, capsys):
        self._run("init", str(tmp_path / "plant"))
        capsys.readouterr()
        # The starter organisation is a placeholder, so the config itself refuses.
        assert self._run("check", str(tmp_path / "plant" / "kit.json")) == 2
        assert "placeholder" in capsys.readouterr().err

    def test_check_names_every_item_that_matches_no_file(self, tmp_path, capsys):
        path = _kit(tmp_path)
        (tmp_path / "exports" / "CELL-0412" / "controller-fw.bin").unlink()
        assert self._run("check", str(path)) == 1
        out = capsys.readouterr().out
        assert "ITM-FW" in out
        assert "NO MATCH" in out
        assert "(required)" in out

    def test_check_passes_a_ready_kit_and_touches_nothing(self, tmp_path, capsys):
        path = _kit(tmp_path)
        assert self._run("check", str(path)) == 0
        assert not (tmp_path / "out").exists()
        assert "would send: nothing" in capsys.readouterr().out

    def test_run_exits_zero_when_complete_and_quiet(self, tmp_path, capsys):
        path = _kit(tmp_path)
        assert self._run("run", str(path), "--out", str(tmp_path / "out")) == 0
        out = capsys.readouterr().out
        assert "COMPLETE" in out
        assert "No outbound connection was attempted" in out
        assert "What this run does not establish" in out

    def test_run_exits_one_on_a_finding(self, tmp_path):
        path = _kit(tmp_path)
        body = json.loads(path.read_text())
        body["machines"].append({"serial": "X", "plan": "plans/cell.json",
                                 "exports": "exports/nope"})
        path.write_text(json.dumps(body))
        assert self._run("run", str(path), "--out", str(tmp_path / "out")) == 1

    def test_run_exits_two_when_nothing_enrolled(self, tmp_path):
        _kit(tmp_path)
        _plan_file(tmp_path, model="CHANGE ME")
        assert self._run("run", str(tmp_path / "kit.json"),
                         "--out", str(tmp_path / "out")) == 2

    def test_json_output_is_machine_readable(self, tmp_path, capsys):
        path = _kit(tmp_path)
        assert self._run("run", str(path), "--out", str(tmp_path / "out"),
                         "--json") == 0
        body = json.loads(capsys.readouterr().out)
        assert body["verdict"] == "complete"
        assert body["airgap"]["held"] is True
