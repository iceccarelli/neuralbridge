"""What the kit tells the integrator about each item, and what it refuses to seal.

A first-time integrator installs the kit, fills in ``kit.json`` and the plan, runs it, and
has to learn (1) what is wrong before anything is sealed, (2) that template data is never
sealed as real, (3) that an incomplete machine is never sealed as THE configuration
without being told, and (4) from a readable report, what was and was not read and from
which file. These tests drive the real CLI entry point on synthetic exports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.kit.cli import main as kit_main
from assurance.machinery.manifest import INCOMPLETE_COLLECTION_MARK
from assurance.machinery.record import MANIFEST_KIND

from .support import plan_dict, write_export


def make_kit(root: Path, serials=("AR7-1001",), **over) -> Path:
    """A filled-in kit: real-looking identity, a tuned plan, one export folder per serial."""
    plan = plan_dict()
    plan["manufacturer"], plan["model"] = "Acme Robotics", "AR-7"
    (root / "plans").mkdir(parents=True, exist_ok=True)
    (root / "plans" / "cell.json").write_text(json.dumps(plan), encoding="utf-8")
    for n, serial in enumerate(serials):
        write_export(root / "exports" / serial, stamp="2026-09-14T06:02:11Z",
                     operator="m.keller", seq=f"004{n}", radius=1500 + n)
    body = {
        "kit_id": "outcomes-kit", "organisation": "Acme Integration GmbH",
        "site": "Hamburg Works", "country": "IT", "prepared_by": "Jane Doe",
        "role": "integrator",
        "machines": [{"serial": s, "plan": "plans/cell.json", "exports": f"exports/{s}",
                      "year": "2024"} for s in serials],
    }
    body.update(over)
    (root / "kit.json").write_text(json.dumps(body), encoding="utf-8")
    return root / "kit.json"


def run_cli(*argv: str) -> int:
    return kit_main(list(argv))


def ledger_kinds(out: Path) -> list[str]:
    return [e.kind for e in EvidenceLedger(out / "evidence.db").entries()]


def run_record(out: Path) -> dict:
    ledger = EvidenceLedger(out / "evidence.db")
    return next(e for e in ledger.entries() if e.kind == "kit.run").payload["body"]


class TestAnIncompleteMachineIsNotSealedAsTheConfiguration:
    def test_a_machine_missing_an_export_is_not_sealed_and_the_attempt_is_recorded(
            self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
        out = tmp_path / "out"

        rc = run_cli("run", str(kit), "--out", str(out))
        text = capsys.readouterr().out

        assert rc == 2                                    # nothing was recorded
        assert MANIFEST_KIND not in ledger_kinds(out)     # no baseline for Watch to inherit
        machine = run_record(out)["machines"][0]
        assert machine["status"] == "incomplete"
        assert machine["sealed"] is False
        assert machine["missing"] == ["ITM-PLC"]
        assert machine["configuration_hash"] == ""        # there is no sealed manifest to name
        # The terminal says it, in words, before the integrator walks away
        assert "NOT sealed" in text and "ITM-PLC" in text
        # ... and run.json says it
        on_disk = json.loads((out / "run.json").read_text())
        assert on_disk["machines"][0]["missing"] == ["ITM-PLC"]
        assert on_disk["machines"][0]["sealed"] is False

    def test_the_report_names_the_machine_and_the_missing_item(self, tmp_path):
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
        out = tmp_path / "out"
        run_cli("run", str(kit), "--out", str(out))
        html = (out / "report.html").read_text()
        assert "AR7-1001 was NOT sealed" in html
        assert "not collected: ITM-PLC" in html

    def test_a_complete_machine_beside_an_incomplete_one_is_still_sealed(self, tmp_path):
        kit = make_kit(tmp_path, ("AR7-1001", "AR7-1002"))
        (tmp_path / "exports" / "AR7-1002" / "controller-fw.bin").unlink()
        out = tmp_path / "out"

        rc = run_cli("run", str(kit), "--out", str(out))

        assert rc == 1                                    # a finding; evidence was produced
        sealed = [e.subject for e in EvidenceLedger(out / "evidence.db").entries()
                  if e.kind == MANIFEST_KIND]
        assert sealed == ["Acme Robotics/AR-7#AR7-1001"]
        statuses = {m["serial"]: m["status"] for m in run_record(out)["machines"]}
        assert statuses == {"AR7-1001": "recorded", "AR7-1002": "incomplete"}

    def test_seal_incomplete_seals_exactly_what_collect_run_would(self, tmp_path, capsys):
        """The flag has the meaning ``collect run --seal-incomplete`` has: the manifest is
        sealed with the incomplete-collection marker, and the operator was told."""
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
        out = tmp_path / "out"

        rc = run_cli("run", str(kit), "--out", str(out), "--seal-incomplete")
        text = capsys.readouterr().out

        assert rc == 2                                    # still not a clean run
        entries = [e for e in EvidenceLedger(out / "evidence.db").entries()
                   if e.kind == MANIFEST_KIND]
        assert len(entries) == 1
        assert INCOMPLETE_COLLECTION_MARK in entries[0].payload["body"]["manifest"]["notes"]
        machine = run_record(out)["machines"][0]
        assert machine["status"] == "incomplete" and machine["sealed"] is True
        assert "SEALED INCOMPLETE" in machine["detail"]
        assert "was sealed INCOMPLETE at the operator" in (out / "report.html").read_text()
        assert "NOT sealed" not in text

    def test_a_failed_machine_is_in_the_report_too(self, tmp_path):
        kit = make_kit(tmp_path, ("AR7-1001", "AR7-1002"))
        import shutil

        shutil.rmtree(tmp_path / "exports" / "AR7-1002")
        out = tmp_path / "out"
        assert run_cli("run", str(kit), "--out", str(out)) == 1
        assert "Machine AR7-1002 was NOT recorded" in (out / "report.html").read_text()


@pytest.mark.parametrize("flag", [[], ["--json"]])
def test_json_mode_carries_the_same_facts(tmp_path, capsys, flag):
    kit = make_kit(tmp_path)
    (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
    run_cli("run", str(kit), "--out", str(tmp_path / "out"), *flag)
    text = capsys.readouterr().out
    if flag:
        machine = json.loads(text)["machines"][0]
        assert machine["missing"] == ["ITM-PLC"] and machine["sealed"] is False
    else:
        assert "ITM-PLC" in text


# =====================================================================
# `kit check` reads exactly what `run` reads, and says what would fail.
# =====================================================================
def _tree_state(root: Path) -> dict[str, tuple[int, int]]:
    return {str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(root.rglob("*"))}


def _zip_bytes(member: str, size: int) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(member, b"\0" * size)
    return buf.getvalue()


def _utf16(path: Path) -> None:
    path.write_bytes("zone=1\n".encode("utf-16"))


def _symlink_out(path: Path) -> None:
    path.unlink()
    path.symlink_to("/etc/hostname")


#: (id, file, how to ruin it, a phrase the reason must contain)
BAD_INPUTS = [
    ("empty text", "scanner-zones.cfg", lambda p: p.write_bytes(b""), "could not be hashed completely"),
    ("binary under a text rule", "scanner-zones.cfg",
     lambda p: p.write_bytes(bytes(range(256)) * 4), "cannot read as utf-8"),
    ("latin-1", "scanner-zones.cfg",
     lambda p: p.write_bytes("zone=Müller\n".encode("latin-1")), "cannot read as utf-8"),
    ("utf-16", "scanner-zones.cfg", _utf16, "cannot read as utf-8"),
    ("invalid json", "robot-params.json", lambda p: p.write_text("{not json"), "ITM-PARAMS"),
    ("duplicate-key json", "robot-params.json",
     lambda p: p.write_text('{"a": 1, "a": 2}'), "ITM-PARAMS"),
    ("not a zip", "plc-project.zip", lambda p: p.write_bytes(b"hello"), "ITM-PLC"),
    ("truncated zip", "plc-project.zip",
     lambda p: p.write_bytes(p.read_bytes()[:-30]), "ITM-PLC"),
    ("2 MB line", "scanner-zones.cfg",
     lambda p: p.write_text("x" * (2 * 1024**2) + "\n"), "line"),
    ("symlink out of the folder", "scanner-zones.cfg", _symlink_out, "outside the collection"),
    ("member missing from the archive", "plc-project.zip",
     lambda p: p.write_bytes(_zip_bytes("other/x.st", 10)), "ITM-PLC"),
]


@pytest.mark.parametrize("name,fname,ruin,phrase", BAD_INPUTS, ids=[b[0] for b in BAD_INPUTS])
class TestCheckFindsWhatRunWouldFail:
    def test_check_fails_and_names_the_item_before_run_does(
            self, tmp_path, capsys, name, fname, ruin, phrase):
        kit = make_kit(tmp_path)
        ruin(tmp_path / "exports" / "AR7-1001" / fname)

        rc = run_cli("check", str(kit))
        out = capsys.readouterr().out

        assert rc == 1, f"{name}: check said it was fine and run would fail"
        assert "NOT READY" in out and "\n  READY:" not in out
        assert phrase in out, out
        # ... and it was right: run, on the same inputs, does not record the machine.
        assert run_cli("run", str(kit), "--out", str(tmp_path / "out")) == 2

    def test_check_json_marks_the_item_and_the_machine(
            self, tmp_path, capsys, name, fname, ruin, phrase):
        kit = make_kit(tmp_path)
        ruin(tmp_path / "exports" / "AR7-1001" / fname)
        rc = run_cli("check", str(kit), "--json")
        body = json.loads(capsys.readouterr().out)
        assert rc == 1 and body["ready"] is False and body["run_command"] == ""
        machine = body["machines"][0]
        assert machine["ready"] is False
        assert any(i["status"] != "collected" for i in machine["items"])


def test_a_zip_bomb_is_found_by_check(tmp_path, capsys, monkeypatch):
    """The 512 MiB member cap, lowered so the test does not build a 600 MB archive."""
    from assurance.collect import normalise

    monkeypatch.setattr(normalise, "MAX_ARCHIVE_MEMBER_BYTES", 1024)
    kit = make_kit(tmp_path)
    (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").write_bytes(
        _zip_bytes("program/main.st", 100_000))
    assert run_cli("check", str(kit)) == 1
    assert "ITM-PLC" in capsys.readouterr().out


class TestCheckOnAReadyKit:
    def test_it_says_ready_and_prints_the_exact_run_command(self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        assert run_cli("check", str(kit)) == 0
        out = capsys.readouterr().out
        assert "READY: every item of every machine was found and read" in out
        assert f"python -m assurance kit run {kit} --out {tmp_path / 'out'}" in out

    def test_it_shows_each_item_with_digest_version_and_file(self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        run_cli("check", str(kit), "--json")
        body = json.loads(capsys.readouterr().out)
        items = {i["item_id"]: i for i in body["machines"][0]["items"]}
        assert items["ITM-PARAMS"]["version"] == "3.8.2"
        assert items["ITM-ZONES"]["version"] == ""
        assert len(items["ITM-FW"]["digest"]) == 64
        assert items["ITM-FW"]["found"] == ["controller-fw.bin"]
        assert body["run_command"].startswith("python -m assurance kit run ")
        run_cli("check", str(kit))
        out = capsys.readouterr().out
        assert "v3.8.2" in out and "version unknown" in out
        assert items["ITM-PARAMS"]["digest"][:12] in out

    def test_it_surfaces_an_item_warning_without_failing(self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        zones = tmp_path / "exports" / "AR7-1001" / "scanner-zones.cfg"
        zones.write_text("[zone.1]\nradius_mm=1500\n")        # no header: both patterns idle
        assert run_cli("check", str(kit)) == 0
        out = capsys.readouterr().out
        assert "matched no line" in out
        assert "carry warnings above" in out

    def test_it_touches_nothing(self, tmp_path, monkeypatch):
        """Safe to hand to an IT department: no file created, none modified, no ledger opened."""
        kit = make_kit(tmp_path)
        before = _tree_state(tmp_path)

        from assurance.evidence import ledger as ledger_module

        def refuse(*_a, **_k):
            raise AssertionError("check opened an evidence ledger")

        monkeypatch.setattr(ledger_module.EvidenceLedger, "__init__", refuse)
        assert run_cli("check", str(kit)) == 0
        assert _tree_state(tmp_path) == before
        assert not (tmp_path / "out").exists()
        assert not list(tmp_path.rglob("*.db"))

    def test_it_reads_under_the_same_socket_guard_as_run(self, tmp_path, capsys, monkeypatch):
        """If reading a file ever tried the network, check must say so and fail."""
        import socket

        from assurance.kit import enrol

        real = enrol.collect

        def collect_that_phones_home(*a, **k):
            try:
                socket.create_connection(("192.0.2.1", 443), timeout=0.1)
            except Exception:  # noqa: S110 - the guard's refusal is the point
                pass
            return real(*a, **k)

        monkeypatch.setattr(enrol, "collect", collect_that_phones_home)
        kit = make_kit(tmp_path)
        rc = run_cli("check", str(kit), "--json")
        body = json.loads(capsys.readouterr().out)
        assert rc == 1 and body["ready"] is False
        assert body["airgap"]["held"] is False
        assert body["airgap"]["attempts"][0]["target"].startswith("192.0.2.1")


# =====================================================================
# Per-item reasons survive into the terminal, run.json and the ledger.
# =====================================================================
class TestPerItemReasonsAreNotThrownAway:
    def _outcomes(self, out: Path) -> dict:
        machine = json.loads((out / "run.json").read_text())["machines"][0]
        return {o["item_id"]: o for o in machine["outcomes"]}

    def test_an_unreadable_item_says_why_in_the_terminal_and_the_record(
            self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "scanner-zones.cfg").write_bytes(
            "zone=Müller\n".encode("latin-1"))
        out = tmp_path / "out"

        run_cli("run", str(kit), "--out", str(out))
        text = capsys.readouterr().out

        assert "ITM-ZONES" in text and "cannot read as utf-8 text" in text
        zones = self._outcomes(out)["ITM-ZONES"]
        assert zones["status"] == "unreadable"
        assert "cannot read as utf-8 text" in zones["detail"]
        # sealed in the ledger as well, so the reason outlives the terminal
        sealed = run_record(out)["machines"][0]["outcomes"]
        assert any("cannot read as utf-8 text" in o["detail"] for o in sealed)

    def test_a_pattern_that_matched_no_line_is_shown_on_a_complete_machine(
            self, tmp_path, capsys):
        """A UTF-8 byte-order mark hides the first-line header from `^#` and the export
        is still COMPLETE; the warning is the only sign the digest is not the one the
        plan's author intended."""
        kit = make_kit(tmp_path)
        zones = tmp_path / "exports" / "AR7-1001" / "scanner-zones.cfg"
        zones.write_bytes(b"\xef\xbb\xbf" + zones.read_bytes())
        out = tmp_path / "out"

        assert run_cli("run", str(kit), "--out", str(out)) == 0
        text = capsys.readouterr().out

        assert "matched no line" in text
        warnings = self._outcomes(out)["ITM-ZONES"]["warnings"]
        assert any("matched no line" in w for w in warnings)

    def test_a_version_that_was_not_found_is_shown(self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        params = tmp_path / "exports" / "AR7-1001" / "robot-params.json"
        params.write_text(json.dumps({"export": {"timestamp": "t", "operator": "o"},
                                      "safety": {"max_tcp_speed_mm_s": 400}}))
        out = tmp_path / "out"

        assert run_cli("run", str(kit), "--out", str(out)) == 0
        text = capsys.readouterr().out

        assert "expects a json version and none was found" in text
        assert self._outcomes(out)["ITM-PARAMS"]["version"] == ""

    def test_every_recorded_item_names_its_file_digest_and_version(self, tmp_path):
        kit = make_kit(tmp_path)
        out = tmp_path / "out"
        assert run_cli("run", str(kit), "--out", str(out)) == 0
        params = self._outcomes(out)["ITM-PARAMS"]
        assert params["files"] == ["robot-params.json"]
        assert len(params["digest"]) == 64 and params["version"] == "3.8.2"
        html = (out / "report.html").read_text()
        assert "ITM-PARAMS read from robot-params.json" in html


# =====================================================================
# Template data is never sealed as real (check AND run say so first).
# =====================================================================
class TestTemplateDataInTheKit:
    def _edit(self, tmp_path, mutate):
        kit = make_kit(tmp_path)
        body = json.loads(kit.read_text())
        mutate(body)
        kit.write_text(json.dumps(body))
        return kit

    @pytest.mark.parametrize("cmd", ["check", "run"])
    @pytest.mark.parametrize("serial", ["TBD", "000000", "xxx", "CHANGE ME"])
    def test_a_placeholder_serial_is_refused_with_exit_2(self, tmp_path, capsys, cmd, serial):
        kit = self._edit(tmp_path, lambda b: b["machines"][0].update(serial=serial))
        extra = ["--out", str(tmp_path / "out")] if cmd == "run" else []
        assert run_cli(cmd, str(kit), *extra) == 2
        assert "serial" in capsys.readouterr().err
        assert not (tmp_path / "out").exists()

    @pytest.mark.parametrize("cmd", ["check", "run"])
    def test_several_serials_on_one_export_folder_are_refused_with_the_remedy(
            self, tmp_path, capsys, cmd):
        def share(body):
            body["machines"] = [dict(body["machines"][0], serial=f"AR7-100{n}")
                                for n in range(1, 4)]
        kit = self._edit(tmp_path, share)
        extra = ["--out", str(tmp_path / "out")] if cmd == "run" else []
        assert run_cli(cmd, str(kit), *extra) == 2
        err = capsys.readouterr().err
        assert "both read the export folder" in err and "its own folder" in err
        assert not (tmp_path / "out").exists()

    def test_prepared_by_an_agent_is_not_sealed_as_a_person(self, tmp_path, capsys):
        for who in ("AI agent", "bot"):
            kit = self._edit(tmp_path, lambda b, who=who: b.update(prepared_by=who))
            assert run_cli("run", str(kit), "--out", str(tmp_path / "out")) == 2
            assert "prepared_by" in capsys.readouterr().err
            assert not (tmp_path / "out").exists()

    def test_starter_values_that_survive_are_named_in_check_and_run(self, tmp_path, capsys):
        def starter(body):
            body.update(site="Plant 1", country="DE")
            body["machines"][0].update(year="2025")
        kit = self._edit(tmp_path, starter)
        # Not refused (a German plant can be "Plant 1"): named, once, where the integrator looks
        assert run_cli("check", str(kit)) == 0
        out = capsys.readouterr().out
        assert "still the value `kit init` wrote" in out and "country='DE'" in out
        out_dir = tmp_path / "out"
        assert run_cli("run", str(kit), "--out", str(out_dir)) == 0
        warnings = json.loads((out_dir / "run.json").read_text())["machines"][0]["warnings"]
        assert any("site='Plant 1'" in w and "year='2025'" in w for w in warnings)

    def test_a_kit_with_chosen_values_has_no_starter_note(self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        run_cli("check", str(kit))
        assert "kit init` wrote" not in capsys.readouterr().out


# =====================================================================
# An existing ledger is verified before anything is appended to it.
# =====================================================================
class TestARunDoesNotAppendToABrokenChain:
    def _edit_first_record(self, db: Path) -> None:
        import sqlite3

        con = sqlite3.connect(db)
        con.execute("UPDATE chain SET at = '2020-01-01T00:00:00Z' WHERE seq = 1")
        con.commit()
        con.close()

    def test_a_tampered_ledger_is_refused_and_nothing_is_appended(self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        out = tmp_path / "out"
        assert run_cli("run", str(kit), "--out", str(out)) == 0
        self._edit_first_record(out / "evidence.db")
        before = len(EvidenceLedger(out / "evidence.db").entries())
        request_before = (out / "attestation-request.json").read_text()
        capsys.readouterr()

        rc = run_cli("run", str(kit), "--out", str(out))

        assert rc == 2
        assert "does not verify as a hash chain" in capsys.readouterr().err
        assert len(EvidenceLedger(out / "evidence.db").entries()) == before
        assert (out / "attestation-request.json").read_text() == request_before

    def test_an_intact_ledger_is_appended_to(self, tmp_path):
        kit = make_kit(tmp_path)
        out = tmp_path / "out"
        run_cli("run", str(kit), "--out", str(out))
        assert run_cli("run", str(kit), "--out", str(out)) == 0
        assert EvidenceLedger(out / "evidence.db").verify_chain()[0] is True


# =====================================================================
# "recorded" is not "enrolled".
# =====================================================================
class TestRecordedIsNotEnrolled:
    def test_the_status_says_recorded_and_the_next_command_really_enrols(
            self, tmp_path, capsys, monkeypatch):
        import shlex

        from assurance.collect.cli import main as collect_main
        from assurance.machinery.cli import main as machinery_main

        kit = make_kit(tmp_path)
        out = tmp_path / "out"
        assert run_cli("run", str(kit), "--out", str(out)) == 0
        text = capsys.readouterr().out
        assert "1/1 machine(s) recorded" in text
        assert json.loads((out / "run.json").read_text())["machines"][0]["status"] == "recorded"
        assert "recorded is not enrolled" in text

        commands = [shlex.split(line.strip()) for line in text.splitlines()
                    if line.strip().startswith("python -m assurance ")]
        assert [c[3] for c in commands] == ["collect", "machinery"]
        monkeypatch.chdir(tmp_path)

        # Before: the machine is not enrolled, exactly as the integrator found out.
        key = "Acme Robotics/AR-7#AR7-1001"
        amend = ["amend-enrolment", "--ledger", str(out / "evidence.db"), "--machine", key,
                 "--actor", "Jane Doe", "--reason", "site corrected", "--site", "Hall 2"]
        assert machinery_main(amend) != 0

        # The printed commands, verbatim, perform the real enrolment.
        assert collect_main(commands[0][4:]) == 0
        assert machinery_main(commands[1][4:]) == 0
        assert machinery_main(amend) == 0


# =====================================================================
# A version the plan declared is not a version read from the file.
# =====================================================================
class TestVersionProvenanceIsInTheNotes:
    def _collect(self, tmp_path, version):
        from assurance.collect.collector import collect
        from assurance.collect.plan import CollectionPlan
        from assurance.core.evidence import Actor

        plan = plan_dict()
        plan["items"][3]["version"] = version          # ITM-FW: random bytes
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        return collect(CollectionPlan.from_dict(plan), root, serial="0412",
                       taken_by=Actor(identifier="Jane Doe", role="x", kind="person"))

    def test_a_literal_version_says_it_was_declared_not_read(self, tmp_path):
        manifest = self._collect(tmp_path, {"kind": "literal", "value": "9.9.9"}).manifest
        fw = manifest.item("ITM-FW")
        assert fw.version == "9.9.9"
        assert "version declared in plan, not read from file" in fw.notes
        # a version actually read from a file does not say that
        assert "declared in plan" not in manifest.item("ITM-PARAMS").notes
        assert "read from key 'firmware.version' of robot-params.json" in \
            manifest.item("ITM-PARAMS").notes

    def test_a_regex_version_names_the_pattern_and_the_file(self, tmp_path):
        manifest = self._collect(
            tmp_path, {"kind": "regex", "value": r"(firmware) "}).manifest
        notes = manifest.item("ITM-FW").notes
        assert "version extracted by pattern" in notes and "from controller-fw.bin" in notes

    def test_notes_are_outside_the_configuration_hash(self, tmp_path):
        """The provenance note must not make two otherwise identical collections differ."""
        from dataclasses import replace

        literal = self._collect(tmp_path, {"kind": "literal", "value": "9.9.9"}).manifest
        stripped = replace(literal, items=tuple(replace(i, notes="") for i in literal.items))
        assert literal.configuration_hash() == stripped.configuration_hash()


# =====================================================================
# `collect probe` does not call an untested plan STABLE.
# =====================================================================
class TestProbeWithNothingToCompare:
    def _probe(self, a, b):
        from assurance.collect.plan import CollectionPlan
        from assurance.collect.volatility import probe

        return probe(CollectionPlan.from_dict(plan_dict()), a, b)

    def test_the_same_folder_twice_is_incomplete_not_stable(self, tmp_path):
        root = write_export(tmp_path / "a", stamp="s", operator="o", seq="1")
        report = self._probe(root, root)
        assert report.verdict == "incomplete"
        assert any("byte-for-byte identical" in c for c in report.checks_skipped)

    def test_a_byte_identical_copy_is_incomplete_not_stable(self, tmp_path):
        import shutil

        root = write_export(tmp_path / "a", stamp="s", operator="o", seq="1")
        shutil.copytree(root, tmp_path / "b")
        assert self._probe(root, tmp_path / "b").verdict == "incomplete"

    def test_two_real_exports_that_differ_only_in_noise_are_still_stable(self, tmp_path):
        a = write_export(tmp_path / "a", stamp="2026-09-14T06:02:11Z", operator="m.keller",
                         seq="0040")
        b = write_export(tmp_path / "b", stamp="2026-10-01T17:45:59Z", operator="s.berg",
                         seq="0057")
        assert self._probe(a, b).verdict == "stable"

    def test_the_cli_exits_non_zero_for_the_same_folder(self, tmp_path, capsys):
        from assurance.collect.cli import main as collect_main

        root = write_export(tmp_path / "a", stamp="s", operator="o", seq="1")
        plan = tmp_path / "plan.json"
        plan.write_text(json.dumps(plan_dict()))
        rc = collect_main(["probe", str(plan), "--first", str(root), "--second", str(root)])
        assert rc == 1
        assert "STABLE" not in capsys.readouterr().out.split("\n")[0]
