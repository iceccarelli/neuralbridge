"""The top-level CLI answers an operator's wrong file with a message and exit 2, not a crash.

Regression: handing a verb a directory, a JSON array where it wants an object, or a --ledger
path that is not a SQLite database ended in an uncaught exception (a traceback, which a shell
reports as exit 1, the code several verbs use for a finding). About 35 verbs did it.
"""
from __future__ import annotations

import json

import pytest

from assurance.cli import EXIT_COULD_NOT_RUN, main


@pytest.fixture()
def files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "env.db"))
    (tmp_path / "array.json").write_text("[]")
    (tmp_path / "notadb.db").write_text("this is not a sqlite database")
    (tmp_path / "adir").mkdir()
    return tmp_path


def test_a_json_array_where_an_object_is_wanted(files, capsys):
    capsys.readouterr()
    code = main(["machinery", "record-manifest", str(files / "array.json"), "--ledger",
                 str(files / "l.db")])
    assert code == EXIT_COULD_NOT_RUN
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err


def test_a_directory_where_a_file_is_wanted(files, capsys):
    capsys.readouterr()
    code = main(["machinery", "record-manifest", str(files / "adir"), "--ledger",
                 str(files / "l.db")])
    assert code == EXIT_COULD_NOT_RUN
    assert capsys.readouterr().err.startswith("error: ")


def test_a_ledger_path_that_is_not_a_database_says_so(files, capsys):
    capsys.readouterr()
    code = main(["fleet", "list", "--ledger", str(files / "notadb.db")])
    assert code == EXIT_COULD_NOT_RUN
    assert "not a ledger" in capsys.readouterr().err


def test_a_good_command_is_unchanged(files, capsys):
    manifest = {
        "manifest_id": "M1", "machine": {"manufacturer": "A", "model": "B", "serial": "1"},
        "source": "as_found", "taken_at": "2026-01-01T00:00:00Z",
        "taken_by": {"identifier": "t", "role": "tech", "kind": "person"},
        "items": [{"item_id": "I", "kind": "firmware", "name": "fw", "version": "1",
                   "content_hash": "a" * 64, "hash_source": "read_from_machine",
                   "supplier": "S", "implements": ["SF"], "modifiable_in_field": False}],
        "functions": [{"function_id": "SF", "description": "d", "verified_by": ["c"]}]}
    (files / "m.json").write_text(json.dumps(manifest))
    assert main(["machinery", "record-manifest", str(files / "m.json"), "--ledger",
                 str(files / "l.db")]) == 0


def test_the_debug_switch_brings_the_traceback_back(files, monkeypatch):
    monkeypatch.setenv("ASSURANCE_DEBUG", "1")
    with pytest.raises(Exception):  # noqa: B017, PT011 - which exception is the point of the switch
        main(["machinery", "record-manifest", str(files / "array.json"), "--ledger",
              str(files / "l.db")])


# ---------------------------------------------------------------------------------------------
# a crash is "could not complete" (2), never the findings code (1)
# ---------------------------------------------------------------------------------------------
# An exception class outside the operator whitelist used to end in a traceback and exit 1, the
# code `watch run`, `ops cycle` and others use for FINDINGS; a cron wrapper that stays silent on
# 1 read a crash as a flagged result. The injected faults go through the real dispatcher.
def _ops_config(root):
    (root / "data").mkdir()
    (root / "ops.json").write_text(json.dumps({
        "schema": "neuralbridge-ops/1", "ops_id": "t", "data_dir": "data",
        "record": "ops/cycles.jsonl", "backup_dir": "backups"}))
    return ["ops", "cycle", "--config", str(root / "ops.json")]


def _crash_cases(root, monkeypatch, exc):
    import assurance.evidence.cli as evidence_cli
    import assurance.kit.cli as kit_cli
    import assurance.ops.cycle as ops_cycle
    import assurance.watch.cli as watch_cli

    def boom(*a, **k):
        raise exc

    (root / "watch.json").write_text("{}")
    (root / "b.json").write_text("{}")
    return {
        "watch run": (watch_cli, "run_watch",
                      ["watch", "run", str(root / "watch.json"), "--ledger", str(root / "l.db")],
                      lambda: monkeypatch.setattr(watch_cli, "WatchConfig",
                                                  type("C", (), {"from_json":
                                                                 staticmethod(lambda p: object())}))),
        "ops cycle": (ops_cycle, "_chain_step", _ops_config(root), lambda: None),
        "kit check": (kit_cli, "_cmd_check", ["kit", "check", str(root / "watch.json")],
                      lambda: None),
        "evidence verify": (evidence_cli, "verify_export_file",
                            ["evidence", "verify", str(root / "b.json")], lambda: None),
    }, boom


@pytest.mark.parametrize("verb", ["watch run", "ops cycle", "kit check", "evidence verify"])
@pytest.mark.parametrize("exc", [RuntimeError("simulated bug"), ZeroDivisionError("x"),
                                 ImportError("No module named 'cryptography'")],
                         ids=["RuntimeError", "ZeroDivisionError", "ImportError"])
def test_an_unexpected_exception_is_exit_2_not_the_findings_code(
        files, capsys, monkeypatch, verb, exc):
    monkeypatch.delenv("ASSURANCE_DEBUG", raising=False)
    cases, boom = _crash_cases(files, monkeypatch, exc)
    module, name, argv, prepare = cases[verb]
    prepare()
    monkeypatch.setattr(module, name, boom)
    capsys.readouterr()
    code = main(argv)
    err = capsys.readouterr().err
    assert code == EXIT_COULD_NOT_RUN == 2
    assert f"could not complete ({type(exc).__name__}: {exc})" in err
    assert "Traceback" not in err


def test_assurance_debug_still_shows_the_traceback(files, monkeypatch):
    monkeypatch.setenv("ASSURANCE_DEBUG", "1")
    cases, boom = _crash_cases(files, monkeypatch, RuntimeError("simulated bug"))
    module, name, argv, prepare = cases["evidence verify"]
    monkeypatch.setattr(module, name, boom)
    with pytest.raises(RuntimeError, match="simulated bug"):
        main(argv)


@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_an_interrupt_or_an_exit_is_not_swallowed(files, monkeypatch, signal):
    monkeypatch.delenv("ASSURANCE_DEBUG", raising=False)
    cases, _ = _crash_cases(files, monkeypatch, RuntimeError("x"))
    module, name, argv, _prepare = cases["evidence verify"]

    def go(*a, **k):
        raise signal()

    monkeypatch.setattr(module, name, go)
    with pytest.raises(signal):
        main(argv)


# ---------------------------------------------------------------------------------------------
# a closed or vanished reader is not a failure of the command (F11)
# ---------------------------------------------------------------------------------------------
def test_closed_stdout_keeps_the_real_exit_code(files, monkeypatch):
    """`>&-` leaves sys.stdout None; the flush raised AttributeError AFTER the work was done."""
    import sys

    monkeypatch.setattr(sys, "stdout", None)
    assert main(["capabilities", "--check"]) in (0, 1)
    assert main(["no-such-domain"]) == 2


def test_ops_status_into_a_closed_pipe_ends_quietly_not_as_could_not_run(files, monkeypatch, capsys):
    import assurance.ops.cli as ops_cli

    (files / "data").mkdir()
    (files / "ops.json").write_text(json.dumps({
        "schema": "neuralbridge-ops/1", "ops_id": "t", "data_dir": "data",
        "record": "ops/cycles.jsonl", "backup_dir": "backups"}))

    def pipe(*a, **k):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(ops_cli, "_cmd_status", pipe)
    from assurance.cli import EXIT_BROKEN_PIPE
    capsys.readouterr()
    code = main(["ops", "status", "--config", str(files / "ops.json")])
    assert code == EXIT_BROKEN_PIPE
    assert "Broken pipe" not in capsys.readouterr().err
