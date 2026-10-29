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
