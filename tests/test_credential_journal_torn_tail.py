"""A journal append interrupted mid-line must not brick every vault connection.

An independent review wrote a partial line (no newline), as a crash or ENOSPC mid-write leaves. Reads
were fine (an unterminated tail is "still being written"), but the NEXT append glued its line onto the
fragment and every later read failed the integrity check: all vault connections answered 503
``credential_journal_corrupt`` until an operator edited the file by hand. The fragment was never
acknowledged (acknowledgement follows the fsync), and the writer holds the exclusive lock, so it is
truncated back to the last verified line before appending.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from neuralbridge.ai.credentials import CustodyError, RollbackJournal


def _journal(tmp_path: Path) -> RollbackJournal:
    return RollbackJournal(tmp_path / "custody" / "journal")


def test_an_append_after_a_torn_tail_repairs_it_and_the_chain_stays_valid(tmp_path):
    j = _journal(tmp_path)
    j.append("create", connection_id="c1", owner="o", version=1)
    good = j.path.read_bytes()
    with open(j.path, "ab") as fh:
        fh.write(b'{"seq":2,"at":"2026-11-08T00:00:00+00:00","op":"revo')     # interrupted mid-line
    assert j.snapshot()[2] == 1, "reading with a torn tail still sees only the complete line"

    j.append("revoke", connection_id="c1", owner="o", version=1)

    assert j.path.read_bytes().startswith(good) and j.path.read_bytes().endswith(b"\n")
    fresh = RollbackJournal(j.path)                       # a new process: full verification
    _, state, entries = fresh.snapshot()
    assert entries == 2 and state["c1"].revoked is True


def test_a_complete_but_tampered_line_is_still_corruption_not_something_to_repair(tmp_path):
    j = _journal(tmp_path)
    j.append("create", connection_id="c1", owner="o", version=1)
    text = j.path.read_text().replace('"version":1', '"version":9')
    j.path.write_text(text)
    with pytest.raises(CustodyError) as exc:
        RollbackJournal(j.path).snapshot()
    assert exc.value.code == "credential_journal_corrupt"


def test_an_ordinary_append_truncates_nothing(tmp_path):
    j = _journal(tmp_path)
    j.append("create", connection_id="c1", owner="o", version=1)
    first = j.path.read_bytes()
    j.append("rotate", connection_id="c1", owner="o", version=2)
    assert j.path.read_bytes().startswith(first)
    assert RollbackJournal(j.path).snapshot()[2] == 2
