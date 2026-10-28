"""A kit config that cannot be read is exit 2 ("could not run"), never a traceback.

Exit 1 means a finding in a run that completed; a crash must not share it.
"""
from __future__ import annotations

import pytest

from assurance.kit.cli import main


@pytest.mark.parametrize("cmd", ["check", "run"])
@pytest.mark.parametrize("make", ["dir", "binary", "array"])
def test_unreadable_config_is_exit_2(tmp_path, capsys, cmd, make):
    target = tmp_path / "kit.json"
    if make == "dir":
        target.mkdir()
    elif make == "binary":
        target.write_bytes(b"\xff\xfe\x00\x80")
    else:
        target.write_text("[1, 2]")
    assert main([cmd, str(target)]) == 2
    assert "Traceback" not in capsys.readouterr().err
