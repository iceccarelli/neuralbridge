"""A backup directory that overlaps the data directory copies its own backups.

Found by running three ``ops cycle`` passes over a config whose ``backup_dir`` sat inside
``data_dir``: every pass exited 0 and the data directory grew from 0.4 MB to 1.2 MB, each backup
containing the earlier ones. The config is refused when it is read. Synthetic paths only.
"""

from __future__ import annotations

import json

import pytest

from assurance.ops.config import OpsConfigError, load_config


def _write(tmp_path, data, backup):
    cfg = {"ops_id": "t", "data_dir": str(tmp_path / data), "record": str(tmp_path / "rec.jsonl"),
           "backup_dir": str(tmp_path / backup)}
    path = tmp_path / "ops.json"
    path.write_text(json.dumps(cfg))
    return path


@pytest.mark.parametrize("data, backup", [
    ("data", "data/backups"),          # inside: each cycle copies every earlier cycle
    ("data", "data"),                  # the same directory
    ("data/sub", "data"),              # the data directory inside the backups
])
def test_an_overlapping_backup_dir_is_refused_when_the_config_is_read(tmp_path, data, backup):
    with pytest.raises(OpsConfigError, match="backup_dir"):
        load_config(_write(tmp_path, data, backup))


def test_a_backup_dir_beside_the_data_dir_is_accepted(tmp_path):
    # a shared name prefix is not nesting
    assert load_config(_write(tmp_path, "data", "data-backups")).backup_dir \
        == tmp_path / "data-backups"
