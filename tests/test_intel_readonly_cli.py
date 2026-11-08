"""Intel READ verbs never create a store, and a tampered payload is unreadable, not a crash.

A mistyped ``--store`` used to create an empty SQLite file and answer "no observations" /
"unknown": a typo reading as "nothing known". Only ``ingest`` and ``refresh --live`` may create.
"""

from __future__ import annotations

import pytest

from assurance.cli import main as top
from assurance.intel.store import IntelStore, IntelStoreError

from . import interfaces_fixtures as fx
from .intel_support import FIXTURES
from .support_sqlite import connect as sqlite_connect
from .test_assurance_intel_api import (
    CVE_LISTED,
    STORE_ENV,
    build_store,
    get,
)

live_api = fx.live_api

READ_VERBS = [
    ("history",),
    ("history", "--json"),
    ("candidates",),
    ("candidates", "--json"),
    ("show", "--cve", "CVE-2026-1234"),
    ("show", "1"),
]


def run(capsys, *argv):
    code = top(["intel", *map(str, argv)])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("verb", READ_VERBS, ids=" ".join)
def test_a_typo_creates_nothing_for_every_read_verb(capsys, tmp_path, verb):
    before = sorted(p.name for p in tmp_path.iterdir())
    target = tmp_path / "typo.db"
    code, out, err = run(capsys, verb[0], "--store", target, *verb[1:])
    assert code == 2, (verb, out, err)
    assert not target.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert "does not exist. Nothing was read, and no store was created." in err
    assert "no observations" not in out and "0 candidate" not in out and "unknown" not in out


def test_candidates_out_dir_is_not_created_for_a_typo(capsys, tmp_path):
    code, _, _ = run(capsys, "candidates", "--store", tmp_path / "typo.db", "--out",
                     tmp_path / "outdir")
    assert code == 2 and not (tmp_path / "outdir").exists()


def test_open_existing_never_creates_and_refuses_foreign_files(tmp_path):
    with pytest.raises(IntelStoreError, match="does not exist. Nothing was read"):
        IntelStore.open_existing(tmp_path / "nope.db")
    assert list(tmp_path.iterdir()) == []
    foreign = tmp_path / "other.db"
    with sqlite_connect(foreign) as db:
        db.execute("CREATE TABLE t(x)")
    with pytest.raises(IntelStoreError, match="not an intel observation store"):
        IntelStore.open_existing(foreign)
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with pytest.raises(IntelStoreError):
        IntelStore.open_existing(empty)
    assert empty.read_bytes() == b""


def test_read_verbs_work_on_an_existing_store_and_do_not_modify_it(capsys, tmp_path):
    path = tmp_path / "intel.db"
    build_store(path)
    before = path.read_bytes()
    for verb in READ_VERBS[:4] + [("show", "--cve", CVE_LISTED)]:
        code, _, err = run(capsys, verb[0], "--store", path, *verb[1:])
        assert code == 0, (verb, err)
    assert path.read_bytes() == before


def test_ingest_still_creates_the_store(capsys, tmp_path):
    target = tmp_path / "new.db"
    code, out, _ = run(capsys, "ingest", "--store", target, "--kev", FIXTURES / "kev_min.json")
    assert code == 0 and target.is_file() and "first" in out


# ------------------------------------------------------------ tampered TEXT payload
def _tamper_body_as_text(path):
    with sqlite_connect(path) as db:
        db.execute("DROP TRIGGER blobs_no_update")
        db.execute("UPDATE blobs SET body = 'not bytes at all'")


def test_a_text_blob_is_an_unreadable_payload_not_a_traceback(capsys, tmp_path):
    path = tmp_path / "intel.db"
    build_store(path)
    _tamper_body_as_text(path)
    ro = IntelStore.open_existing(path)
    shas = [o.sha256 for o in ro.observations()]
    assert shas and all(ro.body(s) is None for s in shas)
    for verb in (("candidates",), ("show", "--cve", CVE_LISTED)):
        try:
            code, out, err = run(capsys, verb[0], "--store", path, *verb[1:])
        except TypeError as exc:       # pragma: no cover - this is the defect
            pytest.fail(f"TypeError escaped the CLI: {exc}")
        # Either reported as unreadable observations (exit 0 with the list) or refused (2);
        # never a conclusion from the tampered data.
        assert code in (0, 2)
        assert "Traceback" not in err


def test_a_text_blob_is_reported_as_unreadable_in_the_report(tmp_path):
    from assurance.intel.view import build_report

    path = tmp_path / "intel.db"
    build_store(path)
    _tamper_body_as_text(path)
    report = build_report(IntelStore.open_existing(path))
    assert report.unreadable, "tampered payloads must be listed as unreadable"
    assert not report.candidates


@pytest.mark.parametrize("route", ["/v1/intel/candidates", f"/v1/intel/cve/{CVE_LISTED}"])
def test_a_text_blob_over_http_is_a_503_not_a_500(live_api, tmp_path, monkeypatch, route):
    path = tmp_path / "intel.db"
    build_store(path)
    _tamper_body_as_text(path)
    monkeypatch.setenv(STORE_ENV, str(path))
    _, headers = live_api.account("intel-text@example.de", tier="cell")
    r = get(live_api, headers, route)
    # unreadable observations are surfaced in-band (200 with the list) or as 503; never 500
    assert r.status_code in (200, 503), r.text
    if r.status_code == 200:
        assert r.json()["unreadable_observations"]
    else:
        assert r.json()["detail"]["error"] == "intel_store_unreadable"


def test_a_type_error_from_a_store_read_maps_to_503(live_api, tmp_path, monkeypatch):
    path = tmp_path / "intel.db"
    build_store(path)
    monkeypatch.setenv(STORE_ENV, str(path))

    def boom(self, *a, **k):
        raise TypeError("bytes(...) on text")

    for name in ("observations", "latest_accepted"):
        monkeypatch.setattr(IntelStore, name, boom)
    _, headers = live_api.account("intel-typeerr@example.de", tier="cell")
    for route in ("/v1/intel/history", "/v1/intel/candidates", f"/v1/intel/cve/{CVE_LISTED}"):
        r = get(live_api, headers, route)
        assert r.status_code == 503, (route, r.status_code)
        assert r.json()["detail"]["error"] == "intel_store_unreadable"
