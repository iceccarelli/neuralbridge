"""``assurance intel`` end to end, and the properties that must hold around it.

Payloads are SYNTHETIC or minimized contract fixtures; the transport used for ``--live`` is an
in-memory CONTRACT FIXTURE injected over the single factory function. Nothing here reaches a
network, and nothing here claims to be live integration.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap

import pytest

from assurance.cli import main as top
from assurance.intel import cli as intel_cli
from assurance.intel.fetch import RequestHeaders, build_headers, fetch
from assurance.intel.sources import SOURCES, nvd_url
from assurance.intel.store import IntelStore

from .intel_support import FIXTURES, ContractFixtureTransport, fixture_bytes

SECRET = "s3cr3t-nvd-key-0123456789"
KEV_URL = SOURCES["cisa_kev"].url


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "intel.db")


def run(capsys, *argv):
    code = top(["intel", *map(str, argv)])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_ingest_history_show_candidates_offline(capsys, db):
    code, out, _ = run(capsys, "ingest", "--store", db, "--kev", FIXTURES / "kev_min.json",
                       "--nvd", FIXTURES / "nvd_synthetic.json", "--epss",
                       FIXTURES / "epss_min.json", "--csaf", FIXTURES / "csaf_synthetic.json")
    assert code == 0 and out.split().count("first") == 4
    code, out, _ = run(capsys, "ingest", "--store", db, "--kev", FIXTURES / "kev_min.json")
    assert code == 0 and "unchanged" in out
    code, out, _ = run(capsys, "history", "--store", db, "--json")
    rows = json.loads(out)
    assert [r["disposition"] for r in rows] == ["first"] * 4 + ["unchanged"]
    assert all(len(r["sha256"]) == 64 and r["via"] == "file" for r in rows)
    code, out, _ = run(capsys, "history", "--store", db, "--source", "kev", "--limit", "1")
    assert code == 0 and out.count("\n") == 1
    code, out, _ = run(capsys, "show", "--store", db, "5")
    assert code == 0 and "unchanged" in out
    code, out, _ = run(capsys, "show", "--store", db, "--cve", "CVE-2021-44228", "--json")
    data = json.loads(out)
    assert data["kev"]["status"] == "listed" and data["epss"]["status"] == "available"
    assert data["nvd"]["status"] == "unknown"                  # only the synthetic CVE was loaded
    code, out, _ = run(capsys, "show", "--store", db, "--cve", "CVE-2026-0001")
    assert "kev:  not_listed_in_kev" in out and "does not establish" in out
    assert "epss: unavailable" in out
    code, out, _ = run(capsys, "candidates", "--store", db, "--out",
                       str(db) + ".out")
    assert code == 0 and "2 candidate advisories" in out


def test_a_rejected_input_exits_1_and_is_recorded(capsys, db, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(fixture_bytes("kev_min.json")[:300])
    code, out, _ = run(capsys, "ingest", "--store", db, "--kev", bad)
    assert code == 1 and "rejected" in out and "truncated" in out
    rows = IntelStore(db).observations()
    assert [(o.disposition, o.parse_result) for o in rows] == [("rejected", "malformed")]


def test_unreadable_file_and_missing_args_are_exit_2(capsys, db, tmp_path):
    assert run(capsys, "ingest", "--store", db, "--kev", tmp_path / "gone")[0] == 2
    assert run(capsys, "ingest", "--store", db)[0] == 2


def test_refresh_without_live_refuses_and_never_builds_a_transport(capsys, db, monkeypatch):
    def boom(_):
        raise AssertionError("a transport was constructed without --live")

    monkeypatch.setattr(intel_cli, "_make_transport", boom)
    for src in ("kev", "nvd", "epss"):
        code, out, err = run(capsys, "refresh", "--source", src, "--store", db,
                             "--cve", "CVE-2026-0001")
        assert code == 2 and "--live" in err and out == ""
    assert not IntelStore(db).observations()


def test_refresh_without_live_does_not_even_import_the_network_client():
    code = textwrap.dedent("""
        import sys
        from assurance.cli import main
        rc = main(["intel", "refresh", "--source", "kev", "--store", sys.argv[1]])
        bad = [m for m in ("urllib.request", "http.client", "socket", "ssl",
                           "assurance.intel.transport_urllib") if m in sys.modules]
        print(rc, bad)
    """)
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        argv = [sys.executable, "-c", code, f"{d}/i.db"]
        r = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    assert r.stdout.strip() == "2 []", r.stdout + r.stderr


def test_the_offline_verbs_import_no_network_client():
    code = textwrap.dedent("""
        import sys
        import assurance.intel, assurance.intel.cli, assurance.intel.view, assurance.intel.store
        import assurance.intel.fetch, assurance.intel.parsers
        # urllib.parse is deliberately not listed: it is string parsing, not a network client, and
        # on Python 3.11 a bare `import pathlib` already loads it (CI runs 3.11, 3.12 and 3.13).
        print([m for m in ("urllib.request", "http.client", "socket", "ssl",
                           "assurance.intel.transport_urllib") if m in sys.modules])
    """)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True,  # noqa: S603
                       text=True, check=False)
    assert r.stdout.strip() == "[]", r.stdout + r.stderr


def test_refresh_live_records_through_the_injected_transport(capsys, db, monkeypatch):
    t = ContractFixtureTransport({KEV_URL: (200, fixture_bytes("kev_min.json"))})
    monkeypatch.setattr(intel_cli, "_make_transport", lambda _s: t)
    code, out, _ = run(capsys, "refresh", "--source", "kev", "--store", db, "--live")
    assert code == 0 and "first" in out and t.calls[0][0] == KEV_URL
    code, out, _ = run(capsys, "refresh", "--source", "kev", "--store", db, "--live")
    assert code == 0 and "unchanged" in out
    o = IntelStore(db).observations()
    assert [x.disposition for x in o] == ["first", "unchanged"]
    assert o[0].sha256 == o[1].sha256 and o[0].http_status == 200 and o[0].via == "network"


def test_refresh_live_nvd_needs_named_cves_and_never_prints_the_key(capsys, db, monkeypatch):
    t = ContractFixtureTransport({nvd_url("CVE-2021-44228"): (200, fixture_bytes("nvd_min.json"))})
    monkeypatch.setattr(intel_cli, "_make_transport", lambda _s: t)
    monkeypatch.setenv("MY_NVD_KEY", SECRET)
    assert run(capsys, "refresh", "--source", "nvd", "--store", db, "--live")[0] == 2
    code, out, err = run(capsys, "refresh", "--source", "nvd", "--store", db, "--live",
                         "--cve", "CVE-2021-44228", "--api-key-env", "MY_NVD_KEY")
    assert code == 0 and SECRET not in out + err
    assert t.calls[0][1]["apiKey"] == SECRET                   # sent as a header ...
    assert "apiKey" not in t.calls[0][0]                       # ... never in the URL
    assert SECRET.encode() not in open(db, "rb").read()        # ... never stored
    assert run(capsys, "refresh", "--source", "nvd", "--store", db, "--live", "--cve",
               "CVE-2021-44228", "--api-key-env", "bad name;")[0] == 2


def test_a_bad_cve_id_is_exit_2_not_a_request(capsys, db, monkeypatch):
    t = ContractFixtureTransport({})
    monkeypatch.setattr(intel_cli, "_make_transport", lambda _s: t)
    code, _, err = run(capsys, "refresh", "--source", "epss", "--store", db, "--live",
                       "--cve", "CVE-1; DROP")
    assert code == 2 and "not a CVE id" in err and t.calls == []


# -- the secret ---------------------------------------------------------------------------
def test_the_secret_is_in_no_repr_log_exception_or_stored_observation(tmp_path, caplog):
    store = IntelStore(tmp_path / "s.db")
    headers = build_headers(SOURCES["nvd_cve_api"], api_key_env="K", environ={"K": SECRET})
    assert isinstance(headers, RequestHeaders) and headers["apiKey"] == SECRET
    assert SECRET not in repr(headers) and SECRET not in str(headers)
    assert "<redacted>" in repr(headers)
    t = ContractFixtureTransport({nvd_url("CVE-2021-44228"): (200, fixture_bytes("nvd_min.json"))})
    with caplog.at_level(logging.DEBUG):
        obs = fetch(store, "nvd", nvd_url("CVE-2021-44228"), t, headers=headers)
        bad = fetch(store, "nvd", nvd_url("CVE-2021-44228"),
                    ContractFixtureTransport({}), headers=headers)
    assert SECRET not in repr(obs) and SECRET not in repr(bad) and SECRET not in caplog.text
    assert SECRET not in json.dumps(obs.to_dict()) and SECRET not in bad.reason
    assert SECRET.encode() not in (tmp_path / "s.db").read_bytes()
    assert SECRET.encode() not in b"".join(p.read_bytes() for p in tmp_path.glob("s.db-*"))


def test_an_unset_key_variable_sends_no_header_and_a_bad_name_is_refused():
    assert "apiKey" not in build_headers(SOURCES["nvd_cve_api"], api_key_env="NOPE", environ={})
    with pytest.raises(ValueError, match="NAME"):
        build_headers(SOURCES["nvd_cve_api"], api_key_env="a b", environ={})
    with pytest.raises(ValueError, match="no API key"):
        build_headers(SOURCES["cisa_kev"], api_key_env="K", environ={"K": "x"})


def test_a_url_that_does_not_belong_to_the_source_is_refused_before_the_transport(tmp_path):
    t = ContractFixtureTransport({})
    with pytest.raises(ValueError, match="not a cisa_kev URL"):
        fetch(IntelStore(tmp_path / "s.db"), "kev", "https://evil.example/kev.json", t)
    assert t.calls == []
