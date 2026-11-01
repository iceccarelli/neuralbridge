"""``watch run|status --now`` (assessment clock), status staleness, and the open-case warning.

Same SYNTHETIC contract fixtures as ``test_assurance_watch_intel_followups``; nothing here
fetches. Observations are recorded with explicit retrieval times, so every age is exact.

Pinned:

* ``--now`` moves the clock for ASSESSMENT only and exactly at the boundary (limit 24 h: at
  24h00m not stale, at 24h01m stale; the run record's assessed-at is the given instant);
* ``watch run --now`` without ``--dry-run`` is REFUSED (exit 2) before anything is opened, so
  a run that seals records can never carry a forged clock - and nothing is written;
* a malformed ``--now`` is refused (exit 2), a zone is never guessed;
* ``watch status`` shows each selected source's age, the limit and fresh / stale /
  never-observed with the same function the runner uses, says "age not checked" without a
  limit, uses the runner's wording for a missing store, and exits 2 on an intel problem
  without changing any other exit code;
* ``watch open-case`` WARNS (stderr + ``--json``) with the age when the store is stale, and
  still opens the case; silent when fresh or when no limit is set.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from assurance.change.store import CaseStore
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.cli import _exit_code, main
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from .test_assurance_watch_intel import CVE, _plant
from .test_assurance_watch_intel_followups import T0, WHO, _fill_at, _hours, _set_age


def _z(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def sealed(tmp_path):
    """Two machines sealed and the finding announced once, with the store retrieved at T0.

    The first (real-clock) run has no limit set, so it is not itself degraded; the limit is
    switched on afterwards, per test.
    """
    p = _plant(tmp_path)
    _fill_at(p["store"])
    first = run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
    assert first.advisories.new
    p["cfg"] = str(p["dir"] / "watch.json")
    p["led"] = str(p["ledger"].path)
    p["id"] = f"nvd:{CVE}"
    return p


def _dry(p, now, *extra):
    return main(["run", p["cfg"], "--ledger", p["led"], "--dry-run", "--json",
                 "--now", now, *extra])


def _feed(capsys):
    doc = json.loads(capsys.readouterr().out)
    return doc, doc["advisories"]["feeds"][0]


# =====================================================================
class TestNowShiftsAssessmentExactlyAtTheBoundary:
    def test_at_24h00m_not_stale_and_at_24h01m_stale(self, sealed, capsys):
        _set_age(sealed, 24)
        code = _dry(sealed, _z(T0 + _hours(24)))
        doc, feed = _feed(capsys)
        assert feed["status"] != "stale" and not any("STALE" in x for x in feed["problems"])
        assert code in (0, 1)
        assert doc["started_at"] == _z(T0 + _hours(24)) == doc["finished_at"]

        code = _dry(sealed, _z(T0 + _hours(24) + timedelta(minutes=1)))
        doc, feed = _feed(capsys)
        assert code == 2 and doc["verdict"] == "degraded" and feed["status"] == "stale"
        assert "24.0 h before" in " ".join(feed["problems"]) or "limit is 24 h" in \
            " ".join(feed["problems"])
        assert doc["started_at"] == _z(T0 + _hours(24) + timedelta(minutes=1))

    def test_a_second_inside_the_limit_is_fresh(self, sealed, capsys):
        _set_age(sealed, 24)
        _dry(sealed, _z(T0 + _hours(24) - timedelta(seconds=1)))
        _, feed = _feed(capsys)
        assert feed["status"] != "stale"

    def test_dry_run_with_now_writes_nothing(self, sealed, capsys):
        _set_age(sealed, 24)
        before = len(sealed["ledger"].entries())
        _dry(sealed, _z(T0 + _hours(99)))
        capsys.readouterr()
        assert len(EvidenceLedger(sealed["led"]).entries()) == before


# =====================================================================
class TestNowIsRefusedWithoutDryRun:
    def test_refused_exit_2_and_nothing_written(self, sealed, tmp_path, capsys):
        fresh = tmp_path / "never-created.db"
        before = len(sealed["ledger"].entries())
        for ledger in (fresh, sealed["led"]):
            code = main(["run", sealed["cfg"], "--ledger", str(ledger),
                         "--now", _z(T0 + _hours(1))])
            assert code == 2
            err = capsys.readouterr().err
            assert "--dry-run" in err and "real clock" in err
            assert "Nothing was run and nothing was written" in err
        assert not fresh.exists()                      # not even opened
        assert len(EvidenceLedger(sealed["led"]).entries()) == before

    def test_without_now_a_real_run_still_seals(self, sealed, capsys):
        # the guard is on --now only: a normal run is unchanged
        assert main(["run", sealed["cfg"], "--ledger", sealed["led"]]) in (0, 1, 2)
        capsys.readouterr()


@pytest.mark.parametrize("bad", [
    "", "yesterday", "2026-11-01", "2026-11-01T06:30:00", "2026-11-01T06:30:00+01:00",
    "2026-11-01 06:30:00Z", "2026-13-45T00:00:00Z", "2026-11-01T25:00:00Z", "1730442600"])
class TestMalformedNowIsRefused:
    def test_run(self, sealed, capsys, bad):
        before = len(sealed["ledger"].entries())
        with pytest.raises(SystemExit) as exc:
            main(["run", sealed["cfg"], "--ledger", sealed["led"], "--dry-run", "--now", bad])
        assert exc.value.code == 2
        assert "--now" in capsys.readouterr().err
        assert len(EvidenceLedger(sealed["led"]).entries()) == before

    def test_status(self, sealed, capsys, bad):
        with pytest.raises(SystemExit) as exc:
            main(["status", sealed["cfg"], "--ledger", sealed["led"], "--now", bad])
        assert exc.value.code == 2


# =====================================================================
class TestStatusShowsIntelAges:
    def _status(self, p, now, *extra):
        return main(["status", p["cfg"], "--ledger", p["led"], "--now", now, *extra])

    def test_ages_limit_and_fresh(self, sealed, capsys):
        _set_age(sealed, 24)
        code = self._status(sealed, _z(T0 + _hours(3)))
        out = capsys.readouterr().out
        assert "intel public-intel" in out
        for src in ("nvd", "kev", "epss"):
            line = next(x for x in out.splitlines() if x.strip().startswith(src + " "))
            assert "3.0 h" in line and "limit 24 h" in line and "fresh" in line
        last = json.loads(_status_json(self, sealed, _z(T0 + _hours(3)), capsys))
        assert code == _exit_code(last["verdict"])      # unchanged when everything is fresh

    def test_stale_exits_2_with_the_age(self, sealed, capsys):
        _set_age(sealed, 24)
        assert self._status(sealed, _z(T0 + _hours(30))) == 2
        out = capsys.readouterr().out
        assert "30.0 h" in out and "STALE" in out

    def test_json_carries_the_same_numbers(self, sealed, capsys):
        _set_age(sealed, 24)
        doc = json.loads(_status_json(self, sealed, _z(T0 + _hours(30)), capsys))
        intel = doc["intel_staleness"]
        assert intel["assessed_at"] == _z(T0 + _hours(30)) and intel["ok"] is False
        (sub,) = intel["subscriptions"]
        assert sub["age_checked"] is True and sub["limit_hours"] == 24
        assert {s["source"]: s["state"] for s in sub["sources"]} == {
            "nvd": "stale", "kev": "stale", "epss": "stale"}
        assert all(s["age_hours"] == 30.0 for s in sub["sources"])

    def test_never_observed_source(self, tmp_path, capsys):
        p = _plant(tmp_path)
        _fill_at(p["store"], epss=None)
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        p["cfg"], p["led"] = str(p["dir"] / "watch.json"), str(p["ledger"].path)
        _set_age(p, 24)
        assert self._status(p, _z(T0 + _hours(1))) == 2
        out = capsys.readouterr().out
        line = next(x for x in out.splitlines() if x.strip().startswith("epss"))
        assert "NEVER OBSERVED" in line
        assert "fresh" in next(x for x in out.splitlines() if x.strip().startswith("nvd"))

    def test_no_limit_says_age_not_checked_and_changes_no_exit_code(self, sealed, capsys):
        last = json.loads(_status_json(self, sealed, _z(T0 + _hours(900)), capsys))
        code = self._status(sealed, _z(T0 + _hours(900)))
        out = capsys.readouterr().out
        assert "age not checked" in out and "STALE" not in out
        assert code == _exit_code(last["verdict"])
        assert last["intel_staleness"]["subscriptions"][0]["age_checked"] is False

    def test_a_missing_store_uses_the_runners_wording(self, sealed, capsys):
        _set_age(sealed, 24)
        (sealed["dir"] / "intel.db").unlink()
        run_text = " ".join(
            f.problems[0] if f.problems else f.detail
            for f in run_watch(WatchConfig.from_json(sealed["cfg"]), sealed["ledger"],
                               seal=False, now=T0 + _hours(1)).advisories.feeds)
        assert self._status(sealed, _z(T0 + _hours(1))) == 2
        out = capsys.readouterr().out
        assert "does not exist" in out and "blind to this source" in out
        assert "does not exist" in run_text

    def test_without_an_intel_subscription_nothing_changes(self, tmp_path, capsys):
        p = _plant(tmp_path)
        body = json.loads((p["dir"] / "watch.json").read_text())
        body.pop("intel")
        (p["dir"] / "watch.json").write_text(json.dumps(body))
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        cfg, led = str(p["dir"] / "watch.json"), str(p["ledger"].path)
        code = main(["status", cfg, "--ledger", led, "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert "intel_staleness" not in doc and code == _exit_code(doc["verdict"])
        assert main(["status", cfg, "--ledger", led]) == code
        assert "intel" not in capsys.readouterr().out


def _status_json(case, p, now, capsys):
    capsys.readouterr()
    case._status(p, now, "--json")
    return capsys.readouterr().out


# =====================================================================
class TestOpenCaseWarnsOnAStaleStore:
    def _open(self, p, *extra):
        return main(["open-case", "--config", p["cfg"], "--ledger", p["led"],
                     "--advisory-id", p["id"], *WHO, *extra])

    def _cases(self, p):
        return CaseStore(EvidenceLedger(p["led"])).list()

    def test_stale_store_warns_with_the_age_and_still_opens(self, tmp_path, capsys):
        old = datetime(2020, 1, 1, tzinfo=UTC)
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=old, kev=old, epss=old)
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        p.update(cfg=str(p["dir"] / "watch.json"), led=str(p["ledger"].path),
                 id=f"nvd:{CVE}")
        _set_age(p, 24)
        assert self._open(p) == 0
        cap = capsys.readouterr()
        assert "warning:" in cap.err and "STALE" in cap.err
        assert "2020-01-01T00:00:00Z" in cap.err and " h ago" in cap.err
        assert "limit is 24 h" in cap.err and "'nvd'" in cap.err
        assert "opened" in cap.out
        assert len(self._cases(p)) == 1                  # proceeded

    def test_json_field(self, tmp_path, capsys):
        old = datetime(2020, 1, 1, tzinfo=UTC)
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=old, kev=T0, epss=T0)
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        p.update(cfg=str(p["dir"] / "watch.json"), led=str(p["ledger"].path),
                 id=f"nvd:{CVE}")
        _set_age(p, 24)
        assert self._open(p, "--json") == 0
        cap = capsys.readouterr()
        body = json.loads(cap.out)
        assert len(body["intel_age_warnings"]) >= 1
        assert all("h ago" in w for w in body["intel_age_warnings"])
        assert any("'nvd'" in w for w in body["intel_age_warnings"])
        assert body["outcome"] == "opened"

    def test_no_accepted_observation_warns_age_unknown(self, tmp_path, capsys):
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=datetime.now(UTC), kev=None, epss=None)
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        p.update(cfg=str(p["dir"] / "watch.json"), led=str(p["ledger"].path),
                 id=f"nvd:{CVE}")
        _set_age(p, 24)
        assert self._open(p, "--json") == 0
        body = json.loads(capsys.readouterr().out)
        assert any("'kev'" in w and "no accepted observation" in w
                   for w in body["intel_age_warnings"])

    @pytest.mark.parametrize("limit", [24, None])
    def test_silent_when_fresh_or_unset(self, tmp_path, capsys, limit):
        p = _plant(tmp_path)
        now = datetime.now(UTC) - timedelta(minutes=5)
        _fill_at(p["store"], nvd=now, kev=now, epss=now)
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        p.update(cfg=str(p["dir"] / "watch.json"), led=str(p["ledger"].path),
                 id=f"nvd:{CVE}")
        _set_age(p, limit)
        assert self._open(p, "--json") == 0
        cap = capsys.readouterr()
        assert "warning" not in cap.err
        assert json.loads(cap.out)["intel_age_warnings"] == []

    def test_a_stale_store_does_not_stop_an_idempotent_rerun(self, tmp_path, capsys):
        old = datetime(2020, 1, 1, tzinfo=UTC)
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=old, kev=old, epss=old)
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        p.update(cfg=str(p["dir"] / "watch.json"), led=str(p["ledger"].path),
                 id=f"nvd:{CVE}")
        _set_age(p, 24)
        assert self._open(p) == 0 and self._open(p) == 0
        assert "warning:" in capsys.readouterr().err
        assert len(self._cases(p)) == 1


def test_open_case_has_no_now_flag(sealed, capsys):
    """It writes a case; its record must not be able to carry a forged clock."""
    with pytest.raises(SystemExit) as exc:
        main(["open-case", "--config", sealed["cfg"], "--ledger", sealed["led"],
              "--advisory-id", sealed["id"], *WHO, "--now", _z(T0)])
    assert exc.value.code == 2
    assert CaseStore(EvidenceLedger(sealed["led"])).list() == []
