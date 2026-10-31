"""Follow-ups to the intel advisory source: store STALENESS, and ``watch open-case``.

Same SYNTHETIC contract fixtures as ``test_assurance_watch_intel``; nothing here fetches.
Observations are recorded with EXPLICIT retrieval times and the run is given an explicit
``now``, so every age below is deterministic.

Pinned: a store that silently stopped refreshing is DEGRADED (never a quiet week) and says
which source, when it was last accepted and the limit; with no limit set the run says age
was NOT checked; the clock is the recorded retrieval time, never the feed's own stamp. And
opening a case from an intel finding is a named person's act that re-derives the finding
(it never trusts the caller), honours the unsigned-import rule, is idempotent, and never
decides anything.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta

import pytest

from assurance.change.model import CaseStatus
from assurance.change.store import CaseStore
from assurance.evidence.ledger import EvidenceLedger
from assurance.intel.fetch import ingest_bytes
from assurance.intel.sources import SOURCES, nvd_url
from assurance.watch.cli import main
from assurance.watch.config import IntelSubscription, WatchConfig, WatchError
from assurance.watch.runner import run_watch

from .intel_support import dump, epss_doc, fixture_json, kev_doc
from .test_assurance_watch_intel import CVE, _nvd, _plant

T0 = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


def _hours(n: float) -> timedelta:
    return timedelta(hours=n)


def _put_at(store, source, doc, at, *, url=None):
    raw = doc if isinstance(doc, bytes) else dump(doc)
    return ingest_bytes(store, source, raw, url=url or SOURCES[source].url, locator="t",
                        via="file", http_status=None, retrieved_at=at)


def _fill_at(store, nvd=T0, kev=T0, epss=T0):
    """NVD, KEV and EPSS recorded at the given retrieval times (None = not recorded)."""
    if nvd is not None:
        _put_at(store, "nvd_cve_api", _nvd(), nvd, url=nvd_url(CVE))
    if kev is not None:
        _put_at(store, "cisa_kev", kev_doc(CVE), kev)
    if epss is not None:
        _put_at(store, "first_epss", epss_doc((CVE, "0.00043", "0.09", "2026-10-31")), epss)


def _set_age(p, hours):
    path = p["dir"] / "watch.json"
    body = json.loads(path.read_text())
    if hours is None:
        body["intel"][0].pop("max_age_hours", None)
    else:
        body["intel"][0]["max_age_hours"] = hours
    path.write_text(json.dumps(body))


def _run(p, now, **kw):
    return run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"], now=now, **kw)


@pytest.fixture()
def plant(tmp_path):
    p = _plant(tmp_path)
    _fill_at(p["store"])
    _set_age(p, 24)
    return p


# =====================================================================
class TestConfigMaxAge:
    @pytest.mark.parametrize("bad", [0, -1, -0.5, "24", True, False, math.nan, math.inf])
    def test_it_must_be_a_positive_number(self, bad):
        with pytest.raises(WatchError, match="max_age_hours"):
            IntelSubscription(store="i.db", max_age_hours=bad)
        with pytest.raises(WatchError, match="max_age_hours"):
            IntelSubscription.from_dict({"store": "i.db", "max_age_hours": bad})

    def test_absent_means_not_checked_and_keeps_the_hash(self, plant):
        _set_age(plant, None)
        c = WatchConfig.from_json(plant["dir"] / "watch.json")
        assert c.intel[0].max_age_hours is None
        assert "max_age_hours" not in c.intel[0].to_dict()
        _set_age(plant, 24)
        c2 = WatchConfig.from_json(plant["dir"] / "watch.json")
        assert c2.intel[0].max_age_hours == 24.0
        assert c2.content_hash() != c.content_hash()
        assert WatchConfig.from_dict(c2.to_dict()).intel[0].max_age_hours == 24.0

    def test_a_null_value_is_the_same_as_absent(self):
        assert IntelSubscription.from_dict({"store": "i", "max_age_hours": None}) \
            .max_age_hours is None


# =====================================================================
class TestStaleness:
    def _feed(self, run):
        (out,) = run.advisories.feeds
        return out

    def test_a_store_older_than_the_limit_is_degraded_and_says_why(self, plant):
        run = _run(plant, T0 + _hours(30))
        out = self._feed(run)
        assert run.verdict == "degraded" and out.status == "stale" and out.is_degraded
        text = " ".join(out.problems)
        assert "STALE" in text and "'nvd'" in text and "'kev'" in text and "'epss'" in text
        assert "2026-10-31T12:00:00Z" in text           # last accepted retrieval time
        assert "30.0 h" in text and "limit is 24 h" in text
        assert "DEGRADED" in run.summary()
        # the older data is still assessed and labelled, not hidden
        assert run.advisories.findings

    def test_a_fresh_store_is_not_degraded(self, plant):
        run = _run(plant, T0 + _hours(2))
        assert self._feed(run).status == "verified" and run.verdict == "findings"
        assert not any("STALE" in p for p in self._feed(run).problems)

    def test_exactly_at_the_limit_is_not_stale(self, plant):
        assert self._feed(_run(plant, T0 + _hours(24), seal=False)).status == "verified"
        assert self._feed(_run(plant, T0 + _hours(24) + timedelta(seconds=1),
                               seal=False)).status == "stale"

    def test_without_a_limit_the_run_says_age_was_not_checked(self, plant):
        _set_age(plant, None)
        run = _run(plant, T0 + _hours(5000))            # absurdly old: still not judged
        assert self._feed(run).status == "verified"
        text = " ".join(run.checks_skipped)
        assert "age of the intel store was NOT checked" in text
        assert "silently stopped" in text

    def test_with_a_limit_the_run_says_what_the_clock_is(self, plant):
        text = " ".join(_run(plant, T0).checks_skipped)
        assert "NOT checked" not in text
        assert "recorded retrieval time" in text and "24 h" in text

    def test_it_is_deterministic_in_the_injected_clock(self, plant):
        a = _run(plant, T0 + _hours(30), seal=False)
        b = _run(plant, T0 + _hours(30), seal=False)
        assert a.advisories.feeds == b.advisories.feeds
        assert self._feed(_run(plant, T0 + _hours(1), seal=False)).status == "verified"

    def test_each_source_is_judged_separately(self, tmp_path):
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=T0, kev=T0 - _hours(100), epss=T0)
        _set_age(p, 24)
        out = self._feed(_run(p, T0 + _hours(2)))
        stale = [x for x in out.problems if "STALE" in x]
        assert out.status == "stale" and len(stale) == 1
        assert "'kev'" in stale[0] and "'nvd'" not in stale[0] and "'epss'" not in stale[0]
        assert "102.0 h" in stale[0]

    def test_the_newest_accepted_observation_is_the_one_that_counts(self, tmp_path):
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=T0 - _hours(100))
        _put_at(p["store"], "nvd_cve_api", _nvd("2026-10-03T00:00:00.001"), T0,
                url=nvd_url(CVE))                          # a later refresh, accepted
        _fill_at(p["store"], nvd=None, kev=T0, epss=T0)
        _set_age(p, 24)
        assert self._feed(_run(p, T0 + _hours(2))).status == "verified"

    def test_the_feeds_own_stamp_is_not_the_clock(self, tmp_path):
        # KEV's catalogue stamp is days older than the retrieval: retrieval is what counts.
        p = _plant(tmp_path)
        _put_at(p["store"], "nvd_cve_api", _nvd(), T0 + _hours(100), url=nvd_url(CVE))
        _put_at(p["store"], "cisa_kev", kev_doc(CVE, version="2026.01.01"), T0 + _hours(100))
        _put_at(p["store"], "first_epss",
                epss_doc((CVE, "0.1", "0.2", "2020-01-01")), T0 + _hours(100))
        _set_age(p, 24)
        assert self._feed(_run(p, T0 + _hours(101))).status == "verified"
        # and a fresh stamp on an old retrieval does not rescue it
        q = _plant(tmp_path / "q") if (tmp_path / "q").mkdir() is None else None
        _fill_at(q["store"], nvd=T0, kev=T0, epss=T0)      # stamps say 2026-10-30/31
        _set_age(q, 24)
        assert self._feed(_run(q, T0 + _hours(200))).status == "stale"

    def test_a_source_with_no_accepted_observation_is_stale_not_quiet(self, tmp_path):
        p = _plant(tmp_path)
        _fill_at(p["store"], kev=None)                      # watch reads kev; none recorded
        _set_age(p, 24)
        out = self._feed(_run(p, T0 + _hours(1)))
        assert out.status == "stale"
        assert any("'kev'" in x and "no accepted observation" in x for x in out.problems)

    def test_rejected_latest_keeps_its_status(self, tmp_path):
        p = _plant(tmp_path)
        _fill_at(p["store"])
        bad = _put_at(p["store"], "nvd_cve_api", b"{ not json", T0 + _hours(1),
                      url=nvd_url(CVE))
        assert bad.disposition == "rejected"
        _set_age(p, 24)
        out = self._feed(_run(p, T0 + _hours(2)))
        assert out.status == "rejected_latest" and out.is_degraded
        # fresh accepted data exists, so no staleness line is added on top
        assert not any("STALE" in x for x in out.problems)

    def test_a_rejected_retrieval_does_not_refresh_an_old_accepted_one(self, tmp_path):
        p = _plant(tmp_path)
        _fill_at(p["store"])
        _put_at(p["store"], "nvd_cve_api", b"{ not json", T0 + _hours(40), url=nvd_url(CVE))
        _set_age(p, 24)
        out = self._feed(_run(p, T0 + _hours(41)))
        assert out.status == "rejected_latest"
        stale = [x for x in out.problems if "STALE" in x and "'nvd'" in x]
        assert len(stale) == 1 and "2026-10-31T12:00:00Z" in stale[0]
        assert "41.0 h" in stale[0]

    def test_a_retrieval_in_the_future_cannot_establish_an_age(self, plant):
        out = self._feed(_run(plant, T0 - _hours(5)))
        assert out.status == "stale"
        assert any("cannot be established" in x for x in out.problems)

    def test_the_cli_exits_two_on_a_stale_store(self, tmp_path):
        p = _plant(tmp_path)
        _fill_at(p["store"], nvd=datetime(2020, 1, 1, tzinfo=UTC),
                 kev=datetime(2020, 1, 1, tzinfo=UTC), epss=datetime(2020, 1, 1, tzinfo=UTC))
        _set_age(p, 1)
        code = main(["run", str(p["dir"] / "watch.json"),
                     "--ledger", str(p["dir"] / "cli.db"), "--dry-run"])
        assert code == 2


# =====================================================================
WHO = ["--actor", "Dana Reviewer", "--role", "safety engineer"]


@pytest.fixture()
def seen(tmp_path):
    """A plant whose machines are sealed, the finding announced once (run 1)."""
    p = _plant(tmp_path)
    _fill_at(p["store"])
    first = run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
    assert first.advisories.new
    p["id"] = f"nvd:{CVE}"
    return p


def _open(p, *extra, advisory=None, who=None, ledger=None):
    return main(["open-case", "--config", str(p["dir"] / "watch.json"),
                 "--ledger", str(ledger or p["ledger"].path),
                 "--advisory-id", advisory or p["id"], *(who if who is not None else WHO),
                 *extra])


def _cases(p):
    return CaseStore(EvidenceLedger(p["dir"] / "ev.db")).list()


class TestOpenCase:
    def test_a_named_person_opens_it_and_is_told_what_is_not_established(self, seen, capsys):
        assert _open(seen) == 0
        out = capsys.readouterr().out
        assert "opened, status open" in out
        assert "unauthenticated_public_source" in out
        assert "NOT established" in out and "not verified" not in out.lower().split("not established")[0]
        assert "genuine" in out and "next, by a person" in out
        assert "change claim" in out and "never does" in out
        (case,) = CaseStore(EvidenceLedger(seen["dir"] / "ev.db")).list()
        assert case.status is CaseStatus.OPEN
        assert case.case_id in out
        assert set(case.machines) == {"Grimaldi/AR-7#CELL-0412", "Grimaldi/AR-7#CELL-0501"}
        assert case.provenance["advisory_trust"] == "unauthenticated_public_source"
        assert case.provenance["advisory_accepted_by"] == "Dana Reviewer"
        assert case.resolved_decisions == ()               # nothing was decided

    def test_json_output(self, seen, capsys):
        assert _open(seen, "--json") == 0
        body = json.loads(capsys.readouterr().out)
        assert body["outcome"] == "opened" and body["trust_state"] == \
            "unauthenticated_public_source"
        assert body["not_established"] and body["next_steps"]

    @pytest.mark.parametrize("name", ["", "   ", "automation", "watch", "System", "bot", "ai"])
    def test_an_empty_or_automation_name_is_refused(self, seen, capsys, name):
        before = len(seen["ledger"].entries())
        assert _open(seen, who=["--actor", name, "--role", "x"]) == 1
        assert "named person" in capsys.readouterr().err
        assert _cases(seen) == [] and len(seen["ledger"].entries()) == before

    @pytest.mark.parametrize("role", ["", "  ", "attribution=authenticated_operator",
                                      "a; operator=op_1"])
    def test_a_missing_or_forged_role_is_refused(self, seen, capsys, role):
        assert _open(seen, who=["--actor", "Dana Reviewer", "--role", role]) == 1
        assert _cases(seen) == []

    def test_an_id_that_is_not_a_current_finding_is_refused(self, seen, capsys):
        assert _open(seen, advisory="nvd:CVE-2099-9999") == 1
        err = capsys.readouterr().err
        assert "not a current finding" in err and "Nothing was opened" in err
        assert _cases(seen) == []

    def test_an_advisory_matching_no_machine_is_refused(self, tmp_path, capsys):
        p = _plant(tmp_path, version="v9.999")             # the NVD record matches nothing
        _fill_at(p["store"])
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        assert _open(p, advisory=f"nvd:{CVE}") == 1
        assert "matches no machine" in capsys.readouterr().err
        assert _cases(p) == []

    def test_an_unusable_store_opens_nothing(self, seen, capsys):
        (seen["dir"] / "intel.db").unlink()
        assert _open(seen) == 1
        assert _cases(seen) == []

    def test_a_csaf_candidate_needs_the_override_and_a_reason(self, tmp_path, capsys):
        p = _plant(tmp_path, supplier="Example Controls GmbH", name="EX-100",
                   version="V2.001", sources=("csaf",))
        _put_at(p["store"], "csaf", fixture_json("csaf_synthetic.json"), T0, url="file:csaf.json")
        run_watch(WatchConfig.from_json(p["dir"] / "watch.json"), p["ledger"])
        cfg = WatchConfig.from_json(p["dir"] / "watch.json")
        run = run_watch(cfg, p["ledger"], seal=False)
        aid = next(f.advisory_id for f in run.advisories.findings if f.inspect_only)

        assert _open(p, advisory=aid) == 1
        err = capsys.readouterr().err
        assert "override explicitly" in err and "needs a reason" not in err
        assert _open(p, "--accept-unsigned", advisory=aid) == 1
        assert "reason" in capsys.readouterr().err
        assert _open(p, "--accept-unsigned", "--reason", "  ", advisory=aid) == 1
        assert _cases(p) == []
        assert _open(p, "--accept-unsigned", "--reason", "read against the vendor page",
                     advisory=aid) == 0
        (case,) = CaseStore(EvidenceLedger(p["dir"] / "ev.db")).list()
        assert case.provenance["advisory_accept_reason"] == "read against the vendor page"
        assert case.provenance["advisory_accepted_by"] == "Dana Reviewer"
        assert "unsigned" in capsys.readouterr().out.lower()

    def test_it_is_idempotent(self, seen, capsys):
        assert _open(seen) == 0
        first = capsys.readouterr().out
        after_first = len(seen["ledger"].entries())
        assert _open(seen) == 0
        second = capsys.readouterr().out
        assert "already open (nothing written)" in second
        assert len(seen["ledger"].entries()) == after_first          # nothing new written
        (case,) = CaseStore(EvidenceLedger(seen["dir"] / "ev.db")).list()
        assert case.case_id in first and case.case_id in second
        # a different person re-running does not rewrite it either
        assert _open(seen, who=["--actor", "Eli Second", "--role", "lead"]) == 0
        assert len(seen["ledger"].entries()) == after_first
        (case,) = CaseStore(EvidenceLedger(seen["dir"] / "ev.db")).list()
        assert case.provenance["advisory_accepted_by"] == "Dana Reviewer"   # not re-attributed
        assert "Dana Reviewer" in capsys.readouterr().out

    def test_a_settled_case_is_left_alone(self, seen, capsys):
        assert _open(seen) == 0
        store = CaseStore(EvidenceLedger(seen["dir"] / "ev.db"))
        (case,) = store.list()
        from dataclasses import replace

        from assurance.core.evidence import Actor
        store.transition(replace(case, status=CaseStatus.REJECTED),
                         actor=Actor("Dana Reviewer", "x"), detail="test: person rejected it")
        n = len(seen["ledger"].entries())
        capsys.readouterr()
        assert _open(seen) == 1
        assert "rejected" in capsys.readouterr().err
        assert len(seen["ledger"].entries()) == n

    def test_the_runner_then_shows_it_outstanding_not_new(self, seen):
        assert _open(seen) == 0
        run = run_watch(WatchConfig.from_json(seen["dir"] / "watch.json"), seen["ledger"])
        assert run.advisories.new == ()
        assert [f.state for f in run.advisories.findings] == ["outstanding"]
        assert run.verdict == "quiet"
        # the watch still opens no case of its own and the person's case is the only one
        assert len(CaseStore(EvidenceLedger(seen["dir"] / "ev.db")).list()) == 1

    def test_it_writes_only_the_case_and_decides_nothing(self, seen):
        before = {e.kind for e in seen["ledger"].entries()}
        assert _open(seen) == 0
        added = {e.kind for e in seen["ledger"].entries()} - before
        assert added == {"assurance.change.opened"}, added
        (case,) = CaseStore(EvidenceLedger(seen["dir"] / "ev.db")).list()
        assert case.status is CaseStatus.OPEN and case.resolved_decisions == ()

    def test_it_opens_no_socket(self, seen, monkeypatch):
        import socket

        def refuse(*a, **k):
            raise AssertionError("open-case opened a network connection")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        assert _open(seen) == 0

    def test_io_and_usage_errors_exit_two(self, seen, tmp_path, capsys):
        assert _open(seen, ledger=tmp_path / "nope.db") == 2           # never creates a ledger
        assert not (tmp_path / "nope.db").exists()
        assert main(["open-case", "--config", str(tmp_path / "missing.json"),
                     "--ledger", str(seen["ledger"].path), "--advisory-id", "x",
                     *WHO]) == 2
        with pytest.raises(SystemExit) as e:
            main(["open-case", "--config", "w.json", "--ledger", "l.db",
                  "--advisory-id", "x"])                                # no --actor
        assert e.value.code == 2

    def test_the_capability_is_declared_and_never_on_mcp(self):
        from assurance.capabilities import CAPABILITIES

        cap = next(c for c in CAPABILITIES if c.id == "watch.open_case")
        assert cap.cli == ("watch open-case",) and not cap.mcp
        assert cap.gaps["mcp"][0] == "by_design"
