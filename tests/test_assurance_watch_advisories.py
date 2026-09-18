"""Watching the suppliers: the half that wakes somebody up.

The machine watch answers "did anything on my floor change". These tests are
about the other half — the world changing underneath machines that did not —
and specifically about the four ways a feature like this is usually built wrong:
re-announcing everything until nobody reads it, forgetting what it already said,
treating a broken sync as a quiet week, and never mentioning that an advisory
somebody acted on has been retracted.
"""

from __future__ import annotations

import json

import pytest

from assurance.attest.keys import SigningKey
from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)
from assurance.supplier import AdvisoryFeed, SupplierIdentity, publish, withdraw
from assurance.watch.advisories import check_feeds
from assurance.watch.config import FeedSubscription, WatchConfig, WatchError
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export

IDENTITY = SupplierIdentity(supplier_id="controlco", legal_name="ControlCo GmbH",
                            key_contact="the 2025 supply contract")


def _advisory(advisory_id: str = "CTRL-2026-11", **over) -> ComponentAdvisory:
    body: dict = {
        "advisory_id": advisory_id,
        "issued_by": "controlco",
        "issued_at": parse_utc("2026-09-10T08:00:00Z"),
        "title": "Authentication bypass in safety controller firmware",
        "summary": "A crafted frame permits a safety parameter write.",
        "severity": AdvisorySeverity.STOP_USE,
        "reference": "https://controlco.example/psirt/CTRL-2026-11",
        "remedy": "Update to 3.9.1.",
        "affected": (AffectedArtefact(supplier="ControlCo",
                                      name="Safety controller firmware",
                                      versions=("3.8.2", "3.9.0")),),
    }
    body.update(over)
    return ComponentAdvisory(**body)


@pytest.fixture()
def plant(tmp_path):
    """Two enrolled machines, a supplier key, and a signed feed."""
    plan = plan_dict()
    plan["manufacturer"], plan["model"] = "Grimaldi", "AR-7"
    for item in plan["items"]:
        item["supplier"] = {
            "ITM-ZONES": "ScanCo", "ITM-PARAMS": "RoboCo",
            "ITM-PLC": "ControlCo", "ITM-FW": "ControlCo"}[item["item_id"]]
    (tmp_path / "plans").mkdir()
    (tmp_path / "plans" / "cell.json").write_text(json.dumps(plan))

    for n, serial in enumerate(("CELL-0412", "CELL-0501")):
        write_export(tmp_path / "exports" / serial,
                     stamp="2026-09-14T06:02:11Z", operator="ci", seq=f"004{n}")

    key = SigningKey.generate()
    (tmp_path / "controlco.pub").write_text(key.verifying.pem())
    feed = AdvisoryFeed(tmp_path / "feed.jsonl")

    config = {
        "watch_id": "plant-1",
        "organisation": "Grimaldi Engineering S.r.l.",
        "targets": [
            {"serial": s, "plan": "plans/cell.json", "root": f"exports/{s}",
             "site": "Plant 1", "country": "IT"}
            for s in ("CELL-0412", "CELL-0501")
        ],
        "feeds": [{"supplier_id": "controlco", "feed": "feed.jsonl",
                   "public_key": "controlco.pub"}],
    }
    (tmp_path / "watch.json").write_text(json.dumps(config))
    return {"dir": tmp_path, "key": key, "feed": feed,
            "ledger": EvidenceLedger(tmp_path / "evidence.db")}


def _run(plant, **kw):
    return run_watch(WatchConfig.from_json(plant["dir"] / "watch.json"),
                     plant["ledger"], **kw)


# =====================================================================
class TestConfig:
    def test_a_subscription_without_a_key_is_refused(self):
        with pytest.raises(WatchError, match="public_key"):
            FeedSubscription(supplier_id="controlco", feed="f.jsonl",
                             public_key="")

    def test_a_supplier_cannot_be_subscribed_twice(self, plant):
        body = json.loads((plant["dir"] / "watch.json").read_text())
        body["feeds"].append(dict(body["feeds"][0]))
        (plant["dir"] / "watch.json").write_text(json.dumps(body))
        with pytest.raises(WatchError, match="twice"):
            WatchConfig.from_json(plant["dir"] / "watch.json")

    def test_feed_paths_resolve_against_the_config(self, plant):
        config = WatchConfig.from_json(plant["dir"] / "watch.json")
        assert config.feeds[0].feed == str(plant["dir"] / "feed.jsonl")
        assert config.feeds[0].public_key == str(plant["dir"] / "controlco.pub")

    def test_a_watch_with_no_feeds_still_works(self, plant):
        body = json.loads((plant["dir"] / "watch.json").read_text())
        body.pop("feeds")
        (plant["dir"] / "watch.json").write_text(json.dumps(body))
        run = _run(plant)
        assert run.advisories.feeds == ()
        assert run.verdict in ("quiet", "findings")


# =====================================================================
class TestTheFourJudgements:
    def test_an_advisory_that_matches_a_still_machine_is_a_finding(self, plant):
        _run(plant)  # enrol
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        run = _run(plant)

        assert run.verdict == "findings"
        assert len(run.advisories.new) == 1
        finding = run.advisories.new[0]
        assert finding.advisory_id == "CTRL-2026-11"
        assert finding.stops_use
        assert len(finding.machines) == 2

    def test_the_same_advisory_is_not_announced_twice(self, plant):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        first = _run(plant)
        assert first.advisories.new

        second = _run(plant)
        assert second.advisories.new == ()
        assert second.verdict == "quiet"
        # It has not been forgotten either: it is still carried, as outstanding.
        assert [f.state for f in second.advisories.findings] == ["outstanding"]

    def test_a_withdrawal_is_announced_once_and_says_why_it_matters(self, plant):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant)
        withdraw("CTRL-2026-11", "3.9.0 is not affected; the range was wrong",
                 IDENTITY, plant["key"], plant["feed"])

        run = _run(plant)
        assert run.verdict == "findings"
        assert len(run.advisories.withdrawn) == 1
        assert "range was wrong" in run.advisories.withdrawn[0].withdrawal_reason

        again = _run(plant)
        assert again.advisories.withdrawn == ()
        assert again.verdict == "quiet"

    def test_a_withdrawal_nobody_was_told_about_is_not_announced(self, plant):
        """Published and retracted between two runs. Nothing was acted on here,
        so saying anything would be noise."""
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        withdraw("CTRL-2026-11", "wrong range", IDENTITY, plant["key"],
                 plant["feed"])
        run = _run(plant)
        assert run.advisories.withdrawn == ()
        assert run.advisories.new == ()

    def test_a_missing_feed_is_degraded_not_quiet(self, plant):
        """A sync that silently stopped must never read as a quiet week."""
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant)
        plant["feed"].path.unlink()

        run = _run(plant)
        assert run.verdict == "degraded"
        assert len(run.advisories.degraded) == 1
        assert run.advisories.degraded[0].status == "absent"
        assert "not the same as" in run.advisories.degraded[0].detail

    def test_a_feed_that_does_not_verify_is_degraded_and_acted_on_by_nothing(
            self, plant):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        raw = json.loads(plant["feed"].path.read_text().splitlines()[0])
        raw["advisory"]["remedy"] = "Flash http://evil.example/fw.bin."
        plant["feed"].path.write_text(json.dumps(raw) + "\n")

        run = _run(plant)
        assert run.verdict == "degraded"
        assert run.advisories.degraded[0].status == "unverifiable"
        assert run.advisories.findings == ()

    def test_the_wrong_key_is_degraded_rather_than_silently_clear(self, plant):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        (plant["dir"] / "controlco.pub").write_text(
            SigningKey.generate().verifying.pem())
        run = _run(plant)
        assert run.verdict == "degraded"
        assert run.advisories.findings == ()


# =====================================================================
class TestWhatItSaysAboutItself:
    def test_an_advisory_that_touches_nothing_is_not_a_finding(self, plant):
        _run(plant)
        publish(_advisory("OTHER-1", affected=(AffectedArtefact(
            supplier="SomebodyElse", name="Unrelated part",
            versions=("1.0",)),)), IDENTITY, plant["key"], plant["feed"])
        run = _run(plant)
        assert run.advisories.findings == ()
        assert run.advisories.feeds[0].status == "verified"
        assert run.verdict == "quiet"

    def test_the_run_names_the_sync_it_cannot_see(self, plant):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        run = _run(plant)
        joined = " ".join(run.checks_skipped)
        assert "a sync that silently stopped" in joined
        assert "belongs to this supplier was not checked" in joined

    def test_the_advisory_pass_is_sealed_into_the_ledger(self, plant):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant)
        runs = list(plant["ledger"].entries(kind="watch.run"))
        body = runs[-1].evidence().body
        assert body["advisories"]["findings"][0]["advisory_id"] == "CTRL-2026-11"

    def test_check_feeds_alone_needs_no_ledger_writes(self, plant):
        from assurance.fleet.registry import Fleet

        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        config = WatchConfig.from_json(plant["dir"] / "watch.json")
        result = check_feeds(list(config.feeds),
                             Fleet.from_ledger(plant["ledger"]))
        assert result.is_finding
        assert result.stop_use


# =====================================================================
class TestCli:
    def _cli(self, *argv) -> int:
        from assurance.watch.cli import main

        return main(list(argv))

    def test_stop_use_is_printed_first_and_alone(self, plant, capsys):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        capsys.readouterr()
        rc = self._cli("run", str(plant["dir"] / "watch.json"),
                       "--ledger", str(plant["dir"] / "evidence.db"))
        out = capsys.readouterr().out
        assert rc == 1
        assert "** STOP USE **" in out
        assert "Update to 3.9.1." in out
        assert "https://controlco.example" in out

    def test_a_broken_sync_exits_two(self, plant, capsys):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant)
        plant["feed"].path.unlink()
        capsys.readouterr()
        rc = self._cli("run", str(plant["dir"] / "watch.json"),
                       "--ledger", str(plant["dir"] / "evidence.db"))
        assert rc == 2
        assert "blind to this supplier" in capsys.readouterr().out

    def test_the_withdrawal_warning_names_the_consequence(self, plant, capsys):
        _run(plant)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant)
        withdraw("CTRL-2026-11", "the range was wrong", IDENTITY,
                 plant["key"], plant["feed"])
        capsys.readouterr()
        self._cli("run", str(plant["dir"] / "watch.json"),
                  "--ledger", str(plant["dir"] / "evidence.db"))
        out = capsys.readouterr().out
        assert "WITHDRAWN" in out
        assert "rests on a retracted advisory" in out
