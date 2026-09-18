"""From a signed advisory to a drafted Article 14 intake, deciding nothing.

The interesting tests are the refusals. A tool that quietly equated receipt with
awareness would either invent a filing obligation or start a real clock late,
and the second is worse. So: no duty declared means no intake at all; awareness
is never established here; and the thing that actually gets reported is a signal
that has been sitting unassessed, with the provision that makes it matter.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from assurance.attest.keys import SigningKey
from assurance.core.evidence import Actor
from assurance.core.identity import parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)
from assurance.security.art14.engine import Art14Register
from assurance.security.art14.model import Awareness, Track
from assurance.supplier import AdvisoryFeed, SupplierIdentity, publish
from assurance.watch.config import Article14Duty, WatchConfig, WatchError
from assurance.watch.filings import ARTICLE_14_WINDOW
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export

IDENTITY = SupplierIdentity(supplier_id="controlco", legal_name="ControlCo GmbH",
                            key_contact="the 2025 supply contract")


def _advisory(advisory_id="CTRL-2026-11", *, severity=AdvisorySeverity.STOP_USE,
              hashes=()) -> ComponentAdvisory:
    return ComponentAdvisory(
        advisory_id=advisory_id, issued_by="controlco",
        issued_at=parse_utc("2026-09-10T08:00:00Z"),
        title="Authentication bypass in safety controller firmware",
        summary="A crafted frame permits a safety parameter write.",
        severity=severity,
        reference="https://controlco.example/psirt/x",
        remedy="Update to 3.9.1.",
        affected=(AffectedArtefact(supplier="ControlCo",
                                   name="Safety controller firmware",
                                   versions=("3.8.2", "3.9.0"),
                                   content_hashes=tuple(hashes)),),
    )


@pytest.fixture()
def site(tmp_path):
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

    def write_config(article_14: dict | None = None) -> None:
        body = {
            "watch_id": "plant-1",
            "targets": [
                {"serial": s, "plan": "plans/cell.json", "root": f"exports/{s}",
                 "site": "Plant 1", "country": "IT"}
                for s in ("CELL-0412", "CELL-0501")],
            "feeds": [{"supplier_id": "controlco", "feed": "feed.jsonl",
                       "public_key": "controlco.pub"}],
        }
        if article_14 is not None:
            body["article_14"] = article_14
        (tmp_path / "watch.json").write_text(json.dumps(body))

    write_config({"as_manufacturer": True,
                  "received_by": "v.grimaldi@example.com"})
    return {"dir": tmp_path, "key": key, "feed": feed,
            "ledger": EvidenceLedger(tmp_path / "evidence.db"),
            "write_config": write_config}


def _run(site, **kw):
    return run_watch(WatchConfig.from_json(site["dir"] / "watch.json"),
                     site["ledger"], **kw)


# =====================================================================
class TestTheDutyIsDeclaredNeverInferred:
    def test_without_a_declaration_nothing_is_drafted(self, site):
        site["write_config"](None)
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        run = _run(site)

        assert run.advisories.new          # the advisory was still found
        assert run.filings.enabled is False
        assert run.filings.prompts == ()
        assert any("legal question about your role" in c
                   for c in run.filings.checks_skipped)

    def test_a_declared_duty_with_nobody_receiving_is_refused(self):
        with pytest.raises(WatchError, match="received_by is required"):
            Article14Duty(as_manufacturer=True, received_by="")

    def test_declaring_no_duty_needs_no_recipient(self):
        assert Article14Duty().as_manufacturer is False


# =====================================================================
class TestDrafting:
    def test_an_advisory_that_matches_produces_an_intake(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        run = _run(site)

        assert run.filings.enabled
        assert len(run.filings.drafted) == 1
        prompt = run.filings.drafted[0]
        assert prompt.advisory_id == "CTRL-2026-11"
        assert prompt.draft is not None
        assert prompt.draft.case_id == "CASE-CTRL-2026-11"

    def test_awareness_is_never_established_here(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        run = _run(site)
        prefill = run.filings.drafted[0].draft.srp_prefill()

        # The two fields a tool must never guess.
        assert "awareness_datetime" not in prefill
        assert "notification_type" not in prefill
        assert any("Only a person can make it" in c
                   for c in run.filings.checks_skipped)

    def test_a_label_only_match_confirms_nothing_and_says_so(self, site):
        """ControlCo published no hashes, so nothing is confirmed affected and
        field 5 cannot be completed. '0 machines' must never read as 'fine'."""
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        draft = _run(site).filings.drafted[0].draft

        assert draft.machines == ()
        assert len(draft.machines_needing_a_human) == 2
        assert not draft.can_complete_field_5

    def test_an_informational_advisory_does_not_draft_an_intake(self, site):
        _run(site)
        publish(_advisory(severity=AdvisorySeverity.INFORMATIONAL),
                IDENTITY, site["key"], site["feed"])
        run = _run(site)
        assert run.advisories.findings          # still reported as an advisory
        assert run.filings.prompts == ()        # but no regulatory intake

    def test_an_advisory_matching_nothing_drafts_nothing(self, site):
        _run(site)
        publish(ComponentAdvisory(
            advisory_id="OTHER-1", issued_by="controlco",
            issued_at=parse_utc("2026-09-10T08:00:00Z"),
            title="Unrelated", summary="x",
            severity=AdvisorySeverity.STOP_USE,
            reference="https://controlco.example/psirt/y",
            affected=(AffectedArtefact(supplier="Nobody", name="Nothing",
                                       versions=("1.0",)),)),
            IDENTITY, site["key"], site["feed"])
        run = _run(site)
        assert run.filings.prompts == ()


# =====================================================================
class TestTheUnassessedSignal:
    def test_receipt_is_measured_from_the_run_that_first_saw_it(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        first = _run(site)
        received = first.filings.drafted[0].received_at

        later = _run(site, now=utc_now() + timedelta(hours=5))
        assert later.filings.unassessed[0].received_at == received
        assert later.filings.unassessed[0].hours_since_receipt == pytest.approx(
            5, abs=0.1)

    def test_beyond_the_window_it_escalates_without_calling_it_a_breach(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        _run(site)

        hours = ARTICLE_14_WINDOW.total_seconds() / 3600 + 15
        run = _run(site, now=utc_now() + timedelta(hours=hours))
        assert len(run.filings.escalating) == 1
        prompt = run.filings.escalating[0]
        assert "runs 24 hours from awareness, not from receipt" in prompt.summary()
        assert "§214" in prompt.summary()
        assert run.verdict == "findings"

    def test_inside_the_window_it_is_outstanding_but_not_escalating(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        _run(site)
        run = _run(site, now=utc_now() + timedelta(hours=3))
        assert run.filings.unassessed
        assert run.filings.escalating == ()

    def test_once_a_person_records_awareness_the_prompt_stops(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        run = _run(site)
        draft = run.filings.drafted[0].draft

        register = Art14Register(site["ledger"])
        actor = Actor(identifier="v.grimaldi@example.com", role="product security")
        register.record_signal(draft.case_id, draft.signal, actor)
        moment = utc_now()
        register.record_awareness(
            draft.case_id,
            Awareness(established_at=moment,
                      assessment_started_at=moment - timedelta(hours=1),
                      assessment_completed_at=moment,
                      determined_by="v.grimaldi@example.com",
                      reasoning="Firmware confirmed as 3.9.0 on both cells after "
                                "reading the controllers directly."),
            Track.VULNERABILITY, actor)

        after = _run(site, now=utc_now() + timedelta(hours=48))
        assert after.filings.prompts == ()
        assert after.filings.escalating == ()

    def test_a_withdrawn_advisory_stops_prompting(self, site):
        from assurance.supplier import withdraw

        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        _run(site)
        withdraw("CTRL-2026-11", "the range was wrong", IDENTITY, site["key"],
                 site["feed"])
        run = _run(site, now=utc_now() + timedelta(hours=48))
        assert run.filings.prompts == ()


# =====================================================================
class TestCli:
    def _cli(self, *argv) -> int:
        from assurance.watch.cli import main

        return main(list(argv))

    def test_the_draft_never_prints_a_bare_zero(self, site, capsys):
        """'0 machines' alone reads as 'you are fine'. It usually means the
        supplier published no hashes, which is the opposite of fine."""
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        capsys.readouterr()
        self._cli("run", str(site["dir"] / "watch.json"),
                  "--ledger", str(site["dir"] / "evidence.db"))
        out = capsys.readouterr().out
        assert "0 confirmed affected (matched by hash)" in out
        assert "2 machine(s) in NEITHER column" in out
        assert "field 5: CANNOT BE COMPLETED" in out
        assert "still to be decided by a person" in out

    def test_an_escalation_cites_the_provision(self, site):
        _run(site)
        publish(_advisory(), IDENTITY, site["key"], site["feed"])
        _run(site)
        # Driven through the library: the CLI has no clock flag, deliberately.
        run = _run(site, now=utc_now() + timedelta(hours=39))
        assert run.filings.escalating
        summary = run.filings.escalating[0].summary()
        assert "§214" in summary
        assert "not from receipt" in summary
