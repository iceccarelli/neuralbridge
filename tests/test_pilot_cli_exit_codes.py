"""Exit codes a script can read: a re-verification that cleared nothing is not success.

``change reverify`` used to exit 0 whenever the submission was *accepted*, even
though it printed ``blocked: below_validated_tier`` and left the case where it
was. A cron job or a script reading the exit code could not tell a cleared case
from an uncleared one. The submission is still recorded (it is evidence), so
this is not the ``1`` the same CLI uses for a refused transition: it is the
``3`` that ``assurance evidence verify`` already uses for "nothing wrong was
found, but something asked for is not established".
"""

from __future__ import annotations

import json

import pytest

from assurance.change import CaseStatus, CaseStore
from assurance.change.cli import main as change_main
from assurance.evidence.ledger import EvidenceLedger

from .support_clock import install, today_at_noon
from .test_assurance_change import LATER, drive
from .test_assurance_change import seal_a_real_verification as seal

NOT_CLEARED = 3


@pytest.fixture(autouse=True)
def _pinned_clock(monkeypatch):
    install(monkeypatch, today_at_noon())


def _reverify(tmp_path, capsys, *, attested: bool):
    path = tmp_path / "cli.db"
    led = EvidenceLedger(path)
    case, observed = drive(led, CaseStore(led), CaseStatus.AWAITING_REVERIFICATION)
    bundle = seal(led, when=LATER, attested=attested)
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(observed.to_dict()))
    capsys.readouterr()
    rc = change_main(["reverify", "--ledger", str(path), case.case_id,
                      "--manifest", str(manifest_path),
                      "--verification-hash", bundle.content_hash,
                      "--actor", "v.grimaldi"])
    out = capsys.readouterr().out
    stored = CaseStore(EvidenceLedger(path)).get(case.case_id)
    return rc, out, stored


class TestReverifyExitCode:
    def test_a_reverification_that_cleared_nothing_does_not_exit_zero(self, tmp_path, capsys):
        rc, out, stored = _reverify(tmp_path, capsys, attested=False)
        assert stored.status is CaseStatus.AWAITING_REVERIFICATION
        assert stored.required_reverifications          # nothing was cleared
        assert rc == NOT_CLEARED, out
        assert "blocked: below_validated_tier" in out   # the reason is still printed

    def test_the_uncleared_submission_is_still_recorded_not_refused(self, tmp_path, capsys):
        """3 means recorded-but-not-cleared; a refused transition stays 1."""
        rc, _, stored = _reverify(tmp_path, capsys, attested=False)
        assert rc == NOT_CLEARED
        assert stored.evidence_current["SF-01"] == "below_validated:community"

    def test_a_reverification_that_cleared_the_case_still_exits_zero(self, tmp_path, capsys):
        rc, out, stored = _reverify(tmp_path, capsys, attested=True)
        assert stored.status is CaseStatus.READY_TO_CLOSE
        assert not stored.required_reverifications
        assert rc == 0, out

    def test_a_refused_transition_keeps_exit_one(self, tmp_path, capsys):
        path = tmp_path / "cli.db"
        led = EvidenceLedger(path)
        case, observed = drive(led, CaseStore(led), CaseStatus.AWAITING_REVERIFICATION)
        manifest_path = tmp_path / "m.json"
        manifest_path.write_text(json.dumps(observed.to_dict()))
        rc = change_main(["reverify", "--ledger", str(path), case.case_id,
                          "--manifest", str(manifest_path),
                          "--verification-hash", "b" * 64, "--actor", "v.grimaldi"])
        assert rc == 1

    def test_the_documented_exit_codes_name_the_new_one(self):
        from assurance.change import cli

        doc = " ".join((cli.__doc__ or "").split())
        assert "3 a re-verification was recorded but cleared nothing" in doc
