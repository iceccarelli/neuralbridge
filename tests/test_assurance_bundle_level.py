"""One implementation of the bundle rules, and an honest answer to 'how much is ok worth?'.

``verify_bundle`` answers ``(ok, problems)`` and ``ok`` means *no inconsistency
found*. A seal is not a signature, so a bundle someone built by hand and sealed
again can be ``ok``. These tests pin what the checker says in that case
(``level``), that the library, the CLI and the HTTP routes apply the same rules,
and that a replay compares every sealed field the original inputs can give.
"""

from __future__ import annotations

import copy
import json

import pytest

from assurance.core.tiers import AssuranceTier
from assurance.machine.bundle import check_bundle, verify_bundle
from assurance.machine.cli import main
from assurance.machine.envelope import SafetyEnvelope

from .support_recorder import RECORDER, build_attested_bundle
from .test_assurance_bundle_check import (
    ACTOR,
    LIMITS,
    envelope,
    make,
    reseal,
    trace,
    write,
)


def datasheet_envelope():
    d = envelope().to_dict()
    d["stop"]["basis"] = {"kind": "datasheet", "reference": "scanner rev D", "date": ""}
    return SafetyEnvelope.from_dict(d)


def cli_files(tmp_path, env, tr, raw):
    b = write(tmp_path, raw)
    e = tmp_path / "e.json"
    e.write_text(json.dumps(env.to_dict()), encoding="utf-8")
    t = tmp_path / "t.json"
    t.write_text(json.dumps(tr.hashable_payload()), encoding="utf-8")
    return b, e, t


class TestEnvelopeCeilingIsPartOfTheCoherenceRules:
    """The ceiling used to live only in the HTTP route, so the CLI said OK."""

    def forged(self, tmp_path):
        env = datasheet_envelope()
        assert env.tier_ceiling < AssuranceTier.VALIDATED
        _, raw, _, tr = make(tmp_path, env=env)
        raw["evidence"]["body"]["tier"] = "validated"
        raw["result"]["tier"] = "validated"
        raw["result"]["may_claim_physical_behaviour"] = True
        return reseal(raw)

    def test_the_library_refuses_a_tier_above_the_envelopes_own_ceiling(self, tmp_path):
        ok, problems = verify_bundle(write(tmp_path, self.forged(tmp_path)))
        assert not ok
        assert any("envelope" in p and "ceiling" in p for p in problems)

    def test_the_cli_refuses_it_too(self, tmp_path, capsys):
        assert main(["check", str(write(tmp_path, self.forged(tmp_path)))]) == 1
        out = capsys.readouterr().out
        assert "REJECTED" in out and "ceiling" in out

    def test_a_genuine_datasheet_bundle_is_not_refused(self, tmp_path):
        _, raw, env, tr = make(tmp_path, env=datasheet_envelope())
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert ok and problems == []


class TestReplayComparesEverySealedFieldItCanDerive:
    @pytest.mark.parametrize("field,value", [
        ("trace_started_at", "2026-10-20T04:31:00Z"),
        ("product", "Other Cell"),
        ("product_version", "9.9.9"),
        ("trace_id", "RUN-FORGED"),
        ("provenance", "bench"),
        ("surprise", "an injected field"),
    ])
    def test_a_resealed_body_field_the_inputs_do_not_give_is_caught(
            self, tmp_path, field, value):
        _, raw, env, tr = make(tmp_path)
        assert raw["evidence"]["body"].get(field) != value
        raw["evidence"]["body"][field] = value
        del raw["result"]          # isolate the replay from the printed-result check
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)), envelope=env, trace=tr)
        assert not ok
        assert any(field in p for p in problems), problems

    def test_a_resealed_confidence_the_result_does_not_earn_is_caught(self, tmp_path):
        # HIGH confidence needs a physical tier, which a declared provenance does not
        # reach; seal a recording a trusted recorder really attested to have one to tamper.
        env, tr = envelope(), trace()
        raw = json.loads(json.dumps(build_attested_bundle(env, tr, actor=ACTOR).to_dict()))
        assert raw["evidence"]["confidence"] == "high"
        raw["evidence"]["confidence"] = "medium"
        del raw["result"]
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)), envelope=env, trace=tr,
                                     recorder_trust=RECORDER.trust())
        assert not ok and any("confidence" in p for p in problems)

    def test_an_added_relation_is_caught(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        raw["evidence"]["relations"].append(
            {"relation": "supersedes", "content_hash": "a" * 64, "note": "x"})
        del raw["result"]
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)), envelope=env, trace=tr)
        assert not ok and any("relation" in p for p in problems)

    def test_the_original_inputs_still_reproduce_a_genuine_bundle(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert ok and problems == []


class TestTheStandardSetOfChecks:
    def fabricated(self, tmp_path):
        """One invented check on a field, validated, HIGH bundle: hand-built, resealed."""
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["checks"] = [
            {"name": "all_good", "outcome": "verified", "violation_count": 0,
             "violations": []}]
        del raw["result"]
        return reseal(raw)

    def test_a_fabricated_one_check_bundle_is_rejected(self, tmp_path):
        ok, problems = verify_bundle(write(tmp_path, self.fabricated(tmp_path)))
        assert not ok
        assert any("all_good" in p for p in problems)

    def test_a_dropped_check_is_rejected_without_the_originals(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["checks"] = [
            c for c in raw["evidence"]["body"]["checks"] if c["name"] != "speed_limit"]
        del raw["result"]
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok and any("speed_limit" in p for p in problems)

    def test_a_duplicated_check_is_rejected(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        checks = raw["evidence"]["body"]["checks"]
        checks.append(copy.deepcopy(checks[0]))
        del raw["result"]
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok and any(checks[0]["name"] in p and "twice" in p for p in problems)

    def test_the_set_comes_from_the_engine_not_a_copy_of_its_names(self, tmp_path):
        from assurance.machine import bundle as bundle_module
        _, raw, _, _ = make(tmp_path)
        names = {c["name"] for c in raw["evidence"]["body"]["checks"]}
        assert set(bundle_module._standard_check_names()) == names

    def test_another_engine_versions_set_is_a_limitation_not_a_guess(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["engine_version"] = "0-old"
        raw["evidence"]["body"]["checks"] = raw["evidence"]["body"]["checks"][:3]
        del raw["result"]
        _, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert any("NOT CHECKED" in p and "0-old" in p for p in problems)


class TestLevel:
    """``ok`` stays 'no inconsistency found'; ``level`` says how much that is worth."""

    def test_a_genuine_bundle_alone_is_integrity_only(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        r = check_bundle(write(tmp_path, raw))
        assert r.ok and r.level == "integrity_only" and not r.reproduced

    def test_with_the_originals_it_is_reproduced(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        r = check_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert r.ok and r.level == "reproduced" and r.reproduced
        assert r.replayed and r.seal_intact and r.internally_consistent

    def test_a_failure_is_rejected(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["verdict"] = "fail"
        r = check_bundle(write(tmp_path, raw))
        assert not r.ok and r.level == "rejected" and not r.reproduced
        assert not r.seal_intact

    def test_only_the_envelope_is_not_a_reproduction(self, tmp_path):
        _, raw, env, _ = make(tmp_path)
        r = check_bundle(write(tmp_path, raw), envelope=env)
        assert r.ok and r.level == "integrity_only"

    def test_a_pfl_bundle_without_its_table_is_not_a_reproduction(self, tmp_path):
        env, tr = envelope(pfl=True), trace(pfl=True)
        _, raw, _, _ = make(tmp_path, env=env, tr=tr, limits=LIMITS)
        r = check_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert r.ok and r.level == "integrity_only" and not r.replayed
        assert any("limits" in n for n in r.limitations)
        full = check_bundle(write(tmp_path, raw), envelope=env, trace=tr, limits=LIMITS)
        assert full.level == "reproduced"

    def test_the_tuple_contract_is_unchanged(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        ok, notes = verify_bundle(write(tmp_path, raw))
        assert ok is True and isinstance(notes, list)
        assert notes and all(n.startswith("NOT CHECKED") for n in notes)

    def test_a_hand_built_coherent_bundle_is_ok_and_never_called_reproduced(
            self, tmp_path):
        """A seal is not a signature: that is the documented contract."""
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["trace_started_at"] = "2020-01-01T00:00:00Z"
        r = check_bundle(write(tmp_path, reseal(raw)))
        assert r.ok and r.level == "integrity_only"

    def test_cli_says_not_reproduced_and_still_exits_zero(self, tmp_path, capsys):
        _, raw, env, tr = make(tmp_path)
        b, e, _ = cli_files(tmp_path, env, tr, raw)
        assert main(["check", str(b)]) == 0
        assert "NOT REPRODUCED" in capsys.readouterr().out
        assert main(["check", str(b), "--envelope", str(e)]) == 0
        assert "NOT REPRODUCED" in capsys.readouterr().out

    def test_cli_says_reproduced_when_it_was(self, tmp_path, capsys):
        _, raw, env, tr = make(tmp_path)
        b, e, t = cli_files(tmp_path, env, tr, raw)
        assert main(["check", str(b), "--envelope", str(e), "--trace", str(t)]) == 0
        out = capsys.readouterr().out
        assert "REPRODUCED" in out and "NOT REPRODUCED" not in out

    def test_cli_json_carries_the_level(self, tmp_path, capsys):
        _, raw, env, tr = make(tmp_path)
        b, e, t = cli_files(tmp_path, env, tr, raw)
        assert main(["check", str(b), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["level"] == "integrity_only"
        assert main(["check", str(b), "--envelope", str(e), "--trace", str(t),
                     "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["level"] == "reproduced" and out["ok"] is True
