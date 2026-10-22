"""The only route to a VALIDATED limits tier is an accepted, signed, independent review.

A table's ``verified_by`` / ``verified_on`` text is written by whoever wrote the
table. These tests pin that it never lifts the tier, that a hash pin alone is not
a review, and that every way a review can be defective fails closed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.attest.keys import SigningKey
from assurance.core.evidence import Actor
from assurance.core.tiers import AssuranceTier
from assurance.machine.bundle import build_bundle, check_bundle, check_bundle_data
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.limits_review import (
    LimitsReview,
    ReviewStatus,
    ReviewTrust,
    TrustedReviewer,
    assess_reviews,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import CheckOutcome, Verdict, verify

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")


def table(**over) -> LimitsTable:
    kw = {
        "edition": "Example 2016", "transcribed_by": "a",
        "verified_by": "b", "verified_on": "2026-04-01", "transient_multiplier": 2.0,
        "regions": {"hand": BodyRegionLimit("hand", "Hand", 140.0, 140.0)},
    }
    kw.update(over)
    return LimitsTable(**kw)


def env(t: LimitsTable) -> SafetyEnvelope:
    return SafetyEnvelope(
        envelope_id="ENV-1", product="Cell", product_version="1.0.0",
        workspace=Workspace((-1000.0, -1000.0, 0.0), (1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0, OperatingMode.PFL: 250.0},
        stop=StopPerformance(0.1, 0.25, 120.0, 500.0, MEASURED),
        uncertainty=SensingUncertainty(100.0, 50.0, MEASURED),
        intrusion_distance_mm=850.0, human_approach_speed_mm_s=1600.0,
        pfl_limits_hash=t.content_hash())


def tr() -> Trace:
    samples = [Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=100.0,
                      mode=OperatingMode.PFL, contact_force=10.0, contact_area=20.0,
                      body_region="hand") for i in range(40)]
    return Trace(trace_id="RUN-1", provenance=Provenance.FIELD, source_system="fw",
                 started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC),
                 sample_rate_hz=50.0, samples=tuple(samples))


REVIEWER = SigningKey.generate()
OTHER = SigningKey.generate()


def trust(*keys, revoked=()):
    return ReviewTrust([
        TrustedReviewer(label=f"reviewer-{i}", key=k.verifying,
                        revoked=k.fingerprint in revoked)
        for i, k in enumerate(keys)])


def review(t: LimitsTable, key=REVIEWER, **over) -> LimitsReview:
    kw = {"reviewer": "Dr. R", "basis": "compared with licensed copy of Example 2016",
          "reviewed_on": "2026-09-01"}
    kw.update(over)
    return LimitsReview.sign(t, key, **kw)


def run(t, reviews=(), tr_=None, trust_=None, **kw):
    return verify(env(t), tr_ or tr(), limits=t, limits_reviews=reviews,
                  review_trust=trust_, now=NOW, **kw)


def test_the_engine_was_bumped_because_the_tier_semantics_changed():
    assert run(table()).engine_version == "4"


# -- the original defect --------------------------------------------------

def test_arbitrary_verified_by_and_pin_cannot_create_a_validated_result():
    t = table(verified_by="Anybody At All", verified_on="2026-10-01")
    r = run(t)
    assert r.check("pfl_contact").outcome is CheckOutcome.VERIFIED
    assert r.verdict is Verdict.PASS
    assert r.tier is AssuranceTier.COMMUNITY
    assert any("author's own claim" in c or "author's claim" in c for c in r.checks_skipped)
    assert r.limits_review["status"] == "none"


def test_pin_without_trusted_review_is_insufficient_even_with_a_review_attached():
    t = table()
    r = run(t, [review(t)], trust_=None)
    assert r.tier is AssuranceTier.COMMUNITY
    assert r.limits_review["status"] == "untrusted_key"


def test_a_trusted_review_bound_to_the_exact_table_is_accepted():
    t = table()
    r = run(t, [review(t)], trust_=trust(REVIEWER))
    assert r.tier is AssuranceTier.VALIDATED
    assert r.limits_review["status"] == "accepted"
    why = " ".join(r.checks_skipped)
    assert REVIEWER.fingerprint in why and "does not establish" in why


def test_validated_still_needs_the_envelope_pin():
    t = table()
    e = env(t)
    unpinned = SafetyEnvelope.from_dict({**e.to_dict(), "pfl_limits_hash": ""})
    r = verify(unpinned, tr(), limits=t, limits_reviews=[review(t)],
               review_trust=trust(REVIEWER), now=NOW)
    # An unpinned table is not checked at all, so no pass and no review can rest on it.
    assert r.check("pfl_contact").outcome is CheckOutcome.UNCHECKED
    assert r.verdict is Verdict.INCOMPLETE


def test_editing_the_table_after_review_invalidates_the_review():
    t = table()
    rv = review(t)
    edited = table(regions={"hand": BodyRegionLimit("hand", "Hand", 999.0, 999.0)})
    a = assess_reviews(edited, [rv], trust(REVIEWER), now=NOW)
    assert a.status is ReviewStatus.TABLE_MISMATCH and not a.validated
    assert run(edited, [rv], trust_=trust(REVIEWER)).tier is AssuranceTier.COMMUNITY


def test_editing_verified_by_text_also_invalidates_the_review():
    t = table()
    rv = review(t)
    assert assess_reviews(table(verified_by="someone else"), [rv], trust(REVIEWER),
                          now=NOW).status is ReviewStatus.TABLE_MISMATCH


# -- every defective review fails closed ----------------------------------

def test_unknown_key_is_refused():
    t = table()
    a = assess_reviews(t, [review(t, key=OTHER)], trust(REVIEWER), now=NOW)
    assert a.status is ReviewStatus.UNTRUSTED_KEY


def test_revoked_key_is_refused():
    t = table()
    a = assess_reviews(t, [review(t)], trust(REVIEWER, revoked={REVIEWER.fingerprint}),
                       now=NOW)
    assert a.status is ReviewStatus.REVOKED_KEY and not a.validated


def test_invalid_signature_is_refused():
    t = table()
    d = review(t).to_dict()
    d["basis"] = "edited after signing"
    a = assess_reviews(t, [d], trust(REVIEWER), now=NOW)
    assert a.status is ReviewStatus.BAD_SIGNATURE


def test_a_key_claiming_to_be_another_fingerprint_does_not_verify():
    t = table()
    d = review(t, key=OTHER).to_dict()
    d["key_fingerprint"] = REVIEWER.fingerprint  # pretend to be the trusted reviewer
    a = assess_reviews(t, [d], trust(REVIEWER), now=NOW)
    assert a.status is ReviewStatus.BAD_SIGNATURE


@pytest.mark.parametrize("bad", [None, [], "x", {"format": "nope"},
                                 {"format": "assurance.machine.limits-review.v1"}])
def test_malformed_payload_cannot_pass(bad):
    t = table()
    a = assess_reviews(t, [bad], trust(REVIEWER), now=NOW)
    assert a.status is ReviewStatus.MALFORMED and not a.validated


def test_incompatible_format_version_is_refused():
    t = table()
    d = review(t).to_dict()
    d["format"] = "assurance.machine.limits-review.v2"
    assert assess_reviews(t, [d], trust(REVIEWER), now=NOW).status is ReviewStatus.MALFORMED


def test_incompatible_edition_is_refused():
    t = table()
    rv = review(t)
    # re-sign a review claiming a different edition for the same hash
    forged = LimitsReview(**{**rv._body(), "edition": "Other 2020", "signature": ""})
    import base64
    sig = base64.b64encode(REVIEWER.sign(forged.signed_payload())).decode()
    forged = LimitsReview(**{**forged._body(), "signature": sig})
    assert assess_reviews(t, [forged], trust(REVIEWER), now=NOW).status \
        is ReviewStatus.EDITION_MISMATCH


def test_expired_and_future_dated_reviews_are_refused():
    t = table()
    assert assess_reviews(t, [review(t, expires_on="2026-10-01")], trust(REVIEWER),
                          now=NOW).status is ReviewStatus.EXPIRED
    assert assess_reviews(t, [review(t, reviewed_on="2027-01-01")], trust(REVIEWER),
                          now=NOW).status is ReviewStatus.NOT_YET_VALID


def test_a_review_with_no_stated_basis_cannot_be_created():
    with pytest.raises(Exception, match="basis"):
        LimitsReview.sign(table(), REVIEWER, reviewer="x", basis=" ",
                          reviewed_on="2026-09-01")


def test_a_trust_entry_whose_pinned_fingerprint_is_wrong_is_refused():
    d = {"format": "assurance.machine.limits-trust.v1",
         "reviewers": [{"label": "x", "public_key_pem": REVIEWER.verifying.pem(),
                        "fingerprint": OTHER.fingerprint}]}
    with pytest.raises(Exception, match="fingerprint"):
        ReviewTrust.from_dict(d)


def test_one_good_review_among_bad_ones_is_accepted_and_the_bad_are_reported():
    t = table()
    a = assess_reviews(t, [review(t, key=OTHER), review(t)], trust(REVIEWER), now=NOW)
    assert a.validated and any(f.status is ReviewStatus.UNTRUSTED_KEY for f in a.findings)


# -- bundles: library, CLI, API, replay agree ------------------------------

def sealed(t, reviews=(), trust_=None):
    return build_bundle(env(t), tr(), actor=ACTOR, limits=t, limits_reviews=reviews,
                        review_trust=trust_)


def test_bundle_records_the_review_and_replays_under_the_verifiers_own_trust():
    t = table()
    b = sealed(t, [review(t)], trust(REVIEWER))
    assert b.tier is AssuranceTier.VALIDATED
    assert b.evidence.body["limits_review"]["status"] == "accepted"
    ok = check_bundle_data(b.to_dict(), envelope=env(t), trace=tr(), limits=t,
                           review_trust=trust(REVIEWER))
    assert ok.ok and ok.reproduced
    # A verifier who does not trust the key cannot reproduce the validated tier.
    no_trust = check_bundle_data(b.to_dict(), envelope=env(t), trace=tr(), limits=t,
                                 review_trust=trust(OTHER))
    assert not no_trust.ok
    # With no trust list at all the replay is not performed and says so.
    none = check_bundle_data(b.to_dict(), envelope=env(t), trace=tr(), limits=t)
    assert none.ok and not none.reproduced
    assert any("trust list" in x for x in none.limitations)


def test_a_bundle_claiming_validated_without_an_accepted_review_is_rejected_offline():
    t = table()
    b = sealed(t)  # community: no review
    d = b.to_dict()
    d["evidence"]["body"]["tier"] = "validated"
    d["result"]["tier"] = "validated"
    # even if resealed, the coherence rule refuses validated without a review
    from assurance.core.evidence import Evidence
    ev = Evidence.from_dict(d["evidence"])
    resealed = Evidence(kind=ev.kind, body=ev.body, actor=ev.actor, origin=ev.origin,
                        validation_state=ev.validation_state, confidence=ev.confidence,
                        checks_skipped=ev.checks_skipped, relations=ev.relations).seal()
    d["evidence"] = resealed.to_dict()
    res = check_bundle_data(d)
    assert not res.ok
    assert any("independent review" in p for p in res.problems)


def test_a_tampered_review_in_a_bundle_is_not_reproduced():
    t = table()
    b = sealed(t, [review(t)], trust(REVIEWER))
    d = json.loads(json.dumps(b.to_dict()))
    d["evidence"]["body"]["limits_review"]["reviews"][0]["basis"] = "forged"
    assert not check_bundle_data(d, envelope=env(t), trace=tr(), limits=t,
                                 review_trust=trust(REVIEWER)).ok


def test_old_engine_bundle_with_validated_and_limits_gets_an_honest_limitation():
    t = table()
    b = sealed(t, [review(t)], trust(REVIEWER))
    d = json.loads(json.dumps(b.to_dict()))
    d["evidence"]["body"]["engine_version"] = "3"
    d["evidence"]["body"].pop("limits_review")
    # seal no longer matches: the edit is caught, never silently reinterpreted
    assert not check_bundle_data(d).ok


def test_cli_verify_and_check_use_the_same_contract(tmp_path: Path, capsys):
    from assurance.machine.cli import main
    t = table()
    (tmp_path / "env.json").write_text(json.dumps(env(t).to_dict()))
    (tmp_path / "trace.json").write_text(json.dumps({
        "trace_id": "RUN-1", "provenance": "field", "source_system": "fw",
        "started_at": "2026-09-12T04:31:00Z", "sample_rate_hz": 50.0,
        "samples": [{"t": i / 50.0, "tcp": [0.0, 0.0, 1000.0], "tcp_speed": 100.0,
                     "mode": "pfl", "contact_force": 10.0, "contact_area": 20.0,
                     "body_region": "hand"} for i in range(40)]}))
    (tmp_path / "limits.json").write_text(json.dumps(t.to_dict()))
    (tmp_path / "review.json").write_text(json.dumps(review(t).to_dict()))
    (tmp_path / "trust.json").write_text(json.dumps({
        "format": "assurance.machine.limits-trust.v1",
        "reviewers": [{"label": "R", "public_key_pem": REVIEWER.verifying.pem()}]}))
    base = ["machine", "verify", "--envelope", str(tmp_path / "env.json"),
            "--trace", str(tmp_path / "trace.json"), "--limits", str(tmp_path / "limits.json"),
            "--actor", "v.g", "--json"]

    def tier(extra, out):
        main_args = (base + extra + ["--out", str(tmp_path / out)])[1:]
        main(main_args)
        capsys.readouterr()
        return json.loads((tmp_path / out).read_text())["result"]["tier"]

    assert tier([], "a.json") == "community"
    assert tier(["--limits-review", str(tmp_path / "review.json")], "b.json") == "community"
    assert tier(["--limits-review", str(tmp_path / "review.json"),
                 "--limits-trust", str(tmp_path / "trust.json")], "c.json") == "validated"
    res = check_bundle(tmp_path / "c.json", envelope=env(t), trace=tr(), limits=t,
                       review_trust=ReviewTrust.from_json(tmp_path / "trust.json"))
    assert res.ok and res.reproduced


def test_api_check_reports_the_review_and_seal_ignores_caller_trust(monkeypatch):
    from fastapi.testclient import TestClient

    from assurance.api.service import app
    t = table()
    b = sealed(t, [review(t)], trust(REVIEWER))
    c = TestClient(app)
    body = {"bundle": b.to_dict(), "envelope": env(t).to_dict(), "limits": t.to_dict(),
            "limits_trust": {"format": "assurance.machine.limits-trust.v1", "reviewers": [
                {"label": "R", "public_key_pem": REVIEWER.verifying.pem()}]}}
    body["trace"] = {
        "trace_id": "RUN-1", "provenance": "field", "source_system": "fw",
        "started_at": "2026-09-12T04:31:00Z", "sample_rate_hz": 50.0,
        "samples": [{"t": i / 50.0, "tcp": [0.0, 0.0, 1000.0], "tcp_speed": 100.0,
                     "mode": "pfl", "contact_force": 10.0, "contact_area": 20.0,
                     "body_region": "hand"} for i in range(40)]}
    r = c.post("/v1/machine/bundle/check", json=body).json()
    assert r["ok"], r
    assert r["reproduced"] and r["recorded_tier"] == "validated"
    assert r["recorded_limits_review"]["status"] == "accepted"
    assert r["checked"]["limits_review"] is True
    # No trust list: validated tier is not reproduced, and the response says so.
    del body["limits_trust"]
    r2 = c.post("/v1/machine/bundle/check", json=body).json()
    assert r2["ok"] and not r2["reproduced"]
    assert any("trust list" in x for x in r2["limitations"])
    # The request-supplied trust is not a field on the sealing route.
    seal = {"envelope": env(t).to_dict(), "trace": body["trace"], "limits": t.to_dict(),
            "limits_reviews": [review(t).to_dict()], "actor": "v.g", "seal": False}
    monkeypatch.delenv("ASSURANCE_LIMITS_REVIEW_TRUST", raising=False)
    assert "limits_trust" not in __import__(
        "assurance.api.machine_routes", fromlist=["VerifyIn"]).VerifyIn.model_fields
    del seal
