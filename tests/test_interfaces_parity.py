"""The same Change Assurance sequence through the library, the CLI, the HTTP API
and MCP must produce the same case, the same states, the same refusals and
evidence that verifies offline.

Everything is real: the exports are synthetic vendor files, enrolment is the
offline kit, detection is ``watch run``, the CLI is a ``python -m assurance``
subprocess, the API is a uvicorn server on a real socket (ports 18400-18499)
with real accounts and per-account ledgers, and the hosted ledger is fed by the
real ``watch push``. The only thing not run is Stripe.

``tests/interfaces_scenario.py`` holds the sequence, written once.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from . import interfaces_fixtures as fx
from .interfaces_scenario import (
    KEY,
    PERSON,
    ApiDriver,
    CliDriver,
    LibraryDriver,
    Plant,
    rows_of,
    run_cli,
    run_sequence,
)

live_api = fx.live_api


def verify_offline(bundle: dict, tmp_path: Path, name: str) -> None:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    r = run_cli("evidence", "verify", path)
    assert r.returncode == 0 and "VERIFIED" in r.stdout, r.stdout + r.stderr


def export_shape(bundle: dict) -> list[tuple[str, str]]:
    return [(e["kind"], e["evidence"]["body"]["case"]["status"]) for e in bundle["entries"]]


def final_links(bundle: dict, relation: str) -> set[str]:
    case = bundle["entries"][-1]["evidence"]["body"]["case"]
    return {r["content_hash"] for r in case["linked_evidence"] if r["relation"] == relation}


@pytest.fixture
def world(live_api, tmp_path):
    """The same plant three times: for the library, for the CLI, and for a hosted account."""
    lib, cli, api = (Plant(tmp_path / n) for n in ("lib", "cli", "api"))
    lib.enrol_and_change("lib")
    cli.enrol_and_change("cli")
    account_id, headers = live_api.account("plant2-cell@example.de")
    api.enrol_and_change_hosted(live_api.url, headers["X-API-Key"])
    return {"lib": lib, "cli": cli, "api": api, "live": live_api,
            "account": account_id, "headers": headers}


class TestTheSameSequenceOnEveryInterface:
    def test_states_refusals_and_evidence_agree(self, world, tmp_path):
        lib, cli, api = world["lib"], world["cli"], world["api"]
        live = world["live"]
        # The case id is derived from the observed configuration, so independent
        # collections of the same files in three folders must agree on it.
        drift_id = lib.expected_drift_case_id()
        assert cli.expected_drift_case_id() == api.expected_drift_case_id() == drift_id

        drivers = {
            "library": LibraryDriver(lib),
            "cli": CliDriver(cli),
            "api": ApiDriver(
                api, live.url, world["headers"],
                operator_for=lambda who: live.operator_headers(world["account"], who)),
        }
        results = {name: run_sequence(d, drift_id) for name, d in drivers.items()}

        base = results["library"]
        for name in ("cli", "api"):
            r = results[name]
            assert len(r.trace) == len(base.trace)
            for mine, theirs in zip(r.trace, base.trace, strict=True):
                assert mine == theirs, f"{name} diverged at step {theirs[0]!r}"
            assert r.drift_id == base.drift_id and r.advisory_id == base.advisory_id
            # the queue, as each interface lists it
            assert rows_of(r.listing) == rows_of(base.listing)
            assert r.listing["summary"] == base.listing["summary"]
            # Each world dates its own verification run (see run_started), so the hash
            # itself differs between worlds; what must hold is that every world's case
            # links to ITS OWN verification, which is asserted below.
            assert len(r.verification_hash) == 64

        summary = base.listing["summary"]
        assert summary["open"] == 0 and summary["deferred"] == 0
        assert {row[1] for row in rows_of(base.listing)} == {"closed"}

        for name, r in results.items():
            for cid, bundle in r.exports.items():
                assert bundle["subject"] == cid and bundle["chain_verified"] is True
                # Same entries, same state at each, on every interface.
                assert export_shape(bundle) == export_shape(base.exports[cid]), (name, cid)
                verify_offline(bundle, tmp_path, f"{name}-{cid}")
            # The verification a case cites is the one that was sealed.
            assert final_links(r.exports[r.drift_id], "supports") == {r.verification_hash}
            # Replay rebuilds the same final case from the ledger alone.
            for cid, replay in r.replays.items():
                assert replay["ok"] is True and replay["case"]["status"] == "closed", \
                    (name, cid, replay["violations"])
            # The advisory is cited by its own hash, which is the same everywhere.
            assert final_links(r.exports[r.advisory_id], "concerns") == \
                final_links(base.exports[base.advisory_id], "concerns")

        # Waived means waived, in every export: never 'current'.
        for r in results.values():
            adv = r.exports[r.advisory_id]["entries"][-1]["evidence"]["body"]["case"]
            assert set(adv["evidence_current"].values()) == {"waived"}
            assert {d["by"] for d in adv["resolved_decisions"]} == {PERSON}

    def test_the_hosted_case_lives_only_in_the_accounts_own_ledger(self, world):
        """The API's case was opened by the real ingest of a real ``watch push``."""
        from assurance.change.store import OPENED_KIND
        from assurance.evidence.ledger import EvidenceLedger

        live = world["live"]
        drift_id = world["lib"].expected_drift_case_id()
        ledger = live.tenant_ledger(world["account"])
        assert [e.kind for e in ledger.entries(subject=drift_id)] == [OPENED_KIND]
        tenants = sorted(p.name for p in (live.root / "tenants").glob("*.db"))
        assert tenants == [world["account"] + ".db"]
        operator = live.root / "operator.db"
        assert not operator.exists() or not EvidenceLedger(operator).entries(subject=drift_id)


class TestHostedRefusalsAndMcp:
    def test_401_402_and_cross_tenant_404_on_every_verb_and_mcp_reads_agree(
            self, world, tmp_path, monkeypatch):
        import asyncio

        live = world["live"]
        drift_id = world["lib"].expected_drift_case_id()
        a_headers = world["headers"]
        b_account_id, b_headers = live.account("other-cell@example.de", "cell")
        _, r_headers = live.account("register-only@example.de", "register")

        bodies = [
            ("POST", f"/v1/change/cases/{drift_id}/claim", {"owner": PERSON, "actor": PERSON}),
            ("POST", f"/v1/change/cases/{drift_id}/advance", {"actor": PERSON}),
            ("POST", f"/v1/change/cases/{drift_id}/reverification",
             {"manifest": world["api"].manifest_dict(), "verification_content_hash": "a" * 64,
              "actor": PERSON}),
            ("POST", f"/v1/change/cases/{drift_id}/decision",
             {"disposition": "rejected", "reason": "r", "actor": PERSON}),
            ("POST", f"/v1/change/cases/{drift_id}/resume", {"reason": "r", "actor": PERSON}),
            ("POST", f"/v1/change/cases/{drift_id}/resolve-decision",
             {"decision": "q", "resolution": "r", "actor": PERSON}),
            ("POST", f"/v1/change/cases/{drift_id}/waive-reverification",
             {"entry": "SF-01", "reason": "r", "actor": PERSON}),
            ("POST", "/v1/change/assess/advisory", {"advisory": {}}),
            ("POST", "/v1/change/assess/intervention",
             {"manifest": {}, "intervention_id": "INT-1"}),
            ("GET", "/v1/change/cases", None),
            ("GET", f"/v1/change/cases/{drift_id}", None),
            ("GET", f"/v1/change/cases/{drift_id}/export", None),
            ("GET", f"/v1/change/cases/{drift_id}/replay", None),
        ]
        with live.client() as http:
            def call(method, path, body, headers):
                return http.request(method, path, json=body, headers=headers or {})

            for method, path, body in bodies:
                assert call(method, path, body, None).status_code == 401, path
                assert call(method, path, body, {"X-API-Key": "asr_nope"}).status_code == 401
                assert call(method, path, body, r_headers).status_code == 402, path

            # Another account: an empty queue, and every verb on A's case is a 404.
            assert call("GET", "/v1/change/cases", None, b_headers).json()["cases"] == []
            b_decider = live.operator_headers(b_account_id, PERSON)
            for method, path, body in bodies:
                if drift_id in path:
                    human = path.rsplit("/", 1)[-1] in (
                        "decision", "resume", "resolve-decision", "waive-reverification")
                    r = call(method, path, body, b_decider if human else b_headers)
                    assert r.status_code == 404, (path, r.status_code, r.text)
                    assert r.json()["detail"]["case_id"] == drift_id

            # A's case is exactly as the push left it.
            a_case = call("GET", f"/v1/change/cases/{drift_id}", None, a_headers).json()
            assert a_case["status"] == "open" and a_case["case_id"] == drift_id
            a_list = call("GET", "/v1/change/cases", None, a_headers).json()
            a_export = call("GET", f"/v1/change/cases/{drift_id}/export", None,
                            a_headers).json()
        verify_offline(a_export, tmp_path, "hosted")

        # MCP read tools: the same documents, no new rules.
        from assurance.mcp import server

        async def via_mcp(key: str):
            monkeypatch.setenv("ASSURANCE_API_URL", live.url)
            if key:
                monkeypatch.setenv("ASSURANCE_API_KEY", key)
            else:
                monkeypatch.delenv("ASSURANCE_API_KEY", raising=False)
            return (await server.change_cases(), await server.change_case(drift_id),
                    await server.change_export(drift_id))

        cases, case, export = asyncio.run(via_mcp(a_headers["X-API-Key"]))
        assert cases["status"] == 200 and cases["body"] == a_list
        assert case["status"] == 200 and case["body"] == a_case
        assert export["status"] == 200
        # The same bundle (only the moment of export differs) that verifies offline.
        for volatile in (export["body"], a_export):
            volatile.pop("exported_at")
            volatile["attestation"].pop("attested_at")
        assert export["body"] == a_export

        for key, expected in ((b_headers["X-API-Key"], 404), ("", 401),
                              (r_headers["X-API-Key"], 402)):
            _, case_r, export_r = asyncio.run(via_mcp(key))
            assert case_r["status"] == expected and export_r["status"] == expected, key
            if expected == 404:
                assert case_r["body"]["detail"] == {"error": "case_not_found",
                                                    "case_id": drift_id}

    def test_a_case_exported_by_the_api_verifies_with_the_cli_and_a_tampered_one_does_not(
            self, world, tmp_path):
        live = world["live"]
        drift_id = world["lib"].expected_drift_case_id()
        with live.client() as http:
            bundle = http.get(f"/v1/change/cases/{drift_id}/export",
                              headers=world["headers"]).json()
        verify_offline(bundle, tmp_path, "good")
        bundle["entries"][0]["evidence"]["body"]["case"]["status"] = "closed"
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        r = run_cli("evidence", "verify", path)
        assert r.returncode == 1 and "DOES NOT VERIFY" in r.stdout

    def test_the_machine_key_the_cases_name_is_the_one_the_verification_is_filed_under(
            self, world):
        drift = LibraryDriver(world["lib"]).get(world["lib"].expected_drift_case_id())
        assert drift["machines"] == [KEY]
