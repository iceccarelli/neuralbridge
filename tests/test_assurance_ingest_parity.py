"""The CLI, the HTTP API and MCP are one capability: the same domain function, the same answer.

One synthetic SBOM and one synthetic CSAF advisory go through all three surfaces, each onto its own
ledger (the CLI onto a file, the API and MCP onto two hosted accounts of one live server). The
facts compared are the domain fields (draft id, SHA-256, counts, unknowns, per-machine results and
their reasons); the envelopes (exit codes, HTTP statuses, ``{status, body}``) are not.
The review has no MCP tool by design; the hosted MCP world's machine is enrolled through the API.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from . import interfaces_fixtures as fx  # noqa: E402
from .ingest_support import approve, csaf_doc, raw, sbom_doc  # noqa: E402
from .interfaces_scenario import run_cli  # noqa: E402

live_api = fx.live_api


def _sbom_text() -> str:
    return raw(sbom_doc()).decode()


def _csaf_text() -> str:
    return raw(csaf_doc()).decode()


class Surfaces:
    def __init__(self, live: fx.LiveApi, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.live, self.root, self.monkeypatch = live, root, monkeypatch
        self.ledger = root / "cli.db"
        (root / "sbom.json").write_text(_sbom_text(), "utf-8")
        (root / "csaf.json").write_text(_csaf_text(), "utf-8")
        self.api_id, self.api_headers = live.account("ingest-parity-api@example.de")
        self.mcp_id, self.mcp_headers = live.account("ingest-parity-mcp@example.de")
        self.client = live.client()

    # ---- CLI
    def cli(self, *argv: Any) -> dict[str, Any]:
        done = run_cli(*argv, "--json", cwd=self.root)
        assert done.stdout.strip(), (argv, done.returncode, done.stderr)
        return json.loads(done.stdout)

    def cli_run(self, *argv: Any):
        return run_cli(*argv, cwd=self.root)

    # ---- API
    def api(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        r = self.client.request(method, path, headers=self.api_headers, **kw)
        assert r.status_code == 200, (method, path, r.status_code, r.text[:300])
        return r.json()

    # ---- MCP
    def mcp(self, tool: str, **args: Any) -> dict[str, Any]:
        from assurance.mcp import server

        self.monkeypatch.setenv("ASSURANCE_API_URL", self.live.url)
        self.monkeypatch.setenv("ASSURANCE_API_KEY", self.mcp_headers["X-API-Key"])
        out = asyncio.run(getattr(server, tool)(**args))
        assert out["status"] == 200, (tool, out)
        return out["body"]


@pytest.fixture()
def s(live_api, tmp_path, monkeypatch):
    return Surfaces(live_api, tmp_path, monkeypatch)


def pick(d: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: d[k] for k in keys}


IMPORT_FIELDS = ("status", "written", "draft_id", "review_state", "counts", "warnings",
                 "decisions_required", "does_not_establish")


def machine_view(impact: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"machine": m["machine"], "state": m["state"], "reason_codes": m["reason_codes"],
             "named": m["named_by_advisory"],
             "items": [(i["item_id"], i["state"], i["reason_codes"], i["identity"],
                        i["item_hash_basis"], i["vulnerabilities"]) for i in m["items"]]}
            for m in impact["machines"]]


def test_the_sbom_import_gives_the_same_draft_on_all_three(s):
    cli = s.cli("ingest", "sbom-import", "sbom.json", "--ledger", s.ledger, "--name", "sbom.json")
    api = s.api("POST", "/v1/ingest/sbom", json={"document": _sbom_text(), "source_name": "sbom.json"})
    mcp = s.mcp("sbom_import", document=_sbom_text(), source_name="sbom.json")
    assert pick(cli, *IMPORT_FIELDS) == pick(api, *IMPORT_FIELDS) == pick(mcp, *IMPORT_FIELDS)
    assert cli["source"] == api["source"] == mcp["source"]
    assert cli["status"] == "imported" and cli["review_state"] == "pending_review"

    draft_id = cli["draft_id"]
    shown_cli = s.cli("ingest", "sbom-show", draft_id, "--ledger", s.ledger)
    shown_api = s.api("GET", f"/v1/ingest/sbom/{draft_id}")
    shown_mcp = s.mcp("sbom_draft", draft_id=draft_id)
    assert shown_cli["draft"] == shown_api["draft"] == shown_mcp["draft"]
    assert shown_cli["review_template"] == shown_api["review_template"] == \
        shown_mcp["review_template"]

    rows = [pick(d, "draft_id", "review_state", "components", "source_sha256", "source_name",
                 "spec_version") for d in (
        s.cli("ingest", "sbom-list", "--ledger", s.ledger)["drafts"][0],
        s.api("GET", "/v1/ingest/sbom")["drafts"][0],
        s.mcp("sbom_drafts")["drafts"][0])]
    assert rows[0] == rows[1] == rows[2]


def test_a_second_import_of_the_same_bytes_is_already_imported_on_all_three(s):
    for first, second in (
            (lambda: s.cli("ingest", "sbom-import", "sbom.json", "--ledger", s.ledger),) * 2,
            (lambda: s.api("POST", "/v1/ingest/sbom", json={"document": _sbom_text()}),) * 2,
            (lambda: s.mcp("sbom_import", document=_sbom_text()),) * 2):
        first()
        assert second()["status"] == "already_imported"


def test_the_csaf_import_gives_the_same_record_on_all_three(s):
    cli = s.cli("ingest", "csaf-import", "csaf.json", "--ledger", s.ledger, "--name", "csaf.json",
                "--url", "https://controlco.example/a.json")
    kw = {"source_name": "csaf.json", "source_url": "https://controlco.example/a.json"}
    api = s.api("POST", "/v1/ingest/csaf", json={"document": _csaf_text(), **kw})
    mcp = s.mcp("csaf_import", document=_csaf_text(), **kw)
    fields = ("status", "written", "advisory_ref", "source", "publisher", "tracking", "title",
              "vulnerabilities", "products", "partial", "partial_reasons", "trust",
              "translation_ok")
    assert pick(cli, *fields) == pick(api, *fields) == pick(mcp, *fields)
    ref = cli["advisory_ref"]
    rec_cli = s.cli("ingest", "csaf-show", ref, "--ledger", s.ledger)["record"]
    rec_api = s.api("GET", f"/v1/ingest/csaf/{ref}")["record"]
    rec_mcp = s.mcp("csaf_record", advisory_ref=ref)["record"]
    assert rec_cli == rec_api == rec_mcp
    listed = [pick(a, "advisory_ref", "tracking_id", "tracking_version", "publisher_name",
                   "source_sha256") for a in (
        s.cli("ingest", "csaf-list", "--ledger", s.ledger)["advisories"][0],
        s.api("GET", "/v1/ingest/csaf")["advisories"][0],
        s.mcp("csaf_records")["advisories"][0])]
    assert listed[0] == listed[1] == listed[2]


def test_the_machine_by_machine_result_is_the_same_on_all_three(s):
    # enrol the same machine in each world through the review: CLI by file, API by a decider; the
    # MCP world is reviewed through the API too (MCP has no review tool, by design)
    s.cli("ingest", "sbom-import", "sbom.json", "--ledger", s.ledger)
    draft_id = s.api("POST", "/v1/ingest/sbom", json={"document": _sbom_text()})["draft_id"]
    s.mcp("sbom_import", document=_sbom_text())
    template = s.api("GET", f"/v1/ingest/sbom/{draft_id}")["review_template"]
    request = approve(template)
    (s.root / "review.json").write_text(json.dumps(request), "utf-8")

    reviewed_cli = s.cli("ingest", "sbom-review", draft_id, "review.json", "--ledger", s.ledger,
                         "--actor", "Maria Rossi")
    body = {k: v for k, v in request.items() if k not in ("draft_id", "instructions")}
    for ident, headers in ((s.api_id, s.api_headers), (s.mcp_id, s.mcp_headers)):
        key = s.live.operator_headers(ident, "Maria Rossi")
        r = s.client.post(f"/v1/ingest/sbom/{draft_id}/review", headers=key, json=body)
        assert r.status_code == 200, r.text
        reviewed_api = r.json()
        assert pick(reviewed_cli, "status", "machine", "configuration_hash", "tier_ceiling") == \
            pick(reviewed_api, "status", "machine", "configuration_hash", "tier_ceiling")
        assert headers

    cli = s.cli("ingest", "csaf-import", "csaf.json", "--ledger", s.ledger)
    s.api("POST", "/v1/ingest/csaf", json={"document": _csaf_text()})
    s.mcp("csaf_import", document=_csaf_text())
    ref = cli["advisory_ref"]
    impact_cli = s.cli("ingest", "csaf-impact", ref, "--ledger", s.ledger)
    impact_api = s.api("GET", f"/v1/ingest/csaf/{ref}/impact")
    impact_mcp = s.mcp("csaf_impact", advisory_ref=ref)
    assert machine_view(impact_cli) == machine_view(impact_api) == machine_view(impact_mcp)
    for key in ("counts", "not_named", "complete", "machines_in_fleet", "machines_affected",
                "ledger_chain_verified", "does_not_establish"):
        assert impact_cli[key] == impact_api[key] == impact_mcp[key], key
    assert impact_cli["machines"][0]["state"] == "affected"
    drop = ("ledger_entry",)
    prov = [{k: v for k, v in i["provenance"].items() if k not in drop}
            for i in (impact_cli, impact_api, impact_mcp)]
    assert prov[0] == prov[1] == prov[2]


def test_the_same_refusals_on_all_three(s):
    bad = sbom_doc()
    bad["components"][0]["bom-ref"] = bad["components"][1]["bom-ref"]
    (s.root / "bad.json").write_text(raw(bad).decode(), "utf-8")
    done = s.cli_run("ingest", "sbom-import", "bad.json", "--ledger", s.ledger)
    assert done.returncode == 2 and "SBOM-R11" in done.stderr
    r = s.client.post("/v1/ingest/sbom", headers=s.api_headers, json={"document": raw(bad).decode()})
    assert r.status_code == 422 and any("SBOM-R11" in v for v in r.json()["detail"]["violations"])
    from assurance.mcp import server

    s.monkeypatch.setenv("ASSURANCE_API_URL", s.live.url)
    s.monkeypatch.setenv("ASSURANCE_API_KEY", s.mcp_headers["X-API-Key"])
    out = asyncio.run(server.sbom_import(document=raw(bad).decode()))
    assert out["status"] == 422
    assert any("SBOM-R11" in v for v in out["body"]["detail"]["violations"])
    assert not s.ledger.exists(), "a refused document must not even create a ledger file"


def test_the_cli_review_needs_a_named_person(s):
    s.cli("ingest", "sbom-import", "sbom.json", "--ledger", s.ledger)
    draft_id = s.cli("ingest", "sbom-list", "--ledger", s.ledger)["drafts"][0]["draft_id"]
    (s.root / "review.json").write_text(json.dumps({"decision": "reject", "reason": "x"}), "utf-8")
    for who in ("bot", "automation", "system"):
        done = s.cli_run("ingest", "sbom-review", draft_id, "review.json", "--ledger", s.ledger,
                         "--actor", who)
        assert done.returncode == 2, (who, done.stdout, done.stderr)
