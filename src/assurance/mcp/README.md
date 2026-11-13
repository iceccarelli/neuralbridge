# assurance-mcp

An MCP server that wraps the real Assurance API — 53 tools, each a thin
`httpx` call to a running `assurance.api.service:app`. No local simulation,
no faked success: with `ASSURANCE_API_URL` unset, every tool returns the
same honest "not configured" error instead of pretending to call anything.

## Install

```bash
pip install -e '.[assurance-mcp]'
```

## Run

```bash
export ASSURANCE_API_URL=http://127.0.0.1:8000   # or a real deployment
export ASSURANCE_API_KEY=...                      # optional — needed for paid tools
assurance-mcp
```

Transport is stdio by default (`assurance.mcp.server:main` calls
`mcp.run()`), which is what most MCP clients — including Cursor's
`mcp.json` — expect. See `/connectors/cursor` and `/connectors/mcp` on
[neuralbridge.io](https://neuralbridge.io) for copy-paste client configs.

## Tools

53 tools. Seven write the account's ledger (the five change-queue tools and the two imports,
marked below); every other tool reads or computes and records nothing. `machine_verify` is one of
those: it verifies a run and asks the API not to seal it, so the reply says `recorded: false`.
Recording a verification is the account holder's, through `POST /v1/machine/verify` or
`assurance machine verify`. There is no tool that decides, closes, rejects, defers or resumes a
case, or that supplies a trust list or a key.

| Tool | Route | Plan | Writes the ledger |
|---|---|---|---|
| `plans` | `GET /v1/plans` | Free | no |
| `capabilities` | `GET /v1/capabilities` | Free | no |
| `spec_validate` | `POST /v1/spec/validate` | Free | no |
| `machine_verify` | `POST /v1/machine/verify` | Cell | no |
| `machine_check` | `POST /v1/machine/bundle/check` | Free | no |
| `evidence_verify` | `POST /v1/evidence/verify` | Free | no |
| `machinery_coverage` | `POST /v1/machinery/coverage` | Cell | no |
| `machinery_passport_check` | `POST /v1/machinery/passport/check` | Free | no |
| `machinery_export` | `GET /v1/machinery/export` | Cell | no |
| `machinery_passport_check_ledger` | `POST /v1/machinery/passport/check-ledger` | Cell | no |
| `fleet_report` | `GET /v1/fleet/report` | Cell | no |
| `register_cases` | `GET /v1/cases` | Register | no |
| `services` | `GET /v1/check/services` | Free | no |
| `machine_assurance_check` | `POST /v1/check/machine` | Free | no |
| `fleet_machine_assurance` | `POST /v1/check/fleet-machine` | Cell | no |
| `change_cases` | `GET /v1/change/cases` | Cell | no |
| `change_case` | `GET /v1/change/cases/{case_id}` | Cell | no |
| `change_export` | `GET /v1/change/cases/{case_id}/export` | Cell | no |
| `intel_history` | `GET /v1/intel/history` | Cell | no |
| `intel_observation` | `GET /v1/intel/observations/{seq}` | Cell | no |
| `intel_cve` | `GET /v1/intel/cve/{cve_id}` | Cell | no |
| `intel_candidates` | `GET /v1/intel/candidates` | Cell | no |
| `change_claim` | `POST /v1/change/cases/{case_id}/claim` | Cell | yes |
| `change_advance` | `POST /v1/change/cases/{case_id}/advance` | Cell | yes |
| `change_reverify` | `POST /v1/change/cases/{case_id}/reverification` | Cell | yes |
| `change_assess_drift` | `POST /v1/change/assess/drift` | Cell | yes |
| `change_assess_intervention` | `POST /v1/change/assess/intervention` | Cell | yes |
| `sbom_import` | `POST /v1/ingest/sbom` | Cell | yes |
| `csaf_import` | `POST /v1/ingest/csaf` | Cell | yes |
| `spec_fields` | `GET /v1/spec/fields` | Free | no |
| `art14_case` | `GET /v1/cases/{case_id}` | Register | no |
| `art14_history` | `GET /v1/cases/{case_id}/history` | Register | no |
| `art14_register` | `GET /v1/register` | Register | no |
| `art14_breaches` | `GET /v1/register/breaches` | Register | no |
| `art14_export` | `GET /v1/cases/{case_id}/export` | Register | no |
| `ledger_verify` | `GET /v1/ledger/verify` | Register | no |
| `attest_log` | `GET /v1/ledger/attest/log` | Cell | no |
| `attest_verify` | `POST /v1/ledger/attest/verify` | Free | no |
| `attest_service_key` | `GET /v1/ledger/attest/key` | Free | no |
| `machine_separation` | `POST /v1/machine/separation` | Free | no |
| `machinery_diff` | `POST /v1/machinery/diff` | Free | no |
| `fleet_machines` | `GET /v1/fleet/machines` | Cell | no |
| `fleet_observations` | `GET /v1/fleet/observations` | Cell | no |
| `fleet_declaration_check` | `POST /v1/fleet/declaration/check` | Free | no |
| `value_position` | `GET /v1/value` | Cell | no |
| `change_replay` | `GET /v1/change/cases/{case_id}/replay` | Cell | no |
| `supplier_trust_list` | `GET /v1/supplier/trust` | Cell | no |
| `supplier_trust_check` | `POST /v1/supplier/trust/evaluate` | Cell | no |
| `sbom_drafts` | `GET /v1/ingest/sbom` | Cell | no |
| `sbom_draft` | `GET /v1/ingest/sbom/{draft_id}` | Cell | no |
| `csaf_records` | `GET /v1/ingest/csaf` | Cell | no |
| `csaf_record` | `GET /v1/ingest/csaf/{advisory_ref}` | Cell | no |
| `csaf_impact` | `GET /v1/ingest/csaf/{advisory_ref}/impact` | Cell | no |

The paid tools are included specifically to prove the fail-closed behavior: called with no key,
or a key on the wrong plan, they return the API's real structured 401/402 — not an error from this
server, and not a fake success.

## Tests

```bash
pytest tests/test_assurance_mcp.py tests/test_assurance_mcp_write_classification.py -v
```

Runs a real local `uvicorn` instance of the assurance API and calls the
tools against it over a real socket — no mocked HTTP.
