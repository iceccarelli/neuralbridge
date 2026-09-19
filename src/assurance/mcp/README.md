# assurance-mcp

An MCP server that wraps the real Assurance API — four tools, each a thin
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

| Tool | Route | Plan |
|---|---|---|
| `plans` | `GET /v1/plans` | Free |
| `spec_validate` | `POST /v1/spec/validate` | Free |
| `machine_verify` | `POST /v1/machine/verify` | Cell |
| `register_cases` | `GET /v1/cases` | Register |

The two paid tools are included specifically to prove the fail-closed
behavior: called with no key, or a key on the wrong plan, they return the
API's real structured 401/402 — not an error from this server, and not a
fake success.

## Tests

```bash
pytest tests/test_assurance_mcp.py -v
```

Runs a real local `uvicorn` instance of the assurance API and calls the
tools against it over a real socket — no mocked HTTP.
