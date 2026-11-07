# Platform status

Industrial Autonomous Assurance is built on NeuralBridge, a smaller
integration layer in this same repository: a FastAPI backend, an MCP
gateway for AI tool exposure, and a small set of adapters whose supported
scope is intended, not yet claimed. This page states plainly what is
supported today versus still evolving. The table is the README's table,
word for word, and the [homepage](https://neuralbridge.io/#platform) shows
the same rows; `tests/test_site_honesty.py` fails if the three differ.

| Area | Status |
|---|---|
| FastAPI backend | **Supported** |
| Connection management model | **Supported as a core direction** |
| MCP tool listing / invocation layer | **Supported** |
| Customer workspace (the Next.js site: /assurance, /console, /ai, reading the real APIs) | **Experimental / evolving** |
| Basic audit trail (in memory by default; cleared on restart) | **Experimental / evolving** |
| Small set of working adapters | **Intended supported scope** |
| Broad adapter ecosystem | **Experimental / evolving** |
| Full enterprise compliance posture | **Not part of the core promise yet** |
| Full zero-trust posture | **Not part of the core promise yet** |
| Immutable enterprise-grade audit guarantees | **Not part of the core promise yet** |
| No-code enterprise deployment for any system | **Too broad for the current promise** |

What "small set of working adapters" means today: PostgreSQL and REST are the candidates. PostgreSQL has been exercised against a real server only by the /ai control-plane and MCP tests (they skip without one). The REST adapter sends real HTTP requests, bounded by SSRF refusal, size, time and redirect limits, and is tested only against a local HTTP server that its own test starts (tests/test_rest_adapter.py); it has not been run against any third-party API.

No enterprise certification or compliance attestation is held.

Treat anything not marked **Supported** as evolving, whatever older marketing
copy elsewhere in this repository's history might have claimed. The former
`src/dashboard` Vite/React admin UI has been retired: it made no API calls and displayed fixed sample figures. The customer
workspace is the root Next.js app (`/assurance`, `/ai`, `/console`), which reads the real APIs and says so when it cannot —
stated here plainly rather than glossed over.

Full detail, including what is not yet claimed, is in the
[README's platform section](https://github.com/iceccarelli/neuralbridge#neuralbridge--the-platform-underneath).
