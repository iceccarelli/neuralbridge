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
| Dashboard foundation (separate Vite admin UI, not wired to the assurance API) | **Experimental / evolving** |
| Basic audit trail (in memory by default; cleared on restart) | **Experimental / evolving** |
| Small set of working adapters | **Intended supported scope** |
| Broad adapter ecosystem | **Experimental / evolving** |
| Full enterprise compliance posture | **Not part of the core promise yet** |
| Full zero-trust posture | **Not part of the core promise yet** |
| Immutable enterprise-grade audit guarantees | **Not part of the core promise yet** |
| No-code enterprise deployment for any system | **Too broad for the current promise** |

What "small set of working adapters" means today: the candidates are
PostgreSQL and REST. PostgreSQL has been exercised against a real server
only by the `/ai` control-plane and MCP tests (they skip without one). The
REST adapter sends no HTTP request: its calls are commented out behind
canned mock data, and its tests construct it and read that data. No
enterprise certification or compliance attestation is held.

Treat anything not marked **Supported** as evolving, whatever older marketing
copy elsewhere in this repository's history might have claimed. `src/dashboard`
exists as a separate Vite/React admin UI that makes no calls to the assurance API and is **not yet integrated** with the assurance
product — stated here plainly rather than glossed over.

Full detail, including what is not yet claimed, is in the
[README's platform section](https://github.com/iceccarelli/neuralbridge#neuralbridge--the-platform-underneath).
