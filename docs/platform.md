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

What "small set of working adapters" means today: PostgreSQL and REST are the candidates. PostgreSQL has been exercised against a real server only by the /ai control-plane and MCP tests (they skip without one). The REST adapter sends real HTTP requests, bounded by SSRF refusal, size, time and redirect limits, and is tested only against a local HTTP server that its own test starts (tests/test_rest_adapter.py); it has not been run against any third-party API.

No enterprise certification or compliance attestation is held.

**Audit trail, as the code now is.** The platform audit trail defaults to a durable, append-only SQLite file (`neuralbridge-audit.db` next to the /ai store; `NEURALBRIDGE_AUDIT_DB` overrides; PostgreSQL via `NEURALBRIDGE_AUDIT_BACKEND=postgres`; in-memory only by explicit opt-in). It is hash-chained, safe for several worker processes, free of credentials, and refuses to start, turns `/health/ready` red (503) and refuses security-relevant calls (503) if it cannot record. It records connection create / rotate / revoke / delete, plan propose / approve / deny / execute, every adapter call and every entitlement or policy denial, each with actor and tenant. It is not an immutable-by-construction store: anyone with write access to the file can edit it, and the hash chain then fails verification (`/api/v1/logs/export` recomputes it); there is no external anchoring or signed head for this trail, so truncation of the whole file is not detected. Retention is the operator's: nothing here deletes or rotates records. The row above still reads "in memory by default" because the homepage copy that must match it word for word (`app/lib/platformStatus.ts`) has not been updated yet; the code, and this paragraph, are the current state.

Treat anything not marked **Supported** as evolving, whatever older marketing
copy elsewhere in this repository's history might have claimed. `src/dashboard`
exists as a separate Vite/React admin UI that makes no calls to the assurance API and is **not yet integrated** with the assurance
product — stated here plainly rather than glossed over.

Full detail, including what is not yet claimed, is in the
[README's platform section](https://github.com/iceccarelli/neuralbridge#neuralbridge--the-platform-underneath).
