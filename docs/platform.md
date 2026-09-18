# Platform status

Industrial Autonomous Assurance is built on NeuralBridge, a smaller
integration layer in this same repository: a FastAPI backend, an MCP
gateway for AI tool exposure, and a small set of supported adapters. This
page states plainly what is supported today versus still evolving — the
same honest table shown on the [homepage](https://neuralbridge.io/#platform).

| Area | Status |
|---|---|
| FastAPI backend | **Supported** |
| Connection management model | **Supported** |
| MCP tool listing / invocation | **Supported** |
| Dashboard foundation | **Supported** |
| Basic audit trail | **Supported** |
| Small set of working adapters (PostgreSQL, REST) | **Supported** |
| Broad adapter ecosystem | Evolving |
| Full enterprise compliance posture | Evolving |

Treat anything not marked **Supported** as evolving, whatever older marketing
copy elsewhere in this repository's history might have claimed. `src/dashboard`
exists as a Next.js console but is **not yet integrated** with the assurance
product — stated here plainly rather than glossed over.

Full detail, including what is not yet claimed, is in the
[README's platform section](https://github.com/iceccarelli/neuralbridge#neuralbridge--the-platform-underneath).
