# NeuralBridge Roadmap

What is shipped versus what is planned, kept to the same honesty standard as
the rest of this repository: nothing here is marked done unless it is gated
in code and covered by `pytest tests/ -q`. The full detail behind this table
is in the [README's platform section](README.md#neuralbridge--the-platform-underneath)
and the live [Platform status page](docs/platform.md).

## Shipped

- [x] Industrial Autonomous Assurance: CRA Art. 14 register, hash-chained
      ledger, offline enrolment kit, Article 14 draft validation
- [x] Machine safety verification (ISO/TS 15066 separation check)
- [x] Machinery Regulation Annex III manifests, passports, staleness join
- [x] Fleet advisory fan-out and hash/version/name matching
- [x] Counter-signed head attestation
- [x] FastAPI backend for connection management and tool exposure
- [x] MCP gateway for tool listing / invocation
- [x] A small set of working adapters (PostgreSQL, REST)
- [x] Dashboard foundation (`src/dashboard`) — not yet integrated with the
      assurance product

## Evolving — real, but not yet the core promise

- [ ] Broad adapter ecosystem beyond the current small supported set
- [ ] Full enterprise compliance posture
- [ ] Full zero-trust security posture
- [ ] Supplier advisory API (skeleton shipped, gated behind an unpriced
      sales-assigned tier — see `deploy/assurance/ADR-0001-supplier-api.md`)

## Planned, not started

- [ ] Adapter marketplace
- [ ] LangChain / AutoGPT toolkits
- [ ] Serverless deployment targets (AWS Lambda, Google Cloud Functions)
- [ ] Dashboard integration with the assurance product

Treat anything not checked off as not built, whatever older marketing copy
elsewhere in this repository's history might have claimed.
