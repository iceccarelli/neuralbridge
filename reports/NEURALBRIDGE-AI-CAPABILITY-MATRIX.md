# NeuralBridge AI — Capability Matrix

Every row is a first-hand code read at `main @ 42787e0`, not a description of
docs. "Callable by" = who can reach this today, not who is meant to
eventually. "Tests" lists the actual file(s); "none" means grepped and found
none. Status column uses the repo's own vocabulary
(SUPPORTED / BETA / EXPERIMENTAL / PLANNED / DISABLED) where the repo
assigns one, and "unlabeled" where it doesn't.

## Legend

- **R/W**: Read / Write / Destructive, describing the operation class, not
  whether authz currently enforces the distinction.
- **Authz**: what actually runs today, not what a docstring claims.
- **Audit**: whether a call through this path produces an audit event.

---

## `src/neuralbridge/` — integration platform

| Capability | Path | Layer | Human/AI callable | R/W | Authz (actual) | Audit | Tests | Status |
|---|---|---|---|---|---|---|---|---|
| AdapterRegistry | `core/router.py` | backend | internal only | n/a | none | no | `test_adapters.py` (register/get/list_all) | unlabeled |
| RequestRouter.route() | `core/router.py` | backend | internal (called by gateway + REST) | R/W (adapter-dependent) | **none** — docstring claims "Validates permissions (RBAC + rate-limit checks)"; the method body never calls either | yes, `adapter_call`/`adapter_error` via `AuditLogger`, always `actor="system"` | none directly (only exercised transitively via `test_adapters.py`'s registry tests) | unlabeled, docstring overstates behavior |
| Connections: list/get | `api/routes/connections.py` `GET` | REST | human + any API caller | R | **none** — no `Depends()` auth on the router | no | `test_api.py` | unlabeled |
| Connections: create/update/delete | `api/routes/connections.py` `POST/PATCH/DELETE` | REST | human + any API caller | W/Destructive | **none** | no | `test_api.py` (create/get/delete happy paths) | unlabeled |
| Connections: test | `api/routes/connections.py` `POST /{id}/test` | REST | human + any API caller | nominally R | none | no | none | **fake** — hardcoded `{"test_result": "success", "latency_ms": 42}` regardless of adapter or reachability; docstring admits "In production, this would instantiate the adapter..." |
| Adapter execute (REST) | `api/routes/adapters.py` | REST | human + any API caller | R/W (adapter op-dependent) | none found wired | via router | not directly | unlabeled |
| MCP `tools/list` | `core/gateway.py` `MCPGateway.list_tools()` | MCP (stdio only) | AI agent | R | none | yes, `mcp_request` | none (`gateway.py` has zero direct test coverage) | unlabeled |
| MCP `tools/call` | `core/gateway.py` `_execute_tool()` | MCP (stdio only) | AI agent | R/W (adapter op-dependent) | **none** — `MCPToolDefinition.permissions` field exists but is never read in `handle_request`/`_execute_tool` | yes, double-logged (once at gateway, once again at router for the same call) | none | unlabeled |
| MCP StreamableHTTP transport | `core/gateway.py` | MCP | AI agent (remote) | — | — | — | none | **not implemented** — `MCPTransport.STREAMABLE_HTTP` is the enum default and is named in the module docstring as supported, but only `serve_stdio()` exists; no `serve_http()` |
| PostgreSQL adapter | `adapters/databases/postgres.py` | adapter | via router/gateway | `query`(R), `execute_sql`(W), `list_tables`(R), `describe_table`(R), `health_check`(R) | inherits router (none) | inherits router | `test_adapters.py` (import/instantiate/connect-fails-without-db) | **SUPPORTED** per README/`docs/platform.md`/ROADMAP — the only DB adapter so labeled |
| REST API adapter | `adapters/apis/rest.py` | adapter | via router/gateway | R/W per call | inherits router | inherits router | `test_adapters.py` (get_request) | **SUPPORTED** |
| Slack adapter | `adapters/messaging/slack.py` | adapter | via router/gateway | W (send_message) | inherits router | inherits router | `test_adapters.py` (send_message) | named as a good demo candidate, not formally "Supported" |
| Salesforce adapter | `adapters/erp_crm/salesforce.py` | adapter | via router/gateway | R/W | inherits router | inherits router | `test_adapters.py` (SOQL query, mocked) | Experimental/evolving |
| GraphQL/OData/SOAP adapters | `adapters/apis/{graphql,odata,soap}.py` | adapter | via router/gateway | R/W | inherits router | inherits router | **none** | Experimental/evolving |
| Cloud adapters (S3/Azure Blob/GCS) | `adapters/cloud/*.py` | adapter | via router/gateway | R/W | inherits router | inherits router | **none** | Experimental/evolving |
| DB adapters (BigQuery/Mongo/MySQL/Snowflake) | `adapters/databases/{bigquery,mongodb,mysql,snowflake}.py` | adapter | via router/gateway | R/W | inherits router | inherits router | **none** | Experimental/evolving |
| SAP adapter | `adapters/erp_crm/sap.py` | adapter | via router/gateway | R/W | inherits router | inherits router | **none** | Experimental/evolving |
| Discord/Email/Teams/Telegram adapters | `adapters/messaging/{discord,email_smtp,teams,telegram}.py` | adapter | via router/gateway | W | inherits router | inherits router | **none** | Experimental/evolving |
| Gmail/Notion adapters | `adapters/productivity/{gmail,notion}.py` | adapter | via router/gateway | R/W | inherits router | inherits router | **none** | Experimental/evolving |
| Audit logging (platform) | `security/audit.py` | backend | internal | W (append) | n/a | is the audit system | `test_security.py` | **hash-chained design is solid**; default storage wired in the app is `InMemoryAuditStorage` — not durable across restarts unless `PostgresAuditStorage` is explicitly substituted (no code path found doing so by default) |
| RBAC | `security/rbac.py` | backend | n/a — unwired | n/a | **`get_current_user()` is a hardcoded mock**, always returns `User(username="mockadmin", role=Role.ADMIN)`; not imported by any route file | n/a | `test_security.py` (tests the policy table in isolation, not absence of wiring) | scaffold, not enforced anywhere |
| Auth (JWT/OAuth2/API key) | `security/auth.py` | backend | n/a — unwired | n/a | real JWT/bcrypt implementation exists but its `get_current_user()` depends on an unimplemented `CredentialsStore` ABC — no concrete store exists, no route imports this module | n/a | `test_security.py` (import/token roundtrip only) | scaffold, not enforced anywhere |
| Sandbox execution | `security/sandbox.py` | backend | n/a — unreferenced by the execution path | n/a | n/a | has its own `audit_callback` hook, unused | `test_sandbox.py` (largest platform-side test file, 257 lines) | well-built, well-tested, **but never called** from `router.py`/`gateway.py`/`adapters/` — adapter and MCP tool execution today is not actually sandboxed |
| Compliance: CRA report / GDPR report / SBOM / incident log | `compliance/{cra_report,gdpr_report,sbom,incident_log}.py` | backend | human via API (route file: `api/routes/compliance.py`) | R (report generation) | none found wired | via router where applicable | `test_compliance.py` | README explicitly: "evolving" |
| Health `/health` | `api/routes/health.py` | REST | anyone | R | n/a (intentionally open) | no | `test_api.py` | real |
| Health `/health/ready` | `api/routes/health.py` | REST | anyone | R | n/a | no | `test_api.py` | **tautological** — `"ok" if registry.list_all() or True else "no_adapters"` is always "ok" |
| Health `/health/live` | `api/routes/health.py` | REST | anyone | R | n/a | no | `test_api.py` | always "alive", no real liveness check |
| `/metrics` | `api/routes/health.py` | REST | anyone | R | n/a | no | `test_api.py` | **placeholder** — all counters hardcoded to 0, docstring admits it isn't real `prometheus_client` output |
| Dashboard (`src/dashboard/`) | React/Vite | frontend | human | R/W (via whatever it calls) | n/a | n/a | none | "foundation" per README; ROADMAP.md: "not yet integrated with the assurance product" |
| OpenClaw skill-YAML generator | `utils/openclaw_plugin.py` | backend util | human/dev tooling | n/a | n/a | n/a | none | real, working; its generated skill description claims "50+ enterprise systems" — not matched by the ~25 adapter files that actually exist |
| OpenClaw example | `examples/openclaw_integration.py` | example | n/a | n/a | n/a | n/a | none | **broken** — calls `OpenClawPluginAdapter(...)`, a class that does not exist anywhere in the codebase; also has wrong call signatures for `AdapterRegistry.register()` and `AuditLogger.query_events()`; cannot run as written |

## `src/assurance/` — Industrial Autonomous Assurance

| Capability | Path | Layer | Human/AI callable | R/W | Authz (actual) | Audit | Tests | Status |
|---|---|---|---|---|---|---|---|---|
| Evidence ledger | `evidence/ledger.py` | backend | internal, single-writer by design | W (append-only) | n/a | is the ledger | `test_assurance_ledger.py` (203 lines) + most other assurance tests transitively | production-grade — SQLite `BEGIN IMMEDIATE`, `max_machines_running=1` deployment constraint documented and load-bearing |
| `GET /v1/plans` | `api/*` | REST + MCP (`plans()` tool) | anyone, no key | R | none needed (free) | yes | `test_assurance_billing.py`, `test_assurance_mcp.py` | real, generated from `PLANS` table |
| `POST /v1/spec/validate` | `api/*` | REST + MCP (`spec_validate()`) | anyone, no key | R (validate-only, does not record) | none needed (free) | yes | `test_assurance_art14.py` | real |
| `POST /v1/machine/verify` | `api/*` | REST + MCP (`machine_verify()`) | authenticated, **Cell-tier only** | W (seals an evidence bundle) | `X-API-Key` + `require_machine` entitlement gate → 402 if unentitled, 503 if service unconfigured | yes | `test_assurance_machine.py` (669 lines) | production-grade |
| `GET /v1/cases` | `api/*` | REST + MCP (`register_cases()`) | authenticated, **Register-tier only** | R | `X-API-Key` + `require_register` gate | yes | `test_assurance_api.py` | production-grade |
| Art. 14 register engine | `security/art14/*` | backend | via CLI/API | R/W | inherits API deps | yes | `test_assurance_art14.py` (621 lines, one of the largest) | production-grade, deadline clocks cite exact regulatory provisions |
| Machinery Annex III manifests | `machinery/*` | backend | via CLI/API | R/W | inherits API deps | yes | `test_assurance_machinery.py` (705 lines, largest test file in repo) | production-grade |
| Fleet advisory fan-out | `fleet/*` | backend | via CLI/API | R | inherits API deps | yes | `test_assurance_fleet.py` (583 lines) | production-grade |
| Attestation (sign/verify) | `attest/*` | backend | via CLI/API | verify: free; sign: gated | inherits API deps + `require_attestation` gate for signing | yes | `test_assurance_attest.py` (548 lines) | production-grade |
| Offline enrolment kit | `kit/*` | CLI, local disk only | operator, local | R for `check`; W to local disk for `run` | n/a — airgap guard blocks all outbound sockets during a run | writes to local `evidence.db`, not a network audit sink | `test_assurance_kit.py` (392 lines) | production-grade; "your ledger, your disk" |
| Watch (unattended monitor) | `watch/*` | CLI/service | operator | R | n/a | yes, distinct exit codes (0/1/2) | `test_assurance_watch*.py` (3 files, 980 lines combined) | production-grade |
| Assurance MCP server | `mcp/server.py` | MCP (stdio) | AI agent | 2 free R tools, 2 gated tools (1 R, 1 W) | thin HTTP passthrough to the real API — inherits its auth; fails closed with an honest error if `ASSURANCE_API_URL` unset, never fakes success | via the API it calls | `test_assurance_mcp.py` (128 lines) | production-grade, deliberately minimal ("nothing more" than a wrapper) |
| Billing / entitlements | `billing/plans.py`, `deps.py` | backend | internal | n/a | `X-API-Key` via `hmac.compare_digest`; 3 modes (`api_key`/`open`/`unconfigured`, the last fails closed 503); entitlement gates return 402 (not 403) for authenticated-but-unentitled | n/a | `test_assurance_billing.py` (438 lines) | this is the strongest access-control code in the repo |
| Bridge (supplier advisory → Art.14 intake) | `bridge/*` | backend | via CLI/API | R/W | inherits API deps | yes | `test_assurance_bridge.py` (345 lines) | production-grade |
| Report generation | `report/*` | backend | via CLI/API | R | inherits API deps | via caller | `test_assurance_report.py` (242 lines) | production-grade, "the page a non-engineer reads" |

## What this means for Phase 1 sizing

- The **only two capabilities that are simultaneously (a) callable by an AI
  agent via MCP today, (b) backed by real (non-mocked) authz, and (c)
  heavily tested** are the two free assurance-MCP tools (`plans`,
  `spec_validate`) and — once a key is supplied — `machine_verify` /
  `register_cases`. Everything on the `src/neuralbridge/` side that an AI
  agent could call via MCP today (`tools/list`, `tools/call` → any adapter)
  runs with **no authz enforcement at all**, despite living in a module
  whose docstring says otherwise.
- This means Phase 1's "one real READ adapter" (PostgreSQL) is not sitting
  behind broken auth that merely needs debugging — it is sitting behind
  **no auth**, on purpose or not. Wiring a real `get_current_user()` (or, at
  minimum, threading a real actor identity through `RequestRouter.route()`
  instead of the hardcoded `actor="system"`) is a Phase-1-scoped
  prerequisite, not an optional hardening pass, per the task brief's own
  requirement #4 ("Actor identity on audit events... no anonymous
  'system'").
- The fake `/connections/{id}/test` endpoint and the always-`or True`
  readiness probe are the kind of thing an AI agent asked to "check
  connection health" would otherwise cheerfully report as trustworthy
  green — Phase 1's health-reporting to the user should not surface these
  two endpoints as evidence of anything until they're fixed.
