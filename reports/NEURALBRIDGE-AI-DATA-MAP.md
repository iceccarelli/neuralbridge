# NeuralBridge AI — Data Map

What holds state, where, and what isolates one tenant/caller from another.
Read from code at `main @ 42787e0`.

## Connections (`src/neuralbridge`)

- **Store:** `_connections: dict[str, dict[str, Any]]`, a plain module-level
  Python dict in `api/routes/connections.py`. Not a database despite the
  file's own comment (`# In-Memory Store (production: PostgreSQL)`).
- **Lifetime:** process lifetime only. Restart the API process, every
  connection definition is gone.
- **Multi-worker:** not shared — if the API runs behind more than one
  worker/process (typical for `uvicorn --workers N` or any horizontal
  scaling), each worker has its own, divergent `_connections` dict. A
  connection created against worker A is invisible to worker B.
- **Tenant boundary:** **none.** There is no tenant/org/user field on a
  connection record at all — every connection created by any caller is
  visible to every other caller via `GET /connections`. This is a global,
  unscoped, unauthenticated table.
- **Secrets handling:** `ConnectionCreateRequest.auth` (the raw
  credential payload submitted by the caller) is **not persisted** — the
  stored record replaces it with `dict.fromkeys(request.auth, "***")`
  (masked keys, no values) before writing to `_connections`. This avoids
  storing plaintext secrets, but it also means the real credentials are
  discarded immediately after creation and are not available for a later
  adapter call to actually use — consistent with `POST /{id}/test` being
  faked (§ below) rather than a sign that credentials are handled securely
  elsewhere.
- **Connection "test"/health check:** `POST /{id}/test` does not touch the
  adapter or the network — it returns a hardcoded
  `{"test_result": "success", "latency_ms": 42}` for any connection ID that
  exists in the dict, regardless of `adapter_type` or actual reachability.

## Audit trail (`src/neuralbridge`)

- **Model:** `AuditEntry` (Pydantic) — `event_id`, `timestamp`, `event_type`,
  `actor`, `resource`, `action`, `result`, `ip_address`, `details`,
  `previous_hash`, `current_hash`. Hash-chained via SHA-256 over canonical
  JSON; genesis = `sha256("neuralbridge_genesis_block_v1")`.
- **Storage backends:** `InMemoryAuditStorage` (asyncio-lock-protected list;
  dev/test) and `PostgresAuditStorage` (real `asyncpg` INSERT/SELECT against
  an `audit_log` table) both exist in `security/audit.py`. **The app's
  default wiring uses the in-memory backend** — no code path found in
  `api/dependencies.py` that swaps in `PostgresAuditStorage` by default, so
  as deployed today the audit trail does **not** survive a restart unless an
  operator explicitly wires the Postgres backend.
- **Actor identity:** every call recorded through `RequestRouter.route()`
  logs `actor="system"`; every call recorded through
  `MCPGateway.handle_request()` logs `actor="mcp_client"`. Neither is a real
  identity — there is no session/user/service-principal distinction
  anywhere in this half of the audit trail. This directly fails the task
  brief's Phase-1 requirement #4 ("Actor identity on audit events (human
  session vs service — no anonymous 'system')") as the code stands today.
- **Double-logging:** a single MCP `tools/call` produces two audit entries
  for the same logical operation — one from the gateway (`mcp_request`) and
  one from the router (`adapter_call`) — with no shared correlation beyond
  `request_id` appearing in the `details` blob of each. A naive "audit
  event count" would overcount actual operations by roughly 2x for
  MCP-originated calls.

## Evidence ledger (`src/assurance`)

- **Store:** SQLite, one file per deployment, append-only, hash-chained.
  Writes use `BEGIN IMMEDIATE` transactions spanning the read of the
  current chain tail and the write of the new entry — the concrete
  mechanism that prevents two concurrent writers from forking the chain.
- **Deployment constraint:** `max_machines_running = 1` in
  `deploy/assurance/fly.toml` is explicitly documented (README, DEPLOY_NOW)
  as load-bearing for this reason — a second Fly.io machine writing to the
  same SQLite file would fork the chain. This is a real single-writer
  constraint, not a performance knob.
- **Tenant boundary:** entries are scoped by the authenticated principal
  (see security matrix) — `X-API-Key`-resolved principal identity is
  threaded through the entitlement gates (`require_register`,
  `require_machine`, etc.) and (based on the billing/case-count fields in
  `plans.py`) case/manifest records are per-account. Not independently
  re-verified in this pass beyond what `deps.py` and `plans.py` show; worth
  a closer read of `api/routes/*` in a future session if strict tenant
  isolation needs to be load-bearing for a compliance claim.
- **Airgap kit:** writes only to the operator's own local disk
  (`plant/out/{report.html,evidence.db,attestation-request.json}`). No
  network egress by design — the kit's guard arms over the process's socket
  layer and refuses outbound connections, including DNS resolution,
  recording any attempted call site into the local ledger. This is the one
  data flow in the repo explicitly engineered to guarantee zero exfiltration.

## Sessions / identity

- **Platform (`src/neuralbridge`) side:** no working session/identity layer
  is actually wired to any route. `security/rbac.py`'s `get_current_user()`
  is a hardcoded mock (`User(username="mockadmin", role=Role.ADMIN)`).
  `security/auth.py` has a real JWT/OAuth2/API-key implementation, but its
  `get_current_user()` depends on an unimplemented `CredentialsStore` ABC —
  no concrete store exists in the codebase, so this dependency cannot
  resolve in a running app. No route file imports either module. **There is
  no real identity concept on the platform side today** — every caller of
  every `src/neuralbridge` REST/MCP endpoint is, in effect, anonymous.
- **Assurance (`src/assurance`) side:** identity is resolved per-request in
  `api/deps.py::current_principal()` via `X-API-Key` (constant-time
  comparison), with an explicit anonymous-but-IP-keyed fallback for the
  always-free routes, and a fail-closed `unconfigured` mode (503) rather
  than silently allowing writes when auth isn't configured at all. This is
  a real, if API-key-only (no session/JWT), identity model.

## Config / secrets

- `.env.example` documents the "ASSURANCE PRODUCT" env vars (Stripe keys,
  Fly volume names, price IDs) per `DEPLOY_NOW.md`'s references — not fully
  enumerated in this pass.
- Adapter credentials submitted via `ConnectionCreateRequest.auth` on the
  platform side are, per above, masked-and-discarded rather than stored —
  so there is currently no persistent secrets store for platform adapter
  connections to audit or protect. Any Phase 1 work that needs a real
  PostgreSQL connection's credentials to actually be usable across calls
  will need to design that storage (encrypted at rest, scoped per
  connection/tenant) — it does not exist yet.

## Summary: tenant boundaries today

| Surface | Tenant/org concept | Enforcement |
|---|---|---|
| Platform connections (`_connections` dict) | none | none — global, unscoped |
| Platform audit trail | none (actor is a hardcoded string) | none |
| Platform RBAC/auth | scaffolded but unwired | none in effect |
| Assurance API (`X-API-Key`) | per-account, key-resolved | real — `hmac.compare_digest`, entitlement gates, fail-closed when unconfigured |
| Assurance evidence ledger | per-deployment (single ledger file), scoped by authenticated principal for writes | real for the single-tenant-per-deployment model the product is built around |
| Offline kit | operator's own disk, no network | real, by construction (airgap guard) |

Phase 1's `/ai` route touches the platform side (PostgreSQL adapter, one
real connection) and should not assume any tenant isolation exists there
today — it will need to either scope Phase 1 narrowly enough that the
missing isolation doesn't matter (e.g., single-operator/demo deployment) or
build minimal scoping as part of the slice, and should say explicitly in
its own docs which of the two it did.
