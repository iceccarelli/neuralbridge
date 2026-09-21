# NeuralBridge AI — Security Matrix

Proven (backed by code that runs and is tested) vs. claimed (asserted in a
docstring, README, or — pending live verification — on the marketing site)
vs. built-but-inert (real code, never actually invoked by the live path).
Read from code at `main @ 42787e0`. `app/security/page.tsx`'s actual
rendered claims are **[LIVE-SITE: UNVERIFIED]** — see the audit report for
why; this matrix gives a future live-site pass something concrete to check
the page against.

## RBAC

| Claim | Reality |
|---|---|
| `security/rbac.py` docstring: "flexible and robust RBAC system," `require_role()` "A FastAPI dependency decorator to protect endpoints" | **Not proven.** `get_current_user()` in this module is a hardcoded mock — always returns `User(username="mockadmin", role=Role.ADMIN)` — and the module's `User` model is annotated "A mock user model for demonstration purposes." No route file in the repo imports `rbac.py`. |
| `security/auth.py` docstring: "robust, production-quality authentication system" | **Partially real, but unwired.** The JWT/bcrypt/OAuth2 mechanics are real code, not stubs — but `get_current_user()` here depends on `CredentialsStore = Depends()`, an abstract interface with **no concrete implementation anywhere in the repo**. This dependency cannot resolve in a running app. No route imports this module either. |
| `core/router.py` docstring: `route()` "Validates permissions (RBAC + rate-limit checks)" | **False as written.** The method body goes straight from adapter lookup to `adapter.execute()`. Confirmed by direct read of `router.py:75-167`. |
| `core/gateway.py`: `MCPToolDefinition.permissions: list[str]` field | **Vestigial.** Defined on the dataclass, never read anywhere in `handle_request`/`_execute_tool`. |
| **Net effect** | Every `src/neuralbridge` REST and MCP endpoint is, as deployed today, reachable without authentication and without any permission check. This is the single most important finding for anything the `/ai` work exposes on this side of the codebase. |
| `src/assurance/api/deps.py::current_principal()` | **Real.** `X-API-Key` via `hmac.compare_digest` (constant-time), anonymous IP-keyed fallback only for always-free routes, explicit `unconfigured` mode that fails closed (503) rather than defaulting open. Entitlement gates (`require_register`, `require_machine`, `require_attestation`, `require_supplier`) check `principal.plan.<feature>` and return 402 (not 403) for an authenticated-but-unentitled caller — a deliberate, documented distinction. This is genuinely production-grade. |

## Sandbox / isolation

| Claim | Reality |
|---|---|
| `security/sandbox.py` docstring: "Implements strict sandboxing for plugin and adapter execution to ensure that untrusted code or third-party OpenClaw plugins cannot compromise the core middleware" | **The sandbox itself is real and well-built** — three isolation levels (Docker with `--network=none`/`--cap-drop=ALL`/`--pids-limit=64`, subprocess with `ulimit` + secret-stripped env, in-process with a restricted-builtins `exec()` explicitly marked dev-only). Largest platform-side test file (257 lines). **But it is never called.** No reference to `SandboxEngine`/`execute_code`/`execute_plugin` exists anywhere in `core/`, `api/routes/`, or `adapters/` outside the sandbox module and its own test. Adapter and MCP tool execution today runs unsandboxed. |

## Secrets handling

| Claim | Reality |
|---|---|
| Connection creation masks `auth` values as `"***"` in the stored/returned record | True, but as a side effect the real credential is discarded, not encrypted-and-stored — there is no working credential store on the platform side (see data map). Don't describe this as "secrets are encrypted at rest"; the accurate description is "secrets are not persisted at all on this path." |
| `security/sandbox.py` subprocess isolation strips env vars matching TOKEN/SECRET/PASSWORD/KEY/CREDENTIAL before exec | Real, in the sandbox module — but see above, the sandbox isn't in the live execution path. |
| Assurance airgap kit: "No account, no upload, no DNS if the airgap guard is armed" | **Proven by design and tested** — the guard arms over the process's socket layer, refuses all outbound connections including name resolution, and records any attempted call site into the local ledger. This is the strongest secrets/exfiltration claim in the repo and it is backed by code + tests (`test_assurance_kit.py`). |

## Prompt injection / external-content handling

- No prompt-injection-specific handling code exists yet anywhere in the
  repo — there is no `/ai` route, no LLM call site, and no agent
  orchestrator in `src/neuralbridge/` or `src/assurance/` as of this commit.
  This is expected: it's Phase 1 work, not something to audit as
  present/absent in Phase 0. Flagging here only so Phase 1 doesn't treat
  "no findings" as "handled" — it means "not built yet."
- The one adjacent precedent worth reusing: the assurance MCP server's
  fail-closed pattern (`_NOT_CONFIGURED`, honest 401/402 passthrough,
  "there is no local simulation, no canned response, no success faked") is
  exactly the posture Phase 1's agent orchestrator needs for treating
  adapter/tool output as data, not instructions — external content (a row
  from a Slack channel, a value from a Postgres table) must never be
  allowed to alter what tool the agent calls next without going back
  through the same approval gate a user-issued request would.

## Audit trail integrity

| Claim | Reality |
|---|---|
| Platform `security/audit.py`: hash-chained, tamper-evident | **Design is real and tested** (`test_security.py`) — SHA-256 chain, `verify_integrity()` re-walks and re-hashes the whole chain. **But** default storage is `InMemoryAuditStorage` (no code path wires `PostgresAuditStorage` by default), so the chain does not survive a process restart as deployed. A hash chain that resets on every restart is not the CRA-grade audit trail the module's own docstring implies. |
| Assurance `evidence/ledger.py`: hash-chained, single-writer-enforced, deletion-detectable via counter-signature | **Real and production-grade.** `BEGIN IMMEDIATE` transactions prevent concurrent-writer forking; `max_machines_running=1` is the deployment-level enforcement of the same invariant; `attest/` provides a signature over the ledger head by a key the operator doesn't hold, specifically to detect deletion (a hash chain alone only detects editing). Backed by `test_assurance_ledger.py` and most other assurance tests transitively. |
| Actor identity on every event | **Fails today on the platform side** — `actor="system"` (router) / `actor="mcp_client"` (gateway) are the only values ever logged; no real human-session or service-principal identity is threaded through. Assurance-side events are tied to the authenticated principal via `deps.py`, which is materially better. |

## Health/readiness claims worth not repeating on a security page

- `/health/ready`: the actual check is `"ok" if registry.list_all() or True else "no_adapters"` — the `or True` makes it unconditionally "ok." Do not describe this as "verifies adapter/DB connectivity."
- `/metrics`: all counters are hardcoded to 0 (`neuralbridge_uptime_seconds: 0, # Placeholder`); this is not real Prometheus output despite the shape.
- `POST /connections/{id}/test`: always returns success/42ms regardless of the adapter or network state.

None of these are "vulnerabilities" in the exploit sense — they're honesty
gaps between what a docstring/endpoint name implies and what the code does.
They matter here because Phase 1's `/ai` route is explicitly meant to let
an AI agent (and, through it, a user) ask "is this connection healthy?" —
and today two of the three plausible ways to answer that question
(`/health/ready`, `POST /connections/{id}/test`) are non-answers dressed as
answers. Phase 1 should either fix these two endpoints or have the agent
avoid citing them as evidence of anything until they're fixed — silently
trusting them would violate the task brief's provenance requirement
("every system fact cites connection, tool, timestamp, result id").

## What to check once the live site is reachable

`app/security/page.tsx` exists in code; a future pass with network access
should confirm its rendered claims do not assert any of the following,
none of which is true of the code today:
- That the platform side enforces RBAC or authentication on any endpoint.
- That adapter/plugin execution is sandboxed.
- That the platform audit trail is durable/immutable in its default
  deployment configuration.
- That connection health checks (`/connections/{id}/test`, `/health/ready`)
  reflect real system state.

The assurance-side claims (airgap kit, hash-chained ledger,
counter-signed attestation, API-key auth with fail-closed unconfigured
mode) are, by contrast, safe to state plainly — they're backed by code and
tests as read in this audit.
