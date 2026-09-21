# NeuralBridge AI — Phase 0 Audit

Read-only audit. No product code changed. Starting point: `main` @ `42787e0`
(PRs #17/#18 merged: on-site roadmap/security pages, `src/assurance/mcp`).

## Method and a limitation to disclose up front

This audit compares the repository against the live site at
`https://neuralbridge.io/`. **Live-site verification could not be completed
in this environment**: outbound network access to `neuralbridge.io` (and to
`neuralbridge.vercel.app`, and to `web.archive.org`) is blocked at the
session's egress proxy — confirmed both via `WebFetch` (`EGRESS_BLOCKED`) and
a direct `curl` (`exit 56`, no connection). "Unchecked" is the honest answer
for every claim below that would require the live page, and each such item
is marked **[LIVE-SITE: UNVERIFIED]** rather than asserted. Everything else
in this report is a first-hand read of the code at the pinned commit, not a
description of GitHub PR titles or secondhand summaries.

If a future session has network access to the domain, re-run this
comparison — the routes below (`app/*/page.tsx`) already exist in code, so
the open question is only what they currently render and claim, not whether
they exist.

## Repo shape

Two products share one repository:

- `src/assurance/` — **Industrial Autonomous Assurance**, the product the
  README, `DEPLOY_NOW.md`, and the Next.js site under `app/` are actually
  built and sold around (CRA Art. 14 / Machinery Reg. Annex III 1.1.9
  evidence). 671 tests reference this tree per the README; direct count of
  `tests/test_assurance_*.py` files: 15, covering core, ledger, attest, kit,
  collect, machine, machinery, fleet, art14/CRA register, watch (+
  advisories/filings), report, bridge, supplier(+API), billing, MCP, CLI,
  API.
- `src/neuralbridge/` — the integration platform the assurance product grew
  out of: FastAPI backend, adapter framework, MCP gateway, dashboard
  foundation, audit/RBAC/sandbox scaffolding. The root `README.md` (lines
  166–366) is explicit that this half is deliberately **narrowed and
  underclaimed**: "not currently presented as a complete enterprise-ready
  universal middleware," broad adapter ecosystem is "Experimental /
  evolving," "full enterprise compliance posture" and "full zero-trust
  posture" are explicitly "Not part of the core promise yet."

This self-narrowing in the README is unusually candid and should be
preserved, not undone, by the `/ai` work — see
`NEURALBRIDGE-AI-CAPABILITY-MATRIX.md` for where the code backs that
candor up and where it doesn't yet.

## Routes that exist in code (Next.js `app/`)

| Route | File |
|---|---|
| `/` | `app/page.tsx` |
| `/applications` | `app/applications/page.tsx` |
| `/checkout`, `/checkout/success` | `app/checkout/success/page.tsx` |
| `/cli` | `app/cli/page.tsx` |
| `/connectors`, `/connectors/cursor`, `/connectors/mcp` | `app/connectors/{cursor,mcp}/page.tsx` |
| `/console` | `app/console/page.tsx` |
| `/contact` | `app/contact/page.tsx` |
| `/developers` | `app/developers/page.tsx` |
| `/docs/*` | `app/docs/[[...slug]]/page.tsx` |
| `/privacy` | `app/privacy/page.tsx` |
| `/roadmap` | `app/roadmap/page.tsx` |
| `/security` | `app/security/page.tsx` |
| `/solutions/[slug]` | `app/solutions/[slug]/page.tsx` |
| `/status` | `app/status/page.tsx` |

**[LIVE-SITE: UNVERIFIED]** whether all of these are deployed as-is, whether
nav/CTAs match, and whether any route 404s live.

There is **no `/ai` route today** — that is new surface for Phase 1, not an
upgrade of something that exists.

## Two separate UI surfaces — do not conflate them

1. **`app/*` (Next.js)** — the marketing/docs/console site, source of the
   live neuralbridge.io experience.
2. **`src/dashboard/` (Vite + React, separate `package.json`)** — a
   standalone component scaffold: `App.tsx` plus five components
   (`AdapterConfig`, `AuditViewer`, `ComplianceDashboard`, `ConnectionWizard`,
   `CostOptimizer`). No routing, no data fetching wired to a real backend
   found in this tree, no tests. This is the "dashboard foundation" the
   platform README credits as Supported — but "Supported" there means
   "compiles and demonstrates the shape," not "production console." It is
   not the same artifact as `app/console/page.tsx`. Phase 1's `/ai` route
   should live in `app/` (Next.js), reusing this repo's existing frontend
   stack, not in the Vite dashboard.

## MCP / adapter / pricing / security language — repo vs README claims

- Root `README.md` (top, Industrial Autonomous Assurance framing) does not
  make adapter-count claims. It states three explicit rules (line 87–97):
  "If it is not gated in code, it is not on the pricing page," every engine
  must declare what it did *not* check, and assurance tiers are "computed
  from the weakest input, never passed in."
- The **NeuralBridge-platform section of the same README** (line ~171)
  contains the self-correction the product-law skill for this repo already
  flags: *"The GitHub one-liner about '22+ adapters / any agent / any API'
  is stale relative to the README."* That one-liner was **not found** in
  the current `README.md` — it appears to already be corrected in-repo (the
  README instead says "small set of working adapters," "Intended supported
  scope," and lists PostgreSQL / REST / Slack / Notion as the realistic
  near-term candidates, explicitly downgrading "broad adapter ecosystem" to
  "Experimental / evolving"). **[LIVE-SITE: UNVERIFIED]** whether the GitHub
  repo *description* field (not README) still carries the stale one-liner —
  that field isn't in this checkout and needs either live GitHub access or
  the account holder to check Settings.
- Pricing: `docs/pricing.md` and `src/assurance/billing/plans.py` agree on
  three tiers — **Validator** (free), **Register** (€390/mo), **Cell**
  (€1,290/mo) — see `NEURALBRIDGE-AI-COMMERCIAL-MAP.md` for the full
  breakdown and entitlement gating. `GET /v1/plans` is documented as
  generated live from the same `PLANS` table the API enforces, which is the
  correct pattern (no drift between advertised and enforced tiers) —
  confirmed by reading `plans.py`, not by hitting the live endpoint.
- Security language: `app/security/page.tsx` exists but its rendered
  content is **[LIVE-SITE: UNVERIFIED]**. See
  `NEURALBRIDGE-AI-SECURITY-MATRIX.md` for what the code actually proves
  vs. what a security page could plausibly claim, so any live-site pass can
  check the page against that table rather than against vibes.

## Free vs. paid, dashboard vs. assurance split

- Free/paid boundary is defined once, in code, at `src/assurance/billing/plans.py`
  (`Tier = "free" | "register" | "cell"`, `Plan` dataclass, `PLANS` table).
  Verification (spec_validate, envelope calculators, bundle re-checks,
  attestation verification) is explicitly free at every tier "and always
  will be" per the README rationale (the audience for evidence is a
  regulator/insurer/customer's-customer, not a paying API-key holder).
- The **platform half** (`src/neuralbridge/`) has no entitlement/billing
  gating at all in this checkout — `src/neuralbridge/api/routes/connections.py`
  has no auth dependency on any of its six endpoints (list/create/get/patch/
  delete/test), and connections are held in a plain in-process
  `dict[str, dict]` (`_connections`, module scope) rather than a database
  despite the file's own comment `# In-Memory Store (production:
  PostgreSQL)`. This matters directly for Phase 1: the "one real READ
  adapter" work must not assume connection CRUD is already authorized or
  persistent — it currently is neither. See the capability matrix and data
  map for the specific rows.

## Decision inputs for Phase 1 (per the task brief)

- **Proposed `/ai` route name:** `/ai`, as specified — no existing route
  collides with it, and it fits the site's flat top-level route convention
  (`/console`, `/developers`, `/status` are all similarly flat).
- **Which one supported adapter for Phase 1:** **PostgreSQL**
  (`src/neuralbridge/adapters/databases/postgres.py`). It is the adapter the
  platform README itself names first under "Supported-Now Philosophy" ("High
  practical value and clear enterprise relevance"), it declares a documented
  operation set (`query`, `execute_sql`, `list_tables`, `describe_table`,
  `health_check`) rather than being a stub, and `query`/`list_tables`/
  `describe_table`/`health_check` are natural READ operations for the "list
  connections → real read → explain with provenance" slice, while
  `execute_sql` is the natural WRITE path to gate behind approval later.
  Full status detail in the capability matrix.
- **Which existing MCP/REST entry points to reuse:** `RequestRouter.route()`
  (`src/neuralbridge/core/router.py`) is the single existing call path from
  "named adapter + operation + params" to a normalized result plus an audit
  event, and it is already what both `MCPGateway._execute_tool()`
  (`src/neuralbridge/core/gateway.py:235`) and (indirectly, for the
  assurance side) the REST routes are meant to sit on top of. Phase 1's
  agent orchestrator should call through `RequestRouter`, not invent a
  second dispatch path — but see the capability matrix and security matrix
  for two defects in that router that Phase 1 must not inherit silently:
  it does not actually enforce RBAC/rate-limiting despite its own
  docstring claiming it does, and it always audits `actor="system"`
  regardless of who or what issued the call.

## Founder leftovers found

- `DEPLOY_NOW.md` — present at repo root, explicitly founder-facing
  ("For the founder's laptop or CI with real network access... Not for
  Claude Code Remote or any sandboxed agent session"). Still needed; not a
  stray file to delete, but flagged per the brief's "report... founder
  leftovers" instruction.
- No `gh-pages` branch reference found merged into product docs (only a
  historical mention in CI/status/branch-consolidation notes — grep hits
  were `.github/workflows/ci.yml`, `app/status/page.tsx`,
  `BRANCH-CONSOLIDATION.md`, `DEPLOY_NOW.md`; none of these indicate an
  active `gh-pages` deployment target for the product site).
- **Stale `neuralbridge.vercel.app` deployment — confirmed in-repo, not yet
  retired.** `app/status/page.tsx` carries this exact checklist item, still
  `done: false`: *"Stale neuralbridge.vercel.app project retired... In the
  Vercel dashboard, delete the old 'v0 Human-like Neural Interface' project
  or redirect it to https://neuralbridge.io. See DEPLOY_NOW.md §5."* So this
  is a real, currently-live artifact from an earlier v0.dev prototype that
  predates the current product, and it is unrelated to anything in this
  codebase. **[LIVE-SITE: UNVERIFIED]** whether it is still publicly
  reachable today — that check needs a human with browser access, since the
  domain is egress-blocked from this session and this repo's code cannot
  reach another Vercel project's settings to retire it itself.
- The same `app/status/page.tsx` checklist (6 items: API base configured,
  Fly secrets set, Stripe webhook registered, GitHub Pages enabled, this
  stale Vercel project retired, smoke test run) is the single clearest
  piece of evidence that **the product is not deployed yet** — as checked
  into the repo, every ops item reads `done: false` because a static build
  cannot verify live infrastructure. This is consistent with `DEPLOY_NOW.md`
  being an unexecuted runbook, not a description of a live system.
- `ROADMAP.md` (repo root, 39 lines) exists as the canonical Shipped /
  Evolving / Planned checklist and is what `app/roadmap/page.tsx` mirrors;
  it explicitly lists "Dashboard integration with the assurance product"
  under Planned/not-started, confirming `src/dashboard/` and `src/assurance/`
  are not wired together yet.

## What Phase 1 must not do (restated from the brief, grounded in what's actually here)

No agent marketplace, no new adapters beyond making PostgreSQL real,
no "zero trust" marketing (the platform README already correctly declines
that claim — don't reintroduce it), no compliance-certification claims from
the AI layer (the assurance engines already draw this line correctly: they
answer `unchecked` rather than assert compliance — the AI layer must inherit
that discipline, not paper over it), no fake connection counts, no live
billing claims beyond what `plans.py`/Stripe already gate, no PTY/shell
cosplay, no rewrite of neuralbridge.io marketing outside the `/ai` slice.
