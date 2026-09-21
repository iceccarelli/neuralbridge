# Phase 4 — product surface that sells

Integration report for the multi-agent Phase 4 pass. Base: `main` @ `b732607`
(PR #22 merged, Phase 3 first-euro path). Five parallel streams (branch
hygiene, nav/SEO audit, design-system + visual QA, money UX, integration)
merged into one branch and validated together below.

## What shipped

### 1. Branch hygiene (Agent A)
`reports/NEURALBRIDGE-BRANCH-HYGIENE.md` — verified via
`git merge-base --is-ancestor` that all four stale `claude/*` branches
(`claude/awesome-bardeen-6ondvv`, `claude/neuralbridge-ai-phase1`,
`claude/neuralbridge-ai-phase2`, `claude/beautiful-hypatia-pqritw`) are
pure ancestors of `main` — no unique commits, safe to delete. `gh-pages`
confirmed as an unrelated orphan history (`git merge-base` finds no common
ancestor) — never merge or delete it. The report gives the founder exact
`gh api -X DELETE repos/iceccarelli/neuralbridge/git/refs/heads/<branch>`
commands and GitHub UI steps. The agent's own
`git push origin --delete <branch>` test hit **HTTP 403**, confirming this
environment cannot delete branches — the founder must run the commands
themselves.

**Founder action after merge: delete these four branches.** Keepers are
`main` and `gh-pages` only.

### 2. Nav / SEO / orphan audit (Agent B)
`reports/NEURALBRIDGE-SURFACE-AUDIT.md` — full route matrix for every
`app/**/page.tsx`. Fixes landed in `app/Header.tsx` and
`public/.well-known/agent.json`:
- `/status` and `/connectors/cursor` added to primary nav (previously
  footer-only / MCP-only).
- `/privacy` added to the desktop mega-nav (was mobile-drill-only).
- `/contact` added to the Resources panel listing (was already reachable
  via the persistent "Talk to sales" CTA, now also listed).
- `agent.json`'s `documentation` array brought in line with `llms.txt`
  (added `/console`, `/connectors/cursor`, `/roadmap`, `/status`).

Confirmed already correct, no change needed: `sitemap.ts` (every route
present, `/checkout/success` and `/status` at low priority),
`robots.ts` (page-level `robots: { index: false }` on
`/checkout/success`/`/status` is the correct pattern, not a
robots.txt-level block), all `github.com` blob links in `app/`
(none have an on-site equivalent), `/ai` and `/console` nav reachability.

### 3. Design-system pass + visual QA (Agents C + E)
Applied `app/DESIGN.md` tokens consistently across `/console`, `/ai`,
homepage pricing, `/checkout/success`, connectors, and `/status`:
- `/ai` and `/console` now share one `.key-row`/`.key-row-note` pattern for
  the API-key field (previously `/ai` buried an unlabeled inline-styled
  input in a list of context rows).
- Fixed two invisible controls in `AiWorkspace.tsx` ("Deny" button, "Talk
  to sales" link) — bare `.btn` has no background/border, both now
  `.btn-secondary`.
- Replaced undefined-token color fallbacks (`var(--danger, #b23b1f)`,
  `var(--brand, #d97b2e)`) with a real `--danger` token and the existing
  `--orange` token — no off-palette hues.
- Fixed a one-primary-CTA-per-view violation in `PricingPlans.tsx`: when
  both Register and Cell are purchasable, both rendered `btn-primary` —
  Cell's checkout button is now always secondary, Register stays the sole
  primary.
- Mobile overflow fix on `.ai-context-row` (flex-wrap + max-width) for
  375–430px widths.

Screenshots for all 11 surfaces × desktop (1440×900) + mobile (Pixel 7,
412×915) are in `reports/demo/phase4/` (22 files) — see below.

### 4. Money UX — first paid action in the browser (Agent D)
The highest-ROI stream. Console now has a guided **First Register case**
flow (`app/components/FirstCase.tsx`, mounted at `/console#first-case`)
that calls the real `POST /v1/cases/{case_id}/signal` route — the same
route `docs/buyer-journey.md` and `tests/test_ai_buyer_journey.py` already
exercise — directly from the browser:
- No key / free key → the API's real 401/402/503 refusal, rendered
  honestly with an upgrade-to-pricing CTA. Never a faked success.
- Register/Cell key → real `content_hash`/`ledger_seq` from the
  hash-chained ledger, shown as the receipt.

`app/lib/apiKey.ts` unifies the API-key session between Console and /ai
(one shared `sessionStorage` key, tab-scoped, documented as not a
substitute for real auth). `/checkout/success` now deep-links into
`/console#first-case` and pre-fills the shared key on a completed
checkout. `/ai`'s gated Context-panel hint links to Console, pricing, and
`/connectors/mcp`. After a successful first case, Console links onward to
`/ai`.

**Real bug found and fixed along the way:** `CORSMiddleware` in
`src/assurance/api/service.py` was missing `x-api-key` from
`allow_headers` — invisible to curl/pytest (only a browser enforces CORS
preflight), but it would silently drop the key on every real cross-origin
deployment, turning a should-succeed paid write into an anonymous 401/402.

### 5. Integration
All four streams' branches merged cleanly except one conflict in
`app/components/Console.tsx` (both the design pass and the money-UX pass
touched the key-field note) — resolved by keeping the unified
`.key-row-note` class with the more informative "shared with /ai" copy.

## Verification (this integration pass, not just per-agent)

- `npm run build` — clean, all 40 routes, no type/lint errors.
- `ruff check src/` — all checks passed.
- `pytest tests/ -q` — **747 passed, 45 skipped, 5 pre-existing failures**
  (`tests/test_assurance_mcp.py`, `ModuleNotFoundError: No module named
  'mcp'` — an optional dependency not installed in this environment,
  unrelated to this diff and unchanged from `main`).
- Playwright, run against a real local stack (SQLite-backed
  `assurance.api.service` on :8001, Next dev server on :3000, a real
  Cell-tier key minted via `AccountStore`):
  - `tests-e2e/console-first-case.spec.ts` — 4/4 passed (both the
    no-key-refused and paid-key-succeeds paths, desktop + mobile).
  - `tests-e2e/phase3-first-euro.spec.ts` — 4/4 passed, 2 skipped (the
    Postgres-backed `/ai` auto-retry spec — honestly skipped, no local
    Postgres in this pass, same limitation the agent reported).
  - `tests-e2e/phase4-visual-qa.spec.ts` — 22/22 passed, screenshots
    regenerated and confirmed matching the committed set.

One environment note found while re-running: the assurance API's CORS
allowlist defaults to `http://localhost:3000`, not `http://127.0.0.1:3000`
— browsers treat these as different origins. Running Playwright against
`127.0.0.1` produces a real (browser-only) CORS failure; against
`localhost` it passes. This is expected behavior given
`ASSURANCE_ALLOWED_ORIGINS`'s documented default, not a bug — noted here
so a future test run doesn't mistake it for a regression.

## Screenshots

`reports/demo/phase4/` — desktop + mobile pairs for: `ai`, `console`,
`homepage-pricing`, `checkout-success`, `connectors-mcp`,
`connectors-cursor`, `status`, `contact`, `developers`, `cli`,
`applications`.

## Remaining founder-only leftovers

- Run `DEPLOY_NOW.md` — not touched by this phase, founder-only.
- Delete the four stale `claude/*` branches per
  `reports/NEURALBRIDGE-BRANCH-HYGIENE.md` (this session hit 403 trying;
  the founder has push-delete rights this environment does not).
- Retire `neuralbridge.vercel.app` per prior phases' notes (not re-audited
  here — out of scope for this UI/UX pass).
- GitHub Pages (`gh-pages`) deploy — untouched, never merged into `main`.

## Explicitly out of scope (per task)

`DEPLOY_NOW.md`/Fly/live Stripe secrets, LLM wiring / agent marketplace /
new adapters, CRA/Machinery "certified" claims, rewriting assurance
engines, merging or deleting `gh-pages`, asking for tokens.
