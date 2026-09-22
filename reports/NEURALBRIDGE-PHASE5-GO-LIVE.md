# Phase 5 — go-live rehearsal + Cell first value

Integration report for the multi-agent Phase 5 pass. Base: `main` @
`4632f9f` (PR #23 merged, Phase 4 product surface). Five parallel streams
(branch hygiene, go-live rehearsal, Cell first-value UI, surface polish,
dependency honesty) merged into one branch and validated together below.

Cash still requires the founder to run `DEPLOY_NOW.md`'s Fly/Stripe steps
from their own machine. Nothing in this phase touches Fly, writes a live
secret, or claims checkout is live on neuralbridge.io.

## What shipped

### 1. Branch hygiene (Agent A)
`reports/NEURALBRIDGE-BRANCH-HYGIENE.md` re-verified: `git ls-remote
--heads origin` shows only two remote heads, `main` and `gh-pages`. Every
branch this phase's brief named as a hygiene candidate — including
`claude/wonderful-edison-grv6yd`, the Phase 4 PR #23 head — is already gone
from the remote (the founder ran Phase 4's delete commands between phases).
No new delete commands to issue this round; the report keeps the template
for the next audit.

**Founder action: none.** Nothing stale remains.

### 2. Go-live rehearsal pack (Agent B)
New `docs/GO-LIVE.md` and `scripts/go-live-preflight.sh`. Split into a
no-secrets preflight half and a founder-only post-secrets half, extending
`DEPLOY_NOW.md`/`SMOKE.md` rather than duplicating them.

Actually run against a real local stack in this session (Postgres 16, real
`assurance.api.service:app` and `neuralbridge.main:app`, no mocking):
- `scripts/verify-buyer-path.sh` — passed, exit 0 (plans lists 3 tiers,
  checkout 503s honestly with no Stripe price configured, a Cell key opens
  a real register case and a real `/ai` execution receipt).
- `pytest tests/test_ai_buyer_journey.py -v --no-cov` — 2 passed against
  real Postgres.
- `scripts/go-live-preflight.sh` — passed clean, and fails loudly (exit 1)
  when the stack isn't up.
- `docker compose -f docker-compose.ai.yml -f docker-compose.demo.yml
  config` — validates cleanly (no Docker daemon in this sandbox, so never
  ran a live `up`).

Playwright was **not** run in this session — this sandbox is shared with
sibling agent sessions already bound to ports 3000/8001, and driving a
browser against another session's dev server would have produced
contaminated results, not a clean read of this branch. `docs/GO-LIVE.md`
states this and gives the exact founder-side command.

Failure-modes table built from the actual code (not invented): Stripe
price IDs unset → `plans.py`'s `purchasable = bool(price_id)`;
`ASSURANCE_API_KEYS`/`ASSURANCE_ALLOW_UNAUTHENTICATED` unset →
`auth_mode()` returns `"unconfigured"`, a 503 rather than a guessed 401;
`ASSURANCE_ALLOWED_ORIGINS` missing the caller's origin → CORS preflight
silently drops `X-API-Key`, paid write looks unauthenticated (including
the `localhost` vs `127.0.0.1` trap from Phase 4); `ASSURANCE_PUBLIC_URL`/
`ASSURANCE_MARKETING_URL` wrong → checkout redirects to a dead page;
webhook unregistered or `STRIPE_WEBHOOK_SECRET` mismatched → `/checkout/
success` polls `202 pending` forever.

**Founder action: none until secrets are set — then follow
`docs/GO-LIVE.md`'s post-secrets checklist in order.**

### 3. Cell first-value UI (Agent C) ★
New `app/components/FirstCell.tsx`, mounted in `Console.tsx` right after
`FirstCase`, at anchor `#cell-verify`. Mirrors `FirstCase.tsx`'s honesty
rules exactly: real refusals, never a faked success.

- Request body (`app/lib/cellVerifyFixture.ts`) is captured by actually
  running `tests/test_assurance_machine.py`'s own `envelope()`/`trace()`
  fixture builders through the real `SafetyEnvelope`/`Trace` classes — not
  hand-typed JSON.
- Gating verified by reading `POST /v1/machine/verify`'s real dependency
  chain (`Machine` → `require_machine`, `src/assurance/api/deps.py`): no
  free preview tier on this route, unlike Register's. No key → real `401`;
  free or Register-tier key → real `402` with
  `detail.error == "plan_does_not_include_machine_verification"`, the
  API's own `tier`/`remedy` text, not invented copy; Cell key → the real
  verdict, tier, `may_claim_physical_behaviour`, and sealed/`content_hash`
  from the actual engine.
- `FirstCase.tsx`'s success state gained one line linking to
  `#cell-verify` — no other restructuring.
- `tests-e2e/console-first-cell.spec.ts` (Playwright) run against a real
  local API + Next dev server (own ports, to avoid the shared sandbox's
  other sessions): all 4 cases (401/402-refusal × desktop/mobile, Cell-key
  success × desktop/mobile) passed. Screenshots in
  `reports/demo/phase5/cell-verify-*.png`.

Never claims "certified"; `may_claim_physical_behaviour` is shown exactly
as the verifier reports it.

### 4. Surface polish (Agent D)
Checked Phase 4's surface report for outstanding leftovers — none flagged;
Phase 4 already closed its known gaps. One net-new fix:
`app/checkout/success/SuccessClient.tsx` gained a third, conditional
next-step card (`key.tier === 'cell'`) linking to `/console#cell-verify`
for Cell buyers, alongside the existing First-Register-case and `/ai`
cards. Confirmed no dead links, no CSS/mobile-parity regressions at
1440px/412px (`npm run build` clean, Playwright viewport check clean).
Screenshots in `reports/demo/phase5/console-*.png` and
`checkout-success-*.png`. Deliberately made zero edits to `Console.tsx`/
`FirstCase.tsx` to avoid colliding with Agent C's parallel work on the
same files.

### 5. Dependency honesty (Agent E + integration fix)
`pyproject.toml` gained three extras groups for adapters that hard-import
a vendor SDK but weren't listed as optional: `bigquery`
(`google-cloud-bigquery`), `mongodb` (`motor`), `mysql` (`aiomysql`,
`pymysql`). `mcp` was already correctly extras'd. No adapter is imported
eagerly by `main.py`/`service.py`/the routers, so a missing SDK cannot
cascade into app startup.

**Integration-time fix, found while validating the merged tree:**
`tests/test_assurance_mcp.py` and `tests/test_neuralbridge_mcp.py` import
`assurance.mcp.server`/`neuralbridge.mcp.server` at module load, which
themselves import the `mcp` SDK directly — a pre-existing gap from PR #18,
not introduced by this phase. CI's own test job
(`.github/workflows/ci.yml`) never installs the `mcp` extra, so both
modules hard-failed with `ModuleNotFoundError` rather than skipping. Added
a module-level `pytest.importorskip("mcp", reason=...)` to each, naming
the extra to install and the entitlement test elsewhere
(`test_assurance_machine.py::TestVerifyEndpoint`,
`test_ai.py`) that already covers the same tier-gating logic without the
SDK — so this is a real, visible skip, never a silent one, and it does not
touch any entitlement test itself.

## Validation on the merged tree

```
$ npm run build          # ✓ compiled, 40/40 routes, no type errors
$ python3 -m pytest tests/ -q --no-cov -rs
787 passed, 2 skipped, 5 warnings in 21.79s
SKIPPED tests/test_assurance_mcp.py — mcp SDK not installed (extra: assurance-mcp)
SKIPPED tests/test_neuralbridge_mcp.py — mcp SDK not installed (extra: neuralbridge-ai-mcp)
$ ruff check src/ tests/
All checks passed!
```

No entitlement/tier-gating test was skipped. The two skips are both for
modules whose entire purpose is wrapping the `mcp` SDK.

## Out of scope, correctly untouched

Fly/Stripe execution, live secrets, LLM/certification claims, supplier
self-serve pricing, `gh-pages` history, a marketplace or adapter-count
redesign.

## Done-when, checked

- [x] Branch hygiene report lists only keepers (`main`, `gh-pages`) —
      nothing stale to delete this round.
- [x] Go-live preflight runs without secrets and fails loudly when the
      stack isn't up (verified live).
- [x] Cell first-value works in Console with First-Register-case-level
      honesty — real 401/402/200, tests + screenshots.
- [x] Desktop + mobile Playwright green on the new Cell flow.
- [x] Build clean, `pytest`/`ruff` clean, CI's actual dependency set
      (no optional SDKs) confirmed non-fatal.
