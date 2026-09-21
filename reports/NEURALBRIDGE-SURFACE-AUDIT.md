# Nav / SEO / orphan-page audit

Every route under `app/**/page.tsx`, checked against `app/Header.tsx`
(desktop mega-nav + mobile drill-in), `app/layout.tsx` (footer),
`app/sitemap.ts`, `app/robots.ts`, `public/llms.txt`, and
`public/.well-known/agent.json`. State reflects this audit's fixes, not the
pre-audit baseline (see "What was fixed" below for the delta).

## Route matrix

| Route | Header (desktop) | Mobile drill | Footer | Sitemap | Indexed (robots) | Notes |
|---|---|---|---|---|---|---|
| `/` | brand lockup, Start free CTA | — (root of drill) | footer-cta | yes (priority 1) | yes | homepage |
| `/ai` | Platform pane + Resources finder | Resources | Developers col | yes | yes | agent control plane |
| `/applications` | Resources finder | Resources | Developers col | yes | yes | |
| `/checkout/success` | not linked (by design) | not linked (by design) | not linked | yes (priority 0.1) | `noindex` (page-level) | post-Stripe redirect target only, reachable from the checkout flow itself, not meant to be browsed to |
| `/cli` | Resources finder | Resources | Developers col | yes | yes | |
| `/connectors/cursor` | Resources finder (fixed) | Resources (fixed) | Developers col | yes | yes | was footer/sitemap-only before this pass |
| `/connectors/mcp` | Resources finder | Resources | Developers col | yes | yes | |
| `/console` | Platform pane + Resources finder | Resources | Developers col | yes | yes | |
| `/contact` | utility bar "Contact sales", Pricing mega, persistent "Talk to sales" CTA, Resources finder (fixed) | persistent "Talk to sales" CTA, Resources (fixed) | not linked | yes | yes | already reachable via the persistent CTA; now also in the Resources list for discoverability |
| `/developers` | Resources finder | Resources | Developers col | yes | yes | |
| `/docs/[[...slug]]` | Products mega ("Docs"), Resources finder | Resources | Developers/Compliance cols | yes (all static slugs) | yes | |
| `/privacy` | Resources finder (fixed) | root menu + Resources (fixed) | Legal col | yes | yes | was footer/mobile-root-only before this pass; now also in the desktop mega |
| `/roadmap` | Products mega promo, Resources finder | Resources | Developers col | yes | yes | |
| `/security` | Resources finder | Resources | Developers col | yes | yes | |
| `/solutions/[slug]` (5 slugs) | Solutions mega (editorial cards) | Solutions | Solutions col | yes (all 5) | yes | |
| `/status` | Resources finder (fixed) | Resources (fixed) | Legal col ("Deploy status") | yes | `noindex` (page-level) | was footer/sitemap-only before this pass — the founder's honest deploy checklist, intentionally `noindex` but not orphaned |

## What was fixed and why

1. **`/status` had no primary-nav link at all.** It was reachable only from
   the footer's Legal column. Added a "Status" item to the desktop
   Resources mega and the mobile Resources drill in `app/Header.tsx`, so it
   has the same nav-level reachability as every other Resources page. It
   keeps its existing page-level `robots: { index: false }` — the checklist
   is honest, operator-facing content, not something we want ranking in
   search, but it should still be one click from primary nav.

2. **`/connectors/cursor` had no primary-nav link.** The desktop and mobile
   "Connectors" item pointed only at `/connectors/mcp`; Cursor was reachable
   only by clicking through from the MCP page's own cross-link, or from the
   footer. Split the single "Connectors" item into two explicit items —
   "MCP connector" and "Cursor connector" — in both the desktop Resources
   mega and the mobile Resources drill, matching how the footer already
   lists them separately.

3. **`/privacy` was desktop-orphaned relative to mobile.** The mobile drill
   has always had a direct "Privacy" link on its root screen; the desktop
   mega-nav had no equivalent (only the footer). Added a "Privacy" item to
   the desktop Resources finder and to the mobile Resources drill (in
   addition to the existing mobile root link) for full parity.

4. **`/contact` was reachable but not listed in either Resources panel.**
   It was already one click away everywhere (utility-bar "Contact sales",
   the persistent "Talk to sales" CTA in both desktop `topbar-actions` and
   the mobile `mobile-drill-sticky` footer, and the Pricing mega's "Talk to
   sales" finder item), so this was not a reachability gap. Added an
   explicit "Contact" item to both Resources panels anyway, for parity with
   the other fixes above and because "Resources" is the panel a buyer
   scanning the nav is most likely to check first.

5. **`.well-known/agent.json`'s `documentation` array was missing several
   real, shipped surfaces** (`/console`, `/connectors/cursor`, `/roadmap`,
   `/status`) that `public/llms.txt` already listed correctly. Brought the
   two in line so an agent reading only `agent.json` sees the same surface
   area as one reading `llms.txt`.

## Checked and found already correct (no change made)

- **`app/sitemap.ts`** already listed every route in the matrix above,
  including `/checkout/success` and `/status` at appropriately low
  priority (0.1 / 0.3). No routes were missing and none needed to be added.
- **`app/robots.ts`** allows `/` broadly with no `Disallow` rules, which is
  correct here: the two pages that shouldn't be indexed
  (`/checkout/success`, `/status`) already carry page-level
  `robots: { index: false, follow: true }` metadata. Blocking them at the
  `robots.txt` level instead would have *prevented* crawlers from ever
  seeing that per-page directive — the current setup is the right pattern,
  not a gap.
- **Raw GitHub blob links** (`grep -rn "github.com" app --include=*.tsx`):
  four `.../blob/main/docs/{ai-local-setup,buyer-journey}.md` links, in
  `app/ai/page.tsx`, `app/components/AiWorkspace.tsx`,
  `app/checkout/success/SuccessClient.tsx`, and
  `app/connectors/mcp/page.tsx`. Checked `app/lib/docs.ts`: those two files
  are **not** part of the on-site `/docs` tree (`resolveDocSource` only
  serves `docs/index.md`, `getting-started.md`, `pricing.md`,
  `platform.md`, `docs/assurance/*`, and the `deploy/assurance/*` engine
  pages) — no on-site equivalent exists, so linking the raw blob is
  correct, not a violation of the "no blob link when an on-site page
  exists" rule. Same for the one `CONTRIBUTING.md` blob link in the
  Resources panel and footer — `CONTRIBUTING.md` also has no on-site
  route.
- **`/ai`, `/console`** were already correctly linked from both the
  desktop mega-nav (Platform pane, Resources finder) and the mobile drill
  (Resources) — no fix needed, contrary to the task's "known gaps to
  re-verify" list, which appears to describe a state from before an
  earlier pass.
- **No orphan marketing copy**: scanned every literal `href="/..."` string
  in `app/**/*.tsx` (`grep -rhoE 'href="/[^"]*"'`) — every target resolves
  to a real route or a real in-page anchor/hash. No dead links found.
- **Solutions dynamic route** (`/solutions/[slug]`): all 5 slugs
  (`manufacturer`, `plant-operator`, `compliance-officer`,
  `insurer-auditor`, `ai-ops`) are linked from the Solutions mega, the
  mobile Solutions drill, and the footer's Solutions column, and all 5 are
  in the sitemap.

## Build

`npm install && npm run build` — succeeded (Next.js 14.2.15, all 40 static
pages generated, no type errors, no lint failures introduced by this
change). Full route list confirmed in the build output, including the
newly-linked `/status` and `/connectors/cursor`.
