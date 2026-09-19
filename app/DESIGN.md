# Design system

For humans and agents editing `app/`. The tokens below live in
`app/globals.css` (`:root`) — this file explains what they're for, not what
they are; read the CSS for exact values.

## Color

One dark neutral scale (`--navy-900` → `--navy-700`) for chrome — header,
footer, hero — and one light neutral scale (`--surface`, `--surface-alt`,
`--border`, `--ink`, `--ink-soft`) for content. One electric accent
(`--orange`) for the single primary action per view. `--link` and
`--success` exist because they carry real meaning (a hyperlink, a
"Supported" status) — they are not decoration. No other hue is
introduced without a reason tied to meaning, not mood.

## Radius

Three sizes only: `--radius-sm` (buttons, small controls), `--radius-md`
(tiles, solution cards), `--radius-lg` (pricing cards — the highest-stakes
surface on the page gets the most generous curve). Don't invent a fourth.

## Elevation

Three shadow levels: `--shadow-sm` / `--shadow-md` / `--shadow-lg`. Rest
state carries **no shadow** — the 1px border is the boundary. A shadow only
ever appears on interaction (hover, focus-within), and only ever deepens
toward a higher level than the surface already had. Don't add a shadow to
something that isn't being interacted with; that's decoration, not signal.

## Motion

One easing curve (`--ease`, a slight overshoot-free ease-out) and two
durations: `--duration-fast` (150ms — hover, press, anything giving
feedback on an action) and `--duration-panel` (220ms — a mega-nav or
drill-in panel opening, which moves more pixels and needs a beat longer to
not feel like a glitch). Every transition using these must be wrapped by
the existing `prefers-reduced-motion: reduce` block near the bottom of
`globals.css` if it moves anything via `transform` — background-color and
border-color transitions are fine to keep, since they carry no vestibular
risk.

## Focus

One ring: `--focus-ring` + `--focus-ring-offset`, applied globally to
`a:focus-visible` and `button:focus-visible`. `.btn` overrides it with the
same values because its own rule needs to win the cascade against the
per-variant background rules — not because it's a different ring.

## Numbers

Prices use `font-variant-numeric: tabular-nums` (`.price-amount`) so digits
don't shift width as a user compares tiers — a detail that matters more on
a pricing page than almost anywhere else on the site.

## What this system does *not* yet cover

The tokens above are wired into the components most people interact with
first — buttons, tiles, solution cards, pricing cards, and the global focus
ring. Older, lower-traffic parts of `globals.css` (mega-nav internals,
search overlay, cookie consent, feedback widget) still carry hand-rolled
`border-radius`/`box-shadow` values from earlier stages. Migrating those to
the tokens is real, low-risk follow-up work — do it opportunistically
whenever you're already touching one of those selectors, rather than as a
separate sweep that touches nothing else.

## Imagery

Every photoreal illustration on the site exists as **two independently
generated frames of the same scene** — never a fake photo standing in for a
real one, never two crops of one file. They come from two source packs
(`assets/illustrations/neuralbridge-illustration-*.zip`, kept for
provenance, not read at runtime):

- **Variant A** (`public/images/variants/a/…`) — the richer pack; also the
  only one with 4:5 mobile portrait crops of the two landing heroes.
- **Variant B** (`public/images/variants/b/…`) — a second frame of the same
  scene. One file the B pack shipped, `solution-aiops-mcp-gateway.jpg`,
  was 0 bytes — that slot ships as A-only (no rotation) rather than as a
  broken image.

Both trees are committed in full (not just the files currently wired) so a
future page can start rotating a slot without re-extracting anything.

**`app/lib/images.ts`** is the single source of truth: one `IMAGES` map,
keyed by slot name, each entry `{ a, b?, portraitA? }` with its own `src`
and `alt` per frame — because A and B are genuinely different compositions,
each needs its own accurate alt text, not one alt text reused for two
different images.

**`app/components/RotatingImage.tsx`** renders a slot:

- No `b` (a portrait, or the mcp-gateway exception) → a single static
  `next/image`, no rotation logic at all.
- Both exist → crossfades between them (opacity, `var(--duration-panel)`,
  well under the 400ms ceiling) every 8–12s (`intervalMs`, default 10s).
  Pass `offsetMs` in a card grid so a row of cards staggers instead of
  flashing in sync.
- Respects `prefers-reduced-motion: reduce` — shows A and never schedules a
  flip at all, not just a CSS override.
- Pauses while the tab is hidden (`document.visibilityState`).
- Only the currently-visible frame carries real `alt` text and stays out of
  `aria-hidden`; the crossfading-out frame gets `alt=""` and
  `aria-hidden="true"` so a screen reader never announces two competing
  captions for one picture.
- `dots` (small indicator dots, bottom-left) — hero images only. Never on
  a card grid; a dozen synchronized-looking dots is noise, not polish.
- `priority` — only the single LCP-critical hero image on a page. Every
  other instance lazy-loads.

**Mobile heroes**: `.hero-media-desktop` / `.hero-media-mobile` are shown
and hidden by the same 900px breakpoint the mega-nav already uses. Below
900px, a hero renders its `portraitA` (4:5) as a single image — never a
squashed 16:9 crop, and never rotating (there is no portrait B).

**Where art does *not* go**: the three `dashboard-*` slots belong to
`src/dashboard`'s own UI (a separate app), not the marketing site — and are
never used to depict a unified "live console" on the homepage. The
homepage's own ai-ops proof tile uses `solution-aiops-dashboard-unwired`,
which depicts the dashboard's disconnected, honest empty state on purpose.

**OG image**: unaffected. `app/opengraph-image.tsx` (code-generated from
these same design tokens) stays the canonical `og:image`/`twitter:image` —
the packs' own `og.jpg`/`readme-og-hero.jpg` are stored for completeness
but not wired into any live metadata.

## Doctrine

- One primary CTA per viewport. If a section has two orange buttons, one of
  them is wrong.
- A hover effect earns its place only if it confirms something is
  interactive or reveals genuinely secondary information (the tile-link
  label reveal). It never exists purely for polish.
- Mobile is not a shrunk desktop: the mega-nav becomes a full-screen
  drill-in, not a squeezed dropdown, at 900px.
