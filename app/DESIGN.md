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

Three sizes only: `--radius-sm` (buttons, tags, small controls), `--radius-md`
(tiles, cards, tables), `--radius-lg` (pricing cards — the highest-stakes
surface on the page gets the most generous curve). Don't invent a fourth.
`--radius-pill` is the one non-box shape, for status pills only.

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

## Identity: company and product

NeuralBridge is the company and platform; Industrial Autonomous Assurance is
its flagship product. The header lockup is the mark `NB`, the word
`NeuralBridge` and, beneath it, the product name (`.brand-text`,
`.brand-name`, `.brand-product`). `BRAND`, `PRODUCT` and `BRAND_SHORT` in
`app/lib/seo.ts` are the only place the names are spelled for metadata: page
titles end `| NeuralBridge`, `og:site_name` is NeuralBridge, the Organization
node is NeuralBridge and the WebSite node carries the product as
`alternateName`. Never use the product name as if it were the company, or the
reverse.

The look is an engineering document, not a SaaS dashboard: navy chrome, white
reading surfaces, hairline rules for structure, a mono face for labels and
numbering, and orange only for the one primary action. No gradients as
decoration beyond the existing hero, no glassy cards, no invented screenshots
or metrics. A diagram is drawn in HTML (`.flow`) so it stays legible at 390px
and reads as a list to a screen reader.

## Type scale and space

Eight steps, `--fs-xs` (0.75rem) to `--fs-2xl` (1.75rem), plus `--mono`. Every
`font-size` in `globals.css` is one of them, or a `clamp()` for a page title;
the caret glyph and the brand subline are the only literal exceptions. Space
is `--space-1` to `--space-6`; section rhythm and gaps in new rules use it.
Text on the navy scale is `--on-dark` / `--on-dark-soft` / `--code-ink`, never a
fresh hex.

## The document layer

New pages are built from a small set of parts at the end of `globals.css`,
not from more card grids:

- `.page-hero` — a short navy header with `h1`, one paragraph and a `.toc`.
- `.ruled` — heading column plus body column between hairlines; the default
  way to list problems, deliverables, limits.
- `.cmp` in `.cmp-wrap` — a comparison table (scrolls inside a focusable
  region below 640px).
- `.paths` — role doors; `.journey` — numbered steps with the state of each.
- `.tag` with `is-live` (green), `is-offline` (blue), `is-gap` (orange, by
  request or needs an API) and `is-none` (dashed, not available). A tag says
  where something runs or that it does not exist; it is never decoration.
- `.note-box` — a limits or read-this-first block. `.flow` — numbered diagram.
- `Inline` (`app/components/Inline.tsx`) turns `` `code` `` spans in data strings into `<code>`.

Copy that states availability lives in import-free data modules
(`app/lib/journey.ts` is the exception because it reads `HOSTED_API`;
`app/lib/services.ts`, `productPages.ts`) so tests can read it.

## What this system does *not* yet cover

Normalised so far: radii (all box radii are tokens), the font-size scale,
dark-surface text colours. Not yet: the mega-nav, search overlay and cookie
banner still carry hand-written `box-shadow` values (six distinct), and about
twenty literal hex values remain for hover and tint states on dark and pale
surfaces. Move them to tokens when you touch those selectors.

## Imagery

Every photoreal illustration on the site exists as **two independently
generated frames of the same scene** — never a fake photo standing in for a
real one, never two crops of one file. They came from two source packs,
already extracted into `public/images/variants/{a,b}`; the zip archives
were not kept in the repo:

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

**The home page hero carries no photographic image**: it is the statement,
the actions and the `.flow` diagram, so the largest paint is text. The two
landing-hero slots remain in `images.ts` for the offline-kit band lower on the
page. A page that renders no `priority` image is correct.

**Mobile heroes** (where a hero does use a slot): `.hero-media-desktop` / `.hero-media-mobile` are shown
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
