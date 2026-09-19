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

## Doctrine

- One primary CTA per viewport. If a section has two orange buttons, one of
  them is wrong.
- A hover effect earns its place only if it confirms something is
  interactive or reveals genuinely secondary information (the tile-link
  label reveal). It never exists purely for polish.
- Mobile is not a shrunk desktop: the mega-nav becomes a full-screen
  drill-in, not a squeezed dropdown, at 900px.
