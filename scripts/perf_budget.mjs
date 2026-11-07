#!/usr/bin/env node
/*
 * perf_budget.mjs - fail the build when a route's initial JavaScript or CSS grows past its budget.
 *
 * Usage (after `npm run build`):   node scripts/perf_budget.mjs [--dist .next] [--json]
 *
 * It reads each route's prerendered HTML in the build output, takes every /_next/static script and
 * stylesheet it references, and sums the real file sizes (raw and gzip). No server and no browser are
 * needed, so it runs in the Site CI job. These are TRANSFER-SIZE budgets, not Core Web Vitals: LCP, INP
 * and CLS need a browser and, for a pass claim, field data (Search Console / RUM), which this repo does
 * not have. Lab numbers for those are measured with scripts/seo_audit.mjs.
 *
 * Budgets are the measured size on 2026-11-03 (Next 16.4.4) plus ~8% headroom for ordinary churn.
 * Raising one needs a reason in the commit message; the point is that growth is a decision.
 *
 * Re-baseline, 2026-11-07 (CSS only; no JS budget changed, none was exceeded): after deleting 3.5 KB
 * of rules for classes nothing references (the retired /status checklist, the removed feedback widget
 * and language stub, unused calculator/mega-menu classes) the shared stylesheet measures 51.8 KB
 * (product page 55.0 KB). The remaining growth is deliberate new interface: the document-layer styles
 * for /start, /trust and /services and the workspace identity bar and panels. New budgets are that
 * measured size plus ~8%: 56 KB, and 59 KB for the product page.
 */
import { existsSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

const args = process.argv.slice(2);
const dist = args.includes('--dist') ? args[args.indexOf('--dist') + 1] : (process.env.NEXT_DIST_DIR || '.next');

// route -> { html: built HTML file, jsGzipKB, cssKB } (scripts/perf_budget.json; no defaults, so a missing file fails)
const BUDGETS = JSON.parse(readFileSync(new URL('./perf_budget.json', import.meta.url), 'utf8'));

const kb = (n) => Math.round((n / 1024) * 10) / 10;
const rows = [];
let failed = false;
for (const [route, b] of Object.entries(BUDGETS)) {
  const file = join(dist, 'server', 'app', b.html);
  if (!existsSync(file)) { rows.push({ route, error: `missing ${file} (run npm run build)` }); failed = true; continue; }
  const html = readFileSync(file, 'utf8');
  const refs = [...new Set([...html.matchAll(/\/_next\/static\/[^"'\\?\s]+\.(?:js|css)/g)].map((m) => m[0]))];
  let jsRaw = 0, jsGz = 0, css = 0;
  for (const r of refs) {
    const p = join(dist, r.replace('/_next/', ''));
    if (!existsSync(p)) { rows.push({ route, error: `referenced file missing from the build: ${r}` }); failed = true; continue; }
    const buf = readFileSync(p);
    if (r.endsWith('.js')) { jsRaw += buf.length; jsGz += gzipSync(buf).length; } else css += buf.length;
  }
  const over = [];
  if (kb(jsGz) > b.jsGzipKB) over.push(`JS gzip ${kb(jsGz)} KB > ${b.jsGzipKB} KB`);
  if (kb(css) > b.cssKB) over.push(`CSS ${kb(css)} KB > ${b.cssKB} KB`);
  if (over.length) failed = true;
  rows.push({ route, jsRawKB: kb(jsRaw), jsGzipKB: kb(jsGz), cssKB: kb(css), budget: `${b.jsGzipKB} / ${b.cssKB}`, over });
}
if (args.includes('--json')) console.log(JSON.stringify(rows, null, 2));
else {
  console.log('| route | JS raw KB | JS gzip KB | CSS KB | budget (gzip JS / CSS) | status |\n|---|---|---|---|---|---|');
  for (const r of rows) console.log(r.error ? `| ${r.route} | ${r.error} |||||` : `| ${r.route} | ${r.jsRawKB} | ${r.jsGzipKB} | ${r.cssKB} | ${r.budget} | ${r.over.length ? 'OVER: ' + r.over.join('; ') : 'ok'} |`);
}
process.exit(failed ? 1 : 0);
