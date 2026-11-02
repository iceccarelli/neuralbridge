#!/usr/bin/env node
/*
 * seo_audit.mjs - measure a RUNNING NeuralBridge site: HTTP status, console errors, transfer
 * bytes, LCP, CLS and axe-core accessibility violations, per route at desktop (1280px) and
 * mobile (390px) widths.
 *
 * Usage (not part of the app; adds nothing to package.json):
 *   npm run build && npx next start -p 3123 &
 *   node scripts/seo_audit.mjs --base http://127.0.0.1:3123 --label after --out after.json
 *
 * Requirements: `playwright` (with a Chromium already installed) and `axe-core` must be
 * resolvable from the environment. Resolution order: the current directory's node_modules,
 * $SEO_AUDIT_MODULES (a node_modules directory), then `npm root -g`. Install them in a scratch
 * directory, e.g. `mkdir /var/tmp/seo-measure && cd /var/tmp/seo-measure && npm i axe-core playwright`,
 * and run from there or set SEO_AUDIT_MODULES. This script never installs anything.
 *
 * Flags: --base URL (default http://127.0.0.1:3000)  --label NAME  --out FILE.json
 *        --routes /a,/b,...  (default: the 12 representative routes)
 * Numbers are one cold load per route on the machine that runs it: use them to compare two runs
 * on the same machine, not as absolute field data.
 */
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

function resolver() {
  const bases = [join(process.cwd(), 'x.js')];
  if (process.env.SEO_AUDIT_MODULES) bases.push(join(process.env.SEO_AUDIT_MODULES, '..', 'x.js'));
  try { bases.push(join(execSync('npm root -g', { encoding: 'utf8' }).trim(), '..', 'x.js')); } catch { /* no npm */ }
  return (name) => {
    for (const b of bases) {
      try { return createRequire(b).resolve(name); } catch { /* try next */ }
    }
    throw new Error(`cannot resolve ${name}; install it in a scratch directory (see header comment)`);
  };
}
const resolve = resolver();
const { chromium } = createRequire(import.meta.url)(resolve('playwright'));
const AXE = resolve('axe-core/axe.min.js');

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => {
  if (a.startsWith('--')) acc.push([a.slice(2), all[i + 1]]);
  return acc;
}, []));
const BASE = (args.base || 'http://127.0.0.1:3000').replace(/\/$/, '');
const ROUTES = (args.routes ? args.routes.split(',') : [
  '/', '/docs', '/docs/capabilities', '/developers', '/cli', '/verify', '/applications',
  '/connectors/mcp', '/solutions/manufacturer', '/security', '/contact', '/privacy',
]);
const VIEWPORTS = [{ name: 'desktop', width: 1280, height: 800 }, { name: 'mobile', width: 390, height: 844 }];

async function measure(browser, route, vp) {
  const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200)); });
  page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${String(e).slice(0, 200)}`));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('Network.enable');
  let bytes = 0;
  cdp.on('Network.loadingFinished', (e) => { bytes += e.encodedDataLength || 0; });
  await page.addInitScript(() => {
    window.__m = { cls: 0, lcp: 0 };
    new PerformanceObserver((l) => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__m.cls += e.value; })
      .observe({ type: 'layout-shift', buffered: true });
    new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__m.lcp = e.startTime; })
      .observe({ type: 'largest-contentful-paint', buffered: true });
  });
  const resp = await page.goto(BASE + route, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  const status = resp ? resp.status() : 0;
  const m = await page.evaluate(() => window.__m);
  await page.addScriptTag({ path: AXE });
  const axe = await page.evaluate(async () => {
    const r = await window.axe.run(document, { resultTypes: ['violations'] });
    return r.violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length }));
  });
  await ctx.close();
  return {
    route, viewport: vp.name, status, consoleErrors, bytes,
    lcp: Math.round(m.lcp), cls: Math.round(m.cls * 10000) / 10000, axe,
  };
}

const browser = await chromium.launch();
const rows = [];
for (const route of ROUTES) for (const vp of VIEWPORTS) rows.push(await measure(browser, route, vp));
await browser.close();

if (args.out) writeFileSync(args.out, JSON.stringify({ label: args.label || '', base: BASE, rows }, null, 2));
console.log(`| route | vp | status | KB | LCP ms | CLS | console errors | axe (id:impact x nodes) |`);
console.log(`|---|---|---|---|---|---|---|---|`);
for (const r of rows) {
  const a = r.axe.map((v) => `${v.id}:${v.impact}x${v.nodes}`).join(', ') || '-';
  console.log(`| ${r.route} | ${r.viewport} | ${r.status} | ${(r.bytes / 1024).toFixed(0)} | ${r.lcp} | ${r.cls} | ${r.consoleErrors.length} | ${a} |`);
}
const sev = rows.flatMap((r) => r.axe).filter((v) => v.impact === 'serious' || v.impact === 'critical');
console.log(`\nserious/critical axe findings: ${sev.length}; console errors: ${rows.reduce((n, r) => n + r.consoleErrors.length, 0)}`);
