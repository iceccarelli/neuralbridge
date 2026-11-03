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
 *        --card  instead of measuring, check the "business card" of every page in /sitemap.xml (or of
 *                --routes) on the running site: Open Graph + Twitter + canonical + icon/manifest tags,
 *                JSON-LD that parses, and every image URL they name fetched from this server and its
 *                PNG dimensions read (og/twitter 1200x630 under 300 KB, logo 512x512, apple-icon 180x180).
 *                Needs no browser or package; exit 1 on any problem. Public URLs (https://neuralbridge.io/...)
 *                are fetched from --base. Its build-output twin is tests/test_site_seo.py.
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
const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => {
  if (a.startsWith('--')) acc.push([a.slice(2), all[i + 1]]);
  return acc;
}, []));
const BASE = (args.base || 'http://127.0.0.1:3000').replace(/\/$/, '');
const ROUTES = (args.routes ? args.routes.split(',') : [
  '/', '/docs', '/docs/capabilities', '/developers', '/cli', '/verify', '/applications',
  '/connectors/mcp', '/solutions/manufacturer', '/security', '/contact', '/privacy',
]);
const SITE = 'https://neuralbridge.io';

// --- business-card audit (no browser) ---------------------------------------------------------------
function attrs(s) {
  return Object.fromEntries([...s.matchAll(/([\w:-]+)="([^"]*)"/g)].map((x) => [x[1], x[2]]));
}

function tags(html) {
  const meta = {}, links = {}, ld = [];
  for (const m of html.matchAll(/<meta\s+([^>]*?)\/?>/g)) {
    const a = attrs(m[1]);
    const key = a.name || a.property;
    if (key && 'content' in a) (meta[key] ||= []).push(a.content);
  }
  for (const m of html.matchAll(/<link\s+([^>]*?)\/?>/g)) {
    const a = attrs(m[1]);
    if (a.rel && a.href) (links[a.rel] ||= []).push(a.href);
  }
  for (const m of html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) ld.push(m[1]);
  return { meta, links, ld };
}

function pngSize(buf) {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (buf.length < 24 || sig.some((b, i) => buf[i] !== b) || buf.toString('latin1', 12, 16) !== 'IHDR') return null;
  return [buf.readUInt32BE(16), buf.readUInt32BE(20)];
}

async function checkImage(url, want, label, maxBytes, problems) {
  const local = url.startsWith(SITE) ? BASE + url.slice(SITE.length) : url;
  let res;
  try { res = await fetch(local); } catch (e) { problems.push(`${label}: ${url} unreachable (${e.message})`); return; }
  if (!res.ok) { problems.push(`${label}: ${url} -> HTTP ${res.status}`); return; }
  if (!(res.headers.get('content-type') || '').startsWith('image/png')) problems.push(`${label}: ${url} content-type ${res.headers.get('content-type')}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const size = pngSize(buf);
  if (!size || size[0] !== want[0] || size[1] !== want[1]) problems.push(`${label}: ${url} is ${size ? size.join('x') : 'not a PNG'}, want ${want.join('x')}`);
  if (maxBytes && buf.length > maxBytes) problems.push(`${label}: ${url} is ${buf.length} bytes (max ${maxBytes})`);
}

const CARD_WANT = {
  'og:type': 'website', 'og:site_name': 'Industrial Autonomous Assurance', 'og:locale': 'en_GB',
  'og:image:type': 'image/png', 'og:image:width': '1200', 'og:image:height': '630',
  'twitter:card': 'summary_large_image', 'theme-color': '#0f1b2d',
};
const CARD_PRESENT = ['og:title', 'og:description', 'og:url', 'og:image', 'og:image:alt', 'twitter:title', 'twitter:description', 'twitter:image'];

async function cardAudit(routes) {
  let failures = 0;
  const logos = new Set();
  for (const route of routes) {
    const problems = [];
    const res = await fetch(BASE + route);
    if (!res.ok) { console.log(`FAIL ${route}: HTTP ${res.status}`); failures++; continue; }
    const { meta, links, ld } = tags(await res.text());
    const one = (k) => (meta[k] || [])[0];
    for (const [k, v] of Object.entries(CARD_WANT)) if (one(k) !== v) problems.push(`${k} is ${JSON.stringify(one(k))}, want ${JSON.stringify(v)}`);
    for (const k of CARD_PRESENT) if (!one(k)) problems.push(`missing ${k}`);
    const expected = route === '/' ? SITE : `${SITE}${route}`;
    if (!(links.canonical || []).includes(expected)) problems.push(`canonical is ${JSON.stringify(links.canonical)}, want ${expected}`);
    if (one('twitter:image') !== one('og:image')) problems.push('twitter:image differs from og:image');
    if ((links.manifest || [])[0] !== '/manifest.webmanifest') problems.push('no manifest link');
    if (!(links['apple-touch-icon'] || []).length) problems.push('no apple-touch-icon');
    if (!(links.icon || []).length) problems.push('no icon link');
    const graph = [];
    if (!ld.length) problems.push('no JSON-LD');
    for (const block of ld) {
      try { const d = JSON.parse(block); graph.push(...(d['@graph'] || [d])); } catch (e) { problems.push(`JSON-LD does not parse: ${e.message}`); }
    }
    const org = graph.find((n) => n['@type'] === 'Organization');
    if (!org) problems.push('no Organization node');
    else if (org.logo && org.logo.url) logos.add(org.logo.url);
    else problems.push('Organization has no logo');
    if (one('og:image')) await checkImage(one('og:image'), [1200, 630], 'og:image', 300000, problems);
    console.log(`${problems.length ? 'FAIL' : 'ok  '} ${route}${problems.length ? ': ' + problems.join('; ') : ''}`);
    if (problems.length) failures++;
  }
  const extra = [];
  for (const logo of logos) await checkImage(logo, [512, 512], 'Organization logo', 0, extra);
  await checkImage(`${SITE}/apple-icon`, [180, 180], 'apple-icon', 0, extra);
  await checkImage(`${SITE}/icons/icon-maskable-512.png`, [512, 512], 'maskable icon', 0, extra);
  for (const p of extra) console.log(`FAIL ${p}`);
  failures += extra.length;
  console.log(`\ncard audit: ${routes.length} pages, ${failures} with problems`);
  return failures;
}

if (args.card) {
  let routes = args.routes ? ROUTES : null;
  if (!routes) {
    const xml = await (await fetch(`${BASE}/sitemap.xml`)).text();
    routes = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => new URL(m[1]).pathname);
  }
  process.exit((await cardAudit(routes)) ? 1 : 0);
}

const resolve = resolver();
const { chromium } = createRequire(import.meta.url)(resolve('playwright'));
const AXE = resolve('axe-core/axe.min.js');

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
