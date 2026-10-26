import { test, expect, type APIRequestContext } from '@playwright/test';
import { FALLBACK_PLANS } from '../app/lib/plans';

// What the built site actually serves, read over HTTP with no JavaScript: the claims the
// source-level guards in tests/test_site_honesty.py make are checked here against rendered HTML.

const pathOf = (url: string) => new URL(url, 'http://x').pathname.replace(/\/+$/, '') || '/';

const plain = (html: string) =>
  html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;|&apos;/g, "'")
    .replace(/\s+/g, ' ');

async function sitemap(request: APIRequestContext) {
  const res = await request.get('/sitemap.xml');
  expect(res.status()).toBe(200);
  const xml = await res.text();
  return { xml, paths: [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => pathOf(m[1])) };
}

function jsonLd(html: string): Array<Record<string, any>> {
  return [...html.matchAll(/<script[^>]+type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)].map((m) =>
    JSON.parse(m[1]),
  );
}

test('the pricing cards render every plan feature, with no truncation, without JavaScript', async ({ request }) => {
  const text = plain(await (await request.get('/')).text());
  for (const plan of FALLBACK_PLANS) {
    for (const feature of plan.includes) {
      expect(text, `${plan.name}: ${feature.slice(0, 60)}…`).toContain(feature.replace(/\s+/g, ' '));
    }
  }
  const cell = FALLBACK_PLANS.find((p) => p.tier === 'cell')!;
  expect(cell.includes.some((i) => i.includes('waiver'))).toBe(true);
});

test('Offer and Product structured data is on / only, monthly, and claims no availability', async ({ request }) => {
  const home = jsonLd(await (await request.get('/')).text());
  const types = home.map((b) => b['@type']);
  expect(types).toEqual(expect.arrayContaining(['Organization', 'SoftwareApplication', 'Product']));
  const offers = home.flatMap((b) => (Array.isArray(b.offers) ? b.offers : b.offers ? [b.offers] : []));
  const paid = offers.filter((o) => o.priceSpecification?.price !== '0');
  expect(paid).toHaveLength(4);
  for (const offer of paid) {
    expect(offer.priceSpecification.unitText).toBe('month');
    expect(offer.priceSpecification.priceCurrency).toBe('EUR');
    expect(offer.price).toBeUndefined();
  }
  expect(JSON.stringify(home)).not.toMatch(/availability/i);

  for (const path of ['/privacy', '/contact', '/status', '/assurance', '/docs', '/solutions/manufacturer']) {
    const blocks = jsonLd(await (await request.get(path)).text());
    expect(blocks.map((b) => b['@type']), `${path} carries only Organization`).toEqual(['Organization']);
  }
});

test('every sitemap page has exactly one h1, and the sitemap invents no modification date', async ({ request }) => {
  const { xml, paths } = await sitemap(request);
  expect(xml).not.toContain('<lastmod>');
  const bad: string[] = [];
  for (const p of paths) {
    const html = await (await request.get(p)).text();
    const n = (html.match(/<h1[\s>]/g) || []).length;
    if (n !== 1) bad.push(`${p}: ${n} h1`);
  }
  expect(bad).toEqual([]);
});

test('every docs page has its own meta description taken from its text', async ({ request }) => {
  const { paths } = await sitemap(request);
  const docs = paths.filter((p) => p === '/docs' || p.startsWith('/docs/'));
  expect(docs.length).toBeGreaterThanOrEqual(10);
  const seen = new Map<string, string>();
  for (const p of docs) {
    const html = await (await request.get(p)).text();
    const d = /<meta[^>]+name="description"[^>]+content="([^"]*)"/.exec(html)?.[1] ?? '';
    expect(d.length, `${p} has a description`).toBeGreaterThan(30);
    expect(d.length, `${p} description is short`).toBeLessThanOrEqual(260);
    expect(d, `${p} description has no markup`).not.toMatch(/[<>`]|\]\(/);
    expect(seen.get(d), `${p} shares a description with ${seen.get(d)}`).toBeUndefined();
    seen.set(d, p);
  }
});

test('every page that shows generated imagery says so, in visible text', async ({ request }) => {
  const { paths } = await sitemap(request);
  const caption = 'Illustrative images, not photographs of a customer site.';
  let shown = 0;
  for (const p of paths) {
    const html = await (await request.get(p)).text();
    if (/images(?:\/|%2F)variants/.test(html)) {
      shown += 1;
      expect(plain(html), `${p} shows imagery without the caption`).toContain(caption);
    }
  }
  expect(shown).toBeGreaterThanOrEqual(7);
});

test('the orphan llm.txt is gone, llms.txt stays, and /status is called a checklist', async ({ request }) => {
  expect((await request.get('/llm.txt', { failOnStatusCode: false })).status()).toBe(404);
  expect((await request.get('/llms.txt')).status()).toBe(200);
  const html = await (await request.get('/status')).text();
  expect(/<title>([^<]*)<\/title>/.exec(html)?.[1]).toContain('Deploy checklist');
});

test('the privacy page names every storage key the app uses', async ({ request }) => {
  const text = plain(await (await request.get('/privacy')).text());
  for (const key of ['iaa-cookie-choice', 'nb-api-key', 'nb-assurance-decision-credential', 'nb-ai-actor', 'nb-ai-session']) {
    expect(text).toContain(key);
  }
  expect(text).not.toContain('record nothing server-side');
});

test('the search box shows where focus is', async ({ page }) => {
  await page.goto('/');
  await page.locator('button[aria-label="Search"]:visible').first().click();
  const input = page.locator('.search-input');
  await expect(input).toBeVisible();
  await input.focus();
  const row = page.locator('.search-input-row');
  const outline = await row.evaluate((el) => getComputedStyle(el).outlineStyle + ' ' + getComputedStyle(el).outlineWidth);
  expect(outline).toMatch(/solid [1-9]/);
});
