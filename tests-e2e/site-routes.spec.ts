import { test, expect } from '@playwright/test';

// Dynamic routes must render the page they were asked for.
//
// On Next 15+ route `params` is a Promise, and Next 16 removed the synchronous access Next 14
// allowed. Code that still reads `params.slug` gets `undefined`: /solutions/<slug> then returns a
// 404 (caught by site-links.spec.ts), but the /docs/[[...slug]] catch-all quietly renders the docs
// INDEX for every URL, with HTTP 200 and a canonical of /docs/. A status-code check cannot see that,
// so this spec reads what each page actually says about itself.

const pathOf = (url: string) => new URL(url, 'http://x').pathname.replace(/\/+$/, '') || '/';
// The path exactly as written: /docs/ and /docs are different URLs (the first redirects to the second).
const exactPathOf = (url: string) => new URL(url, 'http://x').pathname;

const text = (html: string, re: RegExp) =>
  (re.exec(html)?.[1] ?? '')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();

async function sitemapPaths(request: import('@playwright/test').APIRequestContext) {
  const res = await request.get('/sitemap.xml');
  expect(res.status()).toBe(200);
  return [...(await res.text()).matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => pathOf(m[1]));
}

test.describe('dynamic routes render their own page', () => {
  test('every solution page has its own heading, title and canonical', async ({ request }) => {
    const paths = (await sitemapPaths(request)).filter((p) => p.startsWith('/solutions/'));
    expect(paths.length).toBeGreaterThanOrEqual(5);

    const headings = new Set<string>();
    for (const p of paths) {
      const res = await request.get(p);
      expect(res.status(), `${p} status`).toBe(200);
      const html = await res.text();
      expect(html, `${p} must not be noindex`).not.toMatch(/<meta[^>]+name="robots"[^>]+noindex/i);
      const canonical = /<link[^>]+rel="canonical"[^>]+href="([^"]+)"/i.exec(html)?.[1] ?? '';
      expect(pathOf(canonical), `${p} canonical`).toBe(p);
      const h1 = text(html, /<h1[^>]*>([\s\S]*?)<\/h1>/i);
      expect(h1.length, `${p} has an h1`).toBeGreaterThan(10);
      headings.add(h1);
    }
    // One distinct heading per solution: the same page served under every slug is the failure.
    expect(headings.size).toBe(paths.length);
  });

  test('every docs page renders its own document, not the docs index', async ({ request }) => {
    const paths = (await sitemapPaths(request)).filter((p) => p === '/docs' || p.startsWith('/docs/'));
    expect(paths.length).toBeGreaterThanOrEqual(10);

    const titles = new Map<string, string>();
    const h1s = new Map<string, string>();
    for (const p of paths) {
      const res = await request.get(p);
      expect(res.status(), `${p} status`).toBe(200);
      const html = await res.text();
      const canonical = /<link[^>]+rel="canonical"[^>]+href="([^"]+)"/i.exec(html)?.[1] ?? '';
      expect(exactPathOf(canonical), `${p} canonical must be exactly its own path (no trailing slash)`).toBe(p);
      titles.set(p, text(html, /<title[^>]*>([\s\S]*?)<\/title>/i));
      h1s.set(p, text(html, /<h1[^>]*>([\s\S]*?)<\/h1>/i));
      // The sidebar marks the page it is on, and only that one (the footer also links to some docs
      // pages, and every page renders the whole sidebar, so a plain href match proves nothing).
      const active = [...html.matchAll(/<a\b[^>]*>/g)]
        .map((m) => m[0])
        .filter((tag) => /class="[^"]*\bdocs-nav-link\b[^"]*\bactive\b/.test(tag))
        .map((tag) => /href="([^"]+)"/.exec(tag)?.[1]);
      expect(active, `${p} marks exactly itself active in the docs nav`).toEqual([p]);
    }
    // Every page is its own document. If any URL served another page's body (the docs index, say),
    // two would share a title or heading; a tolerance would let exactly that through.
    const dup = (m: Map<string, string>) =>
      [...m.entries()].filter(([, v], i, a) => a.findIndex(([, w]) => w === v) !== i).map(([k]) => k);
    expect(dup(titles), 'docs pages sharing a <title> with an earlier page').toEqual([]);
    expect(dup(h1s), 'docs pages sharing an <h1> with an earlier page').toEqual([]);
  });

  test('an unknown docs path is a real 404, not the index', async ({ request }) => {
    const res = await request.get('/docs/this-page-does-not-exist-9f3a');
    expect(res.status()).toBe(404);
  });

  test('the hero image keeps its high fetch priority (Next 16 stopped adding it for `priority`)', async ({ request }) => {
    for (const p of ['/', '/solutions/manufacturer']) {
      const html = await (await request.get(p)).text();
      expect(html, `${p} preloads its hero with fetchPriority=high`).toMatch(/<link[^>]+rel="preload"[^>]+as="image"[^>]+fetchPriority="high"|<link[^>]+fetchPriority="high"[^>]+rel="preload"/i);
      expect(html, `${p} hero <img>`).toMatch(/<img[^>]+fetchPriority="high"/i);
    }
  });
});
