import { test, expect } from '@playwright/test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

// Every internal link on the site resolves. Crawls the running Next server from the home page
// and the sitemap, over HTTP, and checks: no dead anchors (href="#" or empty), no javascript:
// links, every internal path answers (not 404/5xx), and every #fragment exists as an id on the
// page it points to. External links are not fetched (no network is assumed).

const MAX_PAGES = 400;

// Every route whose page.tsx declares `robots: { index: false }`, derived from the source rather than
// listed by hand, so a page that is made noindex later cannot stay in the sitemap unnoticed.
function noindexRoutes(): string[] {
  const root = join(process.cwd(), 'app');
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (name === 'page.tsx' && /index:\s*false/.test(readFileSync(full, 'utf8'))) {
        const route = '/' + relative(root, dir).split(sep).filter((seg) => !/^\(.*\)$/.test(seg)).join('/');
        out.push(route === '/' ? '/' : route.replace(/\/$/, ''));
      }
    }
  };
  walk(root);
  return out;
}

test('the noindex set is derived from the pages, and covers the three known ones', () => {
  const found = noindexRoutes();
  for (const r of ['/assurance', '/checkout/success', '/status']) expect(found, `${r} declares index: false`).toContain(r);
});

function hrefs(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<a\b[^>]*?\shref=(?:"([^"]*)"|'([^']*)')/gi)) out.push((m[1] ?? m[2] ?? '').replace(/&amp;/g, '&'));
  return out;
}

function ids(html: string): Set<string> {
  const out = new Set<string>();
  for (const m of html.matchAll(/\s(?:id|name)=(?:"([^"]+)"|'([^']+)')/gi)) out.add(m[1] ?? m[2]);
  return out;
}

test('every internal link, anchor and sitemap entry on the site resolves', async ({ request, baseURL }) => {
  test.setTimeout(600_000);
  const origin = new URL(baseURL!).origin;
  const problems: string[] = [];
  const pages = new Map<string, { status: number; html: string }>();

  async function fetchPage(path: string) {
    if (pages.has(path)) return pages.get(path)!;
    const res = await request.get(`${origin}${path}`, { maxRedirects: 5, failOnStatusCode: false });
    const ct = res.headers()['content-type'] || '';
    const entry = { status: res.status(), html: ct.includes('text/html') ? await res.text() : '' };
    pages.set(path, entry);
    return entry;
  }

  const queue: string[] = ['/'];
  const sitemap = await request.get(`${origin}/sitemap.xml`);
  expect(sitemap.status()).toBe(200);
  const noindex = noindexRoutes();
  const listed: string[] = [];
  for (const m of (await sitemap.text()).matchAll(/<loc>([^<]+)<\/loc>/g)) {
    const u = new URL(m[1], origin);
    // noindex pages must not be advertised to crawlers
    for (const r of noindex) {
      expect(u.pathname === r || u.pathname.startsWith(`${r}/`), `noindex page ${r} listed in sitemap`).toBe(false);
    }
    listed.push(u.pathname);
    queue.push(u.pathname + u.search);
  }

  const seen = new Set<string>();
  const referrers = new Map<string, Set<string>>();
  const fragments: { from: string; path: string; frag: string }[] = [];

  while (queue.length && seen.size < MAX_PAGES) {
    const path = queue.shift()!;
    if (seen.has(path)) continue;
    seen.add(path);
    const page = await fetchPage(path);
    if (page.status >= 400) {
      problems.push(`${path} -> HTTP ${page.status} (linked from ${[...(referrers.get(path) ?? ['sitemap or start'])].slice(0, 3).join(', ')})`);
      continue;
    }
    for (const raw of hrefs(page.html)) {
      const href = raw.trim();
      if (href === '' || href === '#') {
        problems.push(`${path}: dead anchor href="${href}"`);
        continue;
      }
      if (/^(javascript|data):/i.test(href)) {
        problems.push(`${path}: unsafe link ${href.slice(0, 40)}`);
        continue;
      }
      if (/^(mailto:|tel:)/i.test(href)) continue;
      let url: URL;
      try {
        url = new URL(href, `${origin}${path}`);
      } catch {
        problems.push(`${path}: unparseable href ${href}`);
        continue;
      }
      if (url.origin !== origin) continue; // external: not fetched
      const target = url.pathname + url.search;
      if (url.pathname.startsWith('/_next') || /\.(png|jpe?g|svg|webp|ico|css|js|woff2?|txt|xml|json)$/i.test(url.pathname)) {
        const asset = await fetchPage(target);
        if (asset.status >= 400) problems.push(`${path}: asset ${target} -> HTTP ${asset.status}`);
        continue;
      }
      if (url.hash) fragments.push({ from: path, path: target, frag: decodeURIComponent(url.hash.slice(1)) });
      if (!referrers.has(target)) referrers.set(target, new Set());
      referrers.get(target)!.add(path);
      if (!seen.has(target)) queue.push(target);
    }
  }

  for (const f of fragments) {
    const page = await fetchPage(f.path);
    if (page.status >= 400 || !page.html) continue; // already reported
    if (!ids(page.html).has(f.frag)) problems.push(`${f.from}: #${f.frag} is not an id on ${f.path}`);
  }

  // And what the page itself says wins over what the source says: a sitemap entry whose rendered page
  // carries a noindex robots tag is a contradiction, however the tag got there.
  for (const path of listed) {
    const page = await fetchPage(path);
    if (/<meta[^>]+name=["']robots["'][^>]*content=["'][^"']*noindex/i.test(page.html)) {
      problems.push(`${path}: listed in the sitemap but renders <meta name="robots" content="...noindex...">`);
    }
  }

  console.log(`crawled ${seen.size} page(s), ${fragments.length} fragment link(s)`);
  expect(problems, problems.join('\n')).toEqual([]);
  expect(seen.size).toBeGreaterThan(20);
});
