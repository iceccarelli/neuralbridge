import type { MetadataRoute } from 'next';
import { SITE_URL } from './lib/seo';

// Everything is crawlable except the pages that are an account's own state or a transaction:
// the keyed workspaces, the post-checkout page and the deploy checklist. Each of those is also
// `noindex` in its own metadata (tests/test_site_seo.py ties this list to those pages and to
// app/sitemap.ts, which must not list them).
const DISALLOWED_PATHS = ['/assurance', '/checkout/', '/investigate', '/status'];

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: '/',
      disallow: DISALLOWED_PATHS,
    },
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
