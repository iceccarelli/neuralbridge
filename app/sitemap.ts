import type { MetadataRoute } from 'next';
import { SOLUTIONS } from './lib/solutions';
import { listDocSlugs } from './lib/docs';

const SITE_URL = 'https://neuralbridge.io';

export default function sitemap(): MetadataRoute.Sitemap {
  // No modification dates: this build cannot know when each page last changed, and stamping every URL
  // with the build time would claim a freshness nothing verified.
  // Only indexable pages belong here: /checkout/success, /assurance and /status are noindex
  // (`robots: { index: false }`); tests-e2e/site-links.spec.ts derives that set from the pages.
  const routes: MetadataRoute.Sitemap = [
    { url: `${SITE_URL}/`, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE_URL}/privacy`, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${SITE_URL}/contact`, changeFrequency: 'yearly', priority: 0.5 },
    { url: `${SITE_URL}/developers`, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${SITE_URL}/applications`, changeFrequency: 'monthly', priority: 0.8 },
    { url: `${SITE_URL}/cli`, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${SITE_URL}/verify`, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${SITE_URL}/console`, changeFrequency: 'monthly', priority: 0.6 },
    { url: `${SITE_URL}/ai`, changeFrequency: 'monthly', priority: 0.6 },
    { url: `${SITE_URL}/connectors/cursor`, changeFrequency: 'monthly', priority: 0.6 },
    { url: `${SITE_URL}/connectors/mcp`, changeFrequency: 'monthly', priority: 0.6 },
    { url: `${SITE_URL}/roadmap`, changeFrequency: 'monthly', priority: 0.5 },
    { url: `${SITE_URL}/security`, changeFrequency: 'monthly', priority: 0.4 },
    ...SOLUTIONS.map((s) => ({
      url: `${SITE_URL}/solutions/${s.slug}`,
     
      changeFrequency: 'monthly' as const,
      priority: 0.8,
    })),
    ...listDocSlugs().map(({ slug }) => ({
      url: `${SITE_URL}/docs${slug.length ? `/${slug.join('/')}` : ''}`,
     
      changeFrequency: 'weekly' as const,
      priority: slug.length === 0 ? 0.6 : 0.5,
    })),
  ];

  return routes;
}
