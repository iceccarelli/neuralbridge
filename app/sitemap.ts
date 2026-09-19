import type { MetadataRoute } from 'next';
import { SOLUTIONS } from './lib/solutions';
import { listDocSlugs } from './lib/docs';

const SITE_URL = 'https://neuralbridge.io';

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();

  const routes: MetadataRoute.Sitemap = [
    { url: `${SITE_URL}/`, lastModified: now, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE_URL}/privacy`, lastModified: now, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${SITE_URL}/contact`, lastModified: now, changeFrequency: 'yearly', priority: 0.5 },
    { url: `${SITE_URL}/checkout/success`, lastModified: now, changeFrequency: 'yearly', priority: 0.1 },
    { url: `${SITE_URL}/developers`, lastModified: now, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${SITE_URL}/applications`, lastModified: now, changeFrequency: 'monthly', priority: 0.8 },
    { url: `${SITE_URL}/cli`, lastModified: now, changeFrequency: 'monthly', priority: 0.7 },
    { url: `${SITE_URL}/console`, lastModified: now, changeFrequency: 'monthly', priority: 0.6 },
    { url: `${SITE_URL}/connectors/cursor`, lastModified: now, changeFrequency: 'monthly', priority: 0.6 },
    { url: `${SITE_URL}/connectors/mcp`, lastModified: now, changeFrequency: 'monthly', priority: 0.6 },
    ...SOLUTIONS.map((s) => ({
      url: `${SITE_URL}/solutions/${s.slug}`,
      lastModified: now,
      changeFrequency: 'monthly' as const,
      priority: 0.8,
    })),
    ...listDocSlugs().map(({ slug }) => ({
      url: `${SITE_URL}/docs${slug.length ? `/${slug.join('/')}` : ''}`,
      lastModified: now,
      changeFrequency: 'weekly' as const,
      priority: slug.length === 0 ? 0.6 : 0.5,
    })),
  ];

  return routes;
}
