import type { MetadataRoute } from 'next';
import { SOLUTIONS } from './lib/solutions';
import { DOCS } from './lib/links';

const SITE_URL = 'https://neuralbridge.io';

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();

  const routes: MetadataRoute.Sitemap = [
    { url: `${SITE_URL}/`, lastModified: now, changeFrequency: 'weekly', priority: 1 },
    { url: `${SITE_URL}/privacy`, lastModified: now, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${SITE_URL}/checkout/success`, lastModified: now, changeFrequency: 'yearly', priority: 0.1 },
    { url: `${SITE_URL}/developers`, lastModified: now, changeFrequency: 'monthly', priority: 0.7 },
    ...SOLUTIONS.map((s) => ({
      url: `${SITE_URL}/solutions/${s.slug}`,
      lastModified: now,
      changeFrequency: 'monthly' as const,
      priority: 0.8,
    })),
    { url: DOCS, lastModified: now, changeFrequency: 'weekly', priority: 0.6 },
  ];

  return routes;
}
