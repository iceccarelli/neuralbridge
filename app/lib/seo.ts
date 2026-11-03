import type { Metadata } from 'next';
import { ownerLink, repoSameAs } from './links';

// The one place page metadata and structured data are assembled. Pages pass a short page name, a
// description and a path; this returns the canonical, OpenGraph and Twitter tags so no page can
// forget one (a page-level `openGraph` replaces the layout's wholesale, and with it the image).
// tests/test_site_seo.py parses the built HTML and holds the limits below.

export const SITE_URL = 'https://neuralbridge.io';
export const BRAND = 'Industrial Autonomous Assurance';
// The abbreviation the site already prints in its social image mark; used only when the full brand
// would push a title past the limit.
export const BRAND_SHORT = 'IAA';
export const TITLE_MAX = 60;
export const DESCRIPTION_MIN = 120;
export const DESCRIPTION_MAX = 160;
export const SITE_DESCRIPTION =
  'Evidence infrastructure for CRA Article 14 and Machinery Regulation Annex III 1.1.9: a hash-chained record of what is on each machine, which checks were run against it, and when.';
export const OG_IMAGE = {
  url: '/opengraph-image',
  width: 1200,
  height: 630,
  type: 'image/png',
  alt: BRAND,
};

/** `Name | Industrial Autonomous Assurance`, shortened (brand, then abbreviation, then the name alone) to fit TITLE_MAX. */
export function pageTitle(name: string): string {
  for (const candidate of [`${name} | ${BRAND}`, `${name} | ${BRAND_SHORT}`, name]) {
    if (candidate.length <= TITLE_MAX) return candidate;
  }
  // A name longer than the limit on its own: cut at a word boundary rather than mid-word.
  const cut = name.slice(0, TITLE_MAX - 1).replace(/\s+\S*$/, '');
  return `${cut}…`;
}

/** A description trimmed at a word boundary to DESCRIPTION_MAX; shorter text is returned unchanged. */
export function fitDescription(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  if (flat.length <= DESCRIPTION_MAX) return flat;
  const cut = flat.slice(0, DESCRIPTION_MAX - 1).replace(/[\s,;:—-]+\S*$/, '');
  return `${cut}…`;
}

/**
 * A docs page's description: its first paragraph (app/lib/docDescription.ts), padded with a plain
 * sentence when it is too short for a snippet and cut at a word boundary when it is too long.
 */
export function docDescription(paragraph: string, title: string): string {
  let text = paragraph.replace(/\s+/g, ' ').trim();
  if (!text) text = `${title}.`;
  if (text.length < DESCRIPTION_MIN) text = `${text} Part of the ${BRAND} documentation.`;
  if (text.length < DESCRIPTION_MIN) text = `${text} Read from the same files the product is built from.`;
  return fitDescription(text);
}

/** `/x/` and `/x` are one URL: canonical paths never carry a trailing slash (except the root). */
export function canonicalPath(path: string): string {
  const p = path.startsWith('/') ? path : `/${path}`;
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

export interface PageMeta {
  /** Page name without the brand, e.g. `Privacy`. Ignored when `absoluteTitle` is set. */
  title: string;
  /** Use `title` exactly as written (the home page, which leads with the brand). */
  absoluteTitle?: boolean;
  description: string;
  /** The page's path; omitted only for the 404 page, which has no address of its own (no canonical, no og:url). */
  path?: string;
  /** Keep the page out of search results (`noindex, follow`). */
  noindex?: boolean;
  /**
   * The page has its own `opengraph-image` route next to it (`<path>/opengraph-image`, rendered by
   * app/lib/ogCard.tsx); otherwise the site-wide card is used.
   */
  ownImage?: boolean;
}

export function buildMetadata({ title, absoluteTitle, description, path, noindex, ownImage }: PageMeta): Metadata {
  const fullTitle = absoluteTitle ? title : pageTitle(title);
  const canonical = path === undefined ? undefined : canonicalPath(path);
  const url = canonical === undefined ? undefined : canonical === '/' ? `${SITE_URL}/` : `${SITE_URL}${canonical}`;
  const image = ownImage && canonical ? { ...OG_IMAGE, url: `${canonical === '/' ? '' : canonical}/opengraph-image`, alt: fullTitle } : OG_IMAGE;
  return {
    title: { absolute: fullTitle },
    description,
    ...(canonical ? { alternates: { canonical } } : {}),
    ...(noindex ? { robots: { index: false, follow: true } } : {}),
    openGraph: {
      title: fullTitle,
      description,
      ...(url ? { url } : {}),
      siteName: BRAND,
      locale: 'en_GB',
      type: 'website',
      images: [image],
    },
    twitter: {
      card: 'summary_large_image',
      title: fullTitle,
      description,
      images: [{ url: image.url, alt: image.alt }],
    },
  };
}

// --- structured data -------------------------------------------------------------------------
// Only what the site can stand behind: the organisation, the website, and breadcrumbs that are
// also visible on the page. No Offer, Product, Review, rating or award: prices are unvalidated
// assertions (see CLAUDE.md) and the home page's own structured-offers.json is a separate, tested
// block. The Organization logo is the generated app icon (app/icons/[file]/route.tsx). The WebSite node has no potentialAction because the site has no search results page: the
// header search is a client-side overlay over a static index and has no URL a crawler could use.

const ORG_ID = `${SITE_URL}/#organization`;
const SITE_ID = `${SITE_URL}/#website`;
// The only addresses already published in this repository: hello@ is the contact form's recipient
// (app/components/ContactForm.tsx). The security address is in SECURITY.md and public/.well-known/security.txt.
export const CONTACT_EMAIL = 'hello@neuralbridge.io';
export const LOGO_URL = `${SITE_URL}/icons/icon-512.png`;

/** The @graph emitted once, by the root layout. */
export function siteGraph() {
  const owner = ownerLink();
  const sameAs = repoSameAs();
  return {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'Organization',
        '@id': ORG_ID,
        name: BRAND,
        url: `${SITE_URL}/`,
        founder: { '@type': 'Person', name: 'Vincenzo Grimaldi', ...(owner ? { url: owner } : {}) },
        logo: { '@type': 'ImageObject', url: LOGO_URL, width: 512, height: 512 },
        image: LOGO_URL,
        email: CONTACT_EMAIL,
        contactPoint: { '@type': 'ContactPoint', contactType: 'sales', email: CONTACT_EMAIL, url: `${SITE_URL}/contact` },
        ...(sameAs.length ? { sameAs } : {}),
      },
      {
        '@type': 'WebSite',
        '@id': SITE_ID,
        name: BRAND,
        url: `${SITE_URL}/`,
        description: SITE_DESCRIPTION,
        inLanguage: 'en',
        publisher: { '@id': ORG_ID },
      },
    ],
  };
}

export interface Crumb {
  name: string;
  path: string;
}

/** BreadcrumbList for a trail that is also rendered on the page (the first crumb is the home page). */
export function breadcrumbJsonLd(trail: Crumb[]) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: trail.map((crumb, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: crumb.name,
      item: `${SITE_URL}${canonicalPath(crumb.path) === '/' ? '/' : canonicalPath(crumb.path)}`,
    })),
  };
}

/** JSON for an inline `application/ld+json` script: `<` is escaped so no value can close the tag. */
export function jsonLdString(data: unknown): string {
  return JSON.stringify(data).replace(/</g, '\\u003c');
}
