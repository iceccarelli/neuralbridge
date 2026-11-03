import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import Header from './Header';
import CookieConsent from './components/CookieConsent';
import CookiePreferencesLink from './components/CookiePreferencesLink';
import RepoLink from './components/RepoLink';
import { DOCS, ownerLink, repoLink } from './lib/links';
import { SOLUTIONS } from './lib/solutions';
import { CATEGORY_SLUG, PRODUCT_PAGES, productHref } from './lib/productPages';
import { HOSTED_API } from './lib/hostedApi';
import SkipLink from './components/SkipLink';
import { BRAND, SITE_URL, jsonLdString, siteGraph } from './lib/seo';
import './globals.css';

// Only site-wide defaults live here. The title, description, canonical and social tags are per page
// (buildMetadata in app/lib/seo.ts): anything set here would be inherited by a page that sets none,
// and a canonical or og:url of "/" on the 404 page would be wrong.
export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: BRAND,
  applicationName: BRAND,
  keywords: [
    'CRA Article 14',
    'Cyber Resilience Act evidence',
    'Machinery Regulation 2023/1230',
    'Annex III 1.1.9',
    'ISO/TS 15066',
    'Declaration of Conformity evidence',
    'hash-chained ledger',
    'industrial safety attestation',
    'robot cell safety evidence',
    'safety software manifest',
  ],
  authors: [{ name: 'Vincenzo Grimaldi', ...(ownerLink() ? { url: ownerLink() as string } : {}) }],
  creator: 'Vincenzo Grimaldi',
  publisher: BRAND,
  formatDetection: { telephone: false, email: false, address: false },
  icons: {
    icon: [
      { url: '/icon.svg', type: 'image/svg+xml' },
      { url: '/icons/icon-48.png', sizes: '48x48', type: 'image/png' },
    ],
    apple: [{ url: '/apple-icon', sizes: '180x180', type: 'image/png' }],
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0f1b2d',
};

// The client Header gets only what it renders (name, one-line intent, href), built here on the server from
// the data modules, so those modules' full text is not shipped in every route's JavaScript.
const productLinks = [...PRODUCT_PAGES]
  .sort((a, b) => Number(b.slug === CATEGORY_SLUG) - Number(a.slug === CATEGORY_SLUG))
  .map((p) => ({ name: p.name, blurb: p.intent, href: productHref(p.slug) }));
const solutionLinks = SOLUTIONS.map((s) => ({ slug: s.slug, role: s.role, headline: s.headline }));

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SkipLink />
        <div className="site-chrome">
          <Header productLinks={productLinks} solutionLinks={solutionLinks} />

          {children}

          <section className="footer-cta" aria-label="Get started">
            <div className="shell footer-cta-inner">
              {HOSTED_API ? (
                <>
                  <span>Re-check a Declaration, evidence bundle or passport for free — no account.</span>
                  <a className="btn btn-primary" href="/#pricing">Start free</a>
                </>
              ) : (
                <>
                  <span>Re-check a Declaration, evidence bundle or passport on your own machine — the offline kit needs no account or upload.</span>
                  <a className="btn btn-primary" href="/docs/getting-started">Read the quickstart</a>
                </>
              )}
            </div>
          </section>

          <footer className="site-footer">
            <div className="shell footer-columns">
              <div>
                <h2>Industrial Autonomous Assurance</h2>
                <p style={{ fontSize: '0.82rem', lineHeight: 1.6, margin: 0 }}>
                  Evidence infrastructure for machines whose software can hurt someone. Re-checking someone
                  else&apos;s evidence needs no account. The file verifier allows 20 a day per address and manifest
                  diff 10; declaration, bundle, passport and attestation checks are not metered.
                  {!HOSTED_API && ' The hosted API is not deployed to a public endpoint yet; the offline kit runs these checks on your own machine.'}
                </p>
              </div>

              <div>
                <h2>Products</h2>
                <ul>
                  <li><a href="/#products">Validator (free)</a></li>
                  <li><a href="/#pricing">Register — &euro;390/mo</a></li>
                  <li><a href="/#pricing">Cell — &euro;1,290/mo</a></li>
                  <li><a href="/assurance">Workspace (your key)</a></li>
                  <li>
                    {repoLink() ? (
                      <RepoLink path="/tree/main/src/assurance/api">Assurance API</RepoLink>
                    ) : (
                      <a href="/developers">Assurance API</a>
                    )}
                  </li>
                </ul>
              </div>

              <div>
                <h2>How it works</h2>
                <ul>
                  {PRODUCT_PAGES.map((p) => (
                    <li key={p.slug}><a href={productHref(p.slug)}>{p.name}</a></li>
                  ))}
                </ul>
              </div>

              <div>
                <h2>Solutions</h2>
                <ul>
                  {SOLUTIONS.map((s) => (
                    <li key={s.slug}><a href={`/solutions/${s.slug}`}>{s.role}</a></li>
                  ))}
                </ul>
              </div>

              <div>
                <h2>Regulation &amp; evidence</h2>
                <ul>
                  <li><a href="/docs">CRA Article 14</a></li>
                  <li><a href="/docs/assurance/machinery">Machinery Reg. Annex III 1.1.9</a></li>
                  <li><a href="/docs/assurance/attest">Hash-chained ledger</a></li>
                  <li><a href="/docs/assurance/kit">Offline enrolment kit</a></li>
                </ul>
              </div>

              <div>
                <h2>Developers</h2>
                <ul>
                  <li><a href={DOCS}>Documentation</a></li>
                  <li><a href="/developers">API reference</a></li>
                  <li><a href="/applications">Applications</a></li>
                  <li><a href="/cli">CLI</a></li>
                  <li><a href="/connectors/mcp">MCP connector</a></li>
                  <li><a href="/connectors/cursor">Cursor connector</a></li>
                  <li><a href="/console">Console</a></li>
                  <li><a href="/ai">AI control plane</a></li>
                  {repoLink() && <li><RepoLink path="">GitHub repository</RepoLink></li>}
                  <li><a href="/roadmap">Roadmap</a></li>
                  {repoLink() && <li><RepoLink path="/blob/main/CONTRIBUTING.md">Contributing</RepoLink></li>}
                  <li><a href="/security">Security</a></li>
                </ul>
              </div>

              <div>
                <h2>Legal</h2>
                <ul>
                  <li><a href="/privacy">Privacy</a></li>
                  <li><CookiePreferencesLink className="footer-link-button" /></li>
                  <li><a href="/contact">Licensing &amp; permissions</a></li>
                  <li><a href="/status">Deploy checklist</a></li>
                </ul>
              </div>
            </div>

            <div className="shell footer-bottom">
              <span>&copy; 2026 Industrial Autonomous Assurance &middot; All rights reserved &middot; Built by Vincenzo Grimaldi</span>
              <RepoLink path="">{(repoLink() ?? '').replace('https://', '')}</RepoLink>
            </div>
          </footer>
        </div>

        <CookieConsent />

        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: jsonLdString(siteGraph()) }}
        />
      </body>
    </html>
  );
}
