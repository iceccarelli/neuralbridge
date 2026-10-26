import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import Header from './Header';
import CookieConsent from './components/CookieConsent';
import CookiePreferencesLink from './components/CookiePreferencesLink';
import { DOCS, REPO } from './lib/links';
import { SOLUTIONS } from './lib/solutions';
import './globals.css';

const SITE_URL = 'https://neuralbridge.io';

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: 'Industrial Autonomous Assurance | CRA Article 14 & Machinery Regulation evidence',
  description:
    'Evidence infrastructure for machines whose software can hurt someone. A hash-chained record of what is on each machine, which checks were run against it, and when — built for CRA Article 14 (Reg. 2024/2847) and Machinery Regulation Annex III 1.1.9 (Reg. 2023/1230). Free Validator tier, paid Register and Cell plans.',
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
  authors: [{ name: 'Vincenzo Grimaldi', url: 'https://github.com/iceccarelli' }],
  creator: 'Vincenzo Grimaldi',
  publisher: 'Industrial Autonomous Assurance',
  alternates: { canonical: '/', languages: { 'x-default': '/' } },
  openGraph: {
    title: 'Industrial Autonomous Assurance',
    description: 'A hash-chained record of what is on each machine, which checks were run against it, and when. Evidence for CRA Art. 14 and Machinery Regulation Annex III 1.1.9 processes, kept in a record instead of a spreadsheet.',
    url: `${SITE_URL}/`,
    siteName: 'Industrial Autonomous Assurance',
    locale: 'en_GB',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Industrial Autonomous Assurance',
    description: 'Evidence infrastructure for machines whose software can hurt someone. Re-checking someone else’s evidence is free.',
  },
};

const organizationData = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'Industrial Autonomous Assurance',
  url: `${SITE_URL}/`,
  founder: {
    '@type': 'Person',
    name: 'Vincenzo Grimaldi',
    url: 'https://github.com/iceccarelli',
  },
  sameAs: [REPO],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="site-chrome">
          <Header />

          {children}

          <section className="footer-cta">
            <div className="shell footer-cta-inner">
              <span>Re-check a Declaration, evidence bundle or passport for free — no account.</span>
              <a className="btn btn-primary" href="/#pricing">Start free</a>
            </div>
          </section>

          <footer className="site-footer">
            <div className="shell footer-columns">
              <div>
                <h4>Industrial Autonomous Assurance</h4>
                <p style={{ fontSize: '0.82rem', lineHeight: 1.6, margin: 0 }}>
                  Evidence infrastructure for machines whose software can hurt someone. Re-checking someone
                  else&apos;s evidence needs no account. The file verifier allows 20 a day per address; the other
                  re-checks are not metered.
                </p>
              </div>

              <div>
                <h4>Products</h4>
                <ul>
                  <li><a href="/#products">Validator (free)</a></li>
                  <li><a href="/#pricing">Register — &euro;390/mo</a></li>
                  <li><a href="/#pricing">Cell — &euro;1,290/mo</a></li>
                  <li><a href="/assurance">Workspace (your key)</a></li>
                  <li><a href={`${REPO}/tree/main/src/assurance/api`} target="_blank" rel="noreferrer">Assurance API</a></li>
                </ul>
              </div>

              <div>
                <h4>Solutions</h4>
                <ul>
                  {SOLUTIONS.map((s) => (
                    <li key={s.slug}><a href={`/solutions/${s.slug}`}>{s.role}</a></li>
                  ))}
                </ul>
              </div>

              <div>
                <h4>Regulation &amp; evidence</h4>
                <ul>
                  <li><a href="/docs">CRA Article 14</a></li>
                  <li><a href="/docs/assurance/machinery">Machinery Reg. Annex III 1.1.9</a></li>
                  <li><a href="/docs/assurance/attest">Hash-chained ledger</a></li>
                  <li><a href="/docs/assurance/kit">Offline enrolment kit</a></li>
                </ul>
              </div>

              <div>
                <h4>Developers</h4>
                <ul>
                  <li><a href={DOCS}>Documentation</a></li>
                  <li><a href="/developers">API reference</a></li>
                  <li><a href="/applications">Applications</a></li>
                  <li><a href="/cli">CLI</a></li>
                  <li><a href="/connectors/mcp">MCP connector</a></li>
                  <li><a href="/connectors/cursor">Cursor connector</a></li>
                  <li><a href="/console">Console</a></li>
                  <li><a href="/ai">AI control plane</a></li>
                  <li><a href={REPO} target="_blank" rel="noreferrer">GitHub repository</a></li>
                  <li><a href="/roadmap">Roadmap</a></li>
                  <li><a href={`${REPO}/blob/main/CONTRIBUTING.md`} target="_blank" rel="noreferrer">Contributing</a></li>
                  <li><a href="/security">Security</a></li>
                </ul>
              </div>

              <div>
                <h4>Legal</h4>
                <ul>
                  <li><a href="/privacy">Privacy</a></li>
                  <li><CookiePreferencesLink className="footer-link-button" /></li>
                  <li><a href={`${REPO}/blob/main/LICENSE`} target="_blank" rel="noreferrer">MIT License</a></li>
                  <li><a href="/status">Deploy checklist</a></li>
                </ul>
              </div>
            </div>

            <div className="shell footer-bottom">
              <span>&copy; 2026 Industrial Autonomous Assurance &middot; MIT Licensed &middot; Built by Vincenzo Grimaldi</span>
              <a href={REPO} target="_blank" rel="noreferrer">github.com/iceccarelli/neuralbridge</a>
            </div>
          </footer>
        </div>

        <CookieConsent />

        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationData) }}
        />
      </body>
    </html>
  );
}
