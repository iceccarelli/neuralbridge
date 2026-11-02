import type { Metadata } from 'next';
import Link from 'next/link';
import { buildMetadata } from './lib/seo';

// Served with HTTP 404 for any URL that matches no route. Next adds `<meta name="robots" content="noindex">`
// to a not-found response itself (tests/test_site_seo.py checks the built page for it), so none is set here.
export const metadata: Metadata = buildMetadata({
  title: 'Page not found',
  description: 'This page does not exist on neuralbridge.io. Go to the documentation, the contact page or the home page.',
});

export default function NotFound() {
  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell" style={{ maxWidth: '640px' }}>
          <div className="section-head">
            <span className="eyebrow">Error 404</span>
            <h1>This page does not exist</h1>
            <p>
              The address may be mistyped, or the page may have moved. These are the places most visitors are
              looking for:
            </p>
          </div>
          <ul>
            <li>
              <Link href="/docs">Documentation</Link> — getting started, each assurance engine, the capability table.
            </li>
            <li>
              <Link href="/contact">Contact</Link> — ask us where something went.
            </li>
            <li>
              <Link href="/">Home</Link> — what Industrial Autonomous Assurance is and what it does.
            </li>
          </ul>
        </div>
      </section>
    </main>
  );
}
