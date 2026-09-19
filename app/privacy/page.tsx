import type { Metadata } from 'next';
import { REPO } from '../lib/links';

export const metadata: Metadata = {
  title: 'Privacy | Industrial Autonomous Assurance',
  description: 'What this website collects: checked against the code, not asserted.',
  alternates: { canonical: '/privacy' },
  openGraph: {
    title: 'Privacy | Industrial Autonomous Assurance',
    description: 'What this website collects: checked against the code, not asserted.',
    url: '/privacy',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'Privacy | Industrial Autonomous Assurance',
    description: 'What this website collects: checked against the code, not asserted.',
  },
};

export default function PrivacyPage() {
  return (
    <main id="top">
      <section className="section" style={{ paddingTop: '3rem' }}>
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">Privacy</span>
            <h2>What this website actually collects</h2>
            <p>
              Written the way the rest of this product is written: checked against the code before it was
              published, not asserted. If this page and the code ever disagree, the code is right and this page is
              wrong — <a href={`${REPO}/issues/new?title=Privacy+page+is+wrong`} target="_blank" rel="noreferrer">tell us</a>.
            </p>
          </div>

          <h3>This marketing site (what you are reading now)</h3>
          <ul>
            <li>No analytics script, tag manager, or third-party tracker is loaded. There is nothing in this
              codebase that phones home when you load this page.</li>
            <li>No advertising cookies, no fingerprinting, no session replay.</li>
            <li>The one thing stored in your browser is a <code>localStorage</code> flag recording your cookie
              preference choice itself — not a cookie, not sent to a server, and not read by anything except the
              banner that wrote it.</li>
            <li>Links marked as opening GitHub, npm, or Vercel leave this site and are covered by those services'
              own privacy policies, not this one.</li>
          </ul>

          <h3>The free API endpoints (Validator tier)</h3>
          <ul>
            <li><code>POST /v1/spec/validate</code>, the separation calculator, manifest diff, advisory check,
              Declaration check, bundle re-verification, and attestation verification are all designed to run
              without an account and record nothing server-side about who called them.</li>
            <li>This service is not deployed to a public host yet — see the pricing section on the homepage for
              exactly what that means today.</li>
          </ul>

          <h3>The offline enrolment kit</h3>
          <p>
            Runs entirely on your machine, writes only to disk you control, and arms a guard that refuses every
            outbound network connection — including DNS lookups — for the duration of the run. This is not a
            policy; it is checkable in <a href={`${REPO}/blob/main/deploy/assurance/KIT.md`} target="_blank" rel="noreferrer">the kit's own source</a>.
          </p>

          <h3>The paid Register / Cell tiers</h3>
          <p>
            Not deployed publicly yet. When they are, the account and billing model (what Stripe stores, what this
            service stores) will be documented here before the first paying customer signs up — not after.
          </p>

          <h3>Contact</h3>
          <p>
            Questions about this page: <a href={`${REPO}/issues/new?title=Privacy+question`} target="_blank" rel="noreferrer">open an issue</a>.
            Security issues: see <a href={`${REPO}/blob/main/SECURITY.md`} target="_blank" rel="noreferrer">SECURITY.md</a>.
          </p>
        </div>
      </section>
    </main>
  );
}
