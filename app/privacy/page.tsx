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
            <h1>What this website actually collects</h1>
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
            <li>This site writes to your browser&apos;s storage in the cases below, and nowhere else. It sets no
              cookies. None of it is sent anywhere except, where stated, to the API you configured.</li>
          </ul>

          <h3>What is stored in your browser</h3>
          <ul>
            <li><code>localStorage</code>, key <code>iaa-cookie-choice</code>: your cookie-banner choice
              (<code>accepted</code> or <code>declined</code>). It stays until you clear site data and is read only
              by the banner that wrote it.</li>
            <li><code>sessionStorage</code>, key <code>nb-api-key</code>: an API key, only if you paste one into
              <code> /console</code>, <code>/ai</code> or <code>/assurance</code>, or receive one on the checkout
              success page. It lasts for that browser tab and is gone when the tab closes. It is sent only as the
              <code> X-API-Key</code> header to the API host this build is configured with. It is readable by any
              script running on this origin and by browser extensions, so use a key you can rotate. On first load
              the site also reads the older keys <code>nb-console-api-key</code> and <code>nb-ai-api-key</code> to
              carry a key you pasted earlier over to <code>nb-api-key</code>; it never writes to them.</li>
            <li><code>sessionStorage</code>, key <code>nb-assurance-decision-credential</code>: an operator key, only
              if you paste one into an operator panel on <code>/assurance</code>. Same lifetime and same
              destination as above.</li>
            <li><code>sessionStorage</code>, keys <code>nb-ai-actor</code> and <code>nb-ai-session</code>: a random
              label (<code>operator-</code> plus six characters) and a random session id, created the first time you
              open <code>/ai</code>. They are sent as the <code>X-NB-Actor</code> and <code>X-NB-Session</code> headers with every
              <code>/ai</code> request to the API, and are gone when the tab closes.</li>
          </ul>

          <h3>Links</h3>
          <ul>
            <li>Links marked as opening GitHub, npm, or Vercel leave this site and are covered by those services'
              own privacy policies, not this one.</li>
          </ul>

          <h3>The free API endpoints (Validator tier)</h3>
          <p>
            Checked against <code>src/assurance/billing/accounts.py</code> and <code>src/assurance/api/deps.py</code>.
            The free endpoints need no account, but they are not unrecorded:
          </p>
          <ul>
            <li>A call with no API key is keyed to the caller&apos;s network address: the IPv4 address, or the
              IPv6 /64 prefix, stored as <code>ip:&lt;address&gt;</code>. To enforce the daily allowance, the
              service stores one counter per address, per metered scope and per UTC day (a row of subject, scope,
              day and count) in its accounts database. The counter holds no request content: nothing about a
              filing, manifest, advisory or file you submit is stored.</li>
            <li>Counters older than 7 days are deleted the first time a caller spends on a route family in a new
              UTC day, so the table is bounded by recent activity.</li>
            <li>Which calls count: <code>POST /v1/spec/validate</code>, the separation calculator, manifest diff,
              advisory check and the file verifier (<code>POST /v1/evidence/verify</code>) carry a daily allowance,
              so they write that counter. Declaration, evidence-bundle, passport and attestation checks are not
              metered and write nothing.</li>
            <li>A call made with an account&apos;s API key on a plan that has a daily allowance (the Validator and
              pay-as-you-go plans) is recorded against the account instead: a counter keyed to the account, and a
              durable usage event per metered call (event id, scope, quantity, time, idempotency key; table
              <code>usage_events</code>), which is also what pay-as-you-go billing reads. Plans with no daily cap
              (Register, Cell) write neither a counter nor a usage event for these calls.</li>
            <li>Whatever web server or proxy sits in front of the service keeps its own access log, which normally
              includes the address, method, path and status. This repository does not configure that log or its
              retention.</li>
            <li>This service is not deployed to a public host yet — see the pricing section on the homepage for
              exactly what that means today.</li>
          </ul>

          <h3>The offline enrolment kit</h3>
          <p>
            Runs entirely on your machine, writes only to disk you control, and arms a guard that refuses every
            outbound network connection — including DNS lookups — for the duration of the run. This is not a
            policy; it is checkable in <a href="/docs/assurance/kit">the kit's own docs</a>.
          </p>

          <h3>The paid Register / Cell tiers</h3>
          <p>
            Not deployed publicly yet. When they are, the account and billing model (what Stripe stores, what this
            service stores) will be documented here before the first paying customer signs up — not after.
          </p>

          <h3>Contact</h3>
          <p>
            Questions about this page: <a href={`${REPO}/issues/new?title=Privacy+question`} target="_blank" rel="noreferrer">open an issue</a>.
            Security issues: see <a href="/security">the security policy</a>.
          </p>
        </div>
      </section>
    </main>
  );
}
