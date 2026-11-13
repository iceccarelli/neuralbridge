import type { Metadata } from 'next';
import { buildMetadata } from '../lib/seo';
import RepoLink from '../components/RepoLink';
import { SALES } from '../lib/links';
import { IMAGES } from '../lib/images';
import RotatingImage from '../components/RotatingImage';
import ImageryNote from '../components/ImageryNote';
import VisualDiagram from '../components/VisualDiagram';
import { APPLICATION_VISUAL_SLUGS } from '../lib/visuals';

export const metadata: Metadata = buildMetadata({
  title: 'Applications',
  description:
    'Cobots, packaging lines, fleet advisory, the OEM register, and insurer evidence — each mapped to a real /v1 route and the plan that gates it.',
  path: '/applications',
});

interface Application {
  slug: string;
  name: string;
  imageKey: string;
  summary: string;
  routes: { method: string; path: string }[];
  plan: string;
  href: string;
}

const APPLICATIONS: Application[] = [
  {
    slug: 'cobots',
    name: 'Cobots & collaborative cells',
    imageKey: 'card-engine-machine-safety',
    summary: 'ISO/TS 15066 protective separation, checked against the declared envelope — free to calculate, gated to verify a recorded run.',
    routes: [
      { method: 'POST', path: '/v1/machine/separation' },
      { method: 'POST', path: '/v1/machine/verify' },
    ],
    plan: 'Free calculator, Cell to verify',
    href: '/docs/assurance/machine',
  },
  {
    slug: 'packaging',
    name: 'Packaging & palletising lines',
    imageKey: 'card-engine-annex-iii',
    summary: 'The staleness join: a sign-off from before a change, dated against the change itself. What safety software is on the line, and who touched it.',
    routes: [
      { method: 'POST', path: '/v1/machinery/manifest' },
      { method: 'POST', path: '/v1/machinery/coverage' },
    ],
    plan: 'Cell',
    href: '/docs/assurance/machinery',
  },
  {
    slug: 'fleet',
    name: 'Fleet advisory (OEM, multi-site)',
    imageKey: 'card-engine-fleet',
    summary: 'One supplier advisory fanned out across every enrolled serial, matched by hash — never version-range arithmetic, never flattened into a boolean.',
    routes: [
      { method: 'POST', path: '/v1/fleet/advisory' },
      { method: 'GET', path: '/v1/fleet/machines' },
    ],
    plan: 'Cell',
    href: '/docs/assurance/fleet',
  },
  {
    slug: 'oem-register',
    name: 'OEM Article 14 register',
    imageKey: 'card-plan-register',
    summary: 'Both deadline clocks computed correctly, hash-chained ledger with verifiable export — the register itself, not a spreadsheet. Cases are not metered — no per-case cap or charge.',
    routes: [
      { method: 'GET', path: '/v1/register' },
      { method: 'GET', path: '/v1/cases' },
    ],
    plan: 'Register',
    href: '/docs/pricing',
  },
  {
    slug: 'insurer-evidence',
    name: 'Insurer / auditor evidence check',
    imageKey: 'solution-auditor-hero',
    summary: 'Declaration check, bundle re-verification, attestation verification — engineered as always-free, because the buyer or auditor is never the paying customer.',
    routes: [
      { method: 'POST', path: '/v1/machine/bundle/check' },
      { method: 'POST', path: '/v1/ledger/attest/verify' },
    ],
    plan: 'Free (not metered in code)',
    href: '/solutions/insurer-auditor',
  },
];

export default function ApplicationsPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 4.5rem' }}>
        <div className="shell">
          <span className="kicker">FIVE APPLICATIONS, EACH A REAL GATED ROUTE</span>
          <h1 style={{ maxWidth: '24ch' }}>What this actually does, by application</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            Not a roadmap slide — every card below names the exact <code>/v1</code> route it calls and the plan
            that gates it, cross-checked against <a href="/openapi.json">openapi.json</a>.
          </p>
          <VisualDiagram slug="applications-hero-five-real-routes" variant="dark" />
        </div>
      </section>

      <section className="section" id="applications-grid">
        <div className="shell">
          <h2 className="sr-only">The five applications</h2>
          <VisualDiagram slug="iso15066-safety-envelope-and-coverage-states" />
          <div className="tile-grid">
            {APPLICATIONS.map((appItem) => (
              <article className="tile" key={appItem.slug}>
                <RotatingImage slot={IMAGES[appItem.imageKey]} aspect="4/3" className="tile-media" />
                <span className="tile-badge">{appItem.plan}</span>
                <h3>{appItem.name}</h3>
                <p>{appItem.summary}</p>
                <p className="code-panel-label" style={{ margin: '0.6rem 0 0.3rem' }}>Real routes</p>
                <p style={{ fontSize: '0.82rem', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', color: 'var(--ink-soft)' }}>
                  {appItem.routes.map((r) => `${r.method} ${r.path}`).join('  ·  ')}
                </p>
                <a className="tile-link" href={appItem.href}>
                  <span className="tile-link-label">Read the engine guide</span>
                  <span className="tile-link-arrow" aria-hidden>→</span>
                </a>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-alt" id="application-diagrams">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Route &amp; entitlement diagrams</span>
            <h2>How each application maps to enforced routes and plans</h2>
          </div>
          {APPLICATION_VISUAL_SLUGS.map((vSlug) => (
            <VisualDiagram key={vSlug} slug={vSlug} />
          ))}
        </div>
      </section>

      <section className="final-cta">
        <div className="shell final-cta-inner">
          <div>
            <h2>Not sure which application fits?</h2>
            <p>Tell us what you are running and how many machines. No response time is promised.</p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href={SALES}>Contact NeuralBridge</a>
            <RepoLink path="" className="btn btn-outline">Browse the source</RepoLink>
          </div>
        </div>
      </section>
      <ImageryNote />
    </main>
  );
}
