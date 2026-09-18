import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { SOLUTIONS, getSolution } from '../../lib/solutions';

export function generateStaticParams() {
  return SOLUTIONS.map((s) => ({ slug: s.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }): Metadata {
  const solution = getSolution(params.slug);
  if (!solution) return {};
  return {
    title: `${solution.role} | Industrial Autonomous Assurance`,
    description: solution.headline,
  };
}

export default function SolutionPage({ params }: { params: { slug: string } }) {
  const solution = getSolution(params.slug);
  if (!solution) notFound();

  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 4.5rem' }}>
        <div className="shell">
          <span className="kicker">{solution.kicker}</span>
          <h1 style={{ maxWidth: '20ch' }}>{solution.headline}</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>{solution.lead}</p>
          <div className="hero-actions">
            <a
              className="btn btn-primary"
              href={solution.primaryCta.href}
              target={solution.primaryCta.external ? '_blank' : undefined}
              rel={solution.primaryCta.external ? 'noreferrer' : undefined}
            >
              {solution.primaryCta.label}
            </a>
            <a
              className="btn btn-outline"
              href={solution.secondaryCta.href}
              target={solution.secondaryCta.external ? '_blank' : undefined}
              rel={solution.secondaryCta.external ? 'noreferrer' : undefined}
            >
              {solution.secondaryCta.label}
            </a>
          </div>
        </div>
        <svg className="hero-seam" viewBox="0 0 1440 60" preserveAspectRatio="none" aria-hidden="true">
          <path d="M0,60 C480,0 960,0 1440,60 L1440,60 L0,60 Z" fill="var(--surface-alt)" />
        </svg>
      </section>

      <section className="trust-strip">
        <div className="shell">
          <div className="trust-item" style={{ maxWidth: '80ch' }}>
            <span className="trust-icon">{'⏱'}</span>
            <div>
              <strong>The clocks that apply to you</strong>
              <span>{solution.clockAngle}</span>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="pain-points">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Why this matters for {solution.role.toLowerCase()}s</span>
            <h2>What the paperwork stops telling you</h2>
          </div>
          <div className="solutions-grid">
            {solution.painPoints.map((p) => (
              <article className="solution-card" key={p.title}>
                <h3>{p.title}</h3>
                <p>{p.body}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section section-alt" id="proof">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">What this checks</span>
            <h2>Proof, not a pitch</h2>
          </div>
          <div className="tile-grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
            {solution.proof.map((item) => (
              <article className="tile" key={item.title}>
                <h3>{item.title}</h3>
                <p>{item.body}</p>
                <a
                  className="tile-link"
                  href={item.href}
                  target={item.external ? '_blank' : undefined}
                  rel={item.external ? 'noreferrer' : undefined}
                >
                  <span className="tile-link-label">Read more</span>
                  <span className="tile-link-arrow" aria-hidden>{'→'}</span>
                </a>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="final-cta">
        <div className="shell final-cta-inner">
          <div>
            <h2>{solution.headline}</h2>
            <p>Verification stays free, forever, at every tier. Start there.</p>
          </div>
          <div className="hero-actions">
            <a
              className="btn btn-primary"
              href={solution.primaryCta.href}
              target={solution.primaryCta.external ? '_blank' : undefined}
              rel={solution.primaryCta.external ? 'noreferrer' : undefined}
            >
              {solution.primaryCta.label}
            </a>
            <a
              className="btn btn-outline"
              href={solution.secondaryCta.href}
              target={solution.secondaryCta.external ? '_blank' : undefined}
              rel={solution.secondaryCta.external ? 'noreferrer' : undefined}
            >
              {solution.secondaryCta.label}
            </a>
          </div>
        </div>
      </section>
    </main>
  );
}
