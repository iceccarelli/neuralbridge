import type { Metadata } from 'next';
import Inline from '../components/Inline';
import { buildMetadata } from '../lib/seo';
import { journeySteps, TAG_CLASS } from '../lib/journey';
import { HOSTED_API } from '../lib/hostedApi';
import { SALES } from '../lib/links';

export const metadata: Metadata = buildMetadata({
  title: 'Get started',
  description:
    'The path from reading about Industrial Autonomous Assurance to an enrolled machine, with what runs offline, what needs a hosted API and what is by request.',
  path: '/start',
});

export default function StartPage() {
  const steps = journeySteps();
  return (
    <main id="top">
      <section className="page-hero">
        <div className="shell">
          <span className="kicker">Get started</span>
          <h1>From reading to your first enrolled machine</h1>
          <p>
            Six steps. Each says what exists today, where it runs, and what is not available. Nothing below is a
            roadmap item presented as a feature.
          </p>
          <ul className="toc" aria-label="Steps">
            {steps.map((step) => (
              <li key={step.id}>
                <a href={`#${step.id}`}>{step.title}</a>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="section">
        <div className="shell">
          <div className="note-box">
            <p>
              <strong>What the labels mean.</strong>{' '}
              <span className="tag is-live">live</span> exists and works as described.{' '}
              <span className="tag is-offline">offline</span> runs on your own machine and opens no socket.{' '}
              <span className="tag is-gap">by request / needs an API</span> goes through a conversation with
              NeuralBridge, or needs a deployed API and key. <span className="tag is-none">not available</span> does
              not exist today.
            </p>
            <p>
              {HOSTED_API
                ? 'This build of the site is connected to a hosted Assurance API.'
                : 'This build of the site is not connected to a hosted Assurance API, and none is deployed to a public endpoint. Pages that would call one say so before you click.'}
            </p>
          </div>

          <ol className="journey">
            {steps.map((step) => (
              <li key={step.id} id={step.id} style={{ scrollMarginTop: '8rem' }}>
                <div>
                  <h2 style={{ margin: '0 0 0.35rem', fontSize: 'var(--fs-lg)' }}>{step.title}</h2>
                  {step.detail.map((paragraph) => (
                    <p key={paragraph}>
                      <Inline text={paragraph} />
                    </p>
                  ))}
                  {step.code && <pre className="code-panel" tabIndex={0}>{step.code}</pre>}
                  <div className="j-links">
                    {step.links.map((link) => (
                      <a key={link.href + link.label} href={link.href}>{link.label}</a>
                    ))}
                  </div>
                </div>
                <div className="j-state">
                  {step.tags.map((tag) => (
                    <span className={`tag ${TAG_CLASS[tag.state]}`} key={tag.label}>
                      {tag.label}
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ol>

          <div className="note-box">
            <p>
              <strong>Not sure where you fit?</strong> Start from your role on the <a href="/#roles">home page</a>, or
              read what is stored where on the <a href="/trust">trust page</a>. If you want help doing any of this, the{' '}
              <a href="/services">services page</a> says what could be offered, what exists to support it today, and
              that no capacity or price is offered.
            </p>
            <p>
              For anything that is not self-serve, <a href={SALES}>contact NeuralBridge</a>.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
