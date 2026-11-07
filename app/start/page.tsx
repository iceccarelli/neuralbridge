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
          <h1>From a first visit to ongoing assurance</h1>
          <p>
            Nine steps, from a first visit to ongoing assurance. Each says what exists today, where it runs, and what is not available. Nothing below is a
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
          <section className="note-box" aria-labelledby="glance-h" data-testid="start-glance">
            <h2 id="glance-h" style={{ margin: '0 0 0.5rem', fontSize: 'var(--fs-lg)' }}>
              At a glance
            </h2>
            <dl className="glance">
              <dt>What it does</dt>
              <dd>
                Records what safety-relevant software and configuration is on each industrial machine, which
                verification covered which configuration, and when that stopped being true.
              </dd>
              <dt>Who uses it</dt>
              <dd>
                Machine manufacturers, system integrators and plant operators, plus the product-security people who
                handle CRA Article 14 reports.
              </dd>
              <dt>The problem</dt>
              <dd>
                A software change or a new vulnerability advisory arrives and nobody can say which machines it
                touches or whether the last verification still applies.
              </dd>
              <dt>What it needs from you</dt>
              <dd>
                A list of machines, the safety software on each (hashes read from the machine where possible), and
                existing verification records. Nothing is read from your machines for you.
              </dd>
              <dt>What it produces</dt>
              <dd>
                Sealed manifests, coverage reports, change-assurance cases, passports and exports that anyone can
                re-verify offline.
              </dd>
              <dt>Free or offline today</dt>
              <dd>The offline kit and the evidence checks run on your machine with no account and no network.</dd>
              <dt>Needs a paid plan</dt>
              <dd>
                Register (Art. 14 workflow, evidence records) and Cell (machine verification, passports, fleet
                advisories, change assurance). Neither can be bought on this site; both are agreed by conversation.
              </dd>
              <dt>Not available</dt>
              <dd>
                Self-serve sign-up and checkout, a public hosted API, hosted monitoring, any certification, and any
                statement that a machine is compliant or safe.
              </dd>
              <dt>Stays with you</dt>
              <dd>
                Declaring each machine, reading hashes from it, deciding awareness, reportability and every case, and
                holding your keys. The software drafts; named people decide.
              </dd>
              <dt>Dates</dt>
              <dd>
                CRA Article 14 reporting applies from 11 September 2026; Machinery Regulation (EU) 2023/1230 applies
                from 20 January 2027.
              </dd>
            </dl>
          </section>

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
