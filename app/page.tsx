import { DEPLOY_BLOB, QUICKSTART, REPO, SALES, SRC } from './lib/links';
import structuredOffers from './lib/structured-offers.json';
import { PLATFORM_STATUS } from './lib/platformStatus';
import { SOLUTIONS } from './lib/solutions';
import { IMAGES } from './lib/images';
import AdvisoryCheckPlayground from './components/AdvisoryCheckPlayground';
import IntentModule from './components/IntentModule';
import PricingPlans from './components/PricingPlans';
import RotatingImage from './components/RotatingImage';
import ImageryNote from './components/ImageryNote';
import SizingCalculator from './components/SizingCalculator';
import ValidatorPlayground from './components/ValidatorPlayground';

const trustStrip = [
  {
    label: 'CRA Art. 14',
    title: 'Reg. (EU) 2024/2847',
    body: 'Applies since 11 Sep 2026. An actively exploited vulnerability means 24 hours to file an early warning.',
    imageKey: 'strip-cra-clock',
  },
  {
    label: 'Annex III 1.1.9',
    title: 'Machinery Reg. 2023/1230',
    body: 'Applies 20 Jan 2027. The machine must identify its safety-relevant software and record evidence of intervention.',
    imageKey: 'strip-machinery-annex',
  },
  {
    label: 'Ledger',
    title: 'Hash-chained evidence',
    body: 'A hash chain catches editing. A counter-signature over the ledger head catches deletion.',
    imageKey: 'strip-hash-chain',
  },
  {
    label: 'Airgap',
    title: 'Offline enrolment kit',
    body: 'Runs on the operator’s disk. The socket guard refuses every outbound connection, including DNS.',
    imageKey: 'strip-offline-kit',
  },
] as const;

const products = [
  {
    badge: 'Free',
    badgeClass: '',
    name: 'Validator',
    body: 'Article 14 draft validation, the ISO/TS 15066 separation calculator, manifest diff, advisory check, Declaration check, bundle re-verification, and attestation verification.',
    href: QUICKSTART,
    cta: 'Start free',
    imageKey: 'card-plan-validator',
  },
  {
    badge: '€390/mo',
    badgeClass: 'paid',
    name: 'Article 14 Register',
    body: 'The CRA register for one manufacturer: both deadline clocks computed correctly, hash-chained ledger with verifiable export. Cases are not metered — no per-case cap or charge.',
    href: '#pricing',
    cta: 'See pricing',
    imageKey: 'card-plan-register',
  },
  {
    badge: '€1,290/mo',
    badgeClass: 'paid',
    name: 'Cell',
    body: 'Everything in Register, plus machine safety verification, Annex III manifests and passports, fleet advisory fan-out, change-assurance cases, and counter-signed head attestation.',
    href: '#pricing',
    cta: 'See pricing',
    imageKey: 'card-plan-cell',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Machine safety verification',
    body: 'A recorded run checked against the declared safety envelope — separation, speed limit, workspace containment, stop characterisation, power-and-force — each with a worst margin, each able to answer unchecked.',
    href: `/docs/assurance/machine`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-machine-safety',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Machinery Annex III',
    body: 'What safety software is on the machine, who changed it, and which safety functions still have evidence that describes the machine as it is today.',
    href: `/docs/assurance/machinery`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-annex-iii',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Fleet advisory',
    body: 'One supplier advisory fanned out across every enrolled serial, matched by hash, then version, then name — never by version-range arithmetic, never flattened into a boolean.',
    href: `/docs/assurance/fleet`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-fleet',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Watch',
    body: 'Scheduled drift checks. Exit 0 quiet, 1 findings, 2 could not see — "I could not look" never shares an exit code with "nothing moved". Runs in your kit or cron; the hosted API does not run it.',
    href: `/docs/assurance/watch`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-watch',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Attest',
    body: 'A signature over the ledger head by a key the ledger’s operator does not hold. Only this catches a ledger that was quietly shortened.',
    href: `/docs/assurance/attest`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-attest',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Offline enrolment kit',
    body: 'Your ledger, your disk. No account, no API key, no upload. `kit check` lists every file a run would open and touches nothing.',
    href: `/docs/assurance/kit`,
    cta: 'Read the kit guide',
    imageKey: 'card-engine-kit',
  },
  {
    badge: 'API',
    badgeClass: 'source',
    name: 'Assurance API',
    body: 'FastAPI surface: plans and entitlements, the Article 14 register, machine verification, fleet and change assurance, Watch reports and hosted supplier feeds. `GET /v1/plans` returns the pricing table generated from the entitlements the software enforces. Self-host with uvicorn today.',
    href: `${SRC}/api`,
    cta: 'View source',
    imageKey: 'card-api-assurance',
  },
] as const;

// Offers and Products are emitted on the home page only (where the prices are shown), not on every
// route: /checkout/success, /assurance and /status are noindex and should carry no price markup.
// Prices are unvalidated launch list prices, monthly, and say so; tests/test_site_copy_parity.py
// pins the numbers and the period to billing/plans.py.
const structuredDataBlocks = [
  structuredOffers.softwareApplication,
  ...structuredOffers.products,
];

export default function IndustrialAutonomousAssuranceSite() {
  return (
    <main id="top">
      {structuredDataBlocks.map((block) => (
        <script
          key={`${block['@type']}-${'name' in block ? block.name : ''}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(block) }}
        />
      ))}
      {/* HERO */}
      <section className="hero">
        <div className="shell hero-grid">
          <div>
            <span className="kicker">Evidence infrastructure for machines whose software can hurt someone</span>
            <h1>A hash-chained record of what is on each machine, which checks were run against it, and when.</h1>
            <p className="hero-lead">
              CRA Article 14 gives you 24 hours to file after an actively exploited vulnerability. Machinery
              Regulation Annex III 1.1.9 requires the machine to identify safety-relevant software and record
              evidence of intervention. Software does not satisfy either for you. What a hash-chained record can do
              is let you evidence your own process, and show a reviewer which records stopped describing the machine.
            </p>
            <div className="hero-actions">
              <a className="btn btn-primary" href="#advisory-check">A change or advisory just landed — check it free</a>
              <a className="btn btn-outline" href={SALES}>Talk to sales</a>
              <a className="btn btn-outline" href="#pricing">See pricing</a>
            </div>
          </div>

          <div>
            <div className="hero-media-desktop" style={{ marginBottom: '1rem' }}>
              <RotatingImage
                slot={IMAGES['hero-hash-chained-cell']}
                aspect="16/9"
                priority
                sizes="(max-width: 900px) 100vw, 45vw"
                dots
                className="hero-media"
              />
            </div>
            <div className="hero-media-mobile" style={{ marginBottom: '1rem' }}>
              {(() => {
                const portrait = IMAGES['hero-hash-chained-cell'].portraitA;
                return portrait ? (
                  <div className="media-band hero-media" style={{ aspectRatio: '4/5' }}>
                    <RotatingImage slot={{ a: portrait }} aspect="4/5" priority sizes="100vw" />
                  </div>
                ) : null;
              })()}
            </div>
            <div className="hero-panel">
              <div className="hero-panel-title">Run it now, inside your plant, nothing uploaded</div>
              <div className="hero-code">{`pip install cryptography && export PYTHONPATH=src
python -m assurance kit init plant/
python -m assurance kit check plant/kit.json
python -m assurance kit run  plant/kit.json --out plant/out`}</div>
              <p className="hero-panel-note">
                Your ledger, your disk. No account, no API key, no upload. The run arms a guard over the process's
                socket layer and refuses every outbound connection, including name resolution.
              </p>
            </div>
          </div>
        </div>
        <svg className="hero-seam" viewBox="0 0 1440 60" preserveAspectRatio="none" aria-hidden="true">
          <path d="M0,60 C480,0 960,0 1440,60 L1440,60 L0,60 Z" fill="var(--surface-alt)" />
        </svg>
      </section>

      {/* SECOND HERO: offline kit */}
      <section className="hero" style={{ padding: '3rem 0' }}>
        <div className="shell hero-grid">
          <div>
            <div className="hero-media-desktop">
              <RotatingImage
                slot={IMAGES['hero-airgap-kit']}
                aspect="16/9"
                sizes="(max-width: 900px) 100vw, 45vw"
                dots
                className="hero-media"
              />
            </div>
            <div className="hero-media-mobile">
              {(() => {
                const portrait = IMAGES['hero-airgap-kit'].portraitA;
                return portrait ? (
                  <div className="media-band hero-media" style={{ aspectRatio: '4/5' }}>
                    <RotatingImage slot={{ a: portrait }} aspect="4/5" sizes="100vw" />
                  </div>
                ) : null;
              })()}
            </div>
          </div>
          <div>
            <span className="kicker">Offline enrolment kit</span>
            <h2 style={{ color: '#ffffff' }}>Your ledger, your disk. Nothing leaves the room.</h2>
            <p className="hero-lead">
              No account, no API key, no upload. <code>kit check</code> lists every file a run would open and
              touches nothing — the run arms a guard over the process's socket layer and refuses every outbound
              connection, including name resolution.
            </p>
            <div className="hero-actions">
              <a className="btn btn-outline" href="/docs/assurance/kit">
                Read the kit guide
              </a>
            </div>
            <a
              className="docs-preview-card"
              href="/docs/assurance/kit"
              style={{ marginTop: '1.25rem' }}
            >
              <RotatingImage slot={IMAGES['docs-offline-enrolment']} aspect="4/3" className="docs-preview-media" />
              <span>KIT.md — the full offline enrolment walkthrough</span>
            </a>
          </div>
        </div>
      </section>

      {/* TRUST STRIP */}
      <section className="trust-strip">
        <div className="shell trust-grid">
          {trustStrip.map((item, i) => (
            <div className="trust-item trust-item-media" key={item.title}>
              <RotatingImage
                slot={IMAGES[item.imageKey]}
                aspect="4/3"
                offsetMs={i * 1500}
                className="trust-item-image"
              />
              <div>
                <strong>{item.title}</strong>
                <span>{item.body}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* INTENT ROUTER */}
      <section className="section" id="intent">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Start here</span>
            <h2>Find your answer in one click.</h2>
            <p>
              Each output below is an excerpt of what the shipped command printed on this repository&apos;s synthetic
              example files (machine names and hashes are fixtures, not a customer&apos;s); a line shown as &hellip;
              was left out. <code>tests/test_site_honesty.py</code> re-runs each command and fails if a line shown is
              not in its output. Re-run the command shown to reproduce it.
            </p>
          </div>
          <IntentModule />
        </div>
      </section>

      {/* EXPLORE PRODUCTS */}
      <section className="section" id="products">
        <div className="shell">
          <div className="section-head" id="advisory-check">
            <span className="eyebrow">Start here — free, no account</span>
            <h2>Machine Assurance Check: a change landed. What does it mean for this machine?</h2>
            <p>
              This is the question the whole system exists to answer. Paste a supplier advisory and one machine&apos;s
              manifest below and run the real check &mdash; the same match logic that decides whether a hash is
              byte-identical, a version label is only a label, or the two disagree and neither column gets to claim
              this machine. An explicit verdict, never collapsed to safe-or-not: no impact found, potentially
              affected, or needs a human to look.
            </p>
          </div>

          <div className="hero-panel" style={{ marginBottom: '2rem' }}>
            <div className="hero-panel-title">Machine Assurance Check &mdash; try it right here</div>
            <AdvisoryCheckPlayground />
            <p className="hero-panel-note">
              This calls the real <code>POST /v1/check/machine</code> endpoint on one machine, free, no account.
              Enrolling the machine unlocks <code>POST /v1/check/fleet-machine</code>: the same check joined to its
              intervention history, its evidence staleness, and the fleet-wide fan-out across every other enrolled
              machine &mdash; the Cell plan.
            </p>
            <p className="hero-panel-note">
              Handed an evidence export, a machine verification bundle or a signed attestation log?{' '}
              <a href="/verify">Check what can and cannot be established from the file</a> &mdash; free, no account,
              nothing stored.
            </p>
          </div>

          <div className="section-head">
            <span className="eyebrow">Explore products</span>
            <h2>Plans, engines, and the API, in one place.</h2>
            <p>
              Every row below maps to code that runs. Nothing on this page is listed that the software does not do.
              Engine tiles link to the buyer-facing guide for that engine; plan tiles link to pricing.
            </p>
          </div>

          <div className="hero-panel" style={{ marginBottom: '2rem' }}>
            <div className="hero-panel-title">The free CRA Article 14 validator &mdash; try it right here</div>
            <ValidatorPlayground />
            <p className="hero-panel-note">
              This calls the real <code>POST /v1/spec/validate</code> endpoint: it reports missing required fields and
              listed territories that are not EU Member States (<strong>Switzerland is not an EU Member State</strong>)
              &mdash; a live regulatory check, not a mockup. See the pricing section for whether this route is hosted
              publicly right now.
            </p>
          </div>

          <div className="tile-grid">
            {products.map((product, i) => (
              <article className="tile" key={product.name}>
                <RotatingImage
                  slot={IMAGES[product.imageKey]}
                  aspect="4/3"
                  offsetMs={i * 900}
                  className="tile-media"
                />
                <span className={`tile-badge ${product.badgeClass}`}>{product.badge}</span>
                <h3>{product.name}</h3>
                <p>{product.body}</p>
                <a
                  className="tile-link"
                  href={product.href}
                  target={product.href.startsWith('http') ? '_blank' : undefined}
                  rel={product.href.startsWith('http') ? 'noreferrer' : undefined}
                >
                  <span className="tile-link-label">{product.cta}</span>
                  <span className="tile-link-arrow" aria-hidden>→</span>
                </a>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* SOLUTIONS BY BUYER */}
      <section className="section section-alt" id="solutions">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Solutions</span>
            <h2>Built for the people who sign, verify, or get blamed.</h2>
            <p>Five buyers, five reasons the paperwork stopped describing the machine.</p>
          </div>
          <div className="solutions-grid">
            {SOLUTIONS.map((solution) => (
              <a className="solution-card" href={`/solutions/${solution.slug}`} key={solution.slug}>
                <span className="solution-role">{solution.role}</span>
                <h3>{solution.headline}</h3>
                <p>{solution.lead}</p>
                <span className="tile-link" style={{ marginTop: '0.75rem' }}>
                  <span className="tile-link-label">See the {solution.role.toLowerCase()} page</span>
                  <span className="tile-link-arrow" aria-hidden>{'→'}</span>
                </span>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* PRICING */}
      <section className="section" id="pricing">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Pricing</span>
            <h2>Three tiers. Re-checking someone else&apos;s evidence needs no account.</h2>
            <p>
              If it is not gated in code, it is not on this page — <code>GET /v1/plans</code> returns this same
              table, generated from the entitlements the software enforces. Re-checking someone else&apos;s evidence
              needs no account. Declaration, evidence-bundle, passport and attestation checks are not metered.
              The file verifier (<code>POST /v1/evidence/verify</code>, and <code>/verify</code> on this site)
              allows 20 a day per address; manifest diff allows 10 a day.
              Register and Cell have no daily cap on either.
            </p>
          </div>

          <RotatingImage
            slot={IMAGES['pricing-three-tiers']}
            aspect="21/9"
            sizes="100vw"
            className="pricing-media"
          />

          <SizingCalculator />

          <PricingPlans />

          <div className="compare-table-wrap">
            <table className="compare-table">
              <thead>
                <tr>
                  <th>Capability</th>
                  <th>Validator</th>
                  <th>Register</th>
                  <th>Cell</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Free verification (Declaration, manifest, attestation)</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Article 14 draft validation &amp; calculators</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Offline enrolment kit</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>/ai control plane — discover + read (30/day)</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>/ai control plane — propose-and-approve writes, bind connections, an in-memory audit log for your account</td>
                  <td>—</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Article 14 register (both clocks; cases are not metered)</td>
                  <td>—</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Hash-chained ledger with verifiable export</td>
                  <td>—</td>
                  <td className="check">✓</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Machine safety verification</td>
                  <td>—</td>
                  <td>—</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Annex III manifests &amp; passports</td>
                  <td>—</td>
                  <td>—</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Fleet advisory fan-out</td>
                  <td>—</td>
                  <td>—</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Change-assurance cases (<code>/v1/change/*</code>; closure is a named human decision; a validated verification needs a recorder attestation accepted under a trust list the operator configures, none is configured in a default deployment, so a required re-verification is closed in practice by a named person&apos;s waiver)</td>
                  <td>—</td>
                  <td>—</td>
                  <td className="check">✓</td>
                </tr>
                <tr>
                  <td>Counter-signed head attestation</td>
                  <td>—</td>
                  <td>—</td>
                  <td className="check">✓</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="pricing-note">
            The plan cards above render live from <code>GET /v1/plans</code> when this page can reach a deployed
            API, and fall back to this static table (identical data) otherwise &mdash; that is the honest state
            right now: the billing API is real and tested (<code>POST /v1/checkout</code> refuses a payment it
            cannot provision rather than faking one, and every register route fails closed with no API keys
            configured), but it is not deployed to a public endpoint. Deploying it needs outbound access to Fly.io
            from wherever runs <code>fly deploy</code>, plus live Stripe keys &mdash; neither is available in the
            environment that built this page. See{' '}
            <a href={`${REPO}/blob/main/src/assurance/api/billing_routes.py`} target="_blank" rel="noreferrer">the billing routes</a>{' '}
            and <a href="/docs/assurance/deploy">the deploy guide</a> for the exact
            remaining steps.
          </p>
          <p className="pricing-note">
            The prices (&euro;390 and &euro;1,290 a month) are launch hypotheses. They have not been validated
            with paying customers, and nothing on this page claims otherwise. Watch (the scheduled drift check)
            runs in your own kit or cron &mdash; the hosted API serves cases, it does not run a scheduler for you.
          </p>
        </div>
      </section>

      {/* PLATFORM UNDERNEATH */}
      <section className="section section-alt" id="platform">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">The platform underneath</span>
            <h2>NeuralBridge: the integration layer the assurance product is built on.</h2>
            <p>
              A lightweight integration hub: a FastAPI backend, an MCP gateway for AI tool exposure, a small set of
              adapters (supported scope intended, see the table), and a dashboard. It is intentionally narrower than
              it once claimed to be. The rows below are the README&apos;s own table, word for word.
            </p>
          </div>
          <RotatingImage
            slot={IMAGES['platform-integration-hub']}
            aspect="21/9"
            sizes="100vw"
            className="pricing-media"
          />
          <div className="status-table-wrap">
            <table className="status-table">
              <thead>
                <tr>
                  <th>Area</th>
                  <th>Current status</th>
                </tr>
              </thead>
              <tbody>
                {PLATFORM_STATUS.map((row) => (
                  <tr key={row.area}>
                    <td>
                      {row.area}
                      {row.note ? <span className="status-note">{row.note}</span> : null}
                    </td>
                    <td>
                      <span className={`status-pill ${row.pill}`}>{row.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="pricing-note">
            Full detail, including what is <em>not</em> yet claimed, is in{' '}
            <a href={`${REPO}#neuralbridge--the-platform-underneath`} target="_blank" rel="noreferrer">
              the README
            </a>.
          </p>
        </div>
      </section>

      {/* FINAL CTA */}
      <section className="final-cta" id="connect">
        <div className="shell final-cta-inner">
          <div>
            <h2>Re-check one Declaration for free. See what your paperwork stopped describing.</h2>
            <p>
              The free checks need no account. The offline kit needs no account, key or upload and opens no sockets.
              The hosted API is not deployed to a public endpoint yet: run the same code locally from the quickstart.
            </p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href={QUICKSTART}>
              Get the quickstart
            </a>
            <a className="btn btn-outline" href="/verify">
              Check an evidence file
            </a>
            <a className="btn btn-outline" href={SALES}>
              Talk to sales
            </a>
          </div>
        </div>
      </section>
      <ImageryNote />
    </main>
  );
}
