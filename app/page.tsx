import { DEPLOY_BLOB, QUICKSTART, REPO, SALES, SRC } from './lib/links';
import PricingPlans from './components/PricingPlans';
import SizingCalculator from './components/SizingCalculator';
import ValidatorPlayground from './components/ValidatorPlayground';

const trustStrip = [
  {
    label: 'CRA Art. 14',
    title: 'Reg. (EU) 2024/2847',
    body: 'Applies since 11 Sep 2026. An actively exploited vulnerability means 24 hours to file an early warning.',
  },
  {
    label: 'Annex III 1.1.9',
    title: 'Machinery Reg. 2023/1230',
    body: 'Applies 20 Jan 2027. The machine must identify its safety-relevant software and record evidence of intervention.',
  },
  {
    label: 'Ledger',
    title: 'Hash-chained evidence',
    body: 'A hash chain catches editing. A counter-signature over the ledger head catches deletion.',
  },
  {
    label: 'Airgap',
    title: 'Offline enrolment kit',
    body: 'Runs on the operator’s disk. The socket guard refuses every outbound connection, including DNS.',
  },
];

const products = [
  {
    badge: 'Free',
    badgeClass: '',
    name: 'Validator',
    body: 'Article 14 draft validation, the ISO/TS 15066 separation calculator, manifest diff, advisory check, Declaration check, bundle re-verification, and attestation verification.',
    href: '#pricing',
    cta: 'Start free',
  },
  {
    badge: '€390/mo',
    badgeClass: 'paid',
    name: 'Article 14 Register',
    body: 'The CRA register for one manufacturer: unlimited cases, both deadline clocks computed correctly, hash-chained ledger with verifiable export, 25 product families.',
    href: '#pricing',
    cta: 'See pricing',
  },
  {
    badge: '€1,290/mo',
    badgeClass: 'paid',
    name: 'Cell',
    body: 'Everything in Register, plus machine safety verification, Annex III manifests and passports, fleet advisory fan-out, and counter-signed head attestation.',
    href: '#pricing',
    cta: 'See pricing',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Machine safety verification',
    body: 'A recorded run checked against the declared safety envelope — separation, speed limit, workspace containment, stop characterisation, power-and-force — each with a worst margin, each able to answer unchecked.',
    href: `${DEPLOY_BLOB}/MACHINE.md`,
    cta: 'Read the engine guide',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Machinery Annex III',
    body: 'What safety software is on the machine, who changed it, and which safety functions still have evidence that describes the machine as it is today.',
    href: `${DEPLOY_BLOB}/MACHINERY.md`,
    cta: 'Read the engine guide',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Fleet advisory',
    body: 'One supplier advisory fanned out across every enrolled serial, matched by hash, then version, then name — never by version-range arithmetic, never flattened into a boolean.',
    href: `${DEPLOY_BLOB}/FLEET.md`,
    cta: 'Read the engine guide',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Watch',
    body: 'The component that runs when nobody is looking. Exit 0 quiet, 1 findings, 2 could not see — "I could not look" never shares an exit code with "nothing moved".',
    href: `${DEPLOY_BLOB}/WATCH.md`,
    cta: 'Read the engine guide',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Attest',
    body: 'A signature over the ledger head by a key the ledger’s operator does not hold. Only this catches a ledger that was quietly shortened.',
    href: `${DEPLOY_BLOB}/ATTEST.md`,
    cta: 'Read the engine guide',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Offline enrolment kit',
    body: 'Your ledger, your disk. No account, no API key, no upload. `kit check` lists every file a run would open and touches nothing.',
    href: `${DEPLOY_BLOB}/KIT.md`,
    cta: 'Read the kit guide',
  },
  {
    badge: 'API',
    badgeClass: 'source',
    name: 'Assurance API',
    body: 'FastAPI surface for billing and entitlements. `GET /v1/plans` returns the pricing table generated from the entitlements the software enforces. Self-host with uvicorn today.',
    href: `${SRC}/api`,
    cta: 'View source',
  },
];

const solutions = [
  {
    role: 'Manufacturer',
    body: 'Bind a Declaration of Conformity to a configuration hash. The moment it stops matching the machine on the floor becomes a date, not an argument.',
  },
  {
    role: 'Plant operator',
    body: 'Verify the safety-relevant software actually on a cell before you take the blame for a firmware change nobody told you about.',
  },
  {
    role: 'Compliance officer',
    body: 'File Article 14 within the 24-hour clock, with awareness records and the reasoning that defends the filing — both deadline clocks computed correctly.',
  },
  {
    role: 'Insurer / auditor',
    body: 'Check a Declaration, a manifest, or an attestation for free, forever. The person who most needs to verify evidence is never the one paying for it.',
  },
  {
    role: 'AI / ops platform team',
    body: 'Layer the NeuralBridge MCP gateway underneath to expose supported adapters and connection state to agents, with a full audit trail.',
  },
];

const platformStatus = [
  { area: 'FastAPI backend', status: 'Supported' },
  { area: 'Connection management model', status: 'Supported' },
  { area: 'MCP tool listing / invocation', status: 'Supported' },
  { area: 'Dashboard foundation', status: 'Supported' },
  { area: 'Basic audit trail', status: 'Supported' },
  { area: 'Small set of working adapters (PostgreSQL, REST)', status: 'Supported' },
  { area: 'Broad adapter ecosystem', status: 'Evolving' },
  { area: 'Full enterprise compliance posture', status: 'Evolving' },
];

export default function IndustrialAutonomousAssuranceSite() {
  return (
    <main id="top">
      {/* HERO */}
      <section className="hero">
        <div className="shell hero-grid">
          <div>
            <span className="kicker">Evidence infrastructure for machines whose software can hurt someone</span>
            <h1>A hash-chained record of what is on each machine, what was verified, and when.</h1>
            <p className="hero-lead">
              CRA Article 14 gives you 24 hours to file after an actively exploited vulnerability. Machinery
              Regulation Annex III 1.1.9 requires you to identify safety-relevant software and record evidence of
              intervention. Neither is satisfiable from a spreadsheet. This is built from the record instead.
            </p>
            <div className="hero-actions">
              <a className="btn btn-primary" href="#pricing">Start free — Validator</a>
              <a className="btn btn-outline" href={SALES} target="_blank" rel="noreferrer">Talk to sales</a>
              <a className="btn btn-outline" href="#pricing">See pricing</a>
            </div>
          </div>

          <div className="hero-panel">
            <div className="hero-panel-title">Run it now, inside your plant, nothing uploaded</div>
            <div className="hero-code">{`pip install -e '.[assurance-attest]'
python -m assurance kit init plant/
python -m assurance kit check plant/kit.json
python -m assurance kit run  plant/kit.json --out plant/out`}</div>
            <p className="hero-panel-note">
              Your ledger, your disk. No account, no API key, no upload. The run arms a guard over the process's
              socket layer and refuses every outbound connection, including name resolution.
            </p>
          </div>
        </div>
        <svg className="hero-seam" viewBox="0 0 1440 60" preserveAspectRatio="none" aria-hidden="true">
          <path d="M0,60 C480,0 960,0 1440,60 L1440,60 L0,60 Z" fill="var(--surface-alt)" />
        </svg>
      </section>

      {/* TRUST STRIP */}
      <section className="trust-strip">
        <div className="shell trust-grid">
          {trustStrip.map((item) => (
            <div className="trust-item" key={item.title}>
              <span className="trust-icon">{item.label.slice(0, 2)}</span>
              <div>
                <strong>{item.title}</strong>
                <span>{item.body}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* EXPLORE PRODUCTS */}
      <section className="section" id="products">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Explore products</span>
            <h2>Plans, engines, and the API, in one place.</h2>
            <p>
              Every row below maps to code that runs. Nothing on this page is listed that the software does not do.
              Engine tiles link to the buyer-facing guide for that engine; plan tiles link to pricing.
            </p>
          </div>

          <div className="hero-panel" style={{ marginBottom: '2rem' }}>
            <div className="hero-panel-title">The free validator &mdash; try it right here</div>
            <ValidatorPlayground />
            <p className="hero-panel-note">
              This calls the real <code>POST /v1/spec/validate</code> endpoint. A prior run against this exact
              service flagged five missing required fields and that <strong>Switzerland is not an EU Member
              State</strong> &mdash; a live regulatory check, not a mockup. See the pricing section for whether this
              route is hosted publicly right now.
            </p>
          </div>

          <div className="tile-grid">
            {products.map((product) => (
              <article className="tile" key={product.name}>
                <span className={`tile-badge ${product.badgeClass}`}>{product.badge}</span>
                <h3>{product.name}</h3>
                <p>{product.body}</p>
                <a
                  className="tile-link"
                  href={product.href}
                  target={product.href.startsWith('#') ? undefined : '_blank'}
                  rel={product.href.startsWith('#') ? undefined : 'noreferrer'}
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
            {solutions.map((solution) => (
              <article className="solution-card" key={solution.role}>
                <span className="solution-role">{solution.role}</span>
                <h3>{solution.body.split('.')[0]}.</h3>
                <p>{solution.body}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* PRICING */}
      <section className="section" id="pricing">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Pricing</span>
            <h2>Three tiers. Verification is free at every one, always.</h2>
            <p>
              Assurance tiers are computed from the weakest input, never passed in. If it is not gated in code, it is
              not on this page — <code>GET /v1/plans</code> returns this same table, generated from the
              entitlements the software enforces.
            </p>
          </div>

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
                  <td>Article 14 register (unlimited cases, both clocks)</td>
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
            and <a href={`${DEPLOY_BLOB}/README.md`} target="_blank" rel="noreferrer">the deploy guide</a> for the exact
            remaining steps.
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
              supported adapters, and a dashboard. It is intentionally narrower than it once claimed to be.
            </p>
          </div>
          <div className="status-table-wrap">
            <table className="status-table">
              <thead>
                <tr>
                  <th>Area</th>
                  <th>Current status</th>
                </tr>
              </thead>
              <tbody>
                {platformStatus.map((row) => (
                  <tr key={row.area}>
                    <td>{row.area}</td>
                    <td>
                      <span className={`status-pill ${row.status === 'Supported' ? 'supported' : 'evolving'}`}>
                        {row.status}
                      </span>
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
            <h2>Verify one Declaration for free. See what your paperwork stopped describing.</h2>
            <p>No account, no upload, no procurement cycle to start. The Validator tier runs on your machine today.</p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href={QUICKSTART} target="_blank" rel="noreferrer">
              Get the quickstart
            </a>
            <a className="btn btn-outline" href={SALES} target="_blank" rel="noreferrer">
              Talk to sales
            </a>
          </div>
        </div>
      </section>
    </main>
  );
}
