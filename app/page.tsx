import type { Metadata } from 'next';
import RepoLink from './components/RepoLink';
import { ownerLink, QUICKSTART, repoSameAs, SALES, srcLink } from './lib/links';
import structuredOffers from './lib/structured-offers.json';
import { PLATFORM_STATUS } from './lib/platformStatus';
import { PRODUCT_PAGES, productHref } from './lib/productPages';
import { journeySteps, TAG_CLASS } from './lib/journey';
import { buildMetadata } from './lib/seo';
import { IMAGES } from './lib/images';
import { HOSTED_API } from './lib/hostedApi';
import AdvisoryCheckPlayground from './components/AdvisoryCheckPlayground';
import IntentModule from './components/IntentModule';
import PricingPlans from './components/PricingPlans';
import RotatingImage from './components/RotatingImage';
import ImageryNote from './components/ImageryNote';
import VisualDiagram from './components/VisualDiagram';
import SizingCalculator from './components/SizingCalculator';
import ValidatorPlayground from './components/ValidatorPlayground';

export const metadata: Metadata = buildMetadata({
  title: 'NeuralBridge | Industrial Autonomous Assurance',
  absoluteTitle: true,
  description:
    'NeuralBridge builds Industrial Autonomous Assurance: tamper-evident records that show when a machine\u2019s safety software no longer matches its verification.',
  path: '/',
});

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
    body: 'Applies 20 Jan 2027. The machine must identify the software it needs to operate safely and collect evidence of intervention in, or modification of, that software or its configuration.',
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
    cta: 'Read the quickstart',
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
    body: 'What safety software is on the machine, who changed it, and which safety functions have a recorded verification dated after the last recorded change.',
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
    name: 'Change assurance',
    body: 'A manifest drift, an advisory or an intervention becomes a case with an owner and a required re-verification. Closing, rejecting, deferring or resuming it is a named person’s decision; software drafts.',
    href: `/docs/assurance/change`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-fleet',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Public-source intelligence',
    body: 'KEV, NVD, EPSS and CSAF files recorded as provenance-stamped observations by an operator command; the hosted routes and MCP tools only read that store and answer 503 until the operator configures one. A CVE no source mentions is unknown, never clear.',
    href: `/docs/assurance/intel`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-watch',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Watch',
    body: 'Scheduled drift checks, optionally reading the operator’s intel store with a maximum age. Exit 0 quiet, 1 findings, 2 could not see — "I could not look" never shares an exit code with "nothing moved". Runs in your kit or cron; the hosted API does not run it.',
    href: `/docs/assurance/watch`,
    cta: 'Read the engine guide',
    imageKey: 'card-engine-watch',
  },
  {
    badge: 'Engine',
    badgeClass: 'source',
    name: 'Attest',
    body: 'A signature over the ledger head by a key the ledger’s operator does not hold. Only this catches a ledger that was quietly shortened. Key and trust-file tooling runs on the operator’s own machine.',
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
    body: 'FastAPI surface: plans and entitlements, the Article 14 register, machine verification, fleet and change assurance, Watch reports, read-only public-source intelligence (503 until the operator configures a store) and hosted supplier feeds. `GET /v1/plans` returns the pricing table generated from the entitlements the software enforces. Self-host with uvicorn today.',
    href: srcLink('/api') ?? '/developers',
    cta: srcLink('/api') ? 'View source' : 'Read the API reference',
    imageKey: 'card-api-assurance',
  },
] as const;


const ROLES = [
  {
    name: 'Manufacturer',
    line: 'Your Declaration of Conformity describes the machine as it was the day you signed it.',
    href: '/solutions/manufacturer',
    go: 'Manufacturer page',
  },
  {
    name: 'System integrator',
    line: 'You change safety software on site. Leave a record the customer and the manufacturer can check.',
    href: '/solutions/system-integrator',
    go: 'Integrator page',
  },
  {
    name: 'Plant operator',
    line: 'You did not change the firmware, and you will still be asked to explain what did.',
    href: '/solutions/plant-operator',
    go: 'Operator page',
  },
  {
    name: 'Safety / compliance engineer',
    line: 'Awareness, the two clocks and the reasoning behind a filing, in a record you can defend.',
    href: '/solutions/compliance-officer',
    go: 'Compliance page',
  },
  {
    name: 'Auditor or insurer',
    line: 'Check someone else’s evidence without an account, and see what the check cannot establish.',
    href: '/solutions/insurer-auditor',
    go: 'Auditor page',
  },
  {
    name: 'Developer',
    line: 'One domain function behind the CLI, the HTTP API and MCP. Routes, auth and what is not exposed, by design.',
    href: '/developers',
    go: 'Developer docs',
  },
] as const;

// Offers and Products are emitted on the home page only (where the prices are shown), not on every
// route: /checkout/success and /assurance are noindex and should carry no price markup.
// Prices are unvalidated launch list prices, monthly, and say so; tests/test_site_copy_parity.py
// pins the numbers and the period to billing/plans.py.
// The owner profile and repository URLs are added only when REPO_PUBLIC (lib/links.ts) is true.
function withRepoLinks<T extends { creator: object }>(app: T) {
  const owner = ownerLink();
  return {
    ...app,
    creator: owner ? { ...app.creator, url: owner } : app.creator,
    ...(repoSameAs().length ? { sameAs: repoSameAs() } : {}),
  };
}

const structuredDataBlocks = [
  withRepoLinks(structuredOffers.softwareApplication),
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
      {/* HERO: what it is, for whom, in one screen */}
      <section className="hero" aria-labelledby="home-title">
        <div className="shell hero-grid">
          <div>
            <span className="kicker">NeuralBridge &middot; Industrial Autonomous Assurance</span>
            <h1 id="home-title">Know the day your safety evidence stops describing the machine.</h1>
            <p className="hero-lead">
              NeuralBridge builds Industrial Autonomous Assurance: a tamper-evident record that ties each safety
              verification to the exact software and configuration it covered. When a firmware patch, a parameter
              change or a supplier advisory lands, it shows which machines and which safety functions are affected,
              and who has to decide what happens next.
            </p>
            <div className="hero-actions">
              <a className="btn btn-primary" href="/start">
                Get started: the path from reading to your first machine
              </a>
              <a className="btn btn-outline" href={productHref('industrial-autonomous-assurance')}>
                How the product works
              </a>
            </div>
            <p className="statement-note">
              <strong>NeuralBridge is the company and platform; Industrial Autonomous Assurance is its flagship product.</strong>{' '}
              Today the CLI and offline kit run on your own machine from a source copy NeuralBridge supplies;{' '}
              {HOSTED_API
                ? 'a hosted API is connected to this site; '
                : 'no hosted API is deployed publicly; '}
              Register and Cell are sales-assisted. <a href="/start" style={{ color: '#ffffff', textDecoration: 'underline' }}>See what is available, step by step</a>.
            </p>
          </div>

          <div>
            <ol className="flow" aria-label="How a change becomes evidence">
              <li>
                <strong>A baseline is sealed</strong>
                The machine&apos;s safety software and configuration, declared by a named person, each item marked as
                read from the machine, supplied by the vendor, or declared.
              </li>
              <li>
                <strong>Something changes</strong>
                A firmware or safety-program change, an intervention, or a supplier advisory naming a component.
              </li>
              <li>
                <strong>It is compared by hash</strong>
                Against the baseline, then version, then name. A label that disagrees with the bytes is reported, not
                smoothed over.
              </li>
              <li>
                <strong>A case names what is unproven</strong>
                Which machines, which safety functions, an owner, and a required re-verification.
              </li>
              <li>
                <strong>A named person decides</strong>
                Close, reject or defer. Software drafts; it does not decide, and an AI never decides a safety
                conclusion.
              </li>
              <li>
                <strong>Every step is chained</strong>
                Each record is sealed to the one before it, and the head can be counter-signed by a key the ledger&apos;s
                operator does not hold.
              </li>
            </ol>
            <p className="flow-caption">The design, drawn as a list. Not a screenshot; nothing here is live data.</p>
          </div>
        </div>
        <div className="shell" style={{ marginTop: '2.25rem' }}>
          <VisualDiagram slug="hero-cryptographic-machine-assurance" variant="dark" />
        </div>
        <svg className="hero-seam" viewBox="0 0 1440 60" preserveAspectRatio="none" aria-hidden="true">
          <path d="M0,60 C480,0 960,0 1440,60 L1440,60 L0,60 Z" fill="var(--surface)" />
        </svg>
      </section>

      {/* THE PROBLEM */}
      <section className="section" id="problem">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">The problem</span>
            <h2>Safety evidence is true of one configuration. Machines do not stay in one.</h2>
            <p>
              A verification, a risk assessment and a Declaration of Conformity each describe the machine as it was on a
              day. Service calls, patches and re-zoned scanners move it off that day, and nothing in a document
              folder says so.
            </p>
          </div>
          <VisualDiagram slug="silent-drift-broken-declaration-of-conformity" />
          <ul className="ruled">
            <li>
              <h3>Changes silently invalidate evidence</h3>
              <div>
                <p>
                  A safety-controller update or a PLC project patch can leave the paperwork reading as current while
                  it no longer describes the machine. The plant is the one asked to explain it.
                </p>
                <p>
                  <strong>Designed answer:</strong> bind each verification to a configuration hash, so the date a
                  safety function&apos;s evidence stopped applying is a recorded fact, not an argument.
                </p>
              </div>
            </li>
            <li>
              <h3>Advisories name products; you operate serial numbers</h3>
              <div>
                <p>
                  A supplier advisory names a component and a version range. Finding which machines in a fleet run
                  the affected artefact is a join nobody does by hand under time pressure, and a version label can
                  disagree with the bytes on the controller.
                </p>
                <p>
                  <strong>Designed answer:</strong> fan one advisory out across every enrolled machine, matched by
                  hash, then version, then name, with a distinct answer when the evidence is missing.
                </p>
              </div>
            </li>
            <li>
              <h3>Regulators ask for a traceable record</h3>
              <div>
                <p>
                  CRA Article 14 (Reg. (EU) 2024/2847, applying since 11 Sep 2026) gives a manufacturer 24 hours from
                  awareness of an actively exploited vulnerability to file an early warning. Machinery Regulation
                  Annex III 1.1.9 (2023/1230, applying 20 Jan 2027) requires evidence of intervention in the safety
                  software or its configuration.
                </p>
                <p>
                  <strong>Designed answer:</strong> a hash-chained record of your own process. Software does not
                  satisfy either regulation for you; people decide and file.
                </p>
              </div>
            </li>
          </ul>
        </div>
      </section>

      {/* WHY NOT WHAT YOU HAVE */}
      <section className="section section-alt" id="why-not">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Why not what you already have</span>
            <h2>The tools you have answer other questions.</h2>
            <p>
              These are descriptions of three categories of tool, not comparisons with named products. Each does its
              own job well enough; none is built to say whether a verification still covers the machine in front of you.
            </p>
          </div>
          <VisualDiagram slug="legacy-tools-vs-hash-chained-ledger-matrix" />
          <div className="cmp-wrap" tabIndex={0} role="region" aria-label="Comparison table, scrolls sideways on narrow screens">
            <table className="cmp">
              <thead>
                <tr>
                  <th scope="col">What you use</th>
                  <th scope="col">What it is built to hold</th>
                  <th scope="col">What it cannot show</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Spreadsheets and shared folders</th>
                  <td>Rows people typed and PDFs people filed.</td>
                  <td>
                    That a row was not edited afterwards, or shortened. That a verification still matches the
                    configuration now on the machine. Nothing prompts anyone when a version changes.
                  </td>
                </tr>
                <tr>
                  <th scope="row">PLM and document control</th>
                  <td>The released design, its revisions and controlled documents.</td>
                  <td>
                    What is actually running on one delivered serial after commissioning and service calls, and which
                    safety functions a recorded verification still stands for.
                  </td>
                </tr>
                <tr>
                  <th scope="row">OT asset-inventory and vulnerability tools</th>
                  <td>Discovered assets, firmware versions and known vulnerabilities.</td>
                  <td>
                    Which verification covered which configuration, a named person&apos;s recorded decision, or a
                    record that can show it was neither edited nor quietly shortened.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="pricing-note">
            Industrial Autonomous Assurance does not replace them. It reads their exports as input files: an inventory
            export to enrol machines, a CSAF 2.0 advisory to check a fleet. Those importers are file-based and
            evolving, not supported connectors (see the platform table below).
          </p>
        </div>
      </section>

      {/* DESIGNED OUTCOME */}
      <section className="section" id="outcome">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">The designed outcome</span>
            <h2>What the product is built to let you do.</h2>
            <p>
              Stated as capability. This page reports no customer result, saving or timing, because none has been
              measured.
            </p>
          </div>
          <ul className="ruled">
            <li>
              <h3>Name the stale evidence</h3>
              <p>
                After a recorded change, list the safety functions whose last verification predates it, dated, per
                machine.
              </p>
            </li>
            <li>
              <h3>Put an advisory on your fleet</h3>
              <p>
                One supplier advisory in, a per-machine answer out: affected, not affected, or cannot tell, with the
                matching basis shown.
              </p>
            </li>
            <li>
              <h3>Keep the Article 14 clocks and the reasoning</h3>
              <p>
                Awareness is a named person&apos;s decision; both deadline clocks run from it; the triage reasoning is
                part of the record. The filing stays the manufacturer&apos;s.
              </p>
            </li>
            <li>
              <h3>Hand an auditor a file they can check without you</h3>
              <p>
                A ledger export or machine bundle that anyone can re-check offline, which says what it establishes
                and what it cannot, including when completeness was not checked.
              </p>
            </li>
          </ul>
        </div>
      </section>

      {/* ROLE PATHS */}
      <section className="section section-alt" id="roles">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Start from your seat</span>
            <h2>Six roles, six honest starting points.</h2>
            <p>Each page says what the problem looks like for that role and links only to things that exist.</p>
          </div>
          <ul className="paths">
            {ROLES.map((role) => (
              <li key={role.href}>
                <a href={role.href}>
                  <strong>{role.name}</strong>
                  <span>{role.line}</span>
                  <span className="path-go">{role.go} &rarr;</span>
                </a>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* THE PATH: reading to using */}
      <section className="section" id="path">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">The path</span>
            <h2>From a first visit to ongoing assurance.</h2>
            <p>
              Each step says what exists today and where it runs: on your own machine, on a hosted API, by request, or
              not at all.
            </p>
          </div>
          <ol className="journey">
            {journeySteps().map((step) => (
              <li key={step.id}>
                <div>
                  <h3>{step.title}</h3>
                  <p>{step.short}</p>
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
          <p className="pricing-note">
            <a href="/start" className="btn btn-primary">Open the full path, with commands</a>
          </p>
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
            <div className="hero-panel">
              <div className="hero-panel-title">Run it now, inside your plant, nothing uploaded</div>
              <div className="hero-code" tabIndex={0} role="region" aria-label="Command example">{`pip install cryptography && export PYTHONPATH=src
python -m assurance report demo --out demo/   # a worked report in a second; nothing to edit
python -m assurance kit init plant/           # then your own: fill in kit.json and plans/cell.json
python -m assurance kit check plant/kit.json  # lists any placeholder still in place
python -m assurance kit run  plant/kit.json --out plant/out`}</div>
              <p className="hero-panel-note">
                Your ledger, your disk. No account, no API key, no upload. The demo uses synthetic machines; a kit run refuses
                to produce evidence until the template values are replaced. The run arms a guard over the process's
                socket layer and refuses every outbound connection, including name resolution.
              </p>
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
            <span className="eyebrow">
              {HOSTED_API ? 'Start here — free, no account' : 'Start here — runs on your own machine today'}
            </span>
            <h2>Machine Assurance Check: a change landed. What does it mean for this machine?</h2>
            <p>
              This is the question the whole system exists to answer. Paste a supplier advisory and one machine&apos;s
              manifest below. {HOSTED_API ? 'Run the real check' : 'The request is shown as the API takes it'} &mdash; the same match logic that decides whether a hash is
              byte-identical, a version label is only a label, or the two disagree and neither column gets to claim
              this machine. An explicit verdict, never collapsed to safe-or-not: no impact found, potentially
              affected, or needs a human to look.
            </p>
          </div>

          <div className="hero-panel" style={{ marginBottom: '2rem' }}>
            <div className="hero-panel-title">
              {HOSTED_API
                ? 'Machine Assurance Check \u2014 try it right here'
                : 'Machine Assurance Check \u2014 the request it takes (hosted endpoint not live yet)'}
            </div>
            <AdvisoryCheckPlayground />
            <p className="hero-panel-note">
              {HOSTED_API ? (
                <>
                  This calls the real <code>POST /v1/check/machine</code> endpoint on one machine, free, no account.
                </>
              ) : (
                <>
                  This site has no hosted API behind it yet, so the button below cannot run the check online. The same
                  check is <code>POST /v1/check/machine</code> in the Assurance API you run yourself (
                  <a href={QUICKSTART}>quickstart</a>), and the offline kit runs it with no server, no account and no
                  upload.
                </>
              )}{' '}
              Enrolling the machine unlocks <code>POST /v1/check/fleet-machine</code>: the same check joined to its
              intervention history, its evidence staleness, and the fleet-wide fan-out across every other enrolled
              machine &mdash; the Cell plan.
            </p>
            <p className="hero-panel-note">
              Handed an evidence export, a machine verification bundle or a signed attestation log?{' '}
              <a href="/verify">Check what can and cannot be established from the file</a> &mdash;{' '}
              {HOSTED_API
                ? 'free, no account, nothing stored.'
                : 'this page needs the hosted API, which is not live yet; the offline kit does the same check on your own machine.'}
            </p>
          </div>

          <div className="section-head">
            <span className="eyebrow">Explore products</span>
            <h2>Plans, engines, and the API, in one place.</h2>
            <p>
              Every row below maps to code that runs. Nothing on this page is listed that the software does not do.
              Engine tiles link to the buyer-facing guide for that engine; plan tiles link to pricing. Which of the command line, the HTTP API and the MCP server offers each capability is on <a href="/docs/capabilities">the capabilities page</a>, generated from the code.
            </p>
          </div>

          <div className="hero-panel" style={{ marginBottom: '2rem' }}>
            <div className="hero-panel-title">
              {HOSTED_API
                ? 'The free CRA Article 14 validator \u2014 try it right here'
                : 'The CRA Article 14 validator \u2014 the request it takes (hosted endpoint not live yet)'}
            </div>
            <ValidatorPlayground />
            <p className="hero-panel-note">
              This is the real <code>POST /v1/spec/validate</code> request: it reports missing required fields and
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

      {/* HOW IT WORKS: the /product pages, generated from app/lib/productPages.ts */}
      <section className="section" id="workflow">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">How it works</span>
            <h2>Machine evidence goes stale when the machine changes. One page per question.</h2>
            <p>
              Each page below follows a real workflow through the commands, routes and tools that exist, says what it
              does not establish, and names who decides.
            </p>
          </div>
          <div className="solutions-grid">
            {PRODUCT_PAGES.map((page) => (
              <a className="solution-card" href={productHref(page.slug)} key={page.slug}>
                <span className="solution-role">{page.kicker}</span>
                <h3>{page.name}</h3>
                <p>{page.intent}</p>
                <span className="tile-link" style={{ marginTop: '0.75rem' }}>
                  <span className="tile-link-label">Read the workflow</span>
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

          <VisualDiagram slug="pricing-entitlement-tiers-validator-register-cell" />

          <SizingCalculator />

          <PricingPlans />

          <div className="compare-table-wrap" tabIndex={0} role="region" aria-label="Comparison table, scrolls sideways">
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
                  <td>/ai control plane — propose-and-approve writes, bind connections, a durable audit log for your account</td>
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
            <RepoLink path="/blob/main/src/assurance/api/billing_routes.py" plain>the billing routes</RepoLink>{' '}
            for the exact behaviour.
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
              adapters (supported scope intended, see the table), and the web workspace at /ai. It is intentionally narrower than
              it once claimed to be. The rows below are the README&apos;s own table, word for word.
            </p>
          </div>
          <RotatingImage
            slot={IMAGES['platform-integration-hub']}
            aspect="21/9"
            sizes="100vw"
            className="pricing-media"
          />
          <div className="status-table-wrap" tabIndex={0} role="region" aria-label="Status table, scrolls sideways">
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
            <RepoLink path="#neuralbridge--the-platform-underneath" plain>
              the README
            </RepoLink>.
          </p>
        </div>
      </section>

      {/* FINAL CTA */}
      <section className="final-cta" id="connect">
        <div className="shell final-cta-inner">
          <div>
            <h2>Re-check one Declaration on your own machine. See what your paperwork stopped describing.</h2>
            <p>
              The offline kit needs no account, key or upload and opens no sockets.{' '}
              {HOSTED_API
                ? 'The hosted API answers the same checks over HTTP; the quickstart runs them locally.'
                : 'The hosted API is not deployed to a public endpoint yet: run the same code locally from the quickstart.'}
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
              Contact NeuralBridge
            </a>
          </div>
        </div>
      </section>
      <ImageryNote />
    </main>
  );
}
