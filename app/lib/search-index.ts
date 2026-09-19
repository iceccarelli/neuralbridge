import { DEPLOY_BLOB, DOCS, REPO, SRC } from './links';
import { SOLUTIONS } from './solutions';

export type SearchGroup = 'Products' | 'Solutions' | 'Docs';

export interface SearchEntry {
  title: string;
  group: SearchGroup;
  href: string;
  blurb: string;
  external?: boolean;
}

// A static index of this site's own sections and the on-site /docs pages —
// not a hosted search service. It covers the marketing site plus the docs
// pages that matter most for wayfinding; the full docs tree is browsable
// from the /docs sidebar itself.
export const SEARCH_INDEX: SearchEntry[] = [
  { title: 'Validator — free', group: 'Products', href: '/#pricing', blurb: 'Article 14 draft validation, calculators, offline kit. No account.' },
  { title: 'Article 14 Register — €390/mo', group: 'Products', href: '/#pricing', blurb: 'The CRA register for one manufacturer.' },
  { title: 'Cell — €1,290/mo', group: 'Products', href: '/#pricing', blurb: 'Register, plus machine and fleet-level assurance.' },
  { title: 'Machine safety verification', group: 'Products', href: `/docs/assurance/machine`, blurb: 'ISO/TS 15066 checks against a declared safety envelope.' },
  { title: 'Machinery Annex III', group: 'Products', href: `/docs/assurance/machinery`, blurb: 'The safety software manifest and the staleness join.' },
  { title: 'Fleet advisory', group: 'Products', href: `/docs/assurance/fleet`, blurb: 'One advisory, fanned out by hash across a fleet.' },
  { title: 'Watch', group: 'Products', href: `/docs/assurance/watch`, blurb: 'The component that runs when nobody is looking.' },
  { title: 'Attest', group: 'Products', href: `/docs/assurance/attest`, blurb: 'Counter-signed head attestation; catches deletion, not just editing.' },
  { title: 'Offline enrolment kit', group: 'Products', href: `/docs/assurance/kit`, blurb: 'Your ledger, your disk. No account, no upload.' },
  { title: 'Assurance API', group: 'Products', href: `${SRC}/api`, blurb: 'FastAPI surface for billing and entitlements.', external: true },
  ...SOLUTIONS.map((s) => ({
    title: s.role,
    group: 'Solutions' as const,
    href: `/solutions/${s.slug}`,
    blurb: s.headline,
  })),
  { title: 'Documentation', group: 'Docs', href: DOCS, blurb: 'Getting started, every engine, deploying the register.' },
  { title: 'Getting started', group: 'Docs', href: '/docs/getting-started', blurb: 'The offline kit walkthrough, one command at a time.' },
  { title: 'Pricing (docs)', group: 'Docs', href: '/docs/pricing', blurb: 'The same capability table, generated from enforced entitlements.' },
  { title: 'Platform status', group: 'Docs', href: '/docs/platform', blurb: 'What is Supported vs. Evolving today.' },
  { title: 'Developers — API reference', group: 'Docs', href: '/developers', blurb: 'Auth, the real free-vs-paid route table, curl and Python examples.' },
  { title: 'OpenAPI schema', group: 'Docs', href: '/openapi.json', blurb: 'The real OpenAPI 3 schema, generated from the FastAPI app.' },
  { title: 'README — full source', group: 'Docs', href: `${REPO}#readme`, blurb: 'Every CLI verb, checked against --help.', external: true },
  { title: 'Deploy guide', group: 'Docs', href: `/docs/assurance/deploy`, blurb: 'fly.io, Stripe, backups, what to check after deploying.' },
  { title: 'Roadmap', group: 'Docs', href: `${REPO}/blob/main/ROADMAP.md`, blurb: 'What is planned and not yet built.', external: true },
  { title: 'Security policy', group: 'Docs', href: `${REPO}/blob/main/SECURITY.md`, blurb: 'How to report a vulnerability.', external: true },
  { title: 'Contributing', group: 'Docs', href: `${REPO}/blob/main/CONTRIBUTING.md`, blurb: 'How to propose a change to this repository.', external: true },
  { title: 'Privacy', group: 'Docs', href: '/privacy', blurb: 'What this site collects — today, nothing tracked.' },
];
