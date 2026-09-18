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

// A static index of this site's own sections and the real docs in the repo —
// not a hosted search service. The MkDocs site at DOCS has its own built-in
// search (mkdocs-material's `search` plugin); this index only covers the
// marketing site itself and links out to the docs site's pages, rather than
// duplicating the docs site's own search.
export const SEARCH_INDEX: SearchEntry[] = [
  { title: 'Validator — free', group: 'Products', href: '#pricing', blurb: 'Article 14 draft validation, calculators, offline kit. No account.' },
  { title: 'Article 14 Register — €390/mo', group: 'Products', href: '#pricing', blurb: 'The CRA register for one manufacturer.' },
  { title: 'Cell — €1,290/mo', group: 'Products', href: '#pricing', blurb: 'Register, plus machine and fleet-level assurance.' },
  { title: 'Machine safety verification', group: 'Products', href: `${DEPLOY_BLOB}/MACHINE.md`, blurb: 'ISO/TS 15066 checks against a declared safety envelope.', external: true },
  { title: 'Machinery Annex III', group: 'Products', href: `${DEPLOY_BLOB}/MACHINERY.md`, blurb: 'The safety software manifest and the staleness join.', external: true },
  { title: 'Fleet advisory', group: 'Products', href: `${DEPLOY_BLOB}/FLEET.md`, blurb: 'One advisory, fanned out by hash across a fleet.', external: true },
  { title: 'Watch', group: 'Products', href: `${DEPLOY_BLOB}/WATCH.md`, blurb: 'The component that runs when nobody is looking.', external: true },
  { title: 'Attest', group: 'Products', href: `${DEPLOY_BLOB}/ATTEST.md`, blurb: 'Counter-signed head attestation; catches deletion, not just editing.', external: true },
  { title: 'Offline enrolment kit', group: 'Products', href: `${DEPLOY_BLOB}/KIT.md`, blurb: 'Your ledger, your disk. No account, no upload.', external: true },
  { title: 'Assurance API', group: 'Products', href: `${SRC}/api`, blurb: 'FastAPI surface for billing and entitlements.', external: true },
  ...SOLUTIONS.map((s) => ({
    title: s.role,
    group: 'Solutions' as const,
    href: `/solutions/${s.slug}`,
    blurb: s.headline,
  })),
  { title: 'Documentation', group: 'Docs', href: DOCS, blurb: 'Getting started, every engine, deploying the register.', external: true },
  { title: 'README — full source', group: 'Docs', href: `${REPO}#readme`, blurb: 'Every CLI verb, checked against --help.', external: true },
  { title: 'Deploy guide', group: 'Docs', href: `${DEPLOY_BLOB}/README.md`, blurb: 'fly.io, Stripe, backups, what to check after deploying.', external: true },
  { title: 'Roadmap', group: 'Docs', href: `${REPO}/blob/main/ROADMAP.md`, blurb: 'What is planned and not yet built.', external: true },
  { title: 'Security policy', group: 'Docs', href: `${REPO}/blob/main/SECURITY.md`, blurb: 'How to report a vulnerability.', external: true },
  { title: 'Contributing', group: 'Docs', href: `${REPO}/blob/main/CONTRIBUTING.md`, blurb: 'How to propose a change to this repository.', external: true },
  { title: 'Privacy', group: 'Docs', href: '/privacy', blurb: 'What this site collects — today, nothing tracked.' },
];
