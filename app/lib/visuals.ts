import manifest from '../../public/images/visuals/visual-manifest.json';

export interface VisualEntry {
  id: string;
  slug: string;
  targetRoute: string;
  targetSection: string;
  cliOrApiReference: string;
  pngPath: string;
  webpPath: string;
  ogPath: string;
  width: number;
  height: number;
  alt: string;
  caption: string;
  aeoSummary: string;
  keywords: string[];
  schemaOrgImageObject: {
    '@type': string;
    contentUrl: string;
    width: number;
    height: number;
    caption: string;
    description: string;
  };
}

export const VISUALS: VisualEntry[] = manifest as VisualEntry[];

const BY_SLUG: Record<string, VisualEntry> = Object.fromEntries(
  VISUALS.map((entry) => [entry.slug, entry]),
);

export function getVisual(slug: string): VisualEntry {
  const entry = BY_SLUG[slug];
  if (!entry) throw new Error(`Unknown visual slug: ${slug}`);
  return entry;
}

export const DOCS_VISUAL_BY_PATH: Record<string, string> = {
  '/docs/getting-started': 'end-to-end-assurance-operator-pipeline',
  '/docs/assurance/pipeline': 'end-to-end-assurance-operator-pipeline',
  '/docs/assurance/attest': 'hash-chain-edits-vs-countersigned-head-truncation',
  '/docs/assurance/machinery': 'machinery-regulation-annex-iii-staleness-join',
  '/docs/pricing': 'pricing-entitlement-tiers-validator-register-cell',
  '/docs/assurance/kit': 'offline-enrolment-kit-socket-guard-airgap',
  '/docs/assurance/fleet': 'fleet-advisory-deterministic-hash-fanout',
  '/docs/assurance': 'change-assurance-case-human-gate-state-machine',
  '/docs/assurance/change': 'change-assurance-case-human-gate-state-machine',
  '/docs/assurance/watch': 'immutable-ledger-anatomy-and-watch-exit-codes',
};
