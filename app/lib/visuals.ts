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
  '/docs/assurance/collect': 'lifecycle-manifest-anatomy-hashes-sources',
  '/docs/assurance/machine': 'iso15066-safety-envelope-and-coverage-states',
  '/docs/assurance/attest': 'hash-chain-edits-vs-countersigned-head-truncation',
  '/docs/assurance/machinery': 'machinery-regulation-annex-iii-staleness-join',
  '/docs/pricing': 'pricing-entitlement-tiers-validator-register-cell',
  '/docs/assurance/kit': 'offline-enrolment-kit-socket-guard-airgap',
  '/docs/assurance/fleet': 'fleet-advisory-deterministic-hash-fanout',
  '/docs/assurance': 'change-assurance-case-human-gate-state-machine',
  '/docs/assurance/change': 'change-assurance-case-human-gate-state-machine',
  '/docs/assurance/watch': 'immutable-ledger-anatomy-and-watch-exit-codes',
};

export const SOLUTION_VISUAL_BY_SLUG: Record<string, string> = {
  manufacturer: 'manufacturer-declaration-of-conformity-evidence-gap',
  'system-integrator': 'system-integrator-verifiable-evidence-chain',
  'plant-operator': 'plant-operator-air-gapped-workstation',
  'compliance-officer': 'eu-cra-article-14-dual-deadline-clocks',
  'insurer-auditor': 'insurer-auditor-zero-account-verification',
  'ai-ops': 'ai-ops-mcp-gateway-human-approval',
};

export const PRODUCT_VISUAL_BY_SLUG: Record<string, string> = {
  'industrial-autonomous-assurance': 'lifecycle-hero-end-to-end-assurance',
  'machine-evidence-ledger': 'lifecycle-hash-chained-ledger-append',
  'continuous-machine-assurance': 'lifecycle-change-assurance-case-opened',
  'supplier-advisory-fleet-impact': 'lifecycle-drift-detection-machinery-diff',
  'cra-article-14': 'lifecycle-external-verification-no-account',
  'machinery-regulation-evidence': 'lifecycle-passport-sealed-evidence-position',
  'machine-safety-verification': 'lifecycle-verification-against-safety-envelope',
  'evidence-attestation': 'lifecycle-signed-ledger-head-attestation',
  'offline-assurance-kit': 'lifecycle-offline-kit-to-optional-hosted',
  'assurance-api-and-mcp': 'lifecycle-artefacts-relationship-diagram',
  'enterprise-integration': 'lifecycle-enrolment-named-person-seals-manifest',
};

export const APPLICATION_VISUAL_SLUGS: string[] = [
  'cobots-iso-ts-15066-separation-envelope',
  'packaging-staleness-join-signoff-vs-change',
  'fleet-advisory-hash-matched-fanout',
  'oem-article14-register-deadline-clocks',
  'insurer-declaration-bundle-attestation-verify',
  'applications-route-to-plan-gating-matrix',
];
