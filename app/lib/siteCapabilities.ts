import contract from '../../public/capabilities.json';

// The site's view of public/capabilities.json, which scripts/export_capabilities.py writes from
// src/assurance/capabilities.py (the catalogue of what the CLI, the HTTP API and the MCP server
// each offer). Nothing here is typed twice: counts and rows are read from that file.
// tests/test_site_capabilities_contract.py fails when the file is stale against the code, and when
// any capability id written in this file is not in the catalogue.

export type SurfaceName = 'cli' | 'api' | 'mcp';
export const SURFACE_NAMES: SurfaceName[] = ['cli', 'api', 'mcp'];

export type SurfaceStatus = 'available' | 'planned' | 'by_design';

export interface SurfaceCell {
  status: SurfaceStatus;
  names?: string[];
  reason?: string;
}

export interface Capability {
  id: string;
  service: string;
  title: string;
  surfaces: Record<SurfaceName, SurfaceCell>;
}

export const CAPABILITIES = contract.capabilities as unknown as Capability[];
export const COUNTS = contract.counts;
export const MCP_TOOL_NAMES = contract.mcp_tools as string[];
export const CLI_DOMAIN_VERBS = contract.cli_domains as Record<string, string[]>;

export const BY_ID = new Map(CAPABILITIES.map((c) => [c.id, c]));

// How a cell is labelled. A surface is "available" only in the sense the contract gives that
// word: the command, route or tool exists in this build.
export const STATUS_LABEL: Record<SurfaceStatus, string> = {
  available: 'available',
  planned: 'planned',
  by_design: 'by design',
};

export const SERVICE_TITLE: Record<string, string> = {
  account: 'Account (keys, checkout, billing)',
  art14: 'CRA Article 14 cases',
  attest: 'Attestation and keys',
  billing: 'Manual grants (operator tooling)',
  catalogue: 'Catalogue',
  change: 'Change assurance cases',
  check: 'Machine Assurance Check',
  collect: 'Collect',
  evidence: 'Evidence and the ledger',
  fleet: 'Fleet',
  intel: 'Public-source intelligence',
  kit: 'Offline kit',
  machine: 'Machine safety',
  machinery: 'Machinery Annex III',
  ops: 'Operator cycle (operator tooling)',
  report: 'Report',
  supplier: 'Supplier feeds',
  watch: 'Watch',
};

export interface FeaturedGroup {
  title: string;
  note: string;
  ids: string[];
}

// What was added since the site last described the product. Every id below must exist in the
// catalogue (tested); the notes say only what the engine guides under deploy/assurance/ say.
export const FEATURED: FeaturedGroup[] = [
  {
    title: 'Public-source intelligence',
    note:
      'KEV, NVD, EPSS and CSAF files recorded as provenance-stamped, append-only observations. Fetching a feed and recording a file are operator commands on the operator’s own machine; the hosted routes and the MCP tools only read the operator’s store, and answer 503 until the operator sets ASSURANCE_INTEL_STORE. A CVE no recorded source mentions is reported unknown, never clear.',
    ids: ['intel.ingest', 'intel.refresh', 'intel.history', 'intel.show', 'intel.candidates'],
  },
  {
    title: 'Watch reading the intel store',
    note:
      'A watch can name the intel store and a maximum age in hours; a stale or never-observed source degrades the run. --now sets the assessment clock for a dry run only. open-case turns a finding into a case and is a named person’s act.',
    ids: ['watch.run', 'watch.status', 'watch.open_case', 'watch.push'],
  },
  {
    title: 'Machine enrolment',
    note:
      'A named person declares a machine’s identity and a baseline is sealed with a receipt. An enrolment is never rewritten; a changed site or owner is a new, chained record. No MCP tool, by design.',
    ids: ['machinery.enrol', 'machinery.amend_enrolment'],
  },
  {
    title: 'Key ceremony and ledger completeness',
    note:
      'Key and trust-file tooling runs on the operator’s own machine; no hosted route or tool can supply a key or a trust decision. A hosted ledger export carries a signed anchor only after the operator has signed the ledger; without one, completeness is reported as not checked.',
    ids: [
      'attest.keygen',
      'attest.trust_list_create',
      'attest.preflight',
      'attest.anchor_all',
      'attest.service_key',
      'evidence.ledger_verify',
      'evidence.verify',
    ],
  },
  {
    title: 'Signed supplier advisory to case',
    note:
      'A feed signed under a key the account pinned can open a change-assurance case without a named person; an unsigned or unpinned advisory cannot. Opening a case from third-party content has no MCP tool, by design.',
    ids: ['supplier.trust_check', 'fleet.advisory_signed', 'change.assess_advisory_signed'],
  },
];

export function cellText(cell: SurfaceCell): string {
  return cell.status === 'available' ? (cell.names ?? []).join(', ') : cell.reason ?? '';
}

const norm = (route: string) => route.replace(/\{[^}]+\}/g, '{}');

/** The MCP cell of the capability that owns an API route ("GET /v1/x/{id}"), or undefined. */
export function mcpCellForRoute(route: string): SurfaceCell | undefined {
  const want = norm(route);
  return CAPABILITIES.find((c) => (c.surfaces.api.names ?? []).some((n) => norm(n) === want))?.surfaces.mcp;
}
