// The platform status table, verbatim from README.md ("## Current Supported Scope").
//
// One copy for the site: the homepage table and the "connect AI agents" sample block both
// render this array. It is typed here (a TSX page cannot import Markdown), so
// tests/test_site_honesty.py::TestPlatformStatusIsTheReadmeTable compares every row, in order,
// with the README table and with docs/platform.md, and fails if any wording differs.
//
// `status` is the README's own word for the row. Only the exact word "Supported" gets the green
// pill; "Supported as a core direction" and "Intended supported scope" are not "Supported".

export type StatusPill = 'supported' | 'evolving' | 'not-claimed';

export interface PlatformStatusRow {
  area: string;
  status: string;
  pill: StatusPill;
  /** What the code and the tests show for this row, where the README word alone would mislead. */
  note?: string;
}

export const PLATFORM_STATUS: PlatformStatusRow[] = [
  { area: 'FastAPI backend', status: 'Supported', pill: 'supported' },
  { area: 'Connection management model', status: 'Supported as a core direction', pill: 'evolving' },
  { area: 'MCP tool listing / invocation layer', status: 'Supported', pill: 'supported' },
  {
    area: 'Dashboard foundation (separate Vite admin UI, not wired to the assurance API)',
    status: 'Experimental / evolving',
    pill: 'evolving',
  },
  {
    area: 'Basic audit trail (in memory by default; cleared on restart)',
    status: 'Experimental / evolving',
    pill: 'evolving',
  },
  {
    area: 'Small set of working adapters',
    status: 'Intended supported scope',
    pill: 'evolving',
    note:
      'PostgreSQL and REST are the candidates. PostgreSQL has been exercised against a real server only by the /ai control-plane and MCP tests (they skip without one). The REST adapter sends no HTTP request: its calls are commented out behind canned mock data, and its tests construct it and read that data.',
  },
  { area: 'Broad adapter ecosystem', status: 'Experimental / evolving', pill: 'evolving' },
  {
    area: 'Full enterprise compliance posture',
    status: 'Not part of the core promise yet',
    pill: 'not-claimed',
    note: 'No enterprise certification or compliance attestation is held.',
  },
  { area: 'Full zero-trust posture', status: 'Not part of the core promise yet', pill: 'not-claimed' },
  {
    area: 'Immutable enterprise-grade audit guarantees',
    status: 'Not part of the core promise yet',
    pill: 'not-claimed',
  },
  {
    area: 'No-code enterprise deployment for any system',
    status: 'Too broad for the current promise',
    pill: 'not-claimed',
  },
];

/** The same rows as a two-column text block, for the monospace sample on the homepage. */
export function platformStatusText(): string {
  const width = Math.max(...PLATFORM_STATUS.map((r) => r.area.length)) + 2;
  return PLATFORM_STATUS.map((r) => `${r.area.padEnd(width)}${r.status}`).join('\n');
}
