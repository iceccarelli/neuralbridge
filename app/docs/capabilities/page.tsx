import type { Metadata } from 'next';
import DocsSidebar from '../../components/DocsSidebar';
import {
  BY_ID,
  CAPABILITIES,
  COUNTS,
  FEATURED,
  MCP_TOOL_NAMES,
  SERVICE_TITLE,
  STATUS_LABEL,
  SURFACE_NAMES,
  type Capability,
  type SurfaceCell,
  type SurfaceName,
} from '../../lib/siteCapabilities';

export const metadata: Metadata = {
  title: 'Capabilities by surface | Docs | Industrial Autonomous Assurance',
  description:
    'Every capability, and which of the command line, the HTTP API and the MCP server offers it. Generated from the code; a missing surface says whether it is by design or planned.',
  alternates: { canonical: '/docs/capabilities' },
};

const SURFACE_HEADING: Record<SurfaceName, string> = { cli: 'CLI', api: 'HTTP API', mcp: 'MCP' };

function Cell({ cell }: { cell: SurfaceCell }) {
  if (cell.status === 'available') {
    return (
      <>
        <span className="status-pill available">{STATUS_LABEL.available}</span>
        {(cell.names ?? []).map((n) => (
          <code key={n} className="cap-name">
            {n}
          </code>
        ))}
      </>
    );
  }
  return (
    <>
      <span className={`status-pill ${cell.status === 'planned' ? 'evolving' : 'not-claimed'}`}>
        {STATUS_LABEL[cell.status]}
      </span>
      <span className="cap-reason">{cell.reason}</span>
    </>
  );
}

function Row({ cap }: { cap: Capability }) {
  return (
    <tr id={`cap-${cap.id}`}>
      <td>
        {cap.title}
        <code className="cap-name">{cap.id}</code>
      </td>
      {SURFACE_NAMES.map((s) => (
        <td key={s} data-surface={s} data-status={cap.surfaces[s].status}>
          <Cell cell={cap.surfaces[s]} />
        </td>
      ))}
    </tr>
  );
}

const INTEL_TOOLS = MCP_TOOL_NAMES.filter((t) => t.startsWith('intel_')).length;
const SERVICES = Array.from(new Set(CAPABILITIES.map((c) => c.service)));

export default function CapabilitiesPage() {
  const s = COUNTS.surfaces;
  return (
    <main id="top">
      <section className="docs-layout">
        <div className="shell docs-shell">
          <DocsSidebar activeHref="/docs/capabilities" editPath="src/assurance/capabilities.py" />

          <article className="docs-content">
            <h1>Capabilities by surface</h1>
            <p>
              One catalogue, <code>src/assurance/capabilities.py</code>, declares what this product can do and on which of
              the command line, the HTTP API and the MCP server. This page renders its export,{' '}
              <a href="/capabilities.json">/capabilities.json</a>; a test fails when that file is out of date with the
              code. The same catalogue is served live at <code>GET /v1/capabilities</code> and printed by{' '}
              <code>python -m assurance capabilities --check</code>.
            </p>
            <p>
              {COUNTS.capabilities} capabilities over {COUNTS.cli_commands} CLI commands in {COUNTS.cli_domains} domains,{' '}
              {COUNTS.api_routes} HTTP routes and {COUNTS.mcp_tools} MCP tools. Counts below are read from that file.
            </p>

            <h2>How to read the table</h2>
            <ul>
              <li>
                <strong>available</strong> means the command, route or tool exists in this build. It does not say that the
                three do exactly the same thing, that a hosted deployment exists, or which plan includes it (
                <code>GET /v1/plans</code> is the enforced list of plans).
              </li>
              <li>
                <strong>by design</strong> means the surface is absent on purpose, for the reason shown: a named person’s
                act (the Article 14 track, awareness, case closure and a case opened from third-party content are human
                decisions; software drafts), key custody, the offline kit opening no socket, or the account plane.
              </li>
              <li>
                <strong>planned</strong> is a known gap, listed so it is not hidden. By surface: CLI {s.cli.planned}, HTTP
                API {s.api.planned}, MCP {s.mcp.planned}.
              </li>
            </ul>
            <p>
              Available per surface: CLI {s.cli.available}, HTTP API {s.api.available}, MCP {s.mcp.available} of{' '}
              {COUNTS.capabilities} capabilities. The MCP server offers read and verify tools plus a few case-working
              writes; every decision that closes, rejects, defers or resumes a case, and every key or trust change, is
              absent by design.
            </p>

            <h2>Public-source intelligence is read-only over HTTP and MCP</h2>
            <p>
              <code>assurance intel ingest</code> and <code>assurance intel refresh --live</code> are commands an operator
              runs on their own machine; fetching KEV, NVD or EPSS is an operator act and the hosted service never reaches
              out to a feed. The hosted <code>/v1/intel</code> routes and the {INTEL_TOOLS} <code>intel_*</code> MCP tools only read
              the operator’s store, and answer <strong>503</strong> until the operator sets{' '}
              <code>ASSURANCE_INTEL_STORE</code>. No store is never reported as an empty answer, and a CVE that no recorded
              source mentions is reported <code>unknown</code>, never clear. See{' '}
              <a href="/docs/assurance/intel">Public-source intelligence</a>.
            </p>

            <h2>Added since this site last described the product</h2>
            {FEATURED.map((group) => (
              <div key={group.title}>
                <h3>{group.title}</h3>
                <p>{group.note}</p>
                <p>
                  {group.ids.map((id, i) => (
                    <span key={id}>
                      {i > 0 ? ' · ' : ''}
                      <a href={`#cap-${id}`}>
                        <code>{BY_ID.get(id)?.id ?? id}</code>
                      </a>
                    </span>
                  ))}
                </p>
              </div>
            ))}

            <h2>Every capability</h2>
            {SERVICES.map((service) => (
              <section key={service} id={`service-${service}`}>
                <h3>{SERVICE_TITLE[service] ?? service}</h3>
                <div className="status-table-wrap cap-table-wrap">
                  <table className="cap-table">
                    <thead>
                      <tr>
                        <th>Capability</th>
                        {SURFACE_NAMES.map((n) => (
                          <th key={n}>{SURFACE_HEADING[n]}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {CAPABILITIES.filter((c) => c.service === service).map((cap) => (
                        <Row key={cap.id} cap={cap} />
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ))}

            <h2>What this page does not establish</h2>
            <p>
              That a command, route or tool exists says nothing about whether it has been deployed or used. Nothing in this
              repository has been deployed, and the adapters in the platform underneath remain evolving unless the{' '}
              <a href="/docs/platform">platform status</a> table says Supported.
            </p>
          </article>
        </div>
      </section>
    </main>
  );
}
