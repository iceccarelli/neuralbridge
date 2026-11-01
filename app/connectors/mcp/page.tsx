import type { Metadata } from 'next';
import { SRC } from '../../lib/links';
import { IMAGES } from '../../lib/images';
import { ROUTES, TIER_LABEL, type Tier } from '../../lib/routes';
import RotatingImage from '../../components/RotatingImage';
import ImageryNote from '../../components/ImageryNote';
import { mcpCellForRoute } from '../../lib/siteCapabilities';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

type McpTool = { name: string; route: string; tier: Tier; agentWrite: boolean };

// The one list this page counts and renders from. tests/test_site_mcp_parity.py
// pins the names and routes to the @mcp.tool() functions in src/assurance/mcp/server.py.
const MCP_TOOLS: McpTool[] = [
  { name: 'plans', route: 'GET /v1/plans', tier: 'free', agentWrite: false },
  { name: 'capabilities', route: 'GET /v1/capabilities', tier: 'free', agentWrite: false },
  { name: 'spec_validate', route: 'POST /v1/spec/validate', tier: 'free', agentWrite: false },
  { name: 'machine_verify', route: 'POST /v1/machine/verify', tier: 'cell', agentWrite: false },
  { name: 'machine_check', route: 'POST /v1/machine/bundle/check', tier: 'free', agentWrite: false },
  { name: 'evidence_verify', route: 'POST /v1/evidence/verify', tier: 'free', agentWrite: false },
  { name: 'machinery_coverage', route: 'POST /v1/machinery/coverage', tier: 'cell', agentWrite: false },
  { name: 'machinery_passport_check', route: 'POST /v1/machinery/passport/check', tier: 'free', agentWrite: false },
  { name: 'fleet_report', route: 'GET /v1/fleet/report', tier: 'cell', agentWrite: false },
  { name: 'register_cases', route: 'GET /v1/cases', tier: 'register', agentWrite: false },
  { name: 'services', route: 'GET /v1/check/services', tier: 'free', agentWrite: false },
  { name: 'machine_assurance_check', route: 'POST /v1/check/machine', tier: 'free', agentWrite: false },
  { name: 'fleet_machine_assurance', route: 'POST /v1/check/fleet-machine', tier: 'cell', agentWrite: false },
  { name: 'change_cases', route: 'GET /v1/change/cases', tier: 'cell', agentWrite: false },
  { name: 'change_case', route: 'GET /v1/change/cases/{case_id}', tier: 'cell', agentWrite: false },
  { name: 'change_export', route: 'GET /v1/change/cases/{case_id}/export', tier: 'cell', agentWrite: false },
  { name: 'intel_history', route: 'GET /v1/intel/history', tier: 'cell', agentWrite: false },
  { name: 'intel_observation', route: 'GET /v1/intel/observations/{seq}', tier: 'cell', agentWrite: false },
  { name: 'intel_cve', route: 'GET /v1/intel/cve/{cve_id}', tier: 'cell', agentWrite: false },
  { name: 'intel_candidates', route: 'GET /v1/intel/candidates', tier: 'cell', agentWrite: false },
  { name: 'change_claim', route: 'POST /v1/change/cases/{case_id}/claim', tier: 'cell', agentWrite: true },
  { name: 'change_advance', route: 'POST /v1/change/cases/{case_id}/advance', tier: 'cell', agentWrite: true },
  { name: 'change_reverify', route: 'POST /v1/change/cases/{case_id}/reverification', tier: 'cell', agentWrite: true },
  { name: 'change_assess_drift', route: 'POST /v1/change/assess/drift', tier: 'cell', agentWrite: true },
  { name: 'change_assess_intervention', route: 'POST /v1/change/assess/intervention', tier: 'cell', agentWrite: true },
  // Read-only: a GET, or a POST that answers a question and records nothing.
  { name: 'spec_fields', route: 'GET /v1/spec/fields', tier: 'free', agentWrite: false },
  { name: 'art14_case', route: 'GET /v1/cases/{case_id}', tier: 'register', agentWrite: false },
  { name: 'art14_register', route: 'GET /v1/register', tier: 'register', agentWrite: false },
  { name: 'art14_breaches', route: 'GET /v1/register/breaches', tier: 'register', agentWrite: false },
  { name: 'art14_export', route: 'GET /v1/cases/{case_id}/export', tier: 'register', agentWrite: false },
  { name: 'ledger_verify', route: 'GET /v1/ledger/verify', tier: 'register', agentWrite: false },
  { name: 'attest_log', route: 'GET /v1/ledger/attest/log', tier: 'cell', agentWrite: false },
  { name: 'attest_verify', route: 'POST /v1/ledger/attest/verify', tier: 'free', agentWrite: false },
  { name: 'attest_service_key', route: 'GET /v1/ledger/attest/key', tier: 'free', agentWrite: false },
  { name: 'machine_separation', route: 'POST /v1/machine/separation', tier: 'free', agentWrite: false },
  { name: 'machinery_diff', route: 'POST /v1/machinery/diff', tier: 'free', agentWrite: false },
  { name: 'fleet_machines', route: 'GET /v1/fleet/machines', tier: 'cell', agentWrite: false },
  { name: 'fleet_observations', route: 'GET /v1/fleet/observations', tier: 'cell', agentWrite: false },
  { name: 'fleet_declaration_check', route: 'POST /v1/fleet/declaration/check', tier: 'free', agentWrite: false },
  { name: 'value_position', route: 'GET /v1/value', tier: 'cell', agentWrite: false },
  { name: 'change_replay', route: 'GET /v1/change/cases/{case_id}/replay', tier: 'cell', agentWrite: false },
  { name: 'supplier_trust_list', route: 'GET /v1/supplier/trust', tier: 'cell', agentWrite: false },
  { name: 'supplier_trust_check', route: 'POST /v1/supplier/trust/evaluate', tier: 'cell', agentWrite: false },
];
const TOOL_BY_ROUTE = new Map(MCP_TOOLS.map((t) => [t.route, t]));
const TOOL_COUNT = MCP_TOOLS.length;
const FREE_COUNT = MCP_TOOLS.filter((t) => t.tier === 'free').length;
const WRITE_TOOLS = MCP_TOOLS.filter((t) => t.agentWrite);

// Decisions only a named person makes. There is deliberately no MCP tool for any of these.
const HUMAN_ONLY = new Set([
  'POST /v1/change/cases/{case_id}/decision',
  'POST /v1/change/cases/{case_id}/resume',
  'POST /v1/change/cases/{case_id}/resolve-decision',
  'POST /v1/change/cases/{case_id}/waive-reverification',
]);

// A route with no tool says why, from the capability catalogue (public/capabilities.json): a decision
// ("by design") or a known gap ("planned"). A route the catalogue does not know is shown as unknown,
// never as a gap that was meant.
function McpGap({ route }: { route: string }) {
  const cell = mcpCellForRoute(route);
  if (!cell || cell.status === 'available') return <span className="status-pill">No tool listed</span>;
  return (
    <span className={`status-pill ${cell.status === 'planned' ? 'evolving' : ''}`} title={cell.reason}>
      {cell.status === 'planned' ? 'Planned, no tool yet' : 'No tool, by design'}
    </span>
  );
}

export const metadata: Metadata = {
  title: 'MCP connector | Industrial Autonomous Assurance',
  description: 'Two installable MCP servers — assurance-mcp for the Assurance API, neuralbridge-ai-mcp for the /ai control plane — pip install, no fake responses.',
  alternates: { canonical: '/connectors/mcp' },
  openGraph: {
    title: 'MCP connector | Industrial Autonomous Assurance',
    description: 'pip install -e ".[assurance-mcp]" or ".[neuralbridge-ai-mcp]" — real MCP servers over real APIs.',
    url: '/connectors/mcp',
    type: 'website',
  },
};

export default function McpConnectorPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 4.5rem' }}>
        <div className="shell">
          <span className="kicker">FOR AGENTS THAT SPEAK MCP, NOT JUST HTTP</span>
          <h1 style={{ maxWidth: '22ch' }}>An installable MCP server for the Assurance API</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            <code>assurance-mcp</code> ships in this repository — {TOOL_COUNT} tools, each a real <code>httpx</code> call to
            a running deployment, no local simulation. With no API URL configured, every tool returns the same
            honest "not configured" error this whole site uses, never a faked response.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="#install">Install it</a>
            <a className="btn btn-outline" href="/connectors/cursor">Cursor connector instead</a>
          </div>
          <RotatingImage
            slot={IMAGES['solution-aiops-mcp-gateway']}
            aspect="21/9"
            sizes="100vw"
            className="pricing-media"
          />
        </div>
      </section>

      <section className="trust-strip">
        <div className="shell">
          <div className="trust-item" style={{ maxWidth: '80ch' }}>
            <span className="trust-icon">{'⚠'}</span>
            <div>
              <strong>{API_BASE ? 'This deployment has a live base URL' : 'No live base URL on this deployment'}</strong>
              <span>
                {API_BASE
                  ? `Point ASSURANCE_API_URL at ${API_BASE} and the two free tools (plans, spec_validate) work with no key.`
                  : 'That only affects this marketing site’s own playground — the MCP server itself works against any deployment you point it at, including your own local run: uvicorn assurance.api.service:app.'}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="install">
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">Install</span>
            <h2>Install and run</h2>
          </div>
          <pre className="code-panel">{`pip install -e '.[assurance-mcp]'

export ASSURANCE_API_URL=http://127.0.0.1:8000   # or a real deployment
export ASSURANCE_API_KEY=...                      # optional — paid tools only

assurance-mcp`}</pre>
          <p>
            Transport is stdio by default, which is what most MCP clients expect — including Cursor's{' '}
            <code>mcp.json</code>, shown on <a href="/connectors/cursor">the Cursor connector page</a>. For a
            generic MCP client, point it at the <code>assurance-mcp</code> command directly:
          </p>
          <pre className="code-panel">{`{
  "mcpServers": {
    "assurance": {
      "command": "assurance-mcp",
      "env": {
        "ASSURANCE_API_URL": "http://127.0.0.1:8000",
        "ASSURANCE_API_KEY": ""
      }
    }
  }
}`}</pre>
        </div>
      </section>

      <section className="section" id="install-ai">
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">A second server — for the control plane, not the register</span>
            <h2><code>neuralbridge-ai-mcp</code>: discover, read, plan, approve</h2>
            <p>
              A separate package with the same honesty rules — a thin <code>httpx</code> wrapper around the real{' '}
              <code>/ai</code> REST API (<code>src/neuralbridge/api/routes/ai.py</code>), not a second policy
              engine. <code>ai_list_connections</code>, <code>ai_capabilities</code>, and <code>ai_read</code> are
              free (rate-limited); <code>ai_plan_write</code>, <code>ai_approve</code>, <code>ai_deny</code>, and{' '}
              <code>ai_audit</code> need a Register or Cell key and return the API&apos;s real 402 otherwise —
              never a faked success.
            </p>
          </div>
          <pre className="code-panel">{`pip install -e '.[neuralbridge-ai-mcp]'

export NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1   # or a real deployment
export NEURALBRIDGE_AI_API_KEY=...                           # optional — write tools only
export NEURALBRIDGE_AI_ACTOR=your-agent-name                 # real identity for the audit trail

neuralbridge-ai-mcp`}</pre>
          <pre className="code-panel">{`{
  "mcpServers": {
    "neuralbridge-ai": {
      "command": "neuralbridge-ai-mcp",
      "env": {
        "NEURALBRIDGE_API_URL": "http://127.0.0.1:8000/api/v1",
        "NEURALBRIDGE_AI_API_KEY": "",
        "NEURALBRIDGE_AI_ACTOR": "your-agent-name"
      }
    }
  }
}`}</pre>
          <p>
            See <a href="https://github.com/iceccarelli/neuralbridge/blob/main/docs/ai-local-setup.md">
            docs/ai-local-setup.md</a> for standing up a local Postgres to point this at.
          </p>
        </div>
      </section>

      <section className="section section-alt" id="tools">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Assurance MCP tool set</span>
            <h2>
              {TOOL_COUNT} tools — {FREE_COUNT} need no key, {TOOL_COUNT - FREE_COUNT} need one on the right plan
            </h2>
            <p>
              Reads, verifications and pure calculations, plus a few change-queue writes: <code>plans</code> and{' '}
              <code>spec_validate</code> need no key at all. The others (<code>register_cases</code> on Register; the
              machine and change tools on Cell) called on the wrong plan return the API&apos;s real structured
              401/402, not an error from this server. The full route table below shows every route; the highlighted
              rows are what ships in <code>assurance-mcp</code> today.
            </p>
            <p>
              <strong>What an agent may write.</strong> Of the change-queue tools, {WRITE_TOOLS.length} write:{' '}
              {WRITE_TOOLS.map((t, i) => (
                <span key={t.name}>
                  {i > 0 ? (i === WRITE_TOOLS.length - 1 ? ', and ' : ', ') : ''}
                  <code>{t.name}</code>
                </span>
              ))}{' '}
              — open a case from a machine's own manifests (drift, or a sealed intervention), claim it, move it to the
              next stop its own required work names, and submit a re-verification for the engine to judge. Assessing
              an <strong>advisory</strong> is not a tool either: it is third-party content, and a case opened from an
              unsigned one is the attack the signed feed exists to stop. Closing, waiving, rejecting or deferring a case, resuming it and resolving its open
              decisions are <strong>human-only</strong>: they have no MCP tool, by design, and stay on the CLI and the
              HTTP API. Each write takes an <code>actor</code> name; it is asserted by the caller and recorded, not
              proven — the API refuses a blank one but does not check who is behind the key.
            </p>
            <p>
              <strong>Public-source intelligence is read-only here.</strong> The{' '}
              {MCP_TOOLS.filter((t) => t.name.startsWith('intel_')).length} <code>intel_*</code> tools read a store the
              operator builds with the CLI. They answer 503 until the operator sets <code>ASSURANCE_INTEL_STORE</code>,
              and nothing in this server fetches a feed or records an observation; those are operator commands. Which
              capabilities have no tool, and whether that is by design or planned, is on{' '}
              <a href="/docs/capabilities">the capabilities page</a>.
            </p>
          </div>
          <div className="status-table-wrap">
            <table className="status-table">
              <thead>
                <tr>
                  <th>Route</th>
                  <th>Plan</th>
                  <th>MCP tool</th>
                </tr>
              </thead>
              <tbody>
                {ROUTES.map((r) => {
                  const key = `${r.method} ${r.path}`;
                  const tool = TOOL_BY_ROUTE.get(key);
                  return (
                    <tr key={key} style={tool ? { background: '#fff7ed' } : undefined}>
                      <td><code>{r.method} {r.path}</code></td>
                      <td><span className={`status-pill ${r.tier}`}>{TIER_LABEL[r.tier]}</span></td>
                      <td>
                        {tool ? (
                          <span className="status-pill supported">Tool: {tool.name}{tool.agentWrite ? ' (agent write)' : ''}</span>
                        ) : HUMAN_ONLY.has(key) ? (
                          <span className="status-pill">Human-only, no tool by design</span>
                        ) : (
                          <McpGap route={key} />
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="section" id="next-pr">
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">What's next</span>
            <h2>Growing the tool set</h2>
          </div>
          <p>
            Adding a route as a tool is mechanical — in <code>src/assurance/mcp/server.py</code> it is one
            <code>@mcp.tool()</code> function per route calling the same <code>_call()</code> helper. Reads and
            pure checks are tools; anything that records, signs, pins or decides a thing is not, by design.
            <code>GET /v1/capabilities</code> lists, from the code, which surface each capability has and why
            any is missing. Read the source or open a PR.
          </p>
          <p>
            Prefer plain HTTP for now? Read <a href="/developers">/developers</a> or fetch{' '}
            <a href="/openapi.json">/openapi.json</a> directly — exactly what <a href="/llms.txt">/llms.txt</a>{' '}
            points agents at.
          </p>
        </div>
      </section>

      <section className="final-cta">
        <div className="shell final-cta-inner">
          <div>
            <h2>Prefer a raw HTTP client?</h2>
            <p>Same routes, same plans, curl and Python examples on the developer reference.</p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/developers">Go to /developers</a>
            <a className="btn btn-outline" href={`${SRC}/mcp`} target="_blank" rel="noreferrer">Browse the source</a>
          </div>
        </div>
      </section>
      <ImageryNote />
    </main>
  );
}
