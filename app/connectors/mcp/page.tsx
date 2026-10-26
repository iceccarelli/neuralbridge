import type { Metadata } from 'next';
import { SRC } from '../../lib/links';
import { IMAGES } from '../../lib/images';
import { ROUTES, TIER_LABEL, type Tier } from '../../lib/routes';
import RotatingImage from '../../components/RotatingImage';
import ImageryNote from '../../components/ImageryNote';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

type McpTool = { name: string; route: string; tier: Tier; agentWrite: boolean };

// The one list this page counts and renders from. tests/test_site_mcp_parity.py
// pins the names and routes to the @mcp.tool() functions in src/assurance/mcp/server.py.
const MCP_TOOLS: McpTool[] = [
  { name: 'plans', route: 'GET /v1/plans', tier: 'free', agentWrite: false },
  { name: 'spec_validate', route: 'POST /v1/spec/validate', tier: 'free', agentWrite: false },
  { name: 'machine_verify', route: 'POST /v1/machine/verify', tier: 'cell', agentWrite: false },
  { name: 'register_cases', route: 'GET /v1/cases', tier: 'register', agentWrite: false },
  { name: 'change_cases', route: 'GET /v1/change/cases', tier: 'cell', agentWrite: false },
  { name: 'change_case', route: 'GET /v1/change/cases/{case_id}', tier: 'cell', agentWrite: false },
  { name: 'change_export', route: 'GET /v1/change/cases/{case_id}/export', tier: 'cell', agentWrite: false },
  { name: 'change_claim', route: 'POST /v1/change/cases/{case_id}/claim', tier: 'cell', agentWrite: true },
  { name: 'change_advance', route: 'POST /v1/change/cases/{case_id}/advance', tier: 'cell', agentWrite: true },
  { name: 'change_reverify', route: 'POST /v1/change/cases/{case_id}/reverification', tier: 'cell', agentWrite: true },
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
            <h2>Three commands</h2>
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
              Deliberately small rather than one tool per route: <code>plans</code> and{' '}
              <code>spec_validate</code> need no key at all. The others (<code>register_cases</code> on Register; the
              machine and change tools on Cell) called on the wrong plan return the API&apos;s real structured
              401/402, not an error from this server. The full route table below is what a larger tool set could
              cover; the highlighted rows are what ships in <code>assurance-mcp</code> today.
            </p>
            <p>
              <strong>What an agent may write.</strong> Of the change-queue tools, three write:{' '}
              {WRITE_TOOLS.map((t, i) => (
                <span key={t.name}>
                  {i > 0 ? (i === WRITE_TOOLS.length - 1 ? ', and ' : ', ') : ''}
                  <code>{t.name}</code>
                </span>
              ))}{' '}
              — claim a case, move it to the next stop its own required work names, and submit a re-verification for
              the engine to judge. Closing, waiving, rejecting or deferring a case, resuming it and resolving its open
              decisions are <strong>human-only</strong>: they have no MCP tool, by design, and stay on the CLI and the
              HTTP API. Each write takes an <code>actor</code> name; it is asserted by the caller and recorded, not
              proven — the API refuses a blank one but does not check who is behind the key.
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
                          <span className="status-pill">Not yet a tool</span>
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
            <code>@mcp.tool()</code> function per route calling the same <code>_call()</code> helper. The
            remaining free-tier routes (separation, bundle/manifest/declaration checks, attestation key/verify)
            are the natural next additions, since they need no key either. Read the source or open a PR.
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
