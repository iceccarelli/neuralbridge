import type { Metadata } from 'next';
import { SRC } from '../../lib/links';
import { IMAGES } from '../../lib/images';
import { ROUTES, TIER_LABEL } from '../../lib/routes';
import RotatingImage from '../../components/RotatingImage';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';
const MCP_TOOLS = new Set(['GET /v1/plans', 'POST /v1/spec/validate', 'POST /v1/machine/verify', 'GET /v1/cases']);

export const metadata: Metadata = {
  title: 'MCP connector | Industrial Autonomous Assurance',
  description: 'An installable MCP server (assurance-mcp) wrapping the real Assurance API — pip install, four tools, no fake responses.',
  alternates: { canonical: '/connectors/mcp' },
  openGraph: {
    title: 'MCP connector | Industrial Autonomous Assurance',
    description: 'pip install -e ".[assurance-mcp]" — a real MCP server over the real Assurance API.',
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
            <code>assurance-mcp</code> ships in this repository — four tools, each a real <code>httpx</code> call to
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

      <section className="section section-alt" id="tools">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Tool set</span>
            <h2>Four tools — two free, two paid on purpose</h2>
            <p>
              Deliberately small rather than one tool per route: <code>plans</code> and{' '}
              <code>spec_validate</code> need no key at all, and <code>machine_verify</code> /{' '}
              <code>register_cases</code> exist specifically to prove the fail-closed behavior — called on the
              wrong plan, they return the API's real structured 401/402, not an error from this server. The full
              route table below is what a future, larger tool set would cover; the four highlighted rows are what
              ships in <code>assurance-mcp</code> today.
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
                  const shipped = MCP_TOOLS.has(key);
                  return (
                    <tr key={key} style={shipped ? { background: '#fff7ed' } : undefined}>
                      <td><code>{r.method} {r.path}</code></td>
                      <td><span className={`status-pill ${r.tier}`}>{TIER_LABEL[r.tier]}</span></td>
                      <td>{shipped ? <span className="status-pill supported">Shipped</span> : <span className="status-pill">Not yet a tool</span>}</td>
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
            Adding a route as a tool is mechanical — <code>src/assurance/mcp/server.py</code> is under 150 lines,
            one <code>@mcp.tool()</code> function per route calling the same <code>_call()</code> helper. The
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
    </main>
  );
}
