import type { Metadata } from 'next';
import { SRC } from '../../lib/links';
import { IMAGES } from '../../lib/images';
import { ROUTES, TIER_LABEL } from '../../lib/routes';
import RotatingImage from '../../components/RotatingImage';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

export const metadata: Metadata = {
  title: 'MCP connector | Industrial Autonomous Assurance',
  description: 'What the assurance API looks like as MCP tools — the real OpenAPI-driven table, and what a standalone mcp/ package still needs.',
  alternates: { canonical: '/connectors/mcp' },
  openGraph: {
    title: 'MCP connector | Industrial Autonomous Assurance',
    description: 'The assurance API surface as MCP tools, generated from the real OpenAPI operations.',
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
          <h1 style={{ maxWidth: '22ch' }}>The assurance API as MCP tools</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            NeuralBridge already runs an MCP gateway for tool listing and invocation (see{' '}
            <a href="/#platform">platform status</a>). This page is the honest state of wiring that gateway to the
            assurance product specifically: the tool table below is generated from the same real{' '}
            <a href="/openapi.json">openapi.json</a> the rest of this site is checked against — it is not yet a
            packaged, installable MCP server.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/openapi.json">Get openapi.json</a>
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
              <strong>What ships today vs. what does not</strong>
              <span>
                {API_BASE
                  ? 'This deployment has a live base URL. The MCP gateway can list/invoke tools against it once configured, but there is no packaged mcp/ server in this repository yet.'
                  : 'No standalone MCP server package exists in this repository yet, and this build has no live API URL either. What is real: the MCP gateway itself (src/neuralbridge/mcp), every route below (checked against openapi.json), and the fail-closed 402 shape a tool call gets on the wrong plan.'}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="tools">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Tool table</span>
            <h2>Every route, as a tool would see it</h2>
            <p>
              One MCP tool per operation, named after its path — the same 42 routes in{' '}
              <a href="/developers">/developers</a>, the same free-vs-paid gating. A tool call on the wrong plan gets
              the same structured 402 a raw HTTP call would.
            </p>
          </div>
          <div className="status-table-wrap">
            <table className="status-table">
              <thead>
                <tr>
                  <th>Tool name</th>
                  <th>Route</th>
                  <th>Plan</th>
                </tr>
              </thead>
              <tbody>
                {ROUTES.map((r) => (
                  <tr key={`${r.method} ${r.path}`}>
                    <td><code>{r.method.toLowerCase()}_{r.path.replace(/[{}]/g, '').split('/').filter(Boolean).join('_')}</code></td>
                    <td><code>{r.method} {r.path}</code></td>
                    <td><span className={`status-pill ${r.tier}`}>{TIER_LABEL[r.tier]}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="section section-alt" id="next-pr">
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">Next PR</span>
            <h2>What a packaged mcp/ server still needs</h2>
          </div>
          <p>
            A minimal <code>mcp/</code> package that wraps the existing <code>/v1</code> surface above — no new
            product logic, just an MCP stdio/SSE server whose tool list is generated from{' '}
            <code>scripts/export_openapi.py</code>'s output instead of hand-maintained. Scope for that PR:
          </p>
          <ul>
            <li>A thin MCP server (Python, using the FastAPI app's own OpenAPI schema) exposing the free-tier
              routes first — the same ones the Validator playground already calls with no auth.</li>
            <li>Fail closed with no <code>NEXT_PUBLIC_ASSURANCE_API_URL</code>-equivalent set, the same honest way
              every other unset-API surface on this site does.</li>
            <li>A published install command here once it exists — this page does not claim one today.</li>
          </ul>
          <p>
            Until that PR lands, the fastest way to wire an agent to this API is the plain HTTP surface: read{' '}
            <a href="/developers">/developers</a> or fetch <a href="/openapi.json">/openapi.json</a> directly, which
            is exactly what <a href="/llms.txt">/llms.txt</a> points agents at today.
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
            <a className="btn btn-outline" href={SRC} target="_blank" rel="noreferrer">Browse the source</a>
          </div>
        </div>
      </section>
    </main>
  );
}
