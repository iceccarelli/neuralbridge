import type { Metadata } from 'next';
import { REPO } from '../../lib/links';
import { IMAGES } from '../../lib/images';
import RotatingImage from '../../components/RotatingImage';

const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

export const metadata: Metadata = {
  title: 'Cursor connector | Industrial Autonomous Assurance',
  description: 'Install assurance-mcp as a Cursor MCP server, or point Cursor at the real openapi.json — no account needed for free routes.',
  alternates: { canonical: '/connectors/cursor' },
  openGraph: {
    title: 'Cursor connector | Industrial Autonomous Assurance',
    description: 'Wire Cursor to the Assurance API — as an MCP server or via its OpenAPI schema.',
    url: '/connectors/cursor',
    type: 'website',
  },
};

export default function CursorConnectorPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 4.5rem' }}>
        <div className="shell">
          <span className="kicker">FOR CURSOR, VIA MCP OR RAW OPENAPI</span>
          <h1 style={{ maxWidth: '22ch' }}>Point Cursor at the Assurance API</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            <code>assurance-mcp</code> installs as a real MCP server Cursor can call directly — no plugin to write.
            Prefer plain HTTP instead? <a href="/openapi.json">openapi.json</a> is a real, generated OpenAPI 3
            schema most agent tooling can read on its own.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="#mcp-setup">Install the MCP server</a>
            <a className="btn btn-outline" href="/developers">Read the route table</a>
          </div>
          <RotatingImage
            slot={IMAGES['api-fastapi-docs']}
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
              <strong>{API_BASE ? 'A live base URL is configured' : 'No live base URL yet'}</strong>
              <span>
                {API_BASE
                  ? 'This deployment is live — point ASSURANCE_API_URL (MCP) or your OpenAPI client at it.'
                  : 'This marketing site was built without a live API URL. The steps below are real and will work against your own local run (uvicorn assurance.api.service:app) today.'}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="mcp-setup">
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">Recommended: MCP</span>
            <h2>assurance-mcp, in Cursor's own config</h2>
          </div>
          <ol className="cli-steps">
            <li>
              <strong>Install the server.</strong>
              <pre className="code-panel">{`pip install -e '.[assurance-mcp]'`}</pre>
            </li>
            <li>
              <strong>Add it to Cursor's <code>mcp.json</code></strong> (Cursor Settings → MCP):
              <pre className="code-panel">{`{
  "mcpServers": {
    "assurance": {
      "command": "assurance-mcp",
      "env": {
        "ASSURANCE_API_URL": "${API_BASE || 'http://127.0.0.1:8000'}",
        "ASSURANCE_API_KEY": ""
      }
    }
  }
}`}</pre>
            </li>
            <li>
              <strong>Ask Cursor to call <code>plans</code> or <code>spec_validate</code> first</strong> — both
              work with an empty <code>ASSURANCE_API_KEY</code>. See <a href="/connectors/mcp">the full tool
              table</a> for what else ships and what's next.
            </li>
          </ol>
        </div>
      </section>

      <section className="section section-alt" id="setup">
        <div className="shell" style={{ maxWidth: '72ch' }}>
          <div className="section-head">
            <span className="eyebrow">Alternative: raw OpenAPI</span>
            <h2>For tools that read a schema directly</h2>
          </div>
          <ol className="cli-steps">
            <li>
              <strong>Run the API locally, or use a deployment.</strong>
              <pre className="code-panel">{`pip install -e '.[assurance-api]'
uvicorn assurance.api.service:app`}</pre>
            </li>
            <li>
              <strong>Point Cursor's OpenAPI/tool config at the schema.</strong> In Cursor's settings for custom
              tools or an OpenAPI-backed connector, use:
              <pre className="code-panel">{`${API_BASE || 'http://localhost:8000'}/openapi.json`}</pre>
            </li>
            <li>
              <strong>Call a free route with no key first.</strong> <code>POST /v1/spec/validate</code>,{' '}
              <code>POST /v1/machine/separation</code>, and every route marked free in{' '}
              <a href="/developers">the route table</a> need nothing but a request body.
            </li>
          </ol>
          <p>
            Paid routes want <code>X-API-Key</code> — get one from <code>POST /v1/checkout</code> once billing is
            live, or run locally with <code>ASSURANCE_ALLOW_UNAUTHENTICATED=1</code> for evaluation. A tool call on
            the wrong plan gets a structured 402, never a bare 403 — see <a href="/developers#paid-example">the
            worked example</a>.
          </p>
        </div>
      </section>

      <section className="final-cta">
        <div className="shell final-cta-inner">
          <div>
            <h2>Rather wire an MCP-native agent?</h2>
            <p>Same routes, laid out as an MCP tool table.</p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/connectors/mcp">Go to /connectors/mcp</a>
            <a className="btn btn-outline" href={REPO} target="_blank" rel="noreferrer">Browse the source</a>
          </div>
        </div>
      </section>
    </main>
  );
}
