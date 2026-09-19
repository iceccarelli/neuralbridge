import type { Metadata } from 'next';
import { REPO, SRC } from '../lib/links';
import { IMAGES } from '../lib/images';
import { ROUTES, TIER_LABEL } from '../lib/routes';
import RotatingImage from '../components/RotatingImage';

const SITE_URL = 'https://neuralbridge.io';
const API_BASE = process.env.NEXT_PUBLIC_ASSURANCE_API_URL || '';

export const metadata: Metadata = {
  title: 'Developers | Industrial Autonomous Assurance',
  description:
    'The Assurance API: auth, base URL, the real free-vs-paid route table generated from the actual FastAPI routers, and copy-paste curl/Python.',
  alternates: { canonical: '/developers' },
  openGraph: {
    title: 'Developers | Industrial Autonomous Assurance',
    description: 'Auth, routes, and examples for the Assurance API — generated from the real routers, not a summary.',
    url: '/developers',
    type: 'website',
  },
};

export default function DevelopersPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 4.5rem' }}>
        <div className="shell">
          <span className="kicker">FOR AGENTS, CI BOTS, AND HUMANS WITH A TERMINAL</span>
          <h1 style={{ maxWidth: '24ch' }}>The Assurance API</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            42 routes over CRA Article 14 and Machinery Regulation Annex III evidence. Bearer auth via one
            header, JSON in and out, and a real OpenAPI 3 schema you can fetch instead of trusting this page.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/openapi.json">Get openapi.json</a>
            <a className="btn btn-outline" href={`${SRC}/api`} target="_blank" rel="noreferrer">Read the source</a>
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
                  ? `This deployment's base URL is set. Everything below is callable now.`
                  : 'This marketing site was built without NEXT_PUBLIC_ASSURANCE_API_URL set. The routes, auth model, and examples below are real — read straight from the code — but there is nothing to call until the founder finishes deploy/assurance/README.md. Run it yourself: uvicorn assurance.api.service:app.'}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="auth">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Auth</span>
            <h2>One header. Bearer token, never a cookie.</h2>
            <p>
              Send <code>X-API-Key: &lt;your key&gt;</code>. Get a key from <code>POST /v1/checkout</code> (Register
              or Cell) or by running the service locally with{' '}
              <code>ASSURANCE_ALLOW_UNAUTHENTICATED=1</code> for evaluation. A missing key is a 401. A valid key on
              the wrong plan is a <strong>402</strong>, never a 403 — the obstacle is payment, not permission, and
              every gated route says exactly which plan unlocks it.
            </p>
          </div>
          <p className="code-panel-label">Free, no key needed</p>
          <pre className="code-panel">{`curl -X POST ${API_BASE || 'https://<your-deployment>'}/v1/spec/validate \\
  -H 'content-type: application/json' \\
  -d '{"track":"actively_exploited_vulnerability","stage":"early_warning","payload":{}}'`}</pre>
        </div>
      </section>

      <section className="section section-alt" id="routes">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Routes</span>
            <h2>Free vs. paid, straight from the routers</h2>
            <p>
              Every row below is gated in code, in <code>src/assurance/api/deps.py</code> — if it is not gated,
              it is free. This is a curated view of the 42 routes; the full machine-readable schema (parameters,
              response shapes, every route including account/billing) is at{' '}
              <a href="/openapi.json">/openapi.json</a>.
            </p>
          </div>
          <div className="status-table-wrap">
            <table className="status-table">
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Route</th>
                  <th>Plan</th>
                  <th>What it does</th>
                </tr>
              </thead>
              <tbody>
                {ROUTES.map((r) => (
                  <tr key={`${r.method} ${r.path}`}>
                    <td><code>{r.method}</code></td>
                    <td><code>{r.path}</code></td>
                    <td><span className={`status-pill ${r.tier}`}>{TIER_LABEL[r.tier]}</span></td>
                    <td>{r.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="section" id="paid-example">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">A paid route, called correctly</span>
            <h2>What a 402 looks like — and what success looks like</h2>
            <p>
              <code>POST /v1/machine/verify</code> needs the Cell plan. Called with a Register-only key, it fails
              closed with a structured upgrade hint instead of a bare 403 — an agent can parse this and route a
              human to checkout automatically.
            </p>
          </div>
          <p className="code-panel-label">Python</p>
          <pre className="code-panel">{`import httpx

resp = httpx.post(
    "${API_BASE || 'https://<your-deployment>'}/v1/machine/verify",
    headers={"X-API-Key": api_key},
    json={"envelope": envelope, "trace": trace, "actor": "you@example.com"},
)
if resp.status_code == 402:
    detail = resp.json()["detail"]
    # {"error": "plan_does_not_include_machine_verification",
    #  "tier": "register", "account_status": "active",
    #  "remedy": "...GET /v1/plans, then POST /v1/checkout."}
    print(detail["remedy"])
else:
    resp.raise_for_status()
    print(resp.json())`}</pre>
        </div>
      </section>

      <section className="final-cta">
        <div className="shell final-cta-inner">
          <div>
            <h2>Wire an agent to this instead of reading it</h2>
            <p>Cursor, Claude, and CI bots discover this the same way: llms.txt, openapi.json, and this page.</p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/llms.txt">Get llms.txt</a>
            <a className="btn btn-outline" href="/cli">Install the CLI</a>
            <a className="btn btn-outline" href="/connectors/mcp">MCP connector</a>
            <a className="btn btn-outline" href={REPO} target="_blank" rel="noreferrer">Browse the source</a>
          </div>
        </div>
      </section>
    </main>
  );
}
