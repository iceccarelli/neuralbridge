import type { Metadata } from 'next';
import RepoLink from '../components/RepoLink';
import { IMAGES } from '../lib/images';
import { CLI_DOMAINS, TIER_LABEL } from '../lib/routes';
import RotatingImage from '../components/RotatingImage';
import ImageryNote from '../components/ImageryNote';
import { COUNTS } from '../lib/siteCapabilities';

export const metadata: Metadata = {
  title: 'CLI | Industrial Autonomous Assurance',
  description: 'Install the assurance CLI, the real domain/verb tree checked against --help, and which commands map to the hosted API vs. stay offline.',
  alternates: { canonical: '/cli' },
  openGraph: {
    title: 'CLI | Industrial Autonomous Assurance',
    description: 'python -m assurance — the real command tree, and what each domain maps to.',
    url: '/cli',
    type: 'website',
  },
};

export default function CliPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 4.5rem' }}>
        <div className="shell">
          <span className="kicker">ONE PACKAGE, {COUNTS.cli_domains} DOMAINS</span>
          <h1 style={{ maxWidth: '22ch' }}>The assurance CLI</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            <code>python -m assurance &lt;domain&gt; &lt;verb&gt;</code> — the same code the hosted API calls, runnable
            on your own machine first. Some domains talk to a deployment once you have one; <code>kit</code> and{' '}
            <code>watch</code> never do, by design.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/docs/getting-started">Read the quickstart</a>            <RepoLink path="/tree/main/src/assurance" className="btn btn-outline">Browse the source</RepoLink>
          </div>
          <RotatingImage
            slot={IMAGES['card-api-assurance']}
            aspect="21/9"
            sizes="100vw"
            className="pricing-media"
          />
        </div>
      </section>

      <section className="section" id="install">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Install</span>
            <h2>Runs on your machine, into your own ledger</h2>
            <p>No account, no upload — every domain reads and writes local files unless it explicitly names an API call below.</p>
          </div>
          <p className="code-panel-label">Install and check</p>
          <pre className="code-panel">{`pip install cryptography && export PYTHONPATH=src   # from a checkout; nothing else to install
python -m assurance                     # lists every domain
python -m assurance kit init plant/     # a runnable kit
python -m assurance kit check plant/kit.json`}</pre>
        </div>
      </section>

      <section className="section section-alt" id="domains">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Command map</span>
            <h2>Every domain, its verbs, and what it maps to</h2>
            <p>
              Checked against each domain's own <code>--help</code> output. A domain with an API tier has hosted routes
              of that tier, listed on <a href="/developers">/developers</a>; a domain marked offline only never calls a
              deployment, and <code>kit</code> and <code>watch</code> are offline by design (<code>watch push</code> is
              the one opt-in command that reports to your own hosted ledger). {COUNTS.cli_commands} commands in all; the
              table lists the first word after the domain, so <code>trust-list</code> and <code>trust</code> stand for
              their own sub-commands, and not every verb of an API-tier domain has a route. Which command has a matching
              API route or MCP tool, and why one is missing, is on{' '}
              <a href="/docs/capabilities">the capabilities page</a>.
            </p>
            <p>
              <code>intel ingest</code> and <code>intel refresh --live</code> are operator commands: fetching KEV, NVD or
              EPSS is an act on the operator&apos;s own machine, and the hosted <code>/v1/intel</code> routes only read the
              store that produces, answering 503 until the operator sets <code>ASSURANCE_INTEL_STORE</code>.
            </p>
          </div>
          <div className="status-table-wrap">
            <table className="status-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Verbs</th>
                  <th>What it does</th>
                  <th>API tier</th>
                </tr>
              </thead>
              <tbody>
                {CLI_DOMAINS.map((d) => (
                  <tr key={d.domain}>
                    <td><code>{d.domain}</code></td>
                    <td>{d.verbs.map((v) => <code key={v} style={{ marginRight: '0.4rem' }}>{v}</code>)}</td>
                    <td>{d.summary}</td>
                    <td>{d.apiTier ? <span className={`status-pill ${d.apiTier}`}>{TIER_LABEL[d.apiTier]}</span> : <span className="status-pill">Offline only</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="section" id="future-mcp">
        <div className="shell">
          <div className="section-head">
            <span className="eyebrow">Wiring an agent to this</span>
            <h2>The CLI, and the MCP server that wraps the same API</h2>
            <p>
              The CLI and the installable <code>assurance-mcp</code> server both call the same FastAPI routes.{' '}
              See <a href="/connectors/mcp">the MCP connector page</a> for the tool table and what it does not cover (it exposes a subset of the API, not every CLI verb; the capabilities page says which, and why).
            </p>
          </div>
        </div>
      </section>

      <section className="final-cta">
        <div className="shell final-cta-inner">
          <div>
            <h2>Read the full route table next</h2>
            <p>Auth, the free-vs-paid split, and copy-paste curl/Python for the same API this CLI calls.</p>
          </div>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/developers">Go to /developers</a>
            <RepoLink path="" className="btn btn-outline">Browse the source</RepoLink>
          </div>
        </div>
      </section>
      <ImageryNote />
    </main>
  );
}
