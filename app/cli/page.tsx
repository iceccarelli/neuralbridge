import type { Metadata } from 'next';
import { REPO, SRC } from '../lib/links';
import { IMAGES } from '../lib/images';
import { CLI_DOMAINS, TIER_LABEL } from '../lib/routes';
import RotatingImage from '../components/RotatingImage';

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
          <span className="kicker">ONE PACKAGE, ELEVEN DOMAINS</span>
          <h1 style={{ maxWidth: '22ch' }}>The assurance CLI</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            <code>python -m assurance &lt;domain&gt; &lt;verb&gt;</code> — the same code the hosted API calls, runnable
            on your own machine first. Some domains talk to a deployment once you have one; <code>kit</code> and{' '}
            <code>watch</code> never do, by design.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="/docs/getting-started">Read the quickstart</a>
            <a className="btn btn-outline" href={`${SRC}`} target="_blank" rel="noreferrer">Browse the source</a>
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
          <pre className="code-panel">{`pip install -e '.[assurance-attest]'
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
              Checked against each domain's own <code>--help</code> output. Two domains — <code>kit</code> and{' '}
              <code>watch</code> — are offline-first and have no API equivalent; the rest call the same tier of the
              Assurance API listed on <a href="/developers">/developers</a>.
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
            <h2>The CLI today, MCP tomorrow</h2>
            <p>
              Every CLI verb above maps 1:1 to a FastAPI route or a local file operation — the same surface an MCP
              server would expose as tools. See <a href="/connectors/mcp">the MCP connector page</a> for the current
              tool table and what ships today versus what a future <code>mcp/</code> package still needs.
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
            <a className="btn btn-outline" href={REPO} target="_blank" rel="noreferrer">Browse the source</a>
          </div>
        </div>
      </section>
    </main>
  );
}
