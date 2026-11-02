import RepoLink from '../components/RepoLink';
import type { Metadata } from 'next';
import { buildMetadata } from '../lib/seo';
import AiWorkspace from '../components/AiWorkspace';

export const metadata: Metadata = buildMetadata({
  title: 'AI',
  description:
    'The agent control plane: discover a connection, read it, plan a write, approve it, get a receipt. The shared demo connection is read-only.',
  path: '/ai',
});

export default function AiPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 3rem' }}>
        <div className="shell">
          <span className="kicker">CONTROL PLANE, NOT A CHATBOT</span>
          <h1 style={{ maxWidth: '26ch' }}>Discover, read, plan, approve — on a connection you bind</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            This talks to the same <code>RequestRouter</code> the REST API and MCP gateway use — no second, invented
            dispatch path. Reads run immediately. Writes always stop for your approval first. The shared demo connection is
            read-only: without a key you can discover and read it (30 reads a day), and writes need your own
            connection bound on Register or Cell. Every result carries the
            connection, tool, timestamp and request id that produced it — nothing here is a fact the model made up.
            <RepoLink path="/blob/main/docs/ai-local-setup.md" plain>(Local setup: docs/ai-local-setup.md.)</RepoLink>
          </p>
        </div>
      </section>

      <section className="section" style={{ paddingTop: 0 }}>
        <div className="shell">
          <AiWorkspace />
        </div>
      </section>
    </main>
  );
}
