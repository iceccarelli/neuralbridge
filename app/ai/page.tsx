import type { Metadata } from 'next';
import AiWorkspace from '../components/AiWorkspace';

export const metadata: Metadata = {
  title: 'AI | Industrial Autonomous Assurance',
  description:
    'The agent control plane: discover a real connection, read it, plan a write, approve it, get a receipt. Every fact cites the connection, tool, and timestamp that produced it — the LLM is never the system of record.',
  alternates: { canonical: '/ai' },
  openGraph: {
    title: 'AI | Industrial Autonomous Assurance',
    description: 'Discover, read, plan, approve, execute, verify — against a real connection, not a demo.',
    url: '/ai',
    type: 'website',
  },
};

export default function AiPage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 3rem' }}>
        <div className="shell">
          <span className="kicker">CONTROL PLANE, NOT A CHATBOT</span>
          <h1 style={{ maxWidth: '26ch' }}>Discover, read, plan, approve — against a real connection</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            This talks to the same <code>RequestRouter</code> the REST API and MCP gateway use — no second, invented
            dispatch path. Reads run immediately. Writes always stop for your approval first. Every result carries the
            connection, tool, timestamp and request id that produced it — nothing here is a fact the model made up.
            (Local setup: <a href="https://github.com/iceccarelli/neuralbridge/blob/main/docs/ai-local-setup.md">docs/ai-local-setup.md</a>.)
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
