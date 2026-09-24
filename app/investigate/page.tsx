import type { Metadata } from 'next';
import InvestigationWorkspace from '../components/InvestigationWorkspace';

export const metadata: Metadata = {
  title: 'Investigate | Industrial Autonomous Assurance',
  description:
    'The Machine Assurance Investigation: an enrolled machine’s configuration status, evidence staleness, intervention history and fleet impact in one place — Cell plan, calling the real API.',
  alternates: { canonical: '/investigate' },
  openGraph: {
    title: 'Investigate | Industrial Autonomous Assurance',
    description: 'One enrolled machine’s full evidence position, from the real API.',
    url: '/investigate',
    type: 'website',
  },
};

export default function InvestigatePage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 3rem' }}>
        <div className="shell">
          <span className="kicker">CELL PLAN — AN ENROLLED MACHINE</span>
          <h1 style={{ maxWidth: '26ch' }}>What does this machine&apos;s evidence actually say right now?</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            One call to <code>POST /v1/check/fleet-machine</code> — the same route the MCP tool and the free{' '}
            <a href="/#advisory-check">Machine Assurance Check</a> lead into once a machine is enrolled. Configuration
            status against the declared baseline, every safety function&apos;s coverage, the intervention timeline, and
            the fleet-wide fan-out when you give it a change to check. No second dataset — this is the same evidence
            the ledger holds.
          </p>
        </div>
      </section>

      <section className="section" style={{ paddingTop: 0 }}>
        <div className="shell">
          <InvestigationWorkspace />
        </div>
      </section>
    </main>
  );
}
