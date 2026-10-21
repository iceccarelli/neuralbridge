import type { Metadata } from 'next';
import AssuranceWorkspace from '../components/AssuranceWorkspace';

export const metadata: Metadata = {
  title: 'Assurance workspace | Industrial Autonomous Assurance',
  description:
    'Your fleet, its evidence freshness and your open change-assurance cases, read from the live Assurance API with your own key.',
  alternates: { canonical: '/assurance' },
  robots: { index: false },
};

export default function AssurancePage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 2.5rem' }}>
        <div className="shell">
          <span className="kicker">CELL PLAN · CHANGE ASSURANCE</span>
          <h1 style={{ maxWidth: '26ch' }}>Which machines changed, and what is still unproven</h1>
          <p className="hero-lead" style={{ maxWidth: '70ch' }}>
            Everything on this page is read from the Assurance API with your key. Nothing is simulated: if the API is
            not configured, unreachable or your plan does not include a view, that is what you will see. The server
            decides what you may read; this page cannot widen it.
          </p>
        </div>
      </section>
      <section className="section" style={{ paddingTop: 0 }}>
        <div className="shell">
          <AssuranceWorkspace />
        </div>
      </section>
    </main>
  );
}
