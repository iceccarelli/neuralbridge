import type { Metadata } from 'next';
import Console from '../components/Console';

export const metadata: Metadata = {
  title: 'Console | Industrial Autonomous Assurance',
  description: 'A browser REST console for the Assurance API — paste an API key, call real /v1 routes. No shell, no websocket, no fake success.',
  alternates: { canonical: '/console' },
  openGraph: {
    title: 'Console | Industrial Autonomous Assurance',
    description: 'Paste an API key, call the real Assurance API routes from your browser.',
    url: '/console',
    type: 'website',
  },
};

export default function ConsolePage() {
  return (
    <main id="top">
      <section className="hero" style={{ padding: '3rem 0 3rem' }}>
        <div className="shell">
          <span className="kicker">A REST CONSOLE, NOT A SHELL</span>
          <h1 style={{ maxWidth: '24ch' }}>Call the Assurance API from your browser</h1>
          <p className="hero-lead" style={{ maxWidth: '68ch' }}>
            Every route from <a href="/developers">the route table</a>, filterable like a command palette. Paste an
            API key and it calls the real deployment over <code>fetch()</code> — there is no server-side process,
            no websocket, no PTY sandbox behind this. If no API URL is configured, the call panel says so and stays
            disabled rather than faking a response.
          </p>
        </div>
      </section>

      <section className="section" style={{ paddingTop: 0 }}>
        <div className="shell">
          <Console />
        </div>
      </section>
    </main>
  );
}
